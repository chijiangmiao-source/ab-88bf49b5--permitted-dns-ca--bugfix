/**
 * X.509 v3 certificate parser restricted to the profile accepted by this
 * application:
 *
 *   - certificate / tbsCertificate signature algorithm: ecdsa-with-SHA256
 *     (OID 1.2.840.10045.4.3.2)
 *   - subject public key: id-ecPublicKey (1.2.840.10045.2.1) with the
 *     prime256v1 / P-256 named curve (1.2.840.10045.3.1.7)
 *
 * Parsing itself is profile-agnostic: structural problems throw X509Error
 * (truncated DER etc.), while profile violations are reported on the parsed
 * certificate via `profileErrors[]` so the verifier can present them at the
 * exact failing certificate/level.
 */

import {
  TAG,
  DerError,
  readTLV,
  parseExactly,
  childList,
  nthChild,
  decodeBoolean,
  decodeUnsignedIntegerBytes,
  decodeInteger,
  decodeOID,
  decodeTime,
  decodeBitString,
  decodeDirectoryString,
  toHex,
} from './der.js';
import { OID } from './oids.js';

export class X509Error extends Error {
  /**
   * @param {string} message
   * @param {number} [offset]
   * @param {string} [slot] which pasted input failed ("信任锚" / "证书 #n")
   */
  constructor(message, offset, slot) {
    super(offset === undefined ? message : `${message} (at byte ${offset})`);
    this.name = 'X509Error';
    this.offset = offset;
    this.slot = slot;
  }
}

const CTX_CONSTRUCTED_0 = 0xa0; // version [0] EXPLICIT
const CTX_PRIMITIVE_1 = 0x81; // issuerUniqueID [1] IMPLICIT
const CTX_PRIMITIVE_2 = 0x82; // subjectUniqueID [2] IMPLICIT
const CTX_CONSTRUCTED_3 = 0xa3; // extensions [3] EXPLICIT
const GN_DNS_TAG = 0x82; // [2] dNSName, context-specific primitive
const GN_DIR_TAG = 0xa4; // [4] directoryName, context-specific constructed
const NC_PERMITTED_TAG = 0xa0; // [0] permittedSubtrees
const NC_EXCLUDED_TAG = 0xa1; // [1] excludedSubtrees
const AKI_KEY_ID_TAG = 0x80; // [0] keyIdentifier IMPLICIT OCTET STRING

/**
 * Parse an AlgorithmIdentifier.
 * AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER, parameters ANY OPTIONAL }
 */
function parseAlgorithmIdentifier(tlv) {
  const kids = childList(tlv);
  if (kids.length < 1 || kids.length > 2) {
    throw new X509Error('AlgorithmIdentifier must contain OID and optional parameters', tlv.start);
  }
  const oid = decodeOID(kids[0]);
  return { oid, params: kids.length === 2 ? kids[1] : null };
}

/**
 * Parse a Name and return both a display string and the exact content bytes
 * of the Name SEQUENCE (used for issuer/subject byte-equality linking).
 * Name ::= SEQUENCE OF RDN; RDN ::= SET OF AttributeTypeAndValue
 */
function parseName(tlv) {
  const rdns = [];
  for (const rdn of childList(tlv)) {
    const atvs = [];
    for (const atv of childList(rdn)) {
      const kids = childList(atv);
      if (kids.length !== 2) throw new X509Error('AttributeTypeAndValue must have type and value', atv.start);
      const oid = decodeOID(kids[0]);
      const value = decodeDirectoryString(kids[1]);
      atvs.push({ oid, value });
    }
    rdns.push(atvs);
  }
  const label = rdns
    .map((atvs) => atvs.map((a) => `${shortAttr(a.oid)}=${a.value}`).join(','))
    .join(', ');
  return { rdns, label, bytes: tlv.content };
}

function shortAttr(oid) {
  switch (oid) {
    case OID.AT_COMMON_NAME:
      return 'CN';
    case OID.AT_ORGANIZATION:
      return 'O';
    case OID.AT_ORGANIZATIONAL_UNIT:
      return 'OU';
    case OID.AT_COUNTRY:
      return 'C';
    case OID.AT_STATE:
      return 'ST';
    case OID.AT_LOCALITY:
      return 'L';
    default:
      return oid;
  }
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/**
 * Parse GeneralNames (the content of subjectAltName) and pull out DNS names
 * and directory names.
 */
function parseGeneralNames(tlv) {
  const dns = [];
  const directory = [];
  for (const gn of childList(tlv)) {
    if (gn.tag === GN_DNS_TAG) {
      dns.push(new TextDecoder().decode(gn.content));
    } else if (gn.tag === GN_DIR_TAG) {
      // [4] EXPLICIT Name: exactly one embedded Name SEQUENCE.
      const inner = childList(gn);
      if (inner.length !== 1 || inner[0].tag !== TAG.SEQUENCE) {
        throw new X509Error('malformed directoryName in GeneralNames', gn.start);
      }
      directory.push(inner[0].content);
    }
    // rfc822Name, uniformResourceIdentifier, iPAddress, otherName, etc. are
    // not needed for DNS-name chain validation and are intentionally ignored.
  }
  return { dns, directory };
}

function parseNameConstraintsValue(tlv) {
  const nc = {
    permittedDns: [],
    excludedDns: [],
    permittedDn: [],
    excludedDn: [],
    otherNameTypes: [],
  };
  const parseSubtrees = (subtrees, bucketDns, bucketDn) => {
    for (const subtree of childList(subtrees)) {
      const kids = childList(subtree);
      if (kids.length < 1) throw new X509Error('empty GeneralSubtree', subtree.start);
      const base = kids[0]; // GeneralName
      if (base.tag === GN_DNS_TAG) {
        bucketDns.push(new TextDecoder().decode(base.content));
      } else if (base.tag === GN_DIR_TAG) {
        const inner = childList(base);
        if (inner.length !== 1 || inner[0].tag !== TAG.SEQUENCE) {
          throw new X509Error('malformed directoryName in NameConstraints', base.start);
        }
        bucketDn.push(inner[0].content);
      } else {
        nc.otherNameTypes.push(base.tag);
      }
    }
  };
  for (const kid of childList(tlv)) {
    if (kid.tag === NC_PERMITTED_TAG) parseSubtrees(kid, nc.permittedDns, nc.permittedDn);
    else if (kid.tag === NC_EXCLUDED_TAG) parseSubtrees(kid, nc.excludedDns, nc.excludedDn);
    else throw new X509Error('unexpected field in NameConstraints', kid.start);
  }
  return nc;
}

/**
 * Parse the extensions field.
 * @param {Uint8Array} certRaw
 */
function parseExtensions(extWrapper, certRaw) {
  // [3] EXPLICIT wraps the Extensions SEQUENCE.
  const seq = childList(extWrapper);
  if (seq.length !== 1 || seq[0].tag !== TAG.SEQUENCE) {
    throw new X509Error('malformed extensions wrapper', extWrapper.start);
  }
  const map = new Map();
  const order = [];
  const unknownCritical = [];
  for (const ext of childList(seq[0])) {
    const kids = childList(ext);
    if (kids.length < 2 || kids.length > 3) {
      throw new X509Error('Extension must contain OID, optional critical and value', ext.start);
    }
    const oid = decodeOID(kids[0]);
    let critical = false;
    let valueTLV;
    if (kids.length === 3) {
      if (kids[1].tag !== TAG.BOOLEAN) {
        throw new X509Error('malformed extension critical field', kids[1].start);
      }
      critical = decodeBoolean(kids[1]);
      valueTLV = kids[2];
    } else {
      valueTLV = kids[1];
    }
    if (valueTLV.tag !== TAG.OCTET_STRING) {
      throw new X509Error('extnValue must be an OCTET STRING', valueTLV.start);
    }
    if (map.has(oid)) {
      throw new X509Error(`duplicate extension ${oid}`, ext.start);
    }
    // extnValue is itself the DER encoding of the extension value; parse that
    // inner TLV from the OCTET STRING content.
    let parsed = null;
    let parseError = null;
    try {
      parsed = readTLV(valueTLV.content, 0);
      if (parsed.end !== valueTLV.content.length) {
        throw new X509Error('trailing bytes inside extnValue', parsed.end);
      }
    } catch (e) {
      parseError = e instanceof DerError ? e.message : String(e);
    }

    const entry = { oid, critical, valueTLV, parsed, parseError };
    map.set(oid, entry);
    order.push(oid);
    if (!KNOWN_EXTENSIONS.has(oid) && critical) unknownCritical.push(oid);
  }
  return { map, order, unknownCritical };
}

const KNOWN_EXTENSIONS = new Set([
  OID.SUBJECT_KEY_IDENTIFIER,
  OID.KEY_USAGE,
  OID.SUBJECT_ALT_NAME,
  OID.BASIC_CONSTRAINTS,
  OID.NAME_CONSTRAINTS,
  OID.AUTHORITY_KEY_IDENTIFIER,
]);

/** Extract a KeyUsage bit (RFC 5280 numbering, MSB of first byte = bit 0). */
function kuBitSet(bytes, bit) {
  const idx = bit >> 3;
  if (idx >= bytes.length) return false;
  return (bytes[idx] & (0x80 >> (bit & 7))) !== 0;
}

export const KU = Object.freeze({
  DIGITAL_SIGNATURE: 0,
  KEY_CERT_SIGN: 5,
  CRL_SIGN: 6,
});

/**
 * Parse one DER-encoded Certificate.
 * @param {Uint8Array} der
 * @param {string} [slot] label used in error messages
 * @returns {ParsedCertificate}
 */
export function parseCertificate(der, slot) {
  let top;
  try {
    top = parseExactly(der, TAG.SEQUENCE);
  } catch (e) {
    if (e instanceof DerError) throw new X509Error(`DER 结构无法解析：${e.message}`, e.offset, slot);
    throw e;
  }
  const outerKids = childList(top);
  if (outerKids.length !== 3) {
    throw new X509Error('Certificate 必须恰好包含 tbsCertificate、signatureAlgorithm、signatureValue', top.start, slot);
  }
  const [tbs, sigAlg, sigValueTLV] = outerKids;
  if (tbs.tag !== TAG.SEQUENCE || sigAlg.tag !== TAG.SEQUENCE) {
    throw new X509Error('Certificate 外层结构标签错误', tbs.start, slot);
  }
  if (sigValueTLV.tag !== TAG.BIT_STRING) {
    throw new X509Error('signatureValue 必须是 BIT STRING', sigValueTLV.start, slot);
  }

  // ----- TBSCertificate -----
  const tbsKids = childList(tbs);
  let p = 0;
  let version = 0; // absent [0] means v1
  if (tbsKids.length > 0 && tbsKids[0].tag === CTX_CONSTRUCTED_0) {
    const inner = childList(tbsKids[0]);
    if (inner.length !== 1 || inner[0].tag !== TAG.INTEGER) {
      throw new X509Error('version 字段格式错误', tbsKids[0].start, slot);
    }
    version = decodeInteger(inner[0]);
    p = 1;
  }
  const required = ['serialNumber', 'signature', 'issuer', 'validity', 'subject', 'subjectPublicKeyInfo'];
  for (let i = 0; i < required.length; i++) {
    if (!tbsKids[p + i]) throw new X509Error(`tbsCertificate 缺少 ${required[i]}`, tbs.end, slot);
  }
  const serialTLV = tbsKids[p];
  const tbsSigAlgTLV = tbsKids[p + 1];
  const issuerTLV = tbsKids[p + 2];
  const validityTLV = tbsKids[p + 3];
  const subjectTLV = tbsKids[p + 4];
  const spkiTLV = tbsKids[p + 5];
  let q = p + 6;
  let extensionsWrapper = null;
  while (q < tbsKids.length) {
    const tag = tbsKids[q].tag;
    if (tag === CTX_PRIMITIVE_1 || tag === CTX_PRIMITIVE_2) {
      q++; // unique identifiers, ignored (v2 legacy)
    } else if (tag === CTX_CONSTRUCTED_3) {
      extensionsWrapper = tbsKids[q];
      q++;
    } else {
      throw new X509Error('tbsCertificate 中出现无法识别的上下文字段', tbsKids[q].start, slot);
    }
  }
  if (serialTLV.tag !== TAG.INTEGER) throw new X509Error('serialNumber 必须是 INTEGER', serialTLV.start, slot);
  if (validityTLV.tag !== TAG.SEQUENCE) throw new X509Error('validity 必须是 SEQUENCE', validityTLV.start, slot);

  const serialBytes = decodeUnsignedIntegerBytes(serialTLV);
  const tbsSigAlg = parseAlgorithmIdentifier(tbsSigAlgTLV);
  const sigAlgOuter = parseAlgorithmIdentifier(sigAlg);
  const issuer = parseName(issuerTLV);
  const subject = parseName(subjectTLV);

  const vKids = childList(validityTLV);
  if (vKids.length !== 2) throw new X509Error('validity 必须包含 notBefore 与 notAfter', validityTLV.start, slot);
  const notBefore = decodeTime(vKids[0]);
  const notAfter = decodeTime(vKids[1]);
  if (vKids[0].tag !== TAG.UTC_TIME && vKids[0].tag !== TAG.GENERALIZED_TIME) {
    throw new X509Error('notBefore 必须是 UTCTime 或 GeneralizedTime', vKids[0].start, slot);
  }
  if (vKids[1].tag !== TAG.UTC_TIME && vKids[1].tag !== TAG.GENERALIZED_TIME) {
    throw new X509Error('notAfter 必须是 UTCTime 或 GeneralizedTime', vKids[1].start, slot);
  }

  // ----- SubjectPublicKeyInfo -----
  const spkiKids = childList(spkiTLV);
  if (spkiKids.length !== 2) throw new X509Error('SubjectPublicKeyInfo 结构错误', spkiTLV.start, slot);
  const spkiAlg = parseAlgorithmIdentifier(spkiKids[0]);
  const pubBitString = decodeBitString(spkiKids[1]);
  const point = pubBitString.bytes;

  // ----- Signature value: BIT STRING wrapping DER ECDSA-Sig-Value -----
  const sigBitString = decodeBitString(sigValueTLV);

  // ----- Extensions -----
  let extensions = new Map();
  let extOrder = [];
  let unknownCritical = [];
  if (extensionsWrapper) {
    ({ map: extensions, order: extOrder, unknownCritical } = parseExtensions(extensionsWrapper));
  }

  const cert = {
    slot,
    raw: der,
    /** exact bytes of the TBSCertificate TLV — the bytes that were signed */
    tbsRaw: tbs.raw,
    version,
    serialHex: serialBytes ? toHex(serialBytes) : '(negative)',
    signatureAlgorithm: sigAlgOuter,
    tbsSignatureAlgorithm: tbsSigAlg,
    issuer,
    subject,
    notBefore,
    notAfter,
    spki: {
      algorithm: spkiAlg,
      point,
      unusedBits: pubBitString.unusedBits,
    },
    signature: {
      unusedBits: sigBitString.unusedBits,
      der: sigBitString.bytes,
    },
    extensions,
    extensionOrder: extOrder,
    sanDns: [],
    sanDirectory: [],
    basicConstraints: null,
    keyUsage: null,
    nameConstraints: null,
    subjectKeyIdentifier: null,
    authorityKeyIdentifier: null,
    unknownCriticalOids: unknownCritical,
    profileErrors: [],
  };

  // Interpret known extensions.
  for (const oid of extOrder) {
    const ext = extensions.get(oid);
    if (ext.parseError) {
      cert.profileErrors.push(`扩展 ${oid} 的值无法解析：${ext.parseError}`);
      continue;
    }
    const v = ext.parsed;
    try {
      if (oid === OID.SUBJECT_ALT_NAME) {
        const names = parseGeneralNames(v);
        cert.sanDns.push(...names.dns);
        cert.sanDirectory.push(...names.directory);
      } else if (oid === OID.BASIC_CONSTRAINTS) {
        const bcKids = childList(v);
        let cA = false;
        let pathLen = null;
        let seenCA = false;
        for (const k of bcKids) {
          if (k.tag === TAG.BOOLEAN) {
            cA = decodeBoolean(k);
            seenCA = true;
          } else if (k.tag === TAG.INTEGER) {
            pathLen = decodeInteger(k);
          } else {
            throw new X509Error('BasicConstraints 含未知字段', k.start);
          }
        }
        cert.basicConstraints = { cA, pathLen, seenCA };
      } else if (oid === OID.KEY_USAGE) {
        const bs = decodeBitString(v);
        cert.keyUsage = {
          unusedBits: bs.unusedBits,
          bytes: bs.bytes,
          digitalSignature: kuBitSet(bs.bytes, KU.DIGITAL_SIGNATURE),
          keyCertSign: kuBitSet(bs.bytes, KU.KEY_CERT_SIGN),
        };
      } else if (oid === OID.NAME_CONSTRAINTS) {
        cert.nameConstraints = parseNameConstraintsValue(v);
      } else if (oid === OID.SUBJECT_KEY_IDENTIFIER) {
        if (v.tag !== TAG.OCTET_STRING) throw new X509Error('SKI 必须是 OCTET STRING', v.start);
        cert.subjectKeyIdentifier = toHex(v.content);
      } else if (oid === OID.AUTHORITY_KEY_IDENTIFIER) {
        for (const k of childList(v)) {
          if (k.tag === AKI_KEY_ID_TAG) {
            cert.authorityKeyIdentifier = toHex(k.content);
          }
        }
      }
    } catch (e) {
      cert.profileErrors.push(`扩展 ${oid} 解析失败：${e.message}`);
    }
  }

  assessProfile(cert);
  return cert;
}

/**
 * Populate profileErrors with every deviation from the accepted P-256
 * ECDSA/SHA-256 v3 profile. All deviations are collected so the UI can show
 * them together rather than one-at-a-time.
 */
function assessProfile(cert) {
  if (cert.version !== 2) {
    // version INTEGER encodes v3 as 2.
    cert.profileErrors.push(
      cert.version === 0 ? '证书版本为 v1，本工具仅接受 X.509 v3' : `证书版本不是 v3（内部版本号 ${cert.version}）`,
    );
  }
  if (cert.signatureAlgorithm.oid !== OID.ECDSA_WITH_SHA256) {
    cert.profileErrors.push(`证书签名算法 ${cert.signatureAlgorithm.oid} 不是 ecdsa-with-SHA256`);
  }
  if (cert.tbsSignatureAlgorithm.oid !== OID.ECDSA_WITH_SHA256) {
    cert.profileErrors.push(`tbsCertificate.signature ${cert.tbsSignatureAlgorithm.oid} 不是 ecdsa-with-SHA256`);
  }
  if (cert.signatureAlgorithm.oid !== cert.tbsSignatureAlgorithm.oid) {
    cert.profileErrors.push('外层与 tbsCertificate 内的签名算法 OID 不一致');
  }
  // RFC 3279: parameters MUST be absent for ecdsa-with-SHA256.
  if (cert.signatureAlgorithm.params !== null) {
    cert.profileErrors.push('ecdsa-with-SHA256 的 AlgorithmIdentifier 不应携带 parameters');
  }
  if (cert.spki.algorithm.oid !== OID.EC_PUBLIC_KEY) {
    cert.profileErrors.push(`公钥算法 ${cert.spki.algorithm.oid} 不是 id-ecPublicKey`);
  }
  const curveParams = cert.spki.algorithm.params;
  if (!curveParams || curveParams.tag !== TAG.OID || decodeOID(curveParams) !== OID.P256) {
    cert.profileErrors.push('公钥曲线不是 P-256（prime256v1）命名曲线');
  }
  if (cert.spki.unusedBits !== 0) {
    cert.profileErrors.push('公钥 BIT STRING 必须字节对齐（unused bits = 0）');
  }
  // Uncompressed P-256 point: 0x04 || 32-byte X || 32-byte Y.
  if (!(cert.spki.point.length === 65 && cert.spki.point[0] === 0x04)) {
    cert.profileErrors.push(`EC 公钥不是 65 字节未压缩点（实际 ${cert.spki.point.length} 字节）`);
  }
  if (cert.signature.unusedBits !== 0) {
    cert.profileErrors.push('签名 BIT STRING 必须字节对齐（unused bits = 0）');
  }
}

/** True when issuer/subject Name DER content is byte-identical. */
export function nameMatches(issuerName, subjectName) {
  return bytesEqual(issuerName.bytes, subjectName.bytes);
}
