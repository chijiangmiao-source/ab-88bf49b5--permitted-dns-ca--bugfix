/**
 * X.509 v3 certificate builder for fixtures.
 * Generates P-256 keys via WebCrypto, encodes TBSCertificate in DER and
 * signs it with ECDSA-SHA256, then wraps r/s back into the DER BIT STRING.
 */

import { webcrypto as nodeCrypto } from 'node:crypto';
import {
  seq, setOf, octet, integerNumber, integerBytes, boolean as derBool,
  bitString, printable, ia5, utf8, utcTime, generalizedTime,
  oid, ctxPrim, ctxCons, concat,
} from './der-encoder.js';

const crypto = nodeCrypto;
const subtle = crypto.subtle;

export const OIDS = {
  ecPublicKey: '1.2.840.10045.2.1',
  ecdsaSha256: '1.2.840.10045.4.3.2',
  p256: '1.2.840.10045.3.1.7',
  skid: '2.5.29.14',
  keyUsage: '2.5.29.15',
  san: '2.5.29.17',
  basicConstraints: '2.5.29.19',
  nameConstraints: '2.5.29.30',
  akid: '2.5.29.35',
  cn: '2.5.4.3',
  o: '2.5.4.10',
  c: '2.5.4.6',
};

export async function generateKeyPair() {
  return subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
}

function algorithmIdentifier() {
  // ecdsa-with-SHA256, parameters absent per RFC 3279.
  return seq(oid(OIDS.ecdsaSha256));
}

function ecSpkiAlgorithm() {
  return seq(oid(OIDS.ecPublicKey), oid(OIDS.p256));
}

/**
 * Build a Name from [{type:'CN'|'O'|'C'|oid, value:string}]
 */
function name(attrs) {
  const rdns = attrs.map((a) => {
    const attrOid = a.type.length > 4 ? a.type : OIDS[a.type.toLowerCase()];
    const enc = a.type === 'C' ? printable(a.value) : utf8(a.value);
    return setOf(seq(oid(attrOid), enc));
  });
  return seq(concat(rdns));
}

function validity(notBefore, notAfter) {
  const enc = (d) => (d.getUTCFullYear() >= 2050 ? generalizedTime(d) : utcTime(d));
  return seq(enc(notBefore), enc(notAfter));
}

function extension(extOid, critical, valueDer) {
  const parts = [oid(extOid)];
  if (critical) parts.push(derBool(true));
  parts.push(octet(valueDer));
  return seq(concat(parts));
}

// ---- Extension value encoders ----

export function extBasicConstraints({ cA = false, pathLen = null, critical = true } = {}) {
  const parts = [];
  if (cA) parts.push(derBool(true));
  if (pathLen !== null) parts.push(integerNumber(pathLen));
  return { oid: OIDS.basicConstraints, critical, der: seq(concat(parts)) };
}

export function extKeyUsage(bits, { critical = true } = {}) {
  // RFC 5280 KeyUsage ::= BIT STRING { digitalSignature(0), ..., keyCertSign(5), cRLSign(6) }
  const bitNames = {
    digitalSignature: 0,
    nonRepudiation: 1,
    keyEncipherment: 2,
    dataEncipherment: 3,
    keyAgreement: 4,
    keyCertSign: 5,
    cRLSign: 6,
  };
  const indices = bits.map((b) => bitNames[b]);
  const max = Math.max(...indices);
  const bytes = new Uint8Array(Math.floor(max / 8) + 1);
  for (const i of indices) bytes[i >> 3] |= 0x80 >> (i & 7);
  const unused = 7 - (max & 7);
  return { oid: OIDS.keyUsage, critical, der: bitString(bytes, unused) };
}

export function extSubjectAltName(dnsNames, { critical = false } = {}) {
  // GeneralName dNSName is [2] IMPLICIT IA5String: the IA5String tag is
  // replaced by the context tag, its octets stay bare.
  const enc = new TextEncoder();
  const names = dnsNames.map((d) => ctxPrim(2, enc.encode(d)));
  return { oid: OIDS.san, critical, der: seq(concat(names)) };
}

export function extSubjectKeyIdentifier(keyIdBytes, { critical = false } = {}) {
  return { oid: OIDS.skid, critical, der: octet(keyIdBytes) };
}

export function extAuthorityKeyIdentifier(keyIdBytes, { critical = false } = {}) {
  // keyIdentifier [0] IMPLICIT OCTET STRING: bare key id octets under tag 0x80.
  return { oid: OIDS.akid, critical, der: seq(ctxPrim(0, keyIdBytes)) };
}

/**
 * @param {{permitted?: string[], excluded?: string[], critical?: boolean}} opts
 */
export function extNameConstraints({ permitted = [], excluded = [], critical = true } = {}) {
  const enc = new TextEncoder();
  // permittedSubtrees/excludedSubtrees are [n] IMPLICIT SEQUENCE OF
  // GeneralSubtree: the constructed context tag replaces the SEQUENCE tag,
  // so the [n] wrapper directly contains GeneralSubtree TLVs.
  const subtrees = (dnsList) =>
    concat(
      dnsList.map((d) =>
        // GeneralSubtree { base GeneralName, minimum [0] BaseDistance DEFAULT 0 }
        seq(ctxPrim(2, enc.encode(d))),
      ),
    );
  const parts = [];
  if (permitted.length) parts.push(ctxCons(0, subtrees(permitted)));
  if (excluded.length) parts.push(ctxCons(1, subtrees(excluded)));
  return { oid: OIDS.nameConstraints, critical, der: seq(concat(parts)) };
}

/** Arbitrary unknown critical extension (e.g. an unused OID 1.3.6.1.4.1.99999.1). */
export function extUnknownCritical(extOid = '1.3.6.1.4.1.99999.1', payload = new Uint8Array([0x05, 0x00])) {
  return { oid: extOid, critical: true, der: payload };
}

async function rawPublicKeyBytes(keyPair) {
  const spki = new Uint8Array(await subtle.exportKey('spki', keyPair.publicKey));
  // The SPKI BIT STRING content: 0x03, len, 0x00, then point bytes.
  // Parse just enough to locate the point (last 65 bytes for P-256).
  if (spki[spki.length - 65] !== 0x00 && spki.length < 65) {
    throw new Error('unexpected SPKI layout');
  }
  return spki.subarray(spki.length - 65);
}

async function keyId(keyPair) {
  const point = await rawPublicKeyBytes(keyPair);
  return new Uint8Array(await subtle.digest('SHA-256', point)).subarray(0, 20);
}

function toDerSignature(raw) {
  // WebCrypto returns 64-byte raw r||s. Rebuild DER SEQUENCE { r INTEGER, s INTEGER }.
  const r = integerBytes(raw.subarray(0, 32));
  const s = integerBytes(raw.subarray(32, 64));
  return seq(r, s);
}

/**
 * Build and sign a certificate.
 *
 * @param {object} spec
 * @param {string} spec.subject CN or full attr list
 * @param {object} spec.keyPair this cert's key pair
 * @param {object} [spec.issuer] { name: attrs, keyPair } — omit for self-signed
 * @param {Date} spec.notBefore
 * @param {Date} spec.notAfter
 * @param {number} [spec.serial]
 * @param {Array}  [spec.extensions] as produced by ext*() helpers
 * @param {object} [opts]
 * @param {boolean} [opts.v1] issue an X.509 v1 cert (no extensions field)
 * @param {object}  [opts.overrideIssuerName] force an issuer Name
 */
export async function buildCertificate(spec, opts = {}) {
  const subjectAttrs = typeof spec.subject === 'string' ? [{ type: 'CN', value: spec.subject }] : spec.subject;
  const issuerInfo = spec.issuer || { nameAttrs: subjectAttrs, keyPair: spec.keyPair };
  const issuerAttrs = issuerInfo.nameAttrs || (typeof issuerInfo.name === 'string'
    ? [{ type: 'CN', value: issuerInfo.name }]
    : issuerInfo.name);
  const effectiveIssuerAttrs = opts.overrideIssuerName || issuerAttrs;

  const serial = integerNumber(spec.serial ?? 1);
  const sigAlg = algorithmIdentifier();
  const issuerName = name(effectiveIssuerAttrs);
  const subjectName = name(subjectAttrs);
  const val = validity(spec.notBefore, spec.notAfter);
  const point = await rawPublicKeyBytes(spec.keyPair);
  const spki = seq(ecSpkiAlgorithm(), bitString(point, 0));

  let extensionsField = null;
  if (!opts.v1) {
    let exts = spec.extensions ? [...spec.extensions] : [];
    if (spec.includeSkid !== false) {
      exts = [{ oid: OIDS.skid, critical: false, der: octet(await keyId(spec.keyPair)) }, ...exts];
    }
    if (spec.includeAkid !== false) {
      exts.push(extAuthorityKeyIdentifier(await keyId(issuerInfo.keyPair || spec.keyPair)));
    }
    const extSeq = seq(concat(exts.map((e) => extension(e.oid, e.critical, e.der))));
    // [3] EXPLICIT Extensions
    extensionsField = ctxCons(3, extSeq);
  }

  // TBSCertificate
  const tbsParts = [];
  if (!opts.v1) tbsParts.push(ctxCons(0, integerNumber(2))); // version [0] v3
  tbsParts.push(
    serial,
    sigAlg,
    issuerName,
    val,
    subjectName,
    spki,
  );
  if (extensionsField) tbsParts.push(extensionsField);
  const tbs = seq(concat(tbsParts));

  const signKey = (issuerInfo.keyPair || spec.keyPair).privateKey;
  const rawSig = new Uint8Array(
    await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, signKey, tbs),
  );
  const derSig = toDerSignature(rawSig);

  const cert = seq(concat([tbs, sigAlg, bitString(derSig, 0)]));
  return {
    der: cert,
    tbs,
    subjectAttrs,
    issuerAttrs: effectiveIssuerAttrs,
    keyPair: spec.keyPair,
    subjectName,
  };
}

export async function pemFromSpec(spec, opts) {
  const built = await buildCertificate(spec, opts);
  const { toPem } = await import('./der-encoder.js');
  return { built, pem: toPem(built.der) };
}
