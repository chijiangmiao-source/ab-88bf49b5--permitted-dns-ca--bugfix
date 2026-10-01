/**
 * WebCrypto wrapper used both in the browser Worker and in the Node-based
 * logical test suite (Node 20 exposes the same webcrypto global).
 *
 * Keys are imported as raw uncompressed P-256 points from
 * SubjectPublicKeyInfo... note that WebCrypto's 'raw' EC import wants just
 * the point (0x04||X||Y), which x509.js has already extracted.
 */

import { OID } from './oids.js';

function subtle() {
  const c = globalThis.crypto;
  if (!c || !c.subtle) {
    throw new Error('当前环境不支持 WebCrypto subtle API');
  }
  return c.subtle;
}

export async function sha256(bytes) {
  const digest = await subtle().digest('SHA-256', bytes);
  return new Uint8Array(digest);
}

export function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Import a parsed certificate's public key for ECDSA verification.
 * Caller has already established (via the profile check) that this is a
 * 65-byte uncompressed P-256 point.
 * @param {{spki:{point: Uint8Array, algorithm:{oid:string}}}} cert
 */
export async function importCertPublicKey(cert) {
  if (cert.spki.algorithm.oid !== OID.EC_PUBLIC_KEY) {
    throw new Error('仅支持 id-ecPublicKey 公钥');
  }
  return subtle().importKey(
    'raw',
    cert.spki.point,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify'],
  );
}

/**
 * Verify an ECDSA-with-SHA-256 signature.
 * @param {CryptoKey} issuerKey
 * @param {Uint8Array} rawSignature 64-byte r||s (see ecdsa.js)
 * @param {Uint8Array} tbsRaw exact tbsCertificate bytes
 */
export async function verifyEcdsaSha256(issuerKey, rawSignature, tbsRaw) {
  try {
    return await subtle().verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      issuerKey,
      rawSignature,
      tbsRaw,
    );
  } catch (e) {
    // Malformed inputs make SubtleCrypto throw rather than return false.
    throw new Error(`WebCrypto 验签调用失败：${e.message || e}`);
  }
}
