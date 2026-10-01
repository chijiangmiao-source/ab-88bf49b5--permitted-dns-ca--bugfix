/**
 * Conversion of an ECDSA signature from the DER encoding carried inside an
 * X.509 certificate:
 *
 *   ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }
 *
 * into the fixed-width raw (r || s) byte string that WebCrypto's
 * ECDSA.verify expects for P-256 (32 + 32 = 64 bytes).
 *
 * DER INTEGERs may be shorter than 32 bytes (leading zeroes stripped), or
 * 33 bytes (leading 0x00 sign octet). Both are normalised exactly.
 */

import { TAG, DerError, parseExactly, childList, decodeUnsignedIntegerBytes } from './der.js';

const P256_FIELD_SIZE = 32;

/**
 * @param {Uint8Array} der signature bytes (content of the certificate's
 *        signature BIT STRING)
 * @returns {Uint8Array} 64-byte r||s
 */
export function ecdsaDerToRaw(der) {
  let seq;
  try {
    seq = parseExactly(der, TAG.SEQUENCE);
  } catch (e) {
    if (e instanceof DerError) throw new DerError(`ECDSA 签名 DER 解析失败：${e.message}`, e.offset);
    throw e;
  }
  const ints = childList(seq);
  if (ints.length !== 2) {
    throw new DerError(`ECDSA-Sig-Value 必须含 r、s 两个 INTEGER（实际 ${ints.length} 个）`, seq.start);
  }
  const [rTLV, sTLV] = ints;
  if (rTLV.tag !== TAG.INTEGER || sTLV.tag !== TAG.INTEGER) {
    throw new DerError('ECDSA-Sig-Value 的 r/s 必须是 INTEGER', rTLV.start);
  }
  const r = decodeUnsignedIntegerBytes(rTLV);
  const s = decodeUnsignedIntegerBytes(sTLV);
  if (r === null || s === null) {
    throw new DerError('ECDSA 签名的 r 或 s 为负数', rTLV.start);
  }
  if (r.length > P256_FIELD_SIZE || s.length > P256_FIELD_SIZE) {
    throw new DerError(
      `ECDSA 整数超出 P-256 阶长度（r=${r.length}, s=${s.length} 字节，上限 ${P256_FIELD_SIZE}）`,
      rTLV.start,
    );
  }
  const out = new Uint8Array(P256_FIELD_SIZE * 2);
  out.set(r, P256_FIELD_SIZE - r.length);
  out.set(s, P256_FIELD_SIZE * 2 - s.length);
  return out;
}
