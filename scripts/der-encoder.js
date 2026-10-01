/**
 * DER encoder used only by the fixture generator (tests + page sample).
 * Mirrors the subset of structures the parser understands.
 */

export function derLen(len) {
  if (len < 0x80) return Uint8Array.from([len]);
  const bytes = [];
  let n = len;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n = Math.floor(n / 256);
  }
  return Uint8Array.from([0x80 | bytes.length, ...bytes]);
}

export function tlv(tag, content) {
  const body = content instanceof Uint8Array ? content : concat(content);
  return concat([Uint8Array.from([tag]), derLen(body.length), body]);
}

export function concat(parts) {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

export const seq = (...parts) => tlv(0x30, concat(parts));
export const setOf = (...parts) => tlv(0x31, concat(parts));
export const octet = (b) => tlv(0x04, b);
export const nullVal = () => Uint8Array.from([0x05, 0x00]);

export function integerBytes(bytes) {
  let b = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
  let start = 0;
  while (start < b.length - 1 && b[start] === 0) start++;
  b = b.subarray(start);
  if (b[0] & 0x80) b = Uint8Array.from([0, ...b]);
  return tlv(0x02, b);
}

export function integerNumber(n) {
  const bytes = [];
  let v = n;
  if (v === 0) bytes.push(0);
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v = Math.floor(v / 256);
  }
  return integerBytes(Uint8Array.from(bytes));
}

export function boolean(val) {
  return tlv(0x01, Uint8Array.from([val ? 0xff : 0x00]));
}

export function bitString(data, unusedBits = 0) {
  return tlv(0x03, concat([Uint8Array.from([unusedBits]), data]));
}

export function printable(s) {
  return tlv(0x13, new TextEncoder().encode(s));
}

export function ia5(s) {
  return tlv(0x16, new TextEncoder().encode(s));
}

export function utf8(s) {
  return tlv(0x0c, new TextEncoder().encode(s));
}

export function utcTime(date) {
  // YYMMDDHHMMSSZ, 1950-2049 per RFC 5280.
  const s =
    String(date.getUTCFullYear()).slice(2) +
    String(date.getUTCMonth() + 1).padStart(2, '0') +
    String(date.getUTCDate()).padStart(2, '0') +
    String(date.getUTCHours()).padStart(2, '0') +
    String(date.getUTCMinutes()).padStart(2, '0') +
    String(date.getUTCSeconds()).padStart(2, '0') +
    'Z';
  return tlv(0x17, new TextEncoder().encode(s));
}

export function generalizedTime(date) {
  const s =
    String(date.getUTCFullYear()) +
    String(date.getUTCMonth() + 1).padStart(2, '0') +
    String(date.getUTCDate()).padStart(2, '0') +
    String(date.getUTCHours()).padStart(2, '0') +
    String(date.getUTCMinutes()).padStart(2, '0') +
    String(date.getUTCSeconds()).padStart(2, '0') +
    'Z';
  return tlv(0x18, new TextEncoder().encode(s));
}

/** Encode an OID from dotted text. */
export function oid(text) {
  const arcs = text.split('.').map(Number);
  const out = [40 * arcs[0] + arcs[1]];
  for (let i = 2; i < arcs.length; i++) {
    let v = arcs[i];
    const groups = [v & 0x7f];
    v >>= 7;
    while (v > 0) {
      groups.unshift((v & 0x7f) | 0x80);
      v >>= 7;
    }
    out.push(...groups);
  }
  return tlv(0x06, Uint8Array.from(out));
}

/** Context-specific primitive, e.g. dNSName [2] IMPLICIT IA5String. */
export const ctxPrim = (n, content) => tlv(0x80 | n, content);
/** Context-specific constructed (explicit wrapper or IMPLICIT SEQUENCE OF). */
export const ctxCons = (n, content) => tlv(0xa0 | n, content);

export function toBase64(der) {
  return Buffer.from(der).toString('base64');
}

export function toPem(der) {
  const b64 = toBase64(der);
  const lines = [];
  for (let i = 0; i < b64.length; i += 64) lines.push(b64.slice(i, i + 64));
  return `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----\n`;
}
