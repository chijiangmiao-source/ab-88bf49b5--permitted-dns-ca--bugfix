/**
 * Minimal DER (BER restricted to DER) decoder used for X.509 parsing.
 *
 * The decoder preserves exact byte slices: every TLV keeps `start` (offset
 * of its tag byte) and `headerLen` so callers can extract the raw
 * tbsCertificate bytes that were actually signed by the issuer.
 */

export const TAG = {
  BOOLEAN: 0x01,
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OID: 0x06,
  UTF8_STRING: 0x0c,
  PRINTABLE_STRING: 0x13,
  TELETEX_STRING: 0x14,
  IA5_STRING: 0x16,
  UTC_TIME: 0x17,
  GENERALIZED_TIME: 0x18,
  BMP_STRING: 0x1e,
  SEQUENCE: 0x30,
  SET: 0x31,
};

const CONSTRUCTED = 0x20;

export class DerError extends Error {
  /**
   * @param {string} message
   * @param {number} [offset] byte offset in the source at which parsing failed
   */
  constructor(message, offset) {
    super(offset === undefined ? message : `${message} (at byte ${offset})`);
    this.name = 'DerError';
    this.offset = offset;
  }
}

/**
 * A decoded TLV node.
 * @typedef {Object} TLV
 * @property {number} tag      full tag byte (class/constructed bits retained)
 * @property {number} tagNum   low 6 bits of the tag
 * @property {number} start    byte offset of the tag in the source buffer
 * @property {number} headerLen length of tag + length octets
 * @property {number} contentStart
 * @property {number} length   content length
 * @property {number} end      offset just past this TLV
 * @property {Uint8Array} raw  exact bytes [start, end)
 * @property {Uint8Array} content exact content bytes
 */

/**
 * Read a single DER TLV beginning at `offset`.
 * @param {Uint8Array} buf
 * @param {number} offset
 * @returns {TLV}
 */
export function readTLV(buf, offset = 0) {
  const total = buf.length;
  if (offset >= total) {
    throw new DerError('unexpected end of DER: expected tag', offset);
  }
  const tagByte = buf[offset];
  const tagNum = tagByte & 0x1f;
  // High tag-number form is never needed for the structures we parse.
  if (tagNum === 0x1f) {
    throw new DerError('high-tag-number form is not supported', offset);
  }
  let p = offset + 1;
  if (p >= total) {
    throw new DerError('unexpected end of DER: missing length', p);
  }
  const first = buf[p++];
  let length;
  let lengthBytes = 1;
  if (first === 0x80) {
    throw new DerError('indefinite length is not valid DER', p - 1);
  }
  if ((first & 0x80) !== 0) {
    lengthBytes = first & 0x7f;
    if (lengthBytes === 0) {
      throw new DerError('invalid long-form length', p - 1);
    }
    if (lengthBytes > 4) {
      throw new DerError('length field too large', p - 1);
    }
    if (p + lengthBytes > total) {
      throw new DerError('truncated DER: length octets run past end', p);
    }
    length = 0;
    for (let i = 0; i < lengthBytes; i++) {
      length = length * 256 + buf[p + i];
    }
    p += lengthBytes;
  } else {
    length = first;
  }
  const headerLen = p - offset;
  const contentStart = p;
  const end = contentStart + length;
  if (end > total) {
    throw new DerError(
      `truncated DER: declared content length ${length} exceeds remaining ${total - contentStart} bytes`,
      contentStart,
    );
  }
  const raw = buf.subarray(offset, end);
  const content = buf.subarray(contentStart, end);
  return { tag: tagByte, tagNum, start: offset, headerLen, contentStart, length, end, raw, content };
}

/** Parse one TLV and require the whole buffer to be consumed. */
export function parseExactly(buf, expectedTag) {
  const tlv = readTLV(buf, 0);
  if (expectedTag !== undefined && tlv.tag !== expectedTag) {
    throw new DerError(
      `unexpected tag 0x${tlv.tag.toString(16)}, expected 0x${expectedTag.toString(16)}`,
      tlv.start,
    );
  }
  if (tlv.end !== buf.length) {
    throw new DerError(`${buf.length - tlv.end} trailing byte(s) after top-level TLV`, tlv.end);
  }
  return tlv;
}

/** Iterate the children of a constructed TLV. */
export function* children(tlv) {
  const buf = tlv.content;
  let offset = 0;
  while (offset < buf.length) {
    const child = readTLV(buf, offset);
    yield child;
    offset = child.end;
  }
}

/** Children as an array. */
export function childList(tlv) {
  return Array.from(children(tlv));
}

/** Find and return the nth (0-based) child, optionally requiring its tag. */
export function nthChild(tlv, index, expectedTag) {
  let i = 0;
  for (const child of children(tlv)) {
    if (i === index) {
      if (expectedTag !== undefined && child.tag !== expectedTag) {
        throw new DerError(
          `child ${index}: unexpected tag 0x${child.tag.toString(16)}, expected 0x${expectedTag.toString(16)}`,
          tlv.contentStart + child.start,
        );
      }
      return child;
    }
    i++;
  }
  throw new DerError(`child index ${index} not present`);
}

export function isConstructed(tlv) {
  return (tlv.tag & CONSTRUCTED) !== 0;
}

// ---------------------------------------------------------------------------
// Primitive value decoders
// ---------------------------------------------------------------------------

/** Decode a BOOLEAN (DER mandates 0x00 / 0xff). */
export function decodeBoolean(tlv) {
  if (tlv.length !== 1) {
    throw new DerError('BOOLEAN must be one byte', tlv.contentStart);
  }
  return tlv.content[0] !== 0;
}

/**
 * Decode an INTEGER's content. Returns null for negative integers (which the
 * fields we care about never are). X.509 serial/certificate values read here
 * are all non-negative.
 */
export function decodeUnsignedIntegerBytes(tlv) {
  if (tlv.length === 0) throw new DerError('zero-length INTEGER', tlv.contentStart);
  const b = tlv.content;
  if (b[0] & 0x80) {
    // Negative integer — not expected for version/serial/sig values.
    return null;
  }
  // Strip leading zeroes, keep at least one byte.
  let start = 0;
  while (start < b.length - 1 && b[start] === 0) start++;
  return b.subarray(start);
}

export function decodeInteger(tlv) {
  if (tlv.length === 0) throw new DerError('zero-length INTEGER', tlv.contentStart);
  const b = tlv.content;
  let value = 0;
  // Values used as small integers (version) fit comfortably; serial numbers
  // are read via decodeUnsignedIntegerBytes instead.
  if (b[0] & 0x80) throw new DerError('negative integer where small non-negative expected', tlv.contentStart);
  for (let i = 0; i < b.length; i++) {
    if (value > 0xffffffff) throw new DerError('integer too large for number', tlv.contentStart);
    value = value * 256 + b[i];
  }
  return value;
}

/** Decode an OBJECT IDENTIFIER into dotted-decimal text. */
export function decodeOID(tlv) {
  const b = tlv.content;
  if (b.length === 0) throw new DerError('zero-length OID', tlv.contentStart);
  // First two arcs are packed into the first byte: X = 40*arc1 + arc2,
  // except that when arc1 is 2, arc2 may exceed 39.
  let arc1;
  if (b[0] < 40) arc1 = 0;
  else if (b[0] < 80) arc1 = 1;
  else arc1 = 2;
  const parts = [arc1, b[0] - 40 * arc1];
  let value = 0;
  for (let i = 1; i < b.length; i++) {
    value = value * 128 + (b[i] & 0x7f);
    if ((b[i] & 0x80) === 0) {
      parts.push(value);
      value = 0;
    }
  }
  if (b.length > 1 && (b[b.length - 1] & 0x80) !== 0) {
    throw new DerError('truncated OID: last base-128 group continues', tlv.end);
  }
  return parts.join('.');
}

/** Decode UTCTime (YY...) / GeneralizedTime (YYYY...) as Date + epoch ms. */
export function decodeTime(tlv) {
  const b = tlv.content;
  const str = new TextDecoder().decode(b);
  const generalized = tlv.tag === TAG.GENERALIZED_TIME;
  const m = generalized
    ? /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(str)
    : /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(str);
  if (!m) {
    throw new DerError(
      `unsupported time format "${str}" (only Zulu seconds form accepted)`,
      tlv.contentStart,
    );
  }
  let year;
  if (generalized) {
    year = Number(m[1]);
  } else {
    const yy = Number(m[1]);
    // RFC 5280 4.1.2.5: UTCTime in 1950-2049.
    year = yy >= 50 ? 1900 + yy : 2000 + yy;
  }
  const month = Number(m[2]) - 1;
  const day = Number(m[3]);
  const hour = Number(m[4]);
  const minute = Number(m[5]);
  const second = Number(m[6]);
  const date = new Date(Date.UTC(year, month, day, hour, minute, second));
  // Reject e.g. month 13 or day overflow that the Date constructor silently
  // rolls over.
  if (
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() !== month ||
    date.getUTCDate() !== day ||
    date.getUTCHours() !== hour ||
    date.getUTCMinutes() !== minute ||
    date.getUTCSeconds() !== second
  ) {
    throw new DerError(`invalid calendar date in time "${str}"`, tlv.contentStart);
  }
  return date;
}

/**
 * Read a BIT STRING: returns { unusedBits, bytes }. For SubjectPublicKeyInfo
 * bit strings DER requires unusedBits === 0 for byte-aligned keys.
 */
export function decodeBitString(tlv) {
  if (tlv.length === 0) throw new DerError('zero-length BIT STRING', tlv.contentStart);
  const unusedBits = tlv.content[0];
  if (unusedBits > 7) throw new DerError('BIT STRING unused-bits count out of range', tlv.contentStart);
  const bytes = tlv.content.subarray(1);
  if (unusedBits !== 0 && bytes.length === 0) {
    throw new DerError('BIT STRING with unused bits but no data', tlv.contentStart);
  }
  return { unusedBits, bytes };
}

/** Decode any commonly-used DirectoryString choice as JS text. */
export function decodeDirectoryString(tlv) {
  const tag = tlv.tag;
  if (
    tag !== TAG.UTF8_STRING &&
    tag !== TAG.PRINTABLE_STRING &&
    tag !== TAG.IA5_STRING &&
    tag !== TAG.TELETEX_STRING &&
    tag !== TAG.BMP_STRING
  ) {
    throw new DerError(`unsupported string tag 0x${tag.toString(16)} in name`, tlv.start);
  }
  if (tag === TAG.BMP_STRING) {
    // UTF-16BE
    let out = '';
    for (let i = 0; i + 1 < tlv.content.length; i += 2) {
      out += String.fromCharCode((tlv.content[i] << 8) | tlv.content[i + 1]);
    }
    return out;
  }
  // TELETEX (T61) is technically Latin-1-ish; decode as latin1 is a pragmatic
  // superset for the ASCII CN/O values used here.
  return new TextDecoder(tag === TAG.TELETEX_STRING ? 'latin1' : 'utf-8').decode(tlv.content);
}

/** Convert raw bytes to a lowercase hex string. */
export function toHex(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) {
    s += bytes[i].toString(16).padStart(2, '0');
  }
  return s;
}
