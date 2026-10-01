import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  readTLV, parseExactly, childList, decodeOID, decodeTime, decodeBitString,
  decodeInteger, decodeUnsignedIntegerBytes, DerError, toHex,
} from '../src/app/crypto/der.js';
import {
  seq, integerNumber, integerBytes, oid, utcTime, bitString, toBase64,
} from '../scripts/der-encoder.js';

test('OID round trip: P-256 and ecdsa-with-SHA256', () => {
  for (const text of ['1.2.840.10045.2.1', '1.2.840.10045.4.3.2', '1.2.840.10045.3.1.7', '2.5.29.30']) {
    const tlv = readTLV(oid(text), 0);
    assert.equal(decodeOID(tlv), text);
  }
});

test('OID first arcs: 0.x / 1.x / 2.x packing and multi-byte later arcs', () => {
  assert.equal(decodeOID(readTLV(oid('0.0'), 0)), '0.0');
  assert.equal(decodeOID(readTLV(oid('1.2'), 0)), '1.2');
  assert.equal(decodeOID(readTLV(oid('2.100'), 0)), '2.100'); // 80+20 = 0x64
  assert.equal(decodeOID(readTLV(oid('1.2.999999'), 0)), '1.2.999999'); // multi-byte group
});

test('integer long form keeps leading-zero/non-leading bytes', () => {
  const enc = (n) => readTLV(integerNumber(n), 0);
  assert.equal(decodeInteger(enc(0)), 0);
  assert.equal(decodeInteger(enc(255)), 255);
  assert.equal(decodeInteger(enc(0x1001)), 0x1001);
  // 32-byte high-bit value keeps sign octet
  const big = integerBytes(Uint8Array.from(Array(32).fill(0xff)));
  const bytes = decodeUnsignedIntegerBytes(readTLV(big, 0));
  assert.equal(bytes.length, 32);
  assert.equal(bytes[0], 0xff);
});

test('truncated DER raises DerError with an offset', () => {
  const good = seq(oid('1.2.3'), integerNumber(7));
  assert.throws(() => parseExactly(good.subarray(0, good.length - 3)), (e) => {
    return e instanceof DerError && typeof e.offset === 'number';
  });
  // declared long length overruns
  assert.throws(() => readTLV(Uint8Array.from([0x30, 0x82, 0x01, 0x00]), 0), DerError);
  // indefinite length forbidden in DER
  assert.throws(() => readTLV(Uint8Array.from([0x30, 0x80, 0x00, 0x00]), 0), DerError);
});

test('trailing bytes after top-level TLV rejected', () => {
  const good = seq(integerNumber(1));
  assert.throws(() => parseExactly(Uint8Array.from([...good, 0x00])), DerError);
});

test('BIT STRING unused-bits prefix', () => {
  const bs = decodeBitString(readTLV(bitString(Uint8Array.from([0xaa, 0x80]), 7), 0));
  assert.equal(bs.unusedBits, 7);
  assert.equal(toHex(bs.bytes), 'aa80');
  assert.throws(() => decodeBitString(readTLV(Uint8Array.from([0x03, 0x01, 0x08]), 0)), DerError);
});

test('UTCTime century pivot and strict calendar validation', () => {
  const t1 = decodeTime(readTLV(utcTime(new Date(Date.UTC(2049, 11, 31, 23, 59, 59))), 0));
  assert.equal(t1.getUTCFullYear(), 2049);
  // month 13 must be rejected rather than rolled over
  const enc = new TextEncoder().encode('261301000000Z');
  assert.throws(() => decodeTime({ tag: 0x17, content: enc, start: 0, contentStart: 0, end: enc.length }), DerError);
});
