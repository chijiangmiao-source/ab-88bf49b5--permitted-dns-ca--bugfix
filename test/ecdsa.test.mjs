import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ecdsaDerToRaw } from '../src/app/crypto/ecdsa.js';
import { DerError } from '../src/app/crypto/der.js';
import { seq, integerBytes } from '../scripts/der-encoder.js';

test('short r/s are zero-padded on the left to 32 bytes each', () => {
  const r = Uint8Array.from([0x01, 0x02, 0x03]);
  const s = Uint8Array.from(Array(32).fill(0x44));
  const raw = ecdsaDerToRaw(seq(integerBytes(r), integerBytes(s)));
  assert.equal(raw.length, 64);
  assert.equal(raw[29], 0x01);
  assert.equal(raw[31], 0x03);
  assert.equal(raw[32], 0x44);
  assert.equal(raw[63], 0x44);
  assert.ok(raw.subarray(0, 29).every((b) => b === 0));
});

test('33-byte INTEGER with leading sign octet is reduced to 32', () => {
  const r = Uint8Array.from([0x00, 0xff, ...Array(31).fill(0x11)]); // 33 bytes, high bit set
  const s = Uint8Array.from(Array(32).fill(0x22));
  const raw = ecdsaDerToRaw(seq(integerBytes(r), integerBytes(s)));
  assert.equal(raw[0], 0xff);
  assert.equal(raw[31], 0x11);
});

test('integer exceeding field order length is rejected', () => {
  const big = Uint8Array.from(Array(33).fill(0x01)); // no sign octet, 33 bytes positive
  assert.throws(() => ecdsaDerToRaw(seq(integerBytes(big), integerBytes(Uint8Array.from([1])))), DerError);
});

test('malformed/truncated signature DER reports DerError', () => {
  const good = seq(integerBytes(Uint8Array.from([1])), integerBytes(Uint8Array.from([2])));
  assert.throws(() => ecdsaDerToRaw(good.subarray(0, good.length - 2)), DerError);
  assert.throws(() => ecdsaDerToRaw(Uint8Array.from([0x02, 0x01, 0x01])), DerError); // not a SEQUENCE
  assert.throws(
    () => ecdsaDerToRaw(seq(integerBytes(Uint8Array.from([1])))),
    /r、s 两个 INTEGER/,
  );
});
