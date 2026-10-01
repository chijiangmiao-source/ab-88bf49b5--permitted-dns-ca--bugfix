/**
 * Edge cases that need bespoke certificates rather than the static fixture
 * set: validity boundaries and an expired-but-present trust anchor.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyChain, CHECK_NAMES } from '../src/app/crypto/verifier.js';
import { toPem } from '../scripts/der-encoder.js';
import {
  generateKeyPair, buildCertificate,
  extBasicConstraints, extKeyUsage, extSubjectAltName,
} from '../scripts/cert-builder.js';

const D = (y, mo, d, h = 0, mi = 0, s = 0) => new Date(Date.UTC(y, mo - 1, d, h, mi, s));
const CA_KU = () => extKeyUsage(['keyCertSign', 'cRLSign']);
const LEAF_KU = () => extKeyUsage(['digitalSignature']);

async function hierarchy({ rootWindow, midWindow, leafWindow }) {
  const kRoot = await generateKeyPair();
  const kMid = await generateKeyPair();
  const kLeaf = await generateKeyPair();
  const root = await buildCertificate({
    subject: 'Temporal Root', keyPair: kRoot,
    notBefore: rootWindow[0], notAfter: rootWindow[1], serial: 1,
    extensions: [extBasicConstraints({ cA: true, pathLen: 2 }), CA_KU()],
  });
  const mid = await buildCertificate({
    subject: 'Temporal Mid', keyPair: kMid,
    issuer: { nameAttrs: root.subjectAttrs, keyPair: kRoot },
    notBefore: midWindow[0], notAfter: midWindow[1], serial: 2,
    extensions: [extBasicConstraints({ cA: true, pathLen: 0 }), CA_KU()],
  });
  const leaf = await buildCertificate({
    subject: 'tick.example', keyPair: kLeaf,
    issuer: { nameAttrs: mid.subjectAttrs, keyPair: kMid },
    notBefore: leafWindow[0], notAfter: leafWindow[1], serial: 3,
    extensions: [extBasicConstraints({ cA: false }), LEAF_KU(), extSubjectAltName(['tick.example'])],
  });
  return { rootPem: toPem(root.der), midPem: toPem(mid.der), leafPem: toPem(leaf.der) };
}

const runAt = (h, t) =>
  verifyChain({ anchorText: h.rootPem, poolText: [h.leafPem, h.midPem].join('\n'), dnsName: 'tick.example', verifyTimeMs: t });

test('validity interval is inclusive on both boundaries (notBefore / notAfter)', async () => {
  const h = await hierarchy({
    rootWindow: [D(2024, 1, 1), D(2036, 1, 1)],
    midWindow: [D(2025, 1, 1), D(2031, 1, 1)],
    leafWindow: [D(2026, 6, 15, 12, 0, 0), D(2026, 6, 15, 12, 0, 0)],
  });
  const atStart = await runAt(h, Date.UTC(2026, 5, 15, 12, 0, 0));
  assert.equal(atStart.ok, true, JSON.stringify(atStart.failure));
});

test('one second past notAfter rejects', async () => {
  const h = await hierarchy({
    rootWindow: [D(2024, 1, 1), D(2036, 1, 1)],
    midWindow: [D(2025, 1, 1), D(2031, 1, 1)],
    leafWindow: [D(2026, 6, 15, 12, 0, 0), D(2026, 6, 15, 12, 0, 0)],
  });
  const r = await runAt(h, Date.UTC(2026, 5, 15, 12, 0, 1));
  assert.equal(r.ok, false);
  assert.equal(r.failure.check, CHECK_NAMES.VALIDITY);
});

test('expired trust anchor is rejected even though descendants are in window', async () => {
  const h = await hierarchy({
    rootWindow: [D(2020, 1, 1), D(2025, 12, 31)], // anchor already expired at verify time
    midWindow: [D(2025, 1, 1), D(2031, 1, 1)],
    leafWindow: [D(2026, 1, 1), D(2027, 1, 1)],
  });
  const r = await runAt(h, Date.UTC(2026, 5, 15, 12, 0, 0));
  assert.equal(r.ok, false);
  assert.equal(r.failure.check, CHECK_NAMES.VALIDITY);
  assert.match(r.failure.reason, /notAfter|过期/);
  // The failing certificate is the anchor itself (level 2 in a 3-cert chain).
  assert.equal(r.failure.level, 2);
  assert.equal(r.failure.role, '信任锚');
});

test('not-yet-valid trust anchor is rejected', async () => {
  const h = await hierarchy({
    rootWindow: [D(2027, 1, 1), D(2036, 1, 1)],
    midWindow: [D(2025, 1, 1), D(2031, 1, 1)],
    leafWindow: [D(2026, 1, 1), D(2027, 1, 1)],
  });
  const r = await runAt(h, Date.UTC(2026, 5, 15, 12, 0, 0));
  assert.equal(r.ok, false);
  assert.equal(r.failure.check, CHECK_NAMES.VALIDITY);
});
