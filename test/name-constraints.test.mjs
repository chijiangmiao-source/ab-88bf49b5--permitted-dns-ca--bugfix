/**
 * Multi-level permittedSubtrees intersection scenarios (RFC 5280 4.2.1.10).
 *
 * The three-cert chains here exist only in memory: keys and certs are built
 * with the same fixture builder (P-256, X.509 v3, ECDSA-SHA256) and run
 * through the production verifyChain module.
 *
 * Primary scenario:
 *   root : permittedSubtrees = example.com
 *   mid  : permittedSubtrees = ground.example
 *   leaf : SAN / checked DNS name = telemetry.example.com
 *
 * The leaf name satisfies the root's broad permit but not the intermediate's
 * narrower permit, so it must be rejected: every CA that states a non-empty
 * permittedSubtrees has to be satisfied independently.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyChain, CHECK_NAMES } from '../src/app/crypto/verifier.js';
import {
  generateKeyPair, buildCertificate, extBasicConstraints, extKeyUsage,
  extSubjectAltName, extNameConstraints,
} from '../scripts/cert-builder.js';
import { toPem } from '../scripts/der-encoder.js';

const D = (y, mo, d) => new Date(Date.UTC(y, mo - 1, d));
const VERIFY_TIME = Date.UTC(2026, 0, 1); // 2026-01-01, covered by every cert below
const CA_KU = () => extKeyUsage(['keyCertSign', 'cRLSign']);
const LEAF_KU = () => extKeyUsage(['digitalSignature']);

/**
 * Build root(permit example.com) -> mid(permit midPermit) -> leaf(SAN leafName).
 * @param {string} midPermit dNSName in the intermediate's permittedSubtrees
 * @param {string} leafName dNSName in the leaf SAN
 */
async function buildCrossConstraintChain(midPermit, leafName) {
  const kRoot = await generateKeyPair();
  const kMid = await generateKeyPair();
  const kLeaf = await generateKeyPair();

  const root = await buildCertificate({
    subject: 'Cross-Constraint Root CA (permit example.com)',
    keyPair: kRoot,
    notBefore: D(2024, 1, 1), notAfter: D(2036, 1, 1),
    serial: 0x1001,
    extensions: [
      extBasicConstraints({ cA: true, pathLen: 2 }), CA_KU(),
      extNameConstraints({ permitted: ['example.com'] }),
    ],
  });
  const mid = await buildCertificate({
    subject: `Cross-Constraint Intermediate CA (permit ${midPermit})`,
    keyPair: kMid,
    issuer: { nameAttrs: root.subjectAttrs, keyPair: kRoot },
    notBefore: D(2025, 1, 1), notAfter: D(2031, 1, 1),
    serial: 0x2001,
    extensions: [
      extBasicConstraints({ cA: true, pathLen: 0 }), CA_KU(),
      extNameConstraints({ permitted: [midPermit] }),
    ],
  });
  const leaf = await buildCertificate({
    subject: leafName,
    keyPair: kLeaf,
    issuer: { nameAttrs: mid.subjectAttrs, keyPair: kMid },
    notBefore: D(2026, 1, 1), notAfter: D(2027, 1, 1),
    serial: 0x3001,
    extensions: [
      extBasicConstraints({ cA: false }), LEAF_KU(),
      extSubjectAltName([leafName]),
    ],
  });
  return {
    anchorText: toPem(root.der),
    poolText: [toPem(mid.der), toPem(leaf.der)].join('\n'),
  };
}

test('name constraints: leaf matching the root permit but violating the intermediate permit is rejected', async () => {
  const chain = await buildCrossConstraintChain('ground.example', 'telemetry.example.com');
  const r = await verifyChain({ ...chain, dnsName: 'telemetry.example.com', verifyTimeMs: VERIFY_TIME });
  assert.equal(r.ok, false, 'chain must not be accepted');
  // failure must be attributable to a DNS name constraint
  assert.equal(r.failure.check, CHECK_NAMES.NAME_CONSTRAINTS);
  assert.match(r.failure.reason, /permittedSubtrees/);
  // the narrower intermediate restriction is what blocks the name
  assert.match(r.failure.reason, /ground\.example/);
});

test('name constraints: leaf inside both permitted subtrees still verifies (normal chains unaffected)', async () => {
  // ground.example.com genuinely lies within example.com, so both per-CA
  // permitted sets are satisfied and the chain must validate as before.
  const chain = await buildCrossConstraintChain('ground.example.com', 'telemetry.ground.example.com');
  const r = await verifyChain({ ...chain, dnsName: 'telemetry.ground.example.com', verifyTimeMs: VERIFY_TIME });
  assert.equal(r.ok, true, JSON.stringify(r.failure));
  assert.equal(r.chain.length, 3);
});
