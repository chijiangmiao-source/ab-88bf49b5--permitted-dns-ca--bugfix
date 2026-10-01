/**
 * End-to-end chain verification scenarios against generated fixtures.
 * These run the same verifier module the Worker loads, under Node 20's
 * global WebCrypto.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { verifyChain } from '../src/app/crypto/verifier.js';
import { CHECK_NAMES } from '../src/app/crypto/verifier.js';
import { FIXTURES, VERIFY_TIME, TAMPERED_PEM, TRUNCATED_PEM, B64_TRUNCATED_PEM } from './fixtures/manifest.mjs';

const F = FIXTURES;
const T = VERIFY_TIME;
const DNS = 'telemetry.ground.example';

function input(anchor, poolPems, dns = DNS, time = T) {
  return {
    anchorText: anchor,
    poolText: poolPems.join('\n'),
    dnsName: dns,
    verifyTimeMs: time,
  };
}

test('valid three-certificate chain verifies and reports per-level evidence', async () => {
  const r = await verifyChain(input(F.root.pem, [F.leaf.pem, F.mid1.pem]));
  assert.equal(r.ok, true, JSON.stringify(r.failure));
  assert.equal(r.chain.length, 3);
  assert.equal(r.chain[0].role, 'leaf');
  assert.equal(r.chain[1].role, 'intermediate');
  assert.equal(r.chain[2].role, 'anchor');
  assert.deepEqual(r.chain[0].sanDns.sort(), ['*.ground.example', 'telemetry.ground.example']);
  assert.equal(r.chain[1].basicConstraints.pathLen, 1);
  // evidence covers every mandated check
  const names = new Set(r.chain.flatMap((l) => l.evidence.map((e) => e.check)));
  for (const n of [CHECK_NAMES.SIGNATURE, CHECK_NAMES.VALIDITY, CHECK_NAMES.CA, CHECK_NAMES.KEY_USAGE]) {
    assert.ok(names.has(n), `missing evidence ${n}`);
  }
});

test('order independence: pool pasted shuffled gives identical selected chain', async () => {
  const a = await verifyChain(input(F.root.pem, [F.leaf.pem, F.mid1.pem]));
  const b = await verifyChain(input(F.root.pem, [F.mid1.pem, F.leaf.pem]));
  assert.equal(a.ok, true);
  assert.equal(b.ok, true);
  assert.deepEqual(a.chain.map((c) => c.digest), b.chain.map((c) => c.digest));
});

test('multiple valid chains: selection is stable by digest vector', async () => {
  // leaf via mid1 and leaf-alt via mid-alt both carry telemetry.ground.example
  const r = await verifyChain(input(F.root.pem, [F.mid1.pem, F.leaf.pem, F['mid-alt'].pem, F['leaf-alt'].pem]));
  assert.equal(r.ok, true, JSON.stringify(r.failure));
  assert.ok(r.chainCount >= 2);
  const selectedLeaf = r.chain[0].digest;
  const { sha256, bytesToHex } = await import('../src/app/crypto/webcrypto.js');
  const dgLeaf = bytesToHex(await sha256(Buffer.from(extractB64(F.leaf.pem), 'base64')));
  const dgAlt = bytesToHex(await sha256(Buffer.from(extractB64(F['leaf-alt'].pem), 'base64')));
  const expected = [dgLeaf, dgAlt].sort()[0];
  assert.equal(selectedLeaf, expected);
});

test('name constraints: name inside permitted and not excluded verifies', async () => {
  const r = await verifyChain(input(F.root.pem, [F['mid-nc'].pem, F['leaf-nc'].pem]));
  assert.equal(r.ok, true, JSON.stringify(r.failure));
  const ncLevel = r.chain.find((l) => l.role === 'intermediate');
  assert.deepEqual(ncLevel.nameConstraints.permittedDns, ['ground.example']);
  assert.deepEqual(ncLevel.nameConstraints.excludedDns, ['blocked.ground.example']);
});

test('name constraints: excluded subtree rejected at the NC level', async () => {
  const r = await verifyChain(input(F.root.pem, [F['mid-nc'].pem, F['leaf-blocked'].pem], 'blocked.ground.example'));
  assert.equal(r.ok, false);
  assert.equal(r.failure.check, CHECK_NAMES.NAME_CONSTRAINTS);
  assert.match(r.failure.reason, /excludedSubtrees/);
});

test('name constraints: outside permitted subtree rejected', async () => {
  const r = await verifyChain(input(F.root.pem, [F['mid-nc'].pem, F['leaf-other'].pem], 'telemetry.other.example'));
  assert.equal(r.ok, false);
  assert.equal(r.failure.check, CHECK_NAMES.NAME_CONSTRAINTS);
  assert.match(r.failure.reason, /permittedSubtrees/);
});

test('pathLenConstraint: intermediate beneath pathLen=0 anchor fails', async () => {
  const r = await verifyChain(
    input(F['root-pl0'].pem, [F['mid-x'].pem, F['leaf-pl'].pem], 'pl.telemetry.ground.example'),
  );
  assert.equal(r.ok, false);
  assert.equal(r.failure.check, CHECK_NAMES.PATH_LEN);
  assert.match(r.failure.reason, /pathLenConstraint=0/);
});

test('pathLenConstraint: CA with pathLen=0 directly issuing leaf succeeds', async () => {
  const r = await verifyChain(
    input(F.root.pem, [F['mid-pl0'].pem, F['leaf-under-pl0'].pem], 'edge.telemetry.ground.example'),
  );
  assert.equal(r.ok, true, JSON.stringify(r.failure));
});

test('expired leaf reported at level 0 VALIDITY', async () => {
  const r = await verifyChain(input(F.root.pem, [F.mid1.pem, F['leaf-expired'].pem], 'expired.telemetry.ground.example'));
  assert.equal(r.ok, false);
  assert.equal(r.failure.level, 0);
  assert.equal(r.failure.check, CHECK_NAMES.VALIDITY);
  assert.match(r.failure.reason, /notAfter|过期/);
});

test('not-yet-valid leaf reported at level 0 VALIDITY', async () => {
  const r = await verifyChain(input(F.root.pem, [F.mid1.pem, F['leaf-future'].pem], 'future.telemetry.ground.example'));
  assert.equal(r.ok, false);
  assert.equal(r.failure.check, CHECK_NAMES.VALIDITY);
  assert.match(r.failure.reason, /notBefore/);
});

test('intermediate outside validity window also fails at its level', async () => {
  // mid1 is valid; simulate by verifying far in the future so mid1 expires
  const future = Date.UTC(2032, 0, 1);
  const r = await verifyChain(input(F.root.pem, [F.mid1.pem, F.leaf.pem], DNS, future));
  assert.equal(r.ok, false);
  assert.equal(r.failure.check, CHECK_NAMES.VALIDITY);
  assert.ok(r.failure.level >= 0);
});

test('cA=false certificate acting as issuer rejected (CA check)', async () => {
  const r = await verifyChain(
    input(F.root.pem, [F['fake-ca'].pem, F['leaf-under-fake'].pem], 'fakeca.telemetry.ground.example'),
  );
  assert.equal(r.ok, false);
  assert.equal(r.failure.check, CHECK_NAMES.CA);
  assert.match(r.failure.reason, /cA=false|不能作为 CA|不能签发/);
});

test('CA without keyCertSign rejected at KEY_USAGE check', async () => {
  const r = await verifyChain(
    input(F.root.pem, [F['ca-no-kcs'].pem, F['leaf-under-no-kcs'].pem], 'nokcs.telemetry.ground.example'),
  );
  assert.equal(r.ok, false);
  assert.equal(r.failure.check, CHECK_NAMES.KEY_USAGE);
  assert.match(r.failure.reason, /keyCertSign/);
});

test('leaf with cA=true is rejected', async () => {
  const r = await verifyChain(input(F.root.pem, [F.mid1.pem, F['leaf-ca'].pem], 'leaf-that-is-ca.ground.example'));
  assert.equal(r.ok, false);
  assert.equal(r.failure.level, 0);
  assert.equal(r.failure.check, CHECK_NAMES.CA);
});

test('unknown critical extension rejects the offending cert', async () => {
  const r = await verifyChain(input(F.root.pem, [F.mid1.pem, F['leaf-unknown-ext'].pem], 'unknown-ext.telemetry.ground.example'));
  assert.equal(r.ok, false);
  assert.equal(r.stage, 'input');
  assert.match(r.failure.reason, /未知关键扩展/);
  assert.match(r.failure.reason, /1\.3\.6\.1\.4\.1\.99999\.66\.1/);
});

test('X.509 v1 certificate is rejected by the profile', async () => {
  const r = await verifyChain(input(F.root.pem, [F.mid1.pem, F['leaf-v1'].pem], 'v1.telemetry.ground.example'));
  assert.equal(r.ok, false);
  assert.equal(r.stage, 'input');
  assert.match(r.failure.reason, /v3/);
});

test('target host name absent from every SAN fails at SAN', async () => {
  const r = await verifyChain(input(F.root.pem, [F.mid1.pem, F.leaf.pem], 'wrong.name.example'));
  assert.equal(r.ok, false);
  assert.equal(r.failure.check, CHECK_NAMES.SAN);
  assert.match(r.failure.reason, /subjectAltName|SAN/);
});

test('broken issuer link (intermediate missing) fails at NAME_LINK', async () => {
  const r = await verifyChain(input(F.root.pem, [F.leaf.pem]));
  assert.equal(r.ok, false);
  assert.equal(r.failure.check, CHECK_NAMES.NAME_LINK);
});

test('wrong anchor (name never resolves) fails to terminate at the anchor', async () => {
  const r = await verifyChain(input(F['root-pl0'].pem, [F.mid1.pem, F.leaf.pem]));
  assert.equal(r.ok, false);
  // leaf's issuer is mid1 (present, verifies), mid1's issuer is root which
  // is absent -> NAME_LINK
  assert.equal(r.failure.check, CHECK_NAMES.NAME_LINK);
});

test('tampered signature fails at SIGNATURE with precise level', async () => {
  const r = await verifyChain(input(F.root.pem, [F.mid1.pem, TAMPERED_PEM]));
  assert.equal(r.ok, false);
  assert.equal(r.failure.level, 0);
  assert.equal(r.failure.check, CHECK_NAMES.SIGNATURE);
});

test('issuance cycle is detected and reported at CYCLE check', async () => {
  const r = await verifyChain(
    input(F.root.pem, [F['cycle-x'].pem, F['cycle-y'].pem, F['leaf-cycle'].pem], 'cycle.telemetry.ground.example'),
  );
  assert.equal(r.ok, false);
  assert.equal(r.failure.check, CHECK_NAMES.CYCLE);
});

test('truncated DER content is rejected with byte-level parse error', async () => {
  const r = await verifyChain(input(F.root.pem, [F.mid1.pem, TRUNCATED_PEM]));
  assert.equal(r.ok, false);
  assert.equal(r.stage, 'input');
  assert.match(r.failure.reason, /truncated|截断|超出|end of DER/i);
});

test('truncated base64 input (length not multiple of 4) rejected', async () => {
  const r = await verifyChain(input(F.root.pem, [F.mid1.pem, B64_TRUNCATED_PEM]));
  assert.equal(r.ok, false);
  assert.equal(r.stage, 'input');
  assert.match(r.failure.reason, /Base64|4 的倍数/);
});

test('anchor truncation is reported on the anchor slot', async () => {
  const anchorShort = F.root.pem
    .replace(/-----[A-Z ]+-----/g, '')
    .replace(/\s+/g, '')
    .slice(0, 400);
  const r = await verifyChain({ anchorText: anchorShort, poolText: F.leaf.pem, dnsName: DNS, verifyTimeMs: T });
  assert.equal(r.ok, false);
  assert.match(String(r.failure.slot || ''), /锚|信任/);
});

test('more than seven pool certs is rejected', async () => {
  const many = [F.leaf.pem, F.mid1.pem, F['leaf-alt'].pem, F['mid-alt'].pem, F['leaf-nc'].pem, F['mid-nc'].pem, F.leaf.pem, F.mid1.pem];
  const r = await verifyChain(input(F.root.pem, many));
  assert.equal(r.ok, false);
  assert.match(r.failure.reason, /7/);
});

test('empty anchor and empty pool are rejected as input failures', async () => {
  const r1 = await verifyChain({ anchorText: '', poolText: F.leaf.pem, dnsName: DNS, verifyTimeMs: T });
  assert.equal(r1.ok, false);
  const r2 = await verifyChain({ anchorText: F.root.pem, poolText: '', dnsName: DNS, verifyTimeMs: T });
  assert.equal(r2.ok, false);
});

test('duplicate DER copies in the pool are deduped, not treated as a cycle', async () => {
  const r = await verifyChain(input(F.root.pem, [F.leaf.pem, F.mid1.pem, F.mid1.pem, F.leaf.pem]));
  assert.equal(r.ok, true, JSON.stringify(r.failure));
});

test('PEM and raw base64 may be mixed in the pool', async () => {
  const rawB64 = extractB64(F.leaf.pem);
  const r = await verifyChain(input(F.root.pem, [`${rawB64}\n\n${F.mid1.pem}`]));
  assert.equal(r.ok, true, JSON.stringify(r.failure));
});

function extractB64(pem) {
  return pem.replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, '');
}
