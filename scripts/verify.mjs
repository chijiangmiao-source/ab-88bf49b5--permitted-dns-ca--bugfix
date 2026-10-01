/**
 * One-shot acceptance entry point used by the `verify` container/profile.
 *
 * Phases, in order:
 *   1. generate fixtures (deterministic key material via WebCrypto)
 *   2. logical test suite (node --test)
 *   3. page build (syntax + reference checks, copy to dist)
 *   4. boot the static server on an ephemeral/configurable port
 *   5. HTTP smoke tests: /healthz, /, /worker.js, module graph, sample data
 *   6. an in-browser-path end-to-end check using the served sample payload
 *      through the same verifyChain module the Worker runs
 *
 * Exit code is 0 only when every phase passes.
 */

import { spawn } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { once } from 'node:events';
import { verifyChain, CHECK_NAMES } from '../src/app/crypto/verifier.js';
import { toPem } from './der-encoder.js';
import {
  generateKeyPair, buildCertificate, extBasicConstraints,
  extKeyUsage, extSubjectAltName, extNameConstraints,
} from './cert-builder.js';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const PORT = Number(process.env.VERIFY_PORT || 8091);

const results = [];
function record(name, ok, detail = '') {
  results.push({ name, ok, detail });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ` — ${detail}` : ''}`);
}

async function run(name, cmd, args) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { cwd: root, env: process.env, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', (d) => (stderr += d));
    child.on('close', (code) => {
      record(name, code === 0, code === 0 ? `exit 0` : `exit ${code}`);
      resolve({ code, stdout, stderr });
    });
  });
}

async function waitFor(url, timeoutMs = 8000) {
  const deadline = Date.now() + timeoutMs;
  let lastErr;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(url);
      if (r.ok) return r;
    } catch (e) {
      lastErr = e;
    }
    await new Promise((r) => setTimeout(r, 150));
  }
  throw lastErr || new Error('server never became ready');
}

/**
 * In-memory only P-256 X.509 v3 three-certificate chain exercising the
 * multi-level permittedSubtrees intersection rule (RFC 5280 4.2.1.10):
 *
 *   root CA permittedSubtrees = example.com
 *     ├─ intermediate CA permittedSubtrees = ground.example (disjoint)
 *     │    └─ leaf SAN/target = telemetry.example.com
 *     │       satisfies the anchor's permit but NOT the intermediate's
 *     │       -> MUST be rejected with a DNS name constraint failure
 *     └─ intermediate CA permittedSubtrees = ground.example.com (nested)
 *          └─ leaf SAN/target = telemetry.ground.example.com
 *             lies within BOTH permits -> MUST still verify
 *
 * The positive control guards against the fix turning the intersection into
 * an empty set for legitimate nested constraints.
 */
async function crossConstraintProbe() {
  const at = Date.UTC(2026, 0, 1, 12, 0, 0); // 2026-01-01, inside every window
  const D = (y, mo, d) => new Date(Date.UTC(y, mo - 1, d));
  const CA_KU = () => extKeyUsage(['keyCertSign', 'cRLSign']);
  const LEAF_KU = () => extKeyUsage(['digitalSignature']);
  const BC_CA = (pathLen = null) => extBasicConstraints({ cA: true, pathLen });
  const BC_LEAF = () => extBasicConstraints({ cA: false });

  const kRoot = await generateKeyPair();
  const kMid = await generateKeyPair();
  const kMidNested = await generateKeyPair();
  const kLeafBad = await generateKeyPair();
  const kLeafOk = await generateKeyPair();

  const root = await buildCertificate({
    subject: 'Probe Root CA permitted example.com',
    keyPair: kRoot,
    notBefore: D(2024, 1, 1), notAfter: D(2036, 1, 1),
    serial: 0xe001,
    extensions: [BC_CA(2), CA_KU(), extNameConstraints({ permitted: ['example.com'] })],
  });
  const mid = await buildCertificate({
    subject: 'Probe Intermediate CA permitted ground.example',
    keyPair: kMid,
    issuer: { nameAttrs: root.subjectAttrs, keyPair: kRoot },
    notBefore: D(2025, 1, 1), notAfter: D(2031, 1, 1),
    serial: 0xe002,
    extensions: [BC_CA(1), CA_KU(), extNameConstraints({ permitted: ['ground.example'] })],
  });
  const midNested = await buildCertificate({
    subject: 'Probe Intermediate CA permitted ground.example.com',
    keyPair: kMidNested,
    issuer: { nameAttrs: root.subjectAttrs, keyPair: kRoot },
    notBefore: D(2025, 1, 1), notAfter: D(2031, 1, 1),
    serial: 0xe005,
    extensions: [BC_CA(1), CA_KU(), extNameConstraints({ permitted: ['ground.example.com'] })],
  });
  const leafBad = await buildCertificate({
    subject: 'telemetry.example.com probe leaf',
    keyPair: kLeafBad,
    issuer: { nameAttrs: mid.subjectAttrs, keyPair: kMid },
    notBefore: D(2025, 6, 1), notAfter: D(2027, 1, 1),
    serial: 0xe003,
    extensions: [BC_LEAF(), LEAF_KU(), extSubjectAltName(['telemetry.example.com'])],
  });
  const leafOk = await buildCertificate({
    subject: 'telemetry.ground.example.com probe leaf',
    keyPair: kLeafOk,
    issuer: { nameAttrs: midNested.subjectAttrs, keyPair: kMidNested },
    notBefore: D(2025, 6, 1), notAfter: D(2027, 1, 1),
    serial: 0xe004,
    extensions: [BC_LEAF(), LEAF_KU(), extSubjectAltName(['telemetry.ground.example.com'])],
  });

  const verify = (intermediate, leaf, dns) =>
    verifyChain({
      anchorText: toPem(root.der),
      poolText: [toPem(intermediate.der), toPem(leaf.der)].join('\n'),
      dnsName: dns,
      verifyTimeMs: at,
    });

  // --- Negative case: non-compliant chain must be rejected ---
  const bad = await verify(mid, leafBad, 'telemetry.example.com');
  let rejected = false;
  if (bad.ok) {
    console.log('BUG: union of permitted constraints accepted');
  } else if (bad.failure?.check !== CHECK_NAMES.NAME_CONSTRAINTS) {
    console.log(`BUG: cross-constraint chain rejected by wrong check: ${bad.failure?.check}`);
  } else if (!/ground\.example(?!\.com)/.test(bad.failure.reason || '')) {
    console.log(`BUG: cross-constraint failure does not name the intermediate restriction: ${bad.failure.reason}`);
  } else {
    rejected = true;
  }
  record(
    'multi-level permittedSubtrees: anchor permit cannot cancel intermediate restriction',
    rejected,
    rejected
      ? 'telemetry.example.com rejected by the intermediate ground.example constraint'
      : bad.ok
        ? 'telemetry.example.com was wrongly accepted'
        : `${bad.failure?.check}: ${bad.failure?.reason}`,
  );

  // --- Positive control: a name inside BOTH nested permits must verify ---
  const good = await verify(midNested, leafOk, 'telemetry.ground.example.com');
  record(
    'multi-level permittedSubtrees: name inside every permit still verifies',
    good.ok === true,
    good.ok ? 'chain length 3' : JSON.stringify(good.failure),
  );

  return rejected && good.ok === true;
}

async function main() {
  // 1. fixtures
  const gen = await run('fixture generation', process.execPath, ['scripts/generate-fixtures.mjs']);
  if (gen.code !== 0) return finish(1);

  // 2. logical tests
  const tests = await run('logical test suite', process.execPath, ['--test', 'test/']);
  if (tests.code !== 0) {
    console.log('\n--- test output (tail) ---');
    console.log(tests.stdout.split('\n').slice(-40).join('\n'));
    return finish(1);
  }

  // 3. build
  const build = await run('page build', process.execPath, ['scripts/build-page.mjs']);
  if (build.code !== 0) {
    console.log(build.stdout);
    console.log(build.stderr);
    return finish(1);
  }

  // 3b. in-memory three-level permittedSubtrees intersection probe
  let crossOk = false;
  try {
    crossOk = await crossConstraintProbe();
  } catch (e) {
    record('multi-level permittedSubtrees probe', false, e.stack || e.message);
  }
  if (!crossOk) return finish(1);

  // 4. boot server
  const child = spawn(process.execPath, ['scripts/server.mjs'], {
    cwd: root,
    env: { ...process.env, PORT: String(PORT), DIST_DIR: join(root, 'dist') },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let serverLog = '';
  child.stdout.on('data', (d) => (serverLog += d));
  child.stderr.on('data', (d) => (serverLog += d));

  let smokeFailed = false;
  try {
    await waitFor(`http://127.0.0.1:${PORT}/healthz`);

    // 5. smoke tests
    const checks = [
      { path: '/healthz', type: 'application/json', test: async (r) => (await r.json()).status === 'ok' },
      { path: '/', type: 'text/html', test: async (r) => (await r.text()).includes('证书链') },
      { path: '/main.js', type: 'text/javascript', test: async (r) => (await r.text()).includes('Worker') },
      { path: '/worker.js', type: 'text/javascript', test: async (r) => (await r.text()).includes('verifyChain') },
      { path: '/styles.css', type: 'text/css', test: async (r) => (await r.text()).includes('--accent') },
      { path: '/samples/chain-sample.json', type: 'application/json', test: async (r) => !!(await r.json()).anchorPem },
    ];
    // Module graph referenced by worker/page must all resolve.
    const graph = [
      '/crypto/der.js', '/crypto/oids.js', '/crypto/x509.js', '/crypto/ecdsa.js',
      '/crypto/dns.js', '/crypto/webcrypto.js', '/crypto/verifier.js',
    ];
    for (const p of graph) {
      const r = await fetch(`http://127.0.0.1:${PORT}${p}`);
      record(`HTTP 200 module ${p}`, r.status === 200, `status ${r.status}`);
      if (r.status !== 200) smokeFailed = true;
    }
    for (const c of checks) {
      try {
        const r = await fetch(`http://127.0.0.1:${PORT}${c.path}`);
        const okType = r.headers.get('content-type')?.includes(c.type) ?? false;
        const okBody = await c.test(r.clone());
        const ok = r.status === 200 && okType && okBody;
        record(`HTTP smoke ${c.path}`, ok, ok ? '' : `status=${r.status} typeMatch=${okType}`);
        if (!ok) smokeFailed = true;
      } catch (e) {
        record(`HTTP smoke ${c.path}`, false, e.message);
        smokeFailed = true;
      }
    }
    // traversal guard
    const trav = await fetch(`http://127.0.0.1:${PORT}/../package.json`);
    // Node fetch normalizes /../ away client-side, so probe an encoded form:
    const trav2 = await fetch(`http://127.0.0.1:${PORT}/%2e%2e/package.json`);
    record('HTTP path traversal blocked', trav2.status === 403 || trav2.status === 404, `status ${trav2.status}`);
    if (![403, 404].includes(trav2.status)) smokeFailed = true;

    // 6. end-to-end through the served sample (same module the worker runs)
    const sample = JSON.parse(await readFile(join(root, 'dist', 'samples', 'chain-sample.json'), 'utf8'));
    const report = await verifyChain({
      anchorText: sample.anchorPem,
      poolText: sample.poolPem,
      dnsName: sample.dns,
      verifyTimeMs: Date.parse(`${sample.verifyTime}Z`),
    });
    record('served sample verifies end-to-end', report.ok === true, report.ok ? `chain length ${report.chain.length}` : JSON.stringify(report.failure));
    if (!report.ok) smokeFailed = true;

    // Restricted-domain rejection smoke through the same API surface.
    const { FIXTURES, VERIFY_TIME } = await import(
      '../test/fixtures/manifest.mjs'
    );
    const denied = await verifyChain({
      anchorText: FIXTURES.root.pem,
      poolText: [FIXTURES['mid-nc'].pem, FIXTURES['leaf-blocked'].pem].join('\n'),
      dnsName: 'blocked.ground.example',
      verifyTimeMs: VERIFY_TIME,
    });
    record(
      'restricted domain (excluded subtree) rejected',
      denied.ok === false && denied.failure?.reason?.includes('excludedSubtrees'),
      denied.ok ? 'unexpected success' : denied.failure?.reason ?? '',
    );
    if (!(denied.ok === false)) smokeFailed = true;
  } catch (e) {
    record('server lifecycle', false, e.message);
    console.log(serverLog);
    smokeFailed = true;
  } finally {
    child.kill('SIGTERM');
    await once(child, 'close').catch(() => {});
  }

  return finish(smokeFailed ? 1 : 0);
}

function finish(code) {
  const passed = results.filter((r) => r.ok).length;
  const failed = results.length - passed;
  console.log('\n================ ACCEPTANCE SUMMARY ================');
  console.log(`total ${results.length}  pass ${passed}  fail ${failed}`);
  if (failed > 0) {
    console.log('failed steps:');
    for (const r of results.filter((x) => !x.ok)) console.log(`  - ${r.name}: ${r.detail}`);
  }
  console.log(code === 0 ? 'ACCEPTANCE: PASS' : 'ACCEPTANCE: FAIL');
  return code;
}

main().then((code) => process.exit(code)).catch((e) => {
  console.error(e);
  process.exit(1);
});
