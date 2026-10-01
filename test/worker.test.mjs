/**
 * Exercises the Worker entry module (src/app/worker.js) under Node by
 * installing a minimal `self` shim, then driving its onmessage protocol:
 *   - a valid verification request comes back as type:'result' with ok report
 *   - a malformed request comes back via type:'error'
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { FIXTURES, VERIFY_TIME } from './fixtures/manifest.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const workerUrl = pathToFileURL(join(here, '..', 'src', 'app', 'worker.js')).href;

const posted = [];

before(async () => {
  globalThis.self = {
    onmessage: null,
    postMessage(msg) {
      posted.push(msg);
    },
  };
  await import(workerUrl); // registers self.onmessage
  assert.equal(typeof self.onmessage, 'function');
});

after(() => {
  delete globalThis.self;
});

test('worker: valid request yields result message with a passing report', async () => {
  posted.length = 0;

  const payload = {
    anchorText: FIXTURES.root.pem,
    poolText: [FIXTURES.leaf.pem, FIXTURES.mid1.pem].join('\n'),
    dnsName: 'telemetry.ground.example',
    verifyTimeMs: VERIFY_TIME,
  };
  await self.onmessage({ data: { type: 'verify', requestId: 7, payload } });
  assert.equal(posted.length, 1);
  const reply = posted[0];
  assert.equal(reply.type, 'result');
  assert.equal(reply.requestId, 7);
  assert.equal(reply.report.ok, true, JSON.stringify(reply.report.failure));
  assert.equal(reply.report.chain.length, 3);
});

test('worker: invalid time throws path that caller can render (result, not crash)', async () => {
  posted.length = 0;
  const payload = {
    anchorText: FIXTURES.root.pem,
    poolText: [FIXTURES.leaf.pem, FIXTURES.mid1.pem].join('\n'),
    dnsName: 'telemetry.ground.example',
    verifyTimeMs: NaN,
  };
  await self.onmessage({ data: { type: 'verify', requestId: 8, payload } });
  // verifyChain handles NaN time itself as an input-failure report.
  assert.equal(posted[0].type, 'result');
  assert.equal(posted[0].requestId, 8);
  assert.equal(posted[0].report.ok, false);
});

test('worker: unexpected verifier exception is caught into an error message', async () => {
  posted.length = 0;
  // Simulate an unexpected runtime failure (not a normal report): a payload
  // whose property access throws. The worker must translate that into a
  // type:'error' reply instead of killing the worker.
  const payload = {};
  Object.defineProperty(payload, 'anchorText', {
    get() { throw new Error('simulated catastrophic failure'); },
  });
  await self.onmessage({ data: { type: 'verify', requestId: 9, payload } });
  assert.equal(posted.length, 1);
  assert.equal(posted[0].type, 'error');
  assert.equal(posted[0].requestId, 9);
  assert.match(posted[0].message, /simulated catastrophic failure/);
});
