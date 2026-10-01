import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeDns, dnsNameMatches, dnsConstraintMatches, checkDnsConstraints } from '../src/app/crypto/dns.js';

test('normalizeDns accepts and lower-cases valid names, strips root dot', () => {
  assert.equal(normalizeDns('  Telemetry.Ground.Example. ').name, 'telemetry.ground.example');
  assert.equal(normalizeDns('a-b.c').ok, true);
});

test('normalizeDns rejects malformed input', () => {
  for (const bad of ['', '   ', 'a..b', '-bad.example', 'bad-.example', 'a'.repeat(64) + '.x', 'ex_ample.com', '.', 'with space.com']) {
    assert.equal(normalizeDns(bad).ok, false, `should reject: ${bad}`);
  }
});

test('SAN matching: exact and case/root-dot insensitive', () => {
  assert.ok(dnsNameMatches('telemetry.ground.example', 'telemetry.ground.example'));
  assert.ok(dnsNameMatches('telemetry.ground.example', 'TELEMETRY.Ground.Example.'));
  assert.ok(!dnsNameMatches('telemetry.ground.example', 'ground.example'));
  assert.ok(!dnsNameMatches('x.telemetry.ground.example', 'telemetry.ground.example'));
});

test('SAN matching: left-label wildcard only', () => {
  assert.ok(dnsNameMatches('foo.ground.example', '*.ground.example'));
  assert.ok(!dnsNameMatches('ground.example', '*.ground.example'));
  assert.ok(!dnsNameMatches('a.b.ground.example', '*.ground.example'));
  assert.ok(!dnsNameMatches('foo.ground.example', 'w*.ground.example'));
  assert.ok(!dnsNameMatches('foo.ground.example', 'foo.*.example'));
  assert.ok(!dnsNameMatches('evilground.example', '*.ground.example'));
});

test('constraint matching RFC 5280 semantics', () => {
  // host.example.com satisfies, www.host.example.com does too
  assert.ok(dnsConstraintMatches('ground.example', 'ground.example'));
  assert.ok(dnsConstraintMatches('telemetry.ground.example', 'ground.example'));
  assert.ok(dnsConstraintMatches('a.b.ground.example', 'ground.example'));
  assert.ok(!dnsConstraintMatches('notground.example', 'ground.example'));
  // leading dot = strict sub-domain convention
  assert.ok(!dnsConstraintMatches('ground.example', '.ground.example'));
  assert.ok(dnsConstraintMatches('telemetry.ground.example', '.ground.example'));
});

test('accumulated constraints: excluded wins; any permitted must match', () => {
  const acc = { permittedSets: [['ground.example']], excludedDns: ['blocked.ground.example'] };
  assert.equal(checkDnsConstraints('telemetry.ground.example', acc).ok, true);
  assert.equal(checkDnsConstraints('blocked.ground.example', acc).ok, false);
  assert.equal(checkDnsConstraints('telemetry.other.example', acc).ok, false);
  // excluded-only set: anything not excluded passes
  assert.equal(checkDnsConstraints('x.y', { permittedSets: [], excludedDns: ['z.y'] }).ok, true);
  assert.equal(checkDnsConstraints('z.y', { permittedSets: [], excludedDns: ['z.y'] }).ok, false);
});

test('permittedSubtrees: each CA with a non-empty set must be satisfied (intersection, not union)', () => {
  // Root permits example.com; a lower CA permits only ground.example.com.
  // Every non-empty set is evaluated independently (RFC 5280 4.2.1.10).
  const cross = { permittedSets: [['example.com'], ['ground.example.com']], excludedDns: [] };
  // matches the broad root permit but violates the narrow intermediate one
  const denied = checkDnsConstraints('telemetry.example.com', cross);
  assert.equal(denied.ok, false);
  assert.match(denied.reason, /permittedSubtrees/);
  assert.deepEqual(denied.violatedPermittedSet, ['ground.example.com']);
  // inside both sets: accepted (the intersection of the per-CA spaces)
  assert.equal(checkDnsConstraints('telemetry.ground.example.com', cross).ok, true);
  assert.equal(checkDnsConstraints('ground.example.com', cross).ok, true);
  // outside the root permit is rejected even though it is inside the lower one
  const outsideRoot = checkDnsConstraints('telemetry.ground.org', cross);
  assert.equal(outsideRoot.ok, false);
  assert.deepEqual(outsideRoot.violatedPermittedSet, ['example.com']);
  // multiple entries within one CA's own set still form a union
  const ownUnion = { permittedSets: [['a.example', 'b.example']], excludedDns: [] };
  assert.equal(checkDnsConstraints('host.a.example', ownUnion).ok, true);
  assert.equal(checkDnsConstraints('host.b.example', ownUnion).ok, true);
  assert.equal(checkDnsConstraints('host.c.example', ownUnion).ok, false);
  // a higher CA with an empty permittedSubtrees adds no requirement
  const emptyHigher = { permittedSets: [['ground.example']], excludedDns: [] };
  assert.equal(checkDnsConstraints('x.ground.example', emptyHigher).ok, true);
});
