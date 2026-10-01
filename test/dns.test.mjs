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
  const acc = { permittedDns: ['ground.example'], excludedDns: ['blocked.ground.example'] };
  assert.equal(checkDnsConstraints('telemetry.ground.example', acc).ok, true);
  assert.equal(checkDnsConstraints('blocked.ground.example', acc).ok, false);
  assert.equal(checkDnsConstraints('telemetry.other.example', acc).ok, false);
  // excluded-only set: anything not excluded passes
  assert.equal(checkDnsConstraints('x.y', { permittedDns: [], excludedDns: ['z.y'] }).ok, true);
  assert.equal(checkDnsConstraints('z.y', { permittedDns: [], excludedDns: ['z.y'] }).ok, false);
});
