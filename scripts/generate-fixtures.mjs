/**
 * Generates the complete fixture set used by the logical test suite and the
 * built-in page sample.
 *
 * All material is generated fresh with P-256 keys via WebCrypto; nothing
 * here depends on an external CA. A fixed validation instant is used:
 *
 *   VERIFY_TIME = 2026-06-15T12:00:00Z
 *
 * Outputs:
 *   test/fixtures/*.pem + manifest.mjs
 *   src/app/samples/chain-sample.json
 */

import { mkdir, writeFile, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  generateKeyPair,
  buildCertificate,
  extBasicConstraints,
  extKeyUsage,
  extSubjectAltName,
  extNameConstraints,
  extUnknownCritical,
} from './cert-builder.js';
import { toPem } from './der-encoder.js';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const fixDir = join(root, 'test', 'fixtures');
const sampleDir = join(root, 'src', 'app', 'samples');

const VERIFY_TIME = Date.UTC(2026, 5, 15, 12, 0, 0);
const D = (y, mo, d, h = 0, mi = 0) => new Date(Date.UTC(y, mo - 1, d, h, mi));

async function mkp() {
  return generateKeyPair();
}

async function saveCert(name, built) {
  await writeFile(join(fixDir, `${name}.pem`), toPem(built.der));
  return { name, built, pem: toPem(built.der) };
}

async function main() {
  await rm(fixDir, { recursive: true, force: true });
  await rm(sampleDir, { recursive: true, force: true });
  await mkdir(fixDir, { recursive: true });
  await mkdir(sampleDir, { recursive: true });

  // ----- Keys -----
  const kRoot = await mkp();
  const kMid1 = await mkp();
  const kMidAlt = await mkp();
  const kMidNc = await mkp();
  const kMidPl0 = await mkp();
  const kRootPl0 = await mkp();
  const kMidX = await mkp();
  const kLeaf = await mkp();
  const kLeafAlt = await mkp();
  const kLeafNc = await mkp();
  const kLeafBlocked = await mkp();
  const kLeafOther = await mkp();
  const kLeafExpired = await mkp();
  const kLeafFuture = await mkp();
  const kLeafPl = await mkp();
  const kFakeCa = await mkp();
  const kCaKu = await mkp();
  const kLeafKu = await mkp();
  const kCycleX = await mkp();
  const kCycleY = await mkp();
  const kLeafCycle = await mkp();
  const kLeafCa = await mkp();

  const CA_KU = () => extKeyUsage(['keyCertSign', 'cRLSign']);
  const LEAF_KU = () => extKeyUsage(['digitalSignature']);
  const BC_CA = (pathLen = null) => extBasicConstraints({ cA: true, pathLen });
  const BC_LEAF = () => extBasicConstraints({ cA: false });

  // ----- Standard valid hierarchy -----
  // root (self-signed anchor) -> mid1 (pathLen=1) -> leaf
  const root = await buildCertificate({
    subject: 'Ground Offline Root CA 2026',
    keyPair: kRoot,
    notBefore: D(2024, 1, 1), notAfter: D(2036, 1, 1),
    serial: 0x1001,
    extensions: [BC_CA(2), CA_KU()],
  });
  await saveCert('root', root);

  const mid1 = await buildCertificate({
    subject: 'Telemetry Issuing CA 1',
    keyPair: kMid1,
    issuer: { nameAttrs: root.subjectAttrs, keyPair: kRoot },
    notBefore: D(2025, 1, 1), notAfter: D(2031, 1, 1),
    serial: 0x2001,
    extensions: [BC_CA(1), CA_KU()],
  });
  await saveCert('mid1', mid1);

  const leaf = await buildCertificate({
    subject: 'telemetry.ground.example',
    keyPair: kLeaf,
    issuer: { nameAttrs: mid1.subjectAttrs, keyPair: kMid1 },
    notBefore: D(2026, 1, 1), notAfter: D(2027, 1, 1),
    serial: 0x3001,
    extensions: [BC_LEAF(), LEAF_KU(), extSubjectAltName(['telemetry.ground.example', '*.ground.example'])],
  });
  await saveCert('leaf', leaf);

  // ----- Alternate chain (different mid under same root) -----
  const midAlt = await buildCertificate({
    subject: 'Telemetry Issuing CA Alt',
    keyPair: kMidAlt,
    issuer: { nameAttrs: root.subjectAttrs, keyPair: kRoot },
    notBefore: D(2025, 1, 1), notAfter: D(2031, 1, 1),
    serial: 0x2002,
    extensions: [BC_CA(1), CA_KU()],
  });
  await saveCert('mid-alt', midAlt);

  const leafAlt = await buildCertificate({
    subject: 'telemetry.ground.example alt leaf',
    keyPair: kLeafAlt,
    issuer: { nameAttrs: midAlt.subjectAttrs, keyPair: kMidAlt },
    notBefore: D(2026, 1, 1), notAfter: D(2027, 1, 1),
    serial: 0x3002,
    extensions: [BC_LEAF(), LEAF_KU(), extSubjectAltName(['telemetry.ground.example'])],
  });
  await saveCert('leaf-alt', leafAlt);

  // ----- Name-constrained hierarchy -----
  // root -> midNc { permitted ground.example ; excluded blocked.ground.example }
  const midNc = await buildCertificate({
    subject: 'Ground-Name-Constrained CA',
    keyPair: kMidNc,
    issuer: { nameAttrs: root.subjectAttrs, keyPair: kRoot },
    notBefore: D(2025, 1, 1), notAfter: D(2031, 1, 1),
    serial: 0x2003,
    extensions: [
      BC_CA(0), CA_KU(),
      extNameConstraints({ permitted: ['ground.example'], excluded: ['blocked.ground.example'] }),
    ],
  });
  await saveCert('mid-nc', midNc);

  const leafNc = await buildCertificate({
    subject: 'telemetry.ground.example nc leaf',
    keyPair: kLeafNc,
    issuer: { nameAttrs: midNc.subjectAttrs, keyPair: kMidNc },
    notBefore: D(2026, 1, 1), notAfter: D(2027, 1, 1),
    serial: 0x3003,
    extensions: [BC_LEAF(), LEAF_KU(), extSubjectAltName(['telemetry.ground.example'])],
  });
  await saveCert('leaf-nc', leafNc);

  const leafBlocked = await buildCertificate({
    subject: 'blocked.ground.example leaf',
    keyPair: kLeafBlocked,
    issuer: { nameAttrs: midNc.subjectAttrs, keyPair: kMidNc },
    notBefore: D(2026, 1, 1), notAfter: D(2027, 1, 1),
    serial: 0x3004,
    extensions: [BC_LEAF(), LEAF_KU(), extSubjectAltName(['blocked.ground.example'])],
  });
  await saveCert('leaf-blocked', leafBlocked);

  const leafOther = await buildCertificate({
    subject: 'telemetry.other.example nc-violation leaf',
    keyPair: kLeafOther,
    issuer: { nameAttrs: midNc.subjectAttrs, keyPair: kMidNc },
    notBefore: D(2026, 1, 1), notAfter: D(2027, 1, 1),
    serial: 0x3005,
    extensions: [BC_LEAF(), LEAF_KU(), extSubjectAltName(['telemetry.other.example'])],
  });
  await saveCert('leaf-other', leafOther);

  // ----- pathLenConstraint hierarchy -----
  // rootPl0 (pathLen=0) -> midX (CA) -> leafPl : must FAIL (one intermediate
  // beneath an anchor that allows zero).
  const rootPl0 = await buildCertificate({
    subject: 'Root CA pathLen Zero',
    keyPair: kRootPl0,
    notBefore: D(2024, 1, 1), notAfter: D(2036, 1, 1),
    serial: 0x5001,
    extensions: [BC_CA(0), CA_KU()],
  });
  await saveCert('root-pl0', rootPl0);

  const midX = await buildCertificate({
    subject: 'Intermediate under pathLen-zero root',
    keyPair: kMidX,
    issuer: { nameAttrs: rootPl0.subjectAttrs, keyPair: kRootPl0 },
    notBefore: D(2025, 1, 1), notAfter: D(2031, 1, 1),
    serial: 0x5002,
    extensions: [BC_CA(0), CA_KU()],
  });
  await saveCert('mid-x', midX);

  const leafPl = await buildCertificate({
    subject: 'pl.telemetry.ground.example',
    keyPair: kLeafPl,
    issuer: { nameAttrs: midX.subjectAttrs, keyPair: kMidX },
    notBefore: D(2026, 1, 1), notAfter: D(2027, 1, 1),
    serial: 0x5003,
    extensions: [BC_LEAF(), LEAF_KU(), extSubjectAltName(['pl.telemetry.ground.example'])],
  });
  await saveCert('leaf-pl', leafPl);

  // Also: midPl0 (pathLen=0) directly issuing a leaf under the normal root:
  // must SUCCEED (zero intermediate CAs beneath it).
  const midPl0 = await buildCertificate({
    subject: 'Edge CA pathLen Zero',
    keyPair: kMidPl0,
    issuer: { nameAttrs: root.subjectAttrs, keyPair: kRoot },
    notBefore: D(2025, 1, 1), notAfter: D(2031, 1, 1),
    serial: 0x5004,
    extensions: [BC_CA(0), CA_KU()],
  });
  await saveCert('mid-pl0', midPl0);
  const leafUnderPl0 = await buildCertificate({
    subject: 'edge.telemetry.ground.example',
    keyPair: await mkp(),
    issuer: { nameAttrs: midPl0.subjectAttrs, keyPair: kMidPl0 },
    notBefore: D(2026, 1, 1), notAfter: D(2027, 1, 1),
    serial: 0x5005,
    extensions: [BC_LEAF(), LEAF_KU(), extSubjectAltName(['edge.telemetry.ground.example'])],
  });
  await saveCert('leaf-under-pl0', leafUnderPl0);

  // ----- Validity violations -----
  const leafExpired = await buildCertificate({
    subject: 'expired.telemetry.ground.example',
    keyPair: kLeafExpired,
    issuer: { nameAttrs: mid1.subjectAttrs, keyPair: kMid1 },
    notBefore: D(2024, 1, 1), notAfter: D(2025, 12, 31),
    serial: 0x6001,
    extensions: [BC_LEAF(), LEAF_KU(), extSubjectAltName(['expired.telemetry.ground.example'])],
  });
  await saveCert('leaf-expired', leafExpired);

  const leafFuture = await buildCertificate({
    subject: 'future.telemetry.ground.example',
    keyPair: kLeafFuture,
    issuer: { nameAttrs: mid1.subjectAttrs, keyPair: kMid1 },
    notBefore: D(2027, 1, 1), notAfter: D(2028, 1, 1),
    serial: 0x6002,
    extensions: [BC_LEAF(), LEAF_KU(), extSubjectAltName(['future.telemetry.ground.example'])],
  });
  await saveCert('leaf-future', leafFuture);

  // ----- cA=false used as issuer -----
  const fakeCa = await buildCertificate({
    subject: 'Not Really A CA',
    keyPair: kFakeCa,
    issuer: { nameAttrs: root.subjectAttrs, keyPair: kRoot },
    notBefore: D(2025, 1, 1), notAfter: D(2031, 1, 1),
    serial: 0x7001,
    extensions: [BC_LEAF(), LEAF_KU()],
  });
  await saveCert('fake-ca', fakeCa);
  const leafUnderFake = await buildCertificate({
    subject: 'fakeca.telemetry.ground.example',
    keyPair: await mkp(),
    issuer: { nameAttrs: fakeCa.subjectAttrs, keyPair: kFakeCa },
    notBefore: D(2026, 1, 1), notAfter: D(2027, 1, 1),
    serial: 0x7002,
    extensions: [BC_LEAF(), LEAF_KU(), extSubjectAltName(['fakeca.telemetry.ground.example'])],
  });
  await saveCert('leaf-under-fake', leafUnderFake);

  // ----- CA missing keyCertSign -----
  const caKu = await buildCertificate({
    subject: 'CA Without KeyCertSign',
    keyPair: kCaKu,
    issuer: { nameAttrs: root.subjectAttrs, keyPair: kRoot },
    notBefore: D(2025, 1, 1), notAfter: D(2031, 1, 1),
    serial: 0x8001,
    extensions: [BC_CA(0), extKeyUsage(['digitalSignature', 'cRLSign'])],
  });
  await saveCert('ca-no-kcs', caKu);
  const leafUnderCaKu = await buildCertificate({
    subject: 'nokcs.telemetry.ground.example',
    keyPair: kLeafKu,
    issuer: { nameAttrs: caKu.subjectAttrs, keyPair: kCaKu },
    notBefore: D(2026, 1, 1), notAfter: D(2027, 1, 1),
    serial: 0x8002,
    extensions: [BC_LEAF(), LEAF_KU(), extSubjectAltName(['nokcs.telemetry.ground.example'])],
  });
  await saveCert('leaf-under-no-kcs', leafUnderCaKu);

  // ----- Leaf with cA=true -----
  const leafCa = await buildCertificate({
    subject: 'leaf-that-is-ca.ground.example',
    keyPair: kLeafCa,
    issuer: { nameAttrs: mid1.subjectAttrs, keyPair: kMid1 },
    notBefore: D(2026, 1, 1), notAfter: D(2027, 1, 1),
    serial: 0x9001,
    extensions: [BC_CA(0), CA_KU(), extSubjectAltName(['leaf-that-is-ca.ground.example'])],
  });
  await saveCert('leaf-ca', leafCa);

  // ----- Unknown critical extension on a leaf -----
  const leafUnknownExt = await buildCertificate({
    subject: 'unknown-ext.telemetry.ground.example',
    keyPair: await mkp(),
    issuer: { nameAttrs: mid1.subjectAttrs, keyPair: kMid1 },
    notBefore: D(2026, 1, 1), notAfter: D(2027, 1, 1),
    serial: 0xa001,
    extensions: [
      BC_LEAF(), LEAF_KU(),
      extSubjectAltName(['unknown-ext.telemetry.ground.example']),
      extUnknownCritical('1.3.6.1.4.1.99999.66.1'),
    ],
  });
  await saveCert('leaf-unknown-ext', leafUnknownExt);

  // ----- X.509 v1 leaf -----
  const leafV1 = await buildCertificate({
    subject: 'v1.telemetry.ground.example',
    keyPair: await mkp(),
    issuer: { nameAttrs: mid1.subjectAttrs, keyPair: kMid1 },
    notBefore: D(2026, 1, 1), notAfter: D(2027, 1, 1),
    serial: 0xb001,
    includeSkid: false, includeAkid: false,
  }, { v1: true });
  await saveCert('leaf-v1', leafV1);

  // ----- Issuance cycle -----
  // X is signed by Y, Y is signed by X; leaf-cycle issued by X.
  const cycX = await buildCertificate({
    subject: 'Cycle CA X',
    keyPair: kCycleX,
    issuer: { nameAttrs: [{ type: 'CN', value: 'Cycle CA Y' }], keyPair: kCycleY },
    notBefore: D(2025, 1, 1), notAfter: D(2031, 1, 1),
    serial: 0xc001,
    extensions: [BC_CA(1), CA_KU()],
  });
  await saveCert('cycle-x', cycX);
  const cycY = await buildCertificate({
    subject: 'Cycle CA Y',
    keyPair: kCycleY,
    issuer: { nameAttrs: [{ type: 'CN', value: 'Cycle CA X' }], keyPair: kCycleX },
    notBefore: D(2025, 1, 1), notAfter: D(2031, 1, 1),
    serial: 0xc002,
    extensions: [BC_CA(1), CA_KU()],
  });
  await saveCert('cycle-y', cycY);
  const leafCycle = await buildCertificate({
    subject: 'cycle.telemetry.ground.example',
    keyPair: kLeafCycle,
    issuer: { nameAttrs: cycX.subjectAttrs, keyPair: kCycleX },
    notBefore: D(2026, 1, 1), notAfter: D(2027, 1, 1),
    serial: 0xc003,
    extensions: [BC_LEAF(), LEAF_KU(), extSubjectAltName(['cycle.telemetry.ground.example'])],
  });
  await saveCert('leaf-cycle', leafCycle);

  // ----- Tampered signature: flip last byte (inside s) of the valid leaf -----
  const tampered = new Uint8Array(leaf.der);
  tampered[tampered.length - 1] ^= 0xff;
  await writeFile(join(fixDir, 'leaf-tampered.pem'), toPem(tampered));

  // ----- Truncated DER: cut 40 bytes off a valid cert -----
  const truncated = leaf.der.subarray(0, leaf.der.length - 40);
  await writeFile(join(fixDir, 'leaf-truncated.pem'), toPem(truncated));

  // ----- Base64-level truncation (drop tail of base64) -----
  const leafB64 = Buffer.from(leaf.der).toString('base64');
  await writeFile(join(fixDir, 'leaf-b64-truncated.pem'),
    `-----BEGIN CERTIFICATE-----\n${leafB64.slice(0, leafB64.length - 10)}\n-----END CERTIFICATE-----\n`);

  // ----- Bundle convenience pools -----
  const saved = {};
  for (const [n, b] of Object.entries({
    root, mid1, leaf, 'mid-alt': midAlt, 'leaf-alt': leafAlt,
    'mid-nc': midNc, 'leaf-nc': leafNc, 'leaf-blocked': leafBlocked, 'leaf-other': leafOther,
    'root-pl0': rootPl0, 'mid-x': midX, 'leaf-pl': leafPl, 'mid-pl0': midPl0, 'leaf-under-pl0': leafUnderPl0,
    'leaf-expired': leafExpired, 'leaf-future': leafFuture,
    'fake-ca': fakeCa, 'leaf-under-fake': leafUnderFake,
    'ca-no-kcs': caKu, 'leaf-under-no-kcs': leafUnderCaKu,
    'leaf-ca': leafCa, 'leaf-unknown-ext': leafUnknownExt, 'leaf-v1': leafV1,
    'cycle-x': cycX, 'cycle-y': cycY, 'leaf-cycle': leafCycle,
  })) saved[n] = { pem: toPem(b.der), der: b.der };

  // ----- Page sample (valid chain) -----
  const sample = {
    anchorPem: saved.root.pem,
    poolPem: [saved.leaf.pem, saved.mid1.pem].join('\n'),
    dns: 'telemetry.ground.example',
    verifyTime: '2026-06-15T12:00:00',
    note: 'Ground telemetry valid chain fixture',
  };
  await writeFile(join(sampleDir, 'chain-sample.json'), JSON.stringify(sample, null, 2));

  // ----- Manifest for the test suite -----
  const manifest = `// AUTO-GENERATED by scripts/generate-fixtures.mjs — do not edit.
// Verification instant shared by every scenario: 2026-06-15T12:00:00Z
export const VERIFY_TIME = ${VERIFY_TIME};
export const FIXTURES = ${JSON.stringify(Object.fromEntries(
    Object.entries(saved).map(([k, v]) => [k, { pem: v.pem }]),
  ), null, 2)};
export const TAMPERED_PEM = ${JSON.stringify(toPem(tampered))};
export const TRUNCATED_PEM = ${JSON.stringify(toPem(truncated))};
export const B64_TRUNCATED_PEM = ${JSON.stringify(
    `-----BEGIN CERTIFICATE-----\n${leafB64.slice(0, leafB64.length - 10)}\n-----END CERTIFICATE-----\n`,
  )};
`;
  await writeFile(join(fixDir, 'manifest.mjs'), manifest);

  console.log(`Fixtures written to ${fixDir}`);
  console.log(`Page sample written to ${sampleDir}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
