/**
 * Candidate-chain construction and path validation.
 *
 * Inputs: one trust anchor, an unordered pool of at most seven certificates
 * (leaf + intermediates), the target DNS name and the validation instant.
 *
 * The search walks from every candidate leaf toward the anchor:
 *
 *   leaf  ->  issuer name match (DER Name byte equality)  ->  ...  ->  anchor
 *
 * Cryptographic signature verification decides which name-matching issuer
 * actually issued the certificate. All valid chains are collected; the final
 * chain is chosen stably by lexicographic SHA-256 digest order (leaf first),
 * so repeated verification of the same unordered paste always reports the
 * same chain.
 */

import { parseCertificate } from './x509.js';
import { nameMatches } from './x509.js';
import { ecdsaDerToRaw } from './ecdsa.js';
import { importCertPublicKey, verifyEcdsaSha256, sha256, bytesToHex } from './webcrypto.js';
import { dnsNameMatches, checkDnsConstraints, normalizeDns } from './dns.js';

export const CHECK_NAMES = Object.freeze({
  PARSE: 'DER 解析与证书配置 (v3 / P-256 / SHA-256)',
  CRITICAL_EXT: '关键扩展可识别性',
  SIGNATURE: '签名核验 (ECDSA P-256 / SHA-256)',
  VALIDITY: '有效期',
  CA: 'BasicConstraints cA',
  KEY_USAGE: 'keyUsage',
  PATH_LEN: 'pathLenConstraint',
  NAME_CONSTRAINTS: 'DNS 名称约束 (permitted/excluded)',
  SAN: 'SAN 中的目标主机名',
  NAME_LINK: '签发者名称链接',
  CYCLE: '循环签发检测',
  ANCHOR: '终止于信任锚',
});

const MAX_POOL = 7;

/**
 * Decode one pasted certificate slot: accepts bare base64 (DER) or a PEM
 * block. Whitespace / armour lines are tolerated.
 * @param {string} text
 * @param {string} slot
 * @returns {Promise<ParsedCertificate>}
 */
export async function certFromPasted(text, slot) {
  const b64 = extractBase64(text);
  if (b64 === '') throw new X509InputError(`${slot}内容为空`, slot);
  let der;
  try {
    der = base64ToBytes(b64);
  } catch (e) {
    throw new X509InputError(`${slot}Base64 解码失败：${e.message}`, slot);
  }
  if (der.length === 0) throw new X509InputError(`${slot}解码后为零字节`, slot);
  const cert = parseCertificate(der, slot);
  cert.digest = bytesToHex(await sha256(der));
  return cert;
}

export class X509InputError extends Error {
  constructor(message, slot) {
    super(message);
    this.name = 'X509InputError';
    this.slot = slot;
  }
}

/**
 * Split pasted pool text into individual certificate base64 strings.
 * Supports PEM-armoured blocks and/or raw base64 chunks separated by blank
 * lines or commas.
 */
export function splitPastedCertificates(text) {
  const blocks = [];
  const pemRe = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g;
  let last = 0;
  let m;
  while ((m = pemRe.exec(text)) !== null) {
    if (text.slice(last, m.index).trim() !== '') {
      blocks.push({ pem: false, body: text.slice(last, m.index) });
    }
    blocks.push({ pem: true, body: m[1] });
    last = pemRe.lastIndex;
  }
  if (text.slice(last).trim() !== '') blocks.push({ pem: false, body: text.slice(last) });

  const out = [];
  for (const block of blocks) {
    if (block.pem) {
      out.push(block.body.replace(/\s+/g, ''));
    } else {
      // Raw base64: allow several chunks separated by blank lines/commas.
      for (const chunk of block.body.split(/(?:\r?\n\s*\r?\n)|,/)) {
        const compact = chunk.replace(/\s+/g, '');
        if (compact !== '') out.push(compact);
      }
    }
  }
  return out.filter((b) => b !== '');
}

function extractBase64(text) {
  const blocks = splitPastedCertificates(text);
  if (blocks.length > 1) {
    throw new X509InputError('该栏只接受一张证书（多证书请粘贴到无序证书区）', null);
  }
  return blocks[0] || '';
}

function base64ToBytes(b64) {
  const clean = b64.replace(/[^A-Za-z0-9+/=]/g, '');
  if (clean.length % 4 !== 0) {
    throw new Error('长度不是 4 的倍数（DER Base64 数据可能被截断）');
  }
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(clean)) {
    throw new Error('含 Base64 字母表之外的字符');
  }
  const bin = atobPoly(clean);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const atobPoly =
  typeof atob === 'function'
    ? atob
    : (s) => Buffer.from(s, 'base64').toString('binary');

/**
 * Main entry point.
 *
 * @param {object} input
 * @param {string} input.anchorText     pasted trust anchor
 * @param {string} input.poolText       up to 7 unordered certs
 * @param {string} input.dnsName        target DNS name
 * @param {number} input.verifyTimeMs   validation instant (epoch ms)
 * @returns {Promise<VerificationReport>}
 */
export async function verifyChain(input) {
  if (!input || typeof input !== 'object') {
    return {
      ok: false,
      stage: 'input',
      failure: { slot: null, check: CHECK_NAMES.PARSE, reason: '复核请求载荷格式无效' },
      certs: [],
      chainsTried: 0,
    };
  }
  const anchorText = typeof input.anchorText === 'string' ? input.anchorText : '';
  const poolText = typeof input.poolText === 'string' ? input.poolText : '';
  const dnsInput = typeof input.dnsName === 'string' ? input.dnsName : '';
  // ---- 1. Parse anchor ----
  let anchor;
  try {
    anchor = await certFromPasted(anchorText, '信任锚');
  } catch (e) {
    return {
      ok: false,
      stage: 'input',
      failure: { slot: '信任锚', check: CHECK_NAMES.PARSE, reason: e.message },
      certs: [],
      chainsTried: 0,
    };
  }
  const anchorIssues = staticCertIssues(anchor);
  if (anchorIssues.length > 0) {
    return inputFailure(anchor, 0, anchorIssues, [], []);
  }

  // ---- 2. Parse pool (dedupe by DER bytes) ----
  const chunks = splitPastedCertificates(poolText);
  if (chunks.length === 0) {
    return {
      ok: false,
      stage: 'input',
      failure: { slot: '无序证书区', check: CHECK_NAMES.PARSE, reason: '未粘贴任何待构造链的证书（至少需要叶证书）' },
      certs: [],
      chainsTried: 0,
    };
  }
  if (chunks.length > MAX_POOL) {
    return {
      ok: false,
      stage: 'input',
      failure: {
        slot: '无序证书区',
        check: CHECK_NAMES.PARSE,
        reason: `最多接受 ${MAX_POOL} 张无序证书，实际粘贴 ${chunks.length} 张`,
      },
      certs: [],
      chainsTried: 0,
    };
  }

  /** @type {ParsedCertificate[]} */
  const pool = [];
  const seenDigests = new Set([anchor.digest]);
  for (let i = 0; i < chunks.length; i++) {
    let cert;
    try {
      cert = parseCertificate(base64ToBytes(chunks[i]), `证书 #${i + 1}`);
      cert.digest = bytesToHex(await sha256(cert.raw));
    } catch (e) {
      return {
        ok: false,
        stage: 'input',
        failure: {
          slot: `证书 #${i + 1}`,
          check: CHECK_NAMES.PARSE,
          reason: e.message,
        },
        certs: summarizeParsed(pool, anchor),
        chainsTried: 0,
      };
    }
    if (seenDigests.has(cert.digest)) continue; // duplicate DER (incl. anchor copy): ignore
    seenDigests.add(cert.digest);
    pool.push(cert);
  }

  // Static profile issues reject the certificate outright; locate the first
  // offending cert in digest order so the report is stable.
  const staticFailures = pool
    .map((cert, index) => ({ cert, index, issues: staticCertIssues(cert) }))
    .filter((x) => x.issues.length > 0)
    .sort((a, b) => (a.cert.digest < b.cert.digest ? -1 : 1));
  if (staticFailures.length > 0) {
    const first = staticFailures[0];
    return inputFailure(first.cert, first.index, first.issues, pool, [anchor, ...pool]);
  }

  // ---- 3. Validate target DNS name ----
  const norm = normalizeDns(dnsInput);
  if (!norm.ok) {
    return {
      ok: false,
      stage: 'input',
      failure: { slot: '目标 DNS 名称', check: CHECK_NAMES.SAN, reason: norm.reason },
      certs: summarizeParsed([...pool, anchor]),
      chainsTried: 0,
    };
  }
  const target = norm.name;
  const timeMs = Number(input.verifyTimeMs);
  if (!Number.isFinite(timeMs)) {
    return {
      ok: false,
      stage: 'input',
      failure: { slot: '验证时刻', check: CHECK_NAMES.VALIDITY, reason: '验证时刻无效' },
      certs: summarizeParsed([...pool, anchor]),
      chainsTried: 0,
    };
  }

  // ---- 4. Candidate leaves: pool certs carrying the target name in SAN ----
  const leafCandidates = pool
    .filter((c) => c.sanDns.some((entry) => dnsNameMatches(target, entry)))
    .sort(byDigest);

  if (leafCandidates.length === 0) {
    // Stable diagnostic: show which pool certs exist and their SANs.
    return {
      ok: false,
      stage: 'path',
      failure: {
        level: 0,
        check: CHECK_NAMES.SAN,
        reason: `没有任何粘贴证书的 subjectAltName 包含主机名 "${target}"`,
        certDigest: poolSorted(pool)[0]?.digest,
      },
      certs: summarizeParsed([...pool, anchor]),
      attemptedEdges: pool.map((c) => ({
        subject: c.subject.label,
        digest: c.digest,
        checks: [{ check: CHECK_NAMES.SAN, ok: false, detail: `SAN = [${c.sanDns.join(', ') || '无 dNSName'}]` }],
      })),
      chainsTried: 0,
    };
  }

  // ---- 5. Import every public key once ----
  // A 65-byte 0x04-prefixed point may still be off the P-256 curve; WebCrypto
  // rejects that at import time, which must surface at the offending cert
  // rather than as a Worker crash.
  const keyByDigest = new Map();
  for (const c of [anchor, ...pool]) {
    try {
      keyByDigest.set(c.digest, await importCertPublicKey(c));
    } catch (e) {
      return {
        ok: false,
        stage: 'input',
        failure: {
          slot: c.slot,
          digest: c.digest,
          subject: c.subject?.label,
          check: CHECK_NAMES.PARSE,
          reason: `P-256 公钥点无法导入（可能不在 P-256 曲线上）：${e.message || e}`,
        },
        certs: summarizeParsed([...pool, anchor]),
        chainsTried: 0,
      };
    }
  }

  // ---- 6. DFS enumeration of chains ----
  // The same (subject, issuer) pair can be reached via different sub-paths;
  // signature/role checks are path-independent, path-level checks are
  // evaluated separately per complete candidate, so attempts are recorded
  // without dedup and merged for display.
  const allChains = [];
  /** @type {EdgeAttempt[]} */
  const attempted = [];
  for (const leaf of leafCandidates) {
    const path = [leaf];
    const visited = new Set([leaf.digest]);
    // eslint-disable-next-line no-await-in-loop
    await extendPath(path, visited, {
      anchor,
      pool,
      keyByDigest,
      target,
      timeMs,
      attempted,
      allChains,
    });
  }

  // ---- 7. Select chain deterministically ----
  if (allChains.length > 0) {
    allChains.sort(compareChains);
    const best = allChains[0];
    const report = buildSuccessReport(best, target, timeMs, allChains.length, attempted);
    return report;
  }

  // ---- 8. No chain: pinpoint the first failing link on the canonical
  // (digest-minimal) traversal starting from the digest-minimal leaf. ----
  const report = buildFailureReport(leafCandidates[0], {
    anchor,
    pool,
    keyByDigest,
    target,
    timeMs,
  }, attempted);
  report.certs = summarizeParsed([...pool, anchor]);
  return report;
}

function byDigest(a, b) {
  return a.digest < b.digest ? -1 : a.digest > b.digest ? 1 : 0;
}

function poolSorted(pool) {
  return [...pool].sort(byDigest);
}

/**
 * Static checks independent of chain position: profile, unknown critical
 * extensions, extension parse errors.
 * @returns {string[]} issue list (empty => fine)
 */
function staticCertIssues(cert) {
  const issues = [...cert.profileErrors];
  for (const oid of cert.unknownCriticalOids) {
    issues.push(`出现未知关键扩展 OID ${oid}，按 X.509 策略必须拒绝该证书`);
  }
  return issues;
}

function inputFailure(cert, index, issues, pool, allCerts) {
  return {
    ok: false,
    stage: 'input',
    failure: {
      slot: cert.slot || `证书 #${index + 1}`,
      digest: cert.digest,
      subject: cert.subject?.label,
      check: CHECK_NAMES.PARSE,
      reason: issues[0],
      allIssues: issues,
    },
    certs: summarizeParsed(allCerts && allCerts.length ? allCerts : [...pool, cert]),
    chainsTried: 0,
  };
}

/**
 * Recursively extend a leaf→root path. When the current head's issuer is the
 * anchor and the anchor link verifies, the path is complete.
 */
async function extendPath(path, visited, ctx) {
  const head = path[path.length - 1];
  const level = path.length - 1; // 0 = leaf

  // Issuer candidates: anchor plus pool certs whose subject Name matches.
  const candidates = [];
  for (const c of [ctx.anchor, ...ctx.pool]) {
    if (nameMatches(head.issuer, c.subject)) candidates.push(c);
  }
  candidates.sort(byDigest);

  let anyNameMatch = false;
  for (const issuer of candidates) {
    const isAnchor = issuer.digest === ctx.anchor.digest;
    anyNameMatch = true;
    const edge = {
      level,
      subject: head.subject.label,
      subjectDigest: head.digest,
      issuer: issuer.subject.label,
      issuerDigest: issuer.digest,
      isAnchor,
      checks: [],
    };
    ctx.attempted.push(edge);

    // Cycle: candidate issuer already appears in the leaf→head path. The
    // anchor is never added to `visited`, so a self-signed anchor is not
    // mistaken for a cycle here.
    if (visited.has(issuer.digest)) {
      edge.checks.push({
        check: CHECK_NAMES.CYCLE,
        ok: false,
        detail:
          issuer.digest === head.digest
            ? '候选签发者即证书自身（路径内自签发），继续上溯没有意义，按循环处理'
            : '签发者证书已在当前路径下游出现，构成签发循环',
      });
      continue;
    }
    edge.checks.push({ check: CHECK_NAMES.NAME_LINK, ok: true, detail: 'issuer Name 与候选签发者 subject Name 的 DER 字节一致' });

    // Role-specific checks of the *head* certificate performed at the edge
    // that links it to its issuer (so each certificate is judged exactly once
    // per chain).
    const role = level === 0 ? 'leaf' : 'intermediate';
    const roleFail = roleChecks(edge, head, role, ctx.timeMs);
    if (roleFail) continue;

    // Signature over the preserved raw tbsCertificate bytes.
    let rawSig;
    try {
      rawSig = ecdsaDerToRaw(head.signature.der);
    } catch (e) {
      edge.checks.push({ check: CHECK_NAMES.SIGNATURE, ok: false, detail: e.message });
      continue;
    }
    let sigOk;
    try {
      sigOk = await verifyEcdsaSha256(ctx.keyByDigest.get(issuer.digest), rawSig, head.tbsRaw);
    } catch (e) {
      edge.checks.push({ check: CHECK_NAMES.SIGNATURE, ok: false, detail: e.message });
      continue;
    }
    edge.checks.push({
      check: CHECK_NAMES.SIGNATURE,
      ok: sigOk,
      detail: sigOk
        ? '以候选签发者 P-256 公钥验证 tbsCertificate 的 ECDSA-SHA256 签名通过（DER r/s 已规范化为 64 字节 raw）'
        : '签名未通过：候选签发者公钥与签名不匹配',
    });
    if (!sigOk) continue;

    // Issuer itself must be a CA permitted to issue.
    const issuerRole = isAnchor ? 'anchor' : 'intermediate';
    const issuerFails = roleChecks(null, issuer, issuerRole, ctx.timeMs);
    if (issuerFails) {
      edge.checks.push(...issuerFails.map((f) => ({
        check: f.check, ok: false, detail: f.detail, target: isAnchor ? 'anchor' : 'issuer',
      })));
      continue;
    }
    edge.checks.push({
      check: CHECK_NAMES.CA,
      ok: true,
      detail: `签发者 cA=true${issuer.keyUsage ? '，keyUsage 含 keyCertSign' : '（无 keyUsage 扩展，按 RFC 5280 允许）'}`,
    });

    if (isAnchor) {
      // Full candidate path collected; now evaluate path-level checks.
      const full = [...path, issuer];
      const pathChecks = evaluatePath(full, ctx.target);
      if (pathChecks.ok) {
        edge.checks.push({ check: CHECK_NAMES.ANCHOR, ok: true, detail: '名称链接与签名均终止于粘贴的信任锚' });
        ctx.allChains.push(full);
      } else {
        edge.checks.push(...pathChecks.failures);
      }
      continue;
    }

    // Recurse into this intermediate issuer (cycle was already rejected above).
    visited.add(issuer.digest);
    // eslint-disable-next-line no-await-in-loop
    await extendPath([...path, issuer], new Set(visited), ctx);
    visited.delete(issuer.digest);
  }

  if (!anyNameMatch) {
    ctx.attempted.push({
      level,
      subject: head.subject.label,
      subjectDigest: head.digest,
      issuer: null,
      isAnchor: false,
      checks: [
        {
          check: CHECK_NAMES.NAME_LINK,
          ok: false,
          detail: `证书池中不存在 subject 与该证书 issuer（${head.issuer.label}）字节一致的证书`,
        },
      ],
    });
  }
}

/**
 * Certificate checks that depend on its role in the chain.
 * @returns {null | Array<{check:string, detail:string}>}
 */
function roleChecks(edge, cert, role, timeMs) {
  const fails = [];

  // Validity window.
  if (timeMs < cert.notBefore.getTime()) {
    fails.push({
      check: CHECK_NAMES.VALIDITY,
      detail: `验证时刻 ${fmtTime(timeMs)} 早于 notBefore ${fmtTime(cert.notBefore.getTime())}`,
    });
  } else if (timeMs > cert.notAfter.getTime()) {
    fails.push({
      check: CHECK_NAMES.VALIDITY,
      detail: `验证时刻 ${fmtTime(timeMs)} 晚于 notAfter ${fmtTime(cert.notAfter.getTime())}（证书已过期）`,
    });
  }

  if (role === 'leaf') {
    // Leaf must not be a CA.
    if (cert.basicConstraints && cert.basicConstraints.cA) {
      fails.push({ check: CHECK_NAMES.CA, detail: '叶证书 BasicConstraints 中 cA=true，叶证书不得是 CA' });
    }
    if (cert.keyUsage && !cert.keyUsage.digitalSignature) {
      fails.push({ check: CHECK_NAMES.KEY_USAGE, detail: '叶证书 keyUsage 未包含 digitalSignature' });
    }
  } else {
    // Issuers must be CAs.
    if (!cert.basicConstraints) {
      fails.push({ check: CHECK_NAMES.CA, detail: '签发证书缺少 BasicConstraints 扩展，不能作为 CA' });
    } else if (!cert.basicConstraints.cA) {
      fails.push({ check: CHECK_NAMES.CA, detail: '签发证书 BasicConstraints cA=false，不能签发下级证书' });
    }
    if (cert.keyUsage && !cert.keyUsage.keyCertSign) {
      fails.push({ check: CHECK_NAMES.KEY_USAGE, detail: 'CA 证书 keyUsage 未包含 keyCertSign' });
    }
  }

  if (fails.length > 0) {
    if (edge) edge.checks.push(...fails.map((f) => ({ check: f.check, ok: false, detail: f.detail })));
    return fails;
  }
  if (edge) {
    edge.checks.push({
      check: CHECK_NAMES.VALIDITY,
      ok: true,
      detail: `${fmtTime(cert.notBefore.getTime())} ～ ${fmtTime(cert.notAfter.getTime())}，覆盖验证时刻 ${fmtTime(timeMs)}`,
    });
    if (role === 'leaf') {
      edge.checks.push({
        check: CHECK_NAMES.KEY_USAGE,
        ok: true,
        detail: cert.keyUsage
          ? cert.keyUsage.digitalSignature
            ? 'keyUsage 含 digitalSignature'
            : 'keyUsage 不含 digitalSignature'
          : '无 keyUsage 扩展（RFC 5280 允许，不限制用途）',
      });
    }
  }
  return null;
}

/**
 * Path-wide checks against a complete leaf→anchor candidate:
 *   - target appears in leaf SAN
 *   - pathLenConstraint of every CA (counting non-self-issued intermediates
 *     below it)
 *   - accumulated DNS name constraints (permitted/excluded), applied to the
 *     DNS SANs of every subordinate certificate and to the target name
 *
 * @returns {{ok:true}|{ok:false, failures: Array}}
 */
function evaluatePath(full, target) {
  const failures = [];
  const L = full.length - 1; // anchor index

  // --- SAN target check on the leaf ---
  const leaf = full[0];
  if (!leaf.sanDns.some((entry) => dnsNameMatches(target, entry))) {
    failures.push({
      check: CHECK_NAMES.SAN,
      ok: false,
      detail: `叶证书 SAN 不包含 "${target}"（SAN dNSName: ${leaf.sanDns.map((s) => `"${s}"`).join(', ') || '无'}）`,
    });
  }

  // --- pathLenConstraint ---
  // For the CA at index i, intermediates below it are indices 1..i-1.
  for (let i = 1; i <= L; i++) {
    const ca = full[i];
    if (ca.basicConstraints && ca.basicConstraints.pathLen !== null) {
      let nonSelfIssued = 0;
      for (let j = 1; j < i; j++) {
        if (!nameMatches(full[j].subject, full[j].issuer)) nonSelfIssued++;
      }
      const limit = ca.basicConstraints.pathLen;
      if (nonSelfIssued > limit) {
        failures.push({
          check: CHECK_NAMES.PATH_LEN,
          ok: false,
          detail: `${i === L ? '信任锚' : `第 ${i} 级中间 CA`}（${ca.subject.label}）pathLenConstraint=${limit}，但其路径下方有 ${nonSelfIssued} 个非自签发中间证书`,
        });
      }
    }
  }

  // --- Name constraints, accumulated top-down ---
  // Constraints stated by the CA at index i apply to every certificate with
  // index < i. Walking leaf-ward, accumulate the union as we pass each CA.
  const accumulated = { permittedDns: [], excludedDns: [] };
  for (let i = L; i >= 1; i--) {
    const ca = full[i];
    if (ca.nameConstraints) {
      accumulated.permittedDns.push(...ca.nameConstraints.permittedDns);
      accumulated.excludedDns.push(...ca.nameConstraints.excludedDns);
    }
    const subordinate = full[i - 1];
    const namesToCheck = i - 1 === 0 ? Array.from(new Set([...subordinate.sanDns.map((s) => s.toLowerCase()), target])) : subordinate.sanDns.map((s) => s.toLowerCase());
    for (const name of namesToCheck) {
      const r = checkDnsConstraints(name, accumulated);
      if (!r.ok) {
        failures.push({
          check: CHECK_NAMES.NAME_CONSTRAINTS,
          ok: false,
          detail: `应用 ${i === L ? '信任锚' : `第 ${i} 级 CA`}（${ca.subject.label}）以上累积约束时：${r.reason}`,
        });
      }
    }
  }

  return failures.length === 0 ? { ok: true } : { ok: false, failures };
}

function compareChains(a, b) {
  // Compare leaf-first digest vectors; shorter vector only matters if prefix.
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const cmp = byDigest(a[i], b[i]);
    if (cmp !== 0) return cmp;
  }
  return a.length - b.length;
}

function buildSuccessReport(chain, target, timeMs, chainCount, attempted) {
  const levels = chain.map((cert, i) => {
    const role = i === 0 ? 'leaf' : i === chain.length - 1 ? 'anchor' : 'intermediate';
    const nc = cert.nameConstraints;
    return {
      level: i,
      role,
      roleLabel: role === 'leaf' ? '叶证书' : role === 'anchor' ? '信任锚' : `中间 CA（第 ${i} 级）`,
      digest: cert.digest,
      subject: cert.subject.label,
      issuer: cert.issuer.label,
      serial: cert.serialHex,
      notBefore: cert.notBefore.getTime(),
      notAfter: cert.notAfter.getTime(),
      sanDns: cert.sanDns,
      basicConstraints: cert.basicConstraints
        ? { cA: cert.basicConstraints.cA, pathLen: cert.basicConstraints.pathLen }
        : null,
      keyUsage: cert.keyUsage
        ? {
            digitalSignature: cert.keyUsage.digitalSignature,
            keyCertSign: cert.keyUsage.keyCertSign,
          }
        : null,
      nameConstraints: nc
        ? {
            permittedDns: nc.permittedDns,
            excludedDns: nc.excludedDns,
            hasOtherNameTypes: nc.otherNameTypes.length > 0,
          }
        : null,
      evidence: evidenceFor(chain, i, target, timeMs),
    };
  });
  return {
    ok: true,
    stage: 'path',
    target,
    verifyTimeMs: timeMs,
    selectionRule:
      chainCount > 1
        ? `共有 ${chainCount} 条候选链通过全部核验；按“叶证书→锚”各级证书 SHA-256 摘要字典序稳定选择了最小的一条。`
        : '仅有一条候选链通过全部核验。',
    chainCount,
    chain: levels,
    attemptedEdges: attempted,
  };
}

function evidenceFor(chain, i, target, timeMs) {
  const cert = chain[i];
  const items = [];
  items.push({ check: CHECK_NAMES.PARSE, ok: true, detail: 'X.509 v3；签名算法 ecdsa-with-SHA256；公钥 id-ecPublicKey / P-256（65 字节未压缩点）；签名 BIT STRING 内 DER INTEGER r/s 已转换为 32+32 字节 raw' });
  items.push({
    check: CHECK_NAMES.VALIDITY,
    ok: true,
    detail: `${fmtTime(cert.notBefore.getTime())} ≤ ${fmtTime(timeMs)} ≤ ${fmtTime(cert.notAfter.getTime())}`,
  });
  if (i === 0) {
    items.push({
      check: CHECK_NAMES.SAN,
      ok: true,
      detail: `目标主机名 "${target}" 命中叶证书 SAN dNSName [${cert.sanDns.join(', ')}]`,
    });
    items.push({
      check: CHECK_NAMES.CA,
      ok: true,
      detail: cert.basicConstraints && cert.basicConstraints.cA ? 'cA=true（异常）' : '叶证书 cA=false/无 BasicConstraints，非 CA',
    });
  } else {
    items.push({
      check: CHECK_NAMES.CA,
      ok: true,
      detail: `BasicConstraints cA=true，pathLenConstraint=${cert.basicConstraints?.pathLen ?? '未设置'}`,
    });
    items.push({
      check: CHECK_NAMES.KEY_USAGE,
      ok: true,
      detail: cert.keyUsage
        ? `keyUsage 含 keyCertSign（bit5）${cert.keyUsage.digitalSignature ? ' 与 digitalSignature' : ''}`
        : '无 keyUsage 扩展（RFC 5280 允许）',
    });
  }
  // Signature evidence toward the issuer.
  if (i < chain.length - 1) {
    items.push({
      check: CHECK_NAMES.SIGNATURE,
      ok: true,
      detail: `tbsCertificate（${cert.tbsRaw.length} 字节原始 DER）由上级 ${chain[i + 1].subject.label} 的 P-256 公钥验签通过`,
    });
  } else {
    items.push({ check: CHECK_NAMES.ANCHOR, ok: true, detail: '该证书即页面粘贴的信任锚，作为信任起点不再上溯' });
  }
  // pathLen evidence
  if (i >= 1 && cert.basicConstraints && cert.basicConstraints.pathLen !== null) {
    let nonSelfIssued = 0;
    for (let j = 1; j < i; j++) {
      if (!nameMatches(chain[j].subject, chain[j].issuer)) nonSelfIssued++;
    }
    items.push({
      check: CHECK_NAMES.PATH_LEN,
      ok: true,
      detail: `路径下方非自签发中间证书数 = ${nonSelfIssued} ≤ pathLenConstraint ${cert.basicConstraints.pathLen}`,
    });
  }
  if (cert.nameConstraints) {
    items.push({
      check: CHECK_NAMES.NAME_CONSTRAINTS,
      ok: true,
      detail: `本 CA 施加 permitted=[${cert.nameConstraints.permittedDns.join(', ') || '—'}]，excluded=[${cert.nameConstraints.excludedDns.join(', ') || '—'}]；与上级约束累积后适用于所有下级证书的 dNSName`,
    });
  }
  return items;
}

/**
 * Deterministic failure report: replay from the digest-minimal leaf, at each
 * level take the digest-minimal name-matching issuer candidate (flagging a
 * revisit as a cycle), and report its first failed check. The full attempt
 * table is attached for detail.
 */
function buildFailureReport(leaf, ctx, attempted) {
  const path = [leaf];
  const visited = new Set([leaf.digest]);
  let firstFail = null;
  for (let guard = 0; guard <= MAX_POOL + 1; guard++) {
    const head = path[path.length - 1];
    const matches = [ctx.anchor, ...ctx.pool]
      .filter((c) => nameMatches(head.issuer, c.subject))
      .sort(byDigest);
    if (matches.length === 0) {
      firstFail = {
        level: path.length - 1,
        cert: head,
        check: CHECK_NAMES.NAME_LINK,
        reason: `无法继续上溯：证书池中没有 subject 与 issuer "${head.issuer.label}" 一致的证书，链在第 ${path.length - 1} 级后中断`,
      };
      break;
    }
    const issuer = matches[0];
    if (visited.has(issuer.digest)) {
      firstFail = {
        level: path.length - 1,
        cert: head,
        issuer,
        check: CHECK_NAMES.CYCLE,
        reason: `沿摘要序最小的候选上溯时，签发者 "${issuer.subject.label}" 已在当前路径中出现，构成循环签发`,
      };
      break;
    }
    // Find the recorded edge attempts for this head+issuer pair.
    const edges = attempted.filter((e) => e.subjectDigest === head.digest && e.issuerDigest === issuer.digest);
    const badEdge = edges
      .flatMap((e) => e.checks.filter((c) => c.ok === false).map((c) => ({ edge: e, check: c })))
      .sort((a, b) => checkOrder(a.check.check) - checkOrder(b.check.check))[0];

    // Path-level failures (pathLen / name constraints / SAN) attach to the
    // anchor-terminating edge only; evaluate directly instead.
    if (issuer.digest === ctx.anchor.digest) {
      const full = [...path, issuer];
      // Signature/role failures first:
      if (badEdge) {
        const onIssuer = badEdge.check.target === 'anchor';
        firstFail = {
          level: onIssuer ? path.length : path.length - 1,
          cert: onIssuer ? issuer : head,
          issuer: onIssuer ? issuer : issuer,
          check: badEdge.check.check,
          reason: badEdge.check.detail,
        };
        break;
      }
      const pc = evaluatePath(full, ctx.target);
      if (!pc.ok) {
        const f = pc.failures.sort((a, b) => checkOrder(a.check) - checkOrder(b.check))[0];
        firstFail = {
          level: path.length - 1,
          cert: head,
          issuer,
          check: f.check,
          reason: f.detail,
          failingCertDigest: f.certDigest,
        };
        break;
      }
      // Should not happen (no chain found), but guard.
      firstFail = { level: path.length - 1, cert: head, check: CHECK_NAMES.ANCHOR, reason: '候选链未能完成（内部状态异常）' };
      break;
    }
    if (badEdge) {
      const onIssuer = badEdge.check.target === 'issuer';
      firstFail = {
        level: onIssuer ? path.length : path.length - 1,
        cert: onIssuer ? issuer : head,
        issuer,
        check: badEdge.check.check,
        reason: badEdge.check.detail,
      };
      break;
    }
    visited.add(issuer.digest);
    path.push(issuer);
  }

  return {
    ok: false,
    stage: 'path',
    target: ctx.target,
    verifyTimeMs: ctx.timeMs,
    failure: firstFail
      ? {
          level: firstFail.level,
          role:
            firstFail.level === 0
              ? '叶证书'
              : firstFail.cert.digest === ctx.anchor.digest
                ? '信任锚'
                : `第 ${firstFail.level} 级证书`,
          subject: firstFail.cert.subject.label,
          digest: firstFail.cert.digest,
          issuer: firstFail.issuer?.subject.label,
          check: firstFail.check,
          reason: firstFail.reason,
        }
      : null,
    attemptedEdges: attempted,
    chainsTried: new Set(attempted.map((e) => e.subjectDigest)).size,
  };
}

const CHECK_ORDER = [
  CHECK_NAMES.NAME_LINK,
  CHECK_NAMES.CYCLE,
  CHECK_NAMES.VALIDITY,
  CHECK_NAMES.CA,
  CHECK_NAMES.KEY_USAGE,
  CHECK_NAMES.SIGNATURE,
  CHECK_NAMES.PATH_LEN,
  CHECK_NAMES.NAME_CONSTRAINTS,
  CHECK_NAMES.SAN,
  CHECK_NAMES.ANCHOR,
];
function checkOrder(name) {
  const i = CHECK_ORDER.indexOf(name);
  return i === -1 ? CHECK_ORDER.length : i;
}

function summarizeParsed(certs) {
  return certs.map((c, i) => ({
    slot: c.slot,
    digest: c.digest,
    subject: c.subject?.label,
    issuer: c.issuer?.label,
    index: i,
  }));
}

export function fmtTime(ms) {
  return new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
}
