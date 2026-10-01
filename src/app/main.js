/**
 * Page controller: collects the draft, dispatches verification to the Worker
 * and renders the returned report. No certificate logic lives here.
 */

const $ = (id) => document.getElementById(id);

const form = $('verify-form');
const anchorEl = $('anchor');
const poolEl = $('pool');
const dnsEl = $('dns');
const timeEl = $('time');
const resultEl = $('result');
const submitBtn = $('submit-btn');
const clearBtn = $('clear-btn');
const sampleBtn = $('sample-btn');
const poolCountEl = $('pool-count');
const workerStatusEl = $('worker-status');

let requestSeq = 0;
let lastReport = null;

// ---- Worker bootstrap (module worker) ----
let worker = null;

// WebCrypto subtle is only exposed in secure contexts (HTTPS or localhost).
// Detect that before starting the worker so the failure mode is explicit
// rather than a thrown error deep inside verification.
if (!globalThis.crypto || !globalThis.crypto.subtle) {
  workerStatusEl.textContent =
    '当前页面不在安全上下文中：WebCrypto 仅可通过 https:// 或 http://localhost 使用。请改用 HTTPS 反代或本机 localhost 访问。';
  submitBtn.disabled = true;
} else {
  try {
    worker = new Worker('/worker.js', { type: 'module' });
    worker.onmessage = onWorkerMessage;
    worker.onerror = (e) => {
      workerStatusEl.textContent = `Worker 错误：${e.message}`;
    };
  } catch (e) {
    workerStatusEl.textContent = '当前浏览器无法启动模块 Worker';
  }
}

// Default the verification instant to "now" in UTC.
timeEl.value = toDatetimeLocalValue(Date.now());

poolEl.addEventListener('input', updatePoolCount);
function updatePoolCount() {
  const { countBlocks } = useSplit(poolEl.value);
  poolCountEl.textContent = String(countBlocks);
  poolCountEl.style.color = countBlocks > 7 ? 'var(--bad)' : '';
}

// Dynamic import keeps the splitter in one place with the verifier; workers
// and page share the same module source.
async function useSplit(text) {
  const mod = await import('./crypto/verifier.js');
  const blocks = mod.splitPastedCertificates(text);
  return { countBlocks: blocks.length, blocks };
}

clearBtn.addEventListener('click', () => {
  form.reset();
  timeEl.value = toDatetimeLocalValue(Date.now());
  lastReport = null;
  resultEl.hidden = true;
  resultEl.replaceChildren();
  updatePoolCount();
});

sampleBtn.addEventListener('click', async () => {
  try {
    const resp = await fetch('/samples/chain-sample.json');
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const sample = await resp.json();
    anchorEl.value = sample.anchorPem;
    poolEl.value = sample.poolPem;
    dnsEl.value = sample.dns;
    if (sample.verifyTime) timeEl.value = sample.verifyTime;
    updatePoolCount();
  } catch (e) {
    workerStatusEl.textContent = `示例加载失败：${e.message}`;
  }
});

form.addEventListener('submit', (e) => {
  e.preventDefault();
  // Any fresh submission invalidates a previously displayed conclusion.
  clearResultView();
  if (!worker) {
    renderFatal('Worker 未就绪，无法执行复核。');
    return;
  }
  const timeMs = parseDatetimeLocal(timeEl.value);
  if (timeMs === null) {
    renderFatal('验证时刻格式无效，请使用 UTC 日期时间输入。');
    return;
  }
  const requestId = ++requestSeq;
  submitBtn.disabled = true;
  workerStatusEl.textContent = 'Worker 核验中…';
  worker.postMessage({
    type: 'verify',
    requestId,
    payload: {
      anchorText: anchorEl.value,
      poolText: poolEl.value,
      dnsName: dnsEl.value,
      verifyTimeMs: timeMs,
    },
  });
});

function onWorkerMessage(ev) {
  const msg = ev.data;
  if (msg.requestId !== requestSeq) return; // stale response
  submitBtn.disabled = false;
  if (msg.type === 'error') {
    workerStatusEl.textContent = '';
    renderFatal(`复核过程中出现未预期错误：${msg.message}`);
    return;
  }
  workerStatusEl.textContent = '';
  lastReport = msg.report;
  renderReport(msg.report);
}

function clearResultView() {
  lastReport = null;
  resultEl.hidden = true;
  resultEl.replaceChildren();
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

function renderFatal(message) {
  resultEl.hidden = false;
  resultEl.replaceChildren();
  const box = el('div', 'verdict bad');
  box.append(
    span('mark', '✕'),
    dom('div', {}, [
      dom('h2', {}, ['无法完成复核']),
      dom('p', {}, [message]),
    ]),
  );
  resultEl.append(box);
}

function renderReport(r) {
  resultEl.hidden = false;
  resultEl.replaceChildren();

  if (r.ok) {
    resultEl.append(renderSuccess(r));
  } else {
    resultEl.append(renderFailure(r));
  }
  if (r.attemptedEdges && r.attemptedEdges.length) {
    resultEl.append(renderAttempts(r));
  }
}

function renderSuccess(r) {
  const frag = document.createDocumentFragment();
  const verdict = el('div', 'verdict ok');
  verdict.append(
    span('mark', '✓'),
    dom('div', {}, [
      dom('h2', {}, [`信任链成立：${r.target}`]),
      dom('p', { class: 'meta' }, [r.selectionRule]),
      dom('p', { class: 'meta' }, [
        `验证时刻 ${fmtTime(r.verifyTimeMs)} · 链长 ${r.chain.length}（含锚）· 共尝试 ${r.chainsTried ?? '多'} 条候选路径`,
      ]),
    ]),
  );
  frag.append(verdict);

  const wrap = el('div', 'chain');
  // Display anchor at top, leaf at bottom.
  for (let i = r.chain.length - 1; i >= 0; i--) {
    wrap.append(renderLevel(r.chain[i]));
    if (i > 0) wrap.append(div('arrow', '↑ 以下证书由上方 CA 签发'));
  }
  frag.append(wrap);
  return frag;
}

function renderFailure(r) {
  const frag = document.createDocumentFragment();
  const verdict = el('div', 'verdict bad');
  const f = r.failure || {};
  const where =
    r.stage === 'input'
      ? f.slot
        ? `${f.slot}${f.subject ? `（${f.subject}）` : ''}`
        : '输入'
      : f.level !== undefined
        ? f.level === 0
          ? `叶证书（${f.subject ?? ''}）`
          : `${f.role || `第 ${f.level} 级`}（${f.subject ?? ''}）`
        : '链构造';
  verdict.append(
    span('mark', '✕'),
    dom('div', {}, [
      dom('h2', {}, ['信任链不成立']),
      dom('p', {}, [
        `首个失败环节：${where} · 检查项「${f.check ?? '输入解析'}」`,
      ]),
      dom('p', {}, [f.reason || '未给出具体原因']),
      dom('p', { class: 'meta' }, [
        r.target ? `目标主机名 ${r.target}` : '',
        r.verifyTimeMs ? ` · 验证时刻 ${fmtTime(r.verifyTimeMs)}` : '',
        f.digest ? ` · 证书 SHA-256 ${f.digest}` : '',
      ]),
    ]),
  );
  frag.append(verdict);

  if (Array.isArray(r.chain) && r.chain.length) {
    const wrap = el('div', 'chain');
    for (let i = r.chain.length - 1; i >= 0; i--) {
      const card = renderLevel(r.chain[i]);
      if (i === f.level) card.classList.add('first-fail');
      wrap.append(card);
      if (i > 0) wrap.append(div('arrow', '↑'));
    }
    frag.append(wrap);
  }
  return frag;
}

function renderLevel(lvl) {
  const card = el('div', 'level-card');
  const head = el('div', 'level-head');
  head.append(
    span(`level-badge ${lvl.role}`, roleLabel(lvl)),
    span('level-subject', lvl.subject),
  );
  card.append(head);

  const kv = el('dl', 'kv');
  kv.append(kvRow('签发者', lvl.issuer));
  kv.append(kvRow('序列号', lvl.serial));
  kv.append(kvRow('有效期', `${fmtTime(lvl.notBefore)} ～ ${fmtTime(lvl.notAfter)}`));
  kv.append(kvRow('SAN dNSName', lvl.sanDns.length ? lvl.sanDns.join(', ') : '（无）'));
  if (lvl.basicConstraints) {
    const bc = lvl.basicConstraints;
    kv.append(kvRow('BasicConstraints', `cA=${bc.cA}${bc.pathLen === null || bc.pathLen === undefined ? '' : `, pathLenConstraint=${bc.pathLen}`}`));
  }
  if (lvl.keyUsage) {
    const parts = [];
    if (lvl.keyUsage.digitalSignature) parts.push('digitalSignature');
    if (lvl.keyUsage.keyCertSign) parts.push('keyCertSign');
    kv.append(kvRow('keyUsage', parts.join(', ') || '（两个关键位均未置位）'));
  }
  if (lvl.nameConstraints) {
    const nc = lvl.nameConstraints;
    kv.append(
      kvRow(
        'NameConstraints',
        `permitted DNS=[${nc.permittedDns.join(', ') || '—'}]；excluded DNS=[${nc.excludedDns.join(', ') || '—'}]${nc.hasOtherNameTypes ? '；含非 DNS 约束（按策略仅核验 DNS 部分）' : ''}`,
      ),
    );
  }
  kv.append(kvRow('SHA-256', lvl.digest));
  card.append(kv);

  if (lvl.evidence && lvl.evidence.length) {
    const ul = el('ul', 'checks');
    for (const c of lvl.evidence) {
      ul.append(
        dom('li', {}, [
          span('ico pass', '✓'),
          span('check-name', c.check),
          span('check-detail', c.detail),
        ]),
      );
    }
    card.append(ul);
  }
  return card;
}

function renderAttempts(r) {
  const details = el('details', 'attempts');
  details.append(dom('summary', {}, [`核验尝试明细（${r.attemptedEdges.length} 条边记录）`]));
  const table = el('table', 'attempt-table');
  table.append(
    dom('thead', {}, [
      dom('tr', {}, [
        dom('th', {}, ['层级']),
        dom('th', {}, ['证书主体 → 候选签发者']),
        dom('th', {}, ['检查项与结果']),
      ]),
    ]),
  );
  const tbody = dom('tbody');
  // Merge duplicate edges (same subject+issuer) by check name, keeping any
  // failing detail.
  const merged = new Map();
  for (const e of r.attemptedEdges) {
    const key = `${e.subjectDigest}|${e.issuerDigest}`;
    if (!merged.has(key)) {
      merged.set(key, { e, checks: new Map() });
    }
    const bucket = merged.get(key);
    for (const c of e.checks) {
      const prev = bucket.checks.get(c.check);
      if (!prev || (prev.ok !== false && c.ok === false)) bucket.checks.set(c.check, c);
    }
  }
  const rows = Array.from(merged.values()).sort((a, b) =>
    a.e.level !== b.e.level ? a.e.level - b.e.level : a.e.subjectDigest.localeCompare(b.e.subjectDigest));
  for (const { e, checks } of rows) {
    const checkHtml = Array.from(checks.values()).map((c) => {
      const icon = c.ok === false ? '✕' : c.ok ? '✓' : '·';
      const cls = c.ok === false ? 'fail' : c.ok ? 'pass' : '';
      return { icon, cls, text: `${c.check}：${c.detail}` };
    });
    tbody.append(
      dom('tr', {}, [
        dom('td', {}, [String(e.level)]),
        dom('td', {}, [
          `${e.subject}`,
          dom('div', { style: 'color:var(--muted)' }, [`→ ${e.issuer}${e.isAnchor ? '（信任锚）' : ''}`]),
        ]),
        dom('td', {}, checkHtml.map((c) => dom('div', { class: c.cls }, [`${c.icon} ${c.text}`]))),
      ]),
    );
  }
  table.append(tbody);
  details.append(table);
  return details;
}

// ---------------------------------------------------------------------------
// tiny DOM helpers
// ---------------------------------------------------------------------------

function el(tag, cls) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  return n;
}
function div(cls, text) { const n = el('div', cls); if (text !== undefined) n.textContent = text; return n; }
function span(cls, text) { const n = el('span', cls); n.textContent = text; return n; }
function dom(tag, attrs, children) {
  const n = document.createElement(tag);
  if (attrs) for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
  if (children) for (const c of children) {
    n.append(typeof c === 'string' ? document.createTextNode(c) : c);
  }
  return n;
}
function kvRow(k, v) {
  const frag = document.createDocumentFragment();
  frag.append(dom('dt', {}, [k]));
  frag.append(dom('dd', {}, [String(v)]));
  return frag;
}
function roleLabel(lvl) {
  if (lvl.role === 'leaf') return '叶证书';
  if (lvl.role === 'anchor') return '信任锚';
  return `中间 CA · L${lvl.level}`;
}
function fmtTime(ms) {
  return new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

// datetime-local works in wall-clock time as displayed; we label it UTC and
// interpret the entered fields directly as UTC.
function toDatetimeLocalValue(ms) {
  const d = new Date(ms);
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}T${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
}
function parseDatetimeLocal(value) {
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?$/.exec(value || '');
  if (!m) return null;
  return Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0));
}
