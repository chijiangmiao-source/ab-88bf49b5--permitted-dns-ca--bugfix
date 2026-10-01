/**
 * DNS name handling for certificate validation.
 *
 *  - normalize/validate the target DNS name typed by the engineer
 *  - RFC 5280 7.2 SAN comparison against dNSName entries (including the
 *    wildcard rules from RFC 6125 that the Web PKI uses)
 *  - RFC 5280 4.2.1.10 name-constraint matching for permitted/excluded
 *    dNSName subtrees
 */

/**
 * Normalize user input for comparison: trailing dot removed, IDN/punycode
 * conversion where the platform supports it, ASCII lower-casing.
 * Returns null when the input is not a syntactically usable DNS name.
 * @param {string} input
 */
export function normalizeDns(input) {
  if (typeof input !== 'string') return { ok: false, reason: '名称必须是文本' };
  let name = input.trim().toLowerCase();
  if (name === '') return { ok: false, reason: '名称为空' };
  if (name.length > 253) return { ok: false, reason: '名称超过 253 个字符' };
  if (name.endsWith('.')) name = name.slice(0, -1);
  // Convert U-labels to A-labels if internationalized names were pasted.
  try {
    if (/[^\x00-\x7f]/.test(name) && typeof URL !== 'undefined') {
      // https://url.spec.whatwg.org/ host parsing punycodes for us.
      name = new URL(`http://${name}/`).hostname.replace(/\.$/, '');
    }
  } catch {
    return { ok: false, reason: '名称无法转换为 ASCII (punycode)' };
  }
  if (name.length === 0) return { ok: false, reason: '名称为空' };
  const labels = name.split('.');
  for (const label of labels) {
    if (label.length === 0) return { ok: false, reason: '存在空标签（连续的点）' };
    if (label.length > 63) return { ok: false, reason: `标签 "${label}" 超过 63 个字符` };
    if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label) && !/^xn--[a-z0-9-]{1,59}$/.test(label)) {
      return { ok: false, reason: `标签 "${label}" 含非法字符` };
    }
    if (label.startsWith('xn--') && !/^xn--[a-z0-9-]+$/.test(label)) {
      return { ok: false, reason: `Punycode 标签 "${label}" 非法` };
    }
  }
  return { ok: true, name };
}

function labelsOf(name) {
  return name.split('.');
}

/**
 * RFC 5280 7.2 DNS name comparison plus the standard single-label wildcard
 * rule of RFC 6125 6.4.3:
 *
 *   - SAN entry "*" matches a single label
 *   - SAN entry "*.example.com" matches any one label directly under
 *     example.com (not example.com itself, and not a.b.example.com)
 *   - otherwise comparison is case-insensitive exact equality
 *
 * Wildcards may only appear as the complete left-most label.
 */
export function dnsNameMatches(target, sanEntry) {
  const t = String(sanEntry).trim().toLowerCase().replace(/\.$/, '');
  if (t === '') return false;
  if (t === '*') {
    // "*" alone matches any single label.
    return labelsOf(target).length === 1 || !target.includes('.');
  }
  if (t.includes('*')) {
    // Wildcard is accepted only as the complete left-most label ("*.x"),
    // never mid-label ("w*.x") or in other positions.
    if (!t.startsWith('*.') || t.indexOf('*', 1) !== -1) return false;
    const base = t.slice(2); // text after "*."
    if (base === '') return false;
    const tLabels = labelsOf(target);
    const bLabels = labelsOf(base);
    if (tLabels.length !== bLabels.length + 1) return false;
    if (tLabels[0] === '' || tLabels[0].length > 63) return false;
    for (let i = 0; i < bLabels.length; i++) {
      if (tLabels[i + 1] !== bLabels[i]) return false;
    }
    return true;
  }
  return target === t;
}

/**
 * RFC 5280 4.2.1.10 dNSName constraint matching.
 *
 * @param {string} target normalized target host name (lower case, no root dot)
 * @param {string} subtree the constraint (possibly begins with ".")
 *
 * Rules quoted from RFC 5280:
 *   "DNS name restrictions are expressed as host.example.com.  Any DNS
 *    name that can be constructed by simply adding zero or more labels to
 *    the left-hand side of the name satisfies the name constraint.  For
 *    example, www.host.example.com would satisfy the constraint but
 *    host1.example.com would not."
 *
 * A leading "." form (".example.com") is accepted as a common vendor
 * convention meaning strict sub-domain (example.com itself excluded).
 */
export function dnsConstraintMatches(target, subtree) {
  const c = String(subtree).trim().toLowerCase().replace(/\.$/, '');
  if (c === '') {
    // Empty subtree: RFC semantics are "all DNS names" when present as
    // permitted; openssl maps that to ".": treat leading-dot empty as such.
    return true;
  }
  if (c.startsWith('.')) {
    const base = c.slice(1);
    if (base === '') return true; // "." = every DNS name
    return target.endsWith('.' + base) && target.length > base.length + 1;
  }
  if (target === c) return true;
  return target.endsWith('.' + c);
}

/**
 * Evaluate accumulated DNS constraints at one path level.
 *
 * @param {string} target
 * @param {{permittedDns: string[], excludedDns: string[]}} accumulated
 * @returns {{ok: true} | {ok: false, reason: string}}
 */
export function checkDnsConstraints(target, accumulated) {
  for (const excluded of accumulated.excludedDns) {
    if (dnsConstraintMatches(target, excluded)) {
      return { ok: false, reason: `主机名 "${target}" 命中 excludedSubtrees 中的 "${excluded}"` };
    }
  }
  if (accumulated.permittedDns.length > 0) {
    let permitted = false;
    for (const p of accumulated.permittedDns) {
      if (dnsConstraintMatches(target, p)) {
        permitted = true;
        break;
      }
    }
    if (!permitted) {
      return {
        ok: false,
        reason: `主机名 "${target}" 不落在任何 permittedSubtrees（${accumulated.permittedDns
          .map((p) => `"${p}"`)
          .join('、')}）内`,
      };
    }
  }
  return { ok: true };
}
