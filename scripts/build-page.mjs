/**
 * Page build step: copies the static ES-module application from src/app into
 * dist/ with no bundling (the browser natively loads modules), after running
 * a few structural checks:
 *
 *   - every local path referenced from index.html exists in the tree
 *   - the worker module and its imports parse (via dynamic import in a
 *     browser-compatible way — here we only statically check referenced
 *     relative specifiers resolve to files)
 *   - the sample fixture exists
 *
 * A dist/build-manifest.json records source SHA-256 digests.
 */

import { cp, rm, mkdir, readFile, writeFile, readdir } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative, sep } from 'node:path';
import { createHash } from 'node:crypto';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const src = join(root, 'src', 'app');
const dist = join(root, 'dist');

async function walk(dir) {
  const out = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...(await walk(p)));
    else out.push(p);
  }
  return out;
}

async function collectLocalSpecifiers(file) {
  const text = await readFile(file, 'utf8');
  const specs = [];
  const re = /(?:from\s*|import\s*|new Worker\()\s*['"](\.{1,2}\/[^'"]+)['"]/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    if (m[1].endsWith('.js') || m[1].endsWith('.json')) specs.push(m[1]);
  }
  return specs;
}

async function main() {
  // 1. Referenced files exist (HTML)
  const html = await readFile(join(src, 'index.html'), 'utf8');
  const refs = [...html.matchAll(/(?:src|href)="(\/[^"]*)"/g)].map((m) => m[1]);
  for (const ref of refs) {
    const target = join(src, ref.replace(/^\//, ''));
    await readFile(target); // throws if missing
  }

  // 2. Every JS module's relative specifiers resolve on disk.
  const allJs = (await walk(src)).filter((f) => f.endsWith('.js'));
  for (const js of allJs) {
    for (const spec of await collectLocalSpecifiers(js)) {
      const resolvedSpec = spec.startsWith('/') ? spec.slice(1) : spec;
      const target = join(dirname(js), resolvedSpec);
      await readFile(target);
    }
    // Syntax check by loading through Node (DOM/Worker entry uses
    // document/self guards? main.js touches document at top-level, so only
    // import the crypto modules + worker specifiers indirectly; use
    // new Function syntax check instead).
    const code = await readFile(js, 'utf8');
    try {
      execFileSync(process.execPath, ['--check', js], { stdio: 'pipe' });
    } catch (e) {
      throw new Error(
        `语法检查失败 ${relative(root, js)}: ${String(e.stderr || e.message).trim()}`,
      );
    }
  }

  // 3. Fresh sample fixture exists.
  await readFile(join(src, 'samples', 'chain-sample.json'), 'utf8');

  // 4. Copy to dist.
  await rm(dist, { recursive: true, force: true });
  await mkdir(dist, { recursive: true });
  await cp(src, dist, { recursive: true });

  // 5. Manifest with SHA-256 of every shipped file.
  const shipped = await walk(dist);
  const manifest = {};
  for (const f of shipped) {
    const data = await readFile(f);
    manifest[relative(dist, f).split(sep).join('/')] = createHash('sha256').update(data).digest('hex');
  }
  await writeFile(join(dist, 'build-manifest.json'), JSON.stringify(manifest, null, 2));

  console.log(`Build OK: ${Object.keys(manifest).length} files -> dist/`);
}

main().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});
