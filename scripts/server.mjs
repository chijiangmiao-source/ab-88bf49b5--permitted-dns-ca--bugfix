/**
 * Zero-dependency static file server for the review page.
 *
 *   GET /            -> index.html
 *   GET /healthz     -> 200 {"status":"ok",...}
 *   GET /<file>      -> dist/<file> (path traversal guarded)
 *
 * Configuration via environment:
 *   PORT       listen port (default 8080)
 *   HOST       bind address (default 0.0.0.0)
 *   DIST_DIR   document root (default ./dist)
 */

import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join, normalize, sep } from 'node:path';
import { createHash } from 'node:crypto';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const distDir = process.env.DIST_DIR || join(root, 'dist');
const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || '0.0.0.0';

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.map': 'application/json; charset=utf-8',
};

function send(res, status, body, headers = {}) {
  res.writeHead(status, { 'Cache-Control': 'no-store', ...headers });
  res.end(body);
}

function json(res, status, obj) {
  send(res, status, JSON.stringify(obj), { 'Content-Type': 'application/json; charset=utf-8' });
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = decodeURIComponent(url.pathname);

  if (req.method !== 'GET' && req.method !== 'HEAD') {
    return send(res, 405, 'method not allowed', { 'Allow': 'GET, HEAD' });
  }

  if (pathname === '/healthz' || pathname === '/health') {
    return json(res, 200, {
      status: 'ok',
      service: 'cert-chain-review',
      time: new Date().toISOString(),
    });
  }

  let rel = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
  // Guard against path traversal: resolve under dist and re-check prefix.
  const target = normalize(join(distDir, rel));
  if (target !== distDir && !target.startsWith(distDir + sep)) {
    return send(res, 403, 'forbidden');
  }

  let data;
  try {
    const st = await stat(target);
    if (st.isDirectory()) {
      data = await readFile(join(target, 'index.html'));
      return send(res, 200, data, { 'Content-Type': MIME['.html'] });
    }
    data = await readFile(target);
  } catch {
    return send(res, 404, 'not found', { 'Content-Type': 'text/plain; charset=utf-8' });
  }

  const dot = rel.lastIndexOf('.');
  const ext = dot >= 0 ? rel.slice(dot) : '';
  const type = MIME[ext] || 'application/octet-stream';
  const etag = '"' + createHash('sha256').update(data).digest('base64url') + '"';
  res.writeHead(200, {
    'Content-Type': type,
    'X-Content-Type-Options': 'nosniff',
    'ETag': etag,
    'Cache-Control': 'no-store',
  });
  res.end(req.method === 'HEAD' ? undefined : data);
});

server.listen(PORT, HOST, () => {
  console.log(`cert-chain-review listening on http://${HOST}:${PORT} (root ${distDir})`);
});

export { server };
