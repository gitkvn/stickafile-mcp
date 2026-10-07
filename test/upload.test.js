// Upload-layer tests against a loopback stub that plays the big-upload API
// (init → presigned PUT → report-etag → complete). No stickr checkout, no
// network beyond 127.0.0.1, no model.
//
//   node --test test/upload.test.js   (part of npm run test:unit)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { open } from 'node:fs/promises';
import { uploadFile, UploadError } from '../src/upload.js';

// A stub big-upload API. `complete` controls the /complete response:
// { status, json?, raw?, contentType? }. `downloadToken` seeds init.
function stub({ complete, downloadToken = null }) {
  return new Promise(resolve => {
    const srv = http.createServer((req, res) => {
      let url;
      const base = 'http://127.0.0.1:' + srv.address().port;
      if (req.method === 'POST' && req.url === '/api/big/init') {
        const body = { sessions: [{
          sessionId: 's1', uploadSecret: 'sec', chunkSize: 1024, totalChunks: 1,
          presignedUrls: [base + '/put/0'], downloadToken,
        }] };
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify(body));
      }
      if (req.method === 'PUT' && req.url === '/put/0') {
        res.writeHead(200, { ETag: '"etag0"' });
        return res.end();
      }
      if (req.method === 'POST' && req.url.startsWith('/api/big/report-etag/')) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end('{}');
      }
      if (req.method === 'POST' && req.url.startsWith('/api/big/complete/')) {
        res.writeHead(complete.status, { 'Content-Type': complete.contentType || 'application/json' });
        return res.end(complete.raw !== undefined ? complete.raw : JSON.stringify(complete.json || {}));
      }
      res.writeHead(404); res.end();
    });
    srv.listen(0, '127.0.0.1', () => resolve({
      url: 'http://127.0.0.1:' + srv.address().port,
      close: () => new Promise(r => { srv.closeAllConnections?.(); srv.close(() => r()); }),
    }));
  });
}

async function run(api, { downloadToken } = {}) {
  const WS = fs.mkdtempSync(path.join(os.tmpdir(), 'sf-up-'));
  const fp = path.join(WS, 'report.bin');
  fs.writeFileSync(fp, 'hello');
  const fh = await open(fp, 'r');
  try {
    return await uploadFile({
      client: { baseUrl: api.url, token: 'sf_x' },
      fh, filePath: fp, name: 'report.bin', size: 5, mimeType: 'text/plain',
      portalToken: 'agentpsh',
    });
  } finally {
    await fh.close().catch(() => {});
    fs.rmSync(WS, { recursive: true, force: true });
  }
}

// FINDING 4 — complete returns 200 but an unparseable body and init gave no
// download token. The file is finalized and public; uploadFile must NOT throw.
test('FINDING4: a successful complete with an unparseable body is not a failure', async () => {
  const api = await stub({ complete: { status: 200, raw: '<html>ok</html>', contentType: 'text/html' } });
  try {
    const result = await run(api);
    assert.equal(result.name, 'report.bin');
    assert.equal(result.size, 5);
    assert.equal(result.url, null, 'no readable link, but not an error');
  } finally { await api.close(); }
});

test('FINDING4: an unparseable complete still yields a link when init gave a token', async () => {
  const api = await stub({ complete: { status: 200, raw: 'nonsense' }, downloadToken: 'dltok123' });
  try {
    const result = await run(api);
    assert.match(result.url, /\/big\/dl\/dltok123$/);
  } finally { await api.close(); }
});

test('a normal complete returns the server downloadUrl', async () => {
  const api = await stub({ complete: { status: 200, json: { downloadUrl: 'https://stickafile.test/big/dl/abc' } } });
  try {
    const result = await run(api);
    assert.equal(result.url, 'https://stickafile.test/big/dl/abc');
  } finally { await api.close(); }
});

test('a failed complete (HTTP 500) still throws UploadError', async () => {
  const api = await stub({ complete: { status: 500, json: { error: 'assembly failed' } } });
  try {
    await assert.rejects(() => run(api), (e) => e instanceof UploadError);
  } finally { await api.close(); }
});
