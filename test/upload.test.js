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
import { uploadFile, initBody, UploadError } from '../src/upload.js';

// A stub big-upload API. `complete` controls the /complete response:
// { status, json?, raw?, contentType? }. `downloadToken` seeds init. The
// parsed init request body is kept on `seen.init`.
function stub({ complete, downloadToken = null }) {
  const seen = { init: null };
  return new Promise(resolve => {
    const srv = http.createServer((req, res) => {
      const base = 'http://127.0.0.1:' + srv.address().port;
      if (req.method === 'POST' && req.url === '/api/big/init') {
        let raw = '';
        req.on('data', d => { raw += d; });
        req.on('end', () => {
          seen.init = JSON.parse(raw);
          const body = { sessions: [{
            sessionId: 's1', uploadSecret: 'sec', chunkSize: 1024, totalChunks: 1,
            presignedUrls: [base + '/put/0'], downloadToken,
          }] };
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(body));
        });
        return;
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
      url: 'http://127.0.0.1:' + srv.address().port, seen,
      close: () => new Promise(r => { srv.closeAllConnections?.(); srv.close(() => r()); }),
    }));
  });
}

// Uploads a 5-byte file through the stub. `target` overrides portalToken /
// note; the default is a portal push, as the older tests below expect.
async function run(api, target = { portalToken: 'agentpsh' }) {
  const WS = fs.mkdtempSync(path.join(os.tmpdir(), 'sf-up-'));
  const fp = path.join(WS, 'report.bin');
  fs.writeFileSync(fp, 'hello');
  const fh = await open(fp, 'r');
  try {
    return await uploadFile({
      client: { baseUrl: api.url, token: 'sf_x' },
      fh, filePath: fp, name: 'report.bin', size: 5, mimeType: 'text/plain',
      ...target,
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

// 0.2.0 — a push with no portal is a quick send: init must carry no
// portalToken at all (the server reads its absence as "make a link"), and
// the optional note rides along only when given.
test('initBody: no portal and no note → files only', () => {
  const body = initBody({ name: 'r.bin', size: 5, mimeType: 'text/plain' });
  assert.deepEqual(body, { files: [{ filename: 'r.bin', fileSize: 5, mimeType: 'text/plain' }] });
  assert.equal('portalToken' in body, false);
  assert.equal('note' in body, false);
});

test('initBody: portal and note are included when given', () => {
  const body = initBody({ name: 'r.bin', size: 5, mimeType: 'text/plain', portalToken: 'agentpsh', note: 'for QA' });
  assert.equal(body.portalToken, 'agentpsh');
  assert.equal(body.note, 'for QA');
});

test('a push without a portal sends init with no portalToken (a link)', async () => {
  const api = await stub({ complete: { status: 200, json: { downloadUrl: 'https://stickafile.test/big/dl/link1' } } });
  try {
    const result = await run(api, { note: 'nightly build' });
    assert.equal(result.url, 'https://stickafile.test/big/dl/link1');
    assert.equal('portalToken' in api.seen.init, false, JSON.stringify(api.seen.init));
    assert.equal(api.seen.init.note, 'nightly build');
  } finally { await api.close(); }
});

test('a push with a portal sends init with that portalToken and no note key', async () => {
  const api = await stub({ complete: { status: 200, json: { downloadUrl: 'https://stickafile.test/big/dl/p1' } } });
  try {
    await run(api);
    assert.equal(api.seen.init.portalToken, 'agentpsh');
    assert.equal('note' in api.seen.init, false);
  } finally { await api.close(); }
});
