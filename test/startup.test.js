// Startup token check, at the process level: spawn the real server against a
// loopback stub that plays the Stickafile API, and assert what happens
// before the MCP client ever sends initialize.
//
//   a 401/403 from the server  → the process exits 1 with a message that
//                                names revoked / expired / wrong URL, and
//                                never serves a request
//   anything else              → the process starts, logs that the token is
//                                unverified, and answers initialize:
//                                5xx, 429, connection refused, and a server
//                                that never responds (timeout)
//
// No stickr checkout, no network beyond 127.0.0.1, no model.
//
//   node --test test/startup.test.js      (part of npm run test:unit)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyToken } from '../src/api.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const INDEX = path.join(HERE, '..', 'src', 'index.js');

// A stub API on a free loopback port. handler(req, res) may leave the
// response unanswered to simulate a hang.
function stub(handler) {
  return new Promise(resolve => {
    const srv = http.createServer(handler);
    srv.listen(0, '127.0.0.1', () => {
      const url = 'http://127.0.0.1:' + srv.address().port;
      resolve({ url, close: () => new Promise(r => { srv.closeAllConnections?.(); srv.close(() => r()); }) });
    });
  });
}
const reply = (status, body) => (req, res) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(body)); };
const hang = () => {}; // never answers

// Launch src/index.js against a base URL. Resolves once the process either
// exits or prints its "ready" line, whichever comes first.
function launch(baseUrl) {
  const child = spawn(process.execPath, [INDEX], {
    env: { ...process.env, STICKAFILE_TOKEN: 'sf_startup_test', STICKAFILE_URL: baseUrl, STICKAFILE_ALLOW: os.tmpdir() },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  let stderr = '', stdout = '';
  child.stderr.on('data', d => { stderr += d; });
  child.stdout.on('data', d => { stdout += d; });
  const settled = new Promise(resolve => {
    child.on('exit', code => resolve({ exited: true, code }));
    child.stderr.on('data', () => { if (stderr.includes('] ready')) resolve({ exited: false, code: null }); });
  });
  return {
    child, settled,
    get stderr() { return stderr; },
    get stdout() { return stdout; },
    kill() { try { child.kill(); } catch {} },
  };
}

// Send initialize over stdio and wait for the id:1 response.
async function initialize(proc) {
  const req = { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'startup-test', version: '0' } } };
  proc.child.stdin.write(JSON.stringify(req) + '\n');
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    const line = proc.stdout.split('\n').find(l => l.includes('"id":1'));
    if (line) return JSON.parse(line);
    await new Promise(r => setTimeout(r, 25));
  }
  throw new Error('no initialize response; stdout=' + proc.stdout + ' stderr=' + proc.stderr);
}

for (const status of [401, 403]) {
  test('rejected token (' + status + ') → exits 1 with causes named, never serves', async () => {
    const api = await stub(reply(status, { error: 'token revoked' }));
    try {
      const proc = launch(api.url);
      const r = await proc.settled;
      assert.equal(r.exited, true, 'process should have exited; stderr=' + proc.stderr);
      assert.equal(r.code, 1);
      assert.match(proc.stderr, /rejected STICKAFILE_TOKEN/);
      assert.match(proc.stderr, /token revoked/, 'server-supplied detail is relayed');
      assert.match(proc.stderr, /revoked or expired/);
      assert.match(proc.stderr, /STICKAFILE_URL/, 'wrong-server cause is named');
      assert.doesNotMatch(proc.stderr, /\] ready/);
      assert.equal(proc.stdout, '', 'nothing written to the MCP channel');
    } finally { await api.close(); }
  });
}

const transient = [
  ['5xx', () => stub(reply(503, { error: 'maintenance' })), /HTTP 503/],
  ['429', () => stub(reply(429, { error: 'slow down' })), /HTTP 429/],
  ['timeout (server never answers)', () => stub(hang), /no response within/],
  ['connection refused', async () => { const s = await stub(hang); const url = s.url; await s.close(); return { url, close: async () => {} }; }, /ECONNREFUSED/],
];
for (const [label, make, expect] of transient) {
  test('transient failure (' + label + ') → starts anyway and answers initialize', async () => {
    const api = await make();
    const proc = launch(api.url);
    try {
      const r = await proc.settled;
      assert.equal(r.exited, false, 'process should still be running; stderr=' + proc.stderr);
      assert.match(proc.stderr, /could not verify STICKAFILE_TOKEN at startup/);
      assert.match(proc.stderr, expect);
      assert.match(proc.stderr, /starting anyway/);
      const res = await initialize(proc);
      assert.equal(res.result.serverInfo.name, 'stickafile');
    } finally { proc.kill(); await api.close(); }
  });
}

test('verifyToken: 200 → ok, 401/403 → rejected, everything else → unknown', async () => {
  const cases = [[200, true], [401, false], [403, false], [404, null], [429, null], [500, null], [502, null]];
  for (const [status, ok] of cases) {
    const api = await stub(reply(status, { portals: [], error: 'e' + status }));
    try {
      const r = await verifyToken({ baseUrl: api.url, token: 'sf_x' }, { timeoutMs: 1000 });
      assert.equal(r.ok, ok, 'status ' + status + ' → ' + JSON.stringify(r));
      if (ok === false) assert.equal(r.status, status);
    } finally { await api.close(); }
  }
});

test('verifyToken: timeout is bounded and reported as unknown, not rejected', async () => {
  const api = await stub(hang);
  try {
    const t0 = Date.now();
    const r = await verifyToken({ baseUrl: api.url, token: 'sf_x' }, { timeoutMs: 300 });
    const took = Date.now() - t0;
    assert.equal(r.ok, null);
    assert.match(r.detail, /no response within 300 ms/);
    assert.ok(took < 1500, 'returned in ' + took + ' ms');
  } finally { await api.close(); }
});
