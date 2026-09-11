// End-to-end: boots the stickr server + mock S3 from a sibling checkout
// (STICKR_REPO, default ../stickr), seeds a user, a token and a portal into
// the scratch DB, then launches src/index.js over stdio through the MCP
// client SDK and exercises both tools: the path vetting, portal defaulting,
// a 3-chunk push, and a 505 MiB push that crosses the 100-URL presign window
// (the riskiest part of the port). Downloads are hashed against the source.
//
//   npm test
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(HERE, '..');
const STICKR = path.resolve(process.env.STICKR_REPO || path.join(ROOT, '..', 'stickr'));
const TMP = path.join(HERE, '.tmp');
const APP_PORT = 3993;
const S3_PORT = 4572;
const APP = 'http://127.0.0.1:' + APP_PORT;

if (!fs.existsSync(path.join(STICKR, 'server.js'))) { console.error('stickr checkout not found at ' + STICKR + ' (set STICKR_REPO)'); process.exit(2); }
fs.rmSync(TMP, { recursive: true, force: true });
fs.mkdirSync(TMP, { recursive: true });

const children = [];
function launch(name, file, args, env) {
  const child = spawn(process.execPath, [file, ...args], { env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
  const log = fs.createWriteStream(path.join(TMP, name + '.log'));
  child.stdout.pipe(log); child.stderr.pipe(log);
  children.push(child);
}
let mcp = null;
function cleanup(code) {
  if (mcp) mcp.close().catch(() => {});
  children.forEach(c => { try { c.kill(); } catch {} });
  process.exit(code);
}
async function waitFor(url, tries = 40) {
  for (let i = 0; i < tries; i++) {
    try { await fetch(url); return; } catch {}
    await new Promise(r => setTimeout(r, 250));
  }
  throw new Error('service at ' + url + ' never came up');
}
let pass = 0, fail = 0;
const check = (label, cond, extra) => { if (cond) { pass++; console.log('  ✓', label); } else { fail++; console.log('  ✗', label, extra || ''); } };
const sha = buf => crypto.createHash('sha256').update(buf).digest('hex');

(async () => {
  // ── boot ──
  launch('mock-s3', path.join(STICKR, 'test', 'upload-e2e', 'mock-s3.js'), [String(S3_PORT)], {});
  launch('server', path.join(STICKR, 'server.js'), [], {
    PORT: String(APP_PORT),
    SESSION_SECRET: 'mcp-e2e-test',
    R2_ACCOUNT_ID: 'testacct', R2_ACCESS_KEY_ID: 'testkey', R2_SECRET_ACCESS_KEY: 'testsecret', R2_BUCKET_NAME: 'testbucket',
    R2_ENDPOINT_OVERRIDE_LOCAL_TEST: 'http://127.0.0.1:' + S3_PORT,
    STICKR_DB_DIR_OVERRIDE_LOCAL_TEST: TMP,
    EMAIL_NOTIFICATIONS_ENABLED: '',
  });
  await waitFor(APP + '/');

  // ── seed: user, token, one active portal ──
  const db = createRequire(path.join(STICKR, 'package.json'))('better-sqlite3')(path.join(TMP, 'stickr.db'));
  db.prepare("INSERT INTO users (id, google_id, email, name) VALUES ('u-mcp', 'g-mcp', 'mcp@harness.test', 'MCP User')").run();
  const secret = 'sf_' + crypto.randomBytes(32).toString('base64url');
  db.prepare("INSERT INTO api_tokens (id, user_id, name, token_hash, token_prefix, scopes) VALUES ('tok-mcp', 'u-mcp', 'e2e', ?, ?, 'portals:read portals:push')").run(sha(secret), secret.slice(0, 11));
  // Portal tokens are 8 chars; init rejects any other length.
  db.prepare("INSERT INTO portals (token, owner_email, name, status, shared_view) VALUES ('agentpsh', 'mcp@harness.test', 'agent pushes', 'active', 0)").run();

  // ── workspace: allowed root with fixtures, plus an outside dir ──
  const WS = fs.mkdtempSync(path.join(os.tmpdir(), 'sf-ws-'));
  const OUTSIDE = fs.mkdtempSync(path.join(os.tmpdir(), 'sf-out-'));
  const small = crypto.randomBytes(12 * 1024 * 1024 + 7); // 3 chunks at 5 MB
  fs.writeFileSync(path.join(WS, 'report.bin'), small);
  fs.mkdirSync(path.join(WS, '.git'));
  fs.writeFileSync(path.join(WS, '.git', 'config'), 'x');
  fs.writeFileSync(path.join(WS, '.env'), 'SECRET=1');
  fs.writeFileSync(path.join(WS, 'server.pem'), 'x');
  fs.writeFileSync(path.join(WS, 'empty.txt'), '');
  fs.writeFileSync(path.join(OUTSIDE, 'id_rsa'), 'x');
  fs.writeFileSync(path.join(OUTSIDE, 'plain.txt'), 'outside');
  fs.symlinkSync(path.join(OUTSIDE, 'plain.txt'), path.join(WS, 'innocent-link.txt'));

  // ── launch the MCP server over stdio ──
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [path.join(ROOT, 'src', 'index.js')],
    cwd: WS,
    env: { ...process.env, STICKAFILE_TOKEN: secret, STICKAFILE_URL: APP },
    stderr: 'pipe',
  });
  const serverLog = fs.createWriteStream(path.join(TMP, 'mcp.log'));
  mcp = new Client({ name: 'e2e', version: '0' });
  await mcp.connect(transport);
  transport.stderr.pipe(serverLog);
  const call = (name, args, opts) => mcp.callTool({ name, arguments: args || {} }, undefined, opts);
  const text = r => (r.content || []).map(c => c.text || '').join('\n');

  console.log('TOOLS');
  const tools = (await mcp.listTools()).tools.map(t => t.name).sort();
  check('exactly push + list_portals', tools.join(',') === 'list_portals,push', tools.join(','));

  console.log('LIST');
  const l = await call('list_portals');
  check('lists the seeded portal as inbox', !l.isError && l.structuredContent.portals.length === 1 && l.structuredContent.portals[0].name === 'agent pushes' && l.structuredContent.portals[0].mode === 'inbox', JSON.stringify(l));

  console.log('SAFETY');
  const refused = async (label, p, needle) => {
    const r = await call('push', { path: p });
    check(label, r.isError && text(r).includes(needle), JSON.stringify(r));
    return r;
  };
  await refused('relative path refused', 'report.bin', 'must be absolute');
  await refused('outside root refused', path.join(OUTSIDE, 'plain.txt'), 'outside the allowed workspace');
  await refused('symlink to outside refused (resolved)', path.join(WS, 'innocent-link.txt'), 'outside the allowed workspace');
  await refused('dot-directory refused', path.join(WS, '.git', 'config'), 'dot-directory');
  await refused('dotfile refused', path.join(WS, '.env'), 'dotfile');
  await refused('credential-shaped name refused', path.join(WS, 'server.pem'), 'credential');
  await refused('directory refused', WS, 'not a regular file');
  await refused('empty file refused', path.join(WS, 'empty.txt'), 'empty');
  await refused('missing file', path.join(WS, 'nope.bin'), 'file not found');
  check('no upload session was opened by any refusal', db.prepare('SELECT COUNT(*) AS c FROM upload_sessions').get().c === 0);

  console.log('PUSH');
  const progress = [];
  const p1 = await call('push', { path: path.join(WS, 'report.bin') }, { onprogress: n => progress.push(n) });
  check('push ok with url/name/size', !p1.isError && p1.structuredContent && p1.structuredContent.name === 'report.bin' && p1.structuredContent.size === small.length && /^http.*\/big\/dl\/[0-9a-f]{32}$/.test(p1.structuredContent.url), JSON.stringify(p1));
  check('text content carries the link', text(p1).includes(p1.structuredContent.url));
  check('progress notifications arrived, monotonic, ending at total', progress.length >= 3 && progress.every((n, i) => i === 0 || n.progress >= progress[i - 1].progress) && progress[progress.length - 1].progress === small.length && progress[progress.length - 1].total === small.length, JSON.stringify(progress));
  const row = db.prepare('SELECT token, file_size, portal_token, uploader_name FROM big_files WHERE filename = ?').get('report.bin');
  check('file row in the seeded portal, uploader defaulted to owner', row && row.portal_token === 'agentpsh' && row.file_size === small.length && row.uploader_name === 'MCP User', JSON.stringify(row));
  const dl = await fetch(APP + '/api/big/download/' + row.token, { redirect: 'follow' });
  check('downloaded bytes identical', dl.ok && sha(Buffer.from(await dl.arrayBuffer())) === sha(small));
  check('session completed and pinned to the token', db.prepare("SELECT status, api_token_id FROM upload_sessions WHERE filename = 'report.bin'").get().api_token_id === 'tok-mcp');
  check('token never appears in tool output', !JSON.stringify(p1).includes(secret) && !JSON.stringify(l).includes(secret));

  console.log('PORTAL DEFAULTING');
  db.prepare("INSERT INTO portals (token, owner_email, name, status, shared_view) VALUES ('secondpt', 'mcp@harness.test', 'Client Drop', 'active', 1)").run();
  const amb = await call('push', { path: path.join(WS, 'report.bin') });
  check('two active portals, none given → error listing both', amb.isError && text(amb).includes('2 active portals') && text(amb).includes('agent pushes') && text(amb).includes('Client Drop'), text(amb));
  const byName = await call('push', { path: path.join(WS, 'report.bin'), portal: 'client drop' });
  check('portal by name (case-insensitive) → pushed to it', !byName.isError && db.prepare("SELECT portal_token FROM big_files WHERE filename = 'report.bin' ORDER BY rowid DESC").get().portal_token === 'secondpt', text(byName));
  const byTok = await call('push', { path: path.join(WS, 'report.bin'), portal: 'agentpsh' });
  check('portal by token → pushed to it', !byTok.isError && db.prepare("SELECT portal_token FROM big_files WHERE filename = 'report.bin' ORDER BY rowid DESC").get().portal_token === 'agentpsh', text(byTok));
  const nf = await call('push', { path: path.join(WS, 'report.bin'), portal: 'nope' });
  check('unknown portal → error naming the choices', nf.isError && text(nf).includes('not found') && text(nf).includes('agent pushes'), text(nf));
  db.prepare("UPDATE portals SET status = 'deactivated' WHERE token = 'secondpt'").run();
  const deact = await call('push', { path: path.join(WS, 'report.bin'), portal: 'Client Drop' });
  check('deactivated portal named explicitly → error', deact.isError && text(deact).includes('deactivated'), text(deact));
  const single = await call('push', { path: path.join(WS, 'report.bin') });
  check('one active again → defaults without arg', !single.isError, text(single));
  db.prepare("UPDATE portals SET status = 'deactivated' WHERE token = 'agentpsh'").run();
  const none = await call('push', { path: path.join(WS, 'report.bin') });
  check('zero active → error pointing at browser creation', none.isError && text(none).includes('/portal/new'), text(none));
  db.prepare("UPDATE portals SET status = 'active' WHERE token = 'agentpsh'").run();

  console.log('BAD TOKEN');
  db.prepare("UPDATE api_tokens SET revoked_at = datetime('now') WHERE id = 'tok-mcp'").run();
  const rv = await call('list_portals');
  check('revoked token → clear error, server still up', rv.isError && text(rv).includes('rejected the token'), text(rv));
  db.prepare("UPDATE api_tokens SET revoked_at = NULL WHERE id = 'tok-mcp'").run();

  console.log('505 MiB — presign continuation past chunk 100');
  const bigPath = path.join(WS, 'big.bin');
  const bigSize = 505 * 1024 * 1024;
  {
    const fd = fs.openSync(bigPath, 'w');
    const block = crypto.randomBytes(1024 * 1024);
    for (let i = 0; i < 505; i++) fs.writeSync(fd, block);
    fs.closeSync(fd);
  }
  const t0 = Date.now();
  const p2 = await call('push', { path: bigPath });
  check('505 MiB push ok (' + Math.round((Date.now() - t0) / 1000) + 's)', !p2.isError && p2.structuredContent.size === bigSize, text(p2));
  const bigRow = db.prepare("SELECT token, file_size FROM big_files WHERE filename = 'big.bin'").get();
  const sess = db.prepare("SELECT total_chunks, received_chunks FROM upload_sessions WHERE filename = 'big.bin'").get();
  check('101 chunks, all received', sess && sess.total_chunks === 101 && JSON.parse(sess.received_chunks).length === 101, JSON.stringify(sess));
  const dl2 = await fetch(APP + '/api/big/download/' + bigRow.token, { redirect: 'follow' });
  const got = Buffer.from(await dl2.arrayBuffer());
  check('505 MiB bytes identical', got.length === bigSize && sha(got) === sha(fs.readFileSync(bigPath)));
  const mcpLog = fs.readFileSync(path.join(TMP, 'mcp.log'), 'utf8');
  check('server log names the resolved path and never the token', mcpLog.includes(bigPath) && !mcpLog.includes(secret));

  console.log('\nRESULT: ' + pass + ' passed, ' + fail + ' failed');
  fs.rmSync(WS, { recursive: true, force: true });
  fs.rmSync(OUTSIDE, { recursive: true, force: true });
  cleanup(fail ? 1 : 0);
})().catch(e => { console.error('HARNESS ERROR:', e); cleanup(1); });
