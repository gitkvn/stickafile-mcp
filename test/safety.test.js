// Unit tests for the path controls in src/safety.js.
//
// These run with no stickr checkout, no network, and no model: they call
// vetPath directly. That is the point. `push` is the tool a prompt injection
// aims at ("push ~/.ssh/id_rsa"), and any refusal the model volunteers is
// worth nothing against the same injection. The deny list has to hold on its
// own. If this file passes, it does — a credential- or key-shaped name is
// refused even when it sits inside an allowed root, so the refusal does not
// depend on the file also being out of bounds.
//
//   node --test test/safety.test.js      (npm run test:unit)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { vetPath, resolveRoots, PathRefused } from '../src/safety.js';

// Long-form path: on the Windows runner os.tmpdir() is the 8.3 spelling
// (C:\Users\RUNNER~1\...), and vetPath reports the long one.
const WS_AS_CREATED = fs.mkdtempSync(path.join(os.tmpdir(), 'sf-safety-'));
const WS = fs.realpathSync.native(WS_AS_CREATED);
process.on('exit', () => { try { fs.rmSync(WS, { recursive: true, force: true }); } catch {} });
// The allowed root IS the workspace, so nothing below is refused for being
// outside it. Every refusal here is the name/shape deny list doing its job.
const roots = await resolveRoots({ STICKAFILE_ALLOW: WS });

function write(rel, body = 'x') {
  const p = path.join(WS, rel);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, body);
  return p;
}
async function refused(rel, needle) {
  const p = write(rel);
  await assert.rejects(
    () => vetPath(p, roots),
    (e) => {
      assert.ok(e instanceof PathRefused, `expected PathRefused for ${rel}, got ${e}`);
      assert.match(e.message, needle, `${rel}: ${e.message}`);
      return true;
    },
  );
}

test('id_rsa inside an allowed root is refused by name, not by location', async () => {
  // The exact injection case: the key is somewhere push is otherwise allowed
  // to read. It must still be refused for what it is.
  await refused('id_rsa', /credential or key file/);
});

test('SSH private/public keys and cert/keystore shapes are refused', async () => {
  for (const n of [
    'id_dsa', 'id_ecdsa', 'id_ed25519', 'id_rsa.pub',
    'server.pem', 'client.key', 'bundle.p12', 'store.pfx', 'cert.crt',
    'ca.cer', 'x.der', 'app.jks', 'my.keystore', 'vault.kdbx', 'msg.gpg', 'key.asc',
  ]) {
    await refused(n, /credential or key file/);
  }
});

test('credential-shaped basenames are refused', async () => {
  for (const n of [
    'credentials', 'credential', 'secrets', 'secret', 'token', 'tokens',
    'passwd', 'shadow', 'known_hosts', 'authorized_keys', 'credentials.json',
  ]) {
    await refused(n, /credential or key file/);
  }
});

test('dotfiles and dot-directories are refused', async () => {
  await refused('.env', /dotfile/);
  await refused('.npmrc', /dotfile/);
  await refused(path.join('.ssh', 'id_rsa'), /dot-directory/);
  await refused(path.join('.aws', 'credentials'), /dot-directory/);
});

test('a relative path is refused before any filesystem access', async () => {
  await assert.rejects(() => vetPath('id_rsa', roots), (e) => {
    assert.ok(e instanceof PathRefused);
    assert.match(e.message, /must be absolute/);
    return true;
  });
});

test('a path outside every root is refused', async () => {
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'sf-out-'));
  const p = path.join(outside, 'plain.txt');
  fs.writeFileSync(p, 'x');
  await assert.rejects(() => vetPath(p, roots), (e) => {
    assert.match(e.message, /outside the allowed workspace/);
    return true;
  });
  fs.rmSync(outside, { recursive: true, force: true });
});

test('a symlink pointing at a denied name is refused (target is resolved)', async () => {
  // realpath runs before the name check, so a benign-looking link cannot
  // smuggle a key out.
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'sf-out-'));
  const key = path.join(outside, 'id_rsa');
  fs.writeFileSync(key, 'x');
  const link = path.join(WS, 'notes.txt');
  fs.symlinkSync(key, link);
  await assert.rejects(() => vetPath(link, roots), (e) => {
    // Refused because the resolved target is outside the root; the resolution
    // is what matters — the pretty name never gets a pass.
    assert.match(e.message, /outside the allowed workspace/);
    return true;
  });
  fs.rmSync(outside, { recursive: true, force: true });
});

test('a plain file inside the root is accepted', async () => {
  const p = write('report.bin', 'hello');
  const f = await vetPath(p, roots);
  assert.equal(f.name, 'report.bin');
  assert.equal(f.size, 5);
  assert.equal(f.path, fs.realpathSync(p));
  assert.equal(typeof f.fd, 'number', 'the vetted result carries the open descriptor');
  await f.fh.close();
});

// ─────────────────────────────────────────────────────────────────────────
// Adversarial findings, 2026-09-12. Each test below encodes the SECURE
// behaviour and FAILS against the current safety.js — it marks a confirmed
// bypass to be fixed. Do not delete a test to make the suite green; fix
// src/safety.js until it passes.
// ─────────────────────────────────────────────────────────────────────────

// FINDING 1 — deny-list regex is anchored to a single optional extension, so
// any credential/key file with a second extension, a backup suffix, or a
// prefix slips through. Confirmed accepted by vetPath.
test('FINDING1: key/credential files with a backup or double extension are refused', async () => {
  for (const n of [
    'id_rsa.bak', 'id_rsa.old', 'id_rsa.1', 'id_ed25519.bak',
    'server.key.bak', 'server.pem.bak', 'server.pem.gz', 'cert.crt.bak',
    'credentials.json.bak', 'secrets.tar.gz',
  ]) {
    await refused(n, /credential or key file/);
  }
});

// FINDING 1b — credential names with a prefix/suffix (not an extension) also
// slip through: the name group is not a substring test.
test('FINDING1b: affixed credential names are refused', async () => {
  for (const n of ['aws_credentials', 'prod-secrets.yaml', 'credentials-prod', 'my_secret_token']) {
    await refused(n, /credential or key file/);
  }
});

// FINDING 1c — real SSH filenames outside the exact anchored set. authorized_keys2
// is a genuine OpenSSH file; known_hosts.old is a routine backup.
test('FINDING1c: authorized_keys2 and known_hosts.old are refused', async () => {
  await refused('authorized_keys2', /credential or key file/);
  await refused('known_hosts.old', /credential or key file/);
});

// FINDING 2 — hardlinks are not symlinks, so realpath() does not resolve them.
// A benign-named hardlink whose inode is an out-of-root file is accepted,
// defeating both the root boundary and the deny list at once.
test('FINDING2: a hardlink whose inode lives outside the root is refused', async () => {
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'sf-hl-out-'));
  const target = path.join(outside, 'id_rsa');
  fs.writeFileSync(target, 'PRIVATE KEY BYTES');
  const link = path.join(WS, 'hardlinked-report.bin');
  fs.linkSync(target, link);
  await assert.rejects(() => vetPath(link, roots), (e) => {
    assert.ok(e instanceof PathRefused, `expected refusal, got ${e}`);
    // The refusal sends the decision to the user; it must not tell the agent to copy.
    assert.match(e.message, /This file has multiple hard links, so it can't be uploaded safely\. Ask the user whether they want to make a copy themselves\./);
    assert.doesNotMatch(e.message, /push a copy/i);
    return true;
  });
  fs.rmSync(outside, { recursive: true, force: true });
});

// FINDING 3 — check/reopen TOCTOU. vetPath resolves and stats a path, then
// returns a plain string; upload.js reopens that string by path. Swapping the
// entry for a symlink to an outside file between the two steps makes the
// upload read out-of-root bytes. The vetted result must pin the exact bytes
// that were vetted (e.g. carry an open fd the uploader reads), so a post-vet
// filesystem swap cannot change what is uploaded.
test('FINDING3: the vetted file cannot be swapped for outside content after vetting', async () => {
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'sf-toctou-out-'));
  const secret = path.join(outside, 'passwd');
  fs.writeFileSync(secret, 'OUT-OF-ROOT SECRET');
  const victim = path.join(WS, 'swap.bin');
  fs.writeFileSync(victim, 'IN-ROOT DATA');

  const vetted = await vetPath(victim, roots);
  // Attacker replaces the just-vetted entry with a symlink out of the root.
  fs.rmSync(victim);
  fs.symlinkSync(secret, victim);

  // What the uploader would actually send. Prefer a pinned fd if vetPath
  // grew one; otherwise reproduce upload.js's reopen-by-path.
  let uploaded;
  if (typeof vetted.fd === 'number') {
    const buf = Buffer.alloc(64);
    const { bytesRead } = fs.readSync(vetted.fd, buf, 0, 64, 0);
    uploaded = buf.slice(0, bytesRead).toString('utf8');
  } else {
    uploaded = fs.readFileSync(vetted.path, 'utf8');
  }
  assert.doesNotMatch(uploaded, /OUT-OF-ROOT SECRET/, 'post-vet swap changed the uploaded bytes (TOCTOU)');
  if (vetted.fh) await vetted.fh.close();
  fs.rmSync(outside, { recursive: true, force: true });
});

// ─────────────────────────────────────────────────────────────────────────
// Swap races, deterministic. vetPath's test seam runs beforeOpen() between
// the identity capture (lstat) and the open, exactly where a racing process
// would swap the entry. On POSIX, O_NOFOLLOW or the identity check catches
// it; on Windows (no O_NOFOLLOW) the identity check must do it alone.
// ─────────────────────────────────────────────────────────────────────────
const OUT = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'sf-out-')));
process.on('exit', () => { try { fs.rmSync(OUT, { recursive: true, force: true }); } catch {} });
const OUT_FILE = path.join(OUT, 'report.txt'); // benign name: only the root check stands in the way
fs.writeFileSync(OUT_FILE, 'OUT-OF-ROOT CONTENT');

async function refuses(p, needle, r = roots) {
  await assert.rejects(() => vetPath(p, r), (e) => {
    assert.ok(e instanceof PathRefused, `${p}: expected PathRefused, got ${e && e.stack || e}`);
    if (needle) assert.match(e.message, needle, `${p}: ${e.message}`);
    return true;
  });
}
async function accepts(p, r = roots) {
  const v = await vetPath(p, r);
  await v.fh.close();
  return v;
}

test('RACE: entry swapped for a symlink to an outside file after the lstat → refused', async () => {
  const victim = write('race-symlink.bin', 'IN-ROOT');
  await assert.rejects(() => vetPath(victim, roots, {
    beforeOpen() { fs.rmSync(victim); fs.symlinkSync(OUT_FILE, victim, 'file'); },
  }), (e) => {
    assert.ok(e instanceof PathRefused, String(e));
    assert.match(e.message, /changed while it was being checked|replaced by a symlink/);
    return true;
  });
});

test('RACE: entry replaced by a different regular file after the lstat → refused (identity mismatch)', async () => {
  const victim = write('race-rename.bin', 'IN-ROOT');
  const other = write('race-other.bin', 'SOMETHING ELSE');
  await assert.rejects(() => vetPath(victim, roots, {
    beforeOpen() { fs.renameSync(other, victim); },
  }), (e) => {
    assert.ok(e instanceof PathRefused, String(e));
    assert.match(e.message, /changed while it was being checked/);
    return true;
  });
});

test('names Windows would rewrite are refused on every platform: trailing dot/space, ":" streams', async () => {
  // Legal POSIX names; on Windows these spell a stream or a stripped name.
  if (process.platform === 'win32') return; // created literally in the Windows block below
  for (const name of ['server.pem ', 'id_rsa.', 'id_rsa. . ', 'secret.pem:hidden', 'prod.key::$DATA']) {
    await refuses(write(name), /credential or key/);
  }
});

test('vetted size is a Number (identity is compared as BigInt, size is handed back as Number)', async () => {
  const v = await accepts(write('size-check.bin', 'abcd'));
  assert.equal(typeof v.size, 'number');
  assert.equal(v.size, 4);
});

// ─────────────────────────────────────────────────────────────────────────
// Windows attack surface. Runs on the windows-latest CI runner (NTFS, admin).
// ─────────────────────────────────────────────────────────────────────────
const WIN = process.platform === 'win32';
const onWin = { skip: !WIN && 'Windows only' };
const R = roots[0];                          // the root as realpath spells it (long names)
const lit = (p) => '\\\\?\\' + p;           // \\?\ — no Win32 normalisation, literal names
const fsutil = (...args) => execFileSync('fsutil', args, { stdio: 'pipe' }).toString();

test('WIN ADS: alternate data streams are refused, whatever the main file is called', onWin, async () => {
  write('secret.pem', 'cert');
  fs.writeFileSync(path.join(R, 'secret.pem:hidden'), 'HIDDEN');
  write('ads-notes.txt', 'plain notes');
  fs.writeFileSync(path.join(R, 'ads-notes.txt:payload'), 'SMUGGLED');
  for (const s of ['secret.pem:hidden', 'ads-notes.txt::$DATA', 'ads-notes.txt:payload', 'ads-notes.txt:payload:$DATA']) {
    await refuses(path.join(R, s), /alternate data stream/);
  }
  await accepts(path.join(R, 'ads-notes.txt')); // control: the main stream is fine
});

test('WIN 8.3: short names resolve to the long name before the name check', onWin, async (t) => {
  const key = write('id_ed25519_backup', 'KEY');
  fs.mkdirSync(path.join(R, '.ssh'), { recursive: true });
  write('.ssh/notes.txt', 'n');
  const plain = write('long_report_name.txt', 'ok');
  try {
    fsutil('file', 'setshortname', key, 'IDED~1');
    fsutil('file', 'setshortname', path.join(R, '.ssh'), 'SSHDIR~1');
    fsutil('file', 'setshortname', plain, 'LONGRE~1.TXT');
  } catch (e) {
    t.skip('fsutil setshortname failed on this volume: ' + (e.stderr || e.message));
    return;
  }
  await refuses(path.join(R, 'IDED~1'), /credential or key/);
  // STICKAFILE_ALLOW in 8.3 form names the same root.
  if (WS_AS_CREATED !== WS) assert.deepEqual(await resolveRoots({ STICKAFILE_ALLOW: WS_AS_CREATED }), roots, 'short-form root ' + WS_AS_CREATED);
  await refuses(path.join(R, 'SSHDIR~1', 'notes.txt'), /dot-directory/);
  const v = await accepts(path.join(R, 'LONGRE~1.TXT'));
  assert.equal(v.path, plain, 'short name resolved to the long one');
});

test('WIN trailing dots and spaces: stripped names and literal \\\\?\\ names are both refused', onWin, async () => {
  write('id_rsa', 'KEY');
  write('server.pem', 'CERT');
  // Win32 would strip these to id_rsa / server.pem, but Node hands Windows
  // \\?\-prefixed paths, so they name the literal (absent) files instead.
  // Either way they must not upload.
  await refuses(path.join(R, 'id_rsa.'), /credential or key|file not found/);
  await refuses(path.join(R, 'server.pem '), /credential or key|file not found/);
  fs.mkdirSync(path.join(R, 'lit'), { recursive: true });
  for (const name of ['id_rsa.', 'server.pem ', 'deploy.key. .']) {
    const p = path.join(R, 'lit', name);
    fs.writeFileSync(lit(p), 'LITERAL');
    await refuses(lit(p), /credential or key|not found/);
  }
});

test('WIN reserved device names: CON, NUL, COM1, with and without extensions, file or directory', onWin, async () => {
  for (const name of ['CON', 'NUL', 'COM1', 'con.txt', 'NUL.tar.gz', 'com1.log', 'AUX ', 'lpt1 .txt', 'COM¹', 'CONIN$']) {
    await refuses(path.join(R, name), /reserved Windows device name/);
  }
  await refuses(path.join(R, 'nul', 'x.txt'), /reserved Windows device name/);
  fs.mkdirSync(path.join(R, 'lit'), { recursive: true });
  const real = path.join(R, 'lit', 'con.txt');
  fs.writeFileSync(lit(real), 'a real file with a device name');
  await refuses(lit(real), /reserved Windows device name/);
});

test('WIN drive-letter case and mixed separators, in STICKAFILE_ALLOW and in the path', onWin, async () => {
  const ok = write('case/ok.txt', 'ok');
  const lowerRoot = R[0].toLowerCase() + R.slice(1);
  for (const allow of [lowerRoot, lowerRoot.replace(/\\/g, '/'), R + '\\', R.replace(/\\/g, '/') + '/']) {
    const r2 = await resolveRoots({ STICKAFILE_ALLOW: allow });
    assert.deepEqual(r2, roots, 'STICKAFILE_ALLOW=' + allow);
  }
  for (const p of [
    ok,
    lowerRoot + '\\case\\ok.txt',
    R.replace(/\\/g, '/') + '/case/ok.txt',
    R + '/case\\ok.txt',
    R.toUpperCase() + '\\CASE\\OK.TXT',
  ]) {
    const v = await accepts(p);
    assert.equal(v.path, ok, p + ' → ' + v.path);
  }
  // A sibling whose name starts with the root's name is still outside.
  const sib = R + '-evil';
  fs.mkdirSync(sib, { recursive: true });
  fs.writeFileSync(path.join(sib, 'x.txt'), 'x');
  await refuses(path.join(sib, 'x.txt'), /outside the allowed workspace/);
  await refuses(sib.toLowerCase().replace(/\\/g, '/') + '/x.txt', /outside the allowed workspace/);
  fs.rmSync(sib, { recursive: true, force: true });
  // Two roots with the Windows delimiter.
  const two = await resolveRoots({ STICKAFILE_ALLOW: lowerRoot + ';' + OUT });
  assert.equal(two.length, 2);
});

test('WIN UNC and \\\\?\\ long paths', onWin, async () => {
  const ok = write('unc/ok.txt', 'ok');
  // \\?\C:\... is the same file: accepted, reported in the plain spelling.
  assert.equal((await accepts(lit(ok))).path, ok);
  // \\?\ does not collapse "..": it must not climb out of the root.
  await refuses(lit(R + '\\..\\' + path.basename(OUT) + '\\report.txt'));
  // Device namespace and volume GUID paths are refused outright.
  for (const p of ['\\\\.\\' + ok, '\\\\.\\PhysicalDrive0', '\\\\?\\GLOBALROOT\\Device\\Null', '\\\\.\\NUL', '//./' + ok.replace(/\\/g, '/')]) {
    await refuses(p, /device path/);
  }
  // The admin share points at the same disk. Refused (outside the C:\ root)
  // or accepted as the same in-root file — never anything outside the root.
  const share = '\\\\localhost\\' + R[0] + '$' + R.slice(2);
  for (const p of [share + '\\unc\\ok.txt', '\\\\?\\UNC\\localhost\\' + R[0] + '$' + R.slice(2) + '\\unc\\ok.txt']) {
    try {
      const v = await accepts(p);
      assert.equal(v.path, ok, p + ' was accepted as ' + v.path);
    } catch (e) {
      assert.ok(e instanceof PathRefused, p + ': ' + e);
    }
  }
  // An outside file through the share is refused.
  const outShare = '\\\\localhost\\' + OUT_FILE[0] + '$' + OUT_FILE.slice(2);
  try { await refuses(outShare); } catch (e) { throw new Error('admin share leaked an outside file: ' + e.message); }
});

test('WIN junctions and symlinks pointing outside the root are refused', onWin, async () => {
  fs.symlinkSync(OUT, path.join(R, 'junc'), 'junction');
  await refuses(path.join(R, 'junc', 'report.txt'), /outside the allowed workspace/);
  fs.symlinkSync(OUT, path.join(R, 'dirlink'), 'dir');
  await refuses(path.join(R, 'dirlink', 'report.txt'), /outside the allowed workspace/);
  fs.symlinkSync(OUT_FILE, path.join(R, 'filelink.txt'), 'file');
  await refuses(path.join(R, 'filelink.txt'), /outside the allowed workspace/);
  // Relative symlink climbing out.
  fs.symlinkSync('..\\' + path.basename(OUT) + '\\report.txt', path.join(R, 'rel-link.txt'), 'file');
  await refuses(path.join(R, 'rel-link.txt'), /outside the allowed workspace/);
  // Control: a junction to a directory inside the root is fine.
  const inner = write('inner/f.txt', 'inner');
  fs.symlinkSync(path.join(R, 'inner'), path.join(R, 'junc-in'), 'junction');
  assert.equal((await accepts(path.join(R, 'junc-in', 'f.txt'))).path, inner);
  // A junction into a dot-directory inside the root is still a dotfile.
  write('.git/config.txt', 'x');
  fs.symlinkSync(path.join(R, '.git'), path.join(R, 'gitjunc'), 'junction');
  await refuses(path.join(R, 'gitjunc', 'config.txt'), /dot-directory/);
});

test('WIN hard links on NTFS are refused (nlink is populated)', onWin, async () => {
  const out = path.join(OUT, 'hl-src.txt');
  fs.writeFileSync(out, 'OUTSIDE');
  fs.linkSync(out, path.join(R, 'hl-out.txt'));
  await refuses(path.join(R, 'hl-out.txt'), /multiple hard links/);
  const a = write('hl-a.txt', 'IN');
  fs.linkSync(a, path.join(R, 'hl-b.txt'));
  await refuses(a, /multiple hard links/);
  assert.equal(fs.statSync(a).nlink, 2, 'nlink reported by stat');
});

test('WIN race: final component swapped for a junction/symlink between lstat and open → refused', onWin, async () => {
  const victim = write('race-win.bin', 'IN-ROOT');
  await assert.rejects(() => vetPath(victim, roots, {
    beforeOpen() { fs.rmSync(victim); fs.symlinkSync(OUT_FILE, victim, 'file'); },
  }), (e) => {
    assert.ok(e instanceof PathRefused, String(e));
    assert.match(e.message, /changed while it was being checked/, 'Windows has no O_NOFOLLOW: the identity check must catch it');
    return true;
  });
});
