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
import { vetPath, resolveRoots, PathRefused } from '../src/safety.js';

const WS = fs.mkdtempSync(path.join(os.tmpdir(), 'sf-safety-'));
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
