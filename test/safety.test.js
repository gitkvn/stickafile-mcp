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
});
