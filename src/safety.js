// Path vetting for push. A tool that reads arbitrary paths and uploads them
// is an exfiltration primitive: a prompt injection in a document can produce
// "push ~/.ssh/id_rsa", and any confirmation the model gives is worth
// nothing against the same injection. So none of this trusts the model.
// The human sets the roots at install time (STICKAFILE_ALLOW, defaulting to
// the directory the server was launched from — Claude Code launches MCP
// servers in the project), the path must be absolute so what the human sees
// in the host's permission prompt is what gets read, symlinks are resolved
// before the root check, and dot-segments and credential-shaped names are
// refused inside the roots with no override in v1.
import { realpath, open, stat } from 'node:fs/promises';
import { constants as FS } from 'node:fs';
import { homedir } from 'node:os';
import path from 'node:path';

export class PathRefused extends Error {}

// Names refused regardless of directory. A credential or key file is refused
// even with a backup suffix or a second extension (id_rsa.bak, server.key.gz),
// and credential words are matched as whole tokens split on separators
// (aws_credentials, prod-secrets.yaml), not by exact filename. All matching is
// case-insensitive.
var SENSITIVE_EXT = new Set(['pem', 'key', 'p12', 'pfx', 'crt', 'cer', 'der', 'jks', 'keystore', 'kdbx', 'gpg', 'asc']);
// These are sensitive only as the whole stem (the name before the first dot),
// so tokenizer.json and shadow_map.png are left alone.
var EXACT_STEM = new Set(['passwd', 'shadow', 'token', 'tokens', 'known_hosts', 'authorized_keys']);
// These are sensitive as a whole word anywhere in the name.
var CRED_WORDS = new Set(['credential', 'credentials', 'secret', 'secrets']);
// id_rsa / id_dsa / id_ecdsa / id_ed25519, bounded so valid_rsa.txt is not hit.
var ID_KEY_RE = /(?:^|[^a-z0-9])id_(?:rsa|dsa|ecdsa|ed25519)(?:[^a-z0-9]|$)/i;

// True if a path segment looks like a credential or key file.
function looksSensitive(segment) {
  var base = segment.toLowerCase();
  var dotParts = base.split('.');
  var stem = dotParts[0];
  var exts = dotParts.slice(1);
  if (exts.some(function (e) { return SENSITIVE_EXT.has(e); })) return true;
  if (ID_KEY_RE.test(base)) return true;
  if (/^authorized_keys\d*$/.test(stem)) return true;
  if (EXACT_STEM.has(stem)) return true;
  var words = base.split(/[._\-\s]+/).filter(Boolean);
  return words.some(function (w) { return CRED_WORDS.has(w); });
}

function expandHome(p) {
  if (p === '~') return homedir();
  if (p.startsWith('~/')) return path.join(homedir(), p.slice(2));
  return p;
}

// Resolve the allowed roots once. Unset → the launch directory only.
export async function resolveRoots(env) {
  var raw = (env.STICKAFILE_ALLOW || '').split(path.delimiter).map(function (s) { return s.trim(); }).filter(Boolean);
  if (raw.length === 0) raw = [process.cwd()];
  var roots = [];
  for (var r of raw) {
    var abs = path.resolve(expandHome(r));
    try { roots.push(await realpath(abs)); }
    catch { throw new Error('STICKAFILE_ALLOW root does not exist: ' + r); }
  }
  return roots;
}

function inside(root, p) {
  return p === root || p.startsWith(root.endsWith(path.sep) ? root : root + path.sep);
}

// Vet one path. Resolves { path, name, size } or throws PathRefused with a
// message meant for the agent (and, through it, the user).
export async function vetPath(input, roots) {
  if (typeof input !== 'string' || input.trim().length === 0) throw new PathRefused('path is required');
  if (!path.isAbsolute(input)) throw new PathRefused('path must be absolute (got "' + input + '"); resolve it before calling push');

  var real;
  try { real = await realpath(input); }
  catch (e) {
    if (e && e.code === 'ENOENT') throw new PathRefused('file not found: ' + input);
    throw new PathRefused('cannot read ' + input + ': ' + (e && e.code ? e.code : e.message));
  }

  var root = roots.find(function (r) { return inside(r, real); });
  if (!root) {
    throw new PathRefused(
      'refused: ' + real + ' is outside the allowed workspace (' + roots.join(', ') + ').'
      + (real !== input ? ' (resolved from ' + input + ')' : '')
      + ' To allow another directory, set STICKAFILE_ALLOW in the MCP server config; the agent cannot change this.'
    );
  }

  // Dot-segments and credential-shaped names, checked on the part below the
  // root so a project that itself lives under a dot-directory still works.
  var rel = path.relative(root, real);
  var segs = rel.split(path.sep).filter(Boolean);
  for (var s of segs) {
    if (s.startsWith('.')) throw new PathRefused('refused: ' + real + ' is under a dot-directory or is a dotfile (' + s + '); these are never uploaded');
    if (looksSensitive(s)) throw new PathRefused('refused: ' + real + ' looks like a credential or key file (' + s + '); these are never uploaded');
  }

  // Open the file ONCE, here, and hand the descriptor back. The uploader reads
  // from this fd and never reopens the path, so a swap of the entry between
  // this check and the read cannot redirect the upload (the finding-3 TOCTOU).
  // O_NOFOLLOW means that if the final component was swapped for a symlink
  // after the checks above, the open fails here instead of following it.
  // (O_NOFOLLOW is absent on Windows; the `|| 0` degrades to a plain open.)
  // The identity of the entry that passed the name checks, by device and
  // inode. After the open, the descriptor's own fstat must match it, so the
  // descriptor is provably the file that was vetted and not something swapped
  // in under the same name.
  var expected;
  try { expected = await stat(real); }
  catch (e) {
    if (e && e.code === 'ENOENT') throw new PathRefused('file not found: ' + real);
    throw new PathRefused('cannot read ' + real + ': ' + (e && e.code ? e.code : e.message));
  }
  var fh;
  try {
    fh = await open(real, FS.O_RDONLY | (FS.O_NOFOLLOW || 0));
  } catch (e) {
    if (e && (e.code === 'ELOOP' || e.code === 'EMLINK')) throw new PathRefused('refused: ' + real + ' was replaced by a symlink after it was checked; not uploaded');
    if (e && e.code === 'ENOENT') throw new PathRefused('file not found: ' + real);
    throw new PathRefused('cannot open ' + real + ': ' + (e && e.code ? e.code : e.message));
  }
  try {
    var st = await fh.stat();
    if (st.dev !== expected.dev || st.ino !== expected.ino) throw new PathRefused('refused: ' + real + ' changed while it was being checked (device/inode mismatch); not uploaded');
    if (!st.isFile()) throw new PathRefused('refused: ' + real + ' is not a regular file (directories and special files are not uploaded)');
    if (st.size < 1) throw new PathRefused('refused: ' + real + ' is empty');
    // A hardlink is not a symlink, so realpath cannot tell that this name is a
    // second link to an inode whose home may be outside the root (the finding-2
    // bypass). Refuse any file with more than one link; the fix for a genuine
    // multi-link file the user wants to send is to push a copy of it.
    if (st.nlink > 1) throw new PathRefused('refused: ' + real + ' has ' + st.nlink + ' hard links; a hardlinked name can point at content outside the workspace, so it is not uploaded. Push a copy instead.');
    return { fd: fh.fd, fh: fh, path: real, name: path.basename(real), size: st.size };
  } catch (e) {
    await fh.close().catch(function () {});
    throw e;
  }
}
