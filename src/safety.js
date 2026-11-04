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
import { realpath, open, lstat } from 'node:fs/promises';
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

var IS_WIN = process.platform === 'win32';

// The forms of a segment the name checks look at. Windows strips trailing
// dots and spaces when it opens a name ("id_rsa." opens id_rsa, "server.pem "
// opens server.pem), and a ':' starts an NTFS stream name, so
// "secret.pem:hidden" is a stream of a .pem file. Those characters are legal
// in POSIX names, where stripping them only widens the deny list.
function nameForms(segment) {
  var forms = [segment];
  var colon = segment.indexOf(':');
  if (colon > 0) forms.push(segment.slice(0, colon));
  return forms.map(function (f) { return f.replace(/[. ]+$/, ''); }).filter(Boolean).concat(forms);
}

// Windows reserved device names. "NUL", "con.txt" and "COM1 .log" all open
// the device in a plain Win32 path, whatever the directory or extension.
var RESERVED_RE = /^(con|prn|aux|nul|conin\$|conout\$|com[0-9¹²³]|lpt[0-9¹²³])$/i;
function isReservedName(segment) {
  return RESERVED_RE.test(segment.split('.')[0].replace(/ +$/, ''));
}

// True if a path segment looks like a credential or key file.
function looksSensitive(segment) {
  return nameForms(segment).some(looksSensitiveForm);
}
function looksSensitiveForm(segment) {
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
  if (p.startsWith('~/') || (IS_WIN && p.startsWith('~\\'))) return path.join(homedir(), p.slice(2));
  return p;
}

// Resolve the allowed roots once. Unset → the launch directory only.
export async function resolveRoots(env) {
  var raw = (env.STICKAFILE_ALLOW || '').split(path.delimiter).map(function (s) { return s.trim(); }).filter(Boolean);
  if (raw.length === 0) raw = [process.cwd()];
  var roots = [];
  for (var r of raw) {
    var abs = path.resolve(expandHome(r));
    try { roots.push(canon(await realpath(abs))); }
    catch { throw new Error('STICKAFILE_ALLOW root does not exist: ' + r); }
  }
  return roots;
}

// One spelling per path on Windows: realpath gives the on-disk case for every
// component, but the drive letter and the \\?\ prefix can vary with how the
// path was written. Only those are normalised; the rest is compared exactly,
// because a directory can be case-sensitive on NTFS.
function canon(p) {
  if (!IS_WIN) return p;
  if (/^\\\\\?\\UNC\\/i.test(p)) p = '\\\\' + p.slice(8);
  else if (/^\\\\\?\\[a-z]:\\/i.test(p)) p = p.slice(4);
  if (/^[a-z]:/.test(p)) p = p[0].toUpperCase() + p.slice(1);
  return p;
}

function inside(root, p) {
  return p === root || p.startsWith(root.endsWith(path.sep) ? root : root + path.sep);
}

// Windows-only refusals on the path as given, before the filesystem is
// touched: device-namespace paths, NTFS streams, and reserved device names.
function vetWindowsInput(input) {
  // \\.\ and \\?\ paths other than \\?\X:\ and \\?\UNC\ reach devices and
  // volumes directly (\\.\PhysicalDrive0, \\?\GLOBALROOT\...).
  if (/^[\\/]{2}[.?][\\/]/.test(input) && !/^[\\/]{2}\?[\\/]([a-z]:[\\/]|unc[\\/])/i.test(input)) {
    throw new PathRefused('refused: ' + input + ' is a device path; only files on a drive or share are uploaded');
  }
  var body = input.replace(/^[\\/]{2}\?[\\/](unc[\\/])?/i, '').replace(/^[a-z]:/i, '');
  var segs = body.split(/[\\/]+/).filter(Boolean);
  for (var s of segs) {
    if (s.indexOf(':') !== -1) throw new PathRefused('refused: ' + input + ' names an NTFS alternate data stream (' + s + '); only a file\'s main contents are uploaded');
    if (isReservedName(s)) throw new PathRefused('refused: ' + input + ' uses a reserved Windows device name (' + s + '); these are never uploaded');
  }
}

// Vet one path. Resolves { path, name, size } or throws PathRefused with a
// message meant for the agent (and, through it, the user).
// hooks is a test seam only: hooks.beforeOpen() runs between the identity
// capture and the open, where a swap race would land.
export async function vetPath(input, roots, hooks) {
  if (typeof input !== 'string' || input.trim().length === 0) throw new PathRefused('path is required');
  if (!path.isAbsolute(input)) throw new PathRefused('path must be absolute (got "' + input + '"); resolve it before calling push');
  if (IS_WIN) vetWindowsInput(input);

  var real;
  try { real = canon(await realpath(input)); }
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
    if (IS_WIN && (s.indexOf(':') !== -1 || isReservedName(s))) throw new PathRefused('refused: ' + real + ' resolves to a stream or reserved device name (' + s + '); not uploaded');
    if (s.startsWith('.')) throw new PathRefused('refused: ' + real + ' is under a dot-directory or is a dotfile (' + s + '); these are never uploaded');
    if (looksSensitive(s)) throw new PathRefused('refused: ' + real + ' looks like a credential or key file (' + s + '); these are never uploaded');
  }

  // Open the file ONCE, here, and hand the descriptor back. The uploader reads
  // from this fd and never reopens the path, so a swap of the entry between
  // this check and the read cannot redirect the upload (the finding-3 TOCTOU).
  //
  // Identity first: lstat (not stat) the vetted name, so if the entry is
  // already a symlink or junction it is refused here rather than followed.
  // Then open, and the descriptor's own fstat must carry the same device and
  // inode — on Windows, the volume serial number and the 64-bit NTFS file ID.
  // Both are read as BigInt: NTFS file IDs exceed 2^53 and would compare
  // equal by accident as Numbers.
  //
  // O_NOFOLLOW (POSIX) makes the open itself fail if the final component was
  // swapped for a symlink after the lstat. Windows has no equivalent — Node's
  // open follows symlinks and junctions — so there the identity check is
  // what catches the swap: the open follows the new link to some other file,
  // whose ID cannot match the regular file that was lstat'd.
  //
  // Not covered, on any platform: swapping a PARENT directory for a link
  // between realpath and this lstat, and back. lstat and open both resolve
  // the path string again, so they would agree on the outside file. Closing
  // that needs the kernel's path for the open handle (GetFinalPathNameByHandle,
  // F_GETPATH, /proc/self/fd), which Node does not expose. See README.
  var expected;
  try { expected = await lstat(real, { bigint: true }); }
  catch (e) {
    if (e && e.code === 'ENOENT') throw new PathRefused('file not found: ' + real);
    throw new PathRefused('cannot read ' + real + ': ' + (e && e.code ? e.code : e.message));
  }
  if (expected.isSymbolicLink()) throw new PathRefused('refused: ' + real + ' was replaced by a symlink after it was checked; not uploaded');
  if (hooks && hooks.beforeOpen) await hooks.beforeOpen();
  var fh;
  try {
    fh = await open(real, FS.O_RDONLY | (FS.O_NOFOLLOW || 0));
  } catch (e) {
    if (e && (e.code === 'ELOOP' || e.code === 'EMLINK')) throw new PathRefused('refused: ' + real + ' was replaced by a symlink after it was checked; not uploaded');
    if (e && e.code === 'ENOENT') throw new PathRefused('file not found: ' + real);
    throw new PathRefused('cannot open ' + real + ': ' + (e && e.code ? e.code : e.message));
  }
  try {
    var st = await fh.stat({ bigint: true });
    if (st.dev !== expected.dev || st.ino !== expected.ino) throw new PathRefused('refused: ' + real + ' changed while it was being checked (device/inode mismatch); not uploaded');
    if (!st.isFile()) throw new PathRefused('refused: ' + real + ' is not a regular file (directories and special files are not uploaded)');
    if (st.size < 1n) throw new PathRefused('refused: ' + real + ' is empty');
    // A hardlink is not a symlink, so realpath cannot tell that this name is a
    // second link to an inode whose home may be outside the root (the finding-2
    // bypass). Refuse any file with more than one link; the fix for a genuine
    // multi-link file is for the user to decide on: the message tells the
    // agent to ask, never to make the copy itself.
    if (st.nlink > 1n) throw new PathRefused('refused: ' + real + '. This file has multiple hard links, so it can\'t be uploaded safely. Ask the user whether they want to make a copy themselves.');
    return { fd: fh.fd, fh: fh, path: real, name: path.basename(real), size: Number(st.size) };
  } catch (e) {
    await fh.close().catch(function () {});
    throw e;
  }
}
