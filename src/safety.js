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
import { realpath, stat } from 'node:fs/promises';
import { homedir } from 'node:os';
import path from 'node:path';

export class PathRefused extends Error {}

// Names refused regardless of directory (compared case-insensitively).
var DENY_NAME = [
  /\.(pem|key|p12|pfx|crt|cer|der|jks|keystore|kdbx|gpg|asc)$/i,
  /^id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$/i,
  /^(credentials?|secrets?|token|tokens|passwd|shadow)(\.[a-z0-9]+)?$/i,
  /^known_hosts$/i,
  /^authorized_keys$/i,
];

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
    if (DENY_NAME.some(function (re) { return re.test(s); })) throw new PathRefused('refused: ' + real + ' looks like a credential or key file (' + s + '); these are never uploaded');
  }

  var st = await stat(real);
  if (!st.isFile()) throw new PathRefused('refused: ' + real + ' is not a regular file (directories and special files are not uploaded)');
  if (st.size < 1) throw new PathRefused('refused: ' + real + ' is empty');

  return { path: real, name: path.basename(real), size: st.size };
}
