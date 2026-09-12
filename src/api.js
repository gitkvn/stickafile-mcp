// Portal listing and the portal-defaulting rule.
import { apiFetch } from './upload.js';

export class ApiError extends Error {}

async function readError(res, fallback) {
  var body = await res.json().catch(function () { return {}; });
  return body.error || fallback;
}

// GET /api/portal/list as the token. Returns the server's portal entries.
export async function listPortals(client) {
  var res = await apiFetch(client, '/api/portal/list');
  if (!res) throw new Error('cancelled');
  if (res.status === 401) throw new ApiError('Stickafile rejected the token (STICKAFILE_TOKEN): it may be revoked, expired, or for a different server than ' + client.baseUrl);
  if (res.status === 429) throw new ApiError('Stickafile is rate limiting this account; try again in a minute');
  if (!res.ok) throw new ApiError(await readError(res, 'could not list portals: HTTP ' + res.status));
  var data = await res.json();
  return data.portals || [];
}

// One probe of the token at startup, so a dead token fails at install time
// rather than on the first push. Resolves to one of:
//   { ok: true }
//   { ok: false, status, detail }   — the server answered 401 or 403: the
//                                     token itself is rejected. Startup stops.
//   { ok: null, detail }            — anything else: no route, DNS failure,
//                                     connection refused, timeout, 5xx, 429,
//                                     an unexpected 4xx. The token may be
//                                     fine; the first real call will tell.
// The split is deliberate: only an explicit auth status from the server is
// evidence about the token. Every other failure is evidence about the
// network or the server, and a server that starts anyway costs nothing,
// whereas one that refuses to start on a blip reports as failed in the MCP
// client for an unrelated reason. The probe is one plain request, not
// apiFetch: a 429 here must not enter the backoff loop, and the in-flight
// request is aborted at the deadline.
export async function verifyToken(client, opts) {
  var timeoutMs = (opts && opts.timeoutMs) || 3000;
  var res;
  try {
    res = await fetch(client.baseUrl + '/api/portal/list', {
      headers: { Authorization: 'Bearer ' + client.token },
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (e) {
    var name = e && e.name;
    var code = e && e.cause && e.cause.code;
    var detail = name === 'TimeoutError' || name === 'AbortError'
      ? 'no response within ' + timeoutMs + ' ms'
      : (code ? code + ' ' : '') + ((e && e.message) || 'network error');
    return { ok: null, detail: detail };
  }
  if (!res) return { ok: null, detail: 'no response within ' + timeoutMs + ' ms' };
  if (res.status === 401 || res.status === 403) {
    var body = await res.json().catch(function () { return {}; });
    return { ok: false, status: res.status, detail: body.error || ('HTTP ' + res.status) };
  }
  if (res.ok) return { ok: true };
  return { ok: null, detail: 'HTTP ' + res.status };
}

export function describePortal(p) {
  return { token: p.token, name: p.name, mode: p.sharedView ? 'shared' : 'inbox', status: p.status, fileCount: p.fileCount, url: p.url };
}

// Portal tokens are exactly 8 chars. A name is guessable ("test"); a token
// ("a1b2c3d4") is not, so requiring the push argument to be a token means the
// model must have called list_portals to learn it rather than inventing one.
var TOKEN_RE = /^[a-z0-9]{8}$/i;

// Exact token match only (case-sensitive against the real token value).
function matchToken(portals, want) {
  var w = String(want).trim();
  return portals.find(function (p) { return p.token === w; }) || null;
}

// Name-or-token match, used only for STICKAFILE_PORTAL (a human sets that at
// install time, where a friendly name is reasonable).
function matchPortal(portals, want) {
  var w = String(want).trim();
  var byToken = portals.find(function (p) { return p.token === w; });
  if (byToken) return byToken;
  var lw = w.toLowerCase();
  var byName = portals.filter(function (p) { return (p.name || '').toLowerCase() === lw; });
  if (byName.length === 1) return byName[0];
  if (byName.length > 1) {
    var active = byName.filter(function (p) { return p.status === 'active'; });
    if (active.length === 1) return active[0];
    throw new ApiError('STICKAFILE_PORTAL name "' + w + '" is ambiguous (' + byName.length + ' portals); set it to a token instead: ' + byName.map(function (p) { return p.token; }).join(', '));
  }
  return null;
}

function listing(portals) {
  return portals.map(function (p) { return '"' + p.name + '" (token ' + p.token + ', ' + (p.sharedView ? 'shared' : 'inbox') + ')'; }).join(', ');
}

// Precedence: explicit push argument (token only) → STICKAFILE_PORTAL (name
// or token) → the single active portal → an error that lists the choices.
// Never picks silently among several: a push to the wrong shared portal
// exposes the file to everyone holding that portal's link. The push argument
// is deliberately token-only — a name is guessable, so accepting one lets a
// model fabricate a plausible target; a token forces it through list_portals.
export async function choosePortal(client, arg, env) {
  var portals = await listPortals(client);
  var active = portals.filter(function (p) { return p.status === 'active'; });

  // Explicit push argument: an 8-character portal token, nothing else.
  var argWant = arg && String(arg).trim();
  if (argWant) {
    if (!TOKEN_RE.test(argWant)) {
      throw new ApiError('`portal` must be an 8-character portal token, not a name (got "' + argWant + '"). Call list_portals to get the token of the portal you want, then pass that token. Do not guess. Portals on this account: ' + (portals.length ? listing(portals) : 'none'));
    }
    var found = matchToken(portals, argWant);
    if (!found) throw new ApiError('no portal has the token "' + argWant + '" on this account. Call list_portals for the current tokens. Portals on this account: ' + (portals.length ? listing(portals) : 'none'));
    if (found.status !== 'active') throw new ApiError('portal "' + found.name + '" (token ' + found.token + ') is deactivated; reactivate it at ' + client.baseUrl + '/links or choose another: ' + (active.length ? listing(active) : 'none active'));
    return found;
  }

  // STICKAFILE_PORTAL: name or token, set by a human at install time.
  var envWant = (env.STICKAFILE_PORTAL || '').trim();
  if (envWant) {
    var envFound = matchPortal(portals, envWant);
    if (!envFound) throw new ApiError('STICKAFILE_PORTAL "' + envWant + '" not found. Portals on this account: ' + (portals.length ? listing(portals) : 'none'));
    if (envFound.status !== 'active') throw new ApiError('STICKAFILE_PORTAL "' + envWant + '" is deactivated; reactivate it at ' + client.baseUrl + '/links or choose another: ' + (active.length ? listing(active) : 'none active'));
    return envFound;
  }

  if (active.length === 1) return active[0];
  if (active.length === 0) {
    throw new ApiError('this account has no active portal to push to. Create one in the browser at ' + client.baseUrl + '/portal/new (API tokens cannot create portals), then push again.');
  }
  throw new ApiError('this account has ' + active.length + ' active portals; none was chosen. Ask the user which one, then pass `portal` with its 8-character token: ' + listing(active) + '. Or set STICKAFILE_PORTAL in the MCP server config as a default (name or token).');
}
