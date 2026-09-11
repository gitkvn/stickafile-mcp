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

export function describePortal(p) {
  return { token: p.token, name: p.name, mode: p.sharedView ? 'shared' : 'inbox', status: p.status, fileCount: p.fileCount, url: p.url };
}

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
    throw new ApiError('portal name "' + w + '" is ambiguous (' + byName.length + ' portals); pass the token instead: ' + byName.map(function (p) { return p.token; }).join(', '));
  }
  return null;
}

function listing(portals) {
  return portals.map(function (p) { return '"' + p.name + '" (' + p.token + ')'; }).join(', ');
}

// Precedence: explicit argument → STICKAFILE_PORTAL → the single active
// portal → an error that lists the choices. Never picks silently among
// several: a push to the wrong shared portal exposes the file to everyone
// holding that portal's link.
export async function choosePortal(client, arg, env) {
  var portals = await listPortals(client);
  var active = portals.filter(function (p) { return p.status === 'active'; });

  var want = (arg && String(arg).trim()) || (env.STICKAFILE_PORTAL || '').trim();
  if (want) {
    var found = matchPortal(portals, want);
    var source = arg ? 'portal "' + want + '"' : 'STICKAFILE_PORTAL "' + want + '"';
    if (!found) throw new ApiError(source + ' not found. Portals on this account: ' + (portals.length ? listing(portals) : 'none'));
    if (found.status !== 'active') throw new ApiError(source + ' is deactivated; reactivate it at ' + client.baseUrl + '/links or choose another: ' + (active.length ? listing(active) : 'none active'));
    return found;
  }

  if (active.length === 1) return active[0];
  if (active.length === 0) {
    throw new ApiError('this account has no active portal to push to. Create one in the browser at ' + client.baseUrl + '/portal/new (API tokens cannot create portals), then push again.');
  }
  throw new ApiError('this account has ' + active.length + ' active portals; pass `portal` (name or token) to choose: ' + listing(active) + '. Or set STICKAFILE_PORTAL in the MCP server config as a default.');
}
