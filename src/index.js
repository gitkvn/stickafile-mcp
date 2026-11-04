#!/usr/bin/env node
// stickafile-mcp — a local stdio MCP server with two tools:
//   push(path, portal?, note?) → { url, name, size }
//   list_portals()             → portals the token owns
// A push with no portal makes a portal-less link (a quick send); a portal
// token puts the file in that portal.
// The file's bytes go from disk to R2 and never enter the model's context.
//
// Config (environment):
//   STICKAFILE_TOKEN   required; an sf_ API token from stickafile.com settings
//   STICKAFILE_URL     base URL, default https://stickafile.com
//   STICKAFILE_PORTAL  optional default portal (name or token); when set, a
//                      push without a portal goes there instead of to a link
//   STICKAFILE_ALLOW   optional path-delimited list of directories push may
//                      read from; default: the directory the server started in
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { createRequire } from 'node:module';
import path from 'node:path';
import { uploadFile, UploadError } from './upload.js';
import { listPortals, choosePortal, describePortal, verifyToken, ApiError } from './api.js';
import { resolveRoots, vetPath, PathRefused } from './safety.js';

const { version } = createRequire(import.meta.url)('../package.json');

function log(msg) { process.stderr.write('[stickafile-mcp] ' + msg + '\n'); }

const token = (process.env.STICKAFILE_TOKEN || '').trim();
if (!token) {
  log('STICKAFILE_TOKEN is not set. Create a token at https://stickafile.com/links (settings → api tokens) and pass it in the MCP server config.');
  process.exit(1);
}
if (!token.startsWith('sf_')) {
  log('STICKAFILE_TOKEN does not look like a Stickafile token (expected an sf_ prefix).');
  process.exit(1);
}
const baseUrl = (process.env.STICKAFILE_URL || 'https://stickafile.com').trim().replace(/\/+$/, '');
const client = { baseUrl, token };
let roots;
try {
  roots = await resolveRoots(process.env);
} catch (e) {
  log(e.message + ' Set STICKAFILE_ALLOW in the MCP server config to an existing directory, or unset it to use the launch directory.');
  process.exit(1);
}

// Probe the token once before accepting connections, so a revoked token is
// reported here, in the MCP client's server log, instead of on the first
// push. Only a 401/403 stops startup; a timeout, DNS or connection failure,
// or a server error starts the server anyway and the first call surfaces it.
const STARTUP_CHECK_MS = 3000;
{
  const check = await verifyToken(client, { timeoutMs: STARTUP_CHECK_MS });
  if (check.ok === false) {
    log('Stickafile rejected STICKAFILE_TOKEN (' + check.detail + '). The token may be revoked or expired, or STICKAFILE_URL (' + baseUrl + ') may point at a server this token was not created on. Create a new token at ' + baseUrl + '/links (settings → api tokens) and update the MCP server config.');
    process.exit(1);
  }
  if (check.ok === null) log('could not verify STICKAFILE_TOKEN at startup (' + check.detail + ' from ' + baseUrl + '); starting anyway. If the token is bad, the first call will say so.');
}

const MIME = {
  pdf: 'application/pdf', zip: 'application/zip', gz: 'application/gzip', tgz: 'application/gzip', tar: 'application/x-tar',
  json: 'application/json', csv: 'text/csv', txt: 'text/plain', md: 'text/markdown', html: 'text/html', xml: 'application/xml',
  png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp', svg: 'image/svg+xml',
  mp4: 'video/mp4', mov: 'video/quicktime', webm: 'video/webm', mp3: 'audio/mpeg', wav: 'audio/wav',
  parquet: 'application/vnd.apache.parquet', sqlite: 'application/vnd.sqlite3', db: 'application/vnd.sqlite3',
};
function mimeFor(name) { return MIME[path.extname(name).slice(1).toLowerCase()] || 'application/octet-stream'; }
function human(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
}

const server = new McpServer({ name: 'stickafile', version });

function fail(message) {
  return { isError: true, content: [{ type: 'text', text: message }] };
}
function ok(structured, text) {
  return { content: [{ type: 'text', text }], structuredContent: structured };
}

server.registerTool('push', {
  title: 'Push a file to Stickafile',
  description:
    'Upload a file from disk to Stickafile and return a shareable download link. '
    + 'Use this when the user wants to send, share, or hand off a file (a build, an export, a report, an archive, a video, a dataset) '
    + 'to a person or another machine, or asks for "a link" to a file. '
    + 'The bytes are read from disk and uploaded directly; they never enter the conversation. '
    + 'By default the file becomes a standalone link owned by the account; this is the normal case and needs no other arguments. '
    + 'Pass `portal` only when the user wants the file in a particular portal (a project\'s shared or inbox space): '
    + 'it is an 8-character portal token obtained from list_portals, never a name and never invented. '
    + '`note` is optional plain text shown on the download page (what the file is, who it is for). '
    + '`path` must be an absolute path to a regular file inside the workspace. '
    + 'Dotfiles and credential-like files (.env, keys, certificates) are refused. '
    + 'Tell the user which file you are uploading before calling this. '
    + 'Uploads take roughly a minute per gigabyte; call once per file and wait for the result. '
    + 'Do NOT retry a failed push automatically: there is no resume, so a retry re-sends the entire file from the start. Stop and ask the user whether to retry. '
    + 'Returns { url, name, size }.',
  inputSchema: {
    path: z.string().describe('Absolute path to the file to upload'),
    portal: z.string().optional().describe('Optional. The 8-character portal token to push to, from list_portals; not a portal name. Omit it to create a standalone link, which is the default.'),
    note: z.string().max(500).optional().describe('Optional plain-text note shown on the download page, up to 500 characters.'),
  },
  outputSchema: {
    url: z.string(),
    name: z.string(),
    size: z.number(),
  },
  annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
}, async ({ path: input, portal: portalArg, note: noteArg }, extra) => {
  let file;
  try { file = await vetPath(input, roots); }
  catch (e) {
    if (e instanceof PathRefused) { log('push refused: ' + e.message); return fail(e.message); }
    throw e;
  }

  // From here on the vetted descriptor (file.fh) is open; close it on every path.
  try {
    // A portal entry, or null for a portal-less link.
    let portal;
    try { portal = await choosePortal(client, portalArg, process.env); }
    catch (e) {
      if (e instanceof ApiError) return fail(e.message);
      if (e.message === 'cancelled') return fail('push cancelled');
      return fail('could not reach ' + baseUrl + ': ' + e.message);
    }
    const note = (noteArg || '').trim() || undefined;
    const target = portal ? 'portal "' + portal.name + '"' : 'link';

    log('push ' + file.path + ' (' + human(file.size) + ') → ' + (portal ? target + ' (' + portal.token + ')' : target) + (note ? ' with note' : ''));

    const progressToken = extra._meta && extra._meta.progressToken;
    let lastPct = -1;
    const onProgress = ({ sent, total, pct }) => {
      if (progressToken === undefined || pct === lastPct) return;
      lastPct = pct;
      extra.sendNotification({
        method: 'notifications/progress',
        params: { progressToken, progress: sent, total, message: pct + '% · ' + human(sent) + ' of ' + human(total) + ' → ' + (portal ? portal.name : 'link') },
      }).catch(() => {});
    };

    try {
      const result = await uploadFile({
        client, fh: file.fh, filePath: file.path, name: file.name, size: file.size, mimeType: mimeFor(file.name),
        portalToken: portal ? portal.token : undefined, note, onProgress, signal: extra.signal,
      });
      if (result.url) {
        log('done ' + result.url);
        return ok(result, 'Uploaded ' + result.name + ' (' + human(result.size) + ')' + (portal ? ' to ' + target : '') + '.\nLink: ' + result.url);
      }
      // Upload finalized, but the server returned no readable link. Report
      // success plainly; never claim failure for a file that is now public.
      log('done (upload finalized; no link returned by the server)');
      return ok({ ...result, url: '' }, 'Uploaded ' + result.name + ' (' + human(result.size) + ')' + (portal ? ' to ' + target : '') + '. The upload succeeded, but the server did not return a readable download link — find it at ' + baseUrl + '/links.');
    } catch (e) {
      if (e instanceof UploadError) { log('push failed: ' + e.message); return fail('Upload of ' + file.name + ' (' + human(file.size) + ') failed after sending part of the file: ' + e.message + '. DO NOT retry automatically. There is no resume, so a retry re-sends the entire ' + human(file.size) + ' from the start. Ask the user whether to retry before calling push again.'); }
      if (e.message === 'cancelled') { log('push cancelled'); return fail('push cancelled; nothing was published'); }
      log('push error: ' + (e.stack || e.message));
      return fail('Upload of ' + file.name + ' (' + human(file.size) + ') failed after sending part of the file: ' + e.message + '. DO NOT retry automatically. There is no resume, so a retry re-sends the entire ' + human(file.size) + ' from the start. Ask the user whether to retry before calling push again.');
    }
  } finally {
    await file.fh.close().catch(() => {});
  }
});

server.registerTool('list_portals', {
  title: 'List Stickafile portals',
  description:
    'List the Stickafile portals this account can push to, with each portal\'s name, token, mode (shared or inbox), status, and file count. '
    + 'Call this when the user wants a file pushed into a particular portal (to get its token for push), or asks what portals exist. '
    + 'Not needed before an ordinary push, which creates a standalone link.',
  inputSchema: {},
  outputSchema: {
    portals: z.array(z.object({
      token: z.string(), name: z.string(), mode: z.enum(['shared', 'inbox']), status: z.string(), fileCount: z.number(), url: z.string(),
    })),
  },
  annotations: { readOnlyHint: true, openWorldHint: true },
}, async () => {
  try {
    const portals = (await listPortals(client)).map(describePortal);
    const lines = portals.length
      ? portals.map(p => '- ' + p.name + ' (' + p.token + ') · ' + p.mode + ' · ' + p.status + ' · ' + p.fileCount + ' file' + (p.fileCount === 1 ? '' : 's')).join('\n')
      : 'No portals. Create one at ' + baseUrl + '/portal/new.';
    return ok({ portals }, lines);
  } catch (e) {
    if (e instanceof ApiError) return fail(e.message);
    return fail('could not reach ' + baseUrl + ': ' + e.message);
  }
});

const transport = new StdioServerTransport();
await server.connect(transport);
log('ready · ' + baseUrl + ' · roots: ' + roots.join(', '));
