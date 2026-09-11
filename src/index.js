#!/usr/bin/env node
// stickafile-mcp — a local stdio MCP server with two tools:
//   push(path, portal?) → { url, name, size }
//   list_portals()      → portals the token owns
// The file's bytes go from disk to R2 and never enter the model's context.
//
// Config (environment):
//   STICKAFILE_TOKEN   required; an sf_ API token from stickafile.com settings
//   STICKAFILE_URL     base URL, default https://stickafile.com
//   STICKAFILE_PORTAL  optional default portal (name or token)
//   STICKAFILE_ALLOW   optional path-delimited list of directories push may
//                      read from; default: the directory the server started in
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { createRequire } from 'node:module';
import path from 'node:path';
import { uploadFile, UploadError } from './upload.js';
import { listPortals, choosePortal, describePortal, ApiError } from './api.js';
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
const roots = await resolveRoots(process.env);

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
    'Upload a file from disk to a Stickafile portal and return a shareable download link. '
    + 'Use this when the user wants to send, share, or hand off a file (a build, an export, a report, an archive, a video, a dataset) '
    + 'to a person or another machine, or asks for "a link" to a file. '
    + 'The bytes are read from disk and uploaded directly; they never enter the conversation. '
    + '`path` must be an absolute path to a regular file inside the workspace. '
    + 'Dotfiles and credential-like files (.env, keys, certificates) are refused. '
    + '`portal` is optional when the account has one portal; pass a portal name or token otherwise. '
    + 'Tell the user which file you are uploading before calling this. '
    + 'Uploads take roughly a minute per gigabyte; call once per file and wait for the result. '
    + 'A failed upload restarts from the beginning (no resume), so before retrying a large file tell the user it will re-send everything. '
    + 'Returns { url, name, size }.',
  inputSchema: {
    path: z.string().describe('Absolute path to the file to upload'),
    portal: z.string().optional().describe('Portal name or 8-character token. Optional when the account has exactly one active portal.'),
  },
  outputSchema: {
    url: z.string(),
    name: z.string(),
    size: z.number(),
  },
  annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
}, async ({ path: input, portal: portalArg }, extra) => {
  let file;
  try { file = await vetPath(input, roots); }
  catch (e) {
    if (e instanceof PathRefused) { log('push refused: ' + e.message); return fail(e.message); }
    throw e;
  }

  let portal;
  try { portal = await choosePortal(client, portalArg, process.env); }
  catch (e) {
    if (e instanceof ApiError) return fail(e.message);
    if (e.message === 'cancelled') return fail('push cancelled');
    return fail('could not reach ' + baseUrl + ': ' + e.message);
  }

  log('push ' + file.path + ' (' + human(file.size) + ') → portal "' + portal.name + '" (' + portal.token + ')');

  const progressToken = extra._meta && extra._meta.progressToken;
  let lastPct = -1;
  const onProgress = ({ sent, total, pct }) => {
    if (progressToken === undefined || pct === lastPct) return;
    lastPct = pct;
    extra.sendNotification({
      method: 'notifications/progress',
      params: { progressToken, progress: sent, total, message: pct + '% · ' + human(sent) + ' of ' + human(total) + ' → ' + portal.name },
    }).catch(() => {});
  };

  try {
    const result = await uploadFile({
      client, filePath: file.path, name: file.name, size: file.size, mimeType: mimeFor(file.name),
      portalToken: portal.token, onProgress, signal: extra.signal,
    });
    log('done ' + result.url);
    return ok(result, 'Uploaded ' + result.name + ' (' + human(result.size) + ') to portal "' + portal.name + '".\nLink: ' + result.url);
  } catch (e) {
    if (e instanceof UploadError) { log('push failed: ' + e.message); return fail('upload of ' + file.name + ' failed: ' + e.message + '. There is no resume; a retry re-sends the whole file.'); }
    if (e.message === 'cancelled') { log('push cancelled'); return fail('push cancelled; nothing was published'); }
    log('push error: ' + (e.stack || e.message));
    return fail('upload of ' + file.name + ' failed: ' + e.message + '. There is no resume; a retry re-sends the whole file.');
  }
});

server.registerTool('list_portals', {
  title: 'List Stickafile portals',
  description:
    'List the Stickafile portals this account can push to, with each portal\'s name, token, mode (shared or inbox), status, and file count. '
    + 'Call this when push reports that a portal must be chosen, or when the user asks what portals exist. '
    + 'Not needed before an ordinary push.',
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
