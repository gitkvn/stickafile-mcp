# stickafile-mcp

A local MCP server that lets a coding agent upload a file from disk to a
[Stickafile](https://stickafile.com) portal and get back a shareable link.
The bytes go from disk to storage; they never enter the model's context.

Two tools:

- `push(path, portal?)` → `{ url, name, size }` — `portal` is an 8-character portal token
- `list_portals()` → the portals the token owns

## Install

1. Create an API token at stickafile.com → links → settings → api tokens.
   Your first token also creates an inbox-mode portal named "agent pushes"
   if you have none.
2. Register the server with Claude Code:

```
claude mcp add stickafile --scope user -e STICKAFILE_TOKEN=sf_... -- npx -y stickafile-mcp
```

Equivalent `.mcp.json` entry:

```json
{
  "mcpServers": {
    "stickafile": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "stickafile-mcp"],
      "env": { "STICKAFILE_TOKEN": "sf_..." }
    }
  }
}
```

## Configuration

| Variable | Required | Meaning |
|---|---|---|
| `STICKAFILE_TOKEN` | yes | An `sf_` API token. Scopes: list portals, push files. |
| `STICKAFILE_URL` | no | Base URL, default `https://stickafile.com`. Point at a dev deploy to test. |
| `STICKAFILE_PORTAL` | no | Default portal (name or token) when `push` is called without one. |
| `STICKAFILE_ALLOW` | no | Path-delimited directories `push` may read from. Default: the directory the server was started in, which Claude Code sets to the project. |

## Choosing a portal

The `push` tool's `portal` argument is an **8-character portal token only**
(e.g. `a1b2c3d4`), never a portal name. Get it from `list_portals`. A name is
passed straight through and refused with a message pointing back at
`list_portals`. This is deliberate: a name like `test` is guessable, so an
agent can fabricate a plausible one; a token is not, so the agent has to have
called `list_portals` and is relaying real data rather than guessing. A push
to the wrong *shared* portal exposes the file to everyone holding that
portal's link, so the argument is built to make that hard to do by accident.

When `portal` is omitted the precedence is:

1. `STICKAFILE_PORTAL` if set — **this accepts a name or a token**, because a
   human sets it once at install time, where a friendly name is reasonable.
2. otherwise the single active portal, if there is exactly one;
3. otherwise an error listing every active portal with its name, token, and
   mode (shared or inbox), for the user to choose from.

The server never picks silently among several portals. Portals are created in
the browser only; tokens cannot create them.

## Safety

`push` reads files, so it is the tool a prompt injection would aim at. The
controls do not depend on the model:

- `path` must be absolute. Symlinks are resolved before any check.
- The resolved path must be inside a `STICKAFILE_ALLOW` root. Anything
  else is refused with a message naming the roots.
- Inside the roots, dotfiles and dot-directories (`.env`, `.git`, `.ssh`,
  `.aws`, ...) and credential-shaped names (`*.pem`, `*.key`, `id_rsa`,
  `credentials`, ...) are refused. There is no override.
- Regular files only, one per call. The token never appears in output.
- Claude Code's own permission prompt is the human confirmation; the path
  shown there is the path that gets read.

## No resume

A failed upload restarts from the beginning; the server-side session is swept
automatically. There is no resume, so a retry re-sends the whole file. Because
that is expensive and silent on a large file, `push` does not want the agent
retrying on its own: a failure returns an error that says, in as many words,
not to retry automatically and to ask the user first. Retrying is the user's
call, not the model's.

## Development

The uploader in `src/upload.js` is a port of `public/upload-core.js` in the
stickr repo. Retry, chunking, and presign-continuation logic must stay in
step between the two; see the header comment in each.

```
npm run test:unit                # path/deny-list unit tests; no stickr checkout needed
STICKR_REPO=../stickr npm test   # unit tests, then the full e2e (boots stickr + mock S3)
```

`npm run test:unit` (`test/safety.test.js`) exercises the path controls in
`src/safety.js` directly — no server, no network, no model. It is the proof
that the credential deny list (`id_rsa`, `*.pem`, `.env`, dot-directories, ...)
fires on its own, which is what has to hold against a prompt injection: any
refusal the model volunteers is worthless against the same injection.
