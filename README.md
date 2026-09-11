# stickafile-mcp

A local MCP server that lets a coding agent upload a file from disk to a
[Stickafile](https://stickafile.com) portal and get back a shareable link.
The bytes go from disk to storage; they never enter the model's context.

Two tools:

- `push(path, portal?)` → `{ url, name, size }`
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

## Portal defaulting

When `portal` is omitted: `STICKAFILE_PORTAL` if set, otherwise the single
active portal if there is exactly one, otherwise an error listing the choices.
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

A failed upload restarts from the beginning. The server-side session is
swept automatically. For a large file, a retry re-sends everything.

## Development

The uploader in `src/upload.js` is a port of `public/upload-core.js` in the
stickr repo. Retry, chunking, and presign-continuation logic must stay in
step between the two; see the header comment in each.

```
STICKR_REPO=../stickr npm test   # boots the stickr server + mock S3 locally
```
