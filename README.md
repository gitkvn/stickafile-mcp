# stickafile-mcp

An MCP server that lets a coding agent upload a file from disk to a
[Stickafile](https://stickafile.com) portal and hand back a shareable link.
The bytes go from disk to storage and never enter the model's context.

Two tools:

- `push(path, portal?)` → `{ url, name, size }`
- `list_portals()` → the portals the token can push to

## Install

1. Sign in at [stickafile.com](https://stickafile.com), open the gear menu,
   choose **api tokens**, and create one. Your first token also creates an
   inbox-mode portal named "agent pushes" if you have none.
2. Register the server with Claude Code, pasting the token:

   ```
   claude mcp add stickafile --scope user -e STICKAFILE_TOKEN=sf_... -- npx -y stickafile-mcp
   ```

3. In a project, ask for a link to a file:

   > push dist/report.pdf and give me the link

The server checks the token once at startup. A revoked, expired, or
wrong-server token makes it exit with a message in the client's MCP log
instead of failing on the first push. A network failure at startup does not
block it; the first call reports the problem instead.

Any MCP client works; the equivalent `.mcp.json` entry is:

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
| `STICKAFILE_ALLOW` | no | Directories `push` may read from, separated by `:` (`;` on Windows). Default: the directory the server was started in, which Claude Code sets to the project. |
| `STICKAFILE_PORTAL` | no | Default portal, by name or 8-character token, when `push` is called without one. |
| `STICKAFILE_URL` | no | Base URL. Default `https://stickafile.com`. Point at a dev deploy to test. |

Set them with more `-e` flags on `claude mcp add`, or in the `env` block of
`.mcp.json`.

## Choosing a portal

When `push` is called without `portal`: `STICKAFILE_PORTAL` if set, otherwise
the single active portal if there is exactly one, otherwise an error listing
every active portal for the user to pick from. The server never picks silently
among several.

The `portal` argument itself takes an 8-character portal token (e.g.
`a1b2c3d4`), never a name. A name is guessable and an agent can invent a
plausible one; a token has to come from `list_portals`.

## Safety

`push` reads files, so it is the tool a prompt injection would aim at. The
controls below run in the server and do not depend on the model behaving.

- **`STICKAFILE_ALLOW` is the real boundary.** `path` must be absolute,
  symlinks are resolved first, and the resolved path must sit inside one of
  the allowed roots. The agent cannot widen the roots.
- **Deny list inside the roots.** Dotfiles and dot-directories (`.env`,
  `.git`, `.ssh`, `.aws`, ...) and credential-shaped names (`*.pem`, `*.key`,
  `id_rsa`, `credentials`, ...) are refused. There is no override. Regular
  files only, one per call. The API token never appears in tool output.
- **Portal choice.** A push to the wrong *shared* portal exposes the file to
  everyone holding that portal's link. Requiring a token rather than a name
  raises the bar, but an agent that has called `list_portals` can still pass
  any token it saw. `STICKAFILE_PORTAL` is the only hard control: when it is
  set, that portal is used unless the agent passes another token explicitly,
  and there is no setting that forbids the argument.

Claude Code's own permission prompt is the human confirmation. The path shown
there is the path that gets read.

## No resume

A failed push restarts from the beginning; the abandoned server-side session
is cleaned up automatically. Because a retry re-sends the whole file, `push`
tells the agent not to retry on its own and to ask the user first.

## Development

```
npm run test:unit                # path and deny-list tests; no network
STICKR_REPO=../stickr npm test   # plus the full e2e against a local stickr checkout
```

The e2e boots the Stickafile backend from a checkout of the private `stickr`
repo, so outside contributors cannot run it; `npm run test:unit` is the suite
that runs anywhere.

`src/upload.js` is a port of `public/upload-core.js` in the stickr repo. The
retry, chunking, and presign-continuation logic must stay in step between the
two; see the header comment in each.
