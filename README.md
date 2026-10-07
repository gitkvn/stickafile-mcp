# stickafile-mcp

An MCP server that lets a coding agent upload a file from disk to
[Stickafile](https://stickafile.com) and hand back a shareable link. The
bytes go from disk to storage and never enter the model's context.

Two tools:

- `push(path, portal?, note?)` → `{ url, name, size }`
- `list_portals()` → the portals the token can push to

A push makes a standalone link by default. Pass a portal token when the file
belongs in a project's portal instead.

## Install

1. Sign in at [stickafile.com](https://stickafile.com), open the gear menu,
   choose **api tokens**, and create one.
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
| `STICKAFILE_TOKEN` | yes | An `sf_` API token. Scopes: list portals, push to portals, create links. |
| `STICKAFILE_ALLOW` | no | Directories `push` may read from, separated by `:` (`;` on Windows). Default: the directory the server was started in, which Claude Code sets to the project. |
| `STICKAFILE_PORTAL` | no | Default portal, by name or 8-character token. When set, a `push` without `portal` goes there instead of making a link. |
| `STICKAFILE_URL` | no | Base URL. Default `https://stickafile.com`. Point at a dev deploy to test. |

Set them with more `-e` flags on `claude mcp add`, or in the `env` block of
`.mcp.json`.

## Links and portals

`push` without `portal` makes a **link**: a standalone file owned by your
account, listed under Links on the dashboard, with no portal involved. This is
the quick-send path and needs nothing configured beyond the token. The usual
limits apply: 2 GB and 24 hours on the free plan, 10 GB and 30 days with pack
credit.

`push` with `portal` puts the file in that **portal** instead, so it sits with
a project's other files and the portal's own settings (gate, password, shared
view) apply. The argument takes an 8-character portal token (e.g. `a1b2c3d4`),
never a name. A name is guessable and an agent can invent a plausible one; a
token has to come from `list_portals`.

`STICKAFILE_PORTAL` changes the default: when it is set, a push without
`portal` goes to that portal rather than making a link. An explicit `portal`
token still wins. If the configured portal is missing or deactivated, the push
fails rather than silently falling back to a link.

`note` is optional plain text, up to 500 characters, shown on the download
page under the file name. It is dropped on portals that have notes turned
off.

## Safety

`push` reads files, so it is the tool a prompt injection would aim at. The
controls below run in the server and do not depend on the model behaving.

- **`STICKAFILE_ALLOW` is the real boundary.** `path` must be absolute,
  symlinks are resolved first, and the resolved path must sit inside one of
  the allowed roots. The agent cannot widen the roots.
- **Deny list inside the roots.** Dotfiles and dot-directories (`.env`,
  `.git`, `.ssh`, `.aws`, ...) and credential-shaped names are refused, with
  no override. The name check strips backup and double extensions
  (`id_rsa.bak`, `server.key.gz`) and matches credential words as whole tokens
  (`aws_credentials`, `prod-secrets.yaml`), so a suffix or affix does not slip
  a key or secret past it. As a side effect, a file whose name contains the
  whole word `secret(s)` or `credential(s)` is refused even when it is not
  sensitive (e.g. `secret_plans.txt`); copy it to a neutral name to push it.
- **Regular files only, and only what was vetted.** `vetPath` opens the file
  once and the uploader reads from that descriptor, so the bytes uploaded are
  the bytes that were checked — a symlink or file swapped in after the check
  cannot redirect the upload. The descriptor's device and inode must match
  the entry that passed the name checks, or the push is refused. Files with more than one hard link are refused,
  because a hardlinked name can point at an inode whose home is outside the
  workspace; push a copy instead. The API token never appears in tool output.
- **Portal choice.** A push to the wrong *shared* portal exposes the file to
  everyone holding that portal's link. The default is therefore a link, which
  only you and the people you send it to can open; the server never picks a
  portal on its own. Requiring a token rather than a name for `portal` raises
  the bar, but an agent that has called `list_portals` can still pass any
  token it saw, and there is no setting that forbids the argument.

Claude Code's own permission prompt is the human confirmation. The path shown
there is the path that gets read.

### Windows is untested

The path controls are developed and tested on macOS and Linux. Windows is not
covered by the test suite, and three things are open questions rather than
cleared: NTFS alternate data streams (a name like `secret.pem:hidden` does not
end in `.pem`), 8.3 short names (`ID_RSA~1`), and whether `realpath` casing
keeps the case-insensitive root-boundary check honest. `O_NOFOLLOW`, which
closes the check-then-open race on POSIX, is also absent on Windows. Treat the
guarantees above as verified on POSIX only until there is Windows coverage.

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
