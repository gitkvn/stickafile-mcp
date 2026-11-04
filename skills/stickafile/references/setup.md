# Setting up the stickafile MCP server

Requires a Stickafile account — free tier available: https://stickafile.com

## 1. Create an API token

Sign in at https://stickafile.com, open the gear menu, choose **api tokens**,
and create one. It starts with `sf_`.

## 2. Register the server

**Claude Code** — run this in a terminal, replacing `sf_...` with the token:

```
claude mcp add stickafile --scope user -e STICKAFILE_TOKEN=sf_... -- npx -y stickafile-mcp
```

**Other MCP clients** — add this to `.mcp.json` (or the client's equivalent):

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

Restart the client afterwards. The server checks the token at startup; a
revoked, expired, or mistyped token makes it exit with a message in the
client's MCP log.

## 3. Optional settings

| Variable | Meaning |
|---|---|
| `STICKAFILE_ALLOW` | Folders `push` may read from, separated by `:` (`;` on Windows). Default: the folder the server was started in, which Claude Code sets to the project. |
| `STICKAFILE_PORTAL` | Default portal, by name or 8-character token. When set, a push without `portal` goes there instead of making a link. |

Set them with more `-e` flags on `claude mcp add`, or in the `env` block of
`.mcp.json`.

Source and full documentation: https://github.com/gitkvn/stickafile-mcp
