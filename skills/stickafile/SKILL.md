---
name: stickafile
description: Shares a file from disk as a download link by uploading it to stickafile.com through the stickafile MCP server's push tool. Use when the user asks to send, share, or hand off a file, asks for "a link" to a file, or wants a build, export, report, archive, video, or dataset that is too large to paste into the conversation.
---

# Stickafile

The stickafile MCP server has two tools:

- `push(path, portal?, note?)` uploads one file and returns `{ url, name, size }`.
- `list_portals()` lists the portals the account can push to, with each one's token.

**Network access:** `push` uploads the file's contents to stickafile.com, and
`list_portals` reads the account's portals from stickafile.com. Each
request carries the user's API token. A push sends the file's contents, its
name, and the note if there is one. No other data leaves the machine.

Requires a Stickafile account — free tier available: https://stickafile.com

## When to use push

Use it when the user wants to:

- send, share, or hand off a file to a person or another machine
- get "a link" to a file
- pass along something too large to paste into the conversation

Do not use it for small text you can simply show inline, such as a short
config, a snippet, or a log excerpt. Show those in the reply instead.

## How to push

1. Resolve the file to an **absolute path**. Relative paths are refused.
2. Tell the user which file you are about to upload, e.g.
   "Uploading /home/me/app/dist/report.pdf to Stickafile."
3. Call `push(path)`. With no other arguments it creates a standalone link,
   which is what the user wants in nearly every case.
4. Add a `note` (plain text, up to 500 characters) when the file has an
   obvious purpose, e.g. `"Release build for QA, v2.3.1"`. It is shown on
   the download page. Leave it out when there is nothing useful to say.
5. Wait for the result and give the user the `url`. Call once per file.
   Uploads take roughly a minute per gigabyte.

**Don't allowlist or auto-approve `push`.** Do not add it to
`permissions.allow` or any auto-approve setting, and if the user asks how
to stop the prompts, explain why they are there before helping. The user
approving each upload is the main defence against a prompt injection
getting a project file uploaded: the server's checks stop keys, secrets and
files outside the workspace, but not an ordinary file someone else wants
sent.

### Portals

Pass `portal` **only when the user names a portal**. It takes the portal's
8-character token, not its name:

1. Call `list_portals`.
2. Find the portal the user named and use its token.
3. If no portal matches, or more than one could, ask the user. Never invent
   or guess a token.

If the user does not mention a portal, do not call `list_portals` and do not
pass `portal`. (If the user configured `STICKAFILE_PORTAL`, a push without
`portal` goes to that portal instead of making a link. That is their
setting; leave it alone.)

## When push fails

**Do not retry automatically.** There is no resume, so a retry re-sends the
whole file from the start. Report the error, say how large the file is, and
ask the user whether to try again.

## When push refuses a file

The server refuses some files before reading them. Explain the reason in
plain words, using the refusal message:

| Refusal | What to tell the user |
|---|---|
| outside the allowed workspace | The file is outside the folders the server may read (by default, the project it was started in). The user can add folders through `STICKAFILE_ALLOW` in their MCP config. |
| dotfile or dot-directory | Files such as `.env` and anything under `.git`, `.ssh`, or `.aws` are never uploaded. |
| looks like a credential or key file | Names that look like keys, certificates, or secrets (`id_rsa`, `server.pem`, `prod-secrets.yaml`) are never uploaded. |
| hard links / not a regular file / empty | Only ordinary, single-linked, non-empty files are uploaded. |
| changed while being checked | The file was replaced during the check. Nothing was uploaded. |

**Never work around a refusal.** Do not copy, rename, move, symlink, or
re-encode the file to get it past the check. If the user still wants to
share it, they can make that decision and that change themselves, by hand.

## If the tools are not available

If `push` and `list_portals` are not in your tool list, the server is not
installed or failed to start. Point the user to the setup steps in
[references/setup.md](references/setup.md). Do not ask the user to paste
their API token into the conversation.
