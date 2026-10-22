# Connecting agents over MCP

LoomCtx's MCP server (`python -m loomctx.mcp_server`) gives an agent 14
tools over the same functions the HTTP API uses; [sdk.md](sdk.md) lists
them. This page is the setup for each client. Every client needs one of
two things:

- **stdio:** a command the client runs per session. The server reads the
  store directly. It is local trust: no API key, because whoever can run
  the command already has the data.
- **streamable HTTP:** a URL. `docker compose --profile mcp up -d mcp`
  serves it at `http://127.0.0.1:8300/mcp`. When the deployment has keys
  (`LOOMCTX_AUTH_FILE` or `LOOMCTX_API_KEYS`), every request must carry
  `X-LoomCtx-Key: <key>` or `Authorization: Bearer <key>`: none is a 401,
  an unknown, expired or disabled key a 403, and each tool call gets that
  key's namespace, read/write and entity-type gates. Without keys the
  server is open (it logs a warning) and the port binds to localhost only.

Load some data first ([quickstart.md](quickstart.md) or
[bring-your-own-data.md](bring-your-own-data.md)), then check the
connection by asking the agent to call `list_namespaces`.

## The stdio command

From a checkout, through compose. `--project-directory` lets the client
start it from any working directory:

```bash
docker compose --project-directory /path/to/loomctx run --rm -T loomctx python -m loomctx.mcp_server
```

Without a checkout, from the published image, against the engine's volume
(compose names it `loomctx_loomctx-data`; `docker volume ls` shows yours):

```bash
docker run -i --rm -v loomctx_loomctx-data:/data ghcr.io/seahop/loomctx:latest python -m loomctx.mcp_server
```

`-T` (compose) and `-i` without `-t` (docker) matter: MCP over stdio is
JSON lines, and a TTY corrupts them. `:latest` is built from `main`; pin a
release tag (`:v0.2.0`) for a fixed version, but note that the alias and
combined-`within` features used in [recipes.md](recipes.md) landed after
v0.2.0.

Both forms run next to a running engine: they open the same SQLite file.

## Switches

| Variable | Effect |
| --- | --- |
| `LOOMCTX_MCP_NAMESPACE=corp` | the namespace a tool uses when the call names none |
| `LOOMCTX_MCP_WRITES=0` | hides `record_claim`: agents can only read |
| `LOOMCTX_MCP_QUERIES=0` | hides `run_query` and the `queries` that `describe_namespace` lists |
| `LOOMCTX_EMBED_*` | needed for `find_related`, semantic ranking and document excerpts |
| `LOOMCTX_LLM_*` | needed for the `answer` tool |

For the `mcp` compose service and for `docker compose run`, put them in
`.env`; compose passes them through. For one stdio command, add `-e`:
`docker compose … run --rm -T -e LOOMCTX_MCP_WRITES=0 loomctx python -m loomctx.mcp_server`,
or `docker run -i --rm -e LOOMCTX_MCP_WRITES=0 …`. A key with only `r`
permission already refuses writes; `LOOMCTX_MCP_WRITES=0` also takes the
tool out of the list, so the agent does not try.

## Keys for the HTTP transport

Mint a read key scoped to the namespaces the agent may see
([administration.md](administration.md) has the full set of gates):

```bash
mkdir -p secrets   # yours, not root's: docker would create a missing mount source as root
docker compose run --rm --user "$(id -u):$(id -g)" -v $PWD/secrets:/secrets loomctx \
  python -m loomctx.keys --file /secrets/keys.json generate --id analyst-agent --namespace corp --perms r
```

The plaintext key is printed once. Point the `mcp` service at the file as
administration.md describes, or, for a trial, set
`LOOMCTX_API_KEYS=<key>:corp:r` in `.env` (plaintext, no fine-grained
gates). Check the endpoint before configuring a client:

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:8300/mcp \
  -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' \
  -H "X-LoomCtx-Key: $KEY" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}'
# 200; 401 without the header, 403 with a wrong key
```

Keep keys out of any config file you commit.

## Claude Code

stdio, run from the checkout:

```bash
claude mcp add loomctx -- docker compose --project-directory "$PWD" run --rm -T loomctx python -m loomctx.mcp_server
```

Read-only, with a default namespace:

```bash
claude mcp add loomctx -- docker compose --project-directory "$PWD" run --rm -T \
  -e LOOMCTX_MCP_WRITES=0 -e LOOMCTX_MCP_NAMESPACE=corp loomctx python -m loomctx.mcp_server
```

Streamable HTTP with a key:

```bash
claude mcp add --transport http loomctx http://127.0.0.1:8300/mcp --header "X-LoomCtx-Key: $KEY"
```

`--scope project` writes the server into `.mcp.json` for the whole team;
use it for the stdio form, not for a command line that holds a key. These
flags are from `claude mcp add --help` (Claude Code 2.1). Claude Code caps
an MCP tool result at 25,000 tokens by default; LoomCtx's server
instructions keep `ask_scope` at `budget<=4000`, well under it.

## Claude Desktop

Claude Desktop starts local servers from `claude_desktop_config.json`
(Settings → Developer → Edit Config). The shape is the same `mcpServers`
object the repo ships in [`demo/mcp.json`](../demo/mcp.json):

```json
{
  "mcpServers": {
    "loomctx": {
      "command": "docker",
      "args": ["compose", "--project-directory", "/path/to/loomctx",
               "run", "--rm", "-T", "loomctx", "python", "-m", "loomctx.mcp_server"],
      "env": {"LOOMCTX_MCP_WRITES": "0"}
    }
  }
}
```

The `env` block reaches `docker compose`, which passes it into the
container. Desktop does not start in the checkout, so the project
directory must be absolute. If Desktop cannot find `docker`, give the full
path to the binary in `command`. Restart Desktop after editing.

This file only starts local (stdio) servers. Remote servers are added in
Desktop's own settings; whether that dialog can send a custom header
depends on the Desktop version, so check Anthropic's documentation for
yours. If it cannot, use the stdio form on the machine that runs LoomCtx.

## Cursor

Cursor reads `mcpServers` from `.cursor/mcp.json` in a project or
`~/.cursor/mcp.json` for every project. stdio:

```json
{
  "mcpServers": {
    "loomctx": {
      "command": "docker",
      "args": ["compose", "--project-directory", "/path/to/loomctx",
               "run", "--rm", "-T", "loomctx", "python", "-m", "loomctx.mcp_server"]
    }
  }
}
```

Streamable HTTP:

```json
{
  "mcpServers": {
    "loomctx": {
      "url": "http://127.0.0.1:8300/mcp",
      "headers": {"X-LoomCtx-Key": "loomctxk_..."}
    }
  }
}
```

Not tested from this repo: check the field names (`url`, `headers`)
against Cursor's MCP documentation for your version.

## VS Code (GitHub Copilot agent mode)

VS Code reads `.vscode/mcp.json` in the workspace. The top-level key is
`servers`, not `mcpServers`, and each server names its `type`. An `inputs`
entry prompts for the key once instead of storing it in the file:

```json
{
  "inputs": [
    {"type": "promptString", "id": "loomctx-key", "description": "LoomCtx API key", "password": true}
  ],
  "servers": {
    "loomctx": {
      "type": "stdio",
      "command": "docker",
      "args": ["compose", "--project-directory", "/path/to/loomctx",
               "run", "--rm", "-T", "loomctx", "python", "-m", "loomctx.mcp_server"]
    },
    "loomctx-remote": {
      "type": "http",
      "url": "http://127.0.0.1:8300/mcp",
      "headers": {"X-LoomCtx-Key": "${input:loomctx-key}"}
    }
  }
}
```

Pick one of the two entries. Then open the Chat view in Agent mode and
enable the server's tools. Not tested from this repo: check the format
against VS Code's MCP documentation for your version.

## Any other client

What every MCP client needs, whatever it calls the fields:

| | stdio | streamable HTTP |
| --- | --- | --- |
| command / URL | `docker` | `http://127.0.0.1:8300/mcp` |
| arguments | `compose --project-directory /path/to/loomctx run --rm -T loomctx python -m loomctx.mcp_server` | none |
| environment | `LOOMCTX_MCP_*` switches (optional) | set on the server, not the client |
| headers | none | `X-LoomCtx-Key: <key>` or `Authorization: Bearer <key>`, when keys are on |

The generic JSON most clients accept:

```json
{
  "mcpServers": {
    "loomctx": {
      "command": "docker",
      "args": ["compose", "--project-directory", "/path/to/loomctx",
               "run", "--rm", "-T", "loomctx", "python", "-m", "loomctx.mcp_server"]
    }
  }
}
```

The server also speaks the older SSE transport
(`--transport sse`) for clients that have no streamable HTTP; the compose
`mcp` service runs streamable HTTP.

A client that sends an `Origin` header from a web page (a browser-based
tool) must be on `LOOMCTX_ALLOWED_ORIGINS`, and a server reached by a
public name must be on `LOOMCTX_ALLOWED_HOSTS` (`.env.example`). Desktop
and CLI clients send no `Origin` and are unaffected.

## What the agent does next

The server's instructions teach the loop: `list_namespaces` and
`describe_namespace` to learn what exists, `find_entity` to turn names into
`type:key` handles, then `ask`, `ask_scope`, `find_path`, `list_entities`
or `run_query`, citing each fact by its 12-hex `cite` token.
[recipes.md](recipes.md) has one worked question per team.
