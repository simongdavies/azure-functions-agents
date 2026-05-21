# Basic Chat

An HTTP chat agent with a built-in web UI, streaming API, MCP server endpoint, and Python code execution via ACA Dynamic Sessions.

| Trigger | Custom Tools | Connectors | MCP Servers | Skills | Sandbox | Chat UI |
| --- | --- | --- | --- | --- | --- | --- |
| HTTP | ✅ word_count | | | | ✅ | ✅ |

## Features

- **Chat UI** — built-in single-page interface at the app root
- **HTTP API** — `POST /agent/chat` (JSON) and `POST /agent/chatstream` (SSE)
- **MCP server** — `/runtime/webhooks/mcp` for connecting from VS Code, Claude Desktop, etc.
- **Code execution** — sandboxed Python via hyperlight-sandbox with persistent session state, HTTP access, and host-backed input/output directories
- **Custom tools** — drop Python files in `src/tools/` to turn their functions into first-class tools the LLM can call directly
- **Session persistence** — multi-turn conversations stored on Azure Files

## Prerequisites

- [Azure Developer CLI (`azd`)](https://learn.microsoft.com/azure/developer/azure-developer-cli/install-azd)
- [Azure Functions Core Tools](https://learn.microsoft.com/azure/azure-functions/functions-run-local)
- A [GitHub Personal Access Token](../../README.md#github-token) with **Copilot** scope
- An Azure subscription

## Deploy

1. **Set environment variables:**

   ```bash
   cd samples/basic-chat
   azd init
   azd env set GITHUB_TOKEN <your-github-pat>
   ```

   Optional:

   ```bash
   azd env set COPILOT_MODEL claude-opus-4.6     # default
   ```

2. **Deploy to Azure:**

   ```bash
   azd up
   ```

3. **Open the chat UI:**

   Navigate to the Function App URL shown in the deployment output (`https://<app-name>.azurewebsites.net/`).

## Run Locally

Follow the [shared local development guide](../README.md#run-locally) in the samples directory. This sample has minimal additional requirements.

### Local settings

- `GITHUB_TOKEN`: required (see shared guide)
- `ACA_SESSION_POOL_ENDPOINT`: optional; if empty, chat works but code execution (Python/Playwright) is unavailable

### Testing endpoints

Once `func start` is running:

- **Chat UI:** `http://localhost:7071/`
- **Chat API:** `POST http://localhost:7071/agent/chat` with JSON body `{"prompt": "..."}`
- **Streaming API:** `POST http://localhost:7071/agent/chatstream` (Server-Sent Events)
- **MCP webhook:** `http://localhost:7071/runtime/webhooks/mcp` (for VS Code, Claude Desktop)

## How It Works

- [`main.agent.md`](src/main.agent.md) defines the agent with code execution sandbox support
- The framework registers HTTP chat endpoints, an MCP server, and a built-in chat UI
- The agent can answer questions and run Python code in a secure sandbox when needed
- Custom tools dropped into [`src/tools/*.py`](src/tools/) become first-class
  tools the LLM can call directly — see [`word_count.py`](src/tools/word_count.py) for an example

## Custom Tools

This sample ships one example tool — [`src/tools/word_count.py`](src/tools/word_count.py) —
to show how developers can extend the agent with their own Python functions
without touching the framework code.

The lifecycle:

1. **Discovery (inside an ephemeral Hyperlight VM).** At agent startup
   the framework walks `src/tools/*.py`, reads each file's bytes off
   disk, and ships them as JSON literals into a one-shot Hyperlight
   sandbox. That sandbox runs a framework-controlled introspection
   snippet — `ast.parse` plus the annotation whitelist — and returns
   a JSON envelope describing each file's outcome. **No developer
   bytes are ever parsed by the host's Python interpreter.** The
   ephemeral VM is destroyed immediately after the snippet returns;
   nothing developer-supplied has any path onto the host CPU.
   The first non-underscore top-level function in each file becomes
   a tool; its parameter annotations are converted into a JSON schema
   for the LLM, and its docstring becomes the tool description.
2. **Bootstrap (inside the per-session sandbox, once per session).**
   The concatenated source of every accepted tool file is shipped to
   the per-agent Hyperlight Wasm sandbox via `Sandbox.run(...)` exactly
   once per session, immediately after the warmup. The developer's
   function definitions land in the guest's global namespace.
3. **Dispatch (inside the per-session sandbox, per call).** When the
   LLM calls a tool, the framework builds a tiny snippet that
   JSON-decodes the arguments, invokes the function in the guest, and
   prints the JSON-encoded result. The same per-session Hyperlight VM
   is reused, so tools share state with `execute_python` calls if you
   want them to.

### Constraints

- One tool per `.py` file. The function name becomes the tool name and
  must be unique across the whole `tools/` directory.
- Allowed parameter annotations: `str`, `int`, `float`, `bool`, `list`,
  `dict`, `tuple`, `Any`, `object`, and `Optional[...]` thereof.
  Anything outside that set (custom generics, `Annotated[...]`,
  `Literal[...]`, your own classes) causes the tool to be skipped with
  a warning — the LLM needs a truthful schema and we'd rather decline
  than lie.
- No `*args` / `**kwargs` / positional-only / keyword-only parameters.
- The function runs **inside the Hyperlight Wasm VM**, so it has only
  the Python stdlib that the guest image ships. No PyPI packages, no
  host filesystem access except via the `/input` and `/output` mounts
  the host configures.

### Selecting which tools an agent gets

By default every agent picks up every `*.py` in `tools/`. To restrict
the set per-agent, add a `tools:` list to the `execution_sandbox`
block in the agent's frontmatter:

```yaml
execution_sandbox:
  tools:
    - word_count     # bare module names, resolved to tools/<name>.py
```

Set `tools: []` (an explicit empty list) to opt this agent out of
custom tools entirely.

### Iterating on tools without rebuilding the container

Tools are baked into the container image at build time (under
`/home/site/wwwroot/tools/`), so the dev `podman run` recipe below
needs no change. For local iteration, bind-mount your source `tools/`
directory over the in-image copy with `:ro` (the host only ever reads
custom tool files):

Linux / macOS:

```bash
-v "$PWD/samples/basic-chat/src/tools:/home/site/wwwroot/tools:ro,Z"
```

Windows PowerShell:

```powershell
-v "${PWD}/samples/basic-chat/src/tools:/home/site/wwwroot/tools:ro"
```

Restart the container after editing a tool — discovery happens at
agent startup, not per request.

## Container image

The Dockerfile is multi-stage with two final targets:

| Target | Default? | Includes | Listens on | Storage backend |
| --- | --- | --- | --- | --- |
| `dev` | ✅ | Functions Core Tools + Azurite + a baked-in `local.settings.json` | `7071` | Azurite (`UseDevelopmentStorage=true`) |
| `prod` | | Functions Core Tools only | `8080` | Operator-supplied via `AzureWebJobsStorage` |

The two targets share a single `runtime-base` layer (Functions Core
Tools, libicu, the Hyperlight Wasm guest with the AOT pre-baked, your
function-app source, and the `app:10001` non-root user), so building
both costs only one full image's worth of layers in your local store.

The Dockerfile's docstring is the source of truth for build/run
recipes and the rationale behind every hardening flag — what's below
is the cheat-sheet.

### Building

Both targets need a sibling checkout of
[`simongdavies/hyperlight-sandbox`](https://github.com/simongdavies/hyperlight-sandbox)
at the commit pinned in `pyproject.toml`, with `just wasm build`
already run so that `src/wasm_sandbox/guests/python/python-sandbox.aot`
exists on disk. Pass that directory as a `--build-context` named
`hyperlight=` so the post-install step can copy the AOT into the
installed `python_guest` package — the upstream wheel ships an empty
`python_guest/resources/` directory and pip-install-via-git URL skips
the `just python-sync-guest-resources` recipe that would otherwise
populate it. (Once the upstream wheel grows a build-hook that copies
the AOT during wheel construction, the `--build-context hyperlight=…`
flag can go away.)

Build the dev image (default target):

```bash
podman build \
  --build-context hyperlight=$HOME/source/repos/hyperlight-sandbox \
  -t basic-chat:dev \
  -f samples/basic-chat/Dockerfile .
```

Build the prod image:

```bash
podman build \
  --target=prod \
  --build-context hyperlight=$HOME/source/repos/hyperlight-sandbox \
  -t basic-chat:prod \
  -f samples/basic-chat/Dockerfile .
```

### Running the dev image

The dev image is the one to use for local hacking. Azurite runs
in-process so you don't need a real storage account, and
`local.settings.json` is baked in so a bare `podman run` Just Works.

Ephemeral (sandbox input/output wiped when the container exits):

Linux / macOS:

```bash
podman run --rm -it \
  --device /dev/kvm \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --ulimit nofile=4096:4096 \
  --read-only \
  --tmpfs /tmp:rw,size=1g,mode=1777 \
  --tmpfs /sandbox/in:rw,size=64m,mode=1777 \
  --tmpfs /sandbox/out:rw,size=128m,mode=1777 \
  -p 127.0.0.1:7071:7071 \
  -e GITHUB_TOKEN="$GITHUB_TOKEN" \
  basic-chat:dev
```

Windows PowerShell:

```powershell
podman run --rm -it `
  --device /dev/kvm `
  --cap-drop=ALL `
  --security-opt=no-new-privileges `
  --ulimit nofile=4096:4096 `
  --read-only `
  --tmpfs /tmp:rw,size=1g,mode=1777 `
  --tmpfs /sandbox/in:rw,size=64m,mode=1777 `
  --tmpfs /sandbox/out:rw,size=128m,mode=1777 `
  -p 127.0.0.1:7071:7071 `
  -e GITHUB_TOKEN=$env:GITHUB_TOKEN `
  basic-chat:dev
```

Then open <http://localhost:7071> in your browser.

Persistent (sandbox input/output survive across container restarts).
Drop the two `/sandbox/*` `--tmpfs` flags and add bind-mounts to host
directories instead:

Linux / macOS:

```bash
-v "$HOME/sandbox-in:/sandbox/in:ro,Z" \
-v "$HOME/sandbox-out:/sandbox/out:Z"
```

Windows PowerShell (forward-slashed, no SELinux `Z`):

```powershell
-v "$($env:USERPROFILE -replace '\\','/')/sandbox-in:/sandbox/in:ro" `
-v "$($env:USERPROFILE -replace '\\','/')/sandbox-out:/sandbox/out"
```

The `/tmp` tmpfs stays at `size=1g` even when the sandbox dirs are
bind-mounted — `/tmp` still needs to hold the Functions extension
bundle download on first start (≈ 100 MB zip + ≈ 300 MB extracted) on
top of the usual `func` + Python tempfile churn.

### Running the prod image

The prod image is what you push to Azure Functions Premium or App
Service custom-container hosting. It deliberately does **not** ship
Azurite or a `local.settings.json` — the operator supplies storage
via `AzureWebJobsStorage` (and any other app settings the function
app needs) on the Function App resource. Locally you'd point it at a
real Azure Storage account too; "let's wire up Azurite as a sidecar
just to smoke-test" defeats the contract.

The hardening flags are identical to dev; only the published port
(`8080`) and the storage configuration differ:

```bash
podman run --rm -it \
  --device /dev/kvm \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --ulimit nofile=4096:4096 \
  --read-only \
  --tmpfs /tmp:rw,size=1g,mode=1777 \
  --tmpfs /sandbox/in:rw,size=64m,mode=1777 \
  --tmpfs /sandbox/out:rw,size=128m,mode=1777 \
  -p 127.0.0.1:8080:8080 \
  -e AzureWebJobsStorage="<your real storage connection string>" \
  -e FUNCTIONS_WORKER_RUNTIME=python \
  -e GITHUB_TOKEN="$GITHUB_TOKEN" \
  basic-chat:prod
```

`8080` is non-privileged (so the non-root `app` user can bind it
without `CAP_NET_BIND_SERVICE`) and App Service / Functions Premium
auto-detects it without setting `WEBSITES_PORT`.

### Hardening flags 

Every flag in the `podman run` lines is documented in the Dockerfile
docstring:

- `--cap-drop=ALL` + `--security-opt=no-new-privileges` — drop all
  Linux capabilities and block setuid/cap escalation. KVM ioctls work
  without caps once `/dev/kvm` is accessible via the device cgroup.
- `--read-only` — rootfs immutable; the tmpfs mounts cover every
  known writer (`func`, the Python worker, Azurite, the Hyperlight
  guest input/output dirs, and the Functions extension bundle cache).
- `--tmpfs /tmp:rw,size=1g,mode=1777` — `HOME=/tmp` redirects every
  first-run state file (`~/.azurefunctions`, `~/.cache`, …) onto the
  tmpfs, plus it holds the extension-bundle download on cold start.
- Deliberately **not** included: `--memory`, `--cpus`, `--pids-limit`,
  Dockerfile `HEALTHCHECK`. Those are either cgroup-controller-gated
  (and silent no-ops in rootless podman) or ignored by App Service
  custom-container hosting. See the Dockerfile docstring for the
  longer rationale.
