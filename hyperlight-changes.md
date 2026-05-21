

# Hyperlight sandbox implementation for Azure Functions Agents

## 🛡️ Trust model

> **All developer-supplied input is either (a) immutable text passed verbatim to the LLM as untrusted data, or (b) executed inside the Hyperlight Wasm VM. Never both. Never anywhere else.**

- **No developer code ever runs in the host** `execute_python` bodies, `tools/*.py` source, and tool-discovery introspection all run inside Hyperlight Sandboxes.
- **No LLM output ever runs in the host.** Tool calls are JSON-dispatched into the guest; tool results come back as data, never as code.
- **No secret ever crosses the Guest/Host boundary.** The host owns every token; the guest holds an opaque name (`credential="azure_mgmt"`) and calls `http_get(url, credential=…)`. The host resolves, scope-checks, and injects the header at WASI-HTTP dispatch time.
- **No host filesystem ever crosses the Guest/Host boundary.** Guest sees only `/input` (ro) and `/output` (rw); host paths are translated, never opened.
- **The container is packaging, not the boundary.** The Hyperlight VM is *the* tenant boundary. Container hardening (read-only rootfs, `--cap-drop=ALL`, `no-new-privileges`, scratch base in future) is defence in depth.

## 🚀 How we deliver that model — changes vs upstream `main`

| Layer | Change |
|---|---|
| Code execution | **ACA Dynamic Sessions removed** — replaced by per-session Hyperlight Sandbox. No external Azure dependency, no per-call cold start, full session-lifetime state |
| Host (Rust + Python SDK) | **Scoped credentials**: host owns the secret, guest holds an opaque name (`credential="azure_mgmt"`) |
| Guest HTTP | `http_get`/`http_post` gained a `credential=` kwarg; host injects the `Authorization` header at WASI-HTTP dispatch time |
| Framework | Agent frontmatter declares `credentials:` block → `Sandbox.register_credential(resolver=...)` plumbing wires it up |
| Framework | `view` / `head` / `tail` / `grep` / `jq` file tools now run **inside the sandbox** against `/input` & `/output` — the same directories `execute_python` reads and writes, so the LLM and Python share data both ways (host filesystem never exposed) |
| Framework | First-class **custom tools** (`tools/*.py`) discovered + bootstrapped + dispatched entirely in the guest |
| Framework | New `azure_imds` credential provider with App Service MSI auto-detection + per-(`resource`, `client_id`, `mi_res_id`) caching |

## 🎁 What we gain by ditching ACA Dynamic Sessions

Replacing ACA Dynamic Sessions with a per-session Hyperlight Sandbox gives us *"VM isolation in-process"*, but the secondary wins are at least as valuable.

### 💰 Cost

ACA Dynamic Sessions bills per-call: vCPU-seconds + memory-GB-seconds against a separate Azure resource, plus a session-pool baseline. Hyperlight runs in the same container the Functions host already pays for — **marginal cost per `execute_python` call is zero**. 

### ⚡ Latency

Each ACA `execute_python` call had to traverse an HTTPS round-trip to a regional ACA endpoint **and** wait on container spin-up. Hyperlight VM creation is sub-millisecond and runs in-process — no network, no scheduler. Round-trip is now bounded by the guest's own execution time, not by service plumbing.

### 🌐 Ops surface

One less Azure resource per deployment: no separate session-pool to provision, no vnet peering / private endpoint, no extra RBAC role assignment, no quota or region-availability matrix, no MSI dance to authenticate against the dynamic-sessions API.

### 🔁 Session state

Because the per-session Hyperlight VM lives for the whole chat session, **everything inside the guest is shared across every tool call**:

- **Python globals persist** — define `df = pd.read_csv(...)` in one `execute_python` call, reference `df` in the next. (ACA could never do it because every call was a fresh container.)
- **`/output` is one directory for the whole session** — a custom tool writes `report.json`, the next `execute_python` reads it, the next call streams it back to the user.
- **`/input` is a real host directory** — bind-mount once at container start; every tool in every turn sees the same files (read-only).
- **Custom tool definitions bootstrapped once per session** — discovery + bootstrap happens at session start, then every dispatch reuses the same guest namespace.

ACA provided isolation but lost every byte of state between calls. Hyperlight gives us *both* — VM-based isolation **and** intra-session continuity.

## ✂️ What we removed

- **ACA Dynamic Sessions code-execution backend** — removed replaced by an in-process Hyperlight Wasm VM per session.
- **`register_tool("imds_token"|"azure_get"|"azure_post"|…)` host-function shims** — no longer needed; credential machinery replaces them.
- **Host filesystem access from guest** — `read_file`/`write_file` on the host are gone; everything goes via `/input` (ro) and `/output` (rw) mounts.
- **Local / stdio MCP servers** — `reject_local_stdio_mcp` enforces remote-only (audience-locked). This could be added back if they ran remotely and we proxied to them (e.g. in ACA)
- **Static-string credentials in the SDK prototype** — `resolver` is required and is a `Callable[[], str]`; static tokens must wrap themselves in a closure.
- **Header smuggling** — host evicts any guest-set header that collides with the credential's header name (case-insensitive).
- **Resolver-error leakage** — failed resolvers surface a fixed `"credential resolver failed"`; diagnostic strings are dropped, not logged.

## 📋 What's left to tighten
Additional changes to consider:

1. **Swap the GitHub Copilot CLI subprocess → MAF (Microsoft Agent Framework)** — speaks to Foundry directly over REST + SSE. Removes the subprocess, the Copilot CLI binary, the npm tooling, and Node from the image. 
2. **Collapse the host into one binary; retire the polyglot worker model.** Because no developer code runs in the host, we don't need a Python worker, .NET worker, Node worker — only an orchestrator. hyperlight-sandbox exposes a Rust/dotnet/python API  and accepts any supported guest backend (Python/JavaScript today; other wasm based as we componentize them, or unikraft based when we add that backend to `hyperlight-sandbox`). **One host, many tool languages.** Result: ~60–120 MB image on `FROM scratch` (Rust binary), fast ms cold start.
3. **Audience pattern-match in the credential resolver** — currently we URL-prefix-match the target; need `urlparse(url).hostname` against a glob (`*.graph.microsoft.com`).
4. **Build-time allow-lists** for connectors + MCP servers ; frontmatter is *intersected*, not *unioned*.
5. **Seccomp profile** for the KVM-using process (curated from a `strace` of a Hyperlight VM lifecycle).

## 🛠️ Quick build & use

**Prereqs (host):**

- `podman` (Windows: rootless WSL or `podman machine` with `/dev/kvm`)
- `just`, `wasm-tools`, `componentize-py`, `hyperlight-wasm-aot` on `PATH`
- A sibling checkout of `simongdavies/hyperlight-sandbox` (commit pinned in `pyproject.toml`) at `../hyperlight-sandbox` (override with `just hyperlight=<path> …` or `$env:HYPERLIGHT_REPO`)
- `$env:GITHUB_TOKEN` set to a GitHub PAT with **Copilot** scope

Everything else is driven by the repo's `Justfile`:

```powershell
just bootstrap        # one-shot: build python guest + dev container
just run-dev          # podman run, hardened, ephemeral, port 7071
```

For day-to-day iteration:

```powershell
just guest-build      # rebuild guest AOT (slow; only when guest source changes)
just build-dev        # rebuild dev container only (assumes guest already built)
just build-prod       # build the prod container image
just clean            # wipe AOT + intermediate wasm + both images
just                  # list all recipes
```

Open <http://localhost:7071/>, ask "Use word_count on 'Mr. Mister sailed on a wing and a prayer.'" → returns `{"words": 9, ...}`.

### Use scoped credentials in your own agent

In `your-agent.agent.md` — pick **one** of the two `source:` types (any other value is a parse-time error):

```yaml
---
execution_sandbox:
  allowed_domains: "management.azure.com,GET"
  credentials:
    - id: azure_mgmt
      # Production: platform-supplied managed identity.
      source: azure_imds
      resource: https://management.azure.com/.default
      target: management.azure.com
      # Local dev alternative — value of a host env var whose name
      # starts with the framework-baked ``AGENT_`` prefix:
      #   source: env:AGENT_AZURE_TOKEN
      # header: Authorization     # default
      # prefix: "Bearer "          # default
---
```

Then, when the LLM calls the built-in `execute_python` tool (the one that runs Python *inside* the sandbox), it asks for the credential by name — never by value:

```python
resp = http_get(
    "https://management.azure.com/subscriptions?api-version=2022-12-01",
    credential="azure_mgmt",
)
```

The host resolves `azure_mgmt`, scope-checks the URL against the credential's `target`, and injects the `Authorization` header at WASI-HTTP dispatch time. The token never crosses the Wasm boundary.

### See it work in `basic-chat`

```powershell
# Get a local ARM token (one-off; expires in ~1 hour).
$env:AGENT_AZURE_TOKEN = (az account get-access-token --resource https://management.azure.com/ --query accessToken -o tsv)

just run-dev
```

In the chat UI ask **"list my Azure subscriptions"**. The LLM calls the `list_azure_subscriptions` custom tool (see [samples/basic-chat/src/tools/list_azure_subscriptions.py](samples/basic-chat/src/tools/list_azure_subscriptions.py)), which runs *inside* the guest and calls `http_get(..., credential="azure_mgmt")`. The bearer token lives on the host the whole time. 