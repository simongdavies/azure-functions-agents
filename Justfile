# Justfile — Azure Functions Agents
#
# Build the python guest, build & run the basic-chat sample container.
#
# Common workflows:
#
#   just                  # list available recipes
#   just bootstrap        # first-time setup: build guest + dev container
#   just build-dev        # rebuild dev container only (assumes guest built)
#   just run-dev          # run dev container (requires $GITHUB_TOKEN)
#   just guest-build      # rebuild python guest AOT (slow; only when
#                         # hyperlight-sandbox guest source changes)
#
# Override the hyperlight-sandbox checkout location:
#
#   just hyperlight=/path/to/hyperlight-sandbox build-dev
#   $env:HYPERLIGHT_REPO = "C:/repos/hyperlight-sandbox"; just build-dev

# ---------------------------------------------------------------------------
# Shell selection.
#
# Linux/macOS keep the default `sh -c`.  Windows uses PowerShell because
# every developer command in this repo was authored against pwsh, and
# pwsh handles forward-slash paths the same as bash for everything we
# invoke (podman, wasm-tools, componentize-py, hyperlight-wasm-aot).
# ---------------------------------------------------------------------------
set windows-shell := ["pwsh.exe", "-NoLogo", "-Command"]

# ---------------------------------------------------------------------------
# Configurable knobs.
# ---------------------------------------------------------------------------

# Sibling checkout of simongdavies/hyperlight-sandbox containing the python
# guest source tree.  Default: ../hyperlight-sandbox relative to this file.
hyperlight := env_var_or_default("HYPERLIGHT_REPO", justfile_directory() / ".." / "hyperlight-sandbox")

# Container image tags.
dev_image  := "basic-chat:dev"
prod_image := "basic-chat:prod"

# Convenience paths inside the hyperlight checkout.
guest_dir  := hyperlight / "src/wasm_sandbox/guests/python"
guest_aot  := guest_dir / "python-sandbox.aot"
guest_wasm := guest_dir / "python-sandbox.wasm"
wit_dir    := hyperlight / "src/wasm_sandbox/wit"

# ---------------------------------------------------------------------------
# Default recipe: list available recipes.
# ---------------------------------------------------------------------------

default:
    @just --list

# ---------------------------------------------------------------------------
# Python guest pipeline.
#
# Produces `python-sandbox.aot` inside the hyperlight-sandbox checkout.
# The basic-chat Dockerfile injects this artefact into the installed
# `python_guest` site-package via `--build-context hyperlight=...`.
# ---------------------------------------------------------------------------

# WIT -> sandbox-world.wasm (cheap; ~1s).
guest-wit:
    cd "{{wit_dir}}/.."; wasm-tools component wit wit/hyperlight-sandbox.wit -w -o wit/sandbox-world.wasm

# Componentize the Python guest into a wasm component (heavy; ~30-60s).
guest-wasm: guest-wit
    cd "{{guest_dir}}"; componentize-py -d ../../wit/hyperlight-sandbox.wit -w root componentize sandbox_executor -o python-sandbox.wasm

# Strip debug info to keep the AOT lean.
guest-strip: guest-wasm
    cd "{{guest_dir}}"; wasm-tools strip --all python-sandbox.wasm -o python-sandbox.wasm

# AOT-compile the component for Hyperlight (heavy; ~60-120s).
guest-aot: guest-strip
    cd "{{guest_dir}}"; hyperlight-wasm-aot compile --component python-sandbox.wasm python-sandbox.aot

# End-to-end guest build: WIT -> componentize -> strip -> AOT.
guest-build: guest-aot
    @echo "Guest built: {{guest_aot}}"

# ---------------------------------------------------------------------------
# Container images.
# ---------------------------------------------------------------------------

# Build the dev image (Functions Core Tools + Azurite + baked local.settings.json).
# Does NOT rebuild the guest -- run `just guest-build` first if needed.
build-dev:
    podman build --target=dev --build-context "hyperlight={{hyperlight}}" -t {{dev_image}} -f samples/basic-chat/Dockerfile .

# Build the prod image (no Azurite; operator supplies AzureWebJobsStorage).
# Does NOT rebuild the guest -- run `just guest-build` first if needed.
build-prod:
    podman build --target=prod --build-context "hyperlight={{hyperlight}}" -t {{prod_image}} -f samples/basic-chat/Dockerfile .

# One-shot first build from a fresh clone: guest + dev container.
bootstrap: guest-build build-dev
    @echo ""
    @echo "Bootstrap complete.  Next:"
    @echo "  set GITHUB_TOKEN, then run: just run-dev"

# ---------------------------------------------------------------------------
# Run.
# ---------------------------------------------------------------------------

# Run the dev image on http://127.0.0.1:7071/.  Requires GITHUB_TOKEN env var.
# Optional: $env:AGENT_AZURE_TOKEN enables the ``list_azure_subscriptions``
# tool / the ``azure_mgmt`` scoped credential.  Get one with:
#   az account get-access-token --resource https://management.azure.com/ --query accessToken -o tsv
# Ephemeral: /sandbox/in and /sandbox/out are wiped on container exit.
run-dev:
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
        -e GITHUB_TOKEN={{env_var("GITHUB_TOKEN")}} \
        -e AGENT_AZURE_TOKEN={{env_var_or_default("AGENT_AZURE_TOKEN", "")}} \
        {{dev_image}}

# ---------------------------------------------------------------------------
# Cleanup.
# ---------------------------------------------------------------------------

# Remove the guest wasm + AOT and both container images.
[unix]
clean:
    rm -f "{{guest_wasm}}" "{{guest_aot}}"
    -podman image rm {{dev_image}} {{prod_image}}

[windows]
clean:
    Remove-Item -Force -ErrorAction SilentlyContinue "{{guest_wasm}}"
    Remove-Item -Force -ErrorAction SilentlyContinue "{{guest_aot}}"
    -podman image rm {{dev_image}} {{prod_image}}
