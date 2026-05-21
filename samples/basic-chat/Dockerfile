# syntax=docker/dockerfile:1.7
# ---------------------------------------------------------------------------
# basic-chat sample — Azure Functions + Hyperlight Wasm sandbox
#
# Multi-stage image with two final targets:
#
#   --target=dev   (default)   — local dev rig: includes Azurite (storage
#                                 emulator) and ships a baked-in
#                                 ``local.settings.json``.  Listens on
#                                 port 7071 (Azure Functions Core Tools
#                                 local-dev convention).
#
#   --target=prod              — Azure Functions custom-container image.
#                                 NO Azurite, NO local.settings.json —
#                                 operator supplies ``AzureWebJobsStorage``
#                                 etc. via App Settings on the
#                                 Function App.  Listens on
#                                 ``$WEBSITES_PORT`` (defaults to 8080,
#                                 which App Service / Functions Premium
#                                 auto-detects without an extra app
#                                 setting; 8080 is also non-privileged so
#                                 the non-root ``app`` user can bind it
#                                 without ``CAP_NET_BIND_SERVICE``).
#
# Pre-reqs on the HOST:
#   - Podman (or Docker)
#   - /dev/kvm available (WSL2 with KVM, or bare-metal Linux)
#   - A sibling checkout of simongdavies/hyperlight-sandbox at the commit
#     pinned in pyproject.toml, with ``just wasm build`` already run so
#     that ``src/wasm_sandbox/guests/python/python-sandbox.aot`` exists.
#     (See "Why is the build-context needed?" below for the reason.)
#
# Build (from repo root) — dev (default target):
#   podman build \
#     --build-context hyperlight=<path-to-hyperlight-sandbox-checkout> \
#     -t basic-chat:dev \
#     -f samples/basic-chat/Dockerfile .
#
# Build (from repo root) — prod:
#   podman build \
#     --target=prod \
#     --build-context hyperlight=<path-to-hyperlight-sandbox-checkout> \
#     -t basic-chat:prod \
#     -f samples/basic-chat/Dockerfile .
#
# Run dev (ephemeral — /sandbox/in and /sandbox/out wiped on container exit):
#   podman run --rm -it \
#     --device /dev/kvm \
#     --cap-drop=ALL \
#     --security-opt=no-new-privileges \
#     --ulimit nofile=4096:4096 \
#     --read-only \
#     --tmpfs /tmp:rw,size=1g,mode=1777 \
#     --tmpfs /sandbox/in:rw,size=64m,mode=1777 \
#     --tmpfs /sandbox/out:rw,size=128m,mode=1777 \
#     -p 7071:7071 \
#     -e GITHUB_TOKEN=<your-token> \
#     basic-chat:dev
#
# Run dev (persistent — /sandbox/in and /sandbox/out survive between runs):
#   podman run --rm -it \
#     --device /dev/kvm \
#     --cap-drop=ALL \
#     --security-opt=no-new-privileges \
#     --ulimit nofile=4096:4096 \
#     --read-only \
#     --tmpfs /tmp:rw,size=1g,mode=1777 \
#     -v $HOME/sandbox-in:/sandbox/in \
#     -v $HOME/sandbox-out:/sandbox/out \
#     -p 7071:7071 \
#     -e GITHUB_TOKEN=<your-token> \
#     basic-chat:dev
#
# Then open http://localhost:7071 in your browser.
#
# Container hardening — every flag above works unconditionally in rootless
# podman:
#   --cap-drop=ALL                drop every Linux capability.  The KVM
#                                 ioctls hyperlight uses (KVM_CREATE_VM/
#                                 _VCPU, KVM_RUN, ...) do not require any
#                                 cap once /dev/kvm is accessible via the
#                                 device cgroup.
#   --security-opt=no-new-privileges
#                                 prctl(PR_SET_NO_NEW_PRIVS); blocks setuid
#                                 / capability escalation inside the
#                                 container.
#   --ulimit nofile=4096:4096     RLIMIT_NOFILE bumped from the 1024-soft
#                                 default so func + azurite + python
#                                 workers don't run out of fds under load.
#   --read-only                   rootfs immutable; any stray write fails
#                                 fast with EROFS instead of silently
#                                 mutating the container.  The tmpfs
#                                 mounts below cover the known writers.
#   --tmpfs /tmp:rw,size=1g,mode=1777
#                                 azurite data dir, func HTTP body
#                                 buffering, python tempfile defaults,
#                                 AND the Functions extension bundle
#                                 download on cold start (~100 MB zip +
#                                 ~300 MB extracted), which is why this
#                                 sizing is well above the 256 MB you'd
#                                 normally pick for a /tmp tmpfs.  Pre-
#                                 baking the bundle into the image would
#                                 remove this dependency — left as a
#                                 future optimisation.
#   --tmpfs /sandbox/in           ephemeral hyperlight input (see the
#   --tmpfs /sandbox/out          persistence variant above for keeping
#                                 these across container restarts).
#                                 ``mode=1777`` (sticky world-writable,
#                                 like /tmp) is used because podman's
#                                 ``--tmpfs`` flag rejects ``uid=``/
#                                 ``gid=`` options that Docker accepts.
#                                 Sticky-bit world-writable is safe here
#                                 — only the non-root ``app`` user runs
#                                 inside the container, so there is no
#                                 cross-user write surface to abuse.
# PYTHONPYCACHEPREFIX=/tmp/pycache is baked into the image (see the ENV
# line further down) so that every CPython ``__pycache__`` write — from
# the Functions worker, the SDK, site-packages, and the function app —
# is funnelled into the /tmp tmpfs instead of trying to mutate the
# read-only rootfs.  Cold starts keep their bytecode cache; we don't
# need a fleet of per-directory tmpfs overlays.
#
# Deliberately NOT included: --memory, --cpus, --pids-limit.  Those are
# cgroup-controller-gated and silently no-op in rootless podman unless
# cgroup-v2 controllers have been delegated to the user — a false sense
# of safety we don't want to bake into a sample.
#
# Why is the build-context needed?
#   The ``hyperlight-sandbox-python-guest`` wheel built from the
#   ``simongdavies/hyperlight-sandbox`` fork ships a ``python_guest``
#   package that *expects* ``python-sandbox.aot`` (~42 MB) at
#   ``python_guest/resources/python-sandbox.aot`` — but the wheel
#   source tree has an *empty* ``resources/`` directory.  The AOT is
#   normally copied in by the ``just python python-sync-guest-resources``
#   recipe *before* the wheel is built.  Pip installing via a git URL
#   bypasses ``just`` entirely, so the resulting wheel has no AOT and
#   ``python_guest.path.MODULE_PATH = get_module_path()`` raises
#   ``FileNotFoundError`` at import time the first time the agent uses
#   ``execute_python``.  We work around that by mounting the sibling
#   ``hyperlight-sandbox`` checkout as a build context (``hyperlight=``)
#   and copying the pre-built AOT into the installed package after
#   ``pip install``.  Long-term fix is a build-hook in the upstream
#   wheel's ``pyproject.toml``; this is the surgical workaround until
#   that lands.
# ---------------------------------------------------------------------------

# Bookworm = glibc 2.36, required by hyperlight-sandbox-backend-wasm
# (manylinux_2_34 wheels need glibc >= 2.34).  ``slim`` drops ~600 MB of
# dev tooling we don't need at runtime.
ARG PYTHON_BASE=python:3.11-slim-bookworm
# Non-root runtime UID/GID.  10001 is the App Service ``mcrappuser``
# convention; we pin it here so the user record inside the image lines
# up with what App Service / Functions Premium expects.
ARG APP_UID=10001
ARG APP_GID=10001


# =============================================================================
# Stage 1 — builder: compiles the SDK + hyperlight wheels.
# =============================================================================
# Carries the build-only dependencies (clang/lld + build-essential for
# cc-rs, git for pip's ``git+https://...`` deps).  Maturin auto-installs
# the Rust toolchain into ``/root/.cache/puccinialin`` at build time — no
# explicit Rust install needed.  The toolchain stays in the builder image
# and is discarded; the final stages only inherit ``site-packages``.
FROM ${PYTHON_BASE} AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        clang \
        git \
        lld \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml /tmp/sdk/pyproject.toml
COPY src/ /tmp/sdk/src/

RUN pip install /tmp/sdk && rm -rf /tmp/sdk

# Inject the missing AOT into python_guest (see "Why is the build-context
# needed?" in the header).  We resolve the install location with
# ``importlib.util.find_spec`` rather than ``import python_guest`` because
# the package's ``__init__.py`` re-exports
# ``MODULE_PATH = get_module_path()`` at import time, which itself reads
# the AOT we are trying to install.  ``find_spec`` only locates the module
# without executing it.
COPY --from=hyperlight src/wasm_sandbox/guests/python/python-sandbox.aot \
    /tmp/python-sandbox.aot
RUN PYTHON_GUEST_DIR=$(python -c "import importlib.util, pathlib; spec = importlib.util.find_spec('python_guest'); print(pathlib.Path(spec.origin).parent)") && \
    install -m 0644 -D /tmp/python-sandbox.aot "$PYTHON_GUEST_DIR/resources/python-sandbox.aot" && \
    rm /tmp/python-sandbox.aot && \
    python -c "from python_guest.path import get_module_path; print('AOT materialised at:', get_module_path())"


# =============================================================================
# Stage 2 — runtime-base: shared runtime layer for dev and prod.
# =============================================================================
# Installs Azure Functions Core Tools v4 (which pulls the .NET runtime
# deps) + ca-certificates.  Copies the prebuilt python ``site-packages``
# tree from the builder.  Creates the non-root ``app`` user, the Hyperlight
# sandbox mount points, and bakes in the function-app source.
FROM ${PYTHON_BASE} AS runtime-base
ARG APP_UID
ARG APP_GID

# ``HOME=/tmp`` redirects the writes that Functions Core Tools and the
# Python worker do on first launch (``~/.azurefunctions``, ``~/.cache``,
# etc.) onto the tmpfs, so the rest of the rootfs can stay read-only.
#
# ``PYTHON_ENABLE_INIT_INDEXING=1`` is required by the Python worker
# whenever the function app uses HTTP streaming (which this sample does
# via the agent chat endpoints).  Without it the worker raises
# ``AppSettingDisabledError`` during indexing and the host never starts.
# Setting it as an image-level ``ENV`` means both dev and prod get it
# without depending on operator config.  (The non-container ``func
# start`` workflow gets it from ``src/local.settings.template.json``
# instead; the dev container's ``docker/local.settings.json`` does
# *not* duplicate the key, to avoid the noisy
# ``Skipping 'PYTHON_ENABLE_INIT_INDEXING' from local settings`` log
# line that ``func`` emits whenever a local-settings key already lives
# in the process environment.)
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPYCACHEPREFIX=/tmp/pycache \
    HOME=/tmp \
    PYTHON_ENABLE_INIT_INDEXING=1

# curl + gnupg are needed only to add the Microsoft apt repo signing key;
# we purge them once Functions Core Tools is installed.
#
# ``libicu72`` is a hard runtime dependency of the .NET-based Functions
# Core Tools binary (without it the host fails on first launch with
# "Couldn't find a valid ICU package installed on the system").  The
# slim base image does not ship libicu, so we install it explicitly.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gnupg \
        libicu72 \
    && install -m 0755 -d /usr/share/keyrings \
    && curl -fsSL https://packages.microsoft.com/keys/microsoft.asc \
        | gpg --dearmor -o /usr/share/keyrings/microsoft.gpg \
    && chmod 0644 /usr/share/keyrings/microsoft.gpg \
    && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft.gpg] https://packages.microsoft.com/debian/12/prod bookworm main" \
        > /etc/apt/sources.list.d/azure-functions.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        azure-functions-core-tools-4 \
    && apt-get purge -y --auto-remove curl gnupg \
    && rm -rf /var/lib/apt/lists/*

# Bring over the python deps + any console-script wrappers from the
# builder stage.  /usr/local/lib/python3.11 covers ``site-packages`` and
# any other lib-dir bits maturin writes during install.
COPY --from=builder /usr/local/lib/python3.11 /usr/local/lib/python3.11
COPY --from=builder /usr/local/bin /usr/local/bin

# Hyperlight sandbox mount points.  The Wasm guest always exposes /input
# (read-only) and /output (read-write) at fixed paths; we map those to
# /sandbox/in and /sandbox/out inside the container.  Operators can bind-
# mount real host directories there with ``-v <host>:/sandbox/in`` and
# ``-v <host>:/sandbox/out``.  When nothing is mounted these placeholders
# keep the Sandbox constructor happy.
#
# /sandbox/in/tmp is the well-known sub-directory where the Copilot CLI
# parks large tool outputs (``client_manager.py`` overrides TMPDIR for the
# subprocess).  The same files are visible to the Hyperlight guest at
# /input/tmp/<file>.
RUN mkdir -p /sandbox/in/tmp /sandbox/out && \
    chmod 0777 /sandbox/in /sandbox/in/tmp /sandbox/out

# Non-root runtime user.  ``/dev/kvm`` itself is granted via the device
# cgroup at ``podman run`` time, not via group membership, so no extra
# wiring needed here.
RUN groupadd --system --gid ${APP_GID} app && \
    useradd --system --uid ${APP_UID} --gid ${APP_GID} \
        --no-create-home --home-dir /home/site \
        --shell /usr/sbin/nologin app && \
    mkdir -p /home/site/wwwroot && \
    chown -R ${APP_UID}:${APP_GID} /home/site /sandbox

COPY --chown=${APP_UID}:${APP_GID} samples/basic-chat/src/ /home/site/wwwroot/

WORKDIR /home/site/wwwroot
USER ${APP_UID}:${APP_GID}


# =============================================================================
# Stage 3 — prod: Azure Functions custom-container image.
# =============================================================================
# No Azurite, no local.settings.json.  Operator supplies storage account,
# ``GITHUB_TOKEN`` (or BYOK env vars), and any other settings via App
# Settings on the Function App.  Push to ACR and deploy with
# ``az functionapp create --image <registry>/<image>:<tag>``.
FROM runtime-base AS prod
ARG APP_UID
ARG APP_GID

USER root
COPY samples/basic-chat/docker/entrypoint.prod.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh
USER ${APP_UID}:${APP_GID}

# Port 8080 is unprivileged (>=1024) so the non-root ``app`` user can
# bind it without ``CAP_NET_BIND_SERVICE``.  App Service / Functions
# Premium auto-detects both 80 and 8080 when no ``WEBSITES_PORT`` app
# setting is configured — no extra config needed on the platform side.
EXPOSE 8080
CMD ["/usr/local/bin/entrypoint.sh"]


# =============================================================================
# Stage 4 — dev (default target): local dev rig.
# =============================================================================
# Adds Node.js + Azurite (storage emulator) and bakes in a
# ``local.settings.json`` pointing at the emulator.  Listens on 7071.
FROM runtime-base AS dev
ARG APP_UID
ARG APP_GID

USER root
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gnupg \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && npm install --omit=dev -g azurite \
    && apt-get purge -y --auto-remove curl gnupg \
    && rm -rf /var/lib/apt/lists/* /root/.npm

COPY --chown=${APP_UID}:${APP_GID} \
    samples/basic-chat/docker/local.settings.json \
    /home/site/wwwroot/local.settings.json
COPY samples/basic-chat/docker/entrypoint.dev.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh

USER ${APP_UID}:${APP_GID}

EXPOSE 7071
CMD ["/usr/local/bin/entrypoint.sh"]
