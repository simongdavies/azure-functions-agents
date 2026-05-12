# ---------------------------------------------------------------------------
# basic-chat sample — Azure Functions + Hyperlight Wasm sandbox
#
# Pre-reqs on the HOST:
#   - Podman (or Docker)
#   - /dev/kvm available (WSL2 with KVM, or bare-metal Linux)
#
# Build (from repo root):
#   podman build -t basic-chat -f samples/basic-chat/Dockerfile .
#
# Run:
#   podman run --rm -it \
#     --device /dev/kvm \
#     -p 7071:7071 \
#     -e GITHUB_TOKEN=<your-token> \
#     basic-chat
#
# Then open http://localhost:7071 in your browser.
# ---------------------------------------------------------------------------

# Bookworm = glibc 2.36, required by hyperlight-sandbox-backend-wasm
# (manylinux_2_34 wheels need glibc >= 2.34)
FROM python:3.11-bookworm

# --- Install Node.js (for Azurite) + Azure Functions Core Tools v4 ---------
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        gnupg \
        apt-transport-https \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && curl -sL https://packages.microsoft.com/keys/microsoft.asc | \
        gpg --dearmor > /etc/apt/trusted.gpg.d/microsoft.gpg && \
    echo "deb [arch=amd64] https://packages.microsoft.com/debian/12/prod bookworm main" > \
        /etc/apt/sources.list.d/azure-functions.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        azure-functions-core-tools-4 \
    && rm -rf /var/lib/apt/lists/*

# --- Install Azurite (Azure Storage emulator) ------------------------------
RUN npm install -g azurite

# --- Install the SDK from local source ------------------------------------
COPY pyproject.toml /tmp/sdk/pyproject.toml
COPY src/ /tmp/sdk/src/

RUN pip install --no-cache-dir /tmp/sdk && \
    rm -rf /tmp/sdk

# --- Copy sample function app ---------------------------------------------
COPY samples/basic-chat/src/ /home/site/wwwroot/

# Azure Functions local settings for container
RUN echo '{ \
  "IsEncrypted": false, \
  "Values": { \
    "FUNCTIONS_WORKER_RUNTIME": "python", \
    "AzureWebJobsStorage": "UseDevelopmentStorage=true", \
    "PYTHON_ENABLE_INIT_INDEXING": "1" \
  } \
}' > /home/site/wwwroot/local.settings.json

# Entrypoint: start Azurite in background, then func
RUN echo '#!/bin/bash\n\
set -e\n\
azurite --silent --location /tmp/azurite --blobHost 0.0.0.0 --queueHost 0.0.0.0 --tableHost 0.0.0.0 &\n\
exec func start --port 7071\n' > /usr/local/bin/entrypoint.sh && \
    chmod +x /usr/local/bin/entrypoint.sh

WORKDIR /home/site/wwwroot

EXPOSE 7071

# GITHUB_TOKEN passed at runtime via -e flag
CMD ["/usr/local/bin/entrypoint.sh"]
