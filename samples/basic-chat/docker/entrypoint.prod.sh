#!/bin/bash
# ---------------------------------------------------------------------------
# Prod entrypoint for the basic-chat sample.
#
# No Azurite — operator MUST supply ``AzureWebJobsStorage`` as a real
# connection string (or managed-identity flavour) via App Settings on
# the Function App.
#
# Listens on ``$WEBSITES_PORT`` (App Service / Functions Premium custom-
# container convention; defaults to 8080 when unset).
#
# Why 8080 and not 80?  Two reasons:
#   1. 8080 is non-privileged (>=1024), so the non-root ``app`` user can
#      bind it without ``CAP_NET_BIND_SERVICE`` — important because the
#      hardening flags in the Dockerfile docstring drop every cap.
#   2. App Service / Functions Premium auto-detects BOTH port 80 and
#      port 8080 when no ``WEBSITES_PORT`` app setting is configured, so
#      operators don't need an extra setting just to use 8080.
#
# No background processes — the Functions host owns PID 1.
# ---------------------------------------------------------------------------
set -euo pipefail

exec func start --port "${WEBSITES_PORT:-8080}"
