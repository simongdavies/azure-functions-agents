#!/bin/bash
# ---------------------------------------------------------------------------
# Dev entrypoint for the basic-chat sample.
#
# Starts the Azurite Azure-Storage emulator in the background (writes its
# data files under /tmp/azurite — must be on a tmpfs when the rootfs is
# --read-only) and then hands off PID 1 to ``func start``.
#
# Port 7071 matches the Azure Functions Core Tools local-dev default so
# that the existing UI / docs / muscle memory keep working unchanged.
# ---------------------------------------------------------------------------
set -euo pipefail

azurite \
    --silent \
    --location /tmp/azurite \
    --blobHost 0.0.0.0 \
    --queueHost 0.0.0.0 \
    --tableHost 0.0.0.0 &

exec func start --port 7071
