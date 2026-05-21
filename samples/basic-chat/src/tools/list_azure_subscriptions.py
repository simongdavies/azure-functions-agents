# Custom tool: list the Azure subscriptions accessible with the
# ``azure_mgmt`` scoped credential declared in ``main.agent.md``.
#
# Demonstrates the end-to-end credential flow:
#   1. The LLM calls this tool by name.
#   2. The function runs inside the Hyperlight Wasm sandbox.
#   3. Inside the sandbox we call ``http_get(url, credential="azure_mgmt")``.
#   4. The host resolves the credential (env var ``AGENT_AZURE_TOKEN``),
#      scope-checks the URL against the credential's ``target``, and
#      injects the ``Authorization`` header at WASI-HTTP dispatch time.
#   5. The bearer token NEVER crosses the Wasm boundary.
#
# ``http_get`` and ``json`` are provided by the guest environment; the
# host parses this file with ``ast`` (no execution), so undefined names
# at parse time are not an issue.

import json


def list_azure_subscriptions() -> dict:
    """List the Azure subscriptions reachable with the ``azure_mgmt`` credential.

    Use this when the user asks "what Azure subscriptions do I have",
    "list my subscriptions", or similar.  Returns a JSON object with
    ``total`` (int) and ``subscriptions`` (list of
    ``{"id", "name", "state"}`` objects).  On an HTTP error, returns
    ``{"error": <status>, "details": <body excerpt>}`` instead --
    surface that to the user rather than retrying.

    The credential and the target host are pre-wired by the agent's
    frontmatter; this tool takes no arguments.
    """
    # ARM returns at most one page per response (server-decided page
    # size) and a ``nextLink`` URL when more pages exist.  We follow
    # the chain so:
    #   * each ``http_get`` response body stays bounded by ARM's page
    #     size -- avoiding the host->guest IPC buffer overflow that
    #     poisons the sandbox when the full list is requested in one
    #     shot;
    #   * the per-item projection below shrinks each page from full
    #     subscription objects (hundreds of fields) down to three
    #     fields before we hand the result back across the boundary
    #     to the host, so the final return payload is bounded by item
    #     count, not by ARM verbosity.
    #
    # ``nextLink`` is fully-qualified (same ``management.azure.com``
    # host) so it passes the credential's target scope-check on each
    # iteration.
    subs = []
    url = "https://management.azure.com/subscriptions?api-version=2022-12-01"
    while url:
        resp = http_get(url, credential="azure_mgmt")  # noqa: F821 - guest builtin
        if resp["status"] >= 400:
            # Keep the body excerpt small so a verbose ARM error page
            # does not blow the model context.
            return {"error": resp["status"], "details": resp["body"][:500]}

        payload = json.loads(resp["body"])
        for item in payload.get("value", []):
            subs.append(
                {
                    "id": item.get("subscriptionId", ""),
                    "name": item.get("displayName", ""),
                    "state": item.get("state", ""),
                }
            )
        # ARM omits ``nextLink`` on the last page; falsy => loop ends.
        url = payload.get("nextLink")

    return {"total": len(subs), "subscriptions": subs}
