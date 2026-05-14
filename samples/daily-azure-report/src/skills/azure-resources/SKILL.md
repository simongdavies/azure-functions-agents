---
name: azure-resources
description: Query and manage Azure resources by calling the ARM REST API from `execute_python` with the `azure_mgmt` scoped credential. Use when listing, filtering, or inspecting Azure resources, resource groups, deployments, or subscription details.
---

# Azure Resources

## How to call ARM

You make Azure Resource Manager (ARM) calls from inside `execute_python`. The Hyperlight Wasm guest exposes `http_get` and `http_post` built-ins (no `import` needed). Pass `credential="azure_mgmt"` to attach the managed-identity bearer token — the host injects the `Authorization` header for you, and the guest **never** sees the literal token value.

```python
import json
resp = http_get(
    "https://management.azure.com/subscriptions/{subscriptionId}/resources"
    "?api-version=2021-04-01",
    credential="azure_mgmt",
)
data = json.loads(resp["body"])
```

Notes:
- Both `http_get(url, credential=...)` and `http_post(url, body=..., content_type=..., credential=...)` accept the `credential` keyword.
- Returned `resp` is `{"status": int, "body": str}`. Parse the body with `json.loads`.
- Filter / shape the response with Python comprehensions before printing so the LLM sees only the fields it needs (the JMESPath dance is no longer required).
- If the call fails the guest will raise — surface the error rather than retrying with a hand-rolled header.

### Microsoft Learn MCP server
Use the Microsoft Learn tools (`microsoft_docs_search`, `microsoft_docs_fetch`) to look up correct ARM REST API paths, api-versions, query parameters, and response schemas when you're unsure.

## Common API paths

### List all resources in a subscription
```
GET /subscriptions/{subscriptionId}/resources?api-version=2021-04-01
```
Response includes `createdTime`, `changedTime`, `name`, `type`, `location`, `resourceGroup` for each resource.

### List resource groups
```
GET /subscriptions/{subscriptionId}/resourcegroups?api-version=2021-04-01
```

### List resources in a specific resource group
```
GET /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/resources?api-version=2021-04-01
```

### Get a specific resource by ID
```
GET /subscriptions/{subscriptionId}/resourceGroups/{rg}/providers/{namespace}/{type}/{name}?api-version={version}
```
Note: api-version varies by resource type. Use Microsoft Learn to look up the correct version.

### List deployments
```
GET /subscriptions/{subscriptionId}/resourcegroups/{resourceGroupName}/providers/Microsoft.Resources/deployments?api-version=2021-04-01
```

## Tips
- The `api-version` query parameter is **required** for all ARM calls. If unsure of the version, search Microsoft Learn.
- To filter recently changed resources, list all resources and filter client-side by `createdTime` and `changedTime` timestamps (ISO 8601 format).
- Large subscriptions may return paginated results with a `nextLink` property. Follow it to get additional pages.
- RBAC on the managed identity controls what the credential can access. Reader role allows listing and reading all resources; broader changes (POST/PUT/PATCH/DELETE) need a role that grants the corresponding write actions.
- Sandbox network access is deny-by-default. `management.azure.com` is allowlisted in the agent frontmatter; calls to other hosts will be rejected even when `azure_mgmt` is attached.
