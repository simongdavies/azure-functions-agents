---
name: Resource Summary
description: Returns a structured summary of Azure resources.

trigger:
  type: http_trigger
  route: resource-summary
  methods: ["POST"]
  auth_level: FUNCTION

execution_sandbox:
  allowed_domains: "management.azure.com,GET"
  credentials:
    - id: azure_mgmt
      source: azure_imds
      resource: https://management.azure.com/.default
      target: management.azure.com

response_example: |
  {
    "total_resources": 42,
    "by_type": {
      "Microsoft.Web/sites": 5,
      "Microsoft.Storage/storageAccounts": 3
    },
    "by_location": {
      "eastus2": 20,
      "westus": 10
    }
  }
---

Given the subscription ID in the request body, use `execute_python` to list every resource in that subscription via the ARM REST API and aggregate the results into the response shape shown above. Do the aggregation **inside the sandbox** so the raw resource list never reaches the model context.

Inside the sandbox, `http_get` injects the managed-identity bearer token when you pass `credential="azure_mgmt"` — do not build an Authorization header yourself:

```python
import json
from collections import Counter

resp = http_get(
    f"https://management.azure.com/subscriptions/{subscription_id}/resources"
    "?api-version=2021-04-01",
    credential="azure_mgmt",
)
if resp["status"] >= 400:
    print(json.dumps({"error": resp["status"], "body": resp["body"]}))
else:
    items = json.loads(resp["body"])["value"]
    by_type = Counter(r["type"] for r in items)
    by_location = Counter(r.get("location", "unknown") for r in items)
    print(json.dumps({
        "total_resources": len(items),
        "by_type": dict(by_type),
        "by_location": dict(by_location),
    }))
```
