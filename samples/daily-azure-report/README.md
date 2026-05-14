# Daily Azure Report

A multi-agent Azure Functions app that monitors your Azure subscription. Includes a timer-triggered agent that emails a daily resource change report and an HTTP-triggered agent that returns a structured resource summary as JSON.

| Trigger | Custom Tools | Connectors | MCP Servers | Skills | Sandbox | Chat UI |
|---|---|---|---|---|---|---|
| Timer + HTTP | | ✅ Office 365 | ✅ MS Learn | ✅ azure-resources | ✅ execute_python + azure_mgmt | ✅ |

## Features

- **Timer trigger** — `daily_azure_report_agent` runs daily at 15:00 UTC, emails a report of resources created or changed in the last 24 hours
- **HTTP trigger** — `resource_summary_agent` at `POST /resource-summary` returns a structured JSON summary of all resources by type and location
- **Sandboxed ARM access via `execute_python`** — the agent runs Python in a Hyperlight Wasm sandbox and calls ARM through `http_get(url, credential="azure_mgmt")`. The host fetches the managed-identity token from IMDS and injects the `Authorization` header on outbound requests; the literal token never crosses into the guest as guest-runnable bytes.
- **Office 365 connector** — sends the report via email
- **Microsoft Learn MCP server** — gives the agent access to Azure documentation for looking up correct API paths and versions
- **`azure-resources` skill** — packages ARM REST API knowledge (paths, api-versions, tips) so the agent instructions can focus on the job, not the technical details
- **Interactive chat UI** — `main.agent.md` enables the built-in chat interface for ad-hoc Azure queries
- **Variable substitution** — subscription ID and recipient email configured via environment variables, resolved at load time in the agent instructions

## Prerequisites

- [Azure Developer CLI (`azd`)](https://learn.microsoft.com/azure/developer/azure-developer-cli/install-azd)
- [Azure Functions Core Tools](https://learn.microsoft.com/azure/azure-functions/functions-run-local)
- A [GitHub Personal Access Token](../../README.md#github-token) with **Copilot** scope
- An Azure subscription

## Deploy

1. **Set environment variables:**

   ```bash
   cd samples/daily-azure-report
   azd init
   azd env set GITHUB_TOKEN <your-github-pat>
   azd env set TO_EMAIL <recipient@example.com>
   ```

   Optional:

   ```bash
   azd env set COPILOT_MODEL claude-opus-4.6     # default
   ```

2. **Deploy to Azure:**

   ```bash
   azd up
   ```

   This provisions all resources (Function App, storage, Office 365 API connection) and deploys the code. The subscription ID is automatically detected from the deployment. The managed identity is granted Reader access on the subscription for querying resources.

3. **Authenticate the Office 365 connector:**

   After deployment, the Office 365 connection is created but **not yet authenticated**. You need to authorize it manually:

   - Go to the [Azure portal](https://portal.azure.com)
   - Navigate to the resource group created by `azd` (named `rg-<environment-name>`)
   - Find the **API Connection** resource (`office365-...`)
   - Click **Edit API connection** in the left menu
   - Click **Authorize**, sign in with your Microsoft account, then click **Save**

   The sandboxed `execute_python` tool uses the function app's managed identity (via the `azure_mgmt` scoped credential) — no manual authentication needed.

4. **Verify:**

   The timer fires daily at 15:00 UTC. To test immediately, trigger the function with curl:

   ```bash
   # Get the master key
   az functionapp keys list -g <resource-group> -n <function-app-name> --query "masterKey" -o tsv

   # Trigger the function
   curl -X POST "https://<function-app-name>.azurewebsites.net/admin/functions/daily_azure_report_agent" \
     -H "x-functions-key: <master-key>" \
     -H "Content-Type: application/json" \
     -d '{}'
   ```

## Run Locally

Follow the [shared local development guide](../README.md#run-locally) in the samples directory. This sample requires Azure credentials and email configuration.

### Local settings

Required:

- `GITHUB_TOKEN` (see shared guide)
- `SUBSCRIPTION_ID`: Azure subscription ID (for querying resources)
- `TO_EMAIL`: recipient email address
- `O365_CONNECTION_ID`: Office 365 connector ID

Optional:

- `ACA_SESSION_POOL_ENDPOINT`: if set, enables code execution features; if empty, agents work but lose advanced capabilities

Without `SUBSCRIPTION_ID`:

- The agents have no subscription to query and both fail
- The `azure_mgmt` credential still resolves (it only depends on IMDS), but calls have nowhere to point

Without `O365_CONNECTION_ID`:

- The timer agent cannot send the daily report email

### Testing locally

**Trigger the daily report manually:**

**Bash:**

```bash
curl -X POST http://localhost:7071/admin/functions/daily_azure_report_agent \
  -H "Content-Type: application/json" \
  -d '{}'
```

**PowerShell:**

```powershell
Invoke-WebRequest -Uri "http://localhost:7071/admin/functions/daily_azure_report_agent" `
  -Method POST `
  -ContentType "application/json" `
  -Body '{}'
```

**Query resources via HTTP:**

**Bash:**

```bash
curl -X POST http://localhost:7071/resource-summary \
  -H "Content-Type: application/json" \
  -d '{}'
```

**PowerShell:**

```powershell
Invoke-WebRequest -Uri "http://localhost:7071/resource-summary" `
  -Method POST `
  -ContentType "application/json" `
  -Body '{}'
```

## How It Works

### Agents

- [`daily_azure_report.agent.md`](src/daily_azure_report.agent.md) — timer-triggered agent that lists resources changed in the last 24 hours and emails a report
- [`resource_summary.agent.md`](src/resource_summary.agent.md) — HTTP-triggered agent at `POST /resource-summary` that returns a structured JSON summary of resources by type and location
- [`main.agent.md`](src/main.agent.md) — interactive chat agent for ad-hoc Azure queries via the built-in UI

### Shared capabilities

- **`execution_sandbox` frontmatter** on each agent — declares `allowed_domains: "management.azure.com,..."` plus a `credentials:` entry binding `azure_mgmt -> azure_imds`. The framework resolves the IMDS token on the host and registers it with the Hyperlight Wasm sandbox so the guest can call ARM without ever seeing the literal bearer.
- [`mcp.json`](src/mcp.json) — Microsoft Learn MCP server for Azure documentation lookups
- [`skills/azure-resources/SKILL.md`](src/skills/azure-resources/SKILL.md) — ARM REST API knowledge (paths, api-versions, tips) phrased around `http_get(url, credential="azure_mgmt")`
- The `tools_from_connections` frontmatter references the Office 365 API Connection for sending email
- When the timer fires, the agent:
  1. Calls `execute_python` to fetch the subscription's resource list via `http_get(..., credential="azure_mgmt")` and filter it in-sandbox
  2. Receives the filtered JSON back in the conversation
  3. Formats a summary report as an HTML email
  4. Sends the report to the configured recipient via the Office 365 connector
- The HTTP agent at `/resource-summary` accepts a JSON body with `subscription_id` and returns a structured summary:

  ```json
  {"total_resources": 239, "by_type": {...}, "by_location": {...}}
  ```

- `$SUBSCRIPTION_ID` and `$TO_EMAIL` in the agent instructions are replaced with actual values at load time (via environment variable substitution)
- `SUBSCRIPTION_ID` is automatically set from the deployment subscription — no manual input needed
