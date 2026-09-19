# Cloud Mail MCP

Remote MCP server for connecting the existing Cloud Mail deployment to ChatGPT and other MCP clients.

## Architecture

```
ChatGPT / MCP client
        |
        | OAuth 2.1 + GitHub login
        v
cloud-mail-mcp
        |
        | Cloudflare Service Binding
        | X-MCP-Internal-Secret
        v
cloud-mail
        |
        +-- D1
        +-- KV
        +-- Cloudflare Email / Resend
```

The MCP worker is intentionally separate from the main web/mail worker. It does not query D1 directly. It calls a small protected adapter in `mail-worker/src/api/mcp-internal-api.js`, which reuses the existing Cloud Mail services and permissions.

## Tools

- `get_profile` — show the connected Cloud Mail identity
- `list_accounts` — list sender/receiver addresses
- `list_emails` — list recent received or sent messages
- `get_email` — read one full message
- `search_emails` — search the current user's messages
- `send_email` — send a new message
- `reply_email` — reply to an existing message

There are deliberately no delete, password, admin, role, or settings tools in v1.

## Security model

This first version is a personal/single-user MCP:

1. The MCP OAuth flow authenticates with GitHub.
2. `ALLOWED_GITHUB_LOGIN` is an allowlist (comma separated).
3. Successful OAuth grants are mapped to the Cloud Mail admin account.
4. The MCP worker talks to `cloud-mail` through a Service Binding.
5. The internal adapter also requires `MCP_INTERNAL_SECRET`.
6. All mail queries force the Cloud Mail admin user's `userId`; the client cannot submit an arbitrary user ID.
7. Write tools are marked as non-read-only and non-idempotent.

## GitHub repository settings

Before running **Deploy Cloud Mail MCP**, add these Actions secrets:

- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ACCOUNT_ID`
- `GH_OAUTH_CLIENT_ID`
- `GH_OAUTH_CLIENT_SECRET`
- `COOKIE_ENCRYPTION_KEY` — random high-entropy string, e.g. 32+ random bytes
- `MCP_INTERNAL_SECRET` — a different random high-entropy string

Optional Actions variables/secrets:

- `ALLOWED_GITHUB_LOGIN` — defaults to `Rst307`
- `MCP_WORKER_NAME` — defaults to `cloud-mail-mcp`
- `MAIL_WORKER_NAME` — defaults to `cloud-mail`
- `MCP_CUSTOM_DOMAIN` — e.g. `mcp.rst307.cn`
- `OAUTH_KV_ID` — if omitted, the workflow creates/finds `cloud-mail-mcp-oauth`

The Cloudflare API token needs permissions to deploy Workers, manage Worker secrets, create/read Workers KV namespaces, and configure a custom domain if `MCP_CUSTOM_DOMAIN` is used.

## GitHub OAuth App

Create a GitHub OAuth App for the MCP deployment.

If using the custom domain:

- Homepage URL: `https://mcp.rst307.cn`
- Authorization callback URL: `https://mcp.rst307.cn/callback`

If you initially use the workers.dev URL, use that hostname instead. The callback host must match the URL used to start the MCP OAuth flow.

Put the OAuth App client ID and secret into the GitHub Actions secrets listed above.

## Deploy

Merge the feature into `main`, then run:

**Actions → Deploy Cloud Mail MCP → Run workflow**

The deployment workflow:

1. installs and type-checks the MCP worker;
2. creates/resolves the OAuth KV namespace;
3. deploys `cloud-mail-mcp`;
4. configures OAuth/MCP secrets;
5. configures the same internal secret on the existing `cloud-mail` worker.

Because the feature also changes `mail-worker/**`, the existing Cloud Mail deployment workflow will redeploy the main worker after merge.

## Test

Use MCP Inspector first:

```bash
npx @modelcontextprotocol/inspector@latest
```

Connect to:

```
https://<your-mcp-host>/mcp
```

Complete the GitHub OAuth flow, then call `get_profile`, `list_accounts`, and `list_emails`.

After that succeeds, connect the same remote MCP URL in ChatGPT's custom plugin/app flow.

## Notes

- Do not expose `MCP_INTERNAL_SECRET`, GitHub client secret, Cloudflare API token, or OAuth access tokens.
- Do not add Cloudflare browser challenges in front of `/mcp`, `/authorize`, `/callback`, `/oauth/*`, or `/.well-known/*`; MCP clients cannot solve interactive browser challenges.
- v1 intentionally does not support attachments.
