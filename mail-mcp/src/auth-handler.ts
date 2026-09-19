import type { AuthRequest, OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import { Hono } from "hono";

interface Env {
  OAUTH_PROVIDER: OAuthHelpers;
  OAUTH_KV: KVNamespace;
  GH_OAUTH_CLIENT_ID: string;
  GH_OAUTH_CLIENT_SECRET: string;
  ALLOWED_GITHUB_LOGIN: string;
}

const app = new Hono<{ Bindings: Env }>();

function escapeHtml(value: string) {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function requestedScopes(request: AuthRequest) {
  const requested = Array.isArray(request.scope) ? request.scope : [];
  const supported = new Set(["mail.read", "mail.send"]);
  const granted = requested.filter((scope) => supported.has(scope));
  return granted.length > 0 ? granted : ["mail.read", "mail.send"];
}

app.get("/authorize", async (c) => {
  const oauthReqInfo = await c.env.OAUTH_PROVIDER.parseAuthRequest(c.req.raw);
  if (!oauthReqInfo.clientId) return c.text("Invalid OAuth request", 400);

  const client = await c.env.OAUTH_PROVIDER.lookupClient(oauthReqInfo.clientId);
  if (!client) return c.text("Unknown OAuth client", 400);

  // Store the full OAuth request server-side before rendering the consent page.
  // The GitHub button can therefore be a normal external link with no form POST
  // or cookie dependency, which is more reliable in embedded OAuth windows.
  const state = crypto.randomUUID();
  await c.env.OAUTH_KV.put(
    `mcp:oauth:state:${state}`,
    JSON.stringify({ oauthReqInfo }),
    { expirationTtl: 600 }
  );

  const callback = new URL("/callback", c.req.url).href;
  const github = new URL("https://github.com/login/oauth/authorize");
  github.searchParams.set("client_id", c.env.GH_OAUTH_CLIENT_ID);
  github.searchParams.set("redirect_uri", callback);
  github.searchParams.set("scope", "read:user user:email");
  github.searchParams.set("state", state);

  const clientName = escapeHtml(client.clientName || "ChatGPT / MCP client");
  const scopes = requestedScopes(oauthReqInfo).map(escapeHtml).join(", ");
  const githubUrl = escapeHtml(github.href);

  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorize Cloud Mail MCP</title>
<style>
body{font-family:system-ui,-apple-system,sans-serif;background:#f6f7f9;color:#111;margin:0;padding:32px}
.card{max-width:560px;margin:40px auto;background:#fff;border:1px solid #ddd;border-radius:14px;padding:28px}
h1{font-size:24px;margin-top:0}.muted{color:#666}.scope{padding:12px;background:#f3f4f6;border-radius:8px}
.actions{display:flex;gap:12px;margin-top:24px}.btn{display:inline-block;text-decoration:none;border:0;border-radius:8px;padding:11px 16px;font-size:15px;cursor:pointer}
.primary{background:#111;color:#fff}.secondary{background:#e8e8e8;color:#111}
</style>
</head>
<body>
<div class="card">
  <h1>Connect Cloud Mail to ChatGPT</h1>
  <p><strong>${clientName}</strong> is requesting access to your Cloud Mail MCP server.</p>
  <p class="muted">You will sign in with GitHub next. Only the GitHub account configured in ALLOWED_GITHUB_LOGIN will be accepted.</p>
  <div class="scope"><strong>Scopes:</strong> ${scopes}</div>
  <div class="actions">
    <a class="btn secondary" href="/">Cancel</a>
    <a class="btn primary" href="${githubUrl}">Continue with GitHub</a>
  </div>
</div>
</body>
</html>`;

  return new Response(html, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'",
      "X-Frame-Options": "DENY",
      "X-Content-Type-Options": "nosniff",
      "Cache-Control": "no-store"
    }
  });
});

app.get("/callback", async (c) => {
  const state = c.req.query("state");
  const code = c.req.query("code");

  if (!state || !code) {
    return c.text("Invalid OAuth callback state", 400);
  }

  const stored = await c.env.OAUTH_KV.get(`mcp:oauth:state:${state}`);
  if (!stored) return c.text("OAuth state expired", 400);

  let oauthReqInfo: AuthRequest;
  try {
    const parsed = JSON.parse(stored) as { oauthReqInfo: AuthRequest };
    oauthReqInfo = parsed.oauthReqInfo;
    if (!oauthReqInfo?.clientId) {
      return c.text("Invalid stored OAuth state", 500);
    }
  } catch {
    return c.text("Invalid stored OAuth state", 500);
  }

  await c.env.OAUTH_KV.delete(`mcp:oauth:state:${state}`);

  const callback = new URL("/callback", c.req.url).href;
  const tokenResponse = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: {
      "Accept": "application/json",
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: new URLSearchParams({
      client_id: c.env.GH_OAUTH_CLIENT_ID,
      client_secret: c.env.GH_OAUTH_CLIENT_SECRET,
      code,
      redirect_uri: callback
    })
  });

  if (!tokenResponse.ok) return c.text("GitHub token exchange failed", 502);
  const tokenJson = await tokenResponse.json() as { access_token?: string; error?: string };
  if (!tokenJson.access_token) return c.text("GitHub did not return an access token", 502);

  const githubHeaders = {
    "Authorization": `Bearer ${tokenJson.access_token}`,
    "Accept": "application/vnd.github+json",
    "User-Agent": "cloud-mail-mcp"
  };

  const userResponse = await fetch("https://api.github.com/user", { headers: githubHeaders });
  if (!userResponse.ok) return c.text("Unable to load GitHub user", 502);

  const user = await userResponse.json() as {
    login: string;
    name?: string | null;
    email?: string | null;
  };

  const allowed = (c.env.ALLOWED_GITHUB_LOGIN || "")
    .split(",")
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean);

  if (!allowed.includes(user.login.toLowerCase())) {
    return c.text("This GitHub account is not allowed to use Cloud Mail MCP", 403);
  }

  let email = user.email || null;
  if (!email) {
    const emailsResponse = await fetch("https://api.github.com/user/emails", { headers: githubHeaders });
    if (emailsResponse.ok) {
      const emails = await emailsResponse.json() as Array<{ email: string; primary?: boolean; verified?: boolean }>;
      email = emails.find((item) => item.primary && item.verified)?.email
        || emails.find((item) => item.verified)?.email
        || null;
    }
  }

  const grantedScopes = requestedScopes(oauthReqInfo);

  const { redirectTo } = await c.env.OAUTH_PROVIDER.completeAuthorization({
    request: oauthReqInfo,
    userId: user.login,
    metadata: {
      label: user.name || user.login
    },
    scope: grantedScopes,
    props: {
      login: user.login,
      name: user.name || user.login,
      email,
      mcpClientId: oauthReqInfo.clientId,
      mcpScopes: grantedScopes
    },
    // ChatGPT can briefly keep using the previous grant while a reconnect
    // finishes propagating. Revoking that grant here turns those in-flight
    // credentials into 401 invalid_token responses. Keep grants side-by-side;
    // OAuthProvider still enforces their normal access/refresh token TTLs.
    revokeExistingGrants: false
  });

  return new Response(null, {
    status: 302,
    headers: { Location: redirectTo }
  });
});

app.get("/", (c) => c.json({
  name: "Cloud Mail MCP",
  mcp: "/mcp",
  authorization: "/authorize",
  token: "/oauth/token",
  registration: "/oauth/register"
}));

export { app as AuthHandler };
