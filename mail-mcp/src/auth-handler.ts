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

function isSameOriginConsentPost(request: Request) {
  const expectedOrigin = new URL(request.url).origin;

  const fetchSite = request.headers.get("Sec-Fetch-Site");
  if (fetchSite && fetchSite !== "same-origin") return false;

  const origin = request.headers.get("Origin");
  if (origin && origin !== expectedOrigin) return false;

  const referer = request.headers.get("Referer");
  if (referer) {
    try {
      if (new URL(referer).origin !== expectedOrigin) return false;
    } catch {
      return false;
    }
  }

  // Require at least one browser-controlled same-origin signal.
  return fetchSite === "same-origin"
    || origin === expectedOrigin
    || Boolean(referer);
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

  const consentToken = crypto.randomUUID();
  await c.env.OAUTH_KV.put(
    `mcp:consent:${consentToken}`,
    JSON.stringify(oauthReqInfo),
    { expirationTtl: 600 }
  );
  const encoded = btoa(JSON.stringify(oauthReqInfo));
  const clientName = escapeHtml(client.clientName || "ChatGPT / MCP client");
  const scopes = requestedScopes(oauthReqInfo).map(escapeHtml).join(", ");

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
.actions{display:flex;gap:12px;margin-top:24px}.btn{border:0;border-radius:8px;padding:11px 16px;font-size:15px;cursor:pointer}
.primary{background:#111;color:#fff}.secondary{background:#e8e8e8;color:#111}
</style>
</head>
<body>
<div class="card">
  <h1>Connect Cloud Mail to ChatGPT</h1>
  <p><strong>${clientName}</strong> is requesting access to your Cloud Mail MCP server.</p>
  <p class="muted">You will sign in with GitHub next. Only the GitHub account configured in ALLOWED_GITHUB_LOGIN will be accepted.</p>
  <div class="scope"><strong>Scopes:</strong> ${scopes}</div>
  <form method="post" action="/authorize">
    <input type="hidden" name="oauth_request" value="${escapeHtml(encoded)}">
    <input type="hidden" name="consent_token" value="${escapeHtml(consentToken)}">
    <div class="actions">
      <button class="btn secondary" type="button" onclick="history.back()">Cancel</button>
      <button class="btn primary" type="submit">Continue with GitHub</button>
    </div>
  </form>
</div>
</body>
</html>`;

  return new Response(html, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self' https://github.com; frame-ancestors 'none'",
      "X-Frame-Options": "DENY",
      "X-Content-Type-Options": "nosniff"
    }
  });
});

app.post("/authorize", async (c) => {
  const form = await c.req.formData();
  const encoded = form.get("oauth_request");
  const consentToken = form.get("consent_token");

  if (typeof encoded !== "string" || typeof consentToken !== "string") {
    return c.text("Invalid authorization form", 400);
  }

  if (!isSameOriginConsentPost(c.req.raw)) {
    return c.text("CSRF validation failed", 400);
  }

  const storedConsent = await c.env.OAUTH_KV.get(`mcp:consent:${consentToken}`);
  if (!storedConsent) {
    return c.text("Authorization request expired. Please restart the connection.", 400);
  }
  let oauthReqInfo: AuthRequest;
  try {
    const submitted = JSON.parse(atob(encoded)) as AuthRequest;
    const stored = JSON.parse(storedConsent) as AuthRequest;

    // The hidden form value is treated as untrusted. It must match the
    // server-side one-time authorization request stored in KV.
    if (JSON.stringify(submitted) !== JSON.stringify(stored)) {
      return c.text("Authorization request mismatch", 400);
    }
    oauthReqInfo = stored;
  } catch {
    return c.text("Invalid OAuth request state", 400);
  }

  if (!oauthReqInfo.clientId || !(await c.env.OAUTH_PROVIDER.lookupClient(oauthReqInfo.clientId))) {
    return c.text("Unknown OAuth client", 400);
  }

  const state = crypto.randomUUID();
  await c.env.OAUTH_KV.put(
    `mcp:oauth:state:${state}`,
    JSON.stringify({ oauthReqInfo, consentToken }),
    { expirationTtl: 600 }
  );

  const callback = new URL("/callback", c.req.url).href;
  const github = new URL("https://github.com/login/oauth/authorize");
  github.searchParams.set("client_id", c.env.GH_OAUTH_CLIENT_ID);
  github.searchParams.set("redirect_uri", callback);
  github.searchParams.set("scope", "read:user user:email");
  github.searchParams.set("state", state);

  return new Response(null, {
    status: 302,
    headers: { Location: github.href }
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
  let consentToken: string;
  try {
    const parsed = JSON.parse(stored) as {
      oauthReqInfo: AuthRequest;
      consentToken: string;
    };
    oauthReqInfo = parsed.oauthReqInfo;
    consentToken = parsed.consentToken;
  } catch {
    return c.text("Invalid stored OAuth state", 500);
  }

  await c.env.OAUTH_KV.delete(`mcp:oauth:state:${state}`);
  await c.env.OAUTH_KV.delete(`mcp:consent:${consentToken}`);

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

  const { redirectTo } = await c.env.OAUTH_PROVIDER.completeAuthorization({
    request: oauthReqInfo,
    userId: user.login,
    metadata: {
      label: user.name || user.login
    },
    scope: requestedScopes(oauthReqInfo),
    props: {
      login: user.login,
      name: user.name || user.login,
      email
    }
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
