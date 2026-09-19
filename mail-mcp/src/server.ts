import { env } from "cloudflare:workers";
import { OAuthProvider } from "@cloudflare/workers-oauth-provider";
import { McpServer } from "@modelcontextprotocol/server";
import { createMcpHandler, getMcpAuthContext } from "agents/mcp/server";
import { z } from "zod";
import { AuthHandler } from "./auth-handler";

interface MailMcpEnv {
  MAIL_SERVICE: {
    fetch(input: Request | string | URL, init?: RequestInit): Promise<Response>;
  };
  MCP_INTERNAL_SECRET: string;
}

function getEnv() {
  return env as unknown as MailMcpEnv;
}

function requireScope(context: any, scope: "mail.read" | "mail.send") {
  const scopes: string[] = context?.http?.authInfo?.scopes || [];
  if (!scopes.includes(scope)) {
    throw new Error(`OAuth scope ${scope} is required for this tool`);
  }
}

async function callMail(path: string, init: RequestInit = {}) {
  const bindings = getEnv();
  const headers = new Headers(init.headers);
  headers.set("X-MCP-Internal-Secret", bindings.MCP_INTERNAL_SECRET);

  if (init.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const request = new Request(`https://cloud-mail.internal/api/internal/mcp${path}`, {
    ...init,
    headers
  });

  const response = await bindings.MAIL_SERVICE.fetch(request);
  const text = await response.text();

  if (!response.ok) {
    throw new Error(`Cloud Mail request failed (${response.status}): ${text.slice(0, 1000)}`);
  }

  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function result(value: unknown) {
  return {
    content: [
      {
        type: "text" as const,
        text: typeof value === "string" ? value : JSON.stringify(value, null, 2)
      }
    ]
  };
}

function createServer() {
  const server = new McpServer({
    name: "Cloud Mail",
    version: "0.1.0"
  });

  server.registerTool(
    "get_profile",
    {
      description: "Show the Cloud Mail account connected to this MCP server.",
      inputSchema: {},
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    async (_args, context) => {
      requireScope(context, "mail.read");
      const auth = getMcpAuthContext();
      const profile = await callMail("/profile");
      return result({
        oauthUser: auth?.props?.login,
        cloudMail: profile
      });
    }
  );

  server.registerTool(
    "list_accounts",
    {
      description: "List the email addresses owned by the connected Cloud Mail user. Use this before sending when an accountId is not already known.",
      inputSchema: {},
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    async (_args, context) => {
      requireScope(context, "mail.read");
      return result(await callMail("/accounts"));
    }
  );

  server.registerTool(
    "list_emails",
    {
      description: "List recent received or sent emails for the connected Cloud Mail user. The result contains short previews; use get_email for the full message.",
      inputSchema: {
        type: z.enum(["receive", "send"]).default("receive"),
        accountId: z.number().int().positive().optional(),
        limit: z.number().int().min(1).max(20).default(10)
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    async ({ type, accountId, limit }, context) => {
      requireScope(context, "mail.read");
      const params = new URLSearchParams({
        type,
        limit: String(limit)
      });
      if (accountId) params.set("accountId", String(accountId));
      return result(await callMail(`/emails?${params}`));
    }
  );

  server.registerTool(
    "get_email",
    {
      description: "Read one full email by its Cloud Mail emailId. Only emails belonging to the connected user can be read.",
      inputSchema: {
        emailId: z.number().int().positive()
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    async ({ emailId }, context) => {
      requireScope(context, "mail.read");
      return result(await callMail(`/email/${emailId}`));
    }
  );

  server.registerTool(
    "search_emails",
    {
      description: "Search the connected user's emails by subject, sender, recipient, name, or plain-text body.",
      inputSchema: {
        query: z.string().min(1).max(200),
        type: z.enum(["receive", "send"]).optional(),
        accountId: z.number().int().positive().optional(),
        limit: z.number().int().min(1).max(20).default(10)
      },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
      }
    },
    async ({ query, type, accountId, limit }, context) => {
      requireScope(context, "mail.read");
      const params = new URLSearchParams({
        q: query,
        limit: String(limit)
      });
      if (type) params.set("type", type);
      if (accountId) params.set("accountId", String(accountId));
      return result(await callMail(`/search?${params}`));
    }
  );

  server.registerTool(
    "send_email",
    {
      description: "Send an email from one of the connected user's Cloud Mail addresses. This causes an external side effect and should only be called after the user has approved the message.",
      inputSchema: {
        accountId: z.number().int().positive(),
        to: z.array(z.string().email()).min(1).max(20),
        subject: z.string().max(300).default(""),
        text: z.string().min(1).max(100000),
        name: z.string().max(100).optional()
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true
      }
    },
    async ({ accountId, to, subject, text, name }, context) => {
      requireScope(context, "mail.send");
      return result(await callMail("/send", {
        method: "POST",
        body: JSON.stringify({
          accountId,
          receiveEmail: to,
          subject,
          text,
          name
        })
      }));
    }
  );

  server.registerTool(
    "reply_email",
    {
      description: "Reply to an existing email owned by the connected Cloud Mail user. The original sender becomes the recipient. This causes an external side effect and should only be called after user approval.",
      inputSchema: {
        emailId: z.number().int().positive(),
        text: z.string().min(1).max(100000),
        accountId: z.number().int().positive().optional(),
        subject: z.string().max(300).optional(),
        name: z.string().max(100).optional()
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true
      }
    },
    async ({ emailId, text, accountId, subject, name }, context) => {
      requireScope(context, "mail.send");
      return result(await callMail("/reply", {
        method: "POST",
        body: JSON.stringify({
          emailId,
          text,
          accountId,
          subject,
          name
        })
      }));
    }
  );

  return server;
}

const mcpHandler = createMcpHandler(createServer);

const apiHandler = {
  fetch(request: Request, bindings: unknown, ctx: ExecutionContext) {
    return mcpHandler(
      request,
      bindings as Record<string, unknown>,
      ctx
    );
  }
};

export default new OAuthProvider({
  authorizeEndpoint: "/authorize",
  tokenEndpoint: "/oauth/token",
  clientRegistrationEndpoint: "/oauth/register",
  apiRoute: "/mcp",
  apiHandler,
  defaultHandler: {
    async fetch(request: Request, bindings: unknown, ctx: ExecutionContext) {
      return AuthHandler.fetch(request, bindings as Record<string, unknown>, ctx);
    }
  }
});
