#!/usr/bin/env node
//
// Authenticates with Figma's MCP server via OAuth 2.1 PKCE.
// Figma's dynamic client registration rejects client_name values other than
// known clients, so this registers as "Claude Code" to get through.
//
// Auto-detects installed MCP clients and writes credentials to their auth
// stores. Currently supports OpenCode; raw tokens are always printed for
// manual use with any other client.
//
// Usage:
//   npx tsx figma-oauth.ts
//   bun run figma-oauth.ts
//

import { createHash, randomBytes } from "node:crypto";
import { access, readFile, writeFile, mkdir } from "node:fs/promises";
import { createServer } from "node:http";
import { createInterface } from "node:readline";
import { join } from "node:path";
import { homedir } from "node:os";
import { spawn } from "node:child_process";

const SERVER_URL = "https://mcp.figma.com/mcp";
const USER_AGENT = "claude-cli/2.1.2 (external, cli)";
const CALLBACK_PORT = 9876;
const REDIRECT_URI = `http://localhost:${CALLBACK_PORT}/callback`;

const FIGMA = {
  register: "https://api.figma.com/v1/oauth/mcp/register",
  authorize: "https://www.figma.com/oauth/mcp",
  token: "https://api.figma.com/v1/oauth/token",
} as const;

type Credentials = {
  clientId: string;
  clientSecret: string;
  accessToken: string;
  refreshToken?: string;
  expiresAt?: number;
};

type McpClient = {
  name: string;
  detect: () => Promise<boolean>;
  hasExisting: () => Promise<boolean>;
  write: (creds: Credentials) => Promise<string>;
};

function prompt(question: string): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.trim().toLowerCase());
    });
  });
}

async function confirm(question: string): Promise<boolean> {
  const answer = await prompt(`${question} [y/N] `);
  return answer === "y" || answer === "yes";
}

function openBrowser(url: string) {
  try {
    const cmd = process.platform === "darwin" ? "open" : "xdg-open";
    spawn(cmd, [url], { detached: true, stdio: "ignore" }).unref();
  } catch {
    /* best-effort */
  }
}

async function readJson<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, "utf-8"));
}

async function writeJson(path: string, data: unknown) {
  await mkdir(join(path, ".."), { recursive: true });
  await writeFile(path, `${JSON.stringify(data, null, 2)}\n`, { mode: 0o600 });
}

function pathExists(path: string) {
  return access(path).then(
    () => true,
    () => false
  );
}

async function register() {
  const res = await fetch(FIGMA.register, {
    method: "POST",
    headers: { "Content-Type": "application/json", "User-Agent": USER_AGENT },
    body: JSON.stringify({
      client_name: "Claude Code (figma)",
      redirect_uris: [REDIRECT_URI],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    }),
  });

  if (!res.ok) {
    throw new Error(`Registration failed: ${res.status} ${await res.text()}`);
  }

  const data = (await res.json()) as {
    client_id: string;
    client_secret?: string;
  };
  if (!data.client_secret) {
    throw new Error("Registration response missing client_secret");
  }

  return { clientId: data.client_id, clientSecret: data.client_secret };
}

async function authorize(clientId: string) {
  const codeVerifier = randomBytes(32).toString("base64url");
  const codeChallenge = createHash("sha256")
    .update(codeVerifier)
    .digest("base64url");
  const state = randomBytes(16).toString("hex");

  const authUrl = new URL(FIGMA.authorize);
  for (const [k, v] of Object.entries({
    client_id: clientId,
    redirect_uri: REDIRECT_URI,
    response_type: "code",
    scope: "mcp:connect",
    state,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
  })) {
    authUrl.searchParams.set(k, v);
  }

  console.log(`\nOpen this URL in your browser:\n\n  ${authUrl}\n`);
  openBrowser(authUrl.toString());
  console.log("Waiting for callback...\n");

  let resolve: (v: string) => void = () => undefined;
  let reject: (e: Error) => void = () => undefined;
  const promise = new Promise<string>((res, rej) => {
    resolve = res;
    reject = rej;
  });

  const server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", `http://localhost:${CALLBACK_PORT}`);

    if (url.pathname !== "/callback") {
      res.writeHead(404).end();
      return;
    }

    if (url.searchParams.get("state") !== state) {
      reject(new Error("State mismatch"));
      res.writeHead(400).end("State mismatch");
      return;
    }

    const code = url.searchParams.get("code");
    if (!code) {
      const err = url.searchParams.get("error") ?? "unknown";
      reject(new Error(`Authorization denied: ${err}`));
      res.writeHead(400).end(err);
      return;
    }

    resolve(code);
    res
      .writeHead(200, { "Content-Type": "text/html" })
      .end("<h1>Done! You can close this tab.</h1>");
  }).listen(CALLBACK_PORT);

  try {
    return { code: await promise, codeVerifier };
  } finally {
    server.close();
  }
}

async function exchangeCode(
  clientId: string,
  clientSecret: string,
  code: string,
  codeVerifier: string
) {
  const res = await fetch(FIGMA.token, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "User-Agent": USER_AGENT,
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: clientId,
      client_secret: clientSecret,
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: codeVerifier,
    }),
  });

  if (!res.ok) {
    throw new Error(`Token exchange failed: ${res.status} ${await res.text()}`);
  }

  return res.json() as Promise<{
    access_token: string;
    refresh_token?: string;
    expires_in?: number;
  }>;
}

const opencodeDataDir = () =>
  join(
    process.env.XDG_DATA_HOME ?? join(homedir(), ".local", "share"),
    "opencode"
  );

const opencodeAuthPath = () => join(opencodeDataDir(), "mcp-auth.json");

const opencode: McpClient = {
  name: "OpenCode",
  detect: () => pathExists(opencodeDataDir()),
  async hasExisting() {
    try {
      const data = await readJson<Record<string, unknown>>(opencodeAuthPath());
      return data.figma != null;
    } catch {
      /* no file */
    }
    return false;
  },
  async write(creds) {
    const authPath = opencodeAuthPath();

    let existing: Record<string, unknown> = {};
    try {
      existing = await readJson(authPath);
    } catch {
      /* first run */
    }

    existing.figma = {
      tokens: {
        accessToken: creds.accessToken,
        refreshToken: creds.refreshToken,
        ...(creds.expiresAt && { expiresAt: creds.expiresAt }),
      },
      clientInfo: {
        clientId: creds.clientId,
        clientSecret: creds.clientSecret,
      },
      serverUrl: SERVER_URL,
    };

    await writeJson(authPath, existing);
    return authPath;
  },
};

const clients: McpClient[] = [opencode];

console.log("Registering OAuth client with Figma...");
const { clientId, clientSecret } = await register();
console.log(`Client registered: ${clientId}`);

const { code, codeVerifier } = await authorize(clientId);
console.log("Exchanging authorization code for tokens...");

const tokens = await exchangeCode(clientId, clientSecret, code, codeVerifier);
const expiresInDays = Math.floor((tokens.expires_in ?? 0) / 86_400);

const creds: Credentials = {
  clientId,
  clientSecret,
  accessToken: tokens.access_token,
  refreshToken: tokens.refresh_token,
  expiresAt: tokens.expires_in
    ? Math.floor(Date.now() / 1000) + tokens.expires_in
    : undefined,
};

console.log(`
Done! Expires in ${expiresInDays} days.

Access token:  ${tokens.access_token}
Refresh token: ${tokens.refresh_token ?? "n/a"}
Client ID:     ${clientId}
Client secret: ${clientSecret}

Use these to configure your MCP client's credential store.
`);

for (const c of clients) {
  if (!(await c.detect())) continue;

  if (await c.hasExisting()) {
    if (
      !(await confirm(
        `${c.name}: existing Figma credentials found. Overwrite?`
      ))
    ) {
      console.log("Skipped.\n");
      continue;
    }
  } else if (!(await confirm(`${c.name} detected. Write credentials?`))) {
    console.log("Skipped.\n");
    continue;
  }

  console.log(`Written to ${await c.write(creds)}`);
}

console.log("Remember to add Figma to your MCP config if you haven't already.");
