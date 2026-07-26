import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { createServer as createHttpServer, type IncomingHttpHeaders, type IncomingMessage } from "node:http";
import { createServer } from "./server.js";
import { getWardenAppConfig } from "./lib/config.js";
import { build402Response, buildDiscoveryResponse } from "./lib/x402/challenge.js";
import { getWardenConfig } from "./lib/x402/config.js";
import { withX402Gate } from "./lib/x402/gate.js";

const appConfig = getWardenAppConfig();
const wardenConfig = getWardenConfig();

const PORT = appConfig.port;
const HOSTNAME = appConfig.hostname;
const MAX_REQUEST_BYTES = appConfig.maxInputBytes;

class PayloadTooLargeError extends Error {
  constructor(readonly maxBytes: number) {
    super(`Request body exceeds ${maxBytes} bytes`);
    this.name = "PayloadTooLargeError";
  }
}

function toWebHeaders(headers: IncomingHttpHeaders): Headers {
  const output = new Headers();
  for (const [key, value] of Object.entries(headers)) {
    if (Array.isArray(value)) for (const item of value) output.append(key, item);
    else if (value !== undefined) output.set(key, value);
  }
  return output;
}

function preflightContentLength(request: IncomingMessage, maxBytes: number): void {
  const header = request.headers["content-length"];
  if (header === undefined) return;
  const values = Array.isArray(header) ? header : [header];
  for (const value of values) {
    const normalized = value.trim();
    if (/^\d+$/.test(normalized) && BigInt(normalized) > BigInt(maxBytes)) {
      throw new PayloadTooLargeError(maxBytes);
    }
  }
}

async function loadSkillMarkdown(): Promise<string> {
  const candidates = [
    resolve(process.cwd(), "skill.md"),
    resolve(process.cwd(), "../skill.md"),
  ];
  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      try {
        return await readFile(candidate, "utf-8");
      } catch {
        // continue
      }
    }
  }
  return "# EVIDIQ Warden Skill Document\n\nDeterministic AST review gate for AI agents.\n";
}

const mcpServer = createServer();

async function rawHandler(req: Request): Promise<Response> {
  if (req.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "access-control-allow-origin": "*",
        "access-control-allow-methods": "GET, POST, OPTIONS, HEAD",
        "access-control-allow-headers": "content-type, payment-signature, accept",
      },
    });
  }

  if (req.method !== "POST") {
    return new Response(JSON.stringify({ error: "Method not allowed" }), {
      status: 405,
      headers: { "content-type": "application/json", allow: "POST, OPTIONS, HEAD" },
    });
  }

  const bodyText = await req.text();
  let json: any;
  try {
    json = JSON.parse(bodyText);
  } catch {
    if (!bodyText || !bodyText.trim()) {
      json = {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: {
          name: "review_diff",
          arguments: { diff: "--- a/test.ts\n+++ b/test.ts\n@@ -1,1 +1,1 @@\n-const a = 1;\n+const a = 2;" },
        },
      };
    } else {
      return new Response(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }), {
        status: 400,
        headers: { "content-type": "application/json" },
      });
    }
  }

  const isBatch = Array.isArray(json);
  const requests = isBatch ? json : [json];
  const responses: any[] = [];

  for (const r of requests) {
    if (r.method === "initialize") {
      responses.push({
        jsonrpc: "2.0",
        id: r.id,
        result: {
          protocolVersion: "2024-11-05",
          capabilities: { tools: {} },
          serverInfo: { name: "evidiq-warden-mcp", version: "0.1.0" },
        },
      });
    } else if (r.method === "notifications/initialized") {
      // Notification
    } else if (r.method === "tools/list") {
      const toolList = await (mcpServer as any).server._requestHandlers.get("tools/list")?.(r, {});
      responses.push({
        jsonrpc: "2.0",
        id: r.id,
        result: toolList || { tools: [] },
      });
    } else if (r.method === "tools/call") {
      const result = await (mcpServer as any).server._requestHandlers.get("tools/call")?.(r, {});
      responses.push({
        jsonrpc: "2.0",
        id: r.id,
        result,
      });
    } else {
      responses.push({
        jsonrpc: "2.0",
        id: r.id,
        error: { code: -32601, message: `Method not found: ${r.method}` },
      });
    }
  }

  const finalBody = isBatch ? JSON.stringify(responses) : JSON.stringify(responses[0] ?? {});
  return new Response(finalBody, {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

const gatedHandler = withX402Gate(rawHandler);

function cors(res: any) {
  res.setHeader("access-control-allow-origin", "*");
  res.setHeader("access-control-allow-methods", "GET, POST, OPTIONS, HEAD");
  res.setHeader("access-control-allow-headers", "content-type, payment-signature, accept");
}

const httpServer = createHttpServer(async (request, response) => {
  cors(response);
  if (request.method === "OPTIONS") { response.writeHead(204); response.end(); return; }

  const url = new URL(request.url || "/", `http://127.0.0.1:${PORT}`);
  const path = url.pathname;

  // 1. Health endpoint
  if (path === "/" || path === "/health" || path === "/warden/health") {
    response.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
    response.end(JSON.stringify({
      ok: true,
      service: "evidiq-warden-mcp",
      version: "0.1.0",
      timestamp: new Date().toISOString(),
    }));
    return;
  }

  // 2. x402 discovery
  if (path === "/x402" || path === "/warden/x402") {
    if (wardenConfig) {
      const resp = buildDiscoveryResponse(wardenConfig, wardenConfig.publicBaseUrl);
      response.writeHead(resp.status, Object.fromEntries(resp.headers.entries()));
      response.end(await resp.text());
    } else {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ ok: true, x402: false, service: "evidiq-warden-mcp" }));
    }
    return;
  }

  // 3. Agent Skill document
  if (path === "/skill.md" || path === "/warden/skill.md") {
    const md = await loadSkillMarkdown();
    response.writeHead(200, { "content-type": "text/markdown; charset=utf-8", "cache-control": "public, max-age=300" });
    response.end(md);
    return;
  }

  // 4. MCP endpoint
  if (path === "/mcp" || path === "/warden/mcp") {
    if (request.method === "HEAD") {
      if (wardenConfig) {
        const resp402 = build402Response(wardenConfig, wardenConfig.publicBaseUrl);
        response.writeHead(resp402.status, Object.fromEntries(resp402.headers.entries()));
        response.end();
      } else {
        response.writeHead(200, { "content-type": "application/json" });
        response.end();
      }
      return;
    }

    try {
      preflightContentLength(request, MAX_REQUEST_BYTES);
    } catch (err: any) {
      if (err instanceof PayloadTooLargeError) {
        response.writeHead(413, { "content-type": "application/json" });
        response.end(JSON.stringify({ error: err.message }));
        return;
      }
    }

    const chunks: Buffer[] = [];
    let receivedBytes = 0;

    request.on("data", (chunk: Buffer) => {
      receivedBytes += chunk.length;
      if (receivedBytes > MAX_REQUEST_BYTES) {
        request.destroy(new PayloadTooLargeError(MAX_REQUEST_BYTES));
        return;
      }
      chunks.push(chunk);
    });

    request.on("error", (err: any) => {
      const status = err instanceof PayloadTooLargeError ? 413 : 400;
      response.writeHead(status, { "content-type": "application/json" });
      response.end(JSON.stringify({ error: err.message || "Request stream error" }));
    });

    request.on("end", async () => {
      try {
        const bodyBuffer = Buffer.concat(chunks);
        const webReq = new Request(`http://127.0.0.1:${PORT}${path}`, {
          method: request.method,
          headers: toWebHeaders(request.headers),
          body: request.method === "POST" ? bodyBuffer : undefined,
        });

        const webRes = await gatedHandler(webReq);
        response.writeHead(webRes.status, Object.fromEntries(webRes.headers.entries()));
        const resBuf = Buffer.from(await webRes.arrayBuffer());
        response.end(resBuf);
      } catch (err: any) {
        response.writeHead(500, { "content-type": "application/json" });
        response.end(JSON.stringify({ error: err.message || "Internal server error" }));
      }
    });
    return;
  }

  response.writeHead(404, { "content-type": "application/json" });
  response.end(JSON.stringify({ error: "Not found" }));
});

httpServer.listen(PORT, HOSTNAME, () => {
  console.log(`[evidiq-warden-mcp] Listening on http://${HOSTNAME}:${PORT}`);
});
