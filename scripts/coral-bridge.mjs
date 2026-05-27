import http from "node:http";
import { Client } from "../node_modules/@modelcontextprotocol/sdk/dist/esm/client/index.js";
import { StdioClientTransport } from "../node_modules/@modelcontextprotocol/sdk/dist/esm/client/stdio.js";

const host = process.env.CORAL_BRIDGE_HOST || "127.0.0.1";
const port = Number(process.env.CORAL_BRIDGE_PORT || "8787");
const token = process.env.CORAL_BRIDGE_TOKEN || "";
const coralCommand = process.env.CORAL_MCP_COMMAND || "wsl";
const coralArgs = process.env.CORAL_MCP_ARGS
  ? JSON.parse(process.env.CORAL_MCP_ARGS)
  : ["/root/.local/bin/coral", "mcp-stdio"];
const forcedToolName = process.env.CORAL_SQL_TOOL || "";

let clientPromise;
let toolNamePromise;

function json(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(body),
  });
  res.end(body);
}

async function getClient() {
  if (!clientPromise) {
    clientPromise = (async () => {
      const client = new Client({
        name: "repoguard-coral-bridge",
        version: "0.1.0",
      });
      const transport = new StdioClientTransport({
        command: coralCommand,
        args: coralArgs,
        stderr: "pipe",
      });
      await client.connect(transport);
      return client;
    })();
  }

  return clientPromise;
}

async function getSqlToolName(client) {
  if (forcedToolName) return forcedToolName;
  if (!toolNamePromise) {
    toolNamePromise = (async () => {
      const toolsResult = await client.listTools();
      const tools = toolsResult.tools ?? [];
      const preferred =
        tools.find((tool) => tool.name === "sql") ??
        tools.find((tool) => /sql|query|execute/i.test(tool.name)) ??
        tools[0];
      if (!preferred) {
        throw new Error("No MCP tools exposed by Coral server");
      }
      return preferred.name;
    })();
  }

  return toolNamePromise;
}

function extractTextBlocks(content) {
  return (content ?? [])
    .filter((block) => block?.type === "text" && typeof block.text === "string")
    .map((block) => block.text)
    .join("\n")
    .trim();
}

async function runSql(sql) {
  const client = await getClient();
  const toolName = await getSqlToolName(client);
  const result = await client.callTool({ name: toolName, arguments: { sql } });
  const text = extractTextBlocks(result.content);

  if (text) {
    try {
      const parsed = JSON.parse(text);
      if (Array.isArray(parsed.items)) return parsed.items;
      if (Array.isArray(parsed.rows)) return parsed.rows;
      if (Array.isArray(parsed.vulnerabilities)) return parsed.vulnerabilities;
      if (Array.isArray(parsed)) return parsed;
      return [parsed];
    } catch {
      return [{ text }];
    }
  }

  return result.content ?? [];
}

const server = http.createServer(async (req, res) => {
  if (req.method !== "POST" || req.url !== "/mcp/sql") {
    json(res, 404, { error: "Not found" });
    return;
  }

  if (token && req.headers["x-coral-bridge-token"] !== token) {
    json(res, 401, { error: "Unauthorized" });
    return;
  }

  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  let body;
  try {
    body = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
  } catch {
    json(res, 400, { error: "Invalid JSON" });
    return;
  }

  if (!body?.sql || typeof body.sql !== "string") {
    json(res, 400, { error: "`sql` is required" });
    return;
  }

  try {
    const rows = await runSql(body.sql);
    json(res, 200, { rows });
  } catch (error) {
    json(res, 500, {
      error: error instanceof Error ? error.message : "Coral bridge failed",
    });
  }
});

server.listen(port, host, () => {
  console.log(`Coral bridge listening on http://${host}:${port}`);
});
