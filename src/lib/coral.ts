type CoralResponse = {
  items?: unknown[];
  rows?: unknown[];
  vulnerabilities?: unknown[];
  data?: unknown;
};

function escapeSqlLiteral(value: string) {
  return value.replace(/'/g, "''");
}

function normalizeRows(payload: CoralResponse | unknown) {
  if (!payload || typeof payload !== "object") return [] as unknown[];

  const data = payload as CoralResponse;
  const rows = data.items ?? data.rows ?? data.vulnerabilities;
  if (Array.isArray(rows)) return rows;
  if (Array.isArray(data.data)) return data.data;
  return [] as unknown[];
}

async function postCoralSql(sql: string) {
  const bridgeUrl = process.env.CORAL_BRIDGE_URL;
  if (!bridgeUrl) return null;

  const token = process.env.CORAL_BRIDGE_TOKEN;
  const res = await fetch(new URL("/mcp/sql", bridgeUrl), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { "x-coral-bridge-token": token } : {}),
    },
    body: JSON.stringify({ sql }),
  });

  if (!res.ok) return null;
  return normalizeRows((await res.json()) as CoralResponse);
}

async function postLegacyCoralSql(sql: string) {
  const coralEndpoint = process.env.CORAL_ENDPOINT;
  if (!coralEndpoint) return null;

  const coralKey = process.env.CORAL_API_KEY;
  const res = await fetch(coralEndpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(coralKey ? { Authorization: `Bearer ${coralKey}` } : {}),
    },
    body: JSON.stringify({ sql }),
  });

  if (!res.ok) return null;
  return normalizeRows((await res.json()) as CoralResponse);
}

export async function runCoralSql(sql: string) {
  return (await postCoralSql(sql)) ?? (await postLegacyCoralSql(sql));
}

export function sqlString(value: string) {
  return `'${escapeSqlLiteral(value)}'`;
}

export function getCoralAssistantContext() {
  return [
    "Coral sources available:",
    "- github.contents: repository files; columns used here include owner, repo, path, content_text.",
    "- osv.query_by_version(package_name, ecosystem, version): returns vulnerability rows for a dependency version.",
    "- cisa_kev.vulnerabilities: known exploited vulnerabilities feed.",
    "SQL patterns:",
    "- Fetch a file: SELECT content_text FROM \"github\".\"contents\" WHERE owner = 'OWNER' AND repo = 'REPO' AND path = 'package.json' LIMIT 1",
    "- Query advisories: SELECT * FROM osv.query_by_version(package_name => 'name', ecosystem => 'npm', version => '1.2.3')",
    '- Load KEV rows: SELECT * FROM "cisa_kev"."vulnerabilities"',
    "Rules:",
    "- Prefer these Coral sources over guessing external APIs.",
    "- Do not invent table names; if a source is missing, say so explicitly.",
  ].join("\n");
}
