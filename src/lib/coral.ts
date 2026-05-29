export type SqlLogEntry = {
  id: string;
  label: string;
  sql: string;
  source: "coral" | "legacy" | "none";
  rowCount: number | null;
  durationMs: number;
  error: string | null;
  timestamp: string;
};

const sqlLog: SqlLogEntry[] = [];
const MAX_LOG = 100;

function recordLog(entry: SqlLogEntry) {
  sqlLog.unshift(entry);
  if (sqlLog.length > MAX_LOG) sqlLog.length = MAX_LOG;
}

export function getSqlLog(): SqlLogEntry[] {
  return [...sqlLog];
}

export function clearSqlLog() {
  sqlLog.length = 0;
}

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

function makeLogId() {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
}

async function postCoralSql(sql: string, label: string, silent: boolean) {
  const bridgeUrl = process.env.CORAL_BRIDGE_URL;
  if (!bridgeUrl) return null;

  const token = process.env.CORAL_BRIDGE_TOKEN;
  const t0 = Date.now();
  try {
    const res = await fetch(new URL("/mcp/sql", bridgeUrl), {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(token ? { "x-coral-bridge-token": token } : {}),
      },
      body: JSON.stringify({ sql }),
    });

    if (!res.ok) {
      if (!silent) recordLog({ id: makeLogId(), label, sql, source: "coral", rowCount: null, durationMs: Date.now() - t0, error: `HTTP ${res.status}`, timestamp: new Date().toISOString() });
      return null;
    }
    const rows = normalizeRows((await res.json()) as CoralResponse);
    if (!silent) recordLog({ id: makeLogId(), label, sql, source: "coral", rowCount: Array.isArray(rows) ? rows.length : null, durationMs: Date.now() - t0, error: null, timestamp: new Date().toISOString() });
    return rows;
  } catch (e) {
    if (!silent) recordLog({ id: makeLogId(), label, sql, source: "coral", rowCount: null, durationMs: Date.now() - t0, error: String(e), timestamp: new Date().toISOString() });
    return null;
  }
}

async function postLegacyCoralSql(sql: string, label: string, silent: boolean) {
  const coralEndpoint = process.env.CORAL_ENDPOINT;
  if (!coralEndpoint) return null;

  const coralKey = process.env.CORAL_API_KEY;
  const t0 = Date.now();
  try {
    const res = await fetch(coralEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(coralKey ? { Authorization: `Bearer ${coralKey}` } : {}),
      },
      body: JSON.stringify({ sql }),
    });

    if (!res.ok) {
      if (!silent) recordLog({ id: makeLogId(), label, sql, source: "legacy", rowCount: null, durationMs: Date.now() - t0, error: `HTTP ${res.status}`, timestamp: new Date().toISOString() });
      return null;
    }
    const rows = normalizeRows((await res.json()) as CoralResponse);
    if (!silent) recordLog({ id: makeLogId(), label, sql, source: "legacy", rowCount: Array.isArray(rows) ? rows.length : null, durationMs: Date.now() - t0, error: null, timestamp: new Date().toISOString() });
    return rows;
  } catch (e) {
    if (!silent) recordLog({ id: makeLogId(), label, sql, source: "legacy", rowCount: null, durationMs: Date.now() - t0, error: String(e), timestamp: new Date().toISOString() });
    return null;
  }
}

export async function runCoralSql(sql: string, label = "query", silent = false) {
  return (await postCoralSql(sql, label, silent)) ?? (await postLegacyCoralSql(sql, label, silent));
}

export function sqlString(value: string) {
  return `'${escapeSqlLiteral(value)}'`;
}

export function getCoralAssistantContext() {
  return `
## Coral Data Sources (verified against live bridge)

### GitHub
- \`github.contents\` — required filters: owner, repo, path
  - SELECT content_text FROM github.contents WHERE owner = 'OWNER' AND repo = 'REPO' AND path = 'package.json' LIMIT 1

### OSV
- \`osv.query_by_version\` — required filters: package_name, ecosystem, version
  - Columns: id, summary, details, published, modified, aliases (JSON string), references (JSON string), severity (JSON string), affected (JSON string), database_specific (JSON string), raw (JSON string)
  - severity format: "[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/..."}]" — parse JSON, then compute score from CVSS vector
  - aliases format: "[\"CVE-2020-11023\",\"BIT-...\"]" — used to join with cisa_kev
- \`osv.query_by_commit\` — required filter: commit
- \`osv.vulns\` — required filter: id (single vuln lookup)

### CISA KEV
- \`cisa_kev.vulnerabilities\` — flat table
  - Columns: cve_id, vendor_project, product, vulnerability_name, date_added, short_description, required_action, due_date, known_ransomware_campaign_use, notes, cwes
- \`cisa_kev.catalog\` — single-row feed metadata only

### Cross-source JOIN (OSV + KEV + NVD in one query)
Coral supports 3-way cross-schema joins. NVD is available but rate-limited without an API key (5 req/30s).

  SELECT v.id, v.summary, v.severity, v.affected, v.references, v.aliases,
         k.cve_id          AS kev_cve_id,
         k.vulnerability_name AS kev_name,
         k.date_added      AS kev_date_added,
         k.required_action AS kev_required_action,
         n.base_score      AS nvd_base_score,
         n.base_severity   AS nvd_severity
  FROM osv.query_by_version v
  LEFT JOIN cisa_kev.vulnerabilities k
    ON v.aliases LIKE '%' || k.cve_id || '%'
  LEFT JOIN nvd.cvss_v3 n
    ON v.aliases LIKE '%' || n.cve_id || '%'
  WHERE v.package_name = 'jquery'
    AND v.ecosystem    = 'npm'
    AND v.version      = '3.4.1'
  LIMIT 50

- kev_cve_id IS NOT NULL → actively exploited (CISA KEV)
- nvd_base_score → numeric CVSS score (most authoritative severity source)
- nvd_severity → plain label (CRITICAL/HIGH/MEDIUM/LOW)
- NVD join may 429 without API key — query still returns OSV+KEV data if NVD fails

### NVD (via Coral — rate-limited without API key)
- \`nvd.vulnerabilities\` — columns: cve_id, source_identifier, published, last_modified, vuln_status, description; filter: cve_id_filter, pub_start_date, pub_end_date, cvss_v3_severity, keyword_search
- \`nvd.cvss_v3\` — columns: cve_id, base_score, base_severity, vector_string, exploitability_score, impact_score, attack_vector, attack_complexity, privileges_required, user_interaction, scope, confidentiality_impact, integrity_impact, availability_impact; filter: cve_id_filter
- \`nvd.cvss_v2\` — columns: cve_id, base_score, severity, vector_string, exploitability_score, impact_score; filter: cve_id_filter
- \`nvd.references\` — columns: cve_id, references (JSON); filter: cve_id_filter
- Use LEFT JOIN on aliases LIKE for cross-join; use cve_id_filter for direct lookup

## Rules
- Prefer the cross-join query over two separate queries — it's more efficient and gives KEV status in one round trip.
- Do not use osv.vulnerabilities, osv.affected, osv.severity, osv.references — those tables do not exist.
- json_each() is not available — use LIKE for JSON string matching.
`.trim();
}
