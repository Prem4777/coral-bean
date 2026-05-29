import { runCoralSql, sqlString } from "@/lib/coral";

export type Dependency = {
  name: string;
  version: string;
  ecosystem: "npm" | "pypi" | "maven" | "cargo" | "golang" | string;
  isDirect?: boolean;
};

export type Vulnerability = {
  id: string;
  summary?: string;
  severity?: string | null;
  fixed_in?: string | null;
  affectedVersions?: string | null;
  advisoryUrl?: string | null;
  epssScore?: number | null;
  references?: { url: string; type?: string }[];
  kev?: boolean;
};

function extractRows(payload: unknown) {
  if (Array.isArray(payload)) return payload as any[];
  if (!payload || typeof payload !== "object") return [] as any[];
  const data = payload as { items?: unknown[]; rows?: unknown[]; vulnerabilities?: unknown[] };
  return (data.items ?? data.rows ?? data.vulnerabilities ?? []) as any[];
}

// ─── GitHub file fetching ────────────────────────────────────────────────────

export async function fetchGitHubFile(
  owner: string,
  repo: string,
  path: string,
  token?: string,
): Promise<string | null> {
  try {
    const rows = extractRows(
      await runCoralSql(
        `SELECT content_text FROM "github"."contents" WHERE owner = ${sqlString(owner)} AND repo = ${sqlString(repo)} AND path = ${sqlString(path)} LIMIT 1`,
        `github.contents — ${owner}/${repo}/${path}`,
        true, // silent — file fetches are infra noise, not agent queries
      ),
    );
    if (rows.length > 0) {
      const first = rows[0] as Record<string, unknown> | unknown[];
      if (first && typeof first === "object" && !Array.isArray(first) && "content_text" in first) {
        return String((first as Record<string, unknown>).content_text ?? "");
      }
      if (Array.isArray(first) && first.length > 0) return String(first[0]);
    }
  } catch {
    // fall through to GitHub REST
  }

  const url = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}`;
  const headers: Record<string, string> = { Accept: "application/vnd.github.v3.raw" };
  if (token) headers["Authorization"] = `token ${token}`;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const res = await fetch(url, { headers, signal: controller.signal });
    clearTimeout(timeout);
    if (res.status === 429) throw new RateLimitError("GitHub");
    if (res.status === 200) return res.text();
  } catch (e) {
    if (e instanceof RateLimitError) throw e;
  }
  return null;
}

/** Fetch the latest commit SHA for the default branch. */
export async function fetchCommitSha(
  owner: string,
  repo: string,
  token?: string,
): Promise<string | null> {
  try {
    const url = `https://api.github.com/repos/${owner}/${repo}/commits/HEAD`;
    const headers: Record<string, string> = { Accept: "application/vnd.github.v3+json" };
    if (token) headers["Authorization"] = `token ${token}`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    const res = await fetch(url, { headers, signal: controller.signal });
    clearTimeout(timeout);
    if (!res.ok) return null;
    const data = await res.json();
    return typeof data?.sha === "string" ? data.sha : null;
  } catch {
    return null;
  }
}

// ─── Manifest parsers ────────────────────────────────────────────────────────

export function parsePackageJson(content: string): Dependency[] {
  try {
    const json = JSON.parse(content);
    const direct = new Set(Object.keys(json.dependencies ?? {}));
    const deps = {
      ...(json.dependencies ?? {}),
      ...(json.devDependencies ?? {}),
    };
    return Object.entries(deps).map(([name, version]) => ({
      name,
      version: typeof version === "string" ? version.replace(/^[^0-9]*/, "") : "",
      ecosystem: "npm" as const,
      isDirect: direct.has(name),
    }));
  } catch {
    return [];
  }
}

export function parseRequirementsTxt(content: string): Dependency[] {
  return content
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"))
    .map((line) => {
      const m = line.match(/^([^=<>!~\[\]\s]+)\s*([=<>~!]+)?\s*([\d\.a-zA-Z\-]*)/);
      const name = m ? m[1] : line;
      const version = m && m[3] ? m[3] : "";
      return { name, version, ecosystem: "pypi" as const, isDirect: true };
    });
}

export function parseGoSum(content: string): Dependency[] {
  const deps: Dependency[] = [];
  const seen = new Set<string>();
  for (const line of content.split(/\r?\n/)) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 2) continue;
    const [module, versionRaw] = parts;
    // go.sum has lines like "module v1.2.3 h1:..." and "module v1.2.3/go.mod h1:..."
    if (versionRaw?.includes("/go.mod")) continue;
    const version = (versionRaw ?? "").replace(/^v/, "");
    const key = `${module}@${version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    deps.push({ name: module, version, ecosystem: "golang", isDirect: false });
  }
  return deps;
}

export function parseGoMod(content: string): Dependency[] {
  const deps: Dependency[] = [];
  let inRequire = false;
  for (const line of content.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed === "require (") { inRequire = true; continue; }
    if (trimmed === ")") { inRequire = false; continue; }
    if (trimmed.startsWith("require ") || inRequire) {
      const m = trimmed.replace(/^require\s+/, "").match(/^(\S+)\s+v([\d\.\-a-zA-Z]+)/);
      if (m) deps.push({ name: m[1], version: m[2], ecosystem: "golang", isDirect: true });
    }
  }
  return deps;
}

export function parseCargoLock(content: string): Dependency[] {
  const deps: Dependency[] = [];
  let current: { name?: string; version?: string } = {};
  for (const line of content.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed === "[[package]]") {
      if (current.name && current.version) {
        deps.push({ name: current.name, version: current.version, ecosystem: "cargo", isDirect: false });
      }
      current = {};
    } else if (trimmed.startsWith("name = ")) {
      current.name = trimmed.slice(7).replace(/"/g, "");
    } else if (trimmed.startsWith("version = ")) {
      current.version = trimmed.slice(10).replace(/"/g, "");
    }
  }
  if (current.name && current.version) {
    deps.push({ name: current.name, version: current.version, ecosystem: "cargo", isDirect: false });
  }
  return deps;
}

export function parseCargoToml(content: string): Set<string> {
  const direct = new Set<string>();
  let inDeps = false;
  for (const line of content.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed === "[dependencies]" || trimmed === "[dev-dependencies]") { inDeps = true; continue; }
    if (trimmed.startsWith("[") && trimmed !== "[dependencies]" && trimmed !== "[dev-dependencies]") { inDeps = false; continue; }
    if (inDeps) {
      const m = trimmed.match(/^([a-zA-Z0-9_\-]+)\s*=/);
      if (m) direct.add(m[1]);
    }
  }
  return direct;
}

export function parsePomXml(content: string): Dependency[] {
  const deps: Dependency[] = [];
  const depRegex = /<dependency>([\s\S]*?)<\/dependency>/g;
  let match;
  while ((match = depRegex.exec(content)) !== null) {
    const block = match[1];
    const groupId = block.match(/<groupId>([^<]+)<\/groupId>/)?.[1]?.trim() ?? "";
    const artifactId = block.match(/<artifactId>([^<]+)<\/artifactId>/)?.[1]?.trim() ?? "";
    const version = block.match(/<version>([^<]+)<\/version>/)?.[1]?.trim() ?? "";
    const scope = block.match(/<scope>([^<]+)<\/scope>/)?.[1]?.trim() ?? "compile";
    if (groupId && artifactId) {
      deps.push({
        name: `${groupId}:${artifactId}`,
        version: version.startsWith("$") ? "" : version,
        ecosystem: "maven",
        isDirect: scope !== "test",
      });
    }
  }
  return deps;
}

// ─── OSV query ───────────────────────────────────────────────────────────────

export class RateLimitError extends Error {
  constructor(public source: string) {
    super(`Rate limited by ${source}`);
    this.name = "RateLimitError";
  }
}

export async function queryOSV(dep: Dependency): Promise<Vulnerability[]> {
  try {
    // 3-way cross-join: OSV vulns + CISA KEV + NVD CVSS scores in one query
    const rows = extractRows(
      await runCoralSql(
        `SELECT v.id, v.summary, v.details, v.severity, v.affected, v.references, v.aliases,
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
         WHERE v.package_name = ${sqlString(dep.name)}
           AND v.ecosystem    = ${sqlString(dep.ecosystem)}
           AND v.version      = ${sqlString(dep.version)}
         LIMIT 50`,
        `OSV × KEV × NVD — ${dep.name}@${dep.version} (${dep.ecosystem})`,
      ),
    );
    if (rows.length > 0) {
      return rows.map((v: any) => mapOsvRow(v, true));
    }
  } catch {
    // fall through to HTTP API
  }

  const body = {
    package: { name: dep.name, ecosystem: dep.ecosystem },
    version: dep.version,
  };
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    const res = await fetch("https://api.osv.dev/v1/query", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    clearTimeout(timeout);
    if (res.status === 429) throw new RateLimitError("OSV");
    if (!res.ok) return [];
    const data = await res.json();
    return (data.vulns ?? []).map((v: any) => mapOsvRow(v, false));
  } catch (e) {
    if (e instanceof RateLimitError) throw e;
    return [];
  }
}

function mapOsvRow(v: any, fromCoral = false): Vulnerability {
  // Coral returns JSON columns as serialized strings — parse them
  const severityRaw = fromCoral && typeof v.severity === "string"
    ? tryJsonParse(v.severity) : v.severity;
  const refsRaw = fromCoral && typeof v.references === "string"
    ? tryJsonParse(v.references) : v.references;
  const affectedRaw = fromCoral && typeof v.affected === "string"
    ? tryJsonParse(v.affected) : v.affected;
  const dbSpecific = fromCoral && typeof v.database_specific === "string"
    ? tryJsonParse(v.database_specific) : v.database_specific;

  const refs: { url: string; type?: string }[] = (refsRaw ?? []).map((r: any) => ({
    url: r.url, type: r.type,
  }));

  const advisoryUrl =
    refs.find((r) => r.type === "ADVISORY")?.url ??
    refs.find((r) => r.url?.includes("nvd.nist.gov"))?.url ??
    refs.find((r) => r.url?.includes("github.com/advisories"))?.url ??
    refs[0]?.url ?? null;

  // Severity: NVD join first (most authoritative numeric score), then OSV database_specific, then CVSS vector
  let severity: string | null = null;
  if (v.nvd_severity) severity = normalizeSeverityLabel(String(v.nvd_severity));
  if (!severity && v.nvd_base_score != null) {
    const n = parseFloat(String(v.nvd_base_score));
    if (!isNaN(n)) severity = cvssScoreToLabel(n);
  }
  if (!severity && dbSpecific?.severity) severity = normalizeSeverityLabel(String(dbSpecific.severity));
  if (!severity) severity = extractSeverity(severityRaw);

  // KEV status from cross-join columns (Coral) or HTTP aliases fallback
  const kevFromJoin = fromCoral && v.kev_cve_id != null;

  // Affected versions
  const affectedVersions: string[] = [];
  if (Array.isArray(affectedRaw)) {
    for (const a of affectedRaw) {
      if (Array.isArray(a.versions)) affectedVersions.push(...a.versions);
    }
  }

  return {
    id: v.id ?? "unknown",
    summary: v.summary ?? v.details ?? null,
    severity,
    references: refs,
    advisoryUrl,
    affectedVersions: affectedVersions.length > 0 ? affectedVersions.slice(0, 20).join(", ") : null,
    fixed_in: extractFixedVersion({ affected: affectedRaw }),
    // Expose KEV join data so langchain.ts can use it directly
    _kevFromJoin: kevFromJoin,
    _kevCveId: fromCoral ? (v.kev_cve_id ?? null) : null,
    _kevName: fromCoral ? (v.kev_name ?? null) : null,
    _kevDateAdded: fromCoral ? (v.kev_date_added ?? null) : null,
  } as any;
}

function tryJsonParse(s: string): any {
  try { return JSON.parse(s); } catch { return null; }
}

function extractFixedVersion(v: any): string | null {
  if (!Array.isArray(v.affected)) return null;
  for (const a of v.affected) {
    for (const range of a.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event.fixed) return String(event.fixed);
      }
    }
  }
  return null;
}

// ─── NVD HTTP fallback (used only when Coral NVD join returns null due to rate limit) ──

const nvdCache = new Map<string, string | null>();

export async function fetchNvdSeverity(cveId: string): Promise<string | null> {
  if (nvdCache.has(cveId)) return nvdCache.get(cveId) ?? null;
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    const res = await fetch(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`,
      { signal: controller.signal },
    );
    clearTimeout(timeout);
    if (res.status === 429) { nvdCache.set(cveId, null); return null; }
    if (!res.ok) { nvdCache.set(cveId, null); return null; }
    const data = await res.json();
    const metrics = data?.vulnerabilities?.[0]?.cve?.metrics;
    const score =
      metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore ??
      metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore ??
      metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore ??
      null;
    const severity = score != null ? cvssScoreToLabel(parseFloat(score)) : null;
    nvdCache.set(cveId, severity);
    return severity;
  } catch {
    nvdCache.set(cveId, null);
    return null;
  }
}

// ─── EPSS score ───────────────────────────────────────────────────────────────

const epssCache = new Map<string, number | null>();

export async function fetchEpssScore(cveId: string): Promise<number | null> {
  if (epssCache.has(cveId)) return epssCache.get(cveId) ?? null;
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    const res = await fetch(
      `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(cveId)}`,
      { signal: controller.signal },
    );
    clearTimeout(timeout);
    if (!res.ok) { epssCache.set(cveId, null); return null; }
    const data = await res.json();
    const score = data?.data?.[0]?.epss != null ? parseFloat(data.data[0].epss) : null;
    epssCache.set(cveId, score);
    return score;
  } catch {
    epssCache.set(cveId, null);
    return null;
  }
}

// ─── KEV ─────────────────────────────────────────────────────────────────────

let cachedKev: Set<string> | null = null;

export async function loadKev(): Promise<Set<string>> {
  if (cachedKev) return cachedKev;
  const set = new Set<string>();
  try {
    const rows = extractRows(
      await runCoralSql(`SELECT cve_id FROM cisa_kev.vulnerabilities`, "cisa_kev — load all CVE IDs", true),
    );
    if (rows.length > 0) {
      rows.forEach((r: any) => {
        const cveId = String(r.cve_id ?? "");
        if (cveId.match(/CVE-\d{4}-\d{4,7}/i)) set.add(cveId.toUpperCase());
      });
      cachedKev = set;
      return set;
    }
  } catch {
    // fall through to HTTP
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const res = await fetch(
      "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
      { signal: controller.signal },
    );
    clearTimeout(timeout);
    if (!res.ok) return set;
    const data = await res.json();
    if (Array.isArray(data)) {
      data.forEach((it: any) => { if (it.cveID) set.add(it.cveID); });
    } else if (data?.vulnerabilities) {
      data.vulnerabilities.forEach((it: any) => { if (it.cveID) set.add(it.cveID); });
    }
    cachedKev = set;
    return set;
  } catch {
    return set;
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function cvssScoreToLabel(score: number): string {
  if (score >= 9.0) return "CRITICAL";
  if (score >= 7.0) return "HIGH";
  if (score >= 4.0) return "MEDIUM";
  return "LOW";
}

/** Parse a CVSS vector string and extract the base score via the AV/AC/etc metrics. */
function cvssVectorToScore(vector: string): number | null {
  // CVSS v3 base score approximation from vector string
  // We use the environmental score shortcut: look for known high-signal metrics
  // Full calculation is complex; instead extract the numeric score from NVD-style vectors
  // OSV sometimes embeds the score as the last segment: "CVSS:3.1/.../X.X"
  // But more reliably, we map common vector patterns to approximate scores.
  // The simplest reliable approach: parse AV, AC, PR, UI, S, C, I, A weights.
  const v3Match = vector.match(/CVSS:3\.[01]\/(AV:[NALP])\/(AC:[LH])\/(PR:[NLH])\/(UI:[NR])\/(S:[UC])\/(C:[NLH])\/(I:[NLH])\/(A:[NLH])/);
  if (!v3Match) return null;

  const [, av, ac, pr, ui, s, c, i, a] = v3Match;

  // ISS = 1 - [(1-ImpactConf) × (1-ImpactInteg) × (1-ImpactAvail)]
  const cScore = c === "C:H" ? 0.56 : c === "C:L" ? 0.22 : 0;
  const iScore = i === "I:H" ? 0.56 : i === "I:L" ? 0.22 : 0;
  const aScore = a === "A:H" ? 0.56 : a === "A:L" ? 0.22 : 0;
  const iss = 1 - (1 - cScore) * (1 - iScore) * (1 - aScore);

  // Impact sub-score
  const impact = s === "S:U"
    ? 6.42 * iss
    : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);

  if (impact <= 0) return 0;

  // Exploitability sub-score
  const avW = av === "AV:N" ? 0.85 : av === "AV:A" ? 0.62 : av === "AV:L" ? 0.55 : 0.2;
  const acW = ac === "AC:L" ? 0.77 : 0.44;
  const prW = pr === "PR:N" ? 0.85 : pr === "PR:L" ? (s === "S:C" ? 0.68 : 0.62) : (s === "S:C" ? 0.5 : 0.27);
  const uiW = ui === "UI:N" ? 0.85 : 0.62;
  const exploitability = 8.22 * avW * acW * prW * uiW;

  const base = s === "S:U"
    ? Math.min(impact + exploitability, 10)
    : Math.min(1.08 * (impact + exploitability), 10);

  return Math.round(base * 10) / 10;
}

/** Normalize a plain-text severity label to CRITICAL/HIGH/MEDIUM/LOW. */
function normalizeSeverityLabel(raw: string): string | null {
  const u = raw.toUpperCase().trim();
  if (u === "CRITICAL") return "CRITICAL";
  if (u === "HIGH") return "HIGH";
  if (u === "MEDIUM" || u === "MODERATE") return "MEDIUM";
  if (u === "LOW") return "LOW";
  return null;
}

function extractSeverity(raw: any): string | null {
  if (!raw) return null;

  // Plain string label
  if (typeof raw === "string") {
    const normalized = normalizeSeverityLabel(raw);
    if (normalized) return normalized;
    // Could be a CVSS vector string directly
    const score = cvssVectorToScore(raw);
    if (score !== null) return cvssScoreToLabel(score);
    return null;
  }

  // Array of severity objects (OSV HTTP format)
  const items: any[] = Array.isArray(raw) ? raw : [raw];

  for (const item of items) {
    if (!item) continue;
    const scoreStr = String(item.score ?? "");

    // Numeric score
    const numeric = parseFloat(scoreStr);
    if (!isNaN(numeric) && numeric > 0) return cvssScoreToLabel(numeric);

    // CVSS vector string in score field
    if (scoreStr.startsWith("CVSS:")) {
      const computed = cvssVectorToScore(scoreStr);
      if (computed !== null) return cvssScoreToLabel(computed);
    }

    // Plain label in type field (fallback)
    if (item.type) {
      const normalized = normalizeSeverityLabel(String(item.type));
      if (normalized) return normalized;
    }
  }

  return null;
}
