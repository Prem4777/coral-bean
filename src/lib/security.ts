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

// ─── GitHub file fetching (Coral only) ───────────────────────────────────────

export async function fetchGitHubFile(
  owner: string,
  repo: string,
  path: string,
): Promise<string | null> {
  const rows = extractRows(
    await runCoralSql(
      `SELECT content_text FROM github.contents WHERE owner = ${sqlString(owner)} AND repo = ${sqlString(repo)} AND path = ${sqlString(path)} LIMIT 1`,
      `github.contents — ${owner}/${repo}/${path}`,
      true,
    ),
  );
  if (rows.length > 0) {
    const first = rows[0] as Record<string, unknown>;
    if (first && "content_text" in first) return String(first.content_text ?? "");
  }
  return null;
}

/** Fetch the latest commit SHA via GitHub Coral table. */
export async function fetchCommitSha(
  owner: string,
  repo: string,
): Promise<string | null> {
  try {
    const rows = extractRows(
      await runCoralSql(
        `SELECT sha FROM github.repo_git_commits WHERE owner = ${sqlString(owner)} AND repo = ${sqlString(repo)} LIMIT 1`,
        `github.commits — ${owner}/${repo}`,
        true,
      ),
    );
    if (rows.length > 0 && rows[0]?.sha) return String(rows[0].sha);
  } catch { /* fall through */ }
  // Fallback: GitHub REST (only for SHA — no Coral table returns HEAD sha directly)
  try {
    const res = await fetch(`https://api.github.com/repos/${owner}/${repo}/commits/HEAD`, {
      headers: { Accept: "application/vnd.github.v3+json" },
    });
    if (!res.ok) return null;
    const data = await res.json();
    return typeof data?.sha === "string" ? data.sha : null;
  } catch { return null; }
}

// ─── Manifest parsers ────────────────────────────────────────────────────────

export function parsePackageJson(content: string): Dependency[] {
  try {
    const json = JSON.parse(content);
    const direct = new Set(Object.keys(json.dependencies ?? {}));
    const deps = { ...(json.dependencies ?? {}), ...(json.devDependencies ?? {}) };
    return Object.entries(deps).map(([name, version]) => ({
      name,
      version: typeof version === "string" ? version.replace(/^[^0-9]*/, "") : "",
      ecosystem: "npm" as const,
      isDirect: direct.has(name),
    }));
  } catch { return []; }
}

export function parseRequirementsTxt(content: string): Dependency[] {
  return content.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#"))
    .map((line) => {
      const m = line.match(/^([^=<>!~\[\]\s]+)\s*([=<>~!]+)?\s*([\d\.a-zA-Z\-]*)/);
      return { name: m ? m[1] : line, version: m?.[3] ?? "", ecosystem: "pypi" as const, isDirect: true };
    });
}

export function parseGoSum(content: string): Dependency[] {
  const deps: Dependency[] = [];
  const seen = new Set<string>();
  for (const line of content.split(/\r?\n/)) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 2) continue;
    const [module, versionRaw] = parts;
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
      if (current.name && current.version)
        deps.push({ name: current.name, version: current.version, ecosystem: "cargo", isDirect: false });
      current = {};
    } else if (trimmed.startsWith("name = ")) {
      current.name = trimmed.slice(7).replace(/"/g, "");
    } else if (trimmed.startsWith("version = ")) {
      current.version = trimmed.slice(10).replace(/"/g, "");
    }
  }
  if (current.name && current.version)
    deps.push({ name: current.name, version: current.version, ecosystem: "cargo", isDirect: false });
  return deps;
}

export function parseCargoToml(content: string): Set<string> {
  const direct = new Set<string>();
  let inDeps = false;
  for (const line of content.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed === "[dependencies]" || trimmed === "[dev-dependencies]") { inDeps = true; continue; }
    if (trimmed.startsWith("[") && inDeps) { inDeps = false; continue; }
    if (inDeps) { const m = trimmed.match(/^([a-zA-Z0-9_\-]+)\s*=/); if (m) direct.add(m[1]); }
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
    if (groupId && artifactId)
      deps.push({ name: `${groupId}:${artifactId}`, version: version.startsWith("$") ? "" : version, ecosystem: "maven", isDirect: scope !== "test" });
  }
  return deps;
}

// ─── OSV + KEV query (Coral single source of truth) ──────────────────────────

export class RateLimitError extends Error {
  constructor(public source: string) { super(`Rate limited by ${source}`); this.name = "RateLimitError"; }
}

export async function queryOSV(dep: Dependency): Promise<Vulnerability[]> {
  // 3-way cross-join: OSV × CISA KEV × NVD — all via Coral
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
  return rows.map((v: any) => mapOsvRow(v));
}

function mapOsvRow(v: any): Vulnerability {
  const severityRaw = typeof v.severity === "string" ? tryJsonParse(v.severity) : v.severity;
  const refsRaw     = typeof v.references === "string" ? tryJsonParse(v.references) : v.references;
  const affectedRaw = typeof v.affected === "string" ? tryJsonParse(v.affected) : v.affected;

  const refs: { url: string; type?: string }[] = (refsRaw ?? []).map((r: any) => ({ url: r.url, type: r.type }));

  const advisoryUrl =
    refs.find((r) => r.type === "ADVISORY")?.url ??
    refs.find((r) => r.url?.includes("nvd.nist.gov"))?.url ??
    refs.find((r) => r.url?.includes("github.com/advisories"))?.url ??
    refs[0]?.url ?? null;

  // Severity: NVD (most authoritative) → OSV CVSS vector → fallback
  let severity: string | null = null;
  if (v.nvd_severity) severity = normalizeSeverityLabel(String(v.nvd_severity));
  if (!severity && v.nvd_base_score != null) {
    const n = parseFloat(String(v.nvd_base_score));
    if (!isNaN(n)) severity = cvssScoreToLabel(n);
  }
  if (!severity) severity = extractSeverity(severityRaw);

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
    _kevFromJoin: v.kev_cve_id != null,
    _kevCveId: v.kev_cve_id ?? null,
    _kevName: v.kev_name ?? null,
    _kevDateAdded: v.kev_date_added ?? null,
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

// ─── KEV set (Coral only — used as fallback for HTTP path) ───────────────────

let cachedKev: Set<string> | null = null;

export async function loadKev(): Promise<Set<string>> {
  if (cachedKev) return cachedKev;
  const set = new Set<string>();
  const rows = extractRows(
    await runCoralSql(`SELECT cve_id FROM cisa_kev.vulnerabilities`, "cisa_kev — load all CVE IDs", true),
  );
  rows.forEach((r: any) => {
    const cveId = String(r.cve_id ?? "");
    if (cveId.match(/CVE-\d{4}-\d{4,7}/i)) set.add(cveId.toUpperCase());
  });
  cachedKev = set;
  return set;
}

// ─── EPSS score (HTTP only — no Coral source) ────────────────────────────────

const epssCache = new Map<string, number | null>();

export async function fetchEpssScore(cveId: string): Promise<number | null> {
  if (epssCache.has(cveId)) return epssCache.get(cveId) ?? null;
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    const res = await fetch(`https://api.first.org/data/v1/epss?cve=${encodeURIComponent(cveId)}`, { signal: controller.signal });
    clearTimeout(timeout);
    if (!res.ok) { epssCache.set(cveId, null); return null; }
    const data = await res.json();
    const score = data?.data?.[0]?.epss != null ? parseFloat(data.data[0].epss) : null;
    epssCache.set(cveId, score);
    return score;
  } catch { epssCache.set(cveId, null); return null; }
}

// ─── NVD HTTP fallback (only if Coral NVD join returns null due to rate limit) ─

const nvdCache = new Map<string, string | null>();

export async function fetchNvdSeverity(cveId: string): Promise<string | null> {
  if (nvdCache.has(cveId)) return nvdCache.get(cveId) ?? null;
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    const res = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`, { signal: controller.signal });
    clearTimeout(timeout);
    if (!res.ok) { nvdCache.set(cveId, null); return null; }
    const data = await res.json();
    const metrics = data?.vulnerabilities?.[0]?.cve?.metrics;
    const score = metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore ?? metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore ?? null;
    const severity = score != null ? cvssScoreToLabel(parseFloat(score)) : null;
    nvdCache.set(cveId, severity);
    return severity;
  } catch { nvdCache.set(cveId, null); return null; }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function cvssScoreToLabel(score: number): string {
  if (score >= 9.0) return "CRITICAL";
  if (score >= 7.0) return "HIGH";
  if (score >= 4.0) return "MEDIUM";
  return "LOW";
}

function cvssVectorToScore(vector: string): number | null {
  const m = vector.match(/CVSS:3\.[01]\/(AV:[NALP])\/(AC:[LH])\/(PR:[NLH])\/(UI:[NR])\/(S:[UC])\/(C:[NLH])\/(I:[NLH])\/(A:[NLH])/);
  if (!m) return null;
  const [, av, ac, pr, ui, s, c, i, a] = m;
  const cS = c === "C:H" ? 0.56 : c === "C:L" ? 0.22 : 0;
  const iS = i === "I:H" ? 0.56 : i === "I:L" ? 0.22 : 0;
  const aS = a === "A:H" ? 0.56 : a === "A:L" ? 0.22 : 0;
  const iss = 1 - (1 - cS) * (1 - iS) * (1 - aS);
  const impact = s === "S:U" ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  if (impact <= 0) return 0;
  const avW = av === "AV:N" ? 0.85 : av === "AV:A" ? 0.62 : av === "AV:L" ? 0.55 : 0.2;
  const acW = ac === "AC:L" ? 0.77 : 0.44;
  const prW = pr === "PR:N" ? 0.85 : pr === "PR:L" ? (s === "S:C" ? 0.68 : 0.62) : (s === "S:C" ? 0.5 : 0.27);
  const uiW = ui === "UI:N" ? 0.85 : 0.62;
  const exp = 8.22 * avW * acW * prW * uiW;
  return Math.round(Math.min(s === "S:U" ? impact + exp : 1.08 * (impact + exp), 10) * 10) / 10;
}

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
  if (typeof raw === "string") {
    return normalizeSeverityLabel(raw) ?? (cvssVectorToScore(raw) !== null ? cvssScoreToLabel(cvssVectorToScore(raw)!) : null);
  }
  const items: any[] = Array.isArray(raw) ? raw : [raw];
  for (const item of items) {
    if (!item) continue;
    const scoreStr = String(item.score ?? "");
    const numeric = parseFloat(scoreStr);
    if (!isNaN(numeric) && numeric > 0) return cvssScoreToLabel(numeric);
    if (scoreStr.startsWith("CVSS:")) {
      const computed = cvssVectorToScore(scoreStr);
      if (computed !== null) return cvssScoreToLabel(computed);
    }
    if (item.type) { const n = normalizeSeverityLabel(String(item.type)); if (n) return n; }
  }
  return null;
}
