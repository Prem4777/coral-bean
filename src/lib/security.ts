import { runCoralSql, sqlString } from "@/lib/coral";

export type Dependency = {
  name: string;
  version: string;
  ecosystem: "npm" | "pypi" | "maven" | "cargo" | "golang" | string;
};

export type Vulnerability = {
  id: string; // OSV or CVE
  summary?: string;
  severity?: string | null;
  fixed_in?: string | null;
  references?: { url: string; type?: string }[];
  kev?: boolean;
};

function extractRows(payload: unknown) {
  if (Array.isArray(payload)) return payload as any[];
  if (!payload || typeof payload !== "object") return [] as any[];
  const data = payload as { items?: unknown[]; rows?: unknown[]; vulnerabilities?: unknown[] };
  return (data.items ?? data.rows ?? data.vulnerabilities ?? []) as any[];
}

export async function fetchGitHubFile(
  owner: string,
  repo: string,
  path: string,
  token?: string,
) {
  try {
    const rows = extractRows(
      await runCoralSql(
        `SELECT content_text FROM "github"."contents" WHERE owner = ${sqlString(owner)} AND repo = ${sqlString(repo)} AND path = ${sqlString(path)} LIMIT 1`,
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

  // Fallback to GitHub REST API
  const url = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}`;
  const headers: Record<string, string> = {
    Accept: "application/vnd.github.v3.raw",
  };
  if (token) headers["Authorization"] = `token ${token}`;
  const res = await fetch(url, { headers });
  if (res.status === 200) return res.text();
  return null;
}

export function parsePackageJson(content: string) {
  try {
    const json = JSON.parse(content);
    const deps = {
      ...(json.dependencies ?? {}),
      ...(json.devDependencies ?? {}),
    };
    return Object.entries(deps).map(([name, version]) => ({
      name,
      version:
        typeof version === "string" ? version.replace(/^[^0-9]*/, "") : "",
      ecosystem: "npm" as const,
    }));
  } catch {
    return [] as Dependency[];
  }
}

export function parseRequirementsTxt(content: string) {
  return content
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"))
    .map((line) => {
      // simple parsing: pkg==version or pkg>=version
      const m = line.match(
        /^([^=<>!~\[\]\s]+)\s*([=<>~!]+)?\s*([\d\.a-zA-Z\-]*)/,
      );
      const name = m ? m[1] : line;
      const version = m && m[3] ? m[3] : "";
      return { name, version, ecosystem: "pypi" as const };
    });
}

export async function queryOSV(dep: Dependency) {
  try {
    const rows = extractRows(
      await runCoralSql(
        `SELECT * FROM osv.query_by_version(package_name => ${sqlString(dep.name)}, ecosystem => ${sqlString(dep.ecosystem)}, version => ${sqlString(dep.version)})`,
      ),
    );
    if (rows.length > 0) {
      return rows.map((v: any) => ({
        id: v.id ?? v.summary ?? "unknown",
        summary: v.summary ?? null,
        severity: extractSeverity(v.severity),
        references: (v.references ?? []).map((r: any) => ({
          url: r.url,
          type: r.type,
        })),
        fixed_in:
          v.versions && v.versions.length > 0
            ? String(v.versions[v.versions.length - 1])
            : null,
      })) as Vulnerability[];
    }
  } catch {
    // fall through to HTTP API
  }

  // Fallback to OSV HTTP API
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
    if (!res.ok) return [] as Vulnerability[];
    const data = await res.json();
    const vulns: Vulnerability[] = (data.vulns ?? []).map((v: any) => ({
      id: v.id ?? v.summary ?? "unknown",
      summary: v.summary ?? null,
      severity: extractSeverity(v.severity),
      references: (v.references ?? []).map((r: any) => ({
        url: r.url,
        type: r.type,
      })),
      fixed_in:
        v.versions && v.versions.length > 0
          ? String(v.versions[v.versions.length - 1])
          : null,
    }));
    return vulns;
  } catch (e) {
    return [] as Vulnerability[];
  }
}

let cachedKev: Set<string> | null = null;

// OSV HTTP API returns severity as [{type:"CVSS_V3", score:"7.5"}].
// Map it to a plain CRITICAL/HIGH/MEDIUM/LOW string.
function extractSeverity(raw: any): string | null {
  if (!raw) return null;
  if (typeof raw === "string") return raw;
  const item = Array.isArray(raw) ? raw[0] : raw;
  if (!item) return null;
  const score = parseFloat(String(item.score ?? ""));
  if (!isNaN(score)) {
    if (score >= 9.0) return "CRITICAL";
    if (score >= 7.0) return "HIGH";
    if (score >= 4.0) return "MEDIUM";
    return "LOW";
  }
  return item.type ? String(item.type) : null;
}
export async function loadKev() {
  if (cachedKev) return cachedKev;
  const set = new Set<string>();
  try {
    const rows = extractRows(await runCoralSql(`SELECT * FROM "cisa_kev"."vulnerabilities"`));
    if (rows.length > 0) {
      rows.forEach((r: any) => {
        const text = String(
          r.cveID ?? r.cve ?? r.id ?? r.name ?? r.description ?? "",
        );
        const m = text.match(/CVE-\d{4}-\d{4,7}/gi);
        if (m) m.forEach((c) => set.add(c.toUpperCase()));
      });
      cachedKev = set;
      return set;
    }
  } catch {
    // fall back to HTTP
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
      data.forEach((it: any) => {
        if (it.cveID) set.add(it.cveID);
        if (it.cve) set.add(it.cve);
      });
    } else if (data && data.vulnerabilities) {
      data.vulnerabilities.forEach((it: any) => it.cveID && set.add(it.cveID));
    }
    cachedKev = set;
    return set;
  } catch (e) {
    return set;
  }
}
