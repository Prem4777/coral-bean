import { URL } from "url";

import {
  createScanJob,
  completeScanJob,
  failScanJob,
  saveScanFindings,
} from "@/lib/scan-store";
import {
  fetchGitHubFile,
  parsePackageJson,
  parseRequirementsTxt,
  queryOSV,
  loadKev,
} from "@/lib/security";
import { generateSecuritySummary } from "@/lib/gemini";

type RunScanResult = {
  scanId: string;
  repo: string;
  findings: Record<string, any>;
  summary: string | null;
};

function parseRepo(url: string) {
  try {
    const u = new URL(url);
    const parts = u.pathname.split("/").filter(Boolean);
    if (parts.length < 2) return null;
    return { owner: parts[0], repo: parts[1] };
  } catch {
    return null;
  }
}

export async function runScanChain(
  repoUrl: string,
  onProgress?: (evt: { type: string; message?: string; meta?: any }) => void,
  existingScanJobId?: string,
): Promise<RunScanResult> {
  const parsed = parseRepo(repoUrl);
  if (!parsed) throw new Error("Invalid repo URL");

  const token = process.env.GITHUB_TOKEN;
  const { owner, repo } = parsed;
  const scanJob = existingScanJobId
    ? { id: existingScanJobId }
    : await createScanJob({ repositoryUrl: repoUrl, owner, repo });

  try {
    onProgress?.({
      type: "started",
      message: `Scan started for ${owner}/${repo}`,
    });

    const filesToCheck = [
      "package.json",
      "requirements.txt",
    ];

    // Fetch all manifest files in parallel
    const fetchResults = await Promise.allSettled(
      filesToCheck.map((path) => fetchGitHubFile(owner, repo, path, token)),
    );
    const fetched: Record<string, string | null> = {};
    fetchResults.forEach((result, i) => {
      const path = filesToCheck[i];
      fetched[path] =
        result.status === "fulfilled" ? result.value : null;
      onProgress?.({
        type: "fetched",
        message: fetched[path] ? `Fetched ${path}` : `Missing ${path}`,
        meta: { path },
      });
    });

    const deps: any[] = [];
    if (fetched["package.json"]) {
      deps.push(...parsePackageJson(fetched["package.json"]!));
      onProgress?.({ type: "parsed", message: "Parsed package.json" });
    }
    if (fetched["requirements.txt"]) {
      deps.push(...parseRequirementsTxt(fetched["requirements.txt"]!));
      onProgress?.({ type: "parsed", message: "Parsed requirements.txt" });
    }

    const unique = new Map<string, any>();
    for (const d of deps.slice(0, 50)) {
      const key = `${d.name}@${d.version || ""}`;
      if (!unique.has(key)) unique.set(key, d);
    }

    const kev = await loadKev();

    const results: Record<string, any> = {};
    const findingsToPersist: Array<any> = [];

    // Process OSV queries in parallel with a concurrency limit of 8
    const depList = Array.from(unique.values());
    const CONCURRENCY = 8;

    async function processOne(d: any, index: number) {
      onProgress?.({
        type: "processing",
        message: `Checking ${d.name}`,
        meta: { index },
      });

      const vulns = await queryOSV(d);
      const mapped = vulns.map((v: any) => {
        const kevStatus = (() => {
          const refs = v.references ?? [];
          for (const r of refs) {
            const m = (r.url || "").match(/CVE-\d{4}-\d{4,7}/i);
            if (m && kev.has(m[0].toUpperCase())) return true;
          }
          if (typeof v.id === "string") {
            const m2 = v.id.match(/CVE-\d{4}-\d{4,7}/i);
            if (m2 && kev.has(m2[0].toUpperCase())) return true;
          }
          return false;
        })();

        const cveId =
          (typeof v.id === "string" &&
            v.id.match(/CVE-\d{4}-\d{4,7}/i)?.[0]) ||
          (v.references ?? [])
            .map((r: any) => String(r.url ?? ""))
            .find((url: string) => url.match(/CVE-\d{4}-\d{4,7}/i))
            ?.match(/CVE-\d{4}-\d{4,7}/i)?.[0] ||
          null;

        findingsToPersist.push({
          packageName: d.name,
          ecosystem: d.ecosystem,
          vulnerabilityId: v.id,
          cveId,
          kevStatus,
          severity: String(v.severity ?? "unknown"),
          summary: String(v.summary ?? "No summary available"),
          fix: String(v.fixed_in ?? "unknown"),
        });

        return {
          id: v.id,
          cveId,
          summary: v.summary,
          severity: typeof v.severity === "string" ? v.severity : null,
          fixed_in: v.fixed_in ?? null,
          references: v.references ?? [],
          kev: kevStatus,
        };
      });

      return { key: `${d.name}@${d.version || ""}`, mapped };
    }

    // Run in batches of CONCURRENCY
    for (let i = 0; i < depList.length; i += CONCURRENCY) {
      const batch = depList.slice(i, i + CONCURRENCY);
      const batchResults = await Promise.allSettled(
        batch.map((d, j) => processOne(d, i + j + 1)),
      );
      for (const r of batchResults) {
        if (r.status === "fulfilled") {
          results[r.value.key] = r.value.mapped;
        }
      }
    }

    onProgress?.({ type: "persisting", message: "Saving findings to DB" });
    await saveScanFindings(scanJob.id, findingsToPersist);
    await completeScanJob(scanJob.id);

    onProgress?.({ type: "summarizing", message: "Generating summary" });
    const summary = await generateSecuritySummary({
      repo: `${owner}/${repo}`,
      findings: results,
    });

    onProgress?.({ type: "done", message: "Scan completed" });

    return {
      scanId: scanJob.id,
      repo: `${owner}/${repo}`,
      findings: results,
      summary,
    };
  } catch (err) {
    try {
      await failScanJob(scanJob.id);
    } catch {}
    onProgress?.({
      type: "error",
      message: (err instanceof Error && err.message) || String(err),
    });
    throw err;
  }
}

export default {
  runScanChain,
};
