import {
  createScanJob,
  completeScanJob,
  failScanJob,
  saveScanFindings,
  findScanByCommitSha,
} from "@/lib/scan-store";
import {
  fetchGitHubFile,
  fetchCommitSha,
  parsePackageJson,
  parseRequirementsTxt,
  parseGoMod,
  parseGoSum,
  parseCargoLock,
  parseCargoToml,
  parsePomXml,
  queryOSV,
  loadKev,
  fetchNvdSeverity,
  fetchEpssScore,
  RateLimitError,
  type Dependency,
} from "@/lib/security";
import { generateSecuritySummary } from "@/lib/gemini";

type ProgressEvent = { type: string; message?: string; meta?: any };

type RunScanResult = {
  scanId: string;
  repo: string;
  findings: Record<string, any>;
  summary: string | null;
  cachedSha?: string | null;
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
  onProgress?: (evt: ProgressEvent) => void,
  existingScanJobId?: string,
): Promise<RunScanResult> {
  const parsed = parseRepo(repoUrl);
  if (!parsed) throw new Error("Invalid repo URL");

  const { owner, repo } = parsed;

  // ── SHA-based cache check ────────────────────────────────────────────────
  onProgress?.({ type: "started", message: `Resolving commit SHA for ${owner}/${repo}` });
  const commitSha = await fetchCommitSha(owner, repo);

  if (commitSha) {
    const cached = await findScanByCommitSha(commitSha);
    if (cached) {
      onProgress?.({ type: "cache_hit", message: "Returning cached scan for this commit" });
      // Re-shape cached findings into FindingsMap
      const findings: Record<string, any> = {};
      for (const f of cached.findings) {
        const key = `${f.packageName}@${f.ecosystem}`;
        findings[key] = findings[key] ?? [];
        findings[key].push({
          id: f.vulnerabilityId,
          cveId: f.cveId,
          summary: f.summary,
          severity: f.severity,
          fixed_in: f.fix,
          affectedVersions: f.affectedVersions,
          advisoryUrl: f.advisoryUrl,
          epssScore: f.epssScore,
          isDirect: f.isDirect,
          kev: f.kevStatus,
          references: [],
        });
      }
      return {
        scanId: cached.job.id,
        repo: `${owner}/${repo}`,
        findings,
        summary: null,
        cachedSha: commitSha,
      };
    }
  }

  const scanJob = existingScanJobId
    ? { id: existingScanJobId }
    : await createScanJob({ repositoryUrl: repoUrl, owner, repo, commitSha });

  const rateLimitedSources: string[] = [];

  try {
    onProgress?.({ type: "started", message: `Scan started for ${owner}/${repo}` });

    // ── Fetch all manifest files in parallel ─────────────────────────────
    const manifests = [
      "package.json",
      "requirements.txt",
      "go.mod",
      "go.sum",
      "Cargo.lock",
      "Cargo.toml",
      "pom.xml",
    ];

    const fetchResults = await Promise.allSettled(
      manifests.map((path) => fetchGitHubFile(owner, repo, path)),
    );

    const fetched: Record<string, string | null> = {};
    fetchResults.forEach((result, i) => {
      const path = manifests[i];
      fetched[path] = result.status === "fulfilled" ? result.value : null;
      onProgress?.({
        type: "fetched",
        message: fetched[path] ? `Fetched ${path}` : `Missing ${path}`,
        meta: { path },
      });
    });

    // ── Parse dependencies ───────────────────────────────────────────────
    const deps: Dependency[] = [];

    if (fetched["package.json"]) {
      deps.push(...parsePackageJson(fetched["package.json"]!));
      onProgress?.({ type: "parsed", message: "Parsed package.json (npm)" });
    }
    if (fetched["requirements.txt"]) {
      deps.push(...parseRequirementsTxt(fetched["requirements.txt"]!));
      onProgress?.({ type: "parsed", message: "Parsed requirements.txt (PyPI)" });
    }
    if (fetched["go.mod"]) {
      const goModDeps = parseGoMod(fetched["go.mod"]!);
      // go.sum has all transitive deps; mark go.mod ones as direct
      const directNames = new Set(goModDeps.filter((d) => d.isDirect).map((d) => d.name));
      if (fetched["go.sum"]) {
        const goSumDeps = parseGoSum(fetched["go.sum"]!);
        deps.push(...goSumDeps.map((d) => ({ ...d, isDirect: directNames.has(d.name) })));
      } else {
        deps.push(...goModDeps);
      }
      onProgress?.({ type: "parsed", message: "Parsed go.mod / go.sum (Go)" });
    }
    if (fetched["Cargo.lock"]) {
      const cargoDeps = parseCargoLock(fetched["Cargo.lock"]!);
      const directNames = fetched["Cargo.toml"]
        ? parseCargoToml(fetched["Cargo.toml"]!)
        : new Set<string>();
      deps.push(...cargoDeps.map((d) => ({ ...d, isDirect: directNames.has(d.name) })));
      onProgress?.({ type: "parsed", message: "Parsed Cargo.lock (Rust)" });
    }
    if (fetched["pom.xml"]) {
      deps.push(...parsePomXml(fetched["pom.xml"]!));
      onProgress?.({ type: "parsed", message: "Parsed pom.xml (Maven)" });
    }

    // Deduplicate, cap at 100
    const unique = new Map<string, Dependency>();
    for (const d of deps.slice(0, 100)) {
      const key = `${d.name}@${d.version || ""}@${d.ecosystem}`;
      if (!unique.has(key)) unique.set(key, d);
    }

    const kev = await loadKev();
    const results: Record<string, any> = {};
    const findingsToPersist: Array<any> = [];
    const CONCURRENCY = 8;
    const depList = Array.from(unique.values());

    async function processOne(d: Dependency, index: number) {
      onProgress?.({ type: "processing", message: `Checking ${d.name}`, meta: { index } });

      let vulns;
      try {
        vulns = await queryOSV(d);
      } catch (e) {
        if (e instanceof RateLimitError) {
          rateLimitedSources.push("OSV");
          return { key: `${d.name}@${d.version || ""}@${d.ecosystem}`, mapped: [] };
        }
        return { key: `${d.name}@${d.version || ""}@${d.ecosystem}`, mapped: [] };
      }

      const mapped = await Promise.all(
        vulns.map(async (v: any) => {
          // KEV status: use cross-join result from Coral if available,
          // otherwise fall back to the separately loaded KEV set
          const kevStatus: boolean =
            v._kevFromJoin === true ||
            (() => {
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

          // CVE ID: from cross-join kev_cve_id, or aliases, or references
          const cveId: string | null =
            v._kevCveId ??
            (
              (typeof v.id === "string" && v.id.match(/CVE-\d{4}-\d{4,7}/i)?.[0]) ||
              (v.references ?? [])
                .map((r: any) => String(r.url ?? ""))
                .find((url: string) => url.match(/CVE-\d{4}-\d{4,7}/i))
                ?.match(/CVE-\d{4}-\d{4,7}/i)?.[0] ||
              null
            );

          // NVD fallback for unknown severity
          let severity = v.severity ?? null;
          if ((!severity || severity === "unknown") && cveId) {
            const nvdSev = await fetchNvdSeverity(cveId).catch(() => null);
            if (nvdSev) severity = nvdSev;
          }

          // EPSS score
          let epssScore: number | null = null;
          if (cveId) {
            epssScore = await fetchEpssScore(cveId).catch(() => null);
          }

          findingsToPersist.push({
            packageName: d.name,
            ecosystem: d.ecosystem,
            vulnerabilityId: v.id,
            cveId,
            kevStatus,
            severity: String(severity ?? "unknown"),
            summary: String(v.summary ?? "No summary available"),
            fix: String(v.fixed_in ?? "unknown"),
            affectedVersions: v.affectedVersions ?? null,
            advisoryUrl: v.advisoryUrl ?? null,
            epssScore,
            isDirect: d.isDirect ?? true,
          });

          return {
            id: v.id,
            cveId,
            summary: v.summary,
            severity: typeof severity === "string" ? severity : null,
            fixed_in: v.fixed_in ?? null,
            affectedVersions: v.affectedVersions ?? null,
            advisoryUrl: v.advisoryUrl ?? null,
            epssScore,
            isDirect: d.isDirect ?? true,
            references: v.references ?? [],
            kev: kevStatus,
          };
        }),
      );

      return { key: `${d.name}@${d.version || ""}@${d.ecosystem}`, mapped };
    }

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

    onProgress?.({ type: "persisting", message: "Saving findings" });
    await saveScanFindings(scanJob.id, findingsToPersist);
    await completeScanJob(scanJob.id);

    onProgress?.({ type: "summarizing", message: "Generating AI summary" });
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
      cachedSha: null,
      ...(rateLimitedSources.length > 0
        ? { rateLimitWarning: `Rate limited by: ${[...new Set(rateLimitedSources)].join(", ")}. Results may be incomplete.` }
        : {}),
    };
  } catch (err) {
    try { await failScanJob(scanJob.id); } catch {}
    onProgress?.({ type: "error", message: (err instanceof Error && err.message) || String(err) });
    throw err;
  }
}

export default { runScanChain };
