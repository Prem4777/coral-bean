# KEVGuard Project Development Report

## 1. Project Summary

KEVGuard is an AI-powered AppSec tool that scans a public GitHub repository, extracts dependency information, checks known vulnerabilities, correlates active exploitation intelligence (CISA KEV), and provides actionable remediation guidance.

Core data sources: GitHub · OSV · CISA KEV · NVD · EPSS (first.org)

---

## 2. Tech Stack

- **Frontend**: Next.js 16 (App Router), TypeScript, Tailwind CSS v4
- **Backend**: Next.js API routes, SSE streaming
- **AI**: Gemini REST API (summary + chat agent)
- **Data bridge**: Coral MCP bridge (local SQL proxy over OSV + KEV + GitHub)
- **Persistence**: In-memory scan store (Drizzle/Neon schema defined but not used at runtime)

---

## 3. Architecture

1. User submits GitHub repo URL
2. HEAD commit SHA resolved → cache check (skip re-scan if same SHA)
3. Manifest files fetched in parallel (Coral-first, GitHub REST fallback)
4. Dependencies parsed per ecosystem
5. Each dep queried via **cross-join SQL**: `osv.query_by_version LEFT JOIN cisa_kev.vulnerabilities ON aliases LIKE '%' || cve_id || '%'`
6. Unknown severities resolved via NVD HTTP API
7. EPSS scores fetched from first.org
8. Findings persisted to in-memory store
9. Gemini generates AI summary
10. UI renders metrics, vuln cards, risk breakdown, comparison, export

---

## 4. All Work Completed (This Collaboration)

### Bug Fixes
- Fixed `CORAL_BRIDGE_TOKEN` env validation crash (empty string rejected by `z.string().min(1).optional()`)
- Fixed duplicate React keys (`block-buffer@cargo-unknown-unknown`) — added ecosystem to results map key + index tiebreaker
- Fixed all severities showing UNKNOWN — OSV returns CVSS vector strings not numeric scores; implemented full CVSS v3 vector parser + `database_specific.severity` fallback
- Fixed wrong Coral SQL syntax (`osv.query_by_version(fn => ...)` → `WHERE` clause)
- Fixed JSON columns from Coral returned as serialized strings — added `tryJsonParse()` in `mapOsvRow`
- Fixed `loadKev()` using wrong join (`cisa_kev.catalog` is single-row metadata, not per-CVE)
- Fixed `??` + `||` mixing without parens (Turbopack parse error)
- Fixed `SqlLogPanel` local type missing `label` field

### Security Pipeline (`security.ts`)
- **Cross-join query**: single Coral SQL fetches OSV vulns + KEV status in one round trip
- **NVD fallback**: for vulns still UNKNOWN after OSV, hits NVD 2.0 API by CVE ID (cached)
- **EPSS scores**: fetches exploit probability from first.org API per CVE (cached)
- **CVSS vector parser**: full v3 base score formula from AV/AC/PR/UI/S/C/I/A components
- **Advisory URL extraction**: prefers ADVISORY-typed reference, falls back to NVD/GitHub links
- **Affected versions**: extracted from `affected[].versions` arrays
- **Fix version**: extracted from `affected[].ranges[].events[].fixed`
- **Multi-ecosystem parsers**: `go.mod`, `go.sum` (Go), `Cargo.lock` + `Cargo.toml` (Rust), `pom.xml` (Maven) — in addition to existing `package.json` and `requirements.txt`
- **Direct vs transitive**: all parsers track `isDirect` flag
- **Commit SHA resolution**: `fetchCommitSha()` hits GitHub API before scanning
- **Rate limit handling**: `RateLimitError` class thrown and caught gracefully

### Scan Orchestration (`langchain.ts`)
- SHA-based scan cache: returns existing completed scan if same HEAD commit
- Fetches 7 manifest files in parallel (was 2)
- Dep cap raised 50 → 100
- KEV status from cross-join `_kevFromJoin` field (no separate KEV set lookup needed)
- Rate limit warnings collected and surfaced in scan result
- `rateLimitWarning` field on result passed through SSE to UI

### Scan Store (`scan-store.ts`)
- Added fields: `commitSha`, `affectedVersions`, `advisoryUrl`, `epssScore`, `isDirect`
- Added `findScanByCommitSha()` for cache lookup
- SHA index map for O(1) cache hits

### Coral Integration (`coral.ts`)
- SQL log: every `runCoralSql` call records `label`, `sql`, `source`, `rowCount`, `durationMs`, `error`, `timestamp`
- `runCoralSql(sql, label?, silent?)` — labeled queries show in log; silent=true suppresses infra noise
- Cross-join query labeled `OSV × KEV — pkg@version (ecosystem)` — the only query shown in SQL log
- GitHub file fetches and KEV cache load marked silent
- `getCoralAssistantContext()` updated with verified real schema, cross-join pattern, `LIKE '%' || k.cve_id || '%'` idiom, note that `json_each()` is unavailable

### New API Routes
- `GET /api/sql-log` — returns SQL log entries
- `DELETE /api/sql-log` — clears log

### New UI Components
- **`VulnerabilityCard`**: EPSS badge, direct/transitive badge, advisory link (↗), affected versions, fix version, reference type labels
- **`ExportButton`**: dropdown to download JSON or CSV report
- **`ScanComparison`**: pick previous scan, shows score delta + new/fixed/unchanged counts + regression/improvement banner
- **`ScoreTooltip`**: `?` button on Security Score card showing exact penalty breakdown
- **`SqlLogPanel`**: collapsible list of cross-join queries with label, SQL, source badge, row count, duration, error state, refresh + clear

### Sidebar (`Sidebar.tsx`)
- Added **SQL Log** tab (database icon)
- `active` + `onTabChange` props for tab switching

### Scoring (`utils.ts`)
- Replaced linear penalty model with **diminishing-returns logarithmic + exponential decay**
- Formula: `score = round(100 × e^(−penalty/55))` where penalty uses `log2` weights
- Unknowns now penalized (×2 log weight)
- `scoreBreakdown()` updated to show actual computed deductions
- `compareScanFindings()` added for scan diff

### Page (`page.tsx`)
- `activeTab` state switches between Dashboard and SQL Log
- Cache hit banner (green) when same SHA reused
- Rate limit warning banner (amber) when APIs throttled
- Export button in sticky top bar
- `ScanComparison` in right column
- `ScoreTooltip` on Security Score card
- `rateLimitWarning` state wired through SSE result

---

## 5. Coral SQL — Verified Real Schema

| Source | Table | Notes |
|---|---|---|
| OSV | `osv.query_by_version` | WHERE package_name, ecosystem, version (all required) |
| OSV | `osv.query_by_commit` | WHERE commit (required) |
| OSV | `osv.vulns` | WHERE id (required) |
| KEV | `cisa_kev.vulnerabilities` | Flat, no join needed for CVE IDs |
| KEV | `cisa_kev.catalog` | Single-row feed metadata only |
| NVD | `nvd.vulnerabilities` | cve_id, description, published; filter: cve_id_filter |
| NVD | `nvd.cvss_v3` | cve_id, base_score, base_severity, vector_string; filter: cve_id_filter |
| NVD | `nvd.cvss_v2` | cve_id, base_score, severity; filter: cve_id_filter |
| NVD | `nvd.references` | cve_id, references (JSON); filter: cve_id_filter |
| GitHub | `github.contents` | WHERE owner, repo, path |

NVD is available via Coral but rate-limited without an API key (5 req/30s). The 3-way join works but may 429 under load — OSV+KEV data still returns if NVD fails.

JSON columns (`severity`, `affected`, `references`, `aliases`) returned as serialized strings — must `JSON.parse()`.

3-way cross-join (OSV + KEV + NVD — verified schema, NVD rate-limited):
```sql
SELECT v.id, v.summary, v.severity, v.affected, v.references, v.aliases,
       k.cve_id AS kev_cve_id, k.vulnerability_name, k.date_added, k.required_action,
       n.base_score AS nvd_base_score, n.base_severity AS nvd_severity
FROM osv.query_by_version v
LEFT JOIN cisa_kev.vulnerabilities k
  ON v.aliases LIKE '%' || k.cve_id || '%'
LEFT JOIN nvd.cvss_v3 n
  ON v.aliases LIKE '%' || n.cve_id || '%'
WHERE v.package_name = 'jquery' AND v.ecosystem = 'npm' AND v.version = '3.4.1'
LIMIT 50
```

Severity resolution order (in code): `nvd_severity` → `nvd_base_score` → `database_specific.severity` → CVSS vector parse → HTTP NVD fallback

---

## 6. Known Gaps / Next Steps

- DB persistence (Drizzle schema exists, scan-store is in-memory only — data lost on restart)
- `pyproject.toml` parser not yet added
- NVD via Coral rate-limits without API key — add `NVD_API_KEY` env var to unlock 50 req/30s
- EPSS fetch adds latency per CVE — consider batching
- Chat panel not wired to results page (component exists, not rendered)
