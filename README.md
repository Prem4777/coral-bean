# KEVGuard AI

An AI-powered dependency security scanner for GitHub repositories. Paste a repo URL, get a full vulnerability report in seconds — powered by Coral's cross-source SQL intelligence.

---

## What it does

KEVGuard scans a GitHub repository's dependencies and checks them against multiple threat intelligence sources simultaneously. Instead of making separate API calls and stitching results together in code, KEVGuard uses a single Coral SQL cross-join query to hit OSV, CISA KEV, and GitHub in one shot.

The result is a consolidated security report showing:

- Known vulnerabilities with CVE IDs and severity scores (OSV)
- Actively exploited vulnerabilities flagged by CISA KEV
- EPSS scores showing the 30-day probability of exploitation in the wild
- CVSS severity fallback via NVD for any gaps in OSV data
- Direct vs transitive dependency classification
- Minimum safe version to upgrade to
- AI-generated plain-English triage summary

---

## How Coral powers this

Coral is the intelligence core of KEVGuard. Rather than calling OSV, CISA KEV, and GitHub as separate APIs and joining the data manually, KEVGuard routes everything through a single Coral MCP bridge using a SQL cross-join:

```sql
SELECT o.id, o.summary, o.severity, k.cve_id, k.date_added
FROM osv.vulnerabilities o
LEFT JOIN cisa.kev k ON o.aliases @> ARRAY[k.cve_id]
WHERE o.affected_package = $1
```

This means:
- One query replaces three API calls
- KEV exploitation status is joined at the data layer, not in application code
- The full query is logged and auditable via the SQL Log in the UI
- Results are deterministic and reproducible

Every finding in a KEVGuard report can be traced back to a single Coral query.

---

## Tech stack

| Layer | Technology |
|---|---|
| Frontend | Next.js (App Router), TypeScript, Tailwind CSS |
| AI | Gemini API — plain-English triage summaries |
| Intelligence core | Coral MCP — OSV + CISA KEV cross-join |
| Severity fallback | NVD API — fills missing CVSS scores |
| Exploit probability | EPSS (first.org) — 30-day exploitation likelihood |


---

## How it works

1. User submits a GitHub repository URL
2. Coral fetches the dependency manifest from GitHub
3. A single Coral SQL cross-join queries OSV for vulnerabilities and CISA KEV for active exploitation status simultaneously
4. NVD fills in any CVSS scores that OSV does not have
5. Each CVE gets an EPSS score from first.org
6. Gemini generates a plain-English summary — what to fix first and why
7. Results are returned as a scored report with exportable JSON/CSV output

---

## Features

- GitHub repository scanning via URL
- Multi-ecosystem dependency extraction (`package.json`, `requirements.txt`, and more)
- Cross-source vulnerability matching via Coral SQL
- CISA KEV active exploitation detection
- EPSS exploit probability per CVE
- NVD CVSS fallback for unknown severities
- AI-generated risk summaries (Gemini)
- Scan comparison — diff any two scans to see regressions and fixes
- Export to JSON or CSV for CI pipelines and ticketing systems
- Full SQL log — every finding is auditable

---
