# RepoGaurd AI

RepoGaurd AI is an AI-powered security scanner for GitHub repositories. It analyzes project dependencies and detects known vulnerabilities using OSV, CISA KEV, and GitHub metadata. It also uses AI to generate clear, human-readable security insights.

---

## Overview

The tool scans a GitHub repository by extracting its dependencies from common package files such as `package.json` and `requirements.txt`. It then checks those dependencies against multiple vulnerability sources and consolidates the results into a single report.

The output highlights:
- Known vulnerabilities (OSV)
- Actively exploited vulnerabilities (CISA KEV)
- Severity levels
- Affected packages
- Suggested risk interpretation (AI-generated)

---

## Features

- GitHub repository scanning via URL
- Dependency extraction for multiple ecosystems
- Vulnerability matching using OSV database
- KEV (Known Exploited Vulnerabilities) detection
- AI-generated security summaries
---

## Tech Stack

- Next.js (App Router)
- TypeScript
- Tailwind CSS
- PostgreSQL (Neon)
- Coral MCP (OSV, GitHub, CISA KEV sources)
- Gemini API

---

## How It Works

1. User submits a GitHub repository URL
2. Dependencies are extracted from project files
3. OSV database is queried for known vulnerabilities
4. CISA KEV is checked for actively exploited CVEs
5. GitHub data is used for additional context
6. AI generates a readable risk summary

---

