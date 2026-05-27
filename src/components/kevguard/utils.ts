import type { DashboardMetrics, FindingsMap, VulnItem } from "./types";

function severityText(severity: VulnItem["severity"]) {
  if (!severity) return "unknown";
  if (typeof severity === "string") return severity.toLowerCase();
  if (typeof severity === "object" && severity.type)
    return String(severity.type).toLowerCase();
  return "unknown";
}

export function computeMetrics(findings: FindingsMap): DashboardMetrics {
  const deps = Object.keys(findings);
  let total = 0;
  let kev = 0;
  const riskBreakdown = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    unknown: 0,
  };

  for (const vulns of Object.values(findings)) {
    for (const vuln of vulns) {
      total += 1;
      if (vuln.kev) kev += 1;
      const sev = severityText(vuln.severity);
      if (sev.includes("critical")) riskBreakdown.critical += 1;
      else if (sev.includes("high")) riskBreakdown.high += 1;
      else if (sev.includes("moderate") || sev.includes("medium"))
        riskBreakdown.medium += 1;
      else if (sev.includes("low")) riskBreakdown.low += 1;
      else riskBreakdown.unknown += 1;
    }
  }

  // Penalty-based score: simple and deterministic for demo usage.
  const penalty =
    riskBreakdown.critical * 20 +
    riskBreakdown.high * 12 +
    riskBreakdown.medium * 7 +
    riskBreakdown.low * 3 +
    kev * 15;
  const securityScore = Math.max(0, Math.min(100, 100 - penalty));

  return {
    securityScore,
    totalVulnerabilities: total,
    activelyExploited: kev,
    dependencyCount: deps.length,
    riskBreakdown,
  };
}

export function topRiskDependency(findings: FindingsMap): string | null {
  let top: { dep: string; score: number } | null = null;

  for (const [dep, vulns] of Object.entries(findings)) {
    const score =
      vulns.reduce((acc, v) => {
        const sev = severityText(v.severity);
        if (sev.includes("critical")) return acc + 4;
        if (sev.includes("high")) return acc + 3;
        if (sev.includes("moderate") || sev.includes("medium")) return acc + 2;
        if (sev.includes("low")) return acc + 1;
        return acc + 1;
      }, 0) +
      vulns.filter((v) => v.kev).length * 4;

    if (!top || score > top.score) top = { dep, score };
  }

  return top?.dep ?? null;
}

export function initialChatAnswer(findings: FindingsMap): string {
  const metrics = computeMetrics(findings);
  if (metrics.totalVulnerabilities === 0) {
    return "No known dependency vulnerabilities were found. Keep dependencies pinned and continue regular scanning.";
  }

  return `This repository has ${metrics.totalVulnerabilities} vulnerabilities, including ${metrics.activelyExploited} actively exploited KEV hits. Prioritize critical/high issues with KEV status first.`;
}
