import { env } from "@/lib/env";
import { getCoralAssistantContext } from "@/lib/coral";
import type { FindingsMap } from "@/components/kevguard/types";

function scoreFinding(
  severity?: string | null | { type?: string; score?: number },
  kev?: boolean,
) {
  const sev =
    typeof severity === "object" && severity
      ? String(severity.type ?? "")
      : String(severity ?? "");
  const sevUpper = sev.toUpperCase();
  const sevScore = sevUpper.includes("CRITICAL")
    ? 4
    : sevUpper.includes("HIGH")
      ? 3
      : sevUpper.includes("MODERATE") || sevUpper.includes("MEDIUM")
        ? 2
        : sevUpper.includes("LOW")
          ? 1
          : 0;
  return sevScore + (kev ? 2 : 0);
}

function topFindings(findings: FindingsMap) {
  return Object.entries(findings)
    .flatMap(([dependency, vulns]) =>
      vulns.map((vuln) => ({ dependency, vuln })),
    )
    .sort((left, right) => {
      const rightScore = scoreFinding(right.vuln.severity, right.vuln.kev);
      const leftScore = scoreFinding(left.vuln.severity, left.vuln.kev);
      if (rightScore !== leftScore) return rightScore - leftScore;
      return left.dependency.localeCompare(right.dependency);
    })
    .slice(0, 6);
}

function fallbackAnswer(question: string, findings: FindingsMap) {
  const q = question.toLowerCase();
  const top = topFindings(findings)[0];
  if (q.includes("fix first") || q.includes("priority")) {
    return top
      ? `Start with ${top.dependency} because it is the highest risk item in the current scan.`
      : "No vulnerabilities were found. Keep dependencies pinned and rescan after changes.";
  }
  if (q.includes("dangerous")) {
    return top
      ? `${top.dependency} is the most dangerous dependency in the report right now.`
      : "No dangerous dependency identified from the current scan data.";
  }
  if (q.includes("summarize") || q.includes("risk")) {
    const items = topFindings(findings);
    return items.length > 0
      ? `The scan found ${items.length} high-priority issues. Focus on KEV and critical items first, then move to high severity packages.`
      : "The repository looks clean from the current scan data.";
  }
  return "Ask for priority, dangerous dependencies, or a short repo risk summary.";
}

export async function generateRepoAgentReply(params: {
  repo: string;
  question: string;
  findings: FindingsMap;
}) {
  const prioritized = topFindings(params.findings);

  if (!env.GEMINI_API_KEY) {
    return fallbackAnswer(params.question, params.findings);
  }

  const prompt = [
    "You are an expert security remediation agent.",
    "Answer the user's question with direct, practical guidance.",
    "Keep the response short, specific, and action oriented.",
    getCoralAssistantContext(),
    `Repository: ${params.repo}`,
    `Question: ${params.question}`,
    "Top findings:",
    ...prioritized.map((item) => {
      const sev = String(item.vuln.severity ?? "unknown");
      const kev = item.vuln.kev ? "yes" : "no";
      return `- ${item.dependency}: ${item.vuln.cveId ?? item.vuln.id} | severity=${sev} | kev=${kev} | fix=${item.vuln.fixed_in ?? "unknown"} | ${item.vuln.summary ?? ""}`;
    }),
    "Return plain text only. Prefer a concise answer with a short follow-up recommendation.",
  ].join("\n");

  const model = env.GEMINI_MODEL || "gemini-2.0-flash";
  const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(
    model,
  )}:generateContent?key=${encodeURIComponent(env.GEMINI_API_KEY)}`;

  const response = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      contents: [
        {
          role: "user",
          parts: [{ text: prompt }],
        },
      ],
    }),
  });

  if (!response.ok) return fallbackAnswer(params.question, params.findings);
  const data = await response.json();
  const text = data?.candidates?.[0]?.content?.parts
    ?.map((part: any) => part?.text)
    .filter(Boolean)
    .join("\n")
    ?.trim();

  return text || fallbackAnswer(params.question, params.findings);
}
