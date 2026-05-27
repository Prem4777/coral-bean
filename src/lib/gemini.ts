import { env } from "@/lib/env";
import { getCoralAssistantContext } from "@/lib/coral";

type Finding = {
  id: string;
  summary?: string | null;
  severity?: string | null;
  fixed_in?: string | null;
  kev?: boolean;
};

function topFindings(findings: Record<string, Finding[]>) {
  return Object.entries(findings)
    .flatMap(([dependency, vulns]) =>
      vulns.map((vuln) => ({ dependency, ...vuln })),
    )
    .sort((left, right) => {
      const score = (item: { severity?: string | null; kev?: boolean }) => {
        const sev = String(item.severity ?? "").toUpperCase();
        const sevScore = sev.includes("CRITICAL")
          ? 4
          : sev.includes("HIGH")
            ? 3
            : sev.includes("MODERATE")
              ? 2
              : sev.includes("LOW")
                ? 1
                : 0;
        return sevScore + (item.kev ? 2 : 0);
      };
      return score(right) - score(left);
    })
    .slice(0, 5);
}

export async function generateSecuritySummary(params: {
  repo: string;
  findings: Record<string, Finding[]>;
}) {
  if (!env.GEMINI_API_KEY) return null;

  const prioritized = topFindings(params.findings);
  const prompt = [
    "You are a security engineer. Summarize the repo risk in short, actionable language.",
    getCoralAssistantContext(),
    `Repository: ${params.repo}`,
    "Findings:",
    ...prioritized.map((item) => {
      const kev = item.kev ? "yes" : "no";
      return `- ${item.dependency}: ${item.id} | severity=${item.severity ?? "n/a"} | kev=${kev} | fix=${item.fixed_in ?? "unknown"} | ${item.summary ?? ""}`;
    }),
    "Return plain text only. Start with one sentence risk summary, then list the top fixes in priority order.",
  ].join("\n");

  const model = env.GEMINI_MODEL || "gemini-2.0-flash";
  const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(
    model,
  )}:generateContent?key=${encodeURIComponent(env.GEMINI_API_KEY)}`;

  const res = await fetch(endpoint, {
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

  if (!res.ok) return null;
  const data = await res.json();
  const text = data?.candidates?.[0]?.content?.parts
    ?.map((part: any) => part?.text)
    .filter(Boolean)
    .join("\n")
    ?.trim();

  return text || null;
}
