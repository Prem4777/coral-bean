import Link from "next/link";
import { notFound } from "next/navigation";

import { getScanById } from "@/lib/scan-store";

type Params = { id: string };

function severityRank(severity: string) {
  const v = severity.toUpperCase();
  if (v.includes("CRITICAL")) return 4;
  if (v.includes("HIGH")) return 3;
  if (v.includes("MODERATE") || v.includes("MEDIUM")) return 2;
  if (v.includes("LOW")) return 1;
  return 0;
}

function severityColor(severity: string) {
  const v = severity.toUpperCase();
  if (v.includes("CRITICAL")) return "text-[#e13052]";
  if (v.includes("HIGH")) return "text-orange-400";
  if (v.includes("MODERATE") || v.includes("MEDIUM")) return "text-amber-400";
  if (v.includes("LOW")) return "text-yellow-400";
  return "text-white/30";
}

export default async function ScanDetailPage({
  params,
}: {
  params: Promise<Params>;
}) {
  const { id } = await params;
  const scan = await getScanById(id);
  if (!scan) notFound();

  const { job, findings } = scan;
  const kevCount = findings.filter((f) => f.kevStatus).length;

  const grouped = findings.reduce<Record<string, typeof findings>>(
    (acc, f) => {
      const key = `${f.packageName}@${f.ecosystem}`;
      acc[key] = acc[key] ?? [];
      acc[key].push(f);
      return acc;
    },
    {},
  );

  return (
    <div className="ml-60 min-h-screen bg-[#060e18] text-[#d4e4fa]">
      <div className="mx-auto max-w-4xl px-8 py-12">
        {/* Back */}
        <Link
          href="/"
          className="mb-8 inline-flex items-center gap-2 font-mono text-[12px] text-white/30 transition-colors hover:text-white/60"
        >
          <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M10.5 19.5L3 12m0 0l7.5-7.5M3 12h18" />
          </svg>
          Back to dashboard
        </Link>

        {/* Header */}
        <h1 className="text-[32px] font-semibold leading-tight tracking-tight text-white">
          {job.owner}/{job.repo}
        </h1>
        <p className="mt-1 font-mono text-[12px] text-white/30">
          {new Date(job.createdAt).toLocaleString()}
        </p>

        {/* Meta row */}
        <div className="mt-6 flex flex-wrap gap-6 border-b border-white/[0.05] pb-8">
          <MetaItem label="Status" value={job.status} accent={job.status === "completed" ? "text-[#45dfa4]" : "text-amber-400"} />
          <MetaItem label="Findings" value={String(findings.length)} />
          <MetaItem label="KEV hits" value={String(kevCount)} accent={kevCount > 0 ? "text-[#e13052]" : undefined} />
        </div>

        {/* Findings list */}
        <div className="mt-8">
          {Object.keys(grouped).length === 0 ? (
            <p className="py-12 text-center text-[15px] text-white/30">
              No findings stored for this scan.
            </p>
          ) : (
            Object.entries(grouped).map(([dependency, depFindings]) => {
              const highestSeverity = depFindings
                .map((f) => f.severity)
                .sort((a, b) => severityRank(b) - severityRank(a))[0] ?? "UNKNOWN";
              const hasKev = depFindings.some((f) => f.kevStatus);

              return (
                <div key={dependency} className="border-b border-white/[0.05] py-6">
                  {/* Package header */}
                  <div className="flex flex-wrap items-center gap-3 mb-4">
                    {hasKev && <span className="h-2 w-2 rounded-full bg-[#e13052]" />}
                    <span className="text-[17px] font-semibold text-white">{dependency}</span>
                    <span className={`font-mono text-[11px] uppercase tracking-wider ${severityColor(highestSeverity)}`}>
                      {highestSeverity}
                    </span>
                    {hasKev && (
                      <span className="rounded border border-[#e13052]/40 px-2 py-0.5 font-mono text-[10px] text-[#e13052]">
                        Actively exploited
                      </span>
                    )}
                    <span className="ml-auto font-mono text-[11px] text-white/25">
                      {depFindings.length} issue{depFindings.length === 1 ? "" : "s"}
                    </span>
                  </div>

                  {/* Individual CVEs */}
                  <div className="space-y-4 pl-5">
                    {depFindings.map((finding) => {
                      const sevStr =
                        typeof finding.severity === "object"
                          ? JSON.stringify(finding.severity)
                          : String(finding.severity ?? "UNKNOWN");
                      return (
                        <div key={finding.vulnerabilityId}>
                          <div className="flex flex-wrap items-center gap-3 mb-1">
                            <span className="font-mono text-[12px] text-white/50">
                              {finding.vulnerabilityId}
                            </span>
                            <span className={`font-mono text-[11px] uppercase ${severityColor(sevStr)}`}>
                              {sevStr}
                            </span>
                            {finding.kevStatus && (
                              <span className="font-mono text-[11px] text-[#e13052]">KEV</span>
                            )}
                          </div>
                          <p className="text-[14px] leading-relaxed text-white/50">
                            {finding.summary}
                          </p>
                          {finding.fix && (
                            <p className="mt-1 font-mono text-[12px] text-[#45dfa4]/60">
                              Fix → {finding.fix}
                            </p>
                          )}
                          {finding.cveId && (
                            <p className="mt-0.5 font-mono text-[11px] text-white/20">
                              {finding.cveId}
                            </p>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}

function MetaItem({
  label,
  value,
  accent,
}: {
  label: string;
  value: string;
  accent?: string;
}) {
  return (
    <div>
      <div className="font-mono text-[11px] uppercase tracking-widest text-white/25">{label}</div>
      <div className={`mt-0.5 text-[15px] font-semibold ${accent ?? "text-white"}`}>{value}</div>
    </div>
  );
}
