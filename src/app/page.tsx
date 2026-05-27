"use client";

import { useEffect, useRef, useState } from "react";
import type React from "react";

import { AISummary } from "@/components/kevguard/AISummary";
import { RiskBreakdown } from "@/components/kevguard/RiskBreakdown";
import { Sidebar } from "@/components/kevguard/Sidebar";
import { VulnerabilityCard } from "@/components/kevguard/VulnerabilityCard";
import type { FindingsMap, RecentScan, ScanResult } from "@/components/kevguard/types";
import { computeMetrics, initialChatAnswer } from "@/components/kevguard/utils";

/* ─── helpers ─────────────────────────────────────────────────────────────── */

function repoDisplayName(url: string) {
  try {
    const parts = new URL(url).pathname.split("/").filter(Boolean);
    if (parts.length >= 2) return `${parts[0]}/${parts[1]}`;
  } catch {
    /* ignore */
  }
  return url;
}

function sortFindings(findings: FindingsMap) {
  return Object.entries(findings)
    .flatMap(([dep, vulns]) => vulns.map((vuln) => ({ dep, vuln })))
    .sort((a, b) => {
      if (Boolean(b.vuln.kev) !== Boolean(a.vuln.kev))
        return Number(Boolean(b.vuln.kev)) - Number(Boolean(a.vuln.kev));
      return 0;
    });
}

/* ─── page ─────────────────────────────────────────────────────────────────── */

export default function HomePage() {
  const [repoUrl, setRepoUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [recentScans, setRecentScans] = useState<RecentScan[]>([]);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanStage, setScanStage] = useState("");
  const progressTimer = useRef<ReturnType<typeof setInterval> | null>(null);

  async function loadRecentScans() {
    try {
      const res = await fetch("/api/scans");
      if (!res.ok) return;
      const data = await res.json();
      setRecentScans(data.scans ?? []);
    } catch { /* ignore */ }
  }

  useEffect(() => { void loadRecentScans(); }, []);

  // Fake-progress ticker while scanning
  useEffect(() => {
    if (loading) {
      setScanProgress(5);
      const stages = [
        "Fetching repository manifest…",
        "Parsing dependencies…",
        "Querying OSV database…",
        "Cross-referencing CISA KEV…",
        "Generating AI summary…",
        "Finalising report…",
      ];
      let stageIdx = 0;
      setScanStage(stages[0]);
      progressTimer.current = setInterval(() => {
        setScanProgress((p) => {
          const next = p + Math.floor(Math.random() * 6) + 2;
          return next >= 92 ? 92 : next;
        });
        stageIdx = Math.min(stageIdx + 1, stages.length - 1);
        setScanStage(stages[stageIdx]);
      }, 1800);
    } else {
      if (progressTimer.current) clearInterval(progressTimer.current);
      if (result) setScanProgress(100);
    }
    return () => { if (progressTimer.current) clearInterval(progressTimer.current); };
  }, [loading, result]);

  async function runScan(e?: React.FormEvent) {
    e?.preventDefault();
    if (!repoUrl.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repoUrl }),
      });

      if (!res.ok || !res.body) {
        const text = await res.text();
        setError(text || `Scan failed: ${res.status}`);
        return;
      }

      // The API returns an SSE stream — read it and extract the result event
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      outer: while (true) {
        const { value, done } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });

        // SSE blocks are separated by double newline
        let sep = buffer.indexOf("\n\n");
        while (sep >= 0) {
          const block = buffer.slice(0, sep).trim();
          buffer = buffer.slice(sep + 2);
          sep = buffer.indexOf("\n\n");

          if (!block) continue;

          // Parse event type and data from the block
          let eventType = "message";
          let dataLine = "";
          for (const line of block.split(/\r?\n/)) {
            if (line.startsWith("event:")) eventType = line.slice(6).trim();
            else if (line.startsWith("data:")) dataLine = line.slice(5).trim();
          }

          if (!dataLine) continue;

          if (eventType === "result") {
            const data = JSON.parse(dataLine) as ScanResult;
            setResult(data);
            await loadRecentScans();
            break outer;
          }

          if (eventType === "error") {
            const payload = JSON.parse(dataLine) as { message?: string };
            setError(payload.message || "Scan failed");
            break outer;
          }
          // "progress" events are handled by the fake-progress ticker — ignore
        }
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  function resetToStart() {
    setResult(null);
    setError(null);
    setScanProgress(0);
    setScanStage("");
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  const findings: FindingsMap = result?.findings ?? {};
  const metrics = computeMetrics(findings);
  const sortedVulns = sortFindings(findings);
  const repoName = result?.repo ? repoDisplayName(result.repo) : repoDisplayName(repoUrl);

  return (
    <div className="flex min-h-screen bg-[#060e18] text-[#d4e4fa]">
      {/* ── Sidebar ── */}
      <Sidebar onNewScan={resetToStart} />

      {/* ── Main canvas ── */}
      <div className="ml-60 flex flex-1 flex-col">

        {/* ════════════════════════════════════════════════════════════
            LANDING — hero + input + progress + about section
        ════════════════════════════════════════════════════════════ */}
        {!result && (
          <>
            {/* Hero section — full viewport height, centered */}
            <section className="flex min-h-screen flex-col items-center justify-center px-6 text-center">
              {/* App name */}
              <div className="mb-3 flex items-center gap-2">
                <svg className="h-5 w-5 text-[#45dfa4]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
                </svg>
                <span className="font-mono text-[12px] uppercase tracking-[0.2em] text-[#45dfa4]">
                  KEVGuard
                </span>
              </div>

              <h1 className="mb-4 max-w-2xl text-[42px] font-semibold leading-[1.1] tracking-[-0.03em] text-white sm:text-[52px]">
                AI-powered dependency security
              </h1>
              <p className="mb-12 max-w-lg text-[17px] leading-relaxed text-white/40">
                Paste a GitHub repository URL. We scan your dependencies against OSV and CISA KEV in seconds.
              </p>

              {/* URL input */}
              <form
                onSubmit={runScan}
                className="w-full max-w-xl"
              >
                <div className="flex overflow-hidden rounded-xl border border-white/[0.1] bg-white/[0.04] focus-within:border-[#45dfa4]/50 focus-within:bg-white/[0.06] transition-all">
                  <input
                    value={repoUrl}
                    onChange={(e) => setRepoUrl(e.target.value)}
                    placeholder="https://github.com/owner/repo"
                    disabled={loading}
                    className="flex-1 bg-transparent px-5 py-4 text-[15px] text-white outline-none placeholder:text-white/20 disabled:opacity-50"
                  />
                  <button
                    type="submit"
                    disabled={loading || !repoUrl.trim()}
                    className="m-1.5 rounded-lg bg-[#45dfa4] px-6 py-2.5 text-[13px] font-semibold text-[#002d1e] transition-all hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    {loading ? "Scanning…" : "Analyze"}
                  </button>
                </div>

                {error && (
                  <p className="mt-3 text-[13px] text-red-400">{error}</p>
                )}
              </form>

              {/* Progress — only visible while scanning, intentionally dim */}
              <div
                className={`mt-10 w-full max-w-xl transition-all duration-500 ${
                  loading ? "opacity-100" : "pointer-events-none opacity-0"
                }`}
              >
                <div className="mb-2 flex items-center justify-between">
                  <span className="font-mono text-[11px] text-white/25">
                    {scanStage}
                  </span>
                  <span className="font-mono text-[11px] text-white/25">
                    {scanProgress}%
                  </span>
                </div>
                <div className="h-px w-full overflow-hidden rounded-full bg-white/[0.06]">
                  <div
                    className="h-full rounded-full bg-[#45dfa4]/30 transition-all duration-700"
                    style={{ width: `${scanProgress}%` }}
                  />
                </div>
              </div>

              {/* Scroll hint */}
              {!loading && (
                <button
                  onClick={() =>
                    document
                      .getElementById("about")
                      ?.scrollIntoView({ behavior: "smooth" })
                  }
                  className="mt-20 flex flex-col items-center gap-2 text-white/20 transition-colors hover:text-white/40"
                  aria-label="Scroll to learn more"
                >
                  <span className="font-mono text-[11px] uppercase tracking-widest">
                    Learn more
                  </span>
                  <svg className="h-4 w-4 animate-bounce" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
                  </svg>
                </button>
              )}
            </section>

            {/* About section — below the fold */}
            <section
              id="about"
              className="border-t border-white/[0.05] px-8 py-24"
            >
              <div className="mx-auto max-w-4xl">
                <p className="mb-3 font-mono text-[11px] uppercase tracking-[0.2em] text-[#45dfa4]">
                  What is KEVGuard
                </p>
                <h2 className="mb-6 text-[32px] font-semibold leading-tight tracking-tight text-white">
                  Know which vulnerabilities are being actively exploited — before attackers reach you.
                </h2>
                <p className="mb-16 max-w-2xl text-[16px] leading-relaxed text-white/40">
                  KEVGuard combines OSV vulnerability intelligence with the CISA Known Exploited Vulnerabilities catalog to give you a prioritised, AI-summarised security report for any public GitHub repository.
                </p>

                {/* Feature list — plain rows, no cards */}
                <div className="divide-y divide-white/[0.05]">
                  {[
                    {
                      num: "01",
                      title: "GitHub dependency parsing",
                      desc: "We fetch your package.json, requirements.txt, and other manifests directly from GitHub and extract every declared dependency.",
                    },
                    {
                      num: "02",
                      title: "OSV vulnerability lookup",
                      desc: "Each dependency is cross-referenced against the Open Source Vulnerabilities database — covering npm, PyPI, Go, Maven, and more.",
                    },
                    {
                      num: "03",
                      title: "CISA KEV correlation",
                      desc: "CVEs are matched against the CISA Known Exploited Vulnerabilities catalog so you know which issues are actively being weaponised in the wild.",
                    },
                    {
                      num: "04",
                      title: "AI-generated summary",
                      desc: "Gemini synthesises the findings into a plain-English summary with a prioritised fix list — no security expertise required to act on it.",
                    },
                  ].map((f) => (
                    <div key={f.num} className="flex gap-8 py-8">
                      <span className="shrink-0 font-mono text-[13px] text-white/20 pt-0.5">
                        {f.num}
                      </span>
                      <div>
                        <h3 className="mb-2 text-[17px] font-semibold text-white">
                          {f.title}
                        </h3>
                        <p className="text-[15px] leading-relaxed text-white/40">
                          {f.desc}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>

                {/* Stats row */}
                <div className="mt-16 grid grid-cols-2 gap-8 border-t border-white/[0.05] pt-16 md:grid-cols-4">
                  {[
                    { value: "< 2s", label: "Scan time" },
                    { value: "1M+", label: "CVEs indexed" },
                    { value: "24/7", label: "CISA sync" },
                    { value: "99.9%", label: "Accuracy" },
                  ].map((s) => (
                    <div key={s.label}>
                      <div className="text-[28px] font-semibold tracking-tight text-white">
                        {s.value}
                      </div>
                      <div className="mt-1 font-mono text-[11px] uppercase tracking-widest text-white/30">
                        {s.label}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </section>

            {/* Recent scans — only if there are any */}
            {recentScans.length > 0 && (
              <section className="border-t border-white/[0.05] px-8 py-16">
                <div className="mx-auto max-w-4xl">
                  <h3 className="mb-6 text-[18px] font-semibold text-white">
                    Recent scans
                  </h3>
                  <div className="divide-y divide-white/[0.05]">
                    {recentScans.map((scan) => (
                      <a
                        key={scan.id}
                        href={`/scan/${scan.id}`}
                        className="flex items-center justify-between gap-4 py-4 transition-colors hover:text-white"
                      >
                        <div>
                          <span className="text-[15px] font-medium text-white/80">
                            {scan.owner}/{scan.repo}
                          </span>
                          <div className="mt-0.5 flex items-center gap-3 font-mono text-[11px] text-white/30">
                            <span>{scan.findingsCount} findings</span>
                            {scan.kevCount > 0 && (
                              <span className="text-[#e13052]/70">
                                {scan.kevCount} KEV
                              </span>
                            )}
                            <span>{new Date(scan.createdAt).toLocaleDateString()}</span>
                          </div>
                        </div>
                        <svg className="h-4 w-4 shrink-0 text-white/20" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
                        </svg>
                      </a>
                    ))}
                  </div>
                </div>
              </section>
            )}
          </>
        )}

        {/* ════════════════════════════════════════════════════════════
            RESULTS — structured report
        ════════════════════════════════════════════════════════════ */}
        {result && (
          <div className="flex flex-col min-h-screen">

            {/* ── Sticky top bar ── */}
            <div className="sticky top-0 z-40 border-b border-white/6 bg-[#060e18]/95 px-8 py-3 backdrop-blur">
              <div className="flex items-center justify-between gap-4">
                <div className="flex items-center gap-3">
                  <button
                    onClick={resetToStart}
                    className="flex items-center gap-1.5 font-mono text-[12px] text-white/30 transition-colors hover:text-white/60"
                  >
                    <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M10.5 19.5L3 12m0 0l7.5-7.5M3 12h18" />
                    </svg>
                    New scan
                  </button>
                  <span className="text-white/10">/</span>
                  <span className="text-[14px] font-medium text-white/60">{repoName}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="h-1.5 w-1.5 rounded-full bg-[#45dfa4]" />
                  <span className="font-mono text-[11px] text-white/30">Scan complete</span>
                </div>
              </div>
            </div>

            <div className="px-8 py-8">

              {/* ── Section 1: Repo header + stat cards ── */}
              <div className="mb-8">
                <p className="mb-1 font-mono text-[11px] uppercase tracking-[0.18em] text-white/30">
                  Security Report
                </p>
                <h2 className="text-[28px] font-semibold leading-tight tracking-tight text-white">
                  {repoName}
                </h2>
                <p className="mt-1 font-mono text-[12px] text-white/25">
                  {new Date().toLocaleString()} · OSV + CISA KEV
                </p>

                {/* Stat cards row */}
                <div className="mt-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
                  <StatCard
                    label="Security Score"
                    value={`${metrics.securityScore}`}
                    sub="/ 100"
                    tone={metrics.securityScore < 60 ? "danger" : metrics.securityScore < 80 ? "warn" : "good"}
                    icon={
                      <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
                      </svg>
                    }
                  />
                  <StatCard
                    label="Critical"
                    value={String(metrics.riskBreakdown.critical)}
                    tone={metrics.riskBreakdown.critical > 0 ? "danger" : "neutral"}
                    icon={
                      <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
                      </svg>
                    }
                  />
                  <StatCard
                    label="Actively Exploited"
                    value={String(metrics.activelyExploited)}
                    tone={metrics.activelyExploited > 0 ? "danger" : "neutral"}
                    icon={
                      <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 13.5l10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75z" />
                      </svg>
                    }
                  />
                  <StatCard
                    label="Total Findings"
                    value={String(metrics.totalVulnerabilities)}
                    tone="neutral"
                    icon={
                      <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M12 12.75c1.148 0 2.278.08 3.383.237 1.037.146 1.866.966 1.866 2.013 0 3.728-2.35 6.75-5.25 6.75S6.75 18.728 6.75 15c0-1.046.83-1.867 1.866-2.013A24.204 24.204 0 0112 12.75zm0 0c2.883 0 5.647.508 8.207 1.44a23.91 23.91 0 01-1.152 6.06M12 12.75c-2.883 0-5.647.508-8.208 1.44.125 2.104.52 4.136 1.153 6.06M12 12.75a2.25 2.25 0 002.248-2.354M12 12.75a2.25 2.25 0 01-2.248-2.354M12 8.25c.995 0 1.971-.08 2.922-.236.403-.066.74-.358.795-.762a3.778 3.778 0 00-.399-2.25M12 8.25c-.995 0-1.97-.08-2.922-.236-.402-.066-.74-.358-.795-.762a3.734 3.734 0 01.4-2.253M12 8.25a2.25 2.25 0 00-2.248 2.146M12 8.25a2.25 2.25 0 012.248 2.146" />
                      </svg>
                    }
                  />
                </div>

                {/* Secondary stats row */}
                <div className="mt-4 grid grid-cols-2 gap-4 lg:grid-cols-4">
                  <MiniStat label="High" value={metrics.riskBreakdown.high} color="text-orange-400" />
                  <MiniStat label="Medium" value={metrics.riskBreakdown.medium} color="text-amber-400" />
                  <MiniStat label="Low" value={metrics.riskBreakdown.low} color="text-yellow-400" />
                  <MiniStat label="Vulnerable Packages" value={metrics.dependencyCount} color="text-white/60" />
                </div>
              </div>

              {/* ── Section 2: Two-column — vulnerabilities + AI summary ── */}
              <div className="grid grid-cols-1 gap-6 lg:grid-cols-[1fr_340px]">

                {/* Left: Vulnerability cards */}
                <div>
                  <div className="mb-4 flex items-center justify-between">
                    <h3 className="text-[16px] font-semibold text-white">
                      Vulnerabilities
                      <span className="ml-2 font-mono text-[13px] font-normal text-white/30">
                        {sortedVulns.length}
                      </span>
                    </h3>
                    {metrics.activelyExploited > 0 && (
                      <span className="rounded-md border border-[#e13052]/40 bg-[#e13052]/10 px-2.5 py-1 font-mono text-[11px] text-[#e13052]">
                        {metrics.activelyExploited} KEV
                      </span>
                    )}
                  </div>

                  {sortedVulns.length === 0 ? (
                    <div className="rounded-xl border border-white/6 bg-[#0b1929] p-8 text-center">
                      <svg className="mx-auto mb-3 h-8 w-8 text-[#45dfa4]/40" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                      <p className="text-[15px] font-medium text-white/50">No vulnerabilities found</p>
                      <p className="mt-1 text-[13px] text-white/25">This repository looks clean.</p>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {sortedVulns.map(({ dep, vuln }) => (
                        <VulnerabilityCard
                          key={`${dep}-${vuln.id}-${vuln.fixed_in ?? "na"}`}
                          dependency={dep}
                          vuln={vuln}
                        />
                      ))}
                    </div>
                  )}
                </div>

                {/* Right: AI Summary + Risk breakdown */}
                <div className="space-y-4">
                  {/* AI Summary card */}
                  <div className="rounded-xl border border-white/6 bg-[#0b1929] p-5">
                    <div className="mb-3 flex items-center gap-2">
                      <svg className="h-4 w-4 text-[#45dfa4]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z" />
                      </svg>
                      <span className="font-mono text-[11px] uppercase tracking-[0.15em] text-[#45dfa4]">
                        AI Summary
                      </span>
                    </div>
                    <p className="text-[14px] leading-relaxed text-white/65">
                      {result.summary ?? initialChatAnswer(findings)}
                    </p>
                  </div>

                  {/* Risk breakdown card */}
                  <div className="rounded-xl border border-white/6 bg-[#0b1929] p-5">
                    <p className="mb-4 font-mono text-[11px] uppercase tracking-[0.15em] text-white/30">
                      Risk Breakdown
                    </p>
                    <RiskBreakdown breakdown={metrics.riskBreakdown} />
                  </div>
                </div>
              </div>

            </div>

            {/* Footer */}
            <footer className="mt-auto border-t border-white/5 px-8 py-4">
              <div className="flex items-center justify-between">
                <span className="font-mono text-[11px] text-white/20">KEVGuard · OSV + CISA KEV</span>
                <span className="font-mono text-[11px] text-white/20">v4.8.2-stable</span>
              </div>
            </footer>
          </div>
        )}

        {/* Footer — landing only */}
        {!result && (
          <footer className="mt-auto border-t border-white/5 px-8 py-5">
            <div className="flex items-center justify-between">
              <span className="font-mono text-[11px] text-white/20">KEVGuard · OSV + CISA KEV</span>
              <span className="font-mono text-[11px] text-white/20">v4.8.2-stable</span>
            </div>
          </footer>
        )}
      </div>
    </div>
  );
}

/* ── Stat card (large) ── */
type Tone = "danger" | "warn" | "good" | "neutral";

const toneStyles: Record<Tone, { card: string; value: string; icon: string }> = {
  danger:  { card: "border-[#e13052]/25 bg-[#e13052]/5",  value: "text-[#e13052]",  icon: "text-[#e13052]/50"  },
  warn:    { card: "border-amber-500/25 bg-amber-500/5",   value: "text-amber-400",  icon: "text-amber-400/50"  },
  good:    { card: "border-[#45dfa4]/25 bg-[#45dfa4]/5",  value: "text-[#45dfa4]",  icon: "text-[#45dfa4]/50"  },
  neutral: { card: "border-white/6 bg-[#0b1929]",         value: "text-white",       icon: "text-white/20"      },
};

function StatCard({
  label,
  value,
  sub,
  tone,
  icon,
}: {
  label: string;
  value: string;
  sub?: string;
  tone: Tone;
  icon: React.ReactNode;
}) {
  const s = toneStyles[tone];
  return (
    <div className={`rounded-xl border p-5 ${s.card}`}>
      <div className={`mb-3 ${s.icon}`}>{icon}</div>
      <div className="flex items-baseline gap-1">
        <span className={`text-[32px] font-semibold leading-none tracking-tight ${s.value}`}>
          {value}
        </span>
        {sub && <span className="text-[14px] text-white/30">{sub}</span>}
      </div>
      <p className="mt-2 font-mono text-[11px] uppercase tracking-widest text-white/30">{label}</p>
    </div>
  );
}

/* ── Mini stat (secondary row) ── */
function MiniStat({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="rounded-xl border border-white/6 bg-[#0b1929] px-4 py-3">
      <span className={`text-[22px] font-semibold leading-none ${color}`}>{value}</span>
      <p className="mt-1 font-mono text-[11px] uppercase tracking-widest text-white/25">{label}</p>
    </div>
  );
}
