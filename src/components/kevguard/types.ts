export type VulnItem = {
  id: string;
  cveId?: string | null;
  summary?: string | null;
  severity?: string | null | { type?: string; score?: number };
  fixed_in?: string | null;
  references?: Array<{ url: string; type?: string }>;
  kev?: boolean;
};

export type FindingsMap = Record<string, VulnItem[]>;

export type RecentScan = {
  id: string;
  repositoryUrl: string;
  owner: string;
  repo: string;
  status: string;
  createdAt: string;
  findingsCount: number;
  vulnerableDependencies: number;
  kevCount: number;
};

export type ScanResult = {
  scanId: string;
  repo: string;
  findings: FindingsMap;
  summary: string | null;
};

export type DashboardMetrics = {
  securityScore: number;
  totalVulnerabilities: number;
  activelyExploited: number;
  dependencyCount: number;
  riskBreakdown: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    unknown: number;
  };
};
