export const CHECK_IDS = [
  "security",
  "regression",
  "functional",
  "nonfunctional",
] as const;
export const SEVERITIES = ["low", "medium", "high", "critical"] as const;
export const CONFIDENCES = ["medium", "high"] as const;
export const CONCLUSIONS = ["success", "neutral", "failure"] as const;
export const IMPACTS = ["low", "medium", "high", "critical"] as const;

export type CheckId = (typeof CHECK_IDS)[number];
export type Severity = (typeof SEVERITIES)[number];
export type Confidence = (typeof CONFIDENCES)[number];
export type Conclusion = (typeof CONCLUSIONS)[number];
export type Impact = (typeof IMPACTS)[number];
export type ProviderId = string;
export type AuditAuth =
  | { type: "api-key"; token: string }
  | { type: "oauth"; token: string }
  | { type: "aws"; region?: string; profile?: string }
  | { type: "bedrock-bearer"; token: string; region?: string };
export type AuditScope = "full" | "incremental";
export type ReportMode = "check" | "comment" | "check-and-comment" | "none";
export type CommitLimit = number | "unlimited";

export interface Finding {
  fingerprint: string;
  check: CheckId;
  severity: Severity;
  confidence: Confidence;
  title: string;
  description: string;
  evidence: string;
  /** Short, concrete repair advice for the PR author. */
  recommendation?: string;
  /** Exact replacement for the selected diff line, when a safe fix exists. */
  suggestion?: string;
  file?: string;
  line?: number;
}

export interface AuditState {
  version: 1;
  /** The merge base of the audited pull request, which is its diff base. */
  baseSha: string;
  auditedHeadSha: string;
  configHash: string;
  policyVersion: string;
  findings: Finding[];
}

/** A reviewer-facing description of what a pull request changes. */
export interface PullRequestOverview {
  summary: string;
  changes: string[];
  /** How far a defect in this change could reach. */
  impact: Impact;
  impactReason: string;
  /** Optional Mermaid source for a multi-step flow the change implements. */
  diagram?: string;
}

/** How much of the change set the audit actually covered. */
export interface AuditCoverage {
  changedFiles: number;
  reviewedFiles: number;
  /** Discovery passes that failed even after a retry. */
  failedPasses: number;
  /** Candidates whose verification failed even after a retry. */
  unverifiedCandidates: number;
}

/** The merge-confidence score shown on the pull request, from 1 to 5. */
export interface AuditAssessment {
  score: 1 | 2 | 3 | 4 | 5;
  verdict: string;
}

export interface AuditReport {
  version: 1;
  conclusion: Conclusion;
  findings: Finding[];
  summary: string;
  assessment?: AuditAssessment;
  overview?: PullRequestOverview;
  coverage?: AuditCoverage;
  /** Findings of the previous audit that no longer reproduce. */
  resolved?: Finding[];
  metadata: {
    runtime: "pi";
    provider: string;
    model: string;
    baseSha: string;
    headSha: string;
    verification: boolean;
    scope: AuditScope;
    previousHeadSha?: string;
  };
}

/** Where Pi sessions are traced. Tracing never changes audit results. */
export interface LangfuseConfig {
  publicKey: string;
  secretKey: string;
  baseUrl: string;
  environment?: string;
}

export interface AuditConfig {
  provider: ProviderId;
  model: string;
  auth: AuditAuth;
  githubToken: string;
  checks: CheckId[];
  verification: boolean;
  report: ReportMode;
  commentOnClean: boolean;
  /** Keep one updatable pull-request comment with the score and overview. */
  summaryComment: boolean;
  failOn: Severity | "never";
  paths: string[];
  incremental: boolean;
  maxPrCommits: CommitLimit;
  maxNewCommits: CommitLimit;
  /** Present only when both Langfuse keys are configured. */
  langfuse?: LangfuseConfig;
}

export interface PullRequestContext {
  owner: string;
  repo: string;
  number: number;
  baseSha: string;
  baseBranch: string;
  headSha: string;
  title: string;
  body: string;
}

export interface CommitMetadata {
  sha: string;
  message: string;
}

export interface ChangedFile {
  path: string;
  status: "added" | "modified" | "deleted" | "renamed";
  additions: number;
  deletions: number;
  /** The bounded diff of this file; empty when it did not fit the snapshot. */
  diff: string;
  /** Lockfiles, generated, binary, and snapshot files are listed, not audited. */
  lowSignal: boolean;
}

export interface RepositorySnapshot {
  repositoryPath: string;
  baseSha: string;
  headSha: string;
  diff: string;
  /** Per-file view of the same diff. */
  files: ChangedFile[];
  changedPaths: string[];
  /** Applicable AGENTS.md files from the PR target's base commit. */
  guidance: Array<{ path: string; content: string }>;
  commits: CommitMetadata[];
}

export interface RuntimeLimits {
  maxTurns: number;
  maxToolCalls: number;
  maxTokens: number;
  maxFileBytes: number;
  maxSearchResults: number;
  maxDiffBytes: number;
  maxOutputBytes: number;
  timeoutMs: number;
}

export interface RuntimeInput {
  repositoryPath: string;
  baseSha: string;
  headSha: string;
  phase: "discovery" | "verification" | "summary";
  checks: CheckId[];
  provider: ProviderId;
  model: string;
  auth: AuditAuth;
  internalPrompt: string;
  permissions: "read-only";
  limits: RuntimeLimits;
}

export interface DiscoveryResult {
  findings: Finding[];
}

export interface VerificationResult {
  verified: boolean;
  finding?: Finding;
  reason?: string;
}

export interface OverviewResult {
  overview: PullRequestOverview;
}

export type AuditPhaseResult =
  DiscoveryResult | VerificationResult | OverviewResult;

export interface AuditRuntime {
  run(input: RuntimeInput): Promise<AuditPhaseResult>;
}

export interface AuditRepository {
  getPullRequest(): Promise<PullRequestContext>;
  getSnapshot(
    baseSha: string,
    headSha: string,
    paths: string[],
    guidanceBaseSha?: string,
  ): Promise<RepositorySnapshot>;
  countCommits(baseSha: string, headSha: string): Promise<number>;
  /** The commit GitHub diffs a pull request against. */
  mergeBase(baseSha: string, headSha: string): Promise<string>;
  isAncestor(ancestor: string, descendant: string): Promise<boolean>;
  findLatestState(pr: PullRequestContext): Promise<AuditState | undefined>;
  isCurrentHead(pr: PullRequestContext, headSha: string): Promise<boolean>;
}

export interface AuditPublisher {
  publish(input: {
    pr: PullRequestContext;
    report: AuditReport;
    state?: AuditState;
    /** The audited diff lets reporters attach findings to changed PR lines. */
    snapshot?: Pick<RepositorySnapshot, "diff">;
  }): Promise<void>;
}

export type RunOutcome =
  | { kind: "published"; report: AuditReport; state?: AuditState }
  | { kind: "stale" }
  | { kind: "skipped"; report: AuditReport }
  | { kind: "errored"; report: AuditReport; error: unknown };
