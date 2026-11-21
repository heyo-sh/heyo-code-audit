import { deduplicateFindings, severityRank } from "./schema.js";
import type {
  AuditAssessment,
  AuditConfig,
  AuditCoverage,
  AuditReport,
  AuditScope,
  Finding,
  PullRequestContext,
  PullRequestOverview,
} from "./types.js";

export function createReport(input: {
  config: AuditConfig;
  pr: PullRequestContext;
  scope: AuditScope;
  previousHeadSha?: string;
  findings: Finding[];
  overview?: PullRequestOverview;
  coverage?: AuditCoverage;
  resolved?: Finding[];
}): AuditReport {
  const findings = deduplicateFindings(input.findings);
  const conclusion = conclusionFor(findings, input.config.failOn);
  const count = findings.length;
  const summary =
    count === 0
      ? "Heyo completed the audit with no verified findings."
      : `Heyo verified ${count} finding${count === 1 ? "" : "s"}; ${blockingCount(findings)} high or critical.`;
  return {
    version: 1,
    conclusion,
    findings,
    summary,
    assessment: assess(findings, input.coverage),
    ...(input.overview ? { overview: input.overview } : {}),
    ...(input.coverage ? { coverage: input.coverage } : {}),
    ...(input.resolved?.length ? { resolved: input.resolved } : {}),
    metadata: {
      runtime: "pi",
      provider: input.config.provider,
      model: input.config.model,
      baseSha: input.pr.baseSha,
      headSha: input.pr.headSha,
      verification: input.config.verification,
      scope: input.scope,
      ...(input.previousHeadSha
        ? { previousHeadSha: input.previousHeadSha }
        : {}),
    },
  };
}

/**
 * Scores merge confidence from the verified findings: 5 with none, 4 with only
 * non-blocking findings, 3 with one high, 2 with several high or one critical,
 * and 1 with several critical. Partial coverage caps the score at 4.
 */
export function assess(
  findings: Finding[],
  coverage?: AuditCoverage,
): AuditAssessment {
  const critical = findings.filter(
    (finding) => finding.severity === "critical",
  ).length;
  const high = findings.filter((finding) => finding.severity === "high").length;
  const blocking = critical + high;
  const score =
    critical >= 2
      ? 1
      : critical === 1 || high >= 2
        ? 2
        : high === 1
          ? 3
          : findings.length > 0
            ? 4
            : 5;
  const verdict =
    blocking > 0
      ? `Fix ${plural(blocking, "blocking finding")} before merging.`
      : findings.length > 0
        ? `Safe to merge after considering ${plural(findings.length, "non-blocking finding")}.`
        : "Safe to merge: no verified findings.";
  if (!isPartial(coverage)) return { score, verdict };
  return {
    score: Math.min(score, 4) as AuditAssessment["score"],
    verdict: `${verdict} Coverage was partial, so review the parts Heyo could not audit.`,
  };
}

export function isPartial(coverage: AuditCoverage | undefined): boolean {
  return Boolean(
    coverage &&
    (coverage.failedPasses > 0 ||
      coverage.unverifiedCandidates > 0 ||
      coverage.reviewedFiles < coverage.changedFiles),
  );
}

export function neutralReport(input: {
  config: AuditConfig;
  pr: PullRequestContext;
  summary: string;
  scope: AuditScope;
}): AuditReport {
  return {
    version: 1,
    conclusion: "neutral",
    findings: [],
    summary: input.summary,
    metadata: {
      runtime: "pi",
      provider: input.config.provider,
      model: input.config.model,
      baseSha: input.pr.baseSha,
      headSha: input.pr.headSha,
      verification: input.config.verification,
      scope: input.scope,
    },
  };
}

export function errorReport(
  input: Parameters<typeof neutralReport>[0],
): AuditReport {
  return { ...neutralReport(input), conclusion: "failure" };
}

export function conclusionFor(
  findings: Finding[],
  failOn: AuditConfig["failOn"],
): AuditReport["conclusion"] {
  if (failOn === "never") return "success";
  return findings.some(
    (finding) => severityRank(finding.severity) >= severityRank(failOn),
  )
    ? "failure"
    : "success";
}

function blockingCount(findings: Finding[]): number {
  return findings.filter(
    (finding) => severityRank(finding.severity) >= severityRank("high"),
  ).length;
}

function plural(count: number, noun: string): string {
  return `${count} ${noun}${count === 1 ? "" : "s"}`;
}
