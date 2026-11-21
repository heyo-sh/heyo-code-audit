import {
  isPartial,
  redactSecrets,
  type AuditReport,
  type Finding,
} from "@heyo-sh/code-audit-core";

export const FINDING_MARKER_PREFIX = "<!-- heyo-code-audit-finding:";
export const SUMMARY_MARKER = "<!-- heyo-code-audit-summary -->";
const REVIEWS_MARKER = /<!-- heyo-code-audit-reviews:(\d+) -->/;

const PRIORITY: Record<Finding["severity"], string> = {
  critical: "🔴 P0",
  high: "🟠 P1",
  medium: "🟡 P2",
  low: "⚪ P3",
};
const IMPACT: Record<NonNullable<AuditReport["overview"]>["impact"], string> = {
  low: "Low impact",
  medium: "Medium impact",
  high: "High impact",
  critical: "Critical impact",
};

/** The Check-run summary: the complete, self-contained audit record. */
export function formatSummary(report: AuditReport): string {
  const findings = report.findings.map(formatFinding).join("\n\n");
  return [
    heading(report),
    "",
    sanitizeReport(report.summary),
    ...(report.overview ? ["", ...formatOverview(report)] : []),
    "",
    "### Findings",
    "",
    findings || "No verified findings.",
    ...formatResolved(report),
    "",
    footer(report),
  ].join("\n");
}

/**
 * The pull-request summary comment, kept up to date in place: the confidence
 * score, the verdict, linked findings, and what the change does.
 */
export function formatSummaryComment(
  report: AuditReport,
  context: { links: Map<string, string>; reviews: number; commitUrl: string },
): string {
  const unlinked = report.findings.filter(
    (finding) => !context.links.has(finding.fingerprint),
  );
  return [
    SUMMARY_MARKER,
    `<!-- heyo-code-audit-reviews:${context.reviews} -->`,
    heading(report),
    "",
    ...(report.overview
      ? [
          `**[${IMPACT[report.overview.impact]}]** ${sanitizeReport(report.overview.impactReason)}`,
          "",
        ]
      : []),
    report.assessment?.verdict ?? sanitizeReport(report.summary),
    ...(report.findings.length
      ? [
          "",
          "### Findings",
          "",
          ...report.findings.map(
            (finding, index) =>
              `${index + 1}. ${PRIORITY[finding.severity]} **${sanitizeInline(finding.title)}**${location(finding)}${context.links.has(finding.fingerprint) ? ` [▶](${context.links.get(finding.fingerprint)})` : ""}`,
          ),
        ]
      : []),
    ...(report.overview ? ["", ...formatOverview(report)] : []),
    ...(unlinked.length
      ? [
          "",
          "<details><summary><b>Findings without an inline comment</b></summary>",
          "",
          unlinked.map(formatFinding).join("\n\n"),
          "",
          "</details>",
        ]
      : []),
    ...formatResolved(report),
    "",
    `<sub>Reviews (${context.reviews}) · Last reviewed commit: [\`${report.metadata.headSha.slice(0, 7)}\`](${context.commitUrl}) · ${footerFacts(report)}</sub>`,
  ].join("\n");
}

/** The number of reviews recorded in an earlier summary comment. */
export function reviewCount(body: string): number {
  return Number(REVIEWS_MARKER.exec(body)?.[1] ?? 0);
}

export function formatCleanReview(report: AuditReport): string {
  return `## Heyo Code Audit — ${report.conclusion}\n\n${sanitizeReport(report.summary)}`;
}

/** Formats a located finding for a GitHub Check annotation. */
export function formatCheckAnnotation(finding: Finding): {
  path: string;
  start_line: number;
  end_line: number;
  annotation_level: "notice" | "warning" | "failure";
  title: string;
  message: string;
} {
  if (!finding.file || !finding.line)
    throw new Error("Check annotations require a file and line.");
  return {
    path: finding.file,
    start_line: finding.line,
    end_line: finding.line,
    annotation_level:
      finding.severity === "low"
        ? "notice"
        : finding.severity === "medium"
          ? "warning"
          : "failure",
    title:
      `${finding.severity.toUpperCase()} · ${finding.check.toUpperCase()}: ${sanitizeInline(finding.title)}`.slice(
        0,
        255,
      ),
    message: [
      sanitizeReport(finding.description),
      ...(finding.recommendation
        ? [`Fix: ${sanitizeReport(finding.recommendation)}`]
        : []),
      `Evidence: ${sanitizeReport(finding.evidence)}`,
    ]
      .join("\n\n")
      .slice(0, 4_000),
  };
}

/** A GitHub review comment, with an apply-able suggestion when one exists. */
export function formatInlineComment(finding: Finding): string {
  return [
    findingMarker(finding),
    `${PRIORITY[finding.severity]} **${sanitizeInline(finding.title)}**`,
    "",
    sanitizeReport(finding.description),
    ...(finding.recommendation
      ? ["", `**Fix:** ${sanitizeReport(finding.recommendation)}`]
      : []),
    ...(finding.suggestion
      ? ["", "```suggestion", finding.suggestion, "```"]
      : []),
    "",
    `<details><summary>How Heyo verified this · ${finding.check} · ${finding.confidence} confidence</summary>`,
    "",
    sanitizeReport(finding.evidence),
    "",
    "</details>",
  ].join("\n");
}

export function findingMarker(finding: Pick<Finding, "fingerprint">): string {
  return `${FINDING_MARKER_PREFIX}${finding.fingerprint} -->`;
}

function heading(report: AuditReport): string {
  return report.assessment
    ? `## Heyo Code Audit · Confidence Score: ${report.assessment.score}/5`
    : `## Heyo Code Audit — ${report.conclusion}`;
}

function formatOverview(report: AuditReport): string[] {
  const overview = report.overview!;
  return [
    "### Summary",
    "",
    sanitizeReport(overview.summary),
    ...(overview.changes.length
      ? ["", ...overview.changes.map((change) => `- ${sanitizeInline(change)}`)]
      : []),
    ...(overview.diagram
      ? [
          "",
          "<details open><summary><b>Diagram</b></summary>",
          "",
          "```mermaid",
          "%%{init: {'theme': 'neutral'}}%%",
          redactSecrets(overview.diagram),
          "```",
          "",
          "</details>",
        ]
      : []),
  ];
}

function formatResolved(report: AuditReport): string[] {
  if (!report.resolved?.length) return [];
  return [
    "",
    "### Resolved since the last review",
    "",
    ...report.resolved.map(
      (finding) =>
        `- ✅ ~~${sanitizeInline(finding.title)}~~${location(finding)}`,
    ),
  ];
}

function formatFinding(finding: Finding): string {
  const recommendation = finding.recommendation
    ? `\n\n**Fix:** ${sanitizeReport(finding.recommendation)}`
    : "";
  const suggestion = finding.suggestion
    ? `\n\n**Suggested replacement:**\n\n\`\`\`\n${finding.suggestion}\n\`\`\``
    : "";
  return `#### ${PRIORITY[finding.severity]} ${sanitizeInline(finding.title)}${location(finding)}\n\n${sanitizeReport(finding.description)}${recommendation}\n\n**Evidence:** ${sanitizeReport(finding.evidence)}${suggestion}`;
}

function footer(report: AuditReport): string {
  return `<sub>Commit \`${report.metadata.headSha.slice(0, 7)}\` · ${footerFacts(report)}</sub>`;
}

function footerFacts(report: AuditReport): string {
  const coverage = report.coverage;
  const facts = [
    `Scope: ${report.metadata.scope}`,
    `Model: ${sanitizeInline(`${report.metadata.provider}/${report.metadata.model}`)}`,
  ];
  if (coverage) {
    facts.push(
      `Reviewed ${coverage.reviewedFiles} of ${coverage.changedFiles} changed files`,
    );
    if (coverage.failedPasses)
      facts.push(`${coverage.failedPasses} review pass(es) failed`);
    if (coverage.unverifiedCandidates)
      facts.push(
        `${coverage.unverifiedCandidates} candidate(s) could not be verified`,
      );
    if (isPartial(coverage)) facts.push("⚠️ partial coverage");
  }
  return facts.join(" · ");
}

function location(finding: Finding): string {
  return finding.file
    ? ` — \`${sanitizeInline(finding.file)}${finding.line ? `:${finding.line}` : ""}\``
    : "";
}

function sanitizeInline(value: string): string {
  return sanitizeReport(value).replaceAll("`", "'").replaceAll("\n", " ");
}

/**
 * Model text is untrusted: redact secrets, neutralize mentions so findings
 * never notify people, and break HTML comments so they cannot forge markers.
 */
function sanitizeReport(value: string): string {
  return redactSecrets(value)
    .replaceAll("<!--", "&lt;!--")
    .replaceAll(/@(?=[A-Za-z0-9-])/g, "@\u200b")
    .slice(0, 55_000);
}
