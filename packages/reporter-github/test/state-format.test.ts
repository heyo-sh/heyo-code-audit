import { describe, expect, test } from "bun:test";
import {
  findingMarker,
  formatCheckAnnotation,
  formatCleanReview,
  formatInlineComment,
  formatSummary,
  formatSummaryComment,
  decodeAuditState,
  encodeAuditState,
  reviewCount,
} from "../src/index.js";
import type { AuditReport, AuditState } from "@heyo-sh/code-audit-core";

const state: AuditState = {
  version: 1,
  baseSha: "a".repeat(40),
  auditedHeadSha: "b".repeat(40),
  configHash: "c".repeat(64),
  policyVersion: "policy",
  findings: [
    {
      fingerprint: "x",
      check: "security",
      severity: "high",
      confidence: "high",
      title: "Leaked token",
      description: "The API token is returned to the client.",
      evidence: "token=abcdefghijklmnopqrstuvwxyz",
      suggestion: "return redact(token);",
      file: "src/api.ts",
      line: 8,
    },
  ],
};

const { suggestion: _suggestion, ...unsuggested } = state.findings[0]!;
const { file: _file, line: _line, ...unlocated } = unsuggested;

const report: AuditReport = {
  version: 1,
  conclusion: "failure",
  findings: state.findings,
  summary: "One verified finding.",
  metadata: {
    runtime: "pi",
    provider: "openai",
    model: "gpt",
    baseSha: state.baseSha,
    headSha: state.auditedHeadSha,
    verification: true,
    scope: "full",
  },
};

describe("GitHub report state and format", () => {
  test("round-trips only valid owned machine state", () => {
    const encoded = encodeAuditState(state);
    const decoded = decodeAuditState(`report\n${encoded}`);
    expect(decoded).toMatchObject({
      ...state,
      findings: [
        {
          check: "security",
          severity: "high",
          confidence: "high",
          title: "Leaked token",
        },
      ],
    });
    expect(decoded?.findings[0]?.fingerprint).toEqual(expect.any(String));
    expect(
      decodeAuditState("<!-- heyo-code-audit-state:not-base64 -->"),
    ).toBeUndefined();
  });

  test("formats the Check summary and inline comments, redacting values that resemble secrets", () => {
    const summary = formatSummary(report);
    expect(summary).toContain("[REDACTED_SECRET]");
    expect(summary).not.toContain("abcdefghijklmnopqrstuvwxyz");
    expect(summary).toStartWith("## Heyo Code Audit — failure");
    expect(summary).toContain("#### 🟠 P1 Leaked token — `src/api.ts:8`");
    expect(summary).toContain("**Suggested replacement:**");
    expect(formatCleanReview(report)).toBe(
      "## Heyo Code Audit — failure\n\nOne verified finding.",
    );
    const inline = formatInlineComment({
      ...state.findings[0]!,
      recommendation: "Return a redacted token.",
    });
    expect(inline).toStartWith(findingMarker(state.findings[0]!));
    expect(inline).toContain("🟠 P1 **Leaked token**");
    expect(inline).toContain("**Fix:** Return a redacted token.");
    expect(inline).toContain("```suggestion\nreturn redact(token);\n```");
    expect(inline).toContain(
      "<details><summary>How Heyo verified this · security · high confidence</summary>",
    );
    expect(formatInlineComment(unsuggested)).not.toContain("suggestion");
    expect(formatCheckAnnotation(state.findings[0]!)).toEqual({
      path: "src/api.ts",
      start_line: 8,
      end_line: 8,
      annotation_level: "failure",
      title: "HIGH · SECURITY: Leaked token",
      message:
        "The API token is returned to the client.\n\nEvidence: token=[REDACTED_SECRET]",
    });
    expect(
      formatCheckAnnotation({ ...state.findings[0]!, severity: "low" })
        .annotation_level,
    ).toBe("notice");
    expect(() => formatCheckAnnotation(unlocated)).toThrow("file and line");
  });

  test("formats the scored summary comment with overview, links, coverage, and resolved findings", () => {
    const scored: AuditReport = {
      ...report,
      findings: [
        state.findings[0]!,
        {
          ...unlocated,
          fingerprint: "y",
          severity: "low",
          title: "Ping @octocat <!-- heyo-code-audit-summary -->",
          recommendation: "Mention @team in docs.",
        },
      ],
      assessment: {
        score: 3,
        verdict: "Fix 1 blocking finding before merging.",
      },
      overview: {
        summary: "Adds tokens.",
        changes: ["Tokens are returned."],
        impact: "high",
        impactReason: "Reaches every API client.",
        diagram: "flowchart LR\n A[Request] --> B[Token]",
      },
      coverage: {
        changedFiles: 4,
        reviewedFiles: 3,
        failedPasses: 1,
        unverifiedCandidates: 2,
      },
      resolved: [{ ...state.findings[0]!, title: "Old leak" }],
    };
    const body = formatSummaryComment(scored, {
      links: new Map([["x", "https://github.test/c/1"]]),
      reviews: 2,
      commitUrl: "https://github.test/commit/b",
    });
    expect(body).toStartWith(
      "<!-- heyo-code-audit-summary -->\n<!-- heyo-code-audit-reviews:2 -->",
    );
    expect(reviewCount(body)).toBe(2);
    expect(reviewCount("no marker")).toBe(0);
    expect(body).toContain("## Heyo Code Audit · Confidence Score: 3/5");
    expect(body).toContain("**[High impact]** Reaches every API client.");
    expect(body).toContain("Fix 1 blocking finding before merging.");
    expect(body).toContain(
      "1. 🟠 P1 **Leaked token** — `src/api.ts:8` [▶](https://github.test/c/1)",
    );
    expect(body).toContain(
      "2. ⚪ P3 **Ping @\u200boctocat &lt;!-- heyo-code-audit-summary -->**",
    );
    expect(body.match(/<!-- heyo-code-audit-summary -->/g)).toHaveLength(1);
    expect(body).toContain("**Fix:** Mention @\u200bteam in docs.");
    expect(body).toContain("- Tokens are returned.");
    expect(body).toContain(
      "```mermaid\n%%{init: {'theme': 'neutral'}}%%\nflowchart LR",
    );
    expect(body).toContain(
      "### Resolved since the last review\n\n- ✅ ~~Old leak~~ — `src/api.ts:8`",
    );
    expect(body).toContain(
      "<sub>Reviews (2) · Last reviewed commit: [`bbbbbbb`](https://github.test/commit/b) · Scope: full · Model: openai/gpt · Reviewed 3 of 4 changed files · 1 review pass(es) failed · 2 candidate(s) could not be verified · ⚠️ partial coverage</sub>",
    );

    const clean = formatSummaryComment(
      {
        ...report,
        findings: [],
        assessment: {
          score: 5,
          verdict: "Safe to merge: no verified findings.",
        },
        overview: {
          summary: "Adds tokens.",
          changes: [],
          impact: "high",
          impactReason: "Reaches every API client.",
        },
        coverage: {
          ...scored.coverage!,
          reviewedFiles: 4,
          failedPasses: 0,
          unverifiedCandidates: 0,
        },
      },
      {
        links: new Map(),
        reviews: 1,
        commitUrl: "https://github.test/commit/b",
      },
    );
    expect(clean).toContain("Confidence Score: 5/5");
    expect(clean).not.toContain("### Findings");
    expect(clean).not.toContain("mermaid");
    expect(clean).not.toContain("partial coverage");
    expect(formatSummary(scored)).toContain("### Summary\n\nAdds tokens.");
    expect(formatSummary(scored)).toContain("~~Old leak~~");
  });
});
