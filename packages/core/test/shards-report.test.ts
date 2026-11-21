import { describe, expect, test } from "bun:test";
import {
  AuditSessionError,
  assess,
  createReport,
  isLowSignalPath,
  isPartial,
  isRetryable,
  parseAuditConfig,
  planShards,
  type ChangedFile,
  type Finding,
  type PullRequestContext,
} from "../src/index.js";

function file(path: string, size: number, lowSignal = false): ChangedFile {
  return {
    path,
    status: "modified",
    additions: 1,
    deletions: 0,
    diff: size ? "x".repeat(size) : "",
    lowSignal,
  };
}

function finding(severity: Finding["severity"], line: number): Finding {
  return {
    fingerprint: `${severity}-${line}`,
    check: "functional",
    severity,
    confidence: "high",
    title: "Title",
    description: "Description",
    evidence: "Evidence",
    file: "src/app.ts",
    line,
  };
}

describe("discovery passes", () => {
  test("recognizes lockfiles, bundles, maps, and snapshots", () => {
    for (const path of [
      "pnpm-lock.yaml",
      "packages/app/package-lock.json",
      "Cargo.lock",
      "dist/app.min.js",
      "src/app.js.map",
      "src/__snapshots__/view.test.ts.snap",
    ])
      expect(isLowSignalPath(path)).toBe(true);
    for (const path of ["src/app.ts", "lock.ts", "README.md"])
      expect(isLowSignalPath(path)).toBe(false);
  });

  test("packs source before tests and docs, keeps directories together, and bounds each pass", () => {
    const plan = planShards(
      [
        file("docs/guide.md", 30),
        file("src/b/app.test.ts", 30),
        file("src/b/two.ts", 30),
        file("src/a/one.ts", 30),
        file("src/a/two.ts", 30),
        file("pnpm-lock.yaml", 0, true),
        file("src/huge.ts", 500),
        file("src/missing.ts", 0),
      ],
      { maxShardChars: 100, maxShards: 2 },
    );
    expect(plan.shards.map((shard) => shard.files.map((f) => f.path))).toEqual([
      ["src/a/one.ts", "src/a/two.ts", "src/b/two.ts"],
      ["src/huge.ts"],
    ]);
    expect(plan.shards[0]?.diff).toBe(
      ["x".repeat(30), "x".repeat(30), "x".repeat(30)].join("\n"),
    );
    expect(plan.shards[1]?.diff.length).toBe(100);
    expect(plan.shards[1]?.diff).toEndWith("read the file for the rest]");
    expect(plan.overflow.map((f) => f.path)).toEqual([
      "src/b/app.test.ts",
      "docs/guide.md",
      "src/missing.ts",
    ]);
    expect(planShards([], { maxShardChars: 100, maxShards: 2 })).toEqual({
      shards: [],
      overflow: [],
    });
  });
});

describe("merge confidence", () => {
  test("scores findings like a reviewer would", () => {
    expect(assess([])).toEqual({
      score: 5,
      verdict: "Safe to merge: no verified findings.",
    });
    expect(assess([finding("low", 1), finding("medium", 2)])).toEqual({
      score: 4,
      verdict: "Safe to merge after considering 2 non-blocking findings.",
    });
    expect(assess([finding("medium", 1)]).verdict).toContain(
      "1 non-blocking finding.",
    );
    expect(assess([finding("high", 1), finding("low", 2)])).toEqual({
      score: 3,
      verdict: "Fix 1 blocking finding before merging.",
    });
    expect(assess([finding("high", 1), finding("high", 2)]).score).toBe(2);
    expect(assess([finding("critical", 1)]).score).toBe(2);
    expect(assess([finding("critical", 1), finding("critical", 2)])).toEqual({
      score: 1,
      verdict: "Fix 2 blocking findings before merging.",
    });
  });

  test("caps the score when coverage was partial", () => {
    const full = {
      changedFiles: 3,
      reviewedFiles: 3,
      failedPasses: 0,
      unverifiedCandidates: 0,
    };
    expect(isPartial(undefined)).toBe(false);
    expect(isPartial(full)).toBe(false);
    expect(assess([], full).score).toBe(5);
    for (const partial of [
      { ...full, reviewedFiles: 2 },
      { ...full, failedPasses: 1 },
      { ...full, unverifiedCandidates: 1 },
    ]) {
      expect(isPartial(partial)).toBe(true);
      expect(assess([], partial)).toEqual({
        score: 4,
        verdict:
          "Safe to merge: no verified findings. Coverage was partial, so review the parts Heyo could not audit.",
      });
    }
    expect(
      assess([finding("critical", 1)], { ...full, failedPasses: 1 }).score,
    ).toBe(2);
  });

  test("carries the overview, coverage, and resolved findings into the report", () => {
    const pr: PullRequestContext = {
      owner: "heyo",
      repo: "audit",
      number: 1,
      baseSha: "a".repeat(40),
      baseBranch: "main",
      headSha: "b".repeat(40),
      title: "Title",
      body: "",
    };
    const config = parseAuditConfig({
      model: "gpt",
      "auth-type": "api-key",
      "auth-token": "key",
      "github-token": "token",
    });
    const overview = {
      summary: "Summary.",
      changes: [],
      impact: "low" as const,
      impactReason: "Internal.",
    };
    const coverage = {
      changedFiles: 1,
      reviewedFiles: 1,
      failedPasses: 0,
      unverifiedCandidates: 0,
    };
    expect(
      createReport({
        config,
        pr,
        scope: "full",
        findings: [finding("high", 1)],
        overview,
        coverage,
        resolved: [finding("low", 9)],
      }),
    ).toMatchObject({
      summary: "Heyo verified 1 finding; 1 high or critical.",
      assessment: { score: 3 },
      overview,
      coverage,
      resolved: [{ line: 9 }],
    });
    const plain = createReport({ config, pr, scope: "full", findings: [] });
    expect(plain.overview).toBeUndefined();
    expect(plain.coverage).toBeUndefined();
    expect(plain.resolved).toBeUndefined();
  });
});

test("marks only exhausted budgets as not worth retrying", () => {
  const error = new AuditSessionError("turn limit", false);
  expect(error.name).toBe("AuditSessionError");
  expect(isRetryable(error)).toBe(false);
  expect(isRetryable(new AuditSessionError("rate limited", true))).toBe(true);
  expect(isRetryable(new SyntaxError("bad JSON"))).toBe(true);
});
