import { describe, expect, test } from "bun:test";
import {
  AuditService,
  AuditSessionError,
  MAX_PASS_DIFF_CHARS,
  PHASE_LIMITS,
  POLICY_VERSION,
  configHash,
  parseAuditConfig,
  type AuditConfig,
  type AuditPhaseResult,
  type AuditPublisher,
  type AuditReport,
  type AuditRepository,
  type AuditRuntime,
  type AuditState,
  type ChangedFile,
  type Finding,
  type PullRequestContext,
  type RepositorySnapshot,
  type RuntimeInput,
} from "../src/index.js";

const mergeBase = "d".repeat(40);
const pr: PullRequestContext = {
  owner: "heyo",
  repo: "audit",
  number: 4,
  baseSha: "a".repeat(40),
  baseBranch: "staging",
  headSha: "b".repeat(40),
  title: "Add account lookup",
  body: "",
};
const config = parseAuditConfig({
  model: "gpt-5.6-terra",
  "auth-type": "api-key",
  "auth-token": "key",
  "github-token": "token",
});
const candidate: Finding = {
  fingerprint: "candidate",
  check: "security",
  severity: "high",
  confidence: "high",
  title: "Authorization missing",
  description: "The route reads an account without a tenant check.",
  evidence: "src/route.ts:12",
  file: "src/route.ts",
  line: 12,
};
const overview = {
  summary: "Adds an account lookup.",
  changes: ["Accounts can be looked up."],
  impact: "medium" as const,
  impactReason: "Affects account pages.",
};

function changedFile(path: string, diff = `diff --git a/${path} b/${path}`) {
  return {
    path,
    status: "modified",
    additions: 1,
    deletions: 1,
    diff,
    lowSignal: false,
  } satisfies ChangedFile;
}

class FakeRepository implements AuditRepository {
  state?: AuditState;
  commits = 1;
  ancestor = true;
  current = true;
  files: ChangedFile[] = [changedFile("src/route.ts")];
  snapshots: Array<{
    base: string;
    head: string;
    paths: string[];
    guidanceBase: string;
  }> = [];
  async getPullRequest() {
    return pr;
  }
  async getSnapshot(
    baseSha: string,
    headSha: string,
    paths: string[],
    guidanceBaseSha = baseSha,
  ): Promise<RepositorySnapshot> {
    this.snapshots.push({
      base: baseSha,
      head: headSha,
      paths,
      guidanceBase: guidanceBaseSha,
    });
    return {
      repositoryPath: "/repo",
      baseSha,
      headSha,
      diff: "diff",
      files: this.files,
      changedPaths: this.files.map((file) => file.path),
      guidance: [
        { path: "AGENTS.md", content: "All routes must validate the tenant." },
      ],
      commits: [],
    };
  }
  async countCommits() {
    return this.commits;
  }
  async mergeBase() {
    return mergeBase;
  }
  async isAncestor() {
    return this.ancestor;
  }
  async findLatestState() {
    return this.state;
  }
  async isCurrentHead() {
    return this.current;
  }
}

type Behavior = (
  input: RuntimeInput,
  call: number,
) => AuditPhaseResult | Promise<AuditPhaseResult>;

class FakeRuntime implements AuditRuntime {
  inputs: RuntimeInput[] = [];
  calls: Record<RuntimeInput["phase"], number> = {
    discovery: 0,
    verification: 0,
    summary: 0,
  };
  behavior: Partial<Record<RuntimeInput["phase"], Behavior>> = {};
  async run(input: RuntimeInput): Promise<AuditPhaseResult> {
    this.inputs.push(input);
    this.calls[input.phase] += 1;
    const behavior = this.behavior[input.phase];
    if (behavior) return behavior(input, this.calls[input.phase]);
    if (input.phase === "discovery") return { findings: [candidate] };
    if (input.phase === "summary") return { overview };
    return { verified: true, finding: candidate };
  }
  prompts(phase: RuntimeInput["phase"]): string[] {
    return this.inputs
      .filter((input) => input.phase === phase)
      .map((input) => input.internalPrompt);
  }
}

class FakePublisher implements AuditPublisher {
  publications: Array<{
    state?: AuditState;
    report: AuditReport;
    snapshot?: Pick<RepositorySnapshot, "diff">;
  }> = [];
  async publish(input: {
    state?: AuditState;
    report: AuditReport;
    snapshot?: Pick<RepositorySnapshot, "diff">;
  }) {
    this.publications.push(input);
  }
}

function service(repository = new FakeRepository()) {
  const runtime = new FakeRuntime();
  const publisher = new FakePublisher();
  return {
    repository,
    runtime,
    publisher,
    audit: new AuditService({ repository, runtime, publisher }),
  };
}

function previousState(overrides: Partial<AuditState> = {}): AuditState {
  return {
    version: 1,
    baseSha: mergeBase,
    auditedHeadSha: "c".repeat(40),
    configHash: configHash(config),
    policyVersion: POLICY_VERSION,
    findings: [],
    ...overrides,
  };
}

describe("audit pipeline", () => {
  test("audits the merge-base diff, verifies candidates, summarizes, and persists state", async () => {
    const setup = service();
    const outcome = await setup.audit.run(config);
    expect(outcome.kind).toBe("published");
    expect(setup.repository.snapshots).toEqual([
      {
        base: mergeBase,
        head: pr.headSha,
        paths: [],
        guidanceBase: pr.baseSha,
      },
    ]);
    // A small change set is reviewed from two perspectives in parallel.
    expect(setup.runtime.calls).toEqual({
      discovery: 2,
      verification: 1,
      summary: 1,
    });
    expect(setup.runtime.prompts("discovery")[0]).toContain(
      "Focus of this pass: contracts and data.",
    );
    expect(setup.runtime.prompts("discovery")[1]).toContain(
      "Focus of this pass: runtime behavior.",
    );
    const publication = setup.publisher.publications[0]!;
    expect(publication.state).toMatchObject({
      baseSha: mergeBase,
      policyVersion: POLICY_VERSION,
    });
    expect(publication.snapshot).toEqual({ diff: "diff" });
    expect(publication.report).toMatchObject({
      overview,
      assessment: { score: 3 },
      coverage: {
        changedFiles: 1,
        reviewedFiles: 1,
        failedPasses: 0,
        unverifiedCandidates: 0,
      },
    });
    for (const prompt of [
      ...setup.runtime.prompts("discovery"),
      ...setup.runtime.prompts("verification"),
    ]) {
      expect(prompt).toContain("<untrusted-pr-target-branch>\nstaging");
      expect(prompt).toContain("<untrusted-pr-title>\nAdd account lookup");
      expect(prompt).toContain(
        "AGENTS.md:\nAll routes must validate the tenant.",
      );
    }
    expect(setup.runtime.prompts("discovery")[0]).toContain(
      "This pass reviews the whole change set.",
    );
  });

  test("sizes each phase's session budget for its job", () => {
    for (const limits of Object.values(PHASE_LIMITS)) {
      // Reasoning tokens are drawn from the response budget, so a small
      // `maxTokens` truncates answers and burns turns on continuations.
      expect(limits.maxTokens).toBeGreaterThanOrEqual(32_000);
      // A turn can call at least two tools before the tool budget ends it.
      expect(limits.maxToolCalls).toBeGreaterThanOrEqual(limits.maxTurns * 2);
      expect(limits.timeoutMs).toBeLessThanOrEqual(20 * 60_000);
    }
    expect(PHASE_LIMITS.discovery.maxTurns).toBe(120);
    expect(PHASE_LIMITS.verification.maxTurns).toBeLessThan(
      PHASE_LIMITS.discovery.maxTurns,
    );
    expect(PHASE_LIMITS.summary.maxTurns).toBeLessThan(
      PHASE_LIMITS.verification.maxTurns,
    );
    // Passes run in parallel, so one discovery and one verification deadline
    // must fit a one-hour job with room for retries of fast failures.
    expect(
      PHASE_LIMITS.discovery.timeoutMs + PHASE_LIMITS.verification.timeoutMs,
    ).toBeLessThanOrEqual(35 * 60_000);
  });

  test("splits a large change set into parallel discovery passes", async () => {
    const repository = new FakeRepository();
    repository.files = [
      changedFile("src/a.ts", "a".repeat(MAX_PASS_DIFF_CHARS - 10)),
      changedFile("src/b.ts", "b".repeat(MAX_PASS_DIFF_CHARS - 10)),
      { ...changedFile("pnpm-lock.yaml"), lowSignal: true, diff: "" },
    ];
    const setup = service(repository);
    setup.runtime.behavior.discovery = (input) => ({
      findings: input.internalPrompt.includes("pass 1 of 2")
        ? [candidate]
        : [{ ...candidate, fingerprint: "other", severity: "medium" }],
    });
    const outcome = await setup.audit.run(config);
    expect(setup.runtime.calls.discovery).toBe(4);
    // Every pass found the same location, so it is verified once.
    expect(setup.runtime.calls.verification).toBe(1);
    expect(setup.runtime.prompts("discovery")[2]).toContain("pass 2 of 2");
    expect(outcome).toMatchObject({
      kind: "published",
      report: { coverage: { changedFiles: 2, reviewedFiles: 2 } },
    });
  });

  test("uses a compatible state incrementally, re-verifies its findings, and reports resolved ones", async () => {
    const repository = new FakeRepository();
    const older = {
      ...candidate,
      fingerprint: "old",
      file: "src/other.ts",
      title: "Old defect",
    };
    repository.state = previousState({ findings: [older] });
    const setup = service(repository);
    setup.runtime.behavior.verification = (input) =>
      input.internalPrompt.includes("Old defect")
        ? { verified: false, reason: "Fixed." }
        : { verified: true, finding: candidate };
    const outcome = await setup.audit.run(config);
    expect(repository.snapshots.map((snapshot) => snapshot.base)).toEqual([
      "c".repeat(40),
      mergeBase,
    ]);
    expect(repository.snapshots[0]?.guidanceBase).toBe(pr.baseSha);
    expect(setup.runtime.calls.verification).toBe(2);
    expect(outcome).toMatchObject({
      kind: "published",
      report: {
        findings: [candidate],
        resolved: [older],
        metadata: { scope: "incremental", previousHeadSha: "c".repeat(40) },
      },
      state: { findings: [candidate] },
    });
  });

  test("falls back to a full audit when state is incompatible", async () => {
    for (const [state, ancestor] of [
      [previousState({ configHash: "different" }), true],
      [previousState({ policyVersion: "old" }), true],
      [previousState({ baseSha: "e".repeat(40) }), true],
      [previousState(), false],
    ] as const) {
      const repository = new FakeRepository();
      repository.state = state;
      repository.ancestor = ancestor;
      const setup = service(repository);
      await setup.audit.run(config);
      expect(repository.snapshots).toHaveLength(1);
      expect(repository.snapshots[0]?.base).toBe(mergeBase);
    }
  });

  test("skips before invoking Pi when a commit limit is exceeded", async () => {
    const setup = service();
    setup.repository.commits = 101;
    const outcome = await setup.audit.run(config);
    expect(outcome.kind).toBe("skipped");
    expect(setup.runtime.inputs).toHaveLength(0);
    expect(setup.publisher.publications[0]?.state).toBeUndefined();
    expect(setup.publisher.publications[0]?.report.conclusion).toBe("neutral");

    const incremental = new FakeRepository();
    incremental.state = previousState();
    incremental.commits = 21;
    const limited = service(incremental);
    expect(await limited.audit.run(config)).toMatchObject({
      kind: "skipped",
      report: { summary: expect.stringContaining("max-new-commits=20") },
    });
  });

  test("does not publish stale heads and fails without state when every pass fails", async () => {
    const stale = service();
    stale.repository.current = false;
    expect((await stale.audit.run(config)).kind).toBe("stale");
    expect(stale.publisher.publications).toHaveLength(0);

    const broken = service();
    broken.runtime.behavior.discovery = () => {
      throw new Error("provider log with secret");
    };
    const outcome = await broken.audit.run(config);
    expect(outcome).toMatchObject({
      kind: "errored",
      report: {
        conclusion: "failure",
        summary:
          "Heyo could not complete this full audit while running discovery. No audit state was advanced.",
      },
    });
    if (outcome.kind !== "errored") throw new Error("Expected an error.");
    expect(outcome.error).toBeInstanceOf(Error);
    // A plain error is retried once with a fresh session.
    expect(broken.runtime.calls.discovery).toBe(4);
    expect(broken.publisher.publications[0]?.state).toBeUndefined();

    const mismatched = service();
    mismatched.runtime.behavior.discovery = () => ({ verified: false });
    const mismatch = await mismatched.audit.run(config);
    if (mismatch.kind !== "errored") throw new Error("Expected an error.");
    expect((mismatch.error as Error).message).toContain(
      "another phase's result",
    );
  });

  test("retries a recoverable session once and never retries an exhausted budget", async () => {
    const recovered = service();
    recovered.runtime.behavior.discovery = (_input, call) => {
      if (call === 1) throw new AuditSessionError("rate limited", true);
      return { findings: [] };
    };
    expect(await recovered.audit.run(config)).toMatchObject({
      kind: "published",
      report: { assessment: { score: 5 } },
    });
    expect(recovered.runtime.calls.discovery).toBe(3);

    const exhausted = service();
    exhausted.runtime.behavior.discovery = () => {
      throw new AuditSessionError("turn limit", false);
    };
    expect((await exhausted.audit.run(config)).kind).toBe("errored");
    expect(exhausted.runtime.calls.discovery).toBe(2);

    // A session that failed late is not retried, to stay inside the job.
    const late = service();
    const now = Date.now;
    let clock = 0;
    Date.now = () => clock;
    late.runtime.behavior.discovery = () => {
      clock += PHASE_LIMITS.discovery.timeoutMs;
      throw new AuditSessionError("malformed answer", true);
    };
    try {
      expect((await late.audit.run(config)).kind).toBe("errored");
    } finally {
      Date.now = now;
    }
    expect(late.runtime.calls.discovery).toBe(2);
  });

  test("publishes partial coverage without advancing state when some sessions fail", async () => {
    const repository = new FakeRepository();
    repository.files = [
      changedFile("src/a.ts", "a".repeat(MAX_PASS_DIFF_CHARS - 10)),
      changedFile("src/b.ts", "b".repeat(MAX_PASS_DIFF_CHARS - 10)),
    ];
    const setup = service(repository);
    setup.runtime.behavior.discovery = (input) => {
      if (input.internalPrompt.includes("pass 2 of 2"))
        throw new AuditSessionError("timed out", false);
      return {
        findings: [
          candidate,
          { ...candidate, fingerprint: "second", line: 20, title: "Second" },
        ],
      };
    };
    setup.runtime.behavior.verification = (input) => {
      if (input.internalPrompt.includes("Second"))
        throw new AuditSessionError("timed out", false);
      return { verified: true, finding: candidate };
    };
    const outcome = await setup.audit.run(config);
    expect(outcome).toMatchObject({
      kind: "published",
      report: {
        coverage: {
          changedFiles: 2,
          reviewedFiles: 1,
          failedPasses: 2,
          unverifiedCandidates: 1,
        },
        assessment: { score: 3 },
      },
    });
    if (outcome.kind !== "published") throw new Error("Expected publication.");
    expect(outcome.state).toBeUndefined();
  });

  test("counts a file group as reviewed when one of its perspectives succeeds", async () => {
    const setup = service();
    setup.runtime.behavior.discovery = (input) => {
      if (input.internalPrompt.includes("Focus of this pass: runtime behavior"))
        throw new AuditSessionError("timed out", false);
      return { findings: [] };
    };
    expect(await setup.audit.run(config)).toMatchObject({
      kind: "published",
      report: {
        coverage: { reviewedFiles: 1, failedPasses: 1 },
        assessment: { score: 4 },
      },
    });
  });

  test("fails when every candidate's verification fails", async () => {
    const setup = service();
    setup.runtime.behavior.verification = () => {
      throw new AuditSessionError("provider down", false);
    };
    expect(await setup.audit.run(config)).toMatchObject({
      kind: "errored",
      report: {
        summary: expect.stringContaining("verifying candidate findings"),
      },
    });

    const mismatched = service();
    mismatched.runtime.behavior.verification = () => ({ findings: [] });
    const outcome = await mismatched.audit.run(config);
    if (outcome.kind !== "errored") throw new Error("Expected an error.");
    expect((outcome.error as Error).message).toContain(
      "another phase's result",
    );
  });

  test("never lets the optional overview fail or delay an audit", async () => {
    const failing = service();
    failing.runtime.behavior.summary = () => {
      throw new AuditSessionError("summary failed", false);
    };
    const outcome = await failing.audit.run(config);
    expect(outcome.kind).toBe("published");
    if (outcome.kind !== "published") throw new Error("Expected publication.");
    expect(outcome.report.overview).toBeUndefined();

    const disabled = service();
    await disabled.audit.run({ ...config, summaryComment: false });
    expect(disabled.runtime.calls.summary).toBe(0);

    const empty = new FakeRepository();
    empty.files = [];
    const nothing = service(empty);
    expect(await nothing.audit.run(config)).toMatchObject({
      kind: "published",
      report: { findings: [], assessment: { score: 5 } },
    });
    expect(nothing.runtime.inputs).toHaveLength(0);
  });

  test("honors disabled verification and full-only mode", async () => {
    const setup = service();
    const noVerification: AuditConfig = {
      ...config,
      verification: false,
      incremental: false,
      failOn: "never",
    };
    setup.repository.state = previousState({ findings: [candidate] });
    const outcome = await setup.audit.run(noVerification);
    expect(setup.runtime.calls.verification).toBe(0);
    expect(setup.repository.snapshots[0]?.base).toBe(mergeBase);
    expect(outcome).toMatchObject({
      kind: "published",
      report: { conclusion: "success" },
    });
  });

  test("does not create incremental state when reporting has no Check", async () => {
    const setup = service();
    const outcome = await setup.audit.run({
      ...config,
      report: "comment",
      commentOnClean: true,
    });
    expect(outcome).toMatchObject({ kind: "published" });
    if (outcome.kind !== "published") throw new Error("Expected publication.");
    expect(outcome.state).toBeUndefined();
    expect(setup.publisher.publications[0]?.state).toBeUndefined();
  });

  test("runs at most four sessions at a time", async () => {
    const repository = new FakeRepository();
    repository.files = Array.from({ length: 6 }, (_, index) =>
      changedFile(`src/${index}.ts`, "x".repeat(MAX_PASS_DIFF_CHARS - 10)),
    );
    const setup = service(repository);
    let active = 0;
    let peak = 0;
    setup.runtime.behavior.discovery = async () => {
      active += 1;
      peak = Math.max(peak, active);
      await new Promise((resolve) => setTimeout(resolve, 5));
      active -= 1;
      return { findings: [] };
    };
    await setup.audit.run(config);
    // Twelve focused passes would exceed the pass budget, so each file group
    // gets one unfocused pass.
    expect(setup.runtime.calls.discovery).toBe(6);
    expect(setup.runtime.prompts("discovery")[0]).not.toContain("Focus of");
    expect(peak).toBe(4);
  });
});
