import { configHash } from "./config.js";
import { isRetryable } from "./errors.js";
import {
  POLICY_VERSION,
  discoveryPrompt,
  summaryPrompt,
  verificationPrompt,
  type DiscoveryFocus,
} from "./prompts.js";
import { createReport, errorReport, neutralReport } from "./report.js";
import { deduplicateFindings } from "./schema.js";
import { planShards, type DiffShard } from "./shards.js";
import type {
  AuditConfig,
  AuditCoverage,
  AuditPhaseResult,
  AuditPublisher,
  AuditRepository,
  AuditRuntime,
  AuditScope,
  AuditState,
  Finding,
  PullRequestContext,
  PullRequestOverview,
  RepositorySnapshot,
  RunOutcome,
  RuntimeInput,
  RuntimeLimits,
} from "./types.js";

// `maxTurns` and `maxTokens` are coupled. The runtime requests a high thinking
// level, so reasoning tokens are drawn from the per-response budget. A budget
// that is too small truncates a response mid-answer, the agent takes another
// turn to continue, and the turn limit is spent on thinking rather than on
// analysis. Raising `maxTokens` therefore lowers turn consumption; the two must
// be raised together.
//
// The byte and result caps are context-window guards, not budget. Raising them
// far enough to overflow the model context fails a session harder than the turn
// limit does, so they grow conservatively.
const SHARED_LIMITS = {
  // Clamped by the selected model in the Pi runtime, so this is an upper bound.
  maxTokens: 32_000,
  maxFileBytes: 200_000,
  maxSearchResults: 200,
  maxDiffBytes: 160_000,
  // Caps one JSON result, and the finding contract allows at most 20 findings.
  maxOutputBytes: 80_000,
} as const;

/**
 * Discovery traces a whole pass across every enabled check, verification
 * re-proves one candidate, and the summary only describes the change. Passes
 * and candidates run in parallel, so a run lasts roughly one discovery and one
 * verification deadline, well inside a one-hour job.
 */
export const PHASE_LIMITS: Record<RuntimeInput["phase"], RuntimeLimits> = {
  discovery: {
    ...SHARED_LIMITS,
    maxTurns: 120,
    maxToolCalls: 360,
    timeoutMs: 20 * 60_000,
  },
  verification: {
    ...SHARED_LIMITS,
    maxTurns: 60,
    maxToolCalls: 180,
    timeoutMs: 12 * 60_000,
  },
  summary: {
    ...SHARED_LIMITS,
    maxTurns: 12,
    maxToolCalls: 24,
    timeoutMs: 6 * 60_000,
  },
};

/** Diff characters reviewed by one discovery pass. */
export const MAX_PASS_DIFF_CHARS = 90_000;
/** Discovery passes per audit; files beyond them are reported as uncovered. */
export const MAX_DISCOVERY_PASSES = 8;
/**
 * Two perspectives on the same files find more defects than one, so a change
 * set that fits half the pass budget is reviewed from both.
 */
const DISCOVERY_FOCUSES: DiscoveryFocus[] = ["contracts", "behavior"];
/** Pi sessions that run at the same time. */
export const SESSION_CONCURRENCY = 4;

type Attempt<T> = { ok: true; value: T } | { ok: false; error: unknown };

export class AuditService {
  constructor(
    private readonly dependencies: {
      repository: AuditRepository;
      runtime: AuditRuntime;
      publisher: AuditPublisher;
    },
  ) {}

  async run(config: AuditConfig): Promise<RunOutcome> {
    const { repository } = this.dependencies;
    const pr = await repository.getPullRequest();
    const configDigest = configHash(config);
    let scope: AuditScope = "full";
    let stage = "resolving the merge base";
    try {
      const mergeBase = await repository.mergeBase(pr.baseSha, pr.headSha);
      stage = "loading previous audit state";
      const previous = await repository.findLatestState(pr);
      stage = "selecting the audit scope";
      const decision = await this.selectScope(
        config,
        configDigest,
        pr,
        mergeBase,
        previous,
      );
      scope = decision.scope;
      const limit =
        scope === "full" ? config.maxPrCommits : config.maxNewCommits;
      stage = "checking the commit limit";
      const commitCount = await repository.countCommits(
        decision.fromSha,
        pr.headSha,
      );
      if (limit !== "unlimited" && commitCount > limit) {
        const label = scope === "full" ? "max-pr-commits" : "max-new-commits";
        return this.publishWithoutState(
          pr,
          neutralReport({
            config,
            pr,
            scope,
            summary: `Heyo skipped this ${scope} audit: ${commitCount} commits exceed ${label}=${limit}.`,
          }),
        );
      }

      stage = "loading the repository snapshot";
      const snapshot = await repository.getSnapshot(
        decision.fromSha,
        pr.headSha,
        config.paths,
        pr.baseSha,
      );
      const overviewSnapshot =
        scope === "full" || !config.summaryComment
          ? snapshot
          : await repository.getSnapshot(
              mergeBase,
              pr.headSha,
              config.paths,
              pr.baseSha,
            );
      stage = "running discovery";
      const plan = planShards(snapshot.files, {
        maxShardChars: MAX_PASS_DIFF_CHARS,
        maxShards: MAX_DISCOVERY_PASSES,
      });
      const [discovery, overview] = await Promise.all([
        this.discover(config, pr, snapshot, plan.shards, scope),
        config.summaryComment
          ? this.summarize(config, pr, overviewSnapshot)
          : Promise.resolve(undefined),
      ]);
      if (discovery.failed > 0 && discovery.reviewedFiles === 0)
        throw discovery.error;

      const previousFindings = decision.previous?.findings ?? [];
      const candidates = deduplicateFindings(
        config.verification
          ? [...discovery.findings, ...previousFindings]
          : discovery.findings,
      );
      stage = "verifying candidate findings";
      const verification = config.verification
        ? await this.verify(config, pr, snapshot, candidates)
        : {
            findings: candidates,
            rejected: new Set<string>(),
            failed: 0,
            error: undefined,
          };
      if (verification.failed > 0 && verification.failed === candidates.length)
        throw verification.error;

      const coverage: AuditCoverage = {
        changedFiles: snapshot.files.filter((file) => !file.lowSignal).length,
        reviewedFiles: discovery.reviewedFiles,
        failedPasses: discovery.failed,
        unverifiedCandidates: verification.failed,
      };
      const report = createReport({
        config,
        pr,
        scope,
        ...(decision.previous
          ? { previousHeadSha: decision.previous.auditedHeadSha }
          : {}),
        findings: verification.findings,
        coverage,
        ...(overview ? { overview } : {}),
        resolved: previousFindings.filter((finding) =>
          verification.rejected.has(finding.fingerprint),
        ),
      });
      // Files a failed session should have audited must be audited again, so
      // a run with failures never advances the incremental state.
      const state =
        coverage.failedPasses || coverage.unverifiedCandidates
          ? undefined
          : this.stateFor(config, configDigest, pr, mergeBase, report.findings);
      stage = "checking the pull request head";
      if (!(await repository.isCurrentHead(pr, pr.headSha)))
        return { kind: "stale" };
      stage = "publishing the audit report";
      await this.dependencies.publisher.publish({
        pr,
        report,
        snapshot: { diff: snapshot.diff },
        ...(state ? { state } : {}),
      });
      return { kind: "published", report, ...(state ? { state } : {}) };
    } catch (error) {
      const report = errorReport({
        config,
        pr,
        scope,
        summary: `Heyo could not complete this ${scope} audit while ${stage}. No audit state was advanced.`,
      });
      return this.publishWithoutState(pr, report, { error });
    }
  }

  private async selectScope(
    config: AuditConfig,
    configDigest: string,
    pr: PullRequestContext,
    mergeBase: string,
    previous: AuditState | undefined,
  ): Promise<{ scope: AuditScope; fromSha: string; previous?: AuditState }> {
    // A changed merge base means the branch absorbed new target commits, so
    // the commits since the previous audit no longer describe the change.
    if (
      !config.incremental ||
      !previous ||
      previous.baseSha !== mergeBase ||
      previous.configHash !== configDigest ||
      previous.policyVersion !== POLICY_VERSION ||
      !(await this.dependencies.repository.isAncestor(
        previous.auditedHeadSha,
        pr.headSha,
      ))
    )
      return { scope: "full", fromSha: mergeBase };
    return { scope: "incremental", fromSha: previous.auditedHeadSha, previous };
  }

  private stateFor(
    config: AuditConfig,
    configDigest: string,
    pr: PullRequestContext,
    mergeBase: string,
    findings: Finding[],
  ): AuditState | undefined {
    if (config.report !== "check" && config.report !== "check-and-comment")
      return undefined;
    return {
      version: 1,
      baseSha: mergeBase,
      auditedHeadSha: pr.headSha,
      configHash: configDigest,
      policyVersion: POLICY_VERSION,
      findings,
    };
  }

  private async discover(
    config: AuditConfig,
    pr: PullRequestContext,
    snapshot: RepositorySnapshot,
    shards: DiffShard[],
    scope: AuditScope,
  ): Promise<{
    findings: Finding[];
    reviewedFiles: number;
    failed: number;
    error?: unknown;
  }> {
    const focuses: Array<DiscoveryFocus | undefined> =
      shards.length * DISCOVERY_FOCUSES.length <= MAX_DISCOVERY_PASSES
        ? DISCOVERY_FOCUSES
        : [undefined];
    const passes = shards.flatMap((shard, index) =>
      focuses.map((focus) => ({ shard, index, focus })),
    );
    const attempts = await mapConcurrently(passes, (pass) =>
      this.attempt(config, snapshot, "discovery", () =>
        discoveryPrompt({
          checks: config.checks,
          snapshot,
          shard: pass.shard,
          pass: pass.index + 1,
          passes: shards.length,
          ...(pass.focus ? { focus: pass.focus } : {}),
          prTitle: pr.title,
          prBody: pr.body,
          baseBranch: pr.baseBranch,
          scope,
        }),
      ),
    );
    const result = {
      findings: [] as Finding[],
      reviewedFiles: 0,
      failed: 0,
      error: undefined as unknown,
    };
    const reviewed = new Set<DiffShard>();
    attempts.forEach((attempt, index) => {
      if (attempt.ok && "findings" in attempt.value) {
        result.findings.push(...attempt.value.findings);
        reviewed.add(passes[index]!.shard);
      } else {
        result.failed += 1;
        result.error ??= attempt.ok
          ? new Error("Discovery runtime returned another phase's result.")
          : attempt.error;
      }
    });
    for (const shard of reviewed) result.reviewedFiles += shard.files.length;
    return result;
  }

  private async verify(
    config: AuditConfig,
    pr: PullRequestContext,
    snapshot: RepositorySnapshot,
    candidates: Finding[],
  ): Promise<{
    findings: Finding[];
    rejected: Set<string>;
    failed: number;
    error?: unknown;
  }> {
    const attempts = await mapConcurrently(candidates, (candidate, index) =>
      this.attempt(config, snapshot, "verification", () =>
        verificationPrompt({
          candidate,
          earlier: candidates.slice(0, index),
          snapshot,
          checks: config.checks,
          prTitle: pr.title,
          prBody: pr.body,
          baseBranch: pr.baseBranch,
        }),
      ),
    );
    const verified: Finding[] = [];
    const rejected = new Set<string>();
    let failed = 0;
    let error: unknown;
    attempts.forEach((attempt, index) => {
      if (attempt.ok && "verified" in attempt.value) {
        if (attempt.value.verified && attempt.value.finding)
          verified.push(attempt.value.finding);
        else rejected.add(candidates[index]!.fingerprint);
      } else {
        failed += 1;
        error ??= attempt.ok
          ? new Error("Verification runtime returned another phase's result.")
          : attempt.error;
      }
    });
    return { findings: deduplicateFindings(verified), rejected, failed, error };
  }

  /** The overview is optional decoration: its failure never fails an audit. */
  private async summarize(
    config: AuditConfig,
    pr: PullRequestContext,
    snapshot: RepositorySnapshot,
  ): Promise<PullRequestOverview | undefined> {
    if (snapshot.files.length === 0) return undefined;
    const attempt = await this.attempt(config, snapshot, "summary", () =>
      summaryPrompt({
        snapshot,
        prTitle: pr.title,
        prBody: pr.body,
        baseBranch: pr.baseBranch,
      }),
    );
    return attempt.ok && "overview" in attempt.value
      ? attempt.value.overview
      : undefined;
  }

  /**
   * Runs one session, retrying once when a fresh session could succeed. A
   * session that failed late is not retried, so a retry never pushes the run
   * past the job timeout.
   */
  private async attempt(
    config: AuditConfig,
    snapshot: RepositorySnapshot,
    phase: RuntimeInput["phase"],
    prompt: () => string,
  ): Promise<Attempt<AuditPhaseResult>> {
    const input = this.runtimeInput(config, snapshot, phase, prompt());
    const started = Date.now();
    try {
      return { ok: true, value: await this.dependencies.runtime.run(input) };
    } catch (error) {
      if (
        !isRetryable(error) ||
        Date.now() - started > input.limits.timeoutMs / 2
      )
        return { ok: false, error };
      try {
        return { ok: true, value: await this.dependencies.runtime.run(input) };
      } catch (retryError) {
        return { ok: false, error: retryError };
      }
    }
  }

  private runtimeInput(
    config: AuditConfig,
    snapshot: RepositorySnapshot,
    phase: RuntimeInput["phase"],
    internalPrompt: string,
  ): RuntimeInput {
    return {
      repositoryPath: snapshot.repositoryPath,
      baseSha: snapshot.baseSha,
      headSha: snapshot.headSha,
      phase,
      checks: config.checks,
      provider: config.provider,
      model: config.model,
      auth: config.auth,
      internalPrompt,
      permissions: "read-only",
      limits: PHASE_LIMITS[phase],
    };
  }

  private async publishWithoutState(
    pr: PullRequestContext,
    report: ReturnType<typeof neutralReport>,
    failure?: { error: unknown },
  ): Promise<RunOutcome> {
    if (!(await this.dependencies.repository.isCurrentHead(pr, pr.headSha)))
      return { kind: "stale" };
    await this.dependencies.publisher.publish({ pr, report });
    return failure
      ? { kind: "errored", report, error: failure.error }
      : { kind: "skipped", report };
  }
}

/** Maps items with at most `SESSION_CONCURRENCY` in flight, keeping order. */
async function mapConcurrently<T, R>(
  items: T[],
  map: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const index = next;
      next += 1;
      results[index] = await map(items[index]!, index);
    }
  };
  await Promise.all(
    Array.from({ length: Math.min(SESSION_CONCURRENCY, items.length) }, worker),
  );
  return results;
}
