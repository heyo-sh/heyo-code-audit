import { readFile } from "node:fs/promises";
import * as core from "@actions/core";
import {
  AuditService,
  parseAuditConfig,
  redactSecrets,
  type AuditConfig,
  type AuditRepository,
  type RunOutcome,
} from "@heyo-sh/code-audit-core";
import {
  createGitHubClient,
  GitHubAuditPublisher,
  GitHubAuditRepository,
  GitHubReviewProgress,
} from "@heyo-sh/code-audit-reporter-github";
import {
  createLangfuseTracer,
  NO_TRACER,
  PiAuditRuntime,
  type AuditTracer,
  type SnapshotResolver,
} from "@heyo-sh/code-audit-runtime-pi";

export interface PullRequestEvent {
  number?: number;
  pull_request?: { head?: { repo?: { full_name?: string | null } | null } };
}

interface ActionCore {
  getInput(name: string): string;
  warning(message: string): void;
  info(message: string): void;
  setOutput(name: string, value: string): void;
  setFailed(message: string): void;
}

export interface AuditRunner {
  run(config: AuditConfig): Promise<RunOutcome>;
}

interface ReviewProgress {
  start(): Promise<void>;
  finish(clean: boolean): Promise<void>;
}

export interface ActionDependencies {
  core: ActionCore;
  readEvent(path: string | undefined): Promise<PullRequestEvent>;
  createAudit(config: AuditConfig, context: AuditContext): AuditRunner;
  createReviewProgress?(
    config: AuditConfig,
    context: AuditContext,
  ): ReviewProgress;
}

export interface AuditContext {
  owner: string;
  repo: string;
  prNumber: number;
  workspace: string | undefined;
}

const DEFAULT_DEPENDENCIES: ActionDependencies = {
  core,
  readEvent: eventPayload,
  createAudit: createAuditService,
  createReviewProgress: createGitHubReviewProgress,
};

export async function runAction(
  environment = process.env,
  dependencies = DEFAULT_DEPENDENCIES,
): Promise<void> {
  if (environment.GITHUB_EVENT_NAME !== "pull_request")
    throw new Error("Heyo Code Audit only supports pull_request events.");
  const event = await dependencies.readEvent(environment.GITHUB_EVENT_PATH);
  const [owner, repo] = (environment.GITHUB_REPOSITORY ?? "").split("/", 2);
  if (!owner || !repo || !event.number)
    throw new Error("GitHub pull request context is incomplete.");
  const authType = dependencies.core.getInput("auth-type");
  const authToken = dependencies.core.getInput("auth-token");
  const isFork =
    event.pull_request?.head?.repo?.full_name !== `${owner}/${repo}`;
  if (isFork && authType !== "aws" && !authToken.trim()) {
    dependencies.core.warning(
      "Heyo Code Audit skipped this fork pull request because no provider authentication token is available.",
    );
    dependencies.core.setOutput("outcome", "skipped-fork-without-auth-token");
    return;
  }
  const config = parseAuditConfig({
    provider: dependencies.core.getInput("provider"),
    model: dependencies.core.getInput("model"),
    "auth-type": authType,
    "auth-token": authToken,
    "aws-region": dependencies.core.getInput("aws-region"),
    "aws-profile": dependencies.core.getInput("aws-profile"),
    "github-token": dependencies.core.getInput("github-token"),
    checks: dependencies.core.getInput("checks"),
    verification: dependencies.core.getInput("verification"),
    report: dependencies.core.getInput("report"),
    "comment-on-clean": dependencies.core.getInput("comment-on-clean"),
    "summary-comment": dependencies.core.getInput("summary-comment"),
    "fail-on": dependencies.core.getInput("fail-on"),
    paths: dependencies.core.getInput("paths"),
    incremental: dependencies.core.getInput("incremental"),
    "max-pr-commits": dependencies.core.getInput("max-pr-commits"),
    "max-new-commits": dependencies.core.getInput("max-new-commits"),
    "langfuse-public-key": dependencies.core.getInput("langfuse-public-key"),
    "langfuse-secret-key": dependencies.core.getInput("langfuse-secret-key"),
    "langfuse-base-url": dependencies.core.getInput("langfuse-base-url"),
    "langfuse-environment": dependencies.core.getInput("langfuse-environment"),
  });
  const context = {
    owner,
    repo,
    prNumber: event.number,
    workspace: environment.GITHUB_WORKSPACE,
  };
  const audit = dependencies.createAudit(config, context);
  const progress = dependencies.createReviewProgress?.(config, context);
  await startReviewProgress(progress, dependencies.core);
  let outcome: RunOutcome;
  try {
    outcome = await audit.run(config);
  } catch (error) {
    await finishReviewProgress(progress, false, dependencies.core);
    throw error;
  }
  await finishReviewProgress(
    progress,
    outcome.kind === "published" && outcome.report.findings.length === 0,
    dependencies.core,
  );
  dependencies.core.setOutput("outcome", outcome.kind);
  if (outcome.kind === "published") {
    dependencies.core.setOutput("conclusion", outcome.report.conclusion);
    dependencies.core.info(
      `Heyo Code Audit completed: ${outcome.report.conclusion}.`,
    );
    if (outcome.report.conclusion === "failure")
      dependencies.core.setFailed(
        "Heyo Code Audit found verified findings at or above fail-on.",
      );
  } else if (outcome.kind === "skipped") {
    dependencies.core.setOutput("conclusion", "neutral");
    dependencies.core.warning(outcome.report.summary);
  } else if (outcome.kind === "errored") {
    dependencies.core.setOutput("conclusion", "failure");
    dependencies.core.setFailed(
      `${outcome.report.summary} ${safeErrorDetail(outcome.error, config)}`,
    );
  } else {
    dependencies.core.warning(
      "Heyo Code Audit did not publish because the pull request head changed during the run.",
    );
  }
}

export function createGitHubReviewProgress(
  config: AuditConfig,
  context: AuditContext,
): GitHubReviewProgress {
  return new GitHubReviewProgress(
    createGitHubClient(config.githubToken),
    context,
  );
}

export function createAuditService(
  config: AuditConfig,
  context: AuditContext,
  tracer: AuditTracer = createTracer(config, context),
): AuditRunner {
  const client = createGitHubClient(config.githubToken);
  const repository = new GitHubAuditRepository(client, {
    owner: context.owner,
    repo: context.repo,
    prNumber: context.prNumber,
    repositoryPath: context.workspace ?? process.cwd(),
  });
  const service = new AuditService({
    repository,
    runtime: new PiAuditRuntime(
      createSnapshotResolver(repository, config.paths, context.workspace),
      tracer,
    ),
    publisher: new GitHubAuditPublisher(client, config),
  });
  return withTraceFlush(service, tracer);
}

/** Sends the traces of a run before the Action process ends, whatever the outcome. */
export function withTraceFlush(
  audit: AuditRunner,
  tracer: AuditTracer,
): AuditRunner {
  return {
    async run(config) {
      try {
        return await audit.run(config);
      } finally {
        await tracer.flush();
      }
    },
  };
}

/** Langfuse tracing when both Langfuse keys are configured. */
export function createTracer(
  config: AuditConfig,
  context: AuditContext,
): AuditTracer {
  if (!config.langfuse) return NO_TRACER;
  return createLangfuseTracer(
    config.langfuse,
    {
      repository: `${context.owner}/${context.repo}`,
      pullRequest: context.prNumber,
    },
    {
      secrets: [
        config.githubToken,
        "token" in config.auth ? config.auth.token : undefined,
      ],
    },
  );
}

/**
 * Resolves the snapshot behind the Pi tools. Every session of one range shares
 * one snapshot, so parallel sessions do not recompute the same git diff.
 */
export function createSnapshotResolver(
  repository: AuditRepository,
  paths: string[],
  workspace: string | undefined,
): SnapshotResolver {
  const snapshots = new Map<string, ReturnType<SnapshotResolver["resolve"]>>();
  return {
    async resolve(repositoryPath, baseSha, headSha) {
      if (workspace && repositoryPath !== workspace)
        throw new Error(
          "Pi runtime repository path did not match the checked-out workspace.",
        );
      const key = `${baseSha}..${headSha}`;
      let snapshot = snapshots.get(key);
      if (!snapshot) {
        snapshot = repository.getSnapshot(baseSha, headSha, paths);
        snapshots.set(key, snapshot);
        // A failed resolution is not cached, so a retry can succeed.
        snapshot.catch(() => snapshots.delete(key));
      }
      return snapshot;
    },
  };
}

async function startReviewProgress(
  progress: ReviewProgress | undefined,
  core: ActionCore,
): Promise<void> {
  if (!progress) return;
  try {
    await progress.start();
  } catch {
    core.warning(
      "Heyo Code Audit could not add its in-progress reaction to this pull request.",
    );
  }
}

async function finishReviewProgress(
  progress: ReviewProgress | undefined,
  clean: boolean,
  core: ActionCore,
): Promise<void> {
  if (!progress) return;
  try {
    await progress.finish(clean);
  } catch {
    core.warning(
      "Heyo Code Audit could not update its in-progress reaction on this pull request.",
    );
  }
}

function safeErrorDetail(error: unknown, config: AuditConfig): string {
  let detail =
    error instanceof Error
      ? `${error.name}: ${error.message}`
      : "Unknown audit error.";
  const configuredSecrets = [
    config.githubToken,
    "token" in config.auth ? config.auth.token : undefined,
    config.langfuse?.secretKey,
  ];
  for (const secret of configuredSecrets) {
    if (secret) detail = detail.replaceAll(secret, "[REDACTED_SECRET]");
  }
  return redactSecrets(detail)
    .replaceAll("\0", "")
    .replaceAll(/\s+/g, " ")
    .trim()
    .slice(0, 500);
}

export async function eventPayload(
  path: string | undefined,
): Promise<PullRequestEvent> {
  if (!path) throw new Error("GITHUB_EVENT_PATH is required.");
  return JSON.parse(await readFile(path, "utf8")) as PullRequestEvent;
}
