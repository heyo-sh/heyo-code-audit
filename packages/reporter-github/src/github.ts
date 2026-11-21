import { execFile, spawn } from "node:child_process";
import { once } from "node:events";
import { promisify } from "node:util";
import { Octokit } from "@octokit/rest";
import {
  isLowSignalPath,
  LOCKFILE_NAMES,
  type AuditConfig,
  type AuditPublisher,
  type AuditReport,
  type AuditRepository,
  type AuditState,
  type ChangedFile,
  type CommitMetadata,
  type PullRequestContext,
  type RepositorySnapshot,
} from "@heyo-sh/code-audit-core";
import { decodeAuditState, encodeAuditState } from "./state.js";
import {
  FINDING_MARKER_PREFIX,
  findingMarker,
  formatCheckAnnotation,
  formatCleanReview,
  formatInlineComment,
  formatSummary,
  formatSummaryComment,
  reviewCount,
  SUMMARY_MARKER,
} from "./format.js";

const execFileAsync = promisify(execFile);
const CHECK_NAME = "Heyo Code Audit";
// The snapshot holds every discovery pass, so it is far larger than one
// prompt. Lockfiles and generated files are excluded before this bound.
const MAX_DIFF_BYTES = 1_200_000;
// Enough context for the model to read a hunk without a tool call, small
// enough that a medium pull request fits one discovery pass.
const DIFF_CONTEXT_LINES = 20;
const LOW_SIGNAL_PATHSPECS = [
  ...[...LOCKFILE_NAMES].map((name) => `:(exclude,glob,icase)**/${name}`),
  ":(exclude,glob)**/*.min.js",
  ":(exclude,glob)**/*.min.css",
  ":(exclude,glob)**/*.map",
  ":(exclude,glob)**/*.snap",
  ":(exclude,glob)**/__snapshots__/**",
];
const MAX_GUIDANCE_BYTES = 64_000;
const MAX_GUIDANCE_FILE_BYTES = 16_000;
const MAX_GUIDANCE_FILES = 24;
const MAX_CHECK_SUMMARY_CHARS = 65_000;

export interface GitHubEnvironment {
  owner: string;
  repo: string;
  prNumber: number;
  repositoryPath: string;
}

/** Maintains the pull-request reaction that indicates an audit is in progress. */
export class GitHubReviewProgress {
  private eyesReactionId: number | undefined;

  constructor(
    private readonly client: Octokit,
    private readonly environment: Pick<
      GitHubEnvironment,
      "owner" | "repo" | "prNumber"
    >,
  ) {}

  async start(): Promise<void> {
    const { data } = await this.client.rest.reactions.createForIssue({
      owner: this.environment.owner,
      repo: this.environment.repo,
      issue_number: this.environment.prNumber,
      content: "eyes",
    });
    this.eyesReactionId = data.id;
  }

  async finish(clean: boolean): Promise<void> {
    if (this.eyesReactionId === undefined) return;
    await this.client.rest.reactions.deleteForIssue({
      owner: this.environment.owner,
      repo: this.environment.repo,
      issue_number: this.environment.prNumber,
      reaction_id: this.eyesReactionId,
    });
    this.eyesReactionId = undefined;
    if (!clean) return;
    await this.client.rest.reactions.createForIssue({
      owner: this.environment.owner,
      repo: this.environment.repo,
      issue_number: this.environment.prNumber,
      content: "+1",
    });
  }
}

export class GitHubAuditRepository implements AuditRepository {
  constructor(
    private readonly client: Octokit,
    private readonly environment: GitHubEnvironment,
  ) {}

  async getPullRequest(): Promise<PullRequestContext> {
    const { data } = await this.client.rest.pulls.get({
      owner: this.environment.owner,
      repo: this.environment.repo,
      pull_number: this.environment.prNumber,
    });
    return {
      owner: this.environment.owner,
      repo: this.environment.repo,
      number: this.environment.prNumber,
      baseSha: data.base.sha,
      baseBranch: data.base.ref,
      headSha: data.head.sha,
      title: data.title,
      body: data.body ?? "",
    };
  }

  async getSnapshot(
    baseSha: string,
    headSha: string,
    paths: string[],
    guidanceBaseSha = baseSha,
  ): Promise<RepositorySnapshot> {
    assertSha(baseSha);
    assertSha(headSha);
    assertSha(guidanceBaseSha);
    const range = `${baseSha}..${headSha}`;
    const stats = parseNumstat(
      (
        await git(
          this.environment.repositoryPath,
          ["diff", "--numstat", "-z", "--no-ext-diff", "--find-renames", range],
          8_000_000,
        )
      ).stdout,
    ).filter((entry) => matchesAny(entry.path, paths));
    const changedPaths = stats.map((entry) => entry.path);
    const diff = await boundedGitDiff(
      this.environment.repositoryPath,
      [
        "diff",
        "--no-ext-diff",
        "--no-color",
        "--find-renames",
        `--unified=${DIFF_CONTEXT_LINES}`,
        range,
        "--",
        ...paths,
        ...LOW_SIGNAL_PATHSPECS,
      ],
      MAX_DIFF_BYTES,
    );
    const chunks = splitDiff(diff);
    const files = stats.map((entry) =>
      changedFile(entry, chunks.get(entry.path)),
    );
    const commits = parseCommits(
      (
        await git(this.environment.repositoryPath, [
          "log",
          "--format=%H%x00%s",
          range,
        ])
      ).stdout,
    );
    const guidance = await scopedGuidance(
      this.environment.repositoryPath,
      guidanceBaseSha,
      changedPaths,
    );
    return {
      repositoryPath: this.environment.repositoryPath,
      baseSha,
      headSha,
      diff: files
        .map((file) => file.diff)
        .filter(Boolean)
        .join("\n"),
      files,
      changedPaths,
      guidance,
      commits,
    };
  }

  async mergeBase(baseSha: string, headSha: string): Promise<string> {
    assertSha(baseSha);
    assertSha(headSha);
    let mergeBase: string;
    try {
      mergeBase = (
        await git(this.environment.repositoryPath, [
          "merge-base",
          baseSha,
          headSha,
        ])
      ).stdout.trim();
    } catch {
      throw new Error(
        "Git could not find the pull request merge base. Check out the repository with fetch-depth: 0.",
      );
    }
    assertSha(mergeBase);
    return mergeBase;
  }

  async countCommits(baseSha: string, headSha: string): Promise<number> {
    assertSha(baseSha);
    assertSha(headSha);
    const value = Number(
      (
        await git(this.environment.repositoryPath, [
          "rev-list",
          "--count",
          `${baseSha}..${headSha}`,
        ])
      ).stdout.trim(),
    );
    if (!Number.isSafeInteger(value) || value < 0)
      throw new Error("Git returned an invalid commit count.");
    return value;
  }

  async isAncestor(ancestor: string, descendant: string): Promise<boolean> {
    assertSha(ancestor);
    assertSha(descendant);
    try {
      await git(this.environment.repositoryPath, [
        "merge-base",
        "--is-ancestor",
        ancestor,
        descendant,
      ]);
      return true;
    } catch (error) {
      if (exitCode(error) === 1) return false;
      throw error;
    }
  }

  async findLatestState(
    pr: PullRequestContext,
  ): Promise<AuditState | undefined> {
    const commits = await this.client.paginate(
      this.client.rest.pulls.listCommits,
      { owner: pr.owner, repo: pr.repo, pull_number: pr.number, per_page: 100 },
    );
    for (const commit of [...commits].reverse()) {
      const checkRuns = await this.client.paginate(
        this.client.rest.checks.listForRef,
        {
          owner: pr.owner,
          repo: pr.repo,
          ref: commit.sha,
          check_name: CHECK_NAME,
          per_page: 100,
        },
      );
      for (const check of checkRuns) {
        if (
          check.status !== "completed" ||
          (check.conclusion !== "success" && check.conclusion !== "failure")
        )
          continue;
        const state = decodeAuditState(check.output?.summary ?? undefined);
        if (state && state.auditedHeadSha === commit.sha) return state;
      }
    }
    return undefined;
  }

  async isCurrentHead(
    pr: PullRequestContext,
    headSha: string,
  ): Promise<boolean> {
    return (await this.getPullRequest()).headSha === headSha;
  }
}

export class GitHubAuditPublisher implements AuditPublisher {
  constructor(
    private readonly client: Octokit,
    private readonly config: AuditConfig,
  ) {}

  async publish(input: {
    pr: PullRequestContext;
    report: AuditReport;
    state?: AuditState;
    snapshot?: Pick<RepositorySnapshot, "diff">;
  }): Promise<void> {
    const writesCheck =
      this.config.report === "check" ||
      this.config.report === "check-and-comment";
    const reportsReview =
      this.config.report === "comment" ||
      this.config.report === "check-and-comment";
    const located = input.report.findings.length
      ? locatedFindings(
          input.report.findings,
          await this.reviewLocations(input.pr, input.snapshot?.diff ?? ""),
        )
      : [];
    if (writesCheck) {
      const summary = checkSummary(input.report, input.state);
      await this.client.rest.checks.create({
        owner: input.pr.owner,
        repo: input.pr.repo,
        name: CHECK_NAME,
        head_sha: input.pr.headSha,
        status: "completed",
        conclusion: input.report.conclusion,
        output: {
          title: checkTitle(input.report),
          summary,
          ...(located.length
            ? { annotations: located.slice(0, 50).map(formatCheckAnnotation) }
            : {}),
        },
      });
    }
    if (!reportsReview) return;
    const links = located.length
      ? await this.publishReview(input.pr, located)
      : new Map<string, string>();
    if (this.config.commentOnClean && input.report.findings.length === 0)
      await this.publishCleanReview(input.pr, input.report);
    if (this.config.summaryComment && input.report.assessment)
      await this.publishSummaryComment(input.pr, input.report, links);
  }

  /**
   * Lines GitHub accepts for review comments: every right-side line of the
   * pull request's own file patches. When those cannot be read, only added
   * lines of the audited diff are used.
   */
  private async reviewLocations(
    pr: PullRequestContext,
    diff: string,
  ): Promise<Set<string>> {
    let files: Array<{ filename: string; patch?: string | null }>;
    try {
      files = await this.client.paginate(this.client.rest.pulls.listFiles, {
        owner: pr.owner,
        repo: pr.repo,
        pull_number: pr.number,
        per_page: 100,
      });
    } catch {
      return reviewableLocations(diff);
    }
    const locations = new Set<string>();
    for (const file of files)
      for (const line of commentableLines(file.patch ?? ""))
        locations.add(locationKey(file.filename, line));
    return locations;
  }

  /** Posts new findings inline and returns the comment URL of each finding. */
  private async publishReview(
    pr: PullRequestContext,
    findings: LocatedFinding[],
  ): Promise<Map<string, string>> {
    const existing = (
      await this.client.paginate(this.client.rest.pulls.listReviewComments, {
        owner: pr.owner,
        repo: pr.repo,
        pull_number: pr.number,
        per_page: 100,
      })
    ).filter(
      (comment) =>
        comment.user?.type === "Bot" &&
        comment.body?.includes(FINDING_MARKER_PREFIX),
    );
    const links = new Map<string, string>();
    for (const finding of findings) {
      // The same finding, or a live comment of Heyo's on the same line, is
      // not posted again on a later push.
      const previous = existing.find(
        (comment) =>
          comment.body.includes(findingMarker(finding)) ||
          (comment.path === finding.file && comment.line === finding.line),
      );
      if (previous) links.set(finding.fingerprint, previous.html_url);
    }
    const fresh = findings.filter((finding) => !links.has(finding.fingerprint));
    if (!fresh.length) return links;
    let reviewId: number;
    try {
      reviewId = (
        await this.client.rest.pulls.createReview({
          owner: pr.owner,
          repo: pr.repo,
          pull_number: pr.number,
          commit_id: pr.headSha,
          event: "COMMENT",
          comments: fresh.map((finding) => ({
            path: finding.file,
            line: finding.line,
            side: "RIGHT",
            body: formatInlineComment(finding),
          })),
        })
      ).data.id;
    } catch (error) {
      // GitHub rejects the whole review when one location no longer resolves.
      // The findings stay in the Check and the summary comment instead.
      if (httpStatus(error) === 422) return links;
      throw error;
    }
    const created = await this.client.paginate(
      this.client.rest.pulls.listCommentsForReview,
      {
        owner: pr.owner,
        repo: pr.repo,
        pull_number: pr.number,
        review_id: reviewId,
        per_page: 100,
      },
    );
    for (const finding of fresh) {
      const comment = created.find((candidate) =>
        candidate.body.includes(findingMarker(finding)),
      );
      if (comment) links.set(finding.fingerprint, comment.html_url);
    }
    return links;
  }

  private async publishCleanReview(
    pr: PullRequestContext,
    report: AuditReport,
  ): Promise<void> {
    await this.client.rest.pulls.createReview({
      owner: pr.owner,
      repo: pr.repo,
      pull_number: pr.number,
      commit_id: pr.headSha,
      event: "COMMENT",
      body: formatCleanReview(report),
    });
  }

  /** Keeps one pull-request comment with the score, overview, and findings. */
  private async publishSummaryComment(
    pr: PullRequestContext,
    report: AuditReport,
    links: Map<string, string>,
  ): Promise<void> {
    const comments = await this.client.paginate(
      this.client.rest.issues.listComments,
      {
        owner: pr.owner,
        repo: pr.repo,
        issue_number: pr.number,
        per_page: 100,
      },
    );
    const existing = comments.find(
      (comment) =>
        comment.user?.type === "Bot" && comment.body?.includes(SUMMARY_MARKER),
    );
    const body = formatSummaryComment(report, {
      links,
      reviews: reviewCount(existing?.body ?? "") + 1,
      commitUrl: `https://github.com/${pr.owner}/${pr.repo}/commit/${pr.headSha}`,
    });
    if (existing)
      await this.client.rest.issues.updateComment({
        owner: pr.owner,
        repo: pr.repo,
        comment_id: existing.id,
        body,
      });
    else
      await this.client.rest.issues.createComment({
        owner: pr.owner,
        repo: pr.repo,
        issue_number: pr.number,
        body,
      });
  }
}

export function createGitHubClient(token: string): Octokit {
  return new Octokit({ auth: token, userAgent: "heyo-code-audit" });
}

function assertSha(value: string): void {
  if (!/^[0-9a-f]{7,64}$/i.test(value))
    throw new Error("Invalid git SHA supplied by GitHub.");
}

async function scopedGuidance(
  cwd: string,
  baseSha: string,
  changedPaths: string[],
): Promise<RepositorySnapshot["guidance"]> {
  if (changedPaths.length === 0) return [];
  const candidates = new Set(["AGENTS.md"]);
  for (const file of changedPaths) {
    const parts = file.split("/");
    for (let depth = 1; depth < parts.length; depth += 1) {
      candidates.add(`${parts.slice(0, depth).join("/")}/AGENTS.md`);
    }
  }
  const tree = await git(
    cwd,
    ["ls-tree", "-r", "-z", "--full-tree", baseSha, "--", ...candidates],
    2_000_000,
  );
  const entries = tree.stdout
    .split("\0")
    .flatMap((record) => {
      const match = /^(100644|100755) blob ([a-f0-9]{40,64})\t(.+)$/s.exec(
        record,
      );
      return match?.[2] && match[3] && candidates.has(match[3])
        ? [{ oid: match[2], path: match[3] }]
        : [];
    })
    .sort(
      (a, b) =>
        a.path.split("/").length - b.path.split("/").length ||
        a.path.localeCompare(b.path),
    );
  if (entries.length > MAX_GUIDANCE_FILES)
    throw new Error("Too many applicable AGENTS.md files to audit safely.");

  const guidance: RepositorySnapshot["guidance"] = [];
  let total = 0;
  for (const entry of entries) {
    const size = Number(
      (await git(cwd, ["cat-file", "-s", entry.oid])).stdout.trim(),
    );
    if (
      !Number.isSafeInteger(size) ||
      size < 0 ||
      size > MAX_GUIDANCE_FILE_BYTES ||
      total + size + Buffer.byteLength(entry.path) + 3 > MAX_GUIDANCE_BYTES
    )
      throw new Error("Applicable AGENTS.md exceeds the audit guidance limit.");
    const content = (
      await git(
        cwd,
        ["cat-file", "blob", entry.oid],
        MAX_GUIDANCE_FILE_BYTES + 1,
      )
    ).stdout;
    total += Buffer.byteLength(content) + Buffer.byteLength(entry.path) + 3;
    guidance.push({ path: entry.path, content });
  }
  return guidance;
}

async function git(
  cwd: string,
  args: string[],
  maxBuffer = 1_000_000,
): Promise<{ stdout: string }> {
  return execFileAsync("git", ["-c", "core.quotepath=false", ...args], {
    cwd,
    timeout: 30_000,
    maxBuffer,
    env: { PATH: process.env.PATH ?? "" },
  });
}

async function boundedGitDiff(
  cwd: string,
  args: string[],
  maximum: number,
): Promise<string> {
  const marker = "\n[Diff truncated by Heyo]";
  const capacity = Math.max(0, maximum - Buffer.byteLength(marker));
  return new Promise((resolve, reject) => {
    const child = spawn("git", ["-c", "core.quotepath=false", ...args], {
      cwd,
      env: { PATH: process.env.PATH ?? "" },
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 30_000,
    });
    const chunks: Buffer[] = [];
    let bytes = 0;
    let truncated = false;
    child.stdout.on("data", (chunk: Buffer) => {
      if (truncated) return;
      const remaining = capacity - bytes;
      if (remaining > 0)
        chunks.push(chunk.subarray(0, Math.min(chunk.length, remaining)));
      bytes += Math.min(chunk.length, Math.max(0, remaining));
      if (chunk.length > remaining) {
        truncated = true;
        child.kill();
      }
    });
    child.stderr.resume();
    void once(child, "close").then(([code]) => {
      if (truncated)
        return resolve(Buffer.concat(chunks).toString("utf8") + marker);
      if (code === 0) return resolve(Buffer.concat(chunks).toString("utf8"));
      return reject(new Error("Git diff failed."));
    }, reject);
  });
}

function parseCommits(output: string): CommitMetadata[] {
  return output
    .split("\n")
    .filter(Boolean)
    .map((line) => {
      const [sha, message = ""] = line.split("\0", 2);
      if (!sha) throw new Error("Git returned malformed commit metadata.");
      return { sha, message };
    });
}

function matchesAny(path: string, patterns: string[]): boolean {
  return (
    patterns.length === 0 ||
    patterns.some((pattern) => glob(pattern).test(path))
  );
}

function checkSummary(
  report: AuditReport,
  state: AuditState | undefined,
): string {
  const marker = state ? optionalStateMarker(state) : "";
  const separator = marker ? "\n\n" : "";
  return `${truncate(formatSummary(report), MAX_CHECK_SUMMARY_CHARS - marker.length - separator.length)}${separator}${marker}`;
}

function optionalStateMarker(state: AuditState): string {
  try {
    return encodeAuditState(state);
  } catch {
    return "";
  }
}

function truncate(value: string, maximum: number): string {
  const marker = "\n\n_Report truncated by Heyo._";
  if (value.length <= maximum) return value;
  return value.slice(0, Math.max(0, maximum - marker.length)) + marker;
}

type LocatedFinding = AuditReport["findings"][number] & {
  file: string;
  line: number;
};

function locatedFindings(
  findings: AuditReport["findings"],
  locations: Set<string>,
): LocatedFinding[] {
  return findings.filter(
    (finding): finding is LocatedFinding =>
      typeof finding.file === "string" &&
      typeof finding.line === "number" &&
      locations.has(locationKey(finding.file, finding.line)),
  );
}

function checkTitle(report: AuditReport): string {
  return report.assessment
    ? `Confidence score ${report.assessment.score}/5 · ${report.assessment.verdict}`.slice(
        0,
        255,
      )
    : `Heyo Code Audit: ${report.conclusion}`;
}

/** Added right-side lines of a unified diff, the safest comment locations. */
export function reviewableLocations(diff: string): Set<string> {
  const locations = new Set<string>();
  let file: string | undefined;
  let headLine = 0;
  let inHunk = false;
  for (const diffLine of diff.split("\n")) {
    if (diffLine.startsWith("diff --git ")) {
      file = undefined;
      inHunk = false;
      continue;
    }
    if (diffLine.startsWith("+++ ")) {
      file = headPath(diffLine);
      inHunk = false;
      continue;
    }
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(diffLine);
    if (hunk?.[1]) {
      headLine = Number(hunk[1]);
      inHunk = Boolean(file);
      continue;
    }
    if (!file || !inHunk || diffLine.startsWith("\\")) continue;
    if (diffLine.startsWith("+")) {
      locations.add(locationKey(file, headLine));
      headLine += 1;
    } else if (diffLine.startsWith(" ")) {
      headLine += 1;
    }
  }
  return locations;
}

/** Right-side lines, added or context, of one GitHub file patch. */
export function commentableLines(patch: string): number[] {
  const lines: number[] = [];
  let headLine = 0;
  for (const patchLine of patch.split("\n")) {
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(patchLine);
    if (hunk?.[1]) {
      headLine = Number(hunk[1]);
      continue;
    }
    if (headLine === 0 || patchLine.startsWith("-")) continue;
    if (patchLine.startsWith("+") || patchLine.startsWith(" ")) {
      lines.push(headLine);
      headLine += 1;
    }
  }
  return lines;
}

interface NumstatEntry {
  path: string;
  additions: number;
  deletions: number;
  binary: boolean;
  renamed: boolean;
}

/** Parses `git diff --numstat -z`, including rename records. */
export function parseNumstat(output: string): NumstatEntry[] {
  const tokens = output.split("\0");
  const entries: NumstatEntry[] = [];
  for (let index = 0; index < tokens.length; index += 1) {
    const match = /^(-|\d+)\t(-|\d+)\t(.*)$/s.exec(tokens[index] ?? "");
    if (!match) continue;
    let path = match[3] ?? "";
    const renamed = path === "";
    // A rename record is followed by the old and the new path.
    if (renamed) {
      path = tokens[index + 2] ?? "";
      index += 2;
    }
    if (!path) continue;
    entries.push({
      path,
      additions: match[1] === "-" ? 0 : Number(match[1]),
      deletions: match[2] === "-" ? 0 : Number(match[2]),
      binary: match[1] === "-",
      renamed,
    });
  }
  return entries;
}

/** Splits a unified diff into per-file chunks keyed by the head path. */
export function splitDiff(diff: string): Map<string, string> {
  const chunks = new Map<string, string>();
  const parts = diff.split(/^(?=diff --git )/m);
  for (const part of parts) {
    if (!part.startsWith("diff --git ")) continue;
    const path =
      /^\+\+\+ b\/(.+)$/m.exec(part)?.[1] ??
      /^rename to (.+)$/m.exec(part)?.[1] ??
      /^--- a\/(.+)$/m.exec(part)?.[1] ??
      /^diff --git a\/.+ b\/(.+)$/m.exec(part)?.[1];
    if (path) chunks.set(path, part.replace(/\n$/, ""));
  }
  return chunks;
}

function changedFile(
  entry: NumstatEntry,
  chunk: string | undefined,
): ChangedFile {
  const status: ChangedFile["status"] = entry.renamed
    ? "renamed"
    : chunk && /^new file mode /m.test(chunk)
      ? "added"
      : chunk && /^deleted file mode /m.test(chunk)
        ? "deleted"
        : "modified";
  const lowSignal = entry.binary || isLowSignalPath(entry.path);
  let diff = lowSignal ? "" : (chunk ?? "");
  // A deleted file's content adds nothing the base version does not show.
  if (status === "deleted" && diff) {
    const header = diff.split(/^@@/m)[0] ?? "";
    diff = `${header}[Deleted file: ${entry.deletions} lines removed. Use read_base_file to inspect it.]`;
  }
  return {
    path: entry.path,
    status,
    additions: entry.additions,
    deletions: entry.deletions,
    diff,
    lowSignal,
  };
}

function headPath(diffLine: string): string | undefined {
  const prefix = "+++ b/";
  if (!diffLine.startsWith(prefix)) return undefined;
  const path = diffLine.slice(prefix.length);
  return path && path !== "/dev/null" ? path : undefined;
}

function locationKey(file: string, line: number): string {
  return `${file}\u0000${line}`;
}

function glob(pattern: string): RegExp {
  let expression = "";
  for (let index = 0; index < pattern.length; index += 1) {
    const character = pattern[index];
    if (!character) continue;
    if (character === "*") {
      if (pattern[index + 1] === "*") {
        index += 1;
        if (pattern[index + 1] === "/") {
          index += 1;
          expression += "(?:.*/)?";
        } else {
          expression += ".*";
        }
      } else {
        expression += "[^/]*";
      }
    } else if (character === "?") {
      expression += "[^/]";
    } else {
      expression += escapeRegex(character);
    }
  }
  return new RegExp(`^${expression}$`);
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function httpStatus(error: unknown): number | undefined {
  return error instanceof Error &&
    "status" in error &&
    typeof error.status === "number"
    ? error.status
    : undefined;
}

function exitCode(error: unknown): number | undefined {
  return error instanceof Error &&
    "code" in error &&
    typeof error.code === "number"
    ? error.code
    : undefined;
}
