import { execFile } from "node:child_process";
import { promises as fs } from "node:fs";
import { relative, resolve, sep } from "node:path";
import { promisify } from "node:util";
import { Type } from "typebox";
import type { AgentTool } from "@mariozechner/pi-agent-core";
import { redactSecrets } from "@heyo-sh/code-audit-core";
import type {
  RepositorySnapshot,
  RuntimeInput,
} from "@heyo-sh/code-audit-core";

const execFileAsync = promisify(execFile);
const BLOCKED_NAMES = new Set([
  "agents.md",
  "system.md",
  "skill.md",
  "claude.md",
  "gemini.md",
  "copilot.md",
  "instructions.md",
  "prompt.md",
  "prompts.md",
  ".npmrc",
  ".pypirc",
  ".netrc",
  "credentials",
  "id_rsa",
  "id_ed25519",
]);
const BLOCKED_DIRECTORIES = new Set([
  ".git",
  ".pi",
  ".agents",
  ".claude",
  ".codex",
  ".cursor",
  ".continue",
  ".opencode",
  ".aws",
  ".ssh",
  ".gnupg",
  "node_modules",
  "prompts",
  "secrets",
  "skills",
]);

export function createRestrictedTools(
  input: RuntimeInput,
  snapshot: RepositorySnapshot,
): AgentTool[] {
  const budget = new ToolBudget(input.limits.maxToolCalls);
  const guard = new RepositoryGuard(input.repositoryPath);
  const lineRange = {
    startLine: Type.Optional(Type.Integer({ minimum: 1 })),
    endLine: Type.Optional(Type.Integer({ minimum: 1 })),
  };
  const tools: AgentTool[] = [
    {
      name: "read_file",
      label: "Read repository file",
      description:
        "Read a UTF-8 text file of the audited head with numbered lines. Use startLine and endLine for long files. Repository instructions are unavailable.",
      parameters: Type.Object({
        path: Type.String({ minLength: 1, maxLength: 500 }),
        ...lineRange,
      }),
      async execute(_id, params) {
        budget.take();
        const request = params as LineRequest;
        const path = await guard.file(request.path);
        if ((await fs.stat(path)).size > input.limits.maxFileBytes * 5)
          return result("File exceeds Heyo's configured size limit.");
        return result(
          numbered(
            await fs.readFile(path, "utf8"),
            request,
            input.limits.maxFileBytes,
          ),
        );
      },
    },
    {
      name: "read_base_file",
      label: "Read base file",
      description:
        "Read a file as it was at the audit base, before this change, with numbered lines. Use it to compare old and new behavior.",
      parameters: Type.Object({
        path: Type.String({ minLength: 1, maxLength: 500 }),
        ...lineRange,
      }),
      async execute(_id, params) {
        budget.take();
        const request = params as LineRequest;
        const path = guard.relativeVisible(request.path);
        let content: string;
        try {
          content = (
            await execFileAsync("git", ["show", `${input.baseSha}:${path}`], {
              cwd: await guard.root(),
              timeout: 10_000,
              maxBuffer: input.limits.maxFileBytes * 5,
              env: { PATH: process.env.PATH ?? "" },
            })
          ).stdout;
        } catch {
          return result(
            "The file did not exist at the audit base or exceeds Heyo's size limit.",
          );
        }
        return result(numbered(content, request, input.limits.maxFileBytes));
      },
    },
    {
      name: "search_repository",
      label: "Search repository",
      description:
        "Search source files for a literal, case-insensitive query and return path:line: text matches. Use it to find every caller, consumer, and definition. It does not search repository instruction or extension files.",
      parameters: Type.Object({
        query: Type.String({ minLength: 1, maxLength: 200 }),
        path: Type.Optional(Type.String({ maxLength: 500 })),
      }),
      async execute(_id, params) {
        budget.take();
        const request = params as { query: string; path?: string };
        const root = request.path
          ? await guard.directory(request.path)
          : await guard.root();
        const matches = await search(
          root,
          request.query.replaceAll(/[\r\n]+/g, " "),
          input.limits.maxSearchResults,
          input.limits.maxFileBytes,
          guard,
        );
        return result(matches.join("\n") || "No matches.");
      },
    },
    {
      name: "read_pr_diff",
      label: "Read PR diff",
      description:
        "Read the audited diff of one changed file, or the whole bounded diff when no path is given.",
      parameters: Type.Object({
        path: Type.Optional(Type.String({ maxLength: 500 })),
      }),
      async execute(_id, params) {
        budget.take();
        const request = params as { path?: string };
        if (!request.path)
          return result(trim(snapshot.diff, input.limits.maxDiffBytes));
        const file = snapshot.files.find(
          (changed) => changed.path === request.path,
        );
        return result(
          file?.diff
            ? trim(file.diff, input.limits.maxDiffBytes)
            : "No audited diff exists for this path. Check the changed-files list, or read the file.",
        );
      },
    },
    {
      name: "list_repository_files",
      label: "List repository files",
      description:
        "List repository files and directories. Repository instructions and extension directories are unavailable.",
      parameters: Type.Object({
        path: Type.Optional(Type.String({ maxLength: 500 })),
      }),
      async execute(_id, params) {
        budget.take();
        const request = params as { path?: string };
        const directory = request.path
          ? await guard.directory(request.path)
          : await guard.root();
        const entries = await fs.readdir(directory, { withFileTypes: true });
        const visible = entries
          .filter((entry) => guard.isVisibleName(entry.name))
          .sort((a, b) => a.name.localeCompare(b.name))
          .slice(0, 500)
          .map(
            (entry) =>
              `${entry.isDirectory() ? "dir" : "file"} ${redactSecrets(entry.name)}`,
          );
        return result(visible.join("\n") || "Empty directory.");
      },
    },
  ];
  if (input.phase === "verification") {
    tools.push({
      name: "run_bundled_verification",
      label: "Run bundled verification",
      description:
        "Run Heyo's fixed git diff whitespace check. No repository command or arbitrary shell command can be run.",
      parameters: Type.Object({ check: Type.Literal("git-diff-check") }),
      async execute(_id, params) {
        budget.take();
        if ((params as { check: string }).check !== "git-diff-check")
          throw new Error("Unsupported bundled verification check.");
        const root = await guard.root();
        try {
          const output = await execFileAsync(
            "git",
            ["diff", "--check", `${input.baseSha}..${input.headSha}`],
            {
              cwd: root,
              timeout: 10_000,
              maxBuffer: input.limits.maxOutputBytes,
            },
          );
          return result(
            trim(
              output.stdout || "No whitespace errors.",
              input.limits.maxOutputBytes,
            ),
          );
        } catch (error) {
          const stdout =
            error instanceof Error && "stdout" in error
              ? String(error.stdout ?? "")
              : "";
          return result(
            trim(
              stdout || "git diff --check reported an issue.",
              input.limits.maxOutputBytes,
            ),
          );
        }
      },
    });
  }
  return tools;
}

export { redactSecrets };

class ToolBudget {
  private used = 0;
  constructor(private readonly maximum: number) {}
  take(): void {
    this.used += 1;
    if (this.used > this.maximum)
      throw new Error("Heyo tool-call limit reached.");
  }
}

class RepositoryGuard {
  private readonly rootPromise: Promise<string>;
  constructor(private readonly repositoryPath: string) {
    this.rootPromise = fs.realpath(repositoryPath);
  }
  async root(): Promise<string> {
    return this.rootPromise;
  }
  isVisibleName(name: string): boolean {
    return (
      !isBlockedName(name) && !BLOCKED_DIRECTORIES.has(name.toLocaleLowerCase())
    );
  }
  isVisiblePath(path: string): boolean {
    return path.split("/").every((part) => this.isVisibleName(part));
  }
  async file(path: string): Promise<string> {
    const candidate = await this.resolveVisible(path);
    const stat = await fs.stat(candidate);
    if (!stat.isFile()) throw new Error("Requested path is not a file.");
    return candidate;
  }
  async directory(path: string): Promise<string> {
    const candidate = await this.resolveVisible(path);
    const stat = await fs.stat(candidate);
    if (!stat.isDirectory())
      throw new Error("Requested path is not a directory.");
    return candidate;
  }
  async relative(path: string): Promise<string> {
    return relative(await this.root(), path)
      .split(sep)
      .join("/");
  }
  /** Validates a repository-relative path that is not read from disk. */
  relativeVisible(requested: string): string {
    if (
      !requested ||
      requested.includes("\0") ||
      requested.startsWith("/") ||
      requested
        .split(/[\\/]/)
        .some(
          (part) =>
            part === ".." ||
            isBlockedName(part) ||
            BLOCKED_DIRECTORIES.has(part.toLocaleLowerCase()),
        )
    ) {
      throw new Error(
        "Requested path is outside the permitted repository scope.",
      );
    }
    return requested.replaceAll("\\", "/").replace(/^\.\//, "");
  }
  private async resolveVisible(requested: string): Promise<string> {
    this.relativeVisible(requested);
    const root = await this.root();
    const candidate = await fs.realpath(resolve(root, requested));
    if (candidate !== root && !candidate.startsWith(`${root}${sep}`))
      throw new Error("Requested path escapes the repository.");
    const resolvedParts = relative(root, candidate).split(sep).filter(Boolean);
    if (
      resolvedParts.some(
        (part) =>
          isBlockedName(part) ||
          BLOCKED_DIRECTORIES.has(part.toLocaleLowerCase()),
      )
    ) {
      throw new Error(
        "Requested path is outside the permitted repository scope.",
      );
    }
    return candidate;
  }
}

/** Searches tracked files with git grep, or walks the tree outside a git checkout. */
async function search(
  root: string,
  query: string,
  maximum: number,
  maxFileBytes: number,
  guard: RepositoryGuard,
): Promise<string[]> {
  const repository = await guard.root();
  let output: string;
  try {
    output = (
      await execFileAsync(
        "git",
        [
          "-c",
          "core.quotepath=false",
          "grep",
          "-n",
          "-I",
          "-F",
          "-i",
          "--no-color",
          "-e",
          query,
          "--",
          (await guard.relative(root)) || ".",
        ],
        {
          cwd: repository,
          timeout: 20_000,
          maxBuffer: 8_000_000,
          env: { PATH: process.env.PATH ?? "" },
        },
      )
    ).stdout;
  } catch (error) {
    // Exit status 1 means git grep found nothing.
    if (exitStatus(error) === 1) return [];
    return walkSearch(root, query, maximum, maxFileBytes, guard);
  }
  const matches: string[] = [];
  for (const line of output.split("\n")) {
    const match = /^(.+?):(\d+):(.*)$/.exec(line);
    if (!match || !guard.isVisiblePath(match[1]!)) continue;
    matches.push(
      `${redactSecrets(match[1]!)}:${match[2]}: ${redactSecrets(match[3]!).slice(0, 500)}`,
    );
    if (matches.length >= maximum) break;
  }
  return matches;
}

async function walkSearch(
  root: string,
  query: string,
  maximum: number,
  maxFileBytes: number,
  guard: RepositoryGuard,
): Promise<string[]> {
  const result: string[] = [];
  const needle = query.toLocaleLowerCase();
  async function walk(directory: string): Promise<void> {
    if (result.length >= maximum) return;
    const entries = (await fs.readdir(directory, { withFileTypes: true })).sort(
      (a, b) => a.name.localeCompare(b.name),
    );
    for (const entry of entries) {
      if (result.length >= maximum || !guard.isVisibleName(entry.name))
        continue;
      const path = resolve(directory, entry.name);
      if (entry.isDirectory()) {
        await walk(path);
      } else if (entry.isFile()) {
        const stat = await fs.stat(path);
        if (stat.size > maxFileBytes) continue;
        const content = await fs.readFile(path, "utf8");
        const lines = content.split("\n");
        for (
          let index = 0;
          index < lines.length && result.length < maximum;
          index += 1
        ) {
          const line = lines[index];
          if (line?.toLocaleLowerCase().includes(needle)) {
            const relativePath = redactSecrets(await guard.relative(path));
            result.push(
              `${relativePath}:${index + 1}: ${redactSecrets(line).slice(0, 500)}`,
            );
          }
        }
      }
    }
  }
  await walk(root);
  return result;
}

interface LineRequest {
  path: string;
  startLine?: number;
  endLine?: number;
}

/** Numbered lines like `cat -n`, so findings can cite exact line numbers. */
function numbered(
  content: string,
  range: LineRequest,
  maximum: number,
): string {
  const lines = content.split("\n");
  if (lines.at(-1) === "") lines.pop();
  const start = Math.max(1, range.startLine ?? 1);
  const end = Math.min(lines.length, range.endLine ?? lines.length);
  const selected = lines
    .slice(start - 1, end)
    .map((line, index) => `${String(start + index).padStart(6)}\t${line}`)
    .join("\n");
  if (!selected) return `The file has ${lines.length} lines.`;
  const partial = selected.length > maximum || start > 1 || end < lines.length;
  return partial
    ? `${trim(selected, maximum)}\n[The file has ${lines.length} lines; request startLine and endLine to read another range]`
    : trim(selected, maximum);
}

function exitStatus(error: unknown): number | undefined {
  return error instanceof Error &&
    "code" in error &&
    typeof error.code === "number"
    ? error.code
    : undefined;
}

function trim(value: string, maximum: number): string {
  const marker = "\n[Output truncated by Heyo]";
  const bounded =
    value.length > maximum
      ? value.slice(0, Math.max(0, maximum - marker.length))
      : value;
  return redactSecrets(bounded) + (value.length > maximum ? marker : "");
}

function isBlockedName(name: string): boolean {
  const normalized = name.toLocaleLowerCase();
  return (
    BLOCKED_NAMES.has(normalized) ||
    normalized.startsWith(".env") ||
    normalized.endsWith(".pem") ||
    normalized.endsWith(".key")
  );
}

function result(text: string) {
  return { content: [{ type: "text" as const, text }], details: {} };
}
