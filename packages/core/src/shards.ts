import type { ChangedFile } from "./types.js";

/** One discovery pass: a group of changed files reviewed together. */
export interface DiffShard {
  files: ChangedFile[];
  diff: string;
}

export interface ShardPlan {
  shards: DiffShard[];
  /** Auditable files that no discovery pass could include. */
  overflow: ChangedFile[];
}

/** Lowercase names of dependency lockfiles, which are listed but not audited. */
export const LOCKFILE_NAMES: ReadonlySet<string> = new Set([
  "bun.lock",
  "bun.lockb",
  "cargo.lock",
  "composer.lock",
  "gemfile.lock",
  "go.sum",
  "package-lock.json",
  "pnpm-lock.yaml",
  "poetry.lock",
  "uv.lock",
  "yarn.lock",
]);
const GENERATED = [
  /\.min\.(?:js|css)$/i,
  /\.map$/i,
  /\.snap$/i,
  /(?:^|\/)__snapshots__\//,
];
const TESTS = [
  /(?:^|\/)(?:__tests__|tests?|e2e|spec)\//i,
  /\.(?:test|spec)\.[^/]+$/i,
];
const DOCS = /\.(?:md|mdx|txt|rst|adoc)$/i;
const TRUNCATION =
  "\n[File diff truncated by Heyo; read the file for the rest]";

/** Lockfiles, minified bundles, source maps, and test snapshots. */
export function isLowSignalPath(path: string): boolean {
  const name = path.split("/").at(-1)?.toLowerCase() ?? "";
  return (
    LOCKFILE_NAMES.has(name) || GENERATED.some((pattern) => pattern.test(path))
  );
}

/**
 * Splits the auditable files into discovery passes that each fit one bounded
 * prompt. Source files come first, then tests, then documentation, and files
 * of one directory stay together. Files beyond `maxShards` passes overflow.
 */
export function planShards(
  files: ChangedFile[],
  options: { maxShardChars: number; maxShards: number },
): ShardPlan {
  const auditable = files
    .filter((file) => !file.lowSignal && file.diff)
    .sort((a, b) => tier(a.path) - tier(b.path) || compare(a.path, b.path));
  const groups: ChangedFile[][] = [];
  let current: ChangedFile[] = [];
  let size = 0;
  for (const file of auditable) {
    const bounded = boundDiff(file, options.maxShardChars);
    if (current.length && size + bounded.diff.length > options.maxShardChars) {
      groups.push(current);
      current = [];
      size = 0;
    }
    current.push(bounded);
    size += bounded.diff.length;
  }
  if (current.length) groups.push(current);
  return {
    shards: groups.slice(0, options.maxShards).map((group) => ({
      files: group,
      diff: group.map((file) => file.diff).join("\n"),
    })),
    overflow: [
      ...groups.slice(options.maxShards).flat(),
      ...files.filter((file) => !file.lowSignal && !file.diff),
    ],
  };
}

function boundDiff(file: ChangedFile, maximum: number): ChangedFile {
  if (file.diff.length <= maximum) return file;
  return {
    ...file,
    diff: file.diff.slice(0, maximum - TRUNCATION.length) + TRUNCATION,
  };
}

function tier(path: string): number {
  if (TESTS.some((pattern) => pattern.test(path))) return 1;
  return DOCS.test(path) ? 2 : 0;
}

function compare(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}
