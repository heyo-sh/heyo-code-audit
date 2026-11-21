import { createHash } from "node:crypto";
import {
  CHECK_IDS,
  CONFIDENCES,
  IMPACTS,
  SEVERITIES,
  type DiscoveryResult,
  type Finding,
  type OverviewResult,
  type VerificationResult,
} from "./types.js";
import { redactSecrets } from "./redaction.js";

export class SchemaError extends Error {}

export function parseDiscovery(value: unknown): DiscoveryResult {
  if (!isObject(value) || !Array.isArray(value.findings))
    throw new SchemaError("Discovery response must contain findings.");
  if (value.findings.length > 20)
    throw new SchemaError("Discovery response exceeds the finding limit.");
  return { findings: value.findings.map(parseFinding) };
}

export function parseVerification(value: unknown): VerificationResult {
  if (!isObject(value) || typeof value.verified !== "boolean")
    throw new SchemaError("Verification response must contain verified.");
  if (!value.verified)
    return typeof value.reason === "string"
      ? { verified: false, reason: clean(value.reason, 500) }
      : { verified: false };
  if (!value.finding)
    throw new SchemaError("A verified response must contain a finding.");
  return { verified: true, finding: parseFinding(value.finding) };
}

export function parseOverview(value: unknown): OverviewResult {
  if (!isObject(value))
    throw new SchemaError("Overview response must be an object.");
  const changes = Array.isArray(value.changes)
    ? value.changes
        .filter((change): change is string => typeof change === "string")
        .map((change) => singleLine(redactSecrets(change), 240))
        .filter(Boolean)
        .slice(0, 8)
    : [];
  const diagram = optionalDiagram(value.diagram);
  return {
    overview: {
      summary: requiredText(value.summary, "Overview summary", 600),
      changes,
      impact: enumValue(value.impact, IMPACTS, "Overview impact"),
      impactReason: singleLine(
        requiredText(value.impactReason, "Overview impactReason", 300),
        300,
      ),
      ...(diagram ? { diagram } : {}),
    },
  };
}

export function parseFinding(value: unknown): Finding {
  if (!isObject(value)) throw new SchemaError("Finding must be an object.");
  const check = enumValue(value.check, CHECK_IDS, "Finding check");
  const severity = enumValue(value.severity, SEVERITIES, "Finding severity");
  const confidence = enumValue(
    value.confidence,
    CONFIDENCES,
    "Finding confidence",
  );
  const title = singleLine(
    requiredText(value.title, "Finding title", 160),
    160,
  );
  const description = requiredText(
    value.description,
    "Finding description",
    1_000,
  );
  const evidence = requiredText(value.evidence, "Finding evidence", 1_000);
  const recommendation = optionalText(value.recommendation, 500);
  const suggestion = optionalSuggestion(value.suggestion);
  const file = optionalFile(value.file);
  const line = optionalLine(value.line);
  const fingerprint = fingerprintFor({
    check,
    title,
    evidence,
    ...(file ? { file } : {}),
    ...(line ? { line } : {}),
  });
  return {
    fingerprint,
    check,
    severity,
    confidence,
    title,
    description,
    evidence,
    ...(recommendation ? { recommendation } : {}),
    ...(suggestion ? { suggestion } : {}),
    ...(file ? { file } : {}),
    ...(line ? { line } : {}),
  };
}

/**
 * Keeps one finding per root cause, the most severe description winning.
 * Parallel passes describe one defect in different words, so findings at the
 * same file and line are one, and so are findings in one file whose titles
 * share most of their words.
 */
export function deduplicateFindings(findings: Finding[]): Finding[] {
  const best = new Map<string, Finding>();
  for (const finding of findings) {
    const key =
      finding.file && finding.line
        ? `${finding.file}\u0000${finding.line}`
        : finding.fingerprint;
    const existing = best.get(key);
    if (
      !existing ||
      severityRank(finding.severity) > severityRank(existing.severity)
    )
      best.set(key, finding);
  }
  const kept: Finding[] = [];
  for (const finding of [...best.values()].sort(
    (a, b) =>
      severityRank(b.severity) - severityRank(a.severity) ||
      a.fingerprint.localeCompare(b.fingerprint),
  ))
    if (!kept.some((other) => sameRootCause(other, finding)))
      kept.push(finding);
  return kept;
}

const STOP_WORDS = new Set(
  "the and for with when without from into onto are can not its their still than then that this".split(
    " ",
  ),
);

/** Two findings in one file whose titles name the same broken behavior. */
export function sameRootCause(a: Finding, b: Finding): boolean {
  if (a.file !== b.file) return false;
  const left = titleWords(a.title);
  const right = titleWords(b.title);
  const shared = [...left].filter((word) => right.has(word)).length;
  return shared >= 3 && shared / (left.size + right.size - shared) >= 0.6;
}

function titleWords(title: string): Set<string> {
  return new Set(
    title
      .toLowerCase()
      .split(/[^a-z0-9]+/)
      .filter((word) => word.length > 2 && !STOP_WORDS.has(word))
      .map((word) => word.replace(/(?:es|s)$/, "")),
  );
}

export function severityRank(severity: Finding["severity"]): number {
  return SEVERITIES.indexOf(severity) + 1;
}

function fingerprintFor(input: {
  check: string;
  title: string;
  evidence: string;
  file?: string;
  line?: number;
}): string {
  const stable = [
    input.check,
    input.file ?? "",
    input.line ?? "",
    input.title,
    input.evidence,
  ]
    .join("\n")
    .toLowerCase();
  return createHash("sha256").update(stable).digest("hex").slice(0, 24);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function enumValue<T extends readonly string[]>(
  value: unknown,
  values: T,
  name: string,
): T[number] {
  if (
    typeof value === "string" &&
    (values as readonly string[]).includes(value)
  )
    return value as T[number];
  throw new SchemaError(`${name} is invalid.`);
}

function requiredText(value: unknown, name: string, max: number): string {
  if (typeof value !== "string" || !value.trim())
    throw new SchemaError(`${name} is required.`);
  return clean(redactSecrets(value), max);
}

function optionalText(value: unknown, max: number): string | undefined {
  if (typeof value !== "string") return undefined;
  return clean(redactSecrets(value), max) || undefined;
}

function clean(value: string, max: number): string {
  return value.replaceAll("\u0000", "").trim().slice(0, max);
}

function singleLine(value: string, max: number): string {
  return clean(value.replaceAll(/\s+/g, " "), max);
}

const DIAGRAM_START = /^(?:flowchart|graph)\s+(?:TD|TB|BT|LR|RL)\b/;
const UNSAFE_DIAGRAM = /```|<[a-z/!?]|%%|\bclick\b|javascript:/i;

/** Accepts only a plain Mermaid flowchart; anything else is dropped. */
function optionalDiagram(value: unknown): string | undefined {
  if (typeof value !== "string" || value.length > 3_000) return undefined;
  const diagram = clean(value, 3_000);
  if (
    !DIAGRAM_START.test(diagram) ||
    UNSAFE_DIAGRAM.test(diagram) ||
    redactSecrets(diagram) !== diagram
  )
    return undefined;
  return diagram;
}

function optionalSuggestion(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || !value.trim())
    throw new SchemaError("Finding suggestion is invalid.");
  // Leading indentation is part of the replacement line, so only the end is
  // trimmed; GitHub applies the suggestion verbatim.
  const suggestion = value
    .replaceAll("\u0000", "")
    .replace(/\s+$/, "")
    .replace(/^(?:[ \t]*\n)+/, "")
    .slice(0, 4_000);
  if (suggestion.includes("```"))
    throw new SchemaError("Finding suggestion is invalid.");
  // A redacted suggestion would no longer be a valid replacement, so omit it.
  return redactSecrets(suggestion) === suggestion ? suggestion : undefined;
}

function optionalFile(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.length > 500)
    throw new SchemaError("Finding file is invalid.");
  const file = clean(redactSecrets(value), 500);
  if (
    !file ||
    file.startsWith("/") ||
    file.startsWith("\\") ||
    file.split(/[\\/]/).includes("..")
  ) {
    throw new SchemaError("Finding file is invalid.");
  }
  return file;
}

function optionalLine(value: unknown): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1)
    throw new SchemaError("Finding line is invalid.");
  return value;
}
