import { deflateRawSync, inflateRawSync } from "node:zlib";
import { parseFinding, type AuditState } from "@heyo-sh/code-audit-core";

const START = "<!-- heyo-code-audit-state:";
const END = " -->";
// Bounds the inflated state, so a forged marker cannot exhaust memory.
const MAX_STATE_BYTES = 2_000_000;

export function encodeAuditState(state: AuditState): string {
  // Compressed, so twenty detailed findings fit GitHub's Check output limit.
  const encoded = deflateRawSync(
    Buffer.from(JSON.stringify(state), "utf8"),
  ).toString("base64url");
  if (encoded.length > 50_000)
    throw new Error("Heyo audit state exceeds GitHub Check output limits.");
  return `${START}${encoded}${END}`;
}

export function decodeAuditState(
  summary: string | undefined,
): AuditState | undefined {
  if (!summary) return undefined;
  const start = summary.lastIndexOf(START);
  if (start < 0) return undefined;
  const end = summary.indexOf(END, start);
  if (end < 0) return undefined;
  try {
    const raw = JSON.parse(
      inflateRawSync(
        Buffer.from(summary.slice(start + START.length, end), "base64url"),
        { maxOutputLength: MAX_STATE_BYTES },
      ).toString("utf8"),
    ) as Record<string, unknown>;
    if (
      raw.version !== 1 ||
      !sha(raw.baseSha) ||
      !sha(raw.auditedHeadSha) ||
      typeof raw.configHash !== "string" ||
      typeof raw.policyVersion !== "string" ||
      !Array.isArray(raw.findings)
    )
      return undefined;
    return {
      version: 1,
      baseSha: raw.baseSha,
      auditedHeadSha: raw.auditedHeadSha,
      configHash: raw.configHash,
      policyVersion: raw.policyVersion,
      findings: raw.findings.map(parseFinding),
    };
  } catch {
    return undefined;
  }
}

function sha(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{7,64}$/i.test(value);
}
