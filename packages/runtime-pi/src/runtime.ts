import { Agent, type AgentOptions } from "@mariozechner/pi-agent-core";
import { getModel, getModels, stream, type Model } from "@mariozechner/pi-ai";
import {
  AuditSessionError,
  parseDiscovery,
  parseOverview,
  parseVerification,
  redactSecrets,
  type AuditPhaseResult,
  type AuditRuntime,
  type RuntimeInput,
} from "@heyo-sh/code-audit-core";
import { sessionErrorCategory } from "./errors.js";
import { NO_TRACER, type AuditTracer } from "./langfuse.js";
import { createRestrictedTools } from "./tools.js";
import type { RepositorySnapshot } from "@heyo-sh/code-audit-core";

export class PiAuditRuntime implements AuditRuntime {
  constructor(
    private readonly snapshots: SnapshotResolver,
    private readonly tracer: AuditTracer = NO_TRACER,
  ) {}

  async run(input: RuntimeInput): Promise<AuditPhaseResult> {
    const response = await this.execute(input);
    if (input.phase === "discovery") return parseDiscovery(response);
    if (input.phase === "verification") return parseVerification(response);
    return parseOverview(response);
  }

  private async execute(input: RuntimeInput): Promise<unknown> {
    if (input.permissions !== "read-only")
      throw new AuditSessionError(
        "Pi runtime requires read-only permissions.",
        false,
      );
    const snapshot = await this.snapshots.resolve(
      input.repositoryPath,
      input.baseSha,
      input.headSha,
    );
    const selectedModel = providerModel(input.provider, input.model);
    const model = {
      ...selectedModel,
      maxTokens: Math.min(selectedModel.maxTokens, input.limits.maxTokens),
    };
    const agent = new Agent({
      initialState: {
        systemPrompt: input.internalPrompt,
        model,
        thinkingLevel: "high",
        tools: createRestrictedTools(input, snapshot),
      },
      ...piAgentAuthOptions(input),
      toolExecution: "sequential",
      maxRetryDelayMs: 5_000,
    });
    const trace = this.tracer.startSession(input);
    let turns = 0;
    agent.subscribe((event) => {
      trace.observe(event);
      if (event.type === "turn_start") {
        turns += 1;
        if (turns > input.limits.maxTurns) agent.abort();
      }
    });
    let timedOut = false;
    const timeout = setTimeout(() => {
      timedOut = true;
      agent.abort();
    }, input.limits.timeoutMs);
    try {
      const text = await finalAnswer(agent, input, () => ({ turns, timedOut }));
      const response: unknown = JSON.parse(extractJson(text));
      trace.end({ output: text });
      return response;
    } catch (error) {
      trace.end({
        error: error instanceof Error ? error.message : "Pi audit failed.",
      });
      throw error;
    } finally {
      clearTimeout(timeout);
    }
  }
}

/** Runs the session and returns its final text, or throws a safe error. */
async function finalAnswer(
  agent: Agent,
  input: RuntimeInput,
  status: () => { turns: number; timedOut: boolean },
): Promise<string> {
  await agent.prompt(
    "Perform the requested Heyo audit phase now. Return the required JSON object only.",
  );
  // An exhausted budget would be exhausted again, so it is not retried.
  if (status().turns > input.limits.maxTurns)
    throw new AuditSessionError(
      `Pi audit session exceeded the turn limit (${input.limits.maxTurns}).`,
      false,
    );
  if (status().timedOut)
    throw new AuditSessionError(
      `Pi audit session timed out after ${input.limits.timeoutMs} ms.`,
      false,
    );
  if (agent.state.errorMessage) {
    const category = sessionErrorCategory(agent.state.errorMessage);
    throw new AuditSessionError(
      `Pi audit session failed: ${category}.`,
      !category.startsWith("authentication"),
    );
  }
  const assistant = [...agent.state.messages]
    .reverse()
    .find((message) => message.role === "assistant");
  if (
    !assistant ||
    assistant.stopReason === "error" ||
    assistant.stopReason === "aborted"
  )
    throw new AuditSessionError(
      "Pi audit session returned no valid final answer.",
      true,
    );
  const text = assistant.content
    .filter(
      (block): block is Extract<typeof block, { type: "text" }> =>
        block.type === "text",
    )
    .map((block) => block.text)
    .join("\n");
  if (!text || Buffer.byteLength(text) > input.limits.maxOutputBytes)
    throw new AuditSessionError(
      "Pi audit response exceeded the output limit.",
      true,
    );
  return text;
}

function piAgentAuthOptions(
  input: RuntimeInput,
): Pick<AgentOptions, "getApiKey" | "streamFn"> {
  const auth = input.auth;
  switch (auth.type) {
    case "api-key":
    case "oauth":
      return {
        getApiKey: (provider) =>
          provider === input.provider ? auth.token : undefined,
      };
    case "aws":
      return {
        streamFn: (model, context, options) =>
          stream(model, context, {
            ...options,
            ...(auth.region ? { region: auth.region } : {}),
            ...(auth.profile ? { profile: auth.profile } : {}),
          }),
      };
    case "bedrock-bearer":
      return {
        streamFn: (model, context, options) =>
          stream(model, context, {
            ...options,
            bearerToken: auth.token,
            ...(auth.region ? { region: auth.region } : {}),
          }),
      };
  }
}

export interface SnapshotResolver {
  resolve(
    repositoryPath: string,
    baseSha: string,
    headSha: string,
  ): Promise<RepositorySnapshot>;
}

export function providerModel(
  provider: RuntimeInput["provider"],
  id: string,
): Model<import("@mariozechner/pi-ai").Api> {
  if (!id.trim())
    throw new AuditSessionError(
      "Pi audit runtime requires a configured model.",
      false,
    );
  const known = getModel(provider as never, id as never);
  if (known) return known;
  const template = getModels(provider as never)[0];
  if (!template)
    throw new AuditSessionError(
      `Pi does not support provider '${provider}'.`,
      false,
    );
  return { ...template, id, name: id };
}

/**
 * The JSON object of a final answer, even when the model wraps it in prose or
 * a fence, appends more text, or leaves raw line breaks inside strings.
 */
export function extractJson(text: string): string {
  const trimmed = redactSecrets(text).trim();
  const body =
    trimmed.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/i)?.[1] ?? trimmed;
  let first: string | undefined;
  let start = body.indexOf("{");
  for (let attempt = 0; start >= 0 && attempt < 20; attempt += 1) {
    const candidate = balancedObject(body, start);
    if (candidate) {
      first ??= candidate;
      try {
        JSON.parse(candidate);
        return candidate;
      } catch {
        // Braces in prose can precede the answer; try the next object.
      }
    }
    start = body.indexOf("{", start + 1);
  }
  return first ?? body;
}

/** The balanced object starting at `start`, with raw control characters in strings escaped. */
function balancedObject(text: string, start: number): string | undefined {
  const escapes: Record<string, string> = {
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
  };
  let depth = 0;
  let inString = false;
  let escaped = false;
  let result = "";
  for (let index = start; index < text.length; index += 1) {
    const character = text[index]!;
    if (inString) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === '"') inString = false;
      result += escapes[character] ?? character;
      continue;
    }
    result += character;
    if (character === '"') inString = true;
    else if (character === "{") depth += 1;
    else if (character === "}" && --depth === 0) return result;
  }
  return undefined;
}
