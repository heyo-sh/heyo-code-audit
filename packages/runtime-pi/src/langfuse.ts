import type {
  AgentEvent,
  AgentMessage,
  AgentToolResult,
} from "@mariozechner/pi-agent-core";
import type {
  AssistantMessage,
  ToolResultMessage,
  Usage,
} from "@mariozechner/pi-ai";
import { LangfuseSpanProcessor } from "@langfuse/otel";
import {
  LangfuseOtelSpanAttributes,
  setLangfuseTracerProvider,
  startObservation,
  type LangfuseAgent,
  type LangfuseGeneration,
  type LangfuseTool,
} from "@langfuse/tracing";
import {
  BasicTracerProvider,
  type SpanExporter,
} from "@opentelemetry/sdk-trace-base";
import {
  redactSecrets,
  type LangfuseConfig,
  type RuntimeInput,
} from "@heyo-sh/code-audit-core";
import { sessionErrorCategory } from "./errors.js";

/** Characters kept from one traced text. Longer texts are cut with a marker. */
const MAX_TRACED_CHARS = 20_000;
const FLUSH_TIMEOUT_MS = 10_000;
const TRACE_NAME = "heyo-code-audit";

/** Traces the Pi sessions of one audit run. */
export interface AuditTracer {
  startSession(input: RuntimeInput): SessionTrace;
  /** Sends the pending traces. Never throws and waits at most 10 seconds. */
  flush(): Promise<void>;
}

/** One Pi session: a discovery pass or the verification of one candidate. */
export interface SessionTrace {
  observe(event: AgentEvent): void;
  end(result: { output: string } | { error: string }): void;
}

export interface AuditTraceContext {
  repository: string;
  pullRequest: number;
}

const NO_SESSION: SessionTrace = { observe() {}, end() {} };

export const NO_TRACER: AuditTracer = {
  startSession: () => NO_SESSION,
  flush: async () => {},
};

/**
 * Traces every Pi session in Langfuse: the session as an agent observation,
 * each model call as a generation with tokens and cost, and each tool call.
 * Sessions of one pull request head share a Langfuse session. Configured
 * secrets and common credential formats are redacted before export.
 */
export function createLangfuseTracer(
  config: LangfuseConfig,
  context: AuditTraceContext,
  options: {
    secrets?: Array<string | undefined>;
    exporter?: SpanExporter;
  } = {},
): AuditTracer {
  const secrets = [
    config.secretKey,
    config.publicKey,
    ...(options.secrets ?? []),
  ].filter((secret): secret is string => Boolean(secret));
  const processor = new LangfuseSpanProcessor({
    publicKey: config.publicKey,
    secretKey: config.secretKey,
    baseUrl: config.baseUrl,
    ...(config.environment ? { environment: config.environment } : {}),
    ...(options.exporter ? { exporter: options.exporter } : {}),
    mediaUploadEnabled: false,
    mask: ({ data }) => redact(data, secrets),
  });
  // Its own provider: the Action never touches the global OpenTelemetry setup.
  setLangfuseTracerProvider(
    new BasicTracerProvider({ spanProcessors: [processor] }),
  );

  return {
    startSession: (input) => guarded(new LangfuseSession(input, context)),
    async flush() {
      let timer: ReturnType<typeof setTimeout> | undefined;
      await Promise.race([
        processor.forceFlush().catch(() => undefined),
        new Promise((resolve) => {
          timer = setTimeout(resolve, FLUSH_TIMEOUT_MS);
        }),
      ]);
      clearTimeout(timer);
    },
  };
}

/** Tracing must never fail an audit. */
function guarded(session: SessionTrace): SessionTrace {
  return {
    observe(event) {
      try {
        session.observe(event);
      } catch {
        // Losing a trace is acceptable; failing the audit is not.
      }
    },
    end(result) {
      try {
        session.end(result);
      } catch {
        // Losing a trace is acceptable; failing the audit is not.
      }
    },
  };
}

class LangfuseSession implements SessionTrace {
  private readonly root: LangfuseAgent;
  private readonly attributes: Record<string, string | string[]>;
  private readonly tools = new Map<string, LangfuseTool>();
  private generation: LangfuseGeneration | undefined;
  private firstToken = false;
  /** What the next model call reads: the prompt, then the results of the previous tool calls. */
  private pendingInput: { role: "user"; content: string } | ToolResultInput[] =
    [];

  constructor(input: RuntimeInput, context: AuditTraceContext) {
    this.attributes = traceAttributes(input, context);
    this.root = startObservation(
      `Heyo ${input.phase}`,
      {
        input: { system: clip(input.internalPrompt) },
        metadata: {
          phase: input.phase,
          checks: input.checks,
          provider: input.provider,
          model: input.model,
          baseSha: input.baseSha,
          headSha: input.headSha,
        },
      },
      { asType: "agent" },
    );
    this.root.otelSpan.setAttributes(this.attributes);
  }

  observe(event: AgentEvent): void {
    switch (event.type) {
      case "message_start":
        if (event.message.role === "assistant") this.startGeneration();
        break;
      case "message_update":
        if (this.generation && !this.firstToken) {
          this.firstToken = true;
          this.generation.update({ completionStartTime: new Date() });
        }
        break;
      case "message_end":
        this.endMessage(event.message);
        break;
      case "tool_execution_start":
        this.startTool(event.toolCallId, event.toolName, event.args);
        break;
      case "tool_execution_end":
        this.endTool(
          event.toolCallId,
          event.result as AgentToolResult<unknown>,
          event.isError,
        );
        break;
    }
  }

  end(result: { output: string } | { error: string }): void {
    this.closeOpen();
    this.root.update(
      "output" in result
        ? { output: clip(result.output) }
        : { level: "ERROR", statusMessage: result.error },
    );
    this.root.end();
  }

  private startGeneration(): void {
    this.closeGeneration("Superseded by a new model call");
    this.firstToken = false;
    this.generation = this.root.startObservation(
      "Pi model call",
      { input: this.pendingInput },
      { asType: "generation" },
    );
    this.generation.otelSpan.setAttributes(this.attributes);
    this.pendingInput = [];
  }

  private endMessage(message: AgentMessage): void {
    switch (message.role) {
      case "user":
        this.pendingInput = { role: "user", content: textOf(message.content) };
        return;
      case "toolResult":
        this.pendingInput = [
          ...(Array.isArray(this.pendingInput) ? this.pendingInput : []),
          toolResultInput(message),
        ];
        return;
      case "assistant":
        this.endGeneration(message);
        return;
    }
  }

  private endGeneration(message: AssistantMessage): void {
    if (!this.generation) return;
    const failed =
      message.stopReason === "error" || message.stopReason === "aborted";
    this.generation.update({
      model: message.responseModel ?? message.model,
      output: message.content.flatMap((block): unknown[] => {
        if (block.type === "text")
          return [{ type: "text", text: clip(block.text) }];
        if (block.type === "toolCall")
          return [
            { type: "toolCall", name: block.name, arguments: block.arguments },
          ];
        return [];
      }),
      usageDetails: usageDetails(message.usage),
      ...costDetails(message.usage),
      ...(failed
        ? {
            level:
              message.stopReason === "error"
                ? ("ERROR" as const)
                : ("WARNING" as const),
            statusMessage:
              message.stopReason === "error"
                ? sessionErrorCategory(message.errorMessage ?? "")
                : "aborted",
          }
        : {}),
    });
    this.generation.end();
    this.generation = undefined;
  }

  private startTool(id: string, name: string, args: unknown): void {
    const tool = this.root.startObservation(
      name,
      { input: args },
      { asType: "tool" },
    );
    tool.otelSpan.setAttributes(this.attributes);
    this.tools.set(id, tool);
  }

  private endTool(
    id: string,
    result: AgentToolResult<unknown>,
    isError: boolean,
  ): void {
    const tool = this.tools.get(id);
    if (!tool) return;
    tool.update({
      output: textOf(result.content),
      ...(isError ? { level: "ERROR" as const } : {}),
    });
    tool.end();
    this.tools.delete(id);
  }

  private closeOpen(): void {
    this.closeGeneration("The session ended during the model call");
    for (const tool of this.tools.values()) {
      tool.update({
        level: "WARNING",
        statusMessage: "The session ended during the tool call",
      });
      tool.end();
    }
    this.tools.clear();
  }

  private closeGeneration(statusMessage: string): void {
    if (!this.generation) return;
    this.generation.update({ level: "WARNING", statusMessage });
    this.generation.end();
    this.generation = undefined;
  }
}

/** Langfuse reads the trace fields from every span, so each span gets them. */
function traceAttributes(
  input: RuntimeInput,
  context: AuditTraceContext,
): Record<string, string | string[]> {
  const metadata = {
    repository: context.repository,
    pullRequest: String(context.pullRequest),
    phase: input.phase,
  };
  return {
    [LangfuseOtelSpanAttributes.TRACE_NAME]: TRACE_NAME,
    [LangfuseOtelSpanAttributes.TRACE_SESSION_ID]: `${context.repository}#${context.pullRequest}@${input.headSha.slice(0, 12)}`,
    [LangfuseOtelSpanAttributes.TRACE_TAGS]: [TRACE_NAME, input.phase],
    ...Object.fromEntries(
      Object.entries(metadata).map(([key, value]) => [
        `${LangfuseOtelSpanAttributes.TRACE_METADATA}.${key}`,
        JSON.stringify(value),
      ]),
    ),
  };
}

function usageDetails(usage: Usage): Record<string, number> {
  return positive({
    input: usage.input,
    output: usage.output,
    cache_read_input_tokens: usage.cacheRead,
    cache_creation_input_tokens: usage.cacheWrite,
  });
}

/** Without a cost, Langfuse prices the generation from its model definitions. */
function costDetails(usage: Usage): {
  costDetails?: Record<string, number>;
} {
  if (!(usage.cost.total > 0)) return {};
  return {
    costDetails: positive({
      total: usage.cost.total,
      input: usage.cost.input,
      output: usage.cost.output,
      cache_read_input_tokens: usage.cost.cacheRead,
      cache_creation_input_tokens: usage.cost.cacheWrite,
    }),
  };
}

function positive(values: Record<string, number>): Record<string, number> {
  return Object.fromEntries(
    Object.entries(values).filter(([, value]) => value > 0),
  );
}

interface ToolResultInput {
  tool: string;
  isError: boolean;
  content: string;
}

function toolResultInput(message: ToolResultMessage): ToolResultInput {
  return {
    tool: message.toolName,
    isError: message.isError,
    content: textOf(message.content),
  };
}

/** The text blocks of a message or tool result; images are left out. */
function textOf(content: AgentToolResult<unknown>["content"] | string): string {
  if (typeof content === "string") return clip(content);
  return clip(
    content
      .flatMap((block) => (block.type === "text" ? [block.text] : []))
      .join("\n"),
  );
}

function clip(text: string): string {
  return text.length > MAX_TRACED_CHARS
    ? `${text.slice(0, MAX_TRACED_CHARS)}\n[Truncated by Heyo]`
    : text;
}

/** Removes configured secrets and common credential formats from traced data. */
export function redact(data: unknown, secrets: string[]): unknown {
  if (typeof data === "string") {
    let redacted = data;
    for (const secret of secrets)
      redacted = redacted.replaceAll(secret, "[REDACTED_SECRET]");
    return redactSecrets(redacted);
  }
  if (Array.isArray(data)) return data.map((item) => redact(item, secrets));
  if (data && typeof data === "object")
    return Object.fromEntries(
      Object.entries(data).map(([key, value]) => [key, redact(value, secrets)]),
    );
  return data;
}
