import { afterEach, describe, expect, test } from "bun:test";
import type { AgentEvent } from "@mariozechner/pi-agent-core";
import {
  fauxAssistantMessage,
  fauxText,
  fauxThinking,
  fauxToolCall,
  registerFauxProvider,
  type AssistantMessage,
  type FauxProviderRegistration,
  type ToolResultMessage,
} from "@mariozechner/pi-ai";
import {
  InMemorySpanExporter,
  type ReadableSpan,
  type SpanExporter,
} from "@opentelemetry/sdk-trace-base";
import type {
  RepositorySnapshot,
  RuntimeInput,
} from "@heyo-sh/code-audit-core";
import {
  createLangfuseTracer,
  NO_TRACER,
  PiAuditRuntime,
  redact,
} from "../src/index.js";

const GITHUB_TOKEN = "github-token-value-0123456789";
const langfuse = {
  publicKey: "pk-lf-public",
  secretKey: "sk-lf-secret-0123456789",
  baseUrl: "https://langfuse.example",
  environment: "ci",
};
const context = { repository: "heyo/audit", pullRequest: 7 };

let registration: FauxProviderRegistration | undefined;
afterEach(() => {
  registration?.unregister();
  registration = undefined;
});

const input: RuntimeInput = {
  repositoryPath: process.cwd(),
  baseSha: "a".repeat(40),
  headSha: "b".repeat(40),
  phase: "discovery",
  checks: ["security"],
  provider: "openai",
  model: "gpt-5.6-terra",
  auth: { type: "api-key", token: "key" },
  internalPrompt: "fixed",
  permissions: "read-only",
  limits: {
    maxTurns: 3,
    maxToolCalls: 3,
    maxTokens: 100,
    maxFileBytes: 1000,
    maxSearchResults: 3,
    maxDiffBytes: 1000,
    maxOutputBytes: 1000,
    timeoutMs: 1000,
  },
};
const snapshot: RepositorySnapshot = {
  repositoryPath: input.repositoryPath,
  baseSha: input.baseSha,
  headSha: input.headSha,
  diff: `+ const token = "${GITHUB_TOKEN}";\n+ password = hunter2-hunter2-hunter2`,
  files: [],
  changedPaths: [],
  guidance: [],
  commits: [],
};

function tracerWith(exporter: SpanExporter) {
  return createLangfuseTracer(langfuse, context, {
    secrets: [GITHUB_TOKEN, undefined],
    exporter,
  });
}

function spansOf(exporter: InMemorySpanExporter, type: string): ReadableSpan[] {
  return exporter
    .getFinishedSpans()
    .filter((span) => span.attributes["langfuse.observation.type"] === type);
}

describe("Langfuse tracing", () => {
  test("traces a Pi session with its model calls and tool calls, without secrets", async () => {
    registration = registerFauxProvider({
      api: "openai-responses",
      provider: "openai",
    });
    registration.setResponses([
      fauxAssistantMessage(fauxToolCall("read_pr_diff", {}), {
        stopReason: "toolUse",
      }),
      fauxAssistantMessage('{"findings":[]}'),
    ]);
    const exporter = new InMemorySpanExporter();
    const tracer = tracerWith(exporter);

    const runtime = new PiAuditRuntime(
      { resolve: async () => snapshot },
      tracer,
    );
    await expect(runtime.run(input)).resolves.toEqual({ findings: [] });
    await tracer.flush();

    const [root] = spansOf(exporter, "agent");
    const generations = spansOf(exporter, "generation");
    const [tool] = spansOf(exporter, "tool");
    expect(root?.name).toBe("Heyo discovery");
    expect(generations).toHaveLength(2);
    expect(tool?.name).toBe("read_pr_diff");

    for (const span of exporter.getFinishedSpans())
      expect(span.attributes).toMatchObject({
        "langfuse.trace.name": "heyo-code-audit",
        "session.id": `heyo/audit#7@${"b".repeat(12)}`,
        "langfuse.trace.tags": ["heyo-code-audit", "discovery"],
        "langfuse.trace.metadata.repository": '"heyo/audit"',
        "langfuse.trace.metadata.pullRequest": '"7"',
        "langfuse.environment": "ci",
      });

    expect(root?.attributes["langfuse.observation.output"]).toContain(
      "findings",
    );
    for (const generation of generations)
      expect(generation.attributes).toMatchObject({
        "langfuse.observation.model.name": "gpt-5.6-terra",
        "langfuse.observation.usage_details": expect.any(String),
      });
    // The second model call reads the result of the tool call.
    expect(
      generations.some((generation) =>
        String(generation.attributes["langfuse.observation.input"]).includes(
          "read_pr_diff",
        ),
      ),
    ).toBe(true);

    const exported = JSON.stringify(
      exporter.getFinishedSpans().map((span) => span.attributes),
    );
    expect(exported).toContain("[REDACTED_SECRET]");
    expect(exported).not.toContain(GITHUB_TOKEN);
    expect(exported).not.toContain("hunter2-hunter2-hunter2");
  });

  test("records a failed session with the error category, not the provider error", async () => {
    registration = registerFauxProvider({
      api: "openai-responses",
      provider: "openai",
    });
    const raw = "HTTP 401: invalid key sk_fakeSecret12345678901234567890";
    registration.setResponses([
      fauxAssistantMessage("", { stopReason: "error", errorMessage: raw }),
    ]);
    const exporter = new InMemorySpanExporter();
    const tracer = tracerWith(exporter);

    const runtime = new PiAuditRuntime(
      { resolve: async () => snapshot },
      tracer,
    );
    await expect(runtime.run(input)).rejects.toThrow("HTTP 401");
    await tracer.flush();

    const [root] = spansOf(exporter, "agent");
    const [generation] = spansOf(exporter, "generation");
    expect(root?.attributes["langfuse.observation.level"]).toBe("ERROR");
    expect(generation?.attributes).toMatchObject({
      "langfuse.observation.level": "ERROR",
      "langfuse.observation.status_message":
        "authentication or permission error (HTTP 401)",
    });
    expect(
      JSON.stringify(
        exporter.getFinishedSpans().map((span) => span.attributes),
      ),
    ).not.toContain("sk_fakeSecret");
  });

  test("closes what a session leaves open and never lets tracing fail the audit", async () => {
    const exporter = new InMemorySpanExporter();
    const tracer = tracerWith(exporter);
    const session = tracer.startSession({ ...input, phase: "verification" });
    const streaming = fauxAssistantMessage("");
    const answer: AssistantMessage = {
      ...fauxAssistantMessage([
        fauxThinking("hidden"),
        fauxText("x".repeat(20_001)),
        fauxToolCall("read_file", { path: "a.ts" }, { id: "call-1" }),
      ]),
      usage: {
        input: 10,
        output: 20,
        cacheRead: 5,
        cacheWrite: 0,
        totalTokens: 35,
        cost: {
          input: 0.1,
          output: 0.2,
          cacheRead: 0.01,
          cacheWrite: 0,
          total: 0.31,
        },
      },
      stopReason: "aborted",
    };
    const toolResult = (text: string): ToolResultMessage => ({
      role: "toolResult",
      toolCallId: "call-1",
      toolName: "read_file",
      content: [
        { type: "text", text },
        { type: "image", data: "", mimeType: "image/png" },
      ],
      isError: false,
      timestamp: 0,
    });
    const update: AgentEvent = {
      type: "message_update",
      message: streaming,
      assistantMessageEvent: { type: "start", partial: streaming },
    };

    session.observe({
      type: "message_end",
      message: { role: "user", content: "Verify it.", timestamp: 0 },
    });
    // A second model call before the first one ended supersedes it.
    session.observe({ type: "message_start", message: streaming });
    session.observe({ type: "message_start", message: streaming });
    session.observe(update);
    session.observe(update);
    session.observe({ type: "message_end", message: answer });
    // An answer without an open model call is ignored.
    session.observe({ type: "message_end", message: answer });
    session.observe({
      type: "tool_execution_start",
      toolCallId: "call-1",
      toolName: "read_file",
      args: { path: "a.ts" },
    });
    session.observe({
      type: "tool_execution_end",
      toolCallId: "call-1",
      toolName: "read_file",
      result: { content: [{ type: "text", text: "plain" }], details: {} },
      isError: true,
    });
    session.observe({
      type: "tool_execution_end",
      toolCallId: "unknown",
      toolName: "read_file",
      result: { content: [], details: {} },
      isError: false,
    });
    session.observe({ type: "message_end", message: toolResult("first") });
    session.observe({ type: "message_end", message: toolResult("second") });
    session.observe({
      type: "tool_execution_start",
      toolCallId: "call-2",
      toolName: "search_repository",
      args: {},
    });
    session.observe({ type: "message_start", message: streaming });
    session.observe({ type: "turn_start" });
    // Malformed input must not fail the audit: these throw inside the tracer.
    session.observe({ type: "message_end", message: null } as never);
    session.end(undefined as never);
    session.end({ error: "Pi audit session timed out after 1 ms." });
    await tracer.flush();

    // Spans reach the exporter in no fixed order, so they are found by their status.
    const generations = Object.fromEntries(
      spansOf(exporter, "generation").map((span) => [
        span.attributes["langfuse.observation.status_message"],
        span.attributes,
      ]),
    );
    const tools = spansOf(exporter, "tool");
    expect(Object.keys(generations).sort()).toEqual([
      "Superseded by a new model call",
      "The session ended during the model call",
      "aborted",
    ]);
    expect(generations.aborted).toMatchObject({
      "langfuse.observation.level": "WARNING",
    });
    expect(
      String(generations.aborted?.["langfuse.observation.output"]),
    ).toContain("[Truncated by Heyo]");
    expect(
      String(generations.aborted?.["langfuse.observation.cost_details"]),
    ).toContain("total");
    expect(
      String(
        generations["The session ended during the model call"]?.[
          "langfuse.observation.input"
        ],
      ),
    ).toContain("second");
    expect(
      Object.fromEntries(
        tools.map((span) => [
          span.name,
          span.attributes["langfuse.observation.level"],
        ]),
      ),
    ).toEqual({ read_file: "ERROR", search_repository: "WARNING" });
    expect(
      spansOf(exporter, "agent")[0]?.attributes["langfuse.observation.level"],
    ).toBe("ERROR");
  });

  test("flushes even when Langfuse rejects the traces", async () => {
    const failing: SpanExporter = {
      export: (_spans, done) => done({ code: 1, error: new Error("down") }),
      shutdown: async () => {},
      forceFlush: async () => {
        throw new Error("down");
      },
    };
    const tracer = tracerWith(failing);
    tracer.startSession(input).end({ output: "{}" });
    await expect(tracer.flush()).resolves.toBeUndefined();
  });

  test("does nothing without Langfuse and redacts nested data", async () => {
    const session = NO_TRACER.startSession(input);
    session.observe({ type: "turn_start" });
    session.end({ output: "{}" });
    await expect(NO_TRACER.flush()).resolves.toBeUndefined();

    expect(
      redact(
        {
          list: [`key ${GITHUB_TOKEN}`, 3],
          nested: { flag: true },
          none: null,
        },
        [GITHUB_TOKEN],
      ),
    ).toEqual({
      list: ["key [REDACTED_SECRET]", 3],
      nested: { flag: true },
      none: null,
    });
  });
});
