// Pi extension skeleton: send every tool_call (with ctx.model) to Admit POST /check.
// Fail-closed: block on anything but an explicit ALLOW, including errors and timeouts.
// NOTE: Pi extension errors fail open unless caught -- this handler wraps everything in
// try/catch and blocks on any exception, non-200 response, or timeout.
// TODO: register handleToolCall as Pi's tool_call handler (extensions load from
// ~/.pi/agent/extensions/ or .pi/extensions/).

const ADMIT_URL = process.env.ADMIT_URL ?? "http://127.0.0.1:8765/check";
const ADMIT_TOKEN = process.env.ADMIT_TOKEN ?? "";
// TODO: keep this below warn.timeout_seconds so a held WARN times out to deny.
const TIMEOUT_MS = 5_000;

interface ToolCall {
  name: string;
  args: unknown;
}

interface Context {
  model?: string;
}

interface Decision {
  verdict: "ALLOW" | "DENY" | "WARN" | "WOULD_DENY" | "PIN_MISMATCH";
  reason?: string;
  policy?: string;
}

export async function handleToolCall(
  toolCall: ToolCall,
  ctx: Context,
): Promise<{ block?: boolean; reason?: string }> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

    const response = await fetch(ADMIT_URL, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${ADMIT_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        caller: "pi",
        tool: toolCall.name,
        args: toolCall.args,
        model: ctx.model ?? "",
      }),
      signal: controller.signal,
    });
    clearTimeout(timeout);

    // Anything but HTTP 200 with an explicit ALLOW blocks.
    if (!response.ok) {
      return { block: true, reason: `admit returned HTTP ${response.status}` };
    }

    const decision: Decision = (await response.json()) as Decision;
    if (decision.verdict === "ALLOW") {
      return {};
    }
    return { block: true, reason: decision.reason ?? "denied by admit" };
  } catch (error) {
    // TODO: surface to Pi's log. Any error (network, JSON parse, timeout) -> block (fail-closed).
    return {
      block: true,
      reason: `admit unavailable: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
}

// TODO: export Pi extension entry point wiring handleToolCall into the tool_call handler.
