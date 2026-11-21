// Pi extension: send every tool_call (with ctx.model) to Admit POST /check.
// Fail-closed: block on anything but an explicit ALLOW, including errors and timeouts.
