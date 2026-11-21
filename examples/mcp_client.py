"""Drive Admit's MCP gateway (/mcp) like an agent would, one call per verdict.

Run while `uv run admit serve` is up, then watch the dashboard:

    uv run python examples/mcp_client.py            # all steps, incl. one held for a human
    uv run python examples/mcp_client.py --no-warn  # skip the Approve/Deny step

Every call goes agent -> Admit (/mcp, bearer token) -> policy -> upstream MCP server.
No model is involved, so the result is the same every run.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import time

from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

STEPS = [
    ("Run the tests", "shell_run", {"command": "python -m pytest -q"}),
    ("Run the poisoned setup script", "shell_run", {"command": "python scripts/bootstrap.py"}),
    ("Read the README", "fs_read_text_file", {"path": "README.md"}),
    ("Read .env (self-protection)", "fs_read_text_file", {"path": ".env"}),
    ("Read outside the workspace", "fs_read_text_file", {"path": "../admit.yaml"}),
    ("Overwrite the hook config", "fs_write_file", {"path": ".agents/hooks.json", "content": "{}"}),
    ("Read a file with a token in it", "fs_read_text_file", {"path": "sample-risky-settings.json"}),
]
WARN_STEP = ("Install an extra package (held for you)", "shell_run",
             {"command": "pip install requests"})


def _summary(result) -> tuple[str, str]:
    data = result.structured_content or {}
    admit = data.get("admit") if isinstance(data, dict) else None
    if result.is_error:
        if isinstance(admit, dict):
            return "BLOCKED", f"{admit.get('reason')} (policy {admit.get('policy')})"
        text = " ".join(getattr(c, "text", "") for c in result.content)
        return "ERROR", text[:160]
    text = " ".join(getattr(c, "text", "") for c in result.content).replace("\n", " ")
    meta = getattr(result, "meta", None) or {}
    redacted = (meta.get("admit") or {}).get("redacted")
    note = f" [admit redacted {redacted} secret(s)]" if redacted else ""
    return "ALLOWED", text[:120] + note


async def main(url: str, token: str, warn: bool) -> None:
    transport = StreamableHttpTransport(url, headers={"Authorization": f"Bearer {token}"})
    async with Client(transport, timeout=120) as client:
        tools = [t.name for t in await client.list_tools()]
        print(f"Connected to {url}: {len(tools)} tools through Admit "
              f"({', '.join(t for t in tools if t.startswith('shell'))}, fs_* ...)\n")
        steps = STEPS + ([WARN_STEP] if warn else [])
        for title, tool, args in steps:
            if (title, tool, args) == WARN_STEP:
                print(">>> Now click Approve or Deny on the dashboard (60 s timeout) ...")
            started = time.monotonic()
            try:
                result = await client.call_tool(tool, args, raise_on_error=False)
                verdict, detail = _summary(result)
            except Exception as exc:  # noqa: BLE001 - show it, keep going
                verdict, detail = "ERROR", f"{type(exc).__name__}: {exc}"
            secs = time.monotonic() - started
            print(f"{verdict:8} {title}: {tool} {json.dumps(args)[:70]}  ({secs:.1f}s)")
            print(f"         {detail}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", default="http://127.0.0.1:8765/mcp")
    parser.add_argument("--token", default="dev-token-coding-agent")
    parser.add_argument("--no-warn", action="store_true", help="skip the human-approval step")
    a = parser.parse_args()
    asyncio.run(main(a.url, a.token, warn=not a.no_warn))
