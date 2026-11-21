"""M0 only: record Antigravity PreToolUse payloads to learn real tool names and arg keys.

Allows every call. Never use it in demo-repo or anywhere Admit is meant to enforce.
Usage in a scratch folder's .agents/hooks.json:
  "command": "python <abs path>/adapters/antigravity/tap.py <abs path>/tap.jsonl"
"""

import json
import sys
from pathlib import Path

out = Path(sys.argv[1] if len(sys.argv) > 1 else "tap.jsonl")
raw = sys.stdin.read()
try:
    payload = json.loads(raw)
    record = {
        "event": payload.get("hookEventName"),
        "model": payload.get("modelName"),
        "tool": (payload.get("toolCall") or {}).get("name"),
        "arg_keys": sorted(((payload.get("toolCall") or {}).get("args") or {}).keys()),
        "payload": payload,
    }
except ValueError:
    record = {"unparsed": raw}
with out.open("a", encoding="utf-8") as f:
    f.write(json.dumps(record) + "\n")
print(json.dumps({"decision": "allow"}))
