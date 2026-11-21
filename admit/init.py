"""``admit init``: detect installed coding-agent harnesses and route them through Admit.

For each chosen harness it writes the pre-tool hook config (``.gemini/settings.json``,
``.agents/hooks.json``, ``.claude/settings.json``), plus ``.admit/hook-token``,
``admit.yaml`` (audit mode by default), ``policies/baseline.yaml`` and a ``.gitignore``
entry. Existing JSON settings are merged (other keys kept, original backed up once to
``<file>.admit-backup``) and a second run changes nothing. Posture is printed before
and after.

The hook command uses the absolute path of the running interpreter, so it works
from any folder without a clone of the Admit repo.
"""

from __future__ import annotations

import copy
import json
import os
import secrets
import shlex
import shutil
import string
import subprocess
import sys
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from rich.console import Console, Group
from rich.text import Text

from admit import posture
from admit.data import config_template, packaged_policy

ORDER = ("antigravity", "gemini", "claude", "pi", "mcp")
LABELS = {
    "antigravity": "Antigravity CLI (agy)",
    "gemini": "Gemini CLI",
    "claude": "Claude Code",
    "pi": "Pi",
    "mcp": "Any MCP client (print snippet)",
}
ALIASES = {"agy": "antigravity", "gemini-cli": "gemini", "claude-code": "claude"}
HOOK_HARNESSES = ("antigravity", "gemini", "claude")  # wired with a pre-tool hook
SUPPORTED_HARNESSES: frozenset[str] = frozenset(ORDER)

DEFAULT_URL = "http://127.0.0.1:8765"
GEMINI_TIMEOUT_MS = 75_000  # above the 60 s WARN hold
HOOK_TIMEOUT_S = 75
VERSION_TIMEOUT_S = 3.0
SAMPLE_PROMPT = "List the files here and summarise README.md"


# --------------------------------------------------------------------------- detection


@dataclass
class Harness:
    key: str
    label: str
    installed: bool
    path: str | None = None
    version: str | None = None
    wired: bool = False

    @property
    def wirable(self) -> bool:
        return self.key in HOOK_HARNESSES or self.key == "mcp"


def _agy_path() -> str | None:
    found = shutil.which("agy")
    if found:
        return found
    local = os.environ.get("LOCALAPPDATA")
    if local:
        candidate = Path(local) / "agy" / "bin" / "agy.exe"
        if candidate.is_file():
            return str(candidate)
    return None


def _locate(key: str) -> tuple[bool, str | None]:
    """(installed, executable path or None)."""
    if key == "antigravity":
        path = _agy_path()
        return path is not None, path
    if key == "gemini":
        path = shutil.which("gemini")
        return path is not None, path
    if key in ("claude", "pi"):
        path = shutil.which(key)
        return (path is not None or (Path.home() / f".{key}").is_dir()), path
    return True, None  # mcp: any client


def _version(executable: str) -> str | None:
    """First line of ``<exe> --version``; never hangs (3 s timeout), never raises."""
    try:
        done = subprocess.run(
            [executable, "--version"],
            capture_output=True,
            text=True,
            timeout=VERSION_TIMEOUT_S,
            stdin=subprocess.DEVNULL,
            check=False,
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    lines = (done.stdout or done.stderr or "").strip().splitlines()
    return lines[0].strip()[:40] if lines else None


def _load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    text = path.read_text(encoding="utf-8-sig").strip()
    if not text:
        return {}
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a JSON object at the top level")
    return data


def is_wired(project: Path, key: str) -> bool:
    if key in HOOK_HARNESSES:
        try:
            data = _load_json(project / posture.HARNESS_FILES[key])
        except (OSError, ValueError):
            return False
        return bool(posture.admit_hooks(data, key))
    if key == "mcp":
        return (project / ".admit" / "hook-token").is_file() and (project / "admit.yaml").is_file()
    return False


def detect(project: Path, *, versions: bool = True) -> list[Harness]:
    """Every known harness with install state, version (cheap) and wiring state."""
    found = [Harness(key, LABELS[key], *_locate(key)) for key in ORDER]
    for harness in found:
        harness.wired = is_wired(project, harness.key)
    if versions:
        with ThreadPoolExecutor(max_workers=4) as pool:
            jobs = {h.key: pool.submit(_version, h.path) for h in found if h.path}
            for harness in found:
                if harness.key in jobs:
                    harness.version = jobs[harness.key].result()
    return found


def normalise(name: str) -> str:
    key = ALIASES.get(name.strip().lower(), name.strip().lower())
    if key not in SUPPORTED_HARNESSES:
        allowed = " | ".join(ORDER)
        raise ValueError(f"unknown harness {name!r} (expected {allowed})")
    return key


# --------------------------------------------------------------------------- hook config


def hook_command(harness: str, python: str | None = None, os_name: str | None = None) -> str:
    """Command line for the harness hook, quoted for the shell that harness uses.

    ``-I`` keeps the project folder off ``sys.path`` so an agent cannot shadow
    ``admit.hook`` with a file in the workspace. Gemini CLI runs hooks through
    PowerShell on Windows (needs ``&``), agy through ``cmd /c``, Claude Code through
    Git Bash (forward slashes); elsewhere they all use ``sh``.
    """
    python = python or sys.executable
    os_name = os_name or os.name
    tail = f"-I -m admit.hook {harness}"
    if os_name == "nt":
        if harness == "gemini":
            return f'& "{python}" {tail}'
        if harness == "claude":
            return f'"{python.replace(chr(92), "/")}" {tail}'
        return f'"{python}" {tail}'
    return f"{shlex.quote(python)} {tail}"


def _find_admit_entry(groups: list[Any]) -> dict[str, Any] | None:
    for group in groups:
        if not isinstance(group, dict):
            continue
        for entry in group.get("hooks") or []:
            if isinstance(entry, dict) and (
                entry.get("name") == "admit"
                or posture.is_admit_hook_command(str(entry.get("command", "")))
            ):
                return entry
    return None


def _merge_hook_list(
    data: dict[str, Any], event: str, matcher: str, entry: dict[str, Any]
) -> dict[str, Any]:
    data = copy.deepcopy(data)
    hooks = data.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError("'hooks' must be a JSON object")
    groups = hooks.setdefault(event, [])
    if not isinstance(groups, list):
        raise ValueError(f"'hooks.{event}' must be a JSON array")
    existing = _find_admit_entry(groups)
    if existing is not None:
        existing.update(entry)  # keeps extra keys such as "description"
    else:
        groups.append({"matcher": matcher, "hooks": [entry]})
    return data


def merge_hook_config(harness: str, data: dict[str, Any], command: str) -> dict[str, Any]:
    """Return ``data`` with the Admit hook added/updated; never drops other keys."""
    if harness == "gemini":
        entry = {"name": "admit", "type": "command", "command": command,
                 "timeout": GEMINI_TIMEOUT_MS}
        return _merge_hook_list(data, "BeforeTool", ".*", entry)
    if harness == "claude":
        entry = {"type": "command", "command": command, "timeout": HOOK_TIMEOUT_S}
        return _merge_hook_list(data, "PreToolUse", ".*", entry)
    if harness == "antigravity":
        data = copy.deepcopy(data)
        data["admit"] = {
            "enabled": True,
            "PreToolUse": [
                {
                    "matcher": "*",
                    "hooks": [{"type": "command", "command": command,
                               "timeout": HOOK_TIMEOUT_S}],
                }
            ],
        }
        return data
    raise ValueError(f"{harness} is not wired with a hook")


# --------------------------------------------------------------------------- plan


@dataclass
class FileChange:
    path: Path
    new_text: str
    old_text: str | None = None  # None = new file
    backup: bool = False  # back up the original to <file>.admit-backup (once)

    @property
    def action(self) -> str:
        return "create" if self.old_text is None else "update"


@dataclass
class InitPlan:
    project: Path
    harnesses: list[str]
    token: str
    changes: list[FileChange] = field(default_factory=list)
    hook_data: dict[str, dict[str, Any]] = field(default_factory=dict)


def _yq(value: str) -> str:
    """Single-quoted YAML scalar: no escapes, so Windows backslashes stay literal."""
    return "'" + value.replace("'", "''") + "'"


def _read(path: Path) -> str | None:
    return path.read_text(encoding="utf-8-sig") if path.is_file() else None


def _shell_upstream(python: str, project: Path) -> dict[str, Any]:
    return {"command": python, "args": ["-m", "admit.servers.shell", "--cwd", str(project)]}


def _admit_yaml_change(
    project: Path, token: str, *, enforce: bool, python: str, npx: bool
) -> FileChange | None:
    path = project / "admit.yaml"
    old = _read(path)
    if old is None:
        fs_block = ""
        if npx:
            fs_block = (
                "  fs:\n"
                "    command: npx\n"
                '    args: ["-y", "@modelcontextprotocol/server-filesystem", "."]\n'
                f"    cwd: {_yq(str(project))}\n"
            )
        text = string.Template(config_template()).substitute(
            mode="enforce" if enforce else "audit",
            token=_yq(token),
            python=_yq(python),
            project=_yq(str(project)),
            fs_block=fs_block,
        )
        return FileChange(path, text)
    raw = yaml.safe_load(old) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"{path} must contain a YAML mapping")
    new = copy.deepcopy(raw)
    callers = new.get("callers")
    if not isinstance(callers, dict):
        callers = new["callers"] = {}
    if callers.get(token) != "coding-agent":
        callers[token] = "coding-agent"
    upstreams = new.get("upstreams")
    if not isinstance(upstreams, dict):
        upstreams = new["upstreams"] = {}
    upstreams.setdefault("shell", _shell_upstream(python, project))
    if enforce:
        new["mode"] = "enforce"
    if new == raw:
        return None
    return FileChange(path, yaml.safe_dump(new, sort_keys=False), old, backup=True)


def plan_init(
    project: Path,
    harnesses: Iterable[str],
    *,
    enforce: bool = False,
    python: str | None = None,
    npx: bool | None = None,
    os_name: str | None = None,
    token: str | None = None,
) -> InitPlan:
    """Compute every file change ``admit init`` would make (nothing is written)."""
    project = project.resolve()
    python = python or sys.executable
    npx = shutil.which("npx") is not None if npx is None else npx
    chosen = [normalise(h) for h in harnesses]

    token_path = project / ".admit" / "hook-token"
    existing_token = (_read(token_path) or "").strip()
    token = existing_token or token or secrets.token_urlsafe(24)
    plan = InitPlan(project, chosen, token)

    for harness in chosen:
        if harness not in HOOK_HARNESSES:
            continue
        path = project / posture.HARNESS_FILES[harness]
        old_text = _read(path)
        old = _load_json(path)
        new = merge_hook_config(harness, old, hook_command(harness, python, os_name))
        plan.hook_data[harness] = new
        if new != old or old_text is None:
            plan.changes.append(
                FileChange(path, json.dumps(new, indent=2) + "\n", old_text,
                           backup=old_text is not None)
            )

    if not any(h in HOOK_HARNESSES or h == "mcp" for h in chosen):
        return plan  # e.g. only Pi: nothing to wire yet

    if not existing_token:
        plan.changes.append(FileChange(token_path, token + "\n"))
    change = _admit_yaml_change(project, token, enforce=enforce, python=python, npx=npx)
    if change is not None:
        plan.changes.append(change)
    if not (project / "policies").exists():
        baseline = packaged_policy("baseline.yaml").read_text(encoding="utf-8")
        plan.changes.append(FileChange(project / "policies" / "baseline.yaml", baseline))
    gitignore = project / ".gitignore"
    old_ignore = _read(gitignore)
    lines = {line.strip() for line in (old_ignore or "").splitlines()}
    if not lines & {".admit", ".admit/", "/.admit", "/.admit/"}:
        prefix = old_ignore or ""
        if prefix and not prefix.endswith("\n"):
            prefix += "\n"
        plan.changes.append(FileChange(gitignore, prefix + ".admit/\n", old_ignore))
    return plan


def apply_plan(plan: InitPlan) -> None:
    for change in plan.changes:
        change.path.parent.mkdir(parents=True, exist_ok=True)
        if change.backup and change.old_text is not None:
            backup = change.path.with_name(change.path.name + ".admit-backup")
            if not backup.exists():
                backup.write_bytes(change.old_text.encode("utf-8"))
        change.path.write_bytes(change.new_text.encode("utf-8"))


# --------------------------------------------------------------------------- picker


def _read_key() -> str:
    """One key press: up | down | space | enter | esc | q | '' (other)."""
    if os.name == "nt":
        import msvcrt

        ch = msvcrt.getwch()
        if ch in ("\x00", "\xe0"):
            return {"H": "up", "P": "down"}.get(msvcrt.getwch(), "")
    else:
        import select
        import termios
        import tty

        fd = sys.stdin.fileno()
        saved = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = os.read(fd, 1).decode(errors="ignore")
            if ch == "\x1b" and select.select([fd], [], [], 0.05)[0]:
                seq = os.read(fd, 2).decode(errors="ignore")
                return {"[A": "up", "OA": "up", "[B": "down", "OB": "down"}.get(seq, "")
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, saved)
    if ch == "\x03":
        raise KeyboardInterrupt
    return {
        "\r": "enter", "\n": "enter", " ": "space", "\x1b": "esc", "q": "q", "Q": "q",
        "k": "up", "j": "down",
    }.get(ch, "")


def _status(h: Harness) -> Text:
    if not h.installed:
        return Text("not installed", style="dim")
    parts = []
    if h.version:
        parts.append(h.version)
    if h.key == "pi":
        parts.append("hook coming soon")
    text = Text("  ".join(parts), style="dim")
    if h.wired:
        text.append("  already wired", style="green")
    return text


def render_picker(harnesses: list[Harness], cursor: int, selected: set[str]) -> Group:
    lines = [
        Text("Route which coding agents through Admit?", style="bold"),
        Text("up/down: move   space: toggle   enter: confirm   q/esc: cancel", style="dim"),
        Text(""),
    ]
    for index, h in enumerate(harnesses):
        line = Text("> " if index == cursor else "  ", style="bold cyan")
        box = "[x]" if h.key in selected else "[ ]"
        style = "dim" if not h.installed else ("bold" if index == cursor else "")
        line.append(f"{box} {h.label:<32}", style=style)
        line.append_text(_status(h))
        lines.append(line)
    return Group(*lines)


def default_selection(harnesses: list[Harness]) -> list[str]:
    chosen = [h.key for h in harnesses if h.installed and h.key in HOOK_HARNESSES]
    return chosen or ["mcp"]


def pick(
    harnesses: list[Harness], console: Console, read_key: Callable[[], str] = _read_key
) -> list[str] | None:
    """Interactive multi-select; ``None`` when cancelled."""
    from rich.live import Live

    selected = set(default_selection(harnesses)) - {"mcp"}
    cursor = 0
    with Live(render_picker(harnesses, cursor, selected), console=console,
              auto_refresh=False, transient=False) as live:
        while True:
            key = read_key()
            if key == "up":
                cursor = (cursor - 1) % len(harnesses)
            elif key == "down":
                cursor = (cursor + 1) % len(harnesses)
            elif key == "space":
                h = harnesses[cursor]
                if h.installed:
                    selected ^= {h.key}
            elif key == "enter":
                return [h.key for h in harnesses if h.key in selected]
            elif key in ("esc", "q"):
                return None
            live.update(render_picker(harnesses, cursor, selected), refresh=True)


# --------------------------------------------------------------------------- output


def mcp_snippet(token: str, url: str = DEFAULT_URL) -> str:
    return json.dumps(
        {"mcpServers": {"admit": {"type": "http", "url": f"{url}/mcp",
                                  "headers": {"Authorization": f"Bearer {token}"}}}},
        indent=2,
    )


def admit_invocation() -> str:
    """How the user should call admit from their shell afterwards."""
    found = shutil.which("admit")
    if found and Path(found).parent != Path(sys.executable).parent:
        return "admit"
    if "archive-v" in sys.executable:  # running from a uvx cache
        return "uvx --from git+https://github.com/lyn1dev/admit admit"
    return f'"{sys.executable}" -m admit.cli' if " " in sys.executable else (
        f"{sys.executable} -m admit.cli"
    )


def harness_command(key: str, os_name: str | None = None) -> str | None:
    os_name = os_name or os.name
    prompt = f'"{SAMPLE_PROMPT}"'
    if key == "gemini":
        if os_name == "nt":
            return f'$env:GEMINI_CLI_TRUST_WORKSPACE = "true"; gemini -p {prompt} --yolo'
        return f"GEMINI_CLI_TRUST_WORKSPACE=true gemini -p {prompt} --yolo"
    if key == "antigravity":
        return f"agy -p {prompt}"
    if key == "claude":
        return f"claude -p {prompt}"
    return None


def _print_posture(console: Console, title: str, findings: list[posture.Finding]) -> None:
    value = posture.score(findings)
    colour = "green" if value >= 90 else "yellow" if value >= 60 else "red"
    console.print(f"[bold]{title}[/]: [{colour}]{value}/100[/]")
    for f in findings:
        sev = {"high": "red", "med": "yellow", "low": "cyan"}.get(f.severity, "white")
        console.print(f"  [{sev}]{f.severity.upper():<4}[/] {f.detail}", highlight=False)


def _posture_for(plan_or_project: Path, harnesses: list[str],
                 data: dict[str, dict[str, Any]] | None = None) -> list[posture.Finding]:
    findings: list[posture.Finding] = []
    for h in harnesses:
        if h in HOOK_HARNESSES:
            findings.extend(posture.scan_harness(plan_or_project, h, (data or {}).get(h)))
    return findings


def run_init(
    project: Path,
    harnesses: list[str] | None = None,
    *,
    yes: bool = False,
    enforce: bool = False,
    dry_run: bool = False,
    print_only: bool = False,
    console: Console | None = None,
    interactive: bool | None = None,
) -> int:
    """The ``admit init`` command. Returns the process exit code."""
    console = console or Console(highlight=False)
    project = Path(project).resolve()
    # In the home folder, .gemini/.claude/.agents settings ARE the global harness
    # config: wiring them would route every session on the machine through Admit.
    if not print_only and (project == Path.home().resolve() or project == Path(project.anchor)):
        console.print(
            f"[red]Refusing to set up {project}:[/] that is your home folder or a drive root, "
            "where harness settings are global.\n"
            "Make a project folder first, e.g.  [bold]mkdir admit-demo && cd admit-demo[/]"
        )
        return 2
    try:
        chosen = [normalise(h) for h in harnesses or []]
    except ValueError as exc:
        console.print(f"[red]{exc}[/]")
        return 2

    if print_only:
        token = (_read(project / ".admit" / "hook-token") or "").strip()
        console.print(mcp_snippet(token or "<token from .admit/hook-token>"), highlight=False)
        for h in chosen:
            if h in HOOK_HARNESSES:
                rel = posture.HARNESS_FILES[h]
                snippet = merge_hook_config(h, {}, hook_command(h))
                console.print(f"\n# {rel}\n" + json.dumps(snippet, indent=2), highlight=False)
        return 0

    found = detect(project)
    if not chosen:
        if interactive is None:
            interactive = sys.stdin.isatty() and sys.stdout.isatty()
        if interactive and not yes:
            try:
                picked = pick(found, console)
            except KeyboardInterrupt:
                picked = None
            if picked is None:
                console.print("cancelled, nothing changed")
                return 1
            if not picked:
                console.print("nothing selected, nothing changed")
                return 1
            chosen = picked
        else:
            chosen = default_selection(found)
            console.print("harnesses: " + ", ".join(LABELS[h] for h in chosen))

    info = {h.key: h for h in found}
    for h in chosen:
        if h in HOOK_HARNESSES and not info[h].installed:
            console.print(f"[yellow]note:[/] {LABELS[h]} not detected; wiring it anyway")

    before = _posture_for(project, chosen)
    try:
        plan = plan_init(project, chosen, enforce=enforce)
    except (OSError, ValueError) as exc:
        console.print(f"[red]cannot plan changes: {exc}[/]")
        return 1

    console.print(f"\nAdmit init in [bold]{project}[/]" + ("  (dry run)" if dry_run else ""))
    _print_posture(console, "Posture before", before)
    console.print()
    if not plan.changes:
        console.print("[green]already set up: nothing to change[/]")
    for change in plan.changes:
        rel = change.path.relative_to(project)
        verb = ("would " if dry_run else "") + change.action
        note = "  (backup: .admit-backup)" if change.backup and not dry_run else ""
        console.print(f"  {verb:<14} {rel}{note}")
        if dry_run and change.path.suffix == ".json":
            console.print(Text(change.new_text, style="dim"))
    if not dry_run:
        apply_plan(plan)
    console.print()
    after = _posture_for(project, chosen, plan.hook_data)
    _print_posture(console, "Posture after" + (" (projected)" if dry_run else ""), after)

    if "pi" in chosen:
        console.print("\n[yellow]Pi:[/] the Admit extension is coming soon; use the MCP snippet.")
    if "mcp" in chosen or "pi" in chosen:
        console.print("\nMCP client config (keep the token private):")
        console.print(mcp_snippet(plan.token), highlight=False)
    if dry_run:
        console.print("\n[dim]dry run: nothing was written[/]")
        return 0

    admit = admit_invocation()
    console.print("\n[bold]Next:[/]")
    console.print(f"  1. {admit} serve", highlight=False, soft_wrap=True)
    console.print("     keep it running, open the dashboard link it prints")
    step_cmds = [c for c in (harness_command(h) for h in chosen) if c]
    if step_cmds:
        console.print("  2. in another terminal, in this folder:")
        for cmd in step_cmds:
            console.print(f"     {cmd}", highlight=False, markup=False, soft_wrap=True)
    console.print(f"  3. {admit} verify", highlight=False, soft_wrap=True)
    mode = "enforce" if enforce else "audit"
    console.print(f"[dim]mode: {mode} (edit admit.yaml or re-run with --enforce)[/]")
    return 0


def init_harness(harness: str, workspace: Path, print_only: bool = False) -> None:
    """Non-interactive wrapper: wire one ``harness`` into Admit at ``workspace``."""
    code = run_init(workspace, [harness], yes=True, print_only=print_only, interactive=False)
    if code:
        raise RuntimeError(f"admit init {harness} failed (exit {code})")
