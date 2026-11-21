"""Bodies of ``admit redteam`` and ``admit learn`` (``admit.cli`` stays a thin shell).

Both return a process exit code. Neither prints secrets: prompts and outputs only
contain policy text, commands and paths.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.syntax import Syntax

from admit.agents import author, llm


def _show_diff(console: Console, diff: str) -> None:
    if diff.strip():
        console.print(Syntax(diff, "diff", theme="ansi_dark", word_wrap=True))
    else:
        console.print("[dim](no changes)[/]")


def _approve(console: Console, prefix: str, target: Path) -> int:
    proposal = author.latest_proposal(prefix)
    if proposal is None:
        cmd = "admit redteam" if prefix == "redteam" else "admit learn"
        console.print(
            f"[red]no {prefix} proposal in {author.PROPOSALS_DIR.as_posix()}[/]: "
            f"run [bold]uv run {cmd}[/] first"
        )
        return 1
    diff_path = proposal.with_suffix(".diff")
    if diff_path.is_file():
        _show_diff(console, diff_path.read_text(encoding="utf-8"))
    try:
        written = author.approve_proposal(proposal, target)
    except ValueError as exc:
        console.print(f"[red]{escape(str(exc))}[/]")
        return 1
    console.print(f"[bold green]approved:[/] {proposal.as_posix()} → [bold]{written.as_posix()}[/]")
    console.print(f"[dim]enforce it with: uv run admit serve --policies {written.as_posix()}[/]")
    return 0


def redteam(policies: Path, rounds: int, replay: bool, approve: bool) -> int:
    from admit.agents.redteam import HARDENED_PATH, run_redteam

    console = Console()
    if approve:
        return _approve(console, "redteam", HARDENED_PATH)
    if not policies.is_file():
        console.print(f"[red]policy file not found: {policies}[/]")
        return 1
    mode = "replaying recorded responses" if replay else "live"
    console.print(
        f"[bold]Admit Red Team[/] — an ADK agent loop: Red Team agent attacks "
        f"[bold]{policies.as_posix()}[/], Policy Author patches, re-run "
        f"[dim](max {rounds} rounds, {llm.model_for('redteam')}, {mode})[/]"
    )
    try:
        report = run_redteam(policies, rounds, replay=replay, console=console)
    except (llm.CacheMiss, llm.LlmUnavailable, ValueError) as exc:
        console.print(f"[bold red]red team stopped:[/] {escape(str(exc))}")
        return 1
    if report.diff:
        console.rule("[bold]Proposed diff")
        _show_diff(console, report.diff)
    return 0 if report.still_open == 0 and report.legit_ok else 1


def learn(observations: Path, replay: bool, approve: bool) -> int:
    console = Console()
    if approve:
        return _approve(console, "learned", author.LEARNED_PATH)
    console.print(
        f"[bold]Admit Policy Author[/] — learning a least-privilege policy from "
        f"[bold]{observations.as_posix()}[/] "
        f"[dim]({llm.model_for('author')}, {'replay' if replay else 'live'})[/]"
    )
    try:
        with console.status("Policy Author is writing the policy...", spinner="dots"):
            draft = asyncio.run(author.propose_policy_async(observations, replay=replay))
    except author.NoObservations:
        console.print(
            f"[yellow]no observations in {observations.as_posix()}[/]. Create some first:\n"
            "  1. [bold]uv run admit serve --mode audit[/]   (records every call, allows all)\n"
            "  2. run your agent, or [bold]uv run python examples/mcp_client.py --no-warn[/]\n"
            "  3. stop the server, then [bold]uv run admit learn[/]"
        )
        return 1
    except (llm.CacheMiss, llm.LlmUnavailable) as exc:
        console.print(f"[bold red]learn stopped:[/] {escape(str(exc))}")
        return 1
    facts = draft.facts
    if facts is not None:
        console.print(
            f"observed [bold]{facts.observations}[/] calls → "
            f"{len(facts.allowed)} routine, {len(facts.suspicious)} suspicious "
            f"(kept out of the policy)"
        )
        console.print(f"  commands: {escape(', '.join(facts.commands) or '-')}")
        console.print(f"  reads (trie-compressed): {escape(', '.join(facts.read_globs) or '-')}")
        for request, why in facts.suspicious:
            console.print(f"  [red]✗[/] {escape(author.describe(request))} [dim]— {why}[/]")
    for change in draft.changes:
        console.print(f"  [cyan]•[/] {escape(change)}")
    if draft.errors:
        console.print("[bold red]proposal rejected by the validator:[/]")
        for error in draft.errors[:8]:
            console.print(f"  [red]- {escape(error)}[/]")
        return 1
    console.print(
        "[green]validated:[/] YAML parses, CEL compiles, every routine call ALLOWED, "
        ".env read + bootstrap.py DENIED, Gherkin scenario passes"
    )
    console.rule("[bold]Proposed diff vs policies/baseline.yaml")
    _show_diff(console, draft.diff)
    console.print(f"Proposal: [bold]{draft.path.as_posix() if draft.path else '-'}[/]")
    console.print(f"Scenario: {draft.feature_path.as_posix() if draft.feature_path else '-'}")
    console.print("Human approval: [bold]uv run admit learn --approve[/]")
    return 0
