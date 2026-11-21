"""``uv run admit ...`` entry point. See docs/dev/plan.md."""

from __future__ import annotations

from pathlib import Path

import typer

app = typer.Typer(help="Admit: admission control for AI agents.", no_args_is_help=True)


def _todo(name: str) -> None:
    typer.echo(f"admit {name}: not implemented yet")
    raise typer.Exit(1)


@app.command()
def serve(
    config_path: Path = typer.Option(
        Path("admit.yaml"), "--config", "-c", help="path to admit.yaml"
    ),
    policies: list[Path] | None = typer.Option(
        None, "--policies", "-p", help="override admit.yaml policies"
    ),
    mode: str | None = typer.Option(None, help="enforce | audit (overrides admit.yaml)"),
    port: int | None = typer.Option(None, help="override admit.yaml port"),
    pin: bool = typer.Option(False, "--pin", help="record/re-approve tool pins (.admit/pins.json)"),
    open_browser: bool = typer.Option(False, "--open", help="open the dashboard in the browser"),
) -> None:
    """Run the MCP proxy on http://127.0.0.1:<port>/mcp with the dashboard on /."""
    # Heavy imports stay inside the command so `admit --help` stays instant.
    import secrets

    import uvicorn

    from admit import audit as audit_mod
    from admit.audit import AuditLog
    from admit.config import load_config
    from admit.dashboard import DashboardApprovals, DashboardSink, routes
    from admit.data import resolve_policies
    from admit.decision import ConsoleSink, DecisionPoint, FanoutSink, NullAudit
    from admit.observations import ObservationLog
    from admit.policy import load_policies
    from admit.proxy import build_gateway
    from admit.server import create_app
    from admit.types import Mode

    if not Path(config_path).is_file():
        typer.secho(
            f"no {config_path} in {Path.cwd()}: run `admit init` here first",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(1)
    try:
        config = load_config(config_path)
    except ValueError as exc:
        typer.secho(f"config error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1) from None

    if mode is not None:
        try:
            config.mode = Mode(mode)
        except ValueError:
            allowed = " | ".join(m.value for m in Mode)
            typer.secho(
                f"unknown mode {mode!r} (expected {allowed})",
                fg=typer.colors.RED,
                err=True,
            )
            raise typer.Exit(1) from None
    if port is not None:
        config.port = port
    if policies:
        config.policies = list(policies)
    # policies/<name>.yaml missing in this folder -> the copy bundled with Admit.
    config.policies = resolve_policies(config.policies)

    try:
        loaded_policies = load_policies(config.policies)
    except NotImplementedError:
        typer.secho(
            "warning: policy engine not implemented yet — every call will be DENIED",
            fg=typer.colors.YELLOW,
            bold=True,
            err=True,
        )
        loaded_policies = []
    except Exception as exc:  # noqa: BLE001 - a bad policy set is fail-closed at startup
        typer.secho(f"policy load failed: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1) from None

    try:
        audit: object = AuditLog()
    except NotImplementedError:
        typer.secho(
            "warning: audit log not implemented yet — decisions are not being recorded",
            fg=typer.colors.YELLOW,
            bold=True,
            err=True,
        )
        audit = NullAudit()

    dashboard_sink = DashboardSink()
    approvals = DashboardApprovals(dashboard_sink)
    dashboard_key = secrets.token_urlsafe(24)
    decision_point = DecisionPoint(
        config,
        loaded_policies,
        audit,
        FanoutSink(ConsoleSink(), dashboard_sink),
        workspace=Path.cwd(),
        approvals=approvals,
        observer=ObservationLog.for_mode(config.mode),
    )
    log_path = getattr(audit, "path", None)
    dashboard_routes = routes(
        dashboard_sink,
        approvals,
        dashboard_key=dashboard_key,
        verify_fn=(lambda: audit_mod.verify(log_path)) if log_path else None,
    )
    gateway = build_gateway(
        config, decision_point, pins_path=Path(".admit/pins.json"), pin=pin
    )
    application = create_app(config, decision_point, gateway, extra_routes=dashboard_routes)

    typer.echo(
        f"admit serve: MCP gateway on http://127.0.0.1:{config.port}/mcp "
        f"(mode {config.mode.value})"
    )
    typer.secho(
        f"dashboard (keep this link private): "
        f"http://127.0.0.1:{config.port}/?key={dashboard_key}",
        fg=typer.colors.CYAN,
        bold=True,
    )
    if open_browser:
        import threading
        import webbrowser

        url = f"http://127.0.0.1:{config.port}/?key={dashboard_key}"
        threading.Timer(1.5, webbrowser.open, args=(url,)).start()
    uvicorn.run(application, host="127.0.0.1", port=config.port, log_level="info")


@app.command()
def run(
    config_path: Path = typer.Option(
        Path("admit.yaml"), "--config", "-c", help="path to admit.yaml"
    ),
    audit: bool = typer.Option(False, "--audit", help="first-time setup in audit mode"),
    no_open: bool = typer.Option(False, "--no-open", help="don't open the dashboard"),
) -> None:
    """Set up this folder if needed (harness picker), then start Admit and open the dashboard."""
    from rich.console import Console
    from rich.panel import Panel

    console = Console()
    console.print(
        Panel.fit(
            "[bold]Admit[/] - every tool call your coding agent makes is checked first.\n"
            "[dim]deterministic CEL policies - fail-closed - signed audit log[/]",
            border_style="green",
        )
    )
    if not config_path.exists():
        from admit.init import run_init

        console.print("[bold]No admit.yaml here yet - let's set this folder up.[/]\n")
        code = run_init(
            Path("."), [], yes=False, enforce=not audit, dry_run=False, print_only=False
        )
        if code:
            raise typer.Exit(code)
        console.print()
    serve(
        config_path=config_path,
        policies=None,
        mode=None,
        port=None,
        pin=False,
        open_browser=not no_open,
    )


@app.command()
def hook(
    harness: str = typer.Option("antigravity", "--harness", help="antigravity | gemini | claude"),
) -> None:
    """BeforeTool/PreToolUse hook: JSON on stdin, fail-closed (exit 2)."""
    from admit.hook import main as hook_main

    raise typer.Exit(hook_main(harness))


@app.command()
def init(
    harness: list[str] | None = typer.Argument(
        None, help="antigravity | gemini | claude | pi | mcp (default: interactive picker)"
    ),
    harness_opt: list[str] | None = typer.Option(
        None, "--harness", help="harness to wire (repeatable); skips the picker"
    ),
    yes: bool = typer.Option(
        False, "--yes", "-y", help="no picker: wire every installed harness"
    ),
    enforce: bool = typer.Option(False, "--enforce", help="start in enforce mode (default audit)"),
    print_only: bool = typer.Option(
        False, "--print", help="print the MCP snippet without writing anything"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="show what would change"),
    project: Path = typer.Option(Path("."), "--dir", help="project folder (default: cwd)"),
) -> None:
    """Detect installed coding agents and route them through Admit."""
    from admit.init import run_init

    raise typer.Exit(
        run_init(
            project,
            [*(harness or []), *(harness_opt or [])],
            yes=yes,
            enforce=enforce,
            dry_run=dry_run,
            print_only=print_only,
        )
    )


@app.command()
def verify(
    log: Path = typer.Argument(None, help="path to a .jsonl audit log (default: newest)"),
) -> None:
    """Verify the audit hash chain and session signature."""
    from admit.audit import latest_log
    from admit.audit import verify as verify_log

    target = Path(log) if log else latest_log()
    if target is None:
        typer.secho("no audit log found in .admit/audit", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)
    ok, message = verify_log(Path(target))
    if ok:
        typer.secho(message, fg=typer.colors.GREEN)
        return
    typer.secho(message, fg=typer.colors.RED, err=True)
    raise typer.Exit(1)


@app.command()
def posture(
    settings: Path = typer.Argument(Path("."), help="agent config file or project folder"),
) -> None:
    """Scan an agent MCP config (or a project folder) for risky settings."""
    from admit.posture import scan, score

    try:
        findings = scan(settings)
    except (OSError, ValueError) as exc:
        typer.secho(f"cannot scan {settings}: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1) from None
    colours = {"high": typer.colors.RED, "med": typer.colors.YELLOW, "low": typer.colors.CYAN}
    for finding in findings:
        typer.secho(
            f"{finding.severity.upper():<4} {finding.check:<20} {finding.detail}",
            fg=colours.get(finding.severity),
        )
    value = score(findings)
    typer.secho(f"score: {value}/100", bold=True)


@app.command()
def learn(
    observations: Path = typer.Option(
        Path(".admit/observations"), "--observations", help="audit-mode observations directory"
    ),
    replay: bool = typer.Option(False, "--replay", help="serve cached LLM responses only"),
    approve: bool = typer.Option(
        False, "--approve", help="copy the latest proposal to policies/learned.yaml"
    ),
) -> None:
    """Policy Author: propose least-privilege policy from audit-mode observations."""
    from admit.agents import commands

    raise typer.Exit(commands.learn(observations, replay, approve))


@app.command()
def redteam(
    policies: Path = typer.Option(Path("policies/naive.yaml"), help="policy file to attack"),
    rounds: int = typer.Option(3, "--rounds", min=1, max=3, help="max attack/patch rounds"),
    replay: bool = typer.Option(False, "--replay", help="serve cached LLM responses only"),
    approve: bool = typer.Option(
        False, "--approve", help="copy the latest proposal to policies/hardened.yaml"
    ),
) -> None:
    """Red Team loop against a policy file (max 3 rounds), then a patched proposal."""
    from admit.agents import commands

    raise typer.Exit(commands.redteam(policies, rounds, replay, approve))


@app.command()
def demo(
    step: str = typer.Argument(..., help="0 | 1 | 2 | 3 | 4 | warn | all"),
    replay: bool = typer.Option(
        False, "--replay", help="beat 1: send the recorded model run instead of a live model"
    ),
    model: str | None = typer.Option(
        None, "--model", "-m", help="beat 1: Gemini model (default gemini-3.5-flash-lite)"
    ),
) -> None:
    """Run one beat of the stage demo: 0 preflight, 1 attack, 2 learn, 3 red team,
    4 tamper, warn (human approval), all. Run sheet: docs/dev/demo-script.md."""
    from admit.demo import run

    raise typer.Exit(run(step, replay=replay, model=model))


def main() -> None:
    app()


if __name__ == "__main__":
    main()
