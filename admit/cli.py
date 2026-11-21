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
) -> None:
    """Run the MCP proxy on http://127.0.0.1:<port>/mcp with the dashboard on /."""
    # Heavy imports stay inside the command so `admit --help` stays instant.
    import secrets

    import uvicorn

    from admit import audit as audit_mod
    from admit.audit import AuditLog
    from admit.config import load_config
    from admit.dashboard import DashboardApprovals, DashboardSink, routes
    from admit.decision import ConsoleSink, DecisionPoint, FanoutSink, NullAudit
    from admit.policy import load_policies
    from admit.proxy import build_gateway
    from admit.server import create_app
    from admit.types import Mode

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
    uvicorn.run(application, host="127.0.0.1", port=config.port, log_level="info")


@app.command()
def hook(
    harness: str = typer.Option("antigravity", "--harness", help="antigravity | gemini | claude"),
) -> None:
    """BeforeTool/PreToolUse hook: JSON on stdin, fail-closed (exit 2)."""
    _todo("hook")


@app.command()
def init(
    harness: str,
    print_only: bool = typer.Option(
        False, "--print", help="print the adapter snippet without writing anything"
    ),
) -> None:
    """Route a harness (antigravity | gemini | claude | pi | mcp) through Admit."""
    _todo("init")


@app.command()
def verify(log: Path = typer.Argument(None)) -> None:
    """Verify the audit hash chain and session signature."""
    _todo("verify")


@app.command()
def posture(settings: Path) -> None:
    """Scan an agent MCP config for risky settings."""
    _todo("posture")


@app.command()
def learn(
    approve: bool = typer.Option(False, "--approve", help="apply the proposed policy diff"),
) -> None:
    """Policy Author: propose least-privilege policy from audit-mode logs."""
    _todo("learn")


@app.command()
def redteam(
    policies: Path = typer.Option(Path("policies/naive.yaml"), help="policy file to attack"),
) -> None:
    """Red Team loop against a policy file (max ``MAX_ROUNDS`` rounds)."""
    _todo("redteam")


@app.command()
def demo(
    step: int,
    replay: bool = typer.Option(
        False, "--replay", help="serve cached agent responses instead of live model calls"
    ),
) -> None:
    """Run one stage of the stage demo (0-4)."""
    _todo("demo")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
