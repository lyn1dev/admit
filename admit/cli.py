"""`uv run admit ...` entry point. See docs/dev/plan.md."""

from __future__ import annotations

from pathlib import Path

import typer

app = typer.Typer(help="Admit: admission control for AI agents.", no_args_is_help=True)


def _todo(name: str) -> None:
    typer.echo(f"admit {name}: not implemented yet")
    raise typer.Exit(1)


@app.command()
def serve(
    policies: list[Path] = typer.Option([Path("policies/baseline.yaml")], "--policies", "-p"),
    mode: str = typer.Option("enforce", help="enforce | audit"),
    port: int = typer.Option(8765),
) -> None:
    """Run the MCP proxy on http://127.0.0.1:<port>/mcp."""
    _todo("serve")


@app.command()
def hook() -> None:
    """BeforeTool hook for built-in tools; reads JSON on stdin. Fail-closed (exit 2)."""
    _todo("hook")


@app.command()
def init(harness: str) -> None:
    """Route an agent harness (gemini, claude, ...) through Admit."""
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
def learn(approve: bool = typer.Option(False, "--approve")) -> None:
    """Policy Author: propose least-privilege policy from audit-mode logs."""
    _todo("learn")


@app.command()
def redteam(policies: Path = typer.Option(Path("policies/naive.yaml"))) -> None:
    """Red Team loop against a policy file."""
    _todo("redteam")


@app.command()
def demo(step: int) -> None:
    """Run one stage of the stage demo (0-4)."""
    _todo("demo")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
