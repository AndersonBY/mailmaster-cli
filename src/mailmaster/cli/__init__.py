from __future__ import annotations

from dataclasses import asdict, is_dataclass
import json
from pathlib import Path
from typing import Any, Callable

import click
import typer

app = typer.Typer(help="MailMaster CLI for local data access and dynamic SMTP sending.")


@app.callback()
def app_callback(
    ctx: typer.Context,
    format: str = typer.Option("text", "--format", help="Output format: text or json."),
) -> None:
    fmt = format.lower().strip()
    if fmt not in {"text", "json"}:
        raise typer.BadParameter("--format must be one of: text, json")
    ctx.obj = {"output_format": fmt}


def _use_json_output() -> bool:
    ctx = click.get_current_context(silent=True)
    return bool(ctx and isinstance(ctx.obj, dict) and ctx.obj.get("output_format") == "json")


def _serialize(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if is_dataclass(value):
        return _serialize(asdict(value))
    if isinstance(value, dict):
        return {str(k): _serialize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_serialize(v) for v in value]
    return value


def _emit(command: str, data: Any, text_renderer: Callable[[], None] | None = None) -> None:
    payload = {"ok": True, "command": command, "data": _serialize(data)}
    if _use_json_output():
        typer.echo(json.dumps(payload, ensure_ascii=False, indent=2))
        return
    if text_renderer is not None:
        text_renderer()
        return
    typer.echo(str(payload["data"]))


def main() -> None:
    app()


from . import commands as _commands  # noqa: E402,F401

__all__ = ["app", "main"]
