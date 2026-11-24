from __future__ import annotations

from collections.abc import Mapping, Sequence
from contextvars import ContextVar
from dataclasses import asdict, is_dataclass
import json
import os
from pathlib import Path
import sys
from typing import Any, Callable, NoReturn

import click
import typer
import typer.core

_output_format_var: ContextVar[str] = ContextVar("output_format", default="text")


def _option_nargs_map(command: click.Command | None) -> dict[str, int]:
    """Return a map of value-taking option flags to their argument count for a Click command."""
    if command is None:
        return {}
    mapping: dict[str, int] = {}
    for param in command.params:
        if isinstance(param, click.Option) and not param.is_flag and param.nargs > 0:
            for opt in (*param.opts, *param.secondary_opts):
                mapping[opt] = param.nargs
    return mapping


def _normalize_cli_args(
    args: Sequence[str],
    commands: Mapping[str, click.Command],
) -> tuple[list[str], str, str | None]:
    """Hoist ``--json`` and ``--format`` anywhere in ``args`` to root level.

    Returns ``(normalized_args, requested_format, subcommand)``.
    Tokens after ``--`` or consumed as values of a subcommand option are left untouched.
    """
    hoisted: list[str] = []
    rest: list[str] = []
    fmt = "text"
    saw_json = False
    subcommand: str | None = None
    value_opts: dict[str, int] = {}
    index = 0
    total = len(args)

    while index < total:
        token = args[index]
        if token == "--":
            rest.extend(args[index:])
            break

        if token == "--json":
            hoisted.append(token)
            saw_json = True
            index += 1
            continue

        if token == "--format":
            if index + 1 < total:
                val = args[index + 1]
                hoisted.extend([token, val])
                fmt = val.strip().lower()
                index += 2
            elif not rest:
                hoisted.append(token)
                index += 1
            else:
                hoisted.extend([token, ""])
                fmt = ""
                index += 1
            continue

        if token.startswith("--format="):
            hoisted.append(token)
            fmt = token.split("=", 1)[1].strip().lower()
            index += 1
            continue

        if subcommand is None and not token.startswith("-"):
            if token in commands:
                subcommand = token
                value_opts = _option_nargs_map(commands[token])
            rest.append(token)
            index += 1
            continue

        if subcommand is not None and token in value_opts:
            consume = value_opts[token]
            rest.append(token)
            end = min(total, index + 1 + consume)
            rest.extend(args[index + 1 : end])
            index = end
            continue

        rest.append(token)
        index += 1

    requested_format = "json" if (saw_json or fmt == "json") else "text"
    return hoisted + rest, requested_format, subcommand


def _usage_error_suggestions(command: str) -> list[str]:
    help_cmd = "mailmaster --help" if command == "cli" else f"mailmaster {command} --help"
    return [
        f"Run '{help_cmd}' to inspect valid options.",
        "AI Agents: run 'mailmaster activate-skill' for full command examples.",
    ]


def _resolve_error_command(exc: click.ClickException, fallback_subcommand: str | None) -> str:
    ctx = getattr(exc, "ctx", None)
    if ctx is not None:
        if ctx.parent is not None and ctx.info_name:
            return str(ctx.info_name)
        if ctx.parent is None and isinstance(exc, click.NoSuchOption):
            return "cli"
    return fallback_subcommand or "cli"


def _build_usage_error_details(exc: click.UsageError, command: str) -> dict[str, Any]:
    details: dict[str, Any] = {"error_type": type(exc).__name__}
    param = getattr(exc, "param", None)
    if param is not None:
        if getattr(param, "name", None):
            details["param_name"] = param.name
        if getattr(param, "param_type_name", None):
            details["param_type"] = param.param_type_name
        opts = getattr(param, "opts", None)
        if opts:
            details["opts"] = list(opts)
    param_hint = getattr(exc, "param_hint", None)
    if param_hint:
        details["param_hint"] = param_hint
    option_name = getattr(exc, "option_name", None)
    if option_name:
        details["option_name"] = option_name
    possibilities = getattr(exc, "possibilities", None)
    if possibilities:
        details["possibilities"] = list(possibilities)
    details["suggestions"] = _usage_error_suggestions(command)
    return details


_HELP_PANEL_ORDER: dict[str, int] = {
    "Setup & Skill": 0,
    "Read & Search": 1,
    "Send & Drafts": 2,
    "Mailbox Actions": 3,
    "Protocol Diagnostics (Advanced)": 4,
}


class JsonAwareTyperGroup(typer.core.TyperGroup):
    """Typer group that accepts ``--json``/``--format`` anywhere and emits JSON parameter errors."""

    def list_commands(self, ctx: click.Context) -> list[str]:
        names = list(super().list_commands(ctx))
        return [
            name
            for _, name in sorted(
                enumerate(names),
                key=lambda item: (
                    _HELP_PANEL_ORDER.get(
                        str(getattr(self.commands.get(item[1]), "rich_help_panel", "") or ""),
                        99,
                    ),
                    item[0],
                ),
            )
        ]

    def parse_args(self, ctx: click.Context, args: list[str]) -> list[str]:
        normalized, _, _ = _normalize_cli_args(args, self.commands)
        args[:] = normalized
        return super().parse_args(ctx, args)

    def main(
        self,
        args: Sequence[str] | None = None,
        prog_name: str | None = None,
        complete_var: str | None = None,
        standalone_mode: bool = True,
        windows_expand_args: bool = True,
        **extra: Any,
    ) -> Any:
        if args is None:
            raw_args = list(sys.argv[1:])
            if os.name == "nt" and windows_expand_args:
                expand_args = getattr(click.utils, "_expand_args", None)
                if callable(expand_args):
                    raw_args = list(expand_args(raw_args))
        else:
            raw_args = list(args)

        normalized_args, requested_format, subcommand = _normalize_cli_args(raw_args, self.commands)
        token = _output_format_var.set(requested_format)
        try:
            if requested_format == "json" and standalone_mode:
                if prog_name is None:
                    prog_name = click.utils._detect_program_name()
                self._main_shell_completion(extra, prog_name, complete_var)
                try:
                    try:
                        with self.make_context(prog_name, list(normalized_args), **extra) as ctx:
                            self.invoke(ctx)
                            ctx.exit()
                    except EOFError as exc:
                        click.echo(file=sys.stderr)
                        raise click.Abort() from exc
                    except KeyboardInterrupt as exc:
                        raise click.exceptions.Exit(130) from exc
                    except click.UsageError as exc:
                        error_command = _resolve_error_command(exc, subcommand)
                        payload = {
                            "ok": False,
                            "command": error_command,
                            "error": {
                                "code": "invalid_argument",
                                "message": exc.format_message(),
                                "details": _serialize(_build_usage_error_details(exc, error_command)),
                            },
                        }
                        typer.echo(json.dumps(payload, ensure_ascii=False, indent=2))
                        sys.exit(2)
                    except click.ClickException as exc:
                        error_command = _resolve_error_command(exc, subcommand)
                        payload = {
                            "ok": False,
                            "command": error_command,
                            "error": {
                                "code": "invalid_argument",
                                "message": exc.format_message(),
                                "details": {
                                    "error_type": type(exc).__name__,
                                    "suggestions": _usage_error_suggestions(error_command),
                                },
                            },
                        }
                        typer.echo(json.dumps(payload, ensure_ascii=False, indent=2))
                        sys.exit(exc.exit_code)
                except click.exceptions.Exit as exc:
                    sys.exit(exc.exit_code)
                except click.Abort:
                    payload = {
                        "ok": False,
                        "command": subcommand or "cli",
                        "error": {
                            "code": "aborted",
                            "message": "Aborted!",
                            "details": {},
                        },
                    }
                    typer.echo(json.dumps(payload, ensure_ascii=False, indent=2))
                    sys.exit(1)

            return super().main(
                args=args,
                prog_name=prog_name,
                complete_var=complete_var,
                standalone_mode=standalone_mode,
                windows_expand_args=windows_expand_args,
                **extra,
            )
        finally:
            _output_format_var.reset(token)


app = typer.Typer(
    cls=JsonAwareTyperGroup,
    help=(
        "Read, search, send, draft, and manage NetEase MailMaster emails on Windows "
        "(IMAP/SMTP & 163/126/yeah.net Wmsvr).\n\n"
        "AI Agents: run 'mailmaster activate-skill' to load the full usage playbook, "
        "and pass '--json' (or '--format json') on any command for structured JSON output."
    ),
)


@app.callback()
def app_callback(
    ctx: typer.Context,
    format: str = typer.Option("text", "--format", help="Output format: text or json (works before or after any command)."),
    json_output: bool = typer.Option(False, "--json", help="Output structured JSON (shortcut for --format json; works anywhere)."),
) -> None:
    fmt = format.lower().strip()
    if fmt not in {"text", "json"}:
        raise typer.BadParameter("--format must be one of: text, json")
    if json_output:
        fmt = "json"
    _output_format_var.set(fmt)
    ctx.obj = {"output_format": fmt}


def _use_json_output() -> bool:
    return _output_format_var.get() == "json"


def _serialize(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
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


def _emit_error(
    command: str,
    *,
    code: str,
    message: str,
    details: Any | None = None,
    exit_code: int = 2,
    text_renderer: Callable[[], None] | None = None,
) -> NoReturn:
    payload = {
        "ok": False,
        "command": command,
        "error": {
            "code": code,
            "message": message,
            "details": _serialize(details),
        },
    }
    if _use_json_output():
        typer.echo(json.dumps(payload, ensure_ascii=False, indent=2))
        raise typer.Exit(exit_code)
    if text_renderer is not None:
        text_renderer()
        raise typer.Exit(exit_code)
    typer.echo(message)
    raise typer.Exit(exit_code)


def main() -> None:
    app()


from . import commands as _commands  # noqa: E402,F401
from . import skill_commands as _skill_commands  # noqa: E402,F401
from . import wmsvr_commands as _wmsvr_commands  # noqa: E402,F401

__all__ = ["app", "main"]
