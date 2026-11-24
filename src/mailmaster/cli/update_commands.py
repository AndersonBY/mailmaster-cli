"""CLI command for checking and installing updates from GitHub Releases."""

from __future__ import annotations

import typer

from ..updater import UpdateCheckResult, UpdateError, UpdateResult, check_for_update, perform_update
from . import _emit, _emit_error, app
from .errors import _render_failure
from .render import console


def _render_check(result: UpdateCheckResult) -> None:
    if result.update_available:
        console.print(
            f"[green]Update available:[/green] v{result.current_version} -> [bold]v{result.latest_version}[/bold]"
        )
        console.print(f"Release: {result.release_url}")
        console.print("Run [bold]mailmaster update[/bold] to install the latest release.")
    else:
        console.print(f"Already up to date (v{result.current_version}).")
        console.print(f"Latest release: {result.release_url}")
    if result.editable_install:
        location = f" ({result.editable_path})" if result.editable_path else ""
        console.print(f"[yellow]Note:[/yellow] Running from an editable/source checkout{location}.")


def _render_update(result: UpdateResult) -> None:
    if result.status in {"updated", "scheduled"}:
        console.print(f"[green]{result.message}[/green]")
    elif result.status == "skipped_editable":
        console.print(f"[yellow]{result.message}[/yellow]")
    else:
        console.print(result.message)


@app.command(name="update", rich_help_panel="Setup & Skill")
def update_cli(
    check: bool = typer.Option(
        False,
        "--check",
        help="Check GitHub Releases for a newer version without installing.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Reinstall the latest release even if already up to date or running from an editable checkout.",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Skip interactive confirmation (non-interactive default).",
    ),
) -> None:
    """Check for or install the latest mailmaster release from GitHub Releases.

    Examples:
      mailmaster update --check
      mailmaster update --check --json
      mailmaster update
      mailmaster update --force --yes
    """
    del yes
    if check:
        try:
            check_result = check_for_update()
        except UpdateError as exc:
            message = exc.message
            suggestions = list(exc.details.get("suggestions") or [])
            _emit_error(
                "update",
                code=exc.code,
                message=message,
                details=exc.details,
                text_renderer=lambda: _render_failure(message, suggestions),
            )
        _emit(
            "update",
            check_result,
            text_renderer=lambda: _render_check(check_result),
        )
        return

    try:
        result = perform_update(force=force)
    except UpdateError as exc:
        message = exc.message
        suggestions = list(exc.details.get("suggestions") or [])
        _emit_error(
            "update",
            code=exc.code,
            message=message,
            details=exc.details,
            text_renderer=lambda: _render_failure(message, suggestions),
        )

    _emit(
        "update",
        result,
        text_renderer=lambda: _render_update(result),
    )


__all__ = ["update_cli"]
