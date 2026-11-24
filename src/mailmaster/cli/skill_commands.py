"""CLI command for outputting and installing the bundled MailMaster Agent skill."""

from __future__ import annotations

from pathlib import Path

import typer

from ..skill import (
    SUPPORTED_SKILL_TARGETS,
    get_skill_source_path,
    install_skill,
    load_skill_markdown,
)
from . import _emit, _emit_error, app
from .errors import _render_failure


def _render_installed(written: list[Path]) -> None:
    for path in written:
        typer.echo(f"Installed mailmaster skill to: {path}")


@app.command(name="activate-skill", rich_help_panel="Setup & Skill")
def activate_skill(
    install: list[str] = typer.Option(
        [],
        "--install",
        help="Install SKILL.md for an agent environment: project (.agents/skills), claude, codex, gemini, or cursor. Repeatable.",
    ),
    dest: Path | None = typer.Option(
        None,
        "--dest",
        help="Install SKILL.md into a custom directory or file path.",
    ),
    path_only: bool = typer.Option(
        False,
        "--path",
        help="Print only the bundled SKILL.md file path.",
    ),
) -> None:
    """Output or install the MailMaster AI Agent skill playbook (SKILL.md).

    Examples:
      mailmaster activate-skill
      mailmaster activate-skill --install project
      mailmaster activate-skill --install claude --install codex --json
      mailmaster activate-skill --path
    """
    src = get_skill_source_path()

    if install or dest is not None:
        try:
            written = install_skill(targets=install or None, dest=dest)
        except ValueError as exc:
            message = str(exc)
            valid = list(SUPPORTED_SKILL_TARGETS)
            _emit_error(
                "activate-skill",
                code="invalid_skill_target",
                message=message,
                details={"valid_targets": valid},
                text_renderer=lambda: _render_failure(
                    message,
                    [f"Choose one or more valid targets: {', '.join(valid)}."],
                ),
            )
        _emit(
            "activate-skill",
            {
                "name": "mailmaster",
                "installed": True,
                "installed_to": [str(path) for path in written],
                "source_path": str(src),
            },
            text_renderer=lambda: _render_installed(written),
        )
        return

    if path_only:
        _emit(
            "activate-skill",
            {"name": "mailmaster", "source_path": str(src)},
            lambda: typer.echo(str(src)),
        )
        return

    content = load_skill_markdown()
    _emit(
        "activate-skill",
        {
            "name": "mailmaster",
            "source_path": str(src),
            "installed": False,
            "installed_to": [],
            "content": content,
        },
        lambda: typer.echo(content, nl=not content.endswith("\n")),
    )


__all__ = ["activate_skill"]
