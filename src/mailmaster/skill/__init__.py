"""Bundled Agent skill loader and installer for MailMaster CLI."""

from __future__ import annotations

from collections.abc import Sequence
from importlib import resources
from pathlib import Path

SUPPORTED_SKILL_TARGETS: tuple[str, ...] = (
    "project",
    "claude",
    "codex",
    "gemini",
    "cursor",
)


def load_skill_markdown() -> str:
    """Return the bundled ``SKILL.md`` content as UTF-8 text."""
    return resources.files("mailmaster.skill").joinpath("SKILL.md").read_text(encoding="utf-8")


def get_skill_source_path() -> Path:
    """Return the resolved filesystem path to the bundled ``SKILL.md``."""
    resource = resources.files("mailmaster.skill").joinpath("SKILL.md")
    if isinstance(resource, Path):
        return resource.resolve()
    candidate = Path(str(resource))
    if candidate.exists():
        return candidate.resolve()
    return (Path(__file__).resolve().parent / "SKILL.md").resolve()


def _resolve_target_path(target: str, *, cwd: Path, home: Path) -> Path:
    normalized = target.strip().lower()
    if normalized == "project":
        return cwd / ".agents" / "skills" / "mailmaster" / "SKILL.md"
    if normalized == "claude":
        return home / ".claude" / "skills" / "mailmaster" / "SKILL.md"
    if normalized == "codex":
        return home / ".codex" / "skills" / "mailmaster" / "SKILL.md"
    if normalized == "gemini":
        return home / ".gemini" / "config" / "skills" / "mailmaster" / "SKILL.md"
    if normalized == "cursor":
        return cwd / ".cursor" / "skills" / "mailmaster" / "SKILL.md"
    valid = ", ".join(SUPPORTED_SKILL_TARGETS)
    raise ValueError(f"Unknown skill target: {target!r}. Valid targets: {valid}")


def _resolve_dest_path(dest: Path, *, cwd: Path) -> Path:
    expanded = dest.expanduser()
    resolved = expanded if expanded.is_absolute() else (cwd / expanded)
    if resolved.suffix.lower() == ".md":
        return resolved
    if resolved.name == "mailmaster":
        return resolved / "SKILL.md"
    return resolved / "mailmaster" / "SKILL.md"


def install_skill(
    *,
    targets: Sequence[str] | None = None,
    dest: Path | None = None,
    cwd: Path | None = None,
    home: Path | None = None,
) -> list[Path]:
    """Install the bundled ``SKILL.md`` into one or more target environments or a custom destination."""
    base_cwd = (cwd if cwd is not None else Path.cwd()).resolve()
    base_home = (home if home is not None else Path.home()).resolve()

    destinations: list[Path] = []
    seen: set[Path] = set()

    for target in targets or ():
        path = _resolve_target_path(target, cwd=base_cwd, home=base_home)
        key = path.resolve()
        if key not in seen:
            seen.add(key)
            destinations.append(path)

    if dest is not None:
        path = _resolve_dest_path(dest, cwd=base_cwd)
        key = path.resolve()
        if key not in seen:
            seen.add(key)
            destinations.append(path)

    if not destinations:
        return []

    content = load_skill_markdown()
    payload = content.encode("utf-8")
    written: list[Path] = []
    for path in destinations:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        written.append(path)
    return written


__all__ = [
    "SUPPORTED_SKILL_TARGETS",
    "get_skill_source_path",
    "install_skill",
    "load_skill_markdown",
]
