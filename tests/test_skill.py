from __future__ import annotations

import json
from pathlib import Path
import re

import pytest
from typer.testing import CliRunner

from mailmaster.cli import app
import mailmaster.cli.skill_commands  # noqa: F401
from mailmaster.skill import (
    SUPPORTED_SKILL_TARGETS,
    get_skill_source_path,
    install_skill,
    load_skill_markdown,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
ROOT_SKILL_PATH = REPO_ROOT / "skill" / "SKILL.md"
BUNDLED_SKILL_PATH = REPO_ROOT / "src" / "mailmaster" / "skill" / "SKILL.md"

runner = CliRunner()


def test_root_and_bundled_skill_are_byte_identical() -> None:
    assert ROOT_SKILL_PATH.is_file()
    assert BUNDLED_SKILL_PATH.is_file()
    assert ROOT_SKILL_PATH.read_bytes() == BUNDLED_SKILL_PATH.read_bytes()
    assert get_skill_source_path().resolve() == BUNDLED_SKILL_PATH.resolve()
    assert load_skill_markdown() == ROOT_SKILL_PATH.read_text(encoding="utf-8")


def test_skill_markdown_frontmatter_and_content_hygiene() -> None:
    content = load_skill_markdown()
    assert content.startswith("---\n")
    parts = content.split("\n---\n", 1)
    assert len(parts) == 2
    frontmatter, body = parts[0], parts[1]

    assert "name: mailmaster" in frontmatter
    assert "description:" in frontmatter
    assert "NetEase MailMaster" in frontmatter

    for expected in (
        "--json",
        "capabilities",
        "fetch-mail",
        "send-mail",
        "save-draft",
        "send-draft",
        "delete-mail",
        "hard-delete",
        "invalid_skill_target",
    ):
        assert expected in body

    assert re.search(r"\bround\s+\d+\b", content, re.IGNORECASE) is None

    emails = set(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", content))
    allowed = {
        "user@163.com",
        "sender@example.com",
        "recipient@example.com",
        "alice@example.com",
    }
    assert emails <= allowed


def test_install_skill_all_supported_targets(tmp_path: Path) -> None:
    cwd = tmp_path / "workspace"
    home = tmp_path / "home"
    cwd.mkdir()
    home.mkdir()

    written = install_skill(targets=list(SUPPORTED_SKILL_TARGETS), cwd=cwd, home=home)

    expected = [
        cwd / ".agents" / "skills" / "mailmaster" / "SKILL.md",
        home / ".claude" / "skills" / "mailmaster" / "SKILL.md",
        home / ".codex" / "skills" / "mailmaster" / "SKILL.md",
        home / ".gemini" / "config" / "skills" / "mailmaster" / "SKILL.md",
        cwd / ".cursor" / "skills" / "mailmaster" / "SKILL.md",
    ]
    assert written == expected
    expected_bytes = load_skill_markdown().encode("utf-8")
    for path in written:
        assert path.is_file()
        assert path.read_bytes() == expected_bytes


def test_install_skill_dest_variants_and_deduplication(tmp_path: Path) -> None:
    cwd = tmp_path / "workspace"
    home = tmp_path / "home"
    cwd.mkdir()
    home.mkdir()

    # Generic directory -> <dest>/mailmaster/SKILL.md
    written_dir = install_skill(dest=tmp_path / "custom-skills", cwd=cwd, home=home)
    assert written_dir == [tmp_path / "custom-skills" / "mailmaster" / "SKILL.md"]
    assert written_dir[0].read_text(encoding="utf-8") == load_skill_markdown()

    # Directory already named mailmaster -> <dest>/SKILL.md
    written_named = install_skill(dest=tmp_path / "mailmaster", cwd=cwd, home=home)
    assert written_named == [tmp_path / "mailmaster" / "SKILL.md"]
    assert written_named[0].read_text(encoding="utf-8") == load_skill_markdown()

    # Explicit markdown file -> write directly
    written_file = install_skill(dest=tmp_path / "custom" / "my-skill.md", cwd=cwd, home=home)
    assert written_file == [tmp_path / "custom" / "my-skill.md"]
    assert written_file[0].read_text(encoding="utf-8") == load_skill_markdown()

    # Relative dest resolved against cwd, and duplicate target deduplicated
    written_rel = install_skill(
        targets=["project", "PROJECT"],
        dest=Path("rel-skills"),
        cwd=cwd,
        home=home,
    )
    assert written_rel == [
        cwd / ".agents" / "skills" / "mailmaster" / "SKILL.md",
        cwd / "rel-skills" / "mailmaster" / "SKILL.md",
    ]


def test_install_skill_rejects_unknown_target_before_writing(tmp_path: Path) -> None:
    cwd = tmp_path / "workspace"
    home = tmp_path / "home"
    cwd.mkdir()
    home.mkdir()

    with pytest.raises(ValueError, match="Unknown skill target") as exc_info:
        install_skill(targets=["project", "bogus"], cwd=cwd, home=home)

    for valid in SUPPORTED_SKILL_TARGETS:
        assert valid in str(exc_info.value)
    assert not (cwd / ".agents" / "skills" / "mailmaster" / "SKILL.md").exists()


def test_cli_activate_skill_text_default() -> None:
    result = runner.invoke(app, ["activate-skill"])

    assert result.exit_code == 0
    assert result.stdout == load_skill_markdown()
    assert "╭" not in result.stdout
    assert "│" not in result.stdout


def test_cli_activate_skill_json_default() -> None:
    result = runner.invoke(app, ["--format", "json", "activate-skill"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert payload["command"] == "activate-skill"
    data = payload["data"]
    assert data["name"] == "mailmaster"
    assert data["installed"] is False
    assert data["installed_to"] == []
    assert data["content"] == load_skill_markdown()
    assert Path(data["source_path"]).resolve() == BUNDLED_SKILL_PATH.resolve()


def test_cli_activate_skill_path_text_and_json() -> None:
    text_res = runner.invoke(app, ["activate-skill", "--path"])
    assert text_res.exit_code == 0
    assert Path(text_res.stdout.strip()).resolve() == BUNDLED_SKILL_PATH.resolve()

    json_res = runner.invoke(app, ["--format", "json", "activate-skill", "--path"])
    assert json_res.exit_code == 0
    payload = json.loads(json_res.stdout)
    assert payload["ok"] is True
    assert payload["command"] == "activate-skill"
    assert payload["data"]["name"] == "mailmaster"
    assert Path(payload["data"]["source_path"]).resolve() == BUNDLED_SKILL_PATH.resolve()
    assert "content" not in payload["data"]


def test_cli_activate_skill_install_and_dest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace = tmp_path / "repo"
    fake_home = tmp_path / "home"
    workspace.mkdir()
    fake_home.mkdir()
    monkeypatch.chdir(workspace)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: fake_home))

    text_res = runner.invoke(app, ["activate-skill", "--install", "project", "--install", "claude"])
    assert text_res.exit_code == 0
    project_skill = workspace / ".agents" / "skills" / "mailmaster" / "SKILL.md"
    claude_skill = fake_home / ".claude" / "skills" / "mailmaster" / "SKILL.md"
    assert project_skill.is_file()
    assert claude_skill.is_file()
    assert str(project_skill) in text_res.stdout
    assert str(claude_skill) in text_res.stdout

    custom_dest = tmp_path / "extra-dir"
    json_res = runner.invoke(
        app,
        [
            "--format",
            "json",
            "activate-skill",
            "--install",
            "codex",
            "--dest",
            str(custom_dest),
        ],
    )
    assert json_res.exit_code == 0
    payload = json.loads(json_res.stdout)
    assert payload["ok"] is True
    assert payload["command"] == "activate-skill"
    data = payload["data"]
    assert data["name"] == "mailmaster"
    assert data["installed"] is True
    codex_skill = fake_home / ".codex" / "skills" / "mailmaster" / "SKILL.md"
    dest_skill = custom_dest / "mailmaster" / "SKILL.md"
    assert data["installed_to"] == [str(codex_skill), str(dest_skill)]
    assert codex_skill.read_text(encoding="utf-8") == load_skill_markdown()
    assert dest_skill.read_text(encoding="utf-8") == load_skill_markdown()


def test_cli_activate_skill_invalid_target_error() -> None:
    text_res = runner.invoke(app, ["activate-skill", "--install", "bogus"])
    assert text_res.exit_code == 2
    assert "bogus" in text_res.stdout

    json_res = runner.invoke(app, ["--format", "json", "activate-skill", "--install", "bogus"])
    assert json_res.exit_code == 2
    payload = json.loads(json_res.stdout)
    assert payload["ok"] is False
    assert payload["command"] == "activate-skill"
    assert payload["error"]["code"] == "invalid_skill_target"
    assert payload["error"]["details"]["valid_targets"] == list(SUPPORTED_SKILL_TARGETS)
