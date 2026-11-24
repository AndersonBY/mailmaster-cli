"""CLI command aggregator re-exporting modular read, send, mutation, and error submodules."""

from __future__ import annotations

from typing import TYPE_CHECKING

import typer

from ..discovery import discover_paths
from ..store import AccountStore, MailMasterStore

if TYPE_CHECKING:
    from ..models import MailMasterPaths


def _paths_and_store() -> tuple[MailMasterPaths, MailMasterStore]:
    paths = discover_paths()
    if not paths.app_db.exists():
        raise typer.BadParameter(f"MailMaster app db not found: {paths.app_db}")
    return paths, MailMasterStore(paths.app_db)


from .errors import (  # noqa: E402
    _emit_draft_send_unsupported,
    _emit_draft_unsupported,
    _emit_fetch_unsupported,
    _emit_local_lookup_error,
    _emit_mail_not_found,
    _emit_send_unsupported,
    _emit_smtp_failure,
    _ensure_mutation_capability,
    _ensure_send_capability,
    _raise_wmsvr_session_gap,
    _render_failure,
    _smtp_error_text,
)
from .mutation_commands import (  # noqa: E402
    _run_wmsvr_delete_mutation,
    _run_wmsvr_flag_mutation,
    _run_wmsvr_folder_mutation,
    delete_mail,
    mark_read,
    mark_unread,
    move_mail,
)
from .read_commands import (  # noqa: E402
    _run_wmsvr_fetch_mail,
    accounts,
    capabilities,
    doctor,
    fetch_mail,
    list_mails,
    mailboxes,
    read,
    search,
    wmsvr_bootstrap,
)
from .send_commands import (  # noqa: E402
    _run_wmsvr_save_draft,
    _run_wmsvr_send,
    _run_wmsvr_send_draft,
    save_draft,
    send_draft,
    send_mail,
    smtp_send,
)
from .skill_commands import activate_skill  # noqa: E402

__all__ = [
    "AccountStore",
    "_paths_and_store",
    "_render_failure",
    "_ensure_send_capability",
    "_ensure_mutation_capability",
    "_raise_wmsvr_session_gap",
    "_emit_send_unsupported",
    "_emit_draft_send_unsupported",
    "_emit_fetch_unsupported",
    "_emit_draft_unsupported",
    "_smtp_error_text",
    "_emit_smtp_failure",
    "_emit_local_lookup_error",
    "_emit_mail_not_found",
    "_run_wmsvr_fetch_mail",
    "_run_wmsvr_send",
    "_run_wmsvr_send_draft",
    "_run_wmsvr_save_draft",
    "_run_wmsvr_delete_mutation",
    "_run_wmsvr_flag_mutation",
    "_run_wmsvr_folder_mutation",
    "activate_skill",
    "doctor",
    "accounts",
    "capabilities",
    "wmsvr_bootstrap",
    "mailboxes",
    "list_mails",
    "read",
    "search",
    "fetch_mail",
    "smtp_send",
    "send_mail",
    "save_draft",
    "send_draft",
    "mark_read",
    "mark_unread",
    "move_mail",
    "delete_mail",
]
