from ._facade import AccountAccess, MailMaster
from .discovery import discover_paths
from .email_renderer import InlineImage, LatexMode, RenderedMarkdownEmail, render_markdown_email
from .imap_ops import ImapMutation, ImapProfile
from .models import Account, MailAttachment, MailContent, MailDetails, MailMasterPaths, MailRecord, Mailbox
from .protocol_config import decrypt_account_config_blob, decrypt_config_password, load_server_configs
from .smtp import SmtpProfile, guess_smtp_settings, profile_from_server_config, send_email
from .store import AccountStore, MailMasterStore

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "MailMaster",
    "AccountAccess",
    "Account",
    "Mailbox",
    "MailRecord",
    "MailContent",
    "MailDetails",
    "MailAttachment",
    "MailMasterPaths",
    "MailMasterStore",
    "AccountStore",
    "SmtpProfile",
    "send_email",
    "guess_smtp_settings",
    "profile_from_server_config",
    "render_markdown_email",
    "RenderedMarkdownEmail",
    "InlineImage",
    "LatexMode",
    "ImapProfile",
    "ImapMutation",
    "discover_paths",
    "decrypt_account_config_blob",
    "decrypt_config_password",
    "load_server_configs",
]
