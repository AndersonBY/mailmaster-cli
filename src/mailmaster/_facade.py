"""High-level library facade for MailMaster access."""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator

from .discovery import discover_paths
from .email_renderer import LatexMode, RenderedMarkdownEmail, render_markdown_email
from .imap_ops import delete_mail as imap_delete_mail
from .imap_ops import mark_seen, move_mail as imap_move_mail
from .imap_ops import open_imap_connection, profile_from_server_config as profile_from_imap_config
from .models import Account, AccountCapabilities, MailDetails, MailRecord, Mailbox, MailMasterPaths
from .smtp import resolve_smtp_profile, send_email
from .store import AccountStore, MailMasterStore
from .wmsvr import (
    DEFAULT_D1_FALLBACK_KEY_DIGEST16,
    DEFAULT_D1_PRIMARY_KEY_DIGEST16,
    WmsvrAuthSurface,
    WmsvrBootstrap,
    WmsvrDecodedKeyUpdate,
    WmsvrGetSettingsResponse,
    WmsvrInitSessionResult,
    WmsvrLoginStaticHints,
    WmsvrLoginContext,
    WmsvrWebRuntimeState,
    build_get_settings_frame,
    build_wmsvr_login_context,
    build_default_wmsvr_login_client_id,
    LOGIN_METHOD_LOGINONE,
    decode_get_settings_key_update,
    discover_wmsvr_login_static_hints,
    discover_wmsvr_web_runtime_state,
    inspect_wmsvr_auth_surface,
    load_wmsvr_bootstrap,
    query_get_settings_peer,
    refresh_wmsvr_master_session,
)
from .wmsvr_mail import (
    ERROR_BOOTSTRAP_MISSING,
    ERROR_FOLDER_NOT_FOUND,
    ERROR_LOGIN_CREDENTIAL_MISSING,
    ERROR_LOGIN_MATERIAL_MISSING,
    ERROR_PART_NOT_FOUND,
    PART_SCAN_LIMIT,
    PART_SOURCE_HEAD,
    WmsvrAttachment,
    WmsvrMailError,
    WmsvrMailSession,
    open_wmsvr_mail_session,
)

VALID_SEND_TRANSPORTS = frozenset({"auto", "smtp", "wmsvr-private"})


def resolve_send_transport(
    capability: AccountCapabilities,
    transport: str = "auto",
) -> str:
    """Resolve a requested send transport against an account's capabilities.

    Returns ``"smtp"``, ``"wmsvr-private"``, or ``"none"``.
    For ``"auto"``, picks ``"smtp"`` when ``supports_smtp_send`` and not
    ``(smtp_settings_source == "guess_smtp_settings" and supports_wmsvr_private_send)``,
    else ``"wmsvr-private"`` if ``supports_wmsvr_private_send``, else ``"none"``.
    """
    requested = transport.strip().lower()
    if requested not in VALID_SEND_TRANSPORTS:
        raise ValueError(
            f"Unknown send transport {transport!r}; expected one of: auto, smtp, wmsvr-private."
        )
    if requested == "smtp":
        return "smtp" if capability.supports_smtp_send else "none"
    if requested == "wmsvr-private":
        return "wmsvr-private" if capability.supports_wmsvr_private_send else "none"
    guessed_smtp = capability.smtp_settings_source == "guess_smtp_settings"
    if capability.supports_smtp_send and not (
        guessed_smtp and capability.supports_wmsvr_private_send
    ):
        return "smtp"
    if capability.supports_wmsvr_private_send:
        return "wmsvr-private"
    return "none"


class AccountAccess:
    def __init__(self, account: Account, *, install_root: Path | None = None, app_db: Path | None = None, local_root: Path | None = None):
        self.account = account
        self._store = AccountStore(account, install_root=install_root)
        self._app_db = app_db
        self._local_root = local_root

    def get_mailboxes(self) -> list[Mailbox]:
        return self._store.get_mailboxes()

    def list_mail(self, *, mailbox: str | None = None, unread_only: bool = False, limit: int = 20) -> list[MailRecord]:
        return self._store.list_mail(mailbox=mailbox, unread_only=unread_only, limit=limit)

    def search_mail(self, query: str, *, mailbox: str | None = None, limit: int = 20, include_body: bool = False) -> list[MailRecord]:
        return self._store.search_mail(query, mailbox=mailbox, limit=limit, include_body=include_body)

    def get_mail(self, mail_id: str) -> MailRecord:
        return self._store.get_mail(mail_id)

    def get_details(self, mail_id: str) -> MailDetails:
        return self._store.get_details(mail_id)

    def get_server_configs(self) -> dict[str, dict[str, object]]:
        return self._store.get_server_configs()

    def get_capabilities(self) -> AccountCapabilities:
        warnings: list[str] = []
        try:
            configs = self.get_server_configs()
        except Exception as exc:
            configs = {}
            warnings.append(f"server_config_load_failed:{type(exc).__name__}")

        has_imap_config = "IMAPServerConfig" in configs
        has_smtp_config = "SMTPServerConfig" in configs
        has_wmsvr_config = "WmsvrServerConfig" in configs
        has_local_store = self._store.mail_db.exists()
        has_content_store = self._store.content_db.exists()
        supports_local_read = has_local_store

        supports_smtp_send = False
        smtp_config_source: str | None = None
        smtp_settings_source: str | None = None
        smtp_credential_source: str | None = None
        if configs:
            try:
                resolved = resolve_smtp_profile(self.account.email, configs)
            except Exception as exc:
                warnings.append(f"smtp_unavailable:{type(exc).__name__}")
            else:
                profile = resolved.profile
                supports_smtp_send = bool(profile.smtp_host and profile.effective_username and profile.password)
                smtp_config_source = resolved.config_source
                smtp_settings_source = resolved.settings_source
                smtp_credential_source = resolved.credential_source

        supports_imap_mutations = False
        if has_imap_config:
            try:
                profile = self.get_imap_profile()
            except Exception as exc:
                warnings.append(f"imap_unavailable:{type(exc).__name__}")
            else:
                supports_imap_mutations = bool(profile.host and (profile.username or self.account.email) and profile.password)
        supports_wmsvr_bootstrap = bool(
            has_wmsvr_config and self._app_db is not None and self._app_db.exists()
        )

        supports_wmsvr_private_mutations = False
        wmsvr_private_mutation_reason: str | None = None
        if has_wmsvr_config:
            if not supports_wmsvr_bootstrap:
                wmsvr_private_mutation_reason = "wmsvr_bootstrap_unavailable"
            else:
                try:
                    context = self.get_wmsvr_login_context()
                except Exception as exc:
                    wmsvr_private_mutation_reason = f"wmsvr_login_context_failed:{type(exc).__name__}"
                else:
                    if not context.peer_candidates:
                        wmsvr_private_mutation_reason = "no_d1_peer_candidates"
                    elif not context.password:
                        wmsvr_private_mutation_reason = "stored_password_is_empty"
                    else:
                        # The recovered handshake needs every one of these; they are
                        # what rounds 51-56 proved the login/business frames ride on.
                        supports_wmsvr_private_mutations = bool(
                            context.master_fp and context.master_sdid and context.device_info_json
                        )
                        if not supports_wmsvr_private_mutations:
                            wmsvr_private_mutation_reason = "device_material_incomplete"

        product_paths: list[str] = []
        if supports_local_read:
            product_paths.append("local-read")
        if supports_smtp_send:
            product_paths.append("smtp-send")
        if supports_imap_mutations:
            product_paths.append("imap-mutations")
        if supports_wmsvr_bootstrap:
            product_paths.append("wmsvr-bootstrap")
        if supports_wmsvr_private_mutations:
            product_paths.append("wmsvr-private-mutations")
        # The private send rides the same handshake, password and device material as the
        # private writes (round 62 sent through it), so it shares that gate.
        supports_wmsvr_private_send = supports_wmsvr_private_mutations
        wmsvr_private_send_reason = wmsvr_private_mutation_reason
        if supports_wmsvr_private_send:
            product_paths.append("wmsvr-private-send")
        # The private draft write is the same compose family (`action:"save"`), so it rides
        # the same gate (round 70 productized what rounds 66/69 proved live).
        supports_wmsvr_private_drafts = supports_wmsvr_private_mutations
        wmsvr_private_draft_reason = wmsvr_private_mutation_reason
        if supports_wmsvr_private_drafts:
            product_paths.append("wmsvr-private-drafts")
        # Attachments ride the same handshake plus the upload family, so the gate is the
        # same one (round 84 proved the four-step send live, round 85 productized it).
        supports_wmsvr_private_attachments = supports_wmsvr_private_mutations
        wmsvr_private_attachment_reason = wmsvr_private_mutation_reason
        if supports_wmsvr_private_attachments:
            product_paths.append("wmsvr-private-attachments")
        # Sending a STORED draft is the compose-open family (`mbox:restoreDraft` + deliver on
        # the restored compose id, round 88), so it rides the same private-write gate.
        supports_wmsvr_private_draft_send = supports_wmsvr_private_mutations
        wmsvr_private_draft_send_reason = wmsvr_private_mutation_reason
        if supports_wmsvr_private_draft_send:
            product_paths.append("wmsvr-private-draft-send")
        # The private read (`wzpm:getMessageData`, round 93) rides the same handshake, password
        # and device material as the private writes, so it shares that gate as well.
        supports_wmsvr_private_read = supports_wmsvr_private_mutations
        wmsvr_private_read_reason = wmsvr_private_mutation_reason
        if supports_wmsvr_private_read:
            product_paths.append("wmsvr-private-read")

        if has_wmsvr_config and not supports_imap_mutations and not supports_wmsvr_private_mutations:
            reason = wmsvr_private_mutation_reason or "unknown"
            warnings.append(f"wmsvr_private_mutations_unavailable:{reason}")

        # Round 113: a profile with no stored `SMTPServerConfig` is guessed from the address
        # domain and paired with the Wmsvr password. That guess is a *attemptable* path, not
        # a verified one: account 7 advertised it as usable and the real attempt answered 535.
        # Keep `supports_smtp_send` (an explicit `--transport smtp` must still try and report
        # the server's verdict), but say out loud that the settings are guesses.
        smtp_profile_guessed = bool(
            supports_smtp_send and smtp_settings_source == "guess_smtp_settings"
        )
        if smtp_profile_guessed:
            warnings.append("smtp_profile_guessed")

        if supports_imap_mutations:
            recommended_mutation_method = "imap"
        elif supports_wmsvr_private_mutations:
            recommended_mutation_method = "wmsvr-private"
        else:
            recommended_mutation_method = "none"

        if supports_smtp_send and not smtp_profile_guessed:
            recommended_send_method = "smtp"
        elif supports_wmsvr_private_send:
            recommended_send_method = "wmsvr-private"
        elif supports_smtp_send:
            # Only a guessed SMTP profile is available; it is still the only send transport.
            recommended_send_method = "smtp"
        else:
            recommended_send_method = "none"

        return AccountCapabilities(
            account_id=self.account.id,
            email=self.account.email,
            name=self.account.name,
            has_local_store=has_local_store,
            has_content_store=has_content_store,
            has_imap_config=has_imap_config,
            has_smtp_config=has_smtp_config,
            has_wmsvr_config=has_wmsvr_config,
            supports_local_read=supports_local_read,
            supports_smtp_send=supports_smtp_send,
            supports_imap_mutations=supports_imap_mutations,
            supports_wmsvr_bootstrap=supports_wmsvr_bootstrap,
            supports_wmsvr_private_mutations=supports_wmsvr_private_mutations,
            wmsvr_private_mutation_reason=wmsvr_private_mutation_reason,
            supports_wmsvr_private_send=supports_wmsvr_private_send,
            wmsvr_private_send_reason=wmsvr_private_send_reason,
            supports_wmsvr_private_drafts=supports_wmsvr_private_drafts,
            wmsvr_private_draft_reason=wmsvr_private_draft_reason,
            supports_wmsvr_private_attachments=supports_wmsvr_private_attachments,
            wmsvr_private_attachment_reason=wmsvr_private_attachment_reason,
            supports_wmsvr_private_draft_send=supports_wmsvr_private_draft_send,
            wmsvr_private_draft_send_reason=wmsvr_private_draft_send_reason,
            supports_wmsvr_private_read=supports_wmsvr_private_read,
            wmsvr_private_read_reason=wmsvr_private_read_reason,
            recommended_read_method="local-store" if supports_local_read else "none",
            recommended_send_method=recommended_send_method,
            recommended_mutation_method=recommended_mutation_method,
            smtp_config_source=smtp_config_source,
            smtp_settings_source=smtp_settings_source,
            smtp_credential_source=smtp_credential_source,
            product_paths=product_paths,
            warnings=warnings,
        )

    def get_wmsvr_bootstrap(self) -> WmsvrBootstrap:
        if self._app_db is None:
            raise ValueError("MailMaster app db path is not configured for this account access.")
        return load_wmsvr_bootstrap(self._app_db)

    def get_wmsvr_login_context(self) -> WmsvrLoginContext:
        return build_wmsvr_login_context(
            self.account.email,
            self.get_server_configs(),
            self.get_wmsvr_bootstrap(),
        )

    def refresh_wmsvr_master_session(
        self,
        *,
        timeout: float = 20.0,
        verify_ssl: bool = True,
    ) -> WmsvrInitSessionResult:
        return refresh_wmsvr_master_session(
            self.get_wmsvr_bootstrap(),
            timeout=timeout,
            verify_ssl=verify_ssl,
        )

    def probe_wmsvr_get_settings(
        self,
        *,
        use_primary_digest: bool = False,
        peer_index: int = 0,
        timeout: float = 10.0,
    ) -> WmsvrGetSettingsResponse:
        bootstrap = self.get_wmsvr_bootstrap()
        peers = bootstrap.get_d1_candidate_peers(account=self.account.email)
        if not peers:
            raise ValueError(f"No d1 peers found for {self.account.email}.")
        if peer_index < 0 or peer_index >= len(peers):
            raise IndexError(f"peer_index out of range: {peer_index} (available={len(peers)})")
        digest = DEFAULT_D1_PRIMARY_KEY_DIGEST16 if use_primary_digest else DEFAULT_D1_FALLBACK_KEY_DIGEST16
        request = build_get_settings_frame(digest=digest)
        return query_get_settings_peer(peers[peer_index], request=request, timeout=timeout)

    def probe_wmsvr_runtime_public_key(
        self,
        *,
        peer_index: int = 0,
        timeout: float = 10.0,
    ) -> WmsvrDecodedKeyUpdate:
        response = self.probe_wmsvr_get_settings(
            use_primary_digest=True,
            peer_index=peer_index,
            timeout=timeout,
        )
        return decode_get_settings_key_update(
            response,
            install_root=self._store.install_root,
        )

    def get_wmsvr_login_static_hints(self) -> WmsvrLoginStaticHints:
        return discover_wmsvr_login_static_hints(self._store.install_root)

    def get_wmsvr_web_runtime_state(self, *, include_values: bool = False) -> WmsvrWebRuntimeState:
        return discover_wmsvr_web_runtime_state(self._local_root, include_values=include_values)

    def inspect_wmsvr_auth_surface(self, *, include_values: bool = False) -> WmsvrAuthSurface:
        return inspect_wmsvr_auth_surface(
            install_root=self._store.install_root,
            local_root=self._local_root,
            include_values=include_values,
        )

    def get_imap_profile(self):
        imap_cfg = self.get_server_configs().get("IMAPServerConfig")
        if not imap_cfg:
            raise ValueError(f"No IMAPServerConfig found for {self.account.email}.")
        return profile_from_imap_config(imap_cfg)

    def render_markdown_email(self, markdown_text: str, *, latex_mode: LatexMode = "auto") -> RenderedMarkdownEmail:
        return render_markdown_email(markdown_text, latex_mode=latex_mode)

    def resolve_send_transport(
        self,
        transport: str = "auto",
        *,
        capability: AccountCapabilities | None = None,
    ) -> str:
        """Resolve ``auto`` / ``smtp`` / ``wmsvr-private`` for this account."""
        cap = self.get_capabilities() if capability is None else capability
        return resolve_send_transport(cap, transport)

    def send_email(
        self,
        *,
        to: list[str],
        cc: list[str] | None = None,
        bcc: list[str] | None = None,
        subject: str = "",
        body: str = "",
        html_body: str = "",
        html_base_dir: Path | None = None,
        attachments: list[Path] | None = None,
        inline_images: list[Any] | None = None,
        in_reply_to: str = "",
    ) -> None:
        resolved = resolve_smtp_profile(self.account.email, self.get_server_configs())
        profile = resolved.profile
        send_email(
            profile,
            to=to,
            cc=cc,
            bcc=bcc,
            subject=subject,
            body=body,
            html_body=html_body,
            html_base_dir=html_base_dir,
            attachments=attachments,
            inline_images=inline_images,
            in_reply_to=in_reply_to,
        )

    def send_markdown_email(
        self,
        *,
        to: list[str],
        markdown_text: str,
        cc: list[str] | None = None,
        bcc: list[str] | None = None,
        subject: str = "",
        latex_mode: LatexMode = "auto",
        attachments: list[Path] | None = None,
        in_reply_to: str = "",
    ) -> None:
        rendered = self.render_markdown_email(markdown_text, latex_mode=latex_mode)
        self.send_email(
            to=to,
            cc=cc,
            bcc=bcc,
            subject=subject,
            body=rendered.plain_text,
            html_body=rendered.html,
            attachments=attachments,
            inline_images=rendered.inline_images,
            in_reply_to=in_reply_to,
        )

    def send_mail(
        self,
        *,
        to: list[str],
        cc: list[str] | None = None,
        bcc: list[str] | None = None,
        subject: str = "",
        body: str = "",
        html_body: str = "",
        markdown_text: str | None = None,
        latex_mode: LatexMode = "auto",
        attachments: list[Path] | None = None,
        in_reply_to: str = "",
        transport: str = "auto",
        verify: bool = True,
        html_base_dir: Path | None = None,
    ) -> dict[str, Any]:
        """Send one email over the resolved transport (SMTP or Wmsvr private protocol).

        Supports optional ``markdown_text`` rendering on both transports. For
        ``wmsvr-private``, ``latex_mode="auto"`` renders formulas as MathML instead of
        CID inline images because the private compose path does not attach inline CID
        parts.
        """
        capability = self.get_capabilities()
        chosen = self.resolve_send_transport(transport, capability=capability)
        if chosen == "none":
            raise ValueError(
                f"Send transport {transport!r} is not available for account {self.account.email}."
            )

        effective_body = body
        effective_html_body = html_body
        inline_images: list[Any] | None = None
        effective_latex_mode: LatexMode | None = None
        if markdown_text is not None:
            effective_latex_mode = (
                "mathml" if (chosen == "wmsvr-private" and latex_mode == "auto") else latex_mode
            )
            rendered = self.render_markdown_email(markdown_text, latex_mode=effective_latex_mode)
            effective_body = rendered.plain_text
            effective_html_body = rendered.html
            if chosen == "smtp":
                inline_images = rendered.inline_images
            content_mode = "markdown"
        else:
            content_mode = "html" if html_body else "plain"

        if chosen == "wmsvr-private":
            result = self.send_mail_private(
                to=to,
                cc=cc,
                bcc=bcc,
                subject=subject,
                body=effective_body,
                html_body=effective_html_body,
                attachments=attachments,
                verify=verify,
            )
            return {
                **result,
                "transport": "wmsvr-private",
                "status": "sent",
                "account": self.account.email,
                "to": list(to),
                "cc": list(cc or []),
                "bcc": list(bcc or []),
                "subject": subject,
                "content_mode": content_mode,
                "latex_mode": effective_latex_mode,
            }

        self.send_email(
            to=to,
            cc=cc,
            bcc=bcc,
            subject=subject,
            body=effective_body,
            html_body=effective_html_body,
            html_base_dir=html_base_dir,
            attachments=attachments,
            inline_images=inline_images,
            in_reply_to=in_reply_to,
        )
        return {
            "transport": "smtp",
            "status": "sent",
            "account": self.account.email,
            "to": list(to),
            "cc": list(cc or []),
            "bcc": list(bcc or []),
            "subject": subject,
            "attachments": [str(path) for path in (attachments or [])],
            "content_mode": content_mode,
            "latex_mode": effective_latex_mode,
        }

    def _private_write_material(self) -> tuple[WmsvrLoginContext, str]:
        """Load the stored password and refresh a session token for a Wmsvr private operation."""
        context = self.get_wmsvr_login_context()
        if not context.password:
            raise WmsvrMailError(
                ERROR_LOGIN_CREDENTIAL_MISSING,
                "this Wmsvr account has an empty stored password, so private-protocol login cannot proceed",
                details={"account": self.account.email},
            )
        init = self.refresh_wmsvr_master_session(timeout=20.0)
        if not init.ok:
            raise WmsvrMailError(
                ERROR_BOOTSTRAP_MISSING,
                f"could not refresh the init/session token (http {init.status_code}, desc {init.desc})",
                details={"account": self.account.email, "status_code": init.status_code, "desc": init.desc},
            )
        return context, init.token

    @contextmanager
    def _open_private_session(self, *, timeout: float = 30.0) -> Iterator[WmsvrMailSession]:
        """Open one per-operation authenticated Wmsvr mail session."""
        context, token = self._private_write_material()
        with open_wmsvr_mail_session(
            context,
            master_session_token=token,
            client_id=build_default_wmsvr_login_client_id(context, method=LOGIN_METHOD_LOGINONE),
            account_id=str(self.account.id),
            timeout=timeout,
        ) as session:
            yield session

    def _resolve_remote_ids(self, mail_ids: list[str]) -> tuple[list[MailRecord], list[str]]:
        """Resolve local mail ids to records and non-empty server-side remote ids."""
        if not mail_ids:
            raise ValueError("At least one mail id is required.")
        records = [self.get_mail(mail_id) for mail_id in mail_ids]
        remote_ids = [record.remote_id for record in records]
        missing = [record.local_id for record, remote_id in zip(records, remote_ids) if not remote_id]
        if missing:
            raise WmsvrMailError(
                ERROR_LOGIN_MATERIAL_MISSING,
                "these mails have no server-side id yet, so the private protocol cannot address them",
                details={"local_ids": missing},
            )
        return records, remote_ids

    def list_wmsvr_folders(self) -> list[dict]:
        """Read the server folder list over the private protocol (one short session)."""
        with self._open_private_session() as session:
            return session.list_folders()

    def fetch_mail_source(
        self,
        message_id: str,
        *,
        part: int | None = None,
        offset: int = 0,
        max_part: int = PART_SCAN_LIMIT,
    ) -> dict:
        """Read a message's raw RFC822 source over the Wmsvr private protocol (`wzpm:getMessageData`).

        Accepts either a server ``RemoteId`` (``<fid>:<mid>``) or a local numeric ``LocalId``
        from ``list_mail()``; local IDs without ``:`` are resolved against the local store
        automatically when present.

        When ``part`` is ``None`` (default), scans slots ``0..max_part`` and returns the
        RFC822 source slice (``mode: "scan"``). Passing ``part`` reads that exact slot
        (``mode: "part"``), and ``offset`` pages within that slot.
        """
        resolved_id = message_id
        if ":" not in message_id:
            try:
                record = self.get_mail(message_id)
            except Exception:
                record = None
            if record is not None and record.remote_id:
                resolved_id = record.remote_id

        with self._open_private_session() as session:
            if part is None:
                if offset:
                    raise ValueError(
                        "a byte offset needs a slot: a slice read at an offset starts "
                        "mid-stream, so `part` has to name the slot a source scan reported."
                    )
                result = session.fetch_message_source(
                    resolved_id, max_part=max_part
                )
                result["mode"] = "scan"
                return result
            read = session.read_message_slice(resolved_id, part=part, offset=offset)
            if not read["served"]:
                raise WmsvrMailError(
                    ERROR_PART_NOT_FOUND,
                    (
                        f"slot {part} of that message served nothing "
                        f"(reply code {read['code'] or 'none'}, "
                        f"{'empty reply' if read['empty'] else 'no payload'})"
                    ),
                    details={
                        "method": read["method"],
                        "mid": read["mid"],
                        "part": int(part),
                        "offset": int(offset),
                        "reply_code": read["code"],
                        "reply_extra16": read["extra16"],
                        "empty_reply": read["empty"],
                    },
                )
            return {
                "method": read["method"],
                "mid": read["mid"],
                "mode": "part",
                "part_slot": int(part),
                "offset": int(offset),
                "source": read["payload"],
                "length": read["length"],
                "sha256": read["sha256"],
                "candidates": [{
                    "part": int(part),
                    "length": read["length"],
                    "sha256": read["sha256"],
                    "is_source": read["payload"].startswith(PART_SOURCE_HEAD),
                }],
                "source_slots": [int(part)],
                "misses": [],
            }

    def send_mail_private(
        self,
        *,
        to: list[str],
        cc: list[str] | None = None,
        bcc: list[str] | None = None,
        subject: str = "",
        body: str = "",
        html_body: str = "",
        attachments: list[Path] | None = None,
        verify: bool = True,
    ) -> dict:
        """Send one mail over the Wmsvr private protocol (`mbox:compose`).

        Round 62: the compose family is the send path — `action:"continue"` mints the
        compose object and `action:"deliver"` sends it. `verify` (the default) reads the
        new sent copy's id, handed back by the delivery reply's `savedSent`, in the same
        session and raises `wmsvr_state_change_not_verified` when it does not resolve.

        Round 84 proved the attachment branch live, so `attachments` (local paths) make
        this a four-step send — compose, `upload:prepare`, one `wzp:uploadAttach` chunk
        per file, then the delivery — and verification additionally requires every chunk's
        `actualSize` to match the bytes sent.
        """
        files = [WmsvrAttachment.from_path(path) for path in (attachments or [])]
        with self._open_private_session() as session:
            if files:
                send = (
                    session.send_mail_with_attachments_verified
                    if verify
                    else session.send_mail_with_attachments
                )
                result = send(
                    account=self.account.email,
                    to=to,
                    cc=cc or [],
                    bcc=bcc or [],
                    subject=subject,
                    html_body=html_body,
                    text_body=body,
                    attachments=files,
                )
            else:
                send = session.send_mail_verified if verify else session.send_mail
                result = send(
                    account=self.account.email,
                    to=to,
                    cc=cc or [],
                    bcc=bcc or [],
                    subject=subject,
                    html_body=html_body,
                    text_body=body,
                )
        result["attachment_paths"] = [str(path) for path in (attachments or [])]
        return result

    def save_mail_draft(
        self,
        *,
        to: list[str],
        cc: list[str] | None = None,
        bcc: list[str] | None = None,
        subject: str = "",
        body: str = "",
        html_body: str = "",
        compose_id: str | None = None,
        attachments: list[Path] | None = None,
        verify: bool = True,
    ) -> dict:
        """Create or update a server-side draft over the Wmsvr private protocol.

        Rounds 66/69 proved the write live and round 70 productized it: the compose family's
        `action:"save"` returns a `draftId` that `wzp:getMessageInfos` resolves, and the
        drafts folder gains one item. `verify` (the default) reads that id back in the same
        session and raises `wmsvr_state_change_not_verified` when it does not resolve. The
        draft is a normal message: the private delete path removes it again.

        `attachments` (local paths) upload first and are referenced by the save, which round 87
        measured does store them on the draft (a 689 B draft without an attachment vs 12305 B
        with an 8192 B one); an upload that does not complete raises `wmsvr_upload_rejected`
        before the write is reported as verified.

        Round 72 settled the identity: the `composeId` is the draft. Passing `compose_id`
        (the `compose_id` of an earlier save) rewrites THAT draft - one folder item, a fresh
        `draftId` in the result, the previous one invalidated - and it works from a later run,
        because the product logs in per call. The result's `mode` says which happened.
        Round 74/75: if that draft was DELETED in the meantime the server creates a fresh one
        and reports it as `recreated=True`, with the new `draft_id` resolved from the drafts
        folder; a `compose_id` the server never issued - or one that has expired (round 76
        measured an id from ~2 h earlier being refused) - raises `wmsvr_compose_id_unknown`, and
        the server answers both cases identically.
        """
        files = [WmsvrAttachment.from_path(path) for path in (attachments or [])]
        with self._open_private_session() as session:
            save = session.save_draft_verified if verify else session.save_draft
            result = save(
                account=self.account.email,
                to=to,
                cc=cc or [],
                bcc=bcc or [],
                subject=subject,
                html_body=html_body,
                text_body=body,
                compose_id=compose_id,
                attachments=files,
            )
            if attachments:
                result["attachment_paths"] = [str(Path(path)) for path in attachments]
            return result

    def send_mail_draft(
        self,
        *,
        draft_id: str,
        to: list[str] | None = None,
        subject: str | None = None,
        body: str | None = None,
        html_body: str | None = None,
        verify: bool = True,
    ) -> dict:
        """Send a STORED draft over the Wmsvr private protocol (round 88).

        The draft is re-opened (`mbox:restoreDraft`) and delivered from the compose object the
        server hands back, so whatever attachments the draft holds ride along WITHOUT being
        uploaded again - the local file is not needed at all. Round 88 measured the whole chain
        live inside one session.

        `to`/`subject`/`body`/`html_body` override what the draft carries (a draft the desktop
        client left without recipients needs `to`). `verify` (the default) reads the new sent
        copy's id back in the same session and raises `wmsvr_state_change_not_verified` when it
        does not resolve.
        """
        with self._open_private_session() as session:
            send = session.send_draft_verified if verify else session.send_draft
            return send(
                draft_id=draft_id,
                to=to,
                subject=subject,
                html_body=html_body,
                text_body=body,
            )

    def find_mail_draft(self, *, subject: str = "", limit: int = 20) -> dict:
        """Resolve one draft in the drafts folder (round 88's listing, newest first).

        A draft can be addressed by the `draft_id` a save reported, or - for a draft the
        desktop client created - by its subject. `subject=""` takes the newest draft.
        """
        with self._open_private_session() as session:
            return session.find_draft(subject=subject, limit=limit)

    def _run_imap_mutation_many(
        self,
        mail_ids: list[str],
        *,
        mutator: Callable[[Any, MailRecord], None],
    ) -> list[MailRecord]:
        if not mail_ids:
            raise ValueError("At least one mail id is required.")
        records = [self.get_mail(mail_id) for mail_id in mail_ids]
        profile = self.get_imap_profile()
        with open_imap_connection(profile) as client:
            for record in records:
                mutator(client, record)
        return records

    def mark_read(self, mail_id: str) -> MailRecord:
        return self.mark_read_many([mail_id])[0]

    def mark_read_many(self, mail_ids: list[str]) -> list[MailRecord]:
        if self._use_wmsvr_private_transport():
            return self._run_wmsvr_flag_mutation(mail_ids, read=True)["records"]
        return self._run_imap_mutation_many(
            mail_ids,
            mutator=lambda client, record: mark_seen(client, record, seen=True),
        )

    def mark_unread(self, mail_id: str) -> MailRecord:
        return self.mark_unread_many([mail_id])[0]

    def mark_unread_many(self, mail_ids: list[str]) -> list[MailRecord]:
        if self._use_wmsvr_private_transport():
            return self._run_wmsvr_flag_mutation(mail_ids, read=False)["records"]
        return self._run_imap_mutation_many(
            mail_ids,
            mutator=lambda client, record: mark_seen(client, record, seen=False),
        )

    def _use_wmsvr_private_transport(self) -> bool:
        """Wmsvr private protocol is the fallback when IMAP material is absent."""
        capability = self.get_capabilities()
        if capability.supports_imap_mutations:
            return False
        return capability.supports_wmsvr_private_mutations

    def mark_read_verified(self, mail_ids: list[str]) -> dict:
        """Mark read over the private protocol and verify the remote state change."""
        return self._run_wmsvr_flag_mutation(mail_ids, read=True)

    def mark_unread_verified(self, mail_ids: list[str]) -> dict:
        """Mark unread over the private protocol and verify the remote state change."""
        return self._run_wmsvr_flag_mutation(mail_ids, read=False)

    def _run_wmsvr_flag_mutation(self, mail_ids: list[str], *, read: bool) -> dict:
        """One login-then-act private-protocol flag write with an in-session read-back.

        The session is opened per call: rounds 55-56 showed the material expires
        within the hour, so nothing here is cached across operations.
        """
        records, remote_ids = self._resolve_remote_ids(mail_ids)
        with self._open_private_session() as session:
            result = session.set_message_read_verified(remote_ids, read=read)
        return {"records": records, "result": result}

    def move_mail(self, mail_id: str, *, target_mailbox: str) -> MailRecord:
        return self.move_mail_many([mail_id], target_mailbox=target_mailbox)[0]

    def move_mail_many(self, mail_ids: list[str], *, target_mailbox: str) -> list[MailRecord]:
        target_mailbox_id = self._store.resolve_mailbox(target_mailbox) or target_mailbox
        if self._use_wmsvr_private_transport():
            return self._run_wmsvr_folder_mutation(mail_ids, target_mailbox_id)["records"]
        return self._run_imap_mutation_many(
            mail_ids,
            mutator=lambda client, record: imap_move_mail(client, record, target_mailbox=target_mailbox_id),
        )

    def move_mail_verified(self, mail_ids: list[str], *, target_mailbox: str) -> dict:
        """Move over the private protocol and verify the new folder in-session."""
        target_mailbox_id = self._store.resolve_mailbox(target_mailbox) or target_mailbox
        return self._run_wmsvr_folder_mutation(mail_ids, target_mailbox_id)

    def _run_wmsvr_folder_mutation(self, mail_ids: list[str], target_mailbox_id: str) -> dict:
        """Move messages with the private protocol (`attrs.fid`), verified via read-back."""
        try:
            fid = int(str(target_mailbox_id), 0)
        except ValueError as exc:
            raise WmsvrMailError(
                ERROR_LOGIN_MATERIAL_MISSING,
                f"the private move needs a numeric folder id, got {target_mailbox_id!r}; "
                "the local mailbox id is the server fid",
                details={"target_mailbox": str(target_mailbox_id)},
            ) from exc
        if fid <= 0:
            raise WmsvrMailError(
                ERROR_FOLDER_NOT_FOUND,
                f"folder id {fid} is a local-only id and has no server counterpart",
                details={"target_mailbox": str(target_mailbox_id)},
            )
        records, remote_ids = self._resolve_remote_ids(mail_ids)
        with self._open_private_session() as session:
            result = session.set_message_folder_verified(remote_ids, fid=fid)
            result["target_mailbox"] = str(target_mailbox_id)
        return {"records": records, "result": result}

    def _run_wmsvr_delete_mutation(self, mail_ids: list[str]) -> dict:
        """Delete messages with the private protocol (`mbox:deleteMessages`), verified via read-back.

        Round 59: the body is `{"deleteType":"batch","ids":[...]}` and the same-session
        read-back must show the message is gone (the id stops resolving).
        """
        records, remote_ids = self._resolve_remote_ids(mail_ids)
        with self._open_private_session() as session:
            result = session.delete_messages_verified(remote_ids)
        return {"records": records, "result": result}

    def delete_mail(self, mail_id: str) -> MailRecord:
        return self.delete_mail_many([mail_id])[0]

    def delete_mail_many(self, mail_ids: list[str]) -> list[MailRecord]:
        if self._use_wmsvr_private_transport():
            return self._run_wmsvr_delete_mutation(mail_ids)["records"]
        return self._run_imap_mutation_many(
            mail_ids,
            mutator=lambda client, record: imap_delete_mail(client, record),
        )

    def delete_mail_verified(self, mail_ids: list[str]) -> dict:
        """Delete over the private protocol and verify the message is gone in-session."""
        return self._run_wmsvr_delete_mutation(mail_ids)


class MailMaster:
    def __init__(self, *, app_db: Path | None = None, install_root: Path | None = None, paths: MailMasterPaths | None = None):
        if paths is None:
            paths = discover_paths()
        if app_db is not None:
            paths = MailMasterPaths(
                install_root=install_root if install_root is not None else paths.install_root,
                launcher_exe=paths.launcher_exe,
                local_root=paths.local_root,
                app_db=app_db,
                accounts_root=paths.accounts_root,
            )
        elif install_root is not None:
            paths = MailMasterPaths(
                install_root=install_root,
                launcher_exe=paths.launcher_exe,
                local_root=paths.local_root,
                app_db=paths.app_db,
                accounts_root=paths.accounts_root,
            )

        self.paths = paths
        self.store = MailMasterStore(self.paths.app_db)

    def get_accounts(self) -> list[Account]:
        return self.store.get_accounts()

    def get_account(self, identifier: str | int) -> Account:
        return self.store.get_account(str(identifier))

    def open_account(self, identifier: str | int) -> AccountAccess:
        return AccountAccess(
            self.get_account(identifier),
            install_root=self.paths.install_root,
            app_db=self.paths.app_db,
            local_root=self.paths.local_root,
        )

    def account(self, identifier: str | int) -> AccountAccess:
        return self.open_account(identifier)

    def get_mailboxes(self, account: str | int) -> list[Mailbox]:
        return self.open_account(account).get_mailboxes()

    def list_mail(self, account: str | int, *, mailbox: str | None = None, unread_only: bool = False, limit: int = 20) -> list[MailRecord]:
        return self.open_account(account).list_mail(mailbox=mailbox, unread_only=unread_only, limit=limit)

    def search_mail(self, account: str | int, query: str, *, mailbox: str | None = None, limit: int = 20, include_body: bool = False) -> list[MailRecord]:
        return self.open_account(account).search_mail(query, mailbox=mailbox, limit=limit, include_body=include_body)

    def get_mail(self, account: str | int, mail_id: str) -> MailRecord:
        return self.open_account(account).get_mail(mail_id)

    def get_details(self, account: str | int, mail_id: str) -> MailDetails:
        return self.open_account(account).get_details(mail_id)

    def get_capabilities(self, account: str | int) -> AccountCapabilities:
        return self.open_account(account).get_capabilities()

    def list_capabilities(
        self,
        *,
        query: str | None = None,
        require_local_read: bool = False,
        require_send: bool = False,
        require_mutation: bool = False,
        require_wmsvr_bootstrap: bool = False,
        require_paths: list[str] | None = None,
    ) -> list[AccountCapabilities]:
        items = [self.open_account(account.email).get_capabilities() for account in self.get_accounts()]
        return [
            item
            for item in items
            if item.matches(
                query=query,
                require_local_read=require_local_read,
                require_send=require_send,
                require_mutation=require_mutation,
                require_wmsvr_bootstrap=require_wmsvr_bootstrap,
                require_paths=require_paths,
            )
        ]

    def get_wmsvr_bootstrap(self, account: str | int | None = None) -> WmsvrBootstrap:
        bootstrap = load_wmsvr_bootstrap(self.paths.app_db)
        if account is None:
            return bootstrap
        self.get_account(account)
        return bootstrap

    def get_wmsvr_login_context(self, account: str | int) -> WmsvrLoginContext:
        return self.open_account(account).get_wmsvr_login_context()

    def refresh_wmsvr_master_session(
        self,
        account: str | int,
        *,
        timeout: float = 20.0,
        verify_ssl: bool = True,
    ) -> WmsvrInitSessionResult:
        return self.open_account(account).refresh_wmsvr_master_session(
            timeout=timeout,
            verify_ssl=verify_ssl,
        )

    def probe_wmsvr_get_settings(
        self,
        account: str | int,
        *,
        use_primary_digest: bool = False,
        peer_index: int = 0,
        timeout: float = 10.0,
    ) -> WmsvrGetSettingsResponse:
        return self.open_account(account).probe_wmsvr_get_settings(
            use_primary_digest=use_primary_digest,
            peer_index=peer_index,
            timeout=timeout,
        )

    def probe_wmsvr_runtime_public_key(
        self,
        account: str | int,
        *,
        peer_index: int = 0,
        timeout: float = 10.0,
    ) -> WmsvrDecodedKeyUpdate:
        return self.open_account(account).probe_wmsvr_runtime_public_key(
            peer_index=peer_index,
            timeout=timeout,
        )

    def get_wmsvr_login_static_hints(self) -> WmsvrLoginStaticHints:
        return discover_wmsvr_login_static_hints(self.paths.install_root)

    def get_wmsvr_web_runtime_state(self, *, include_values: bool = False) -> WmsvrWebRuntimeState:
        return discover_wmsvr_web_runtime_state(self.paths.local_root, include_values=include_values)

    def inspect_wmsvr_auth_surface(self, *, include_values: bool = False) -> WmsvrAuthSurface:
        return inspect_wmsvr_auth_surface(
            install_root=self.paths.install_root,
            local_root=self.paths.local_root,
            include_values=include_values,
        )

    def mark_read(self, account: str | int, mail_id: str) -> MailRecord:
        return self.open_account(account).mark_read(mail_id)

    def mark_read_many(self, account: str | int, mail_ids: list[str]) -> list[MailRecord]:
        return self.open_account(account).mark_read_many(mail_ids)

    def mark_unread(self, account: str | int, mail_id: str) -> MailRecord:
        return self.open_account(account).mark_unread(mail_id)

    def mark_unread_many(self, account: str | int, mail_ids: list[str]) -> list[MailRecord]:
        return self.open_account(account).mark_unread_many(mail_ids)

    def mark_read_verified(self, account: str | int, mail_ids: list[str]) -> dict:
        """Private-protocol mark-read with an in-session remote read-back."""
        return self.open_account(account).mark_read_verified(mail_ids)

    def mark_unread_verified(self, account: str | int, mail_ids: list[str]) -> dict:
        """Private-protocol mark-unread with an in-session remote read-back."""
        return self.open_account(account).mark_unread_verified(mail_ids)

    def move_mail_verified(self, account: str | int, mail_ids: list[str], *, target_mailbox: str) -> dict:
        """Private-protocol move with an in-session folder read-back."""
        return self.open_account(account).move_mail_verified(mail_ids, target_mailbox=target_mailbox)

    def list_wmsvr_folders(self, account: str | int) -> list[dict]:
        """Read the server folder list over the private protocol (one short session)."""
        return self.open_account(account).list_wmsvr_folders()

    def move_mail(self, account: str | int, mail_id: str, *, target_mailbox: str) -> MailRecord:
        return self.open_account(account).move_mail(mail_id, target_mailbox=target_mailbox)

    def move_mail_many(self, account: str | int, mail_ids: list[str], *, target_mailbox: str) -> list[MailRecord]:
        return self.open_account(account).move_mail_many(mail_ids, target_mailbox=target_mailbox)

    def delete_mail(self, account: str | int, mail_id: str) -> MailRecord:
        return self.open_account(account).delete_mail(mail_id)

    def delete_mail_many(self, account: str | int, mail_ids: list[str]) -> list[MailRecord]:
        return self.open_account(account).delete_mail_many(mail_ids)

    def delete_mail_verified(self, account: str | int, mail_ids: list[str]) -> dict:
        """Private-protocol delete with an in-session read-back (round 59)."""
        return self.open_account(account).delete_mail_verified(mail_ids)

    def send_mail(
        self,
        account: str | int,
        *,
        to: list[str],
        cc: list[str] | None = None,
        bcc: list[str] | None = None,
        subject: str = "",
        body: str = "",
        html_body: str = "",
        markdown_text: str | None = None,
        latex_mode: LatexMode = "auto",
        attachments: list[Path] | None = None,
        in_reply_to: str = "",
        transport: str = "auto",
        verify: bool = True,
        html_base_dir: Path | None = None,
    ) -> dict[str, Any]:
        """Send one email over the resolved transport (SMTP or Wmsvr private protocol)."""
        return self.open_account(account).send_mail(
            to=to,
            cc=cc,
            bcc=bcc,
            subject=subject,
            body=body,
            html_body=html_body,
            markdown_text=markdown_text,
            latex_mode=latex_mode,
            attachments=attachments,
            in_reply_to=in_reply_to,
            transport=transport,
            verify=verify,
            html_base_dir=html_base_dir,
        )

    def send_mail_private(
        self,
        account: str | int,
        *,
        to: list[str],
        cc: list[str] | None = None,
        bcc: list[str] | None = None,
        subject: str = "",
        body: str = "",
        html_body: str = "",
        attachments: list[Path] | None = None,
        verify: bool = True,
    ) -> dict:
        """Private-protocol send (`mbox:compose`) with an in-session sent-copy read-back.

        Round 62 for the plain send; round 84's four-step upload (compose -> `upload:prepare`
        -> `wzp:uploadAttach` -> deliver) when `attachments` are given.
        """
        return self.open_account(account).send_mail_private(
            to=to,
            cc=cc,
            bcc=bcc,
            subject=subject,
            body=body,
            html_body=html_body,
            attachments=attachments,
            verify=verify,
        )

    def save_mail_draft(
        self,
        account: str | int,
        *,
        to: list[str],
        cc: list[str] | None = None,
        bcc: list[str] | None = None,
        subject: str = "",
        body: str = "",
        html_body: str = "",
        compose_id: str | None = None,
        attachments: list[Path] | None = None,
        verify: bool = True,
    ) -> dict:
        """Create a server-side draft (`mbox:compose action:"save"`) with a read-back (round 70).

        `compose_id` rewrites that draft instead of creating one (round 72: the composeId is the
        draft's identity); the result's `mode` is `"create"` or `"update"`. `attachments`
        (local paths) are uploaded first and stored on the draft (round 87).
        """
        return self.open_account(account).save_mail_draft(
            to=to,
            cc=cc,
            bcc=bcc,
            subject=subject,
            body=body,
            html_body=html_body,
            compose_id=compose_id,
            attachments=attachments,
            verify=verify,
        )

    def fetch_mail_source(
        self,
        account: str | int,
        mail_id: str,
        *,
        part: int | None = None,
        offset: int = 0,
        max_part: int = PART_SCAN_LIMIT,
    ) -> dict:
        """Read one message's raw RFC822 source over the Wmsvr private protocol.

        Accepts either a local numeric ``LocalId`` or a server ``RemoteId`` (``<fid>:<mid>``).
        Without ``part``, scans the slice window to locate the RFC822 source; with ``part``,
        reads that exact slot and raises ``wmsvr_part_not_found`` if empty.
        """
        return self.open_account(account).fetch_mail_source(
            mail_id, part=part, offset=offset, max_part=max_part
        )

    def send_mail_draft(
        self,
        account: str | int,
        *,
        draft_id: str,
        to: list[str] | None = None,
        subject: str | None = None,
        body: str | None = None,
        html_body: str | None = None,
        verify: bool = True,
    ) -> dict:
        """Send a stored draft (`mbox:restoreDraft` + `deliver`) with an in-session read-back.

        Round 88: the draft's attachments are delivered from the server's own copy, so nothing
        is uploaded again - the caller only needs the draft id.
        """
        return self.open_account(account).send_mail_draft(
            draft_id=draft_id,
            to=to,
            subject=subject,
            body=body,
            html_body=html_body,
            verify=verify,
        )

    def find_mail_draft(self, account: str | int, *, subject: str = "", limit: int = 20) -> dict:
        """Resolve a draft in the drafts folder by subject (or the newest one) - round 88."""
        return self.open_account(account).find_mail_draft(subject=subject, limit=limit)
