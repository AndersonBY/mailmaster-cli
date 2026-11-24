"""Low-level Wmsvr / 163 protocol inspection and diagnostic CLI commands.

These ``wmsvr-*`` commands expose the no-Frida Wmsvr surface for troubleshooting and
protocol inspection: persisted bootstrap material, static anchors read from the
installed ``mastercore.dll``, and raw d1 transport probes.

Supported end-user Wmsvr mail workflows live in the main product commands:
``send-mail``, ``fetch-mail``, ``save-draft``, ``send-draft``, ``mark-read``,
``mark-unread``, ``move-mail``, and ``delete-mail``.
"""

from __future__ import annotations

from typing import Any

import typer

from ..store import LocalLookupError
from ..wmsvr import (
    DEFAULT_D1_FALLBACK_KEY_DIGEST16,
    DEFAULT_D1_KEY_VERSION,
    DEFAULT_D1_PRIMARY_KEY_DIGEST16,
    DEFAULT_D1_SIBLING_KEY_DIGEST16,
    DEFAULT_D1_SLICE_PADDING,
    LOGIN_METHOD_LOGINONE,
    build_loginmail_body,
    build_logincorp_body,
    build_loginone_body,
    build_wmsvr_login_frame,
    execute_wmsvr_login_probe,
    local_sec_name,
    local_sec_os_type,
    parse_login_response,
    summarize_login_response,
    load_wmsvr_hardcoded_public_keys,
)
from . import _emit, app
from .errors import _emit_local_lookup_error
from .render import console, print_key_values, print_string_list

# Fields that carry live auth material rather than identifiers.
REDACTED_CONTEXT_FIELDS = ("password", "cloud_token", "master_fp", "master_sdid")


def _describe_shape(shape: Any) -> str:
    """One-line rendering of a response-slice shape report.

    The point of the line is to say what the bytes *are* even when no known field
    name is in them: undecryptable noise (low printable ratio, no JSON, no tags)
    looks nothing like an answer body.
    """
    if not isinstance(shape, dict):
        return "(none)"
    parts = [
        f"len={shape.get('length')}",
        f"printable={shape.get('printable_ratio')}",
        f"json={bool(shape.get('looks_like_json'))}",
    ]
    if "json_decoded" in shape:
        parts.append(f"json_decoded={bool(shape.get('json_decoded'))}")
    tags = shape.get("tlv_tags") or []
    if tags:
        parts.append(f"tlv_tags={', '.join(str(tag) for tag in tags)}")
    names = shape.get("field_name_offsets") or {}
    if isinstance(names, dict) and names:
        parts.append(
            "names=" + ", ".join(f"{key}@{list(value)[0]}" for key, value in names.items())
        )
    return " ".join(parts)

_RECOVERED_KEY_DIGESTS = {
    "primary_default": DEFAULT_D1_PRIMARY_KEY_DIGEST16,
    "fallback_default": DEFAULT_D1_FALLBACK_KEY_DIGEST16,
    "sibling_default": DEFAULT_D1_SIBLING_KEY_DIGEST16,
}

_LOGIN_BODY_BUILDERS = {
    "wzpa:loginmail": build_loginmail_body,
    "wzpa:loginone": build_loginone_body,
}


def _redact(value: Any) -> Any:
    if not value:
        return value
    return f"<redacted:{len(str(value))} chars>"


def _redact_fields(payload: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    return {key: (_redact(value) if key in fields else value) for key, value in payload.items()}


def _parse_int(value: str, *, option: str) -> int:
    try:
        return int(value, 0)
    except ValueError as exc:
        raise typer.BadParameter(f"{option} must be an integer (decimal or 0x-prefixed hex): {value}") from exc


@app.command(name="wmsvr-keys", rich_help_panel="Protocol Diagnostics (Advanced)")
def wmsvr_keys() -> None:
    """List RSA public keys embedded in the installed mastercore.dll."""
    from .._facade import MailMaster

    mm = MailMaster()
    keys = load_wmsvr_hardcoded_public_keys(mm.paths.install_root)
    rows: list[dict[str, Any]] = []
    for label, key in keys.items():
        expected = _RECOVERED_KEY_DIGESTS.get(label)
        digest_hex = key.digest16.hex()
        rows.append(
            {
                "label": label,
                "bits": key.bits,
                "exponent": key.exponent,
                "digest16": digest_hex,
                "source_path": key.source_path,
                "source_index": key.source_index,
                "matches_recovered_material": None if expected is None else expected.hex() == digest_hex,
            }
        )

    def _render() -> None:
        print_key_values(
            "Wmsvr embedded public keys",
            [
                (
                    row["label"],
                    f"{row['bits']} bits  digest={row['digest16']}  "
                    + (
                        "matches recovered material"
                        if row["matches_recovered_material"]
                        else "DIFFERS from recovered material"
                        if row["matches_recovered_material"] is False
                        else "no recovered digest recorded"
                    ),
                )
                for row in rows
            ]
            + [("key_version_constant", hex(DEFAULT_D1_KEY_VERSION))],
        )

    _emit(
        "wmsvr-keys",
        {"install_root": str(mm.paths.install_root), "key_version": DEFAULT_D1_KEY_VERSION, "keys": rows},
        _render,
    )


@app.command(name="wmsvr-static-hints", rich_help_panel="Protocol Diagnostics (Advanced)")
def wmsvr_static_hints() -> None:
    """Report Wmsvr login and auth string anchors found in mastercore.dll."""
    from .._facade import MailMaster

    mm = MailMaster()
    hints = mm.get_wmsvr_login_static_hints()
    data = hints.to_dict()

    def _render() -> None:
        console.print(f"[bold]source_dll:[/bold] {data['source_dll']}")
        print_string_list("login_methods", data["login_methods"])
        print_string_list("login_request_fields", data["login_request_fields"])
        print_string_list("auth_response_fields", data["auth_response_fields"])
        print_string_list("jsbridge_methods", data["jsbridge_methods"])
        print_string_list("http_auth_types", data["http_auth_types"])
        print_string_list("endpoint_hints", data["endpoint_hints"])

    _emit("wmsvr-static-hints", data, _render)


@app.command(name="wmsvr-web-runtime", rich_help_panel="Protocol Diagnostics (Advanced)")
def wmsvr_web_runtime(
    include_values: bool = typer.Option(
        False,
        "--include-values",
        help="Include raw cookie values from disk (off by default to keep output safe to share).",
    ),
) -> None:
    """Inspect on-disk Chromium web state (cookies, servers, cache hits) for Wmsvr auth."""
    from .._facade import MailMaster

    mm = MailMaster()
    state = mm.get_wmsvr_web_runtime_state(include_values=include_values)
    data = state.to_dict()

    def _render() -> None:
        console.print(f"[bold]source_root:[/bold] {data['source_root']}")
        console.print(f"[bold]snapshot_root:[/bold] {data['snapshot_root']}")
        print_string_list("relevant_servers", data["relevant_servers"])
        print_key_values(
            "cookie_hints",
            [
                (
                    f"{item['host']} {item['name']}",
                    f"value_len={item['value_len']} encrypted_len={item['encrypted_len']}",
                )
                for item in data["cookie_hints"]
            ],
        )
        print_string_list("hits", [f"{item['source']}: {item['term']} ({item['path']})" for item in data["hits"]])

    _emit("wmsvr-web-runtime", {"include_values": include_values, **data}, _render)


@app.command(name="wmsvr-auth-surface", rich_help_panel="Protocol Diagnostics (Advanced)")
def wmsvr_auth_surface(
    include_values: bool = typer.Option(
        False,
        "--include-values",
        help="Include raw cookie values from disk (off by default to keep output safe to share).",
    ),
) -> None:
    """Combine static mastercore.dll anchors with on-disk web runtime state."""
    from .._facade import MailMaster

    mm = MailMaster()
    surface = mm.inspect_wmsvr_auth_surface(include_values=include_values)
    data = surface.to_dict()

    def _render() -> None:
        console.print(f"[bold]source_dll:[/bold] {data['static_hints']['source_dll']}")
        print_string_list("login_methods", data["static_hints"]["login_methods"])
        print_string_list("auth_response_fields", data["static_hints"]["auth_response_fields"])
        print_string_list("jsbridge_methods", data["static_hints"]["jsbridge_methods"])
        print_string_list("endpoint_hints", data["static_hints"]["endpoint_hints"])
        print_string_list("relevant_servers", data["web_runtime_state"]["relevant_servers"])
        console.print(f"[bold]cookie_hints:[/bold] {len(data['web_runtime_state']['cookie_hints'])}")
        console.print(f"[bold]runtime_hits:[/bold] {len(data['web_runtime_state']['hits'])}")

    _emit("wmsvr-auth-surface", {"include_values": include_values, **data}, _render)


@app.command(name="wmsvr-login-context", rich_help_panel="Protocol Diagnostics (Advanced)")
def wmsvr_login_context(
    account: str = typer.Option(..., "--account", help="Account email or numeric ID from 'mailmaster accounts'."),
    show_secrets: bool = typer.Option(
        False,
        "--show-secrets",
        help="Include password and token values (redacted by default).",
    ),
) -> None:
    """Show local device and credential inputs used to open a Wmsvr session."""
    from .._facade import MailMaster

    mm = MailMaster()
    try:
        context = mm.get_wmsvr_login_context(account)
    except LocalLookupError as exc:
        _emit_local_lookup_error("wmsvr-login-context", exc, account=account)
    data = context.to_dict()
    if not show_secrets:
        data = _redact_fields(data, REDACTED_CONTEXT_FIELDS)

    def _render() -> None:
        peers = data["peer_candidates"]
        print_key_values(
            "Wmsvr login context",
            [
                ("account", str(data["account"])),
                ("user", str(data["user"])),
                ("password", str(data["password"])),
                ("area", str(data["area"])),
                ("system", str(data["system"])),
                ("locale", str(data["locale"])),
                ("config_id", str(data["config_id"])),
                ("app_version", str(data["app_version"])),
                ("appver_inner", str(data["appver_inner"])),
                ("device_id", str(data["device_id"])),
                ("cloud_id", str(data["cloud_id"])),
                ("cloud_token", str(data["cloud_token"])),
                ("master_fp", str(data["master_fp"])),
                ("master_sdid", str(data["master_sdid"])),
                ("webui_pub_key", "present" if data["webui_pub_key"] else "missing"),
                ("peer_candidates", str(len(peers))),
            ],
        )
        for peer in peers:
            console.print(f"- {peer['host']}:{peer['port']} ipv6={peer['is_ip_v6']}")

    _emit("wmsvr-login-context", {"account": account, "redacted": not show_secrets, "context": data}, _render)


@app.command(name="wmsvr-refresh-session", rich_help_panel="Protocol Diagnostics (Advanced)")
def wmsvr_refresh_session(
    account: str = typer.Option(..., "--account", help="Account email or numeric ID from 'mailmaster accounts'."),
    timeout: float = typer.Option(20.0, "--timeout", min=1.0, help="HTTP timeout in seconds."),
    verify_ssl: bool = typer.Option(True, "--verify-ssl/--no-verify-ssl", help="Verify TLS certificates."),
    show_secrets: bool = typer.Option(
        False,
        "--show-secrets",
        help="Include the refreshed session token value (redacted by default).",
    ),
) -> None:
    """Refresh the Wmsvr master session token via config.dashi.163.com/init/session."""
    from .._facade import MailMaster

    mm = MailMaster()
    try:
        result = mm.refresh_wmsvr_master_session(account, timeout=timeout, verify_ssl=verify_ssl)
    except LocalLookupError as exc:
        _emit_local_lookup_error("wmsvr-refresh-session", exc, account=account)
    data = result.to_dict()
    token_len = len(str(data.get("token") or ""))
    if not show_secrets:
        data = _redact_fields(data, ("token",))

    def _render() -> None:
        print_key_values(
            "Wmsvr master session refresh",
            [
                ("ok", str(result.ok)),
                ("status_code", str(result.status_code)),
                ("code", str(result.code)),
                ("desc", result.desc),
                ("token_chars", str(token_len)),
                ("token_refresh_interval", str(result.token_refresh_interval)),
            ],
        )

    _emit(
        "wmsvr-refresh-session",
        {"account": account, "redacted": not show_secrets, "token_chars": token_len, "result": data},
        _render,
    )


@app.command(name="wmsvr-get-settings", rich_help_panel="Protocol Diagnostics (Advanced)")
def wmsvr_get_settings(
    account: str = typer.Option(..., "--account", help="Account email or numeric ID from 'mailmaster accounts'."),
    peer_index: int = typer.Option(0, "--peer-index", min=0, help="Index into the candidate d1 peer list."),
    primary_digest: bool = typer.Option(
        False, "--primary-digest", help="Send the primary key digest instead of the fallback digest."
    ),
    timeout: float = typer.Option(10.0, "--timeout", min=1.0, help="Socket timeout in seconds."),
) -> None:
    """Send a diagnostic Wmsvr d1 GET_SETTINGS request and show response metadata."""
    from .._facade import MailMaster

    mm = MailMaster()
    try:
        response = mm.probe_wmsvr_get_settings(
            account,
            use_primary_digest=primary_digest,
            peer_index=peer_index,
            timeout=timeout,
        )
    except LocalLookupError as exc:
        _emit_local_lookup_error("wmsvr-get-settings", exc, account=account)
    key_blob_hex = response.key_blob.hex()
    key_blob_preview = key_blob_hex[:96] + ("..." if len(key_blob_hex) > 96 else "")
    business_code_hex = None if response.business_code is None else hex(response.business_code)
    data = {
        "account": account,
        "peer_index": peer_index,
        "used_primary_digest": primary_digest,
        "business_code": response.business_code,
        "business_code_hex": business_code_hex,
        "key_version": response.key_version,
        "key_blob_len": len(response.key_blob),
        "key_blob_hex": key_blob_hex,
        "frame": response.frame,
    }

    def _render() -> None:
        print_key_values(
            "d1 GET_SETTINGS response",
            [
                ("business_code", str(business_code_hex)),
                ("key_version", str(response.key_version)),
                ("key_blob_len", str(len(response.key_blob))),
                ("key_blob_hex", key_blob_preview),
            ],
        )
        frame = response.frame
        if frame is not None:
            header = frame.header
            print_key_values(
                "response frame header",
                [
                    ("word0", hex(header.word0)),
                    ("word2", hex(header.word2)),
                    ("word4", hex(header.word4)),
                    ("seq", str(header.seq)),
                    ("extra16", "(absent)" if header.extra16 is None else hex(header.extra16)),
                    ("len0", str(header.len0)),
                    ("len1", str(header.len1)),
                ],
            )

    _emit("wmsvr-get-settings", data, _render)


@app.command(name="wmsvr-runtime-key", rich_help_panel="Protocol Diagnostics (Advanced)")
def wmsvr_runtime_key(
    account: str = typer.Option(..., "--account", help="Account email or numeric ID from 'mailmaster accounts'."),
    peer_index: int = typer.Option(0, "--peer-index", min=0, help="Index into the candidate d1 peer list."),
    timeout: float = typer.Option(10.0, "--timeout", min=1.0, help="Socket timeout in seconds."),
) -> None:
    """Fetch and decode the runtime RSA public key returned by GET_SETTINGS."""
    from .._facade import MailMaster

    mm = MailMaster()
    try:
        key = mm.probe_wmsvr_runtime_public_key(account, peer_index=peer_index, timeout=timeout)
    except LocalLookupError as exc:
        _emit_local_lookup_error("wmsvr-runtime-key", exc, account=account)
    data = {
        "account": account,
        "peer_index": peer_index,
        "version": key.version,
        "digest16": key.digest_hex,
        "matched_hardcoded_key": key.matched_hardcoded_key,
        "pem": key.pem,
        "der_len": len(key.der_bytes),
    }

    def _render() -> None:
        print_key_values(
            "d1 runtime public key",
            [
                ("version", f"{key.version} ({hex(key.version)})"),
                ("digest16", key.digest_hex),
                ("matched_hardcoded_key", key.matched_hardcoded_key or "(none)"),
                ("der_len", str(len(key.der_bytes))),
            ],
        )

    _emit("wmsvr-runtime-key", data, _render)


@app.command(name="wmsvr-login-probe", rich_help_panel="Protocol Diagnostics (Advanced)")
def wmsvr_login_probe(
    account: str = typer.Option(..., "--account", help="Account email or numeric ID from 'mailmaster accounts'."),
    method: str = typer.Option(LOGIN_METHOD_LOGINONE, "--method", help="Wmsvr login RPC method (e.g. wzpa:loginone)."),
    access_token: str = typer.Option("", "--access-token", help="Access token required by wzpa:logincorp."),
    word2: str = typer.Option("0x0003", "--word2", help="Request frame header word2 (decimal or 0x hex)."),
    word4: str = typer.Option("0x0003", "--word4", help="Request frame header word4 (decimal or 0x hex)."),
    peer_index: int = typer.Option(0, "--peer-index", min=0, help="Index into the candidate d1 peer list."),
    prefetch: bool = typer.Option(
        True,
        "--prefetch-get-settings/--no-prefetch-get-settings",
        help="Send GET_SETTINGS on the same socket before the login frame.",
    ),
    version_record: bool = typer.Option(
        False,
        "--version-record/--no-version-record",
        help="Prepend a 0x0107 version record to slice0 (diagnostic control; normal login frames omit it).",
    ),
    key_exchange: bool = typer.Option(
        True,
        "--key-exchange/--replay-wrapped-key",
        help="Wrap a fresh session key in GET_SETTINGS (--replay-wrapped-key is a diagnostic control).",
    ),
    timeout: float = typer.Option(30.0, "--timeout", min=1.0, help="Socket timeout in seconds."),
    padding: str = typer.Option(
        DEFAULT_D1_SLICE_PADDING,
        "--padding",
        help="Slice cipher padding mode: 'pkcs7' (default) or 'nul' (legacy diagnostic control).",
    ),
    sec_fingerprint: bool = typer.Option(
        False,
        "--sec-fingerprint/--no-sec-fingerprint",
        help="Include the device-fingerprint block (sec/secName/secOsType/secMdc) in wzpa:loginone.",
    ),
    send: bool = typer.Option(
        False,
        "--send",
        help="Transmit the probe over the network (dry-run by default).",
    ),
    show_secrets: bool = typer.Option(
        False,
        "--show-secrets",
        help="Include response token and cookie values instead of only field names and lengths.",
    ),
) -> None:
    """Build or transmit a diagnostic Wmsvr d1 login frame (dry-run unless --send is set)."""
    from .._facade import MailMaster

    parsed_word2 = _parse_int(word2, option="--word2")
    parsed_word4 = _parse_int(word4, option="--word4")

    mm = MailMaster()
    try:
        context = mm.get_wmsvr_login_context(account)
    except LocalLookupError as exc:
        _emit_local_lookup_error("wmsvr-login-probe", exc, account=account)

    builder = _LOGIN_BODY_BUILDERS.get(method)
    if method == "wzpa:logincorp":
        if not access_token:
            raise typer.BadParameter("wzpa:logincorp requires --access-token.")
        body: dict[str, Any] | None = build_logincorp_body(context, access_token=access_token)
    elif sec_fingerprint and method == LOGIN_METHOD_LOGINONE:
        # secMdc is deliberately empty: the client joins an empty table, so an
        # empty string is the faithful value, not a missing one.
        body = build_loginone_body(
            context,
            sec_name=local_sec_name(),
            sec_os_type=local_sec_os_type(),
            sec_mdc="",
        )
    else:
        body = builder(context) if builder is not None else None

    request = {
        "account": account,
        "method": method,
        "word2": hex(parsed_word2),
        "word4": hex(parsed_word4),
        "peer_index": peer_index,
        "prefetch_get_settings": prefetch,
        "key_exchange": key_exchange,
        "version_record": version_record,
        "sec_fingerprint": sec_fingerprint,
        "padding": padding,
        "body_field_count": 0 if body is None else len(body),
        "transmitted": send,
    }

    if not send:
        frame, session_key, client_id = build_wmsvr_login_frame(
            context,
            method=method,
            body=body,
            prefix_version=version_record,
            word2=parsed_word2,
            word4=parsed_word4,
            padding=padding,
        )
        header = frame.header
        data = {
            **request,
            "client_id": client_id,
            "session_key_len": len(session_key),
            "request_frame_len": len(frame.to_bytes()),
            "request_header": {
                "word0": hex(header.word0),
                "word2": hex(header.word2),
                "word4": hex(header.word4),
                "seq": header.seq,
                "extra16": None if header.extra16 is None else hex(header.extra16),
                "len0": header.len0,
                "len1": header.len1,
            },
        }

        def _render() -> None:
            print_key_values(
                "login probe (not transmitted)",
                [
                    ("method", method),
                    ("client_id", client_id),
                    ("word2", hex(parsed_word2)),
                    ("word4", hex(parsed_word4)),
                    ("session_key_len", str(len(session_key))),
                    ("request_frame_len", str(len(frame.to_bytes()))),
                ],
            )
            console.print("[yellow]Dry run: pass --send to transmit this frame.[/yellow]")

        _emit("wmsvr-login-probe", data, _render)
        return

    probe = execute_wmsvr_login_probe(
        context,
        method=method,
        body=body,
        prefix_version=version_record,
        word2=parsed_word2,
        word4=parsed_word4,
        peer_index=peer_index,
        prefetch_get_settings=prefetch,
        key_exchange=key_exchange,
        timeout=timeout,
        padding=padding,
    )
    response_frame = probe.response_frame
    response_extra16 = None if response_frame is None else response_frame.header.extra16
    response_summary = summarize_login_response(
        parse_login_response(probe.decrypted_slice0, probe.decrypted_slice1),
        include_secrets=show_secrets,
    )
    data = {
        **request,
        "client_id": probe.client_id,
        "error": probe.error,
        "session_key_len": len(probe.session_key),
        "key_exchange": probe.key_exchange,
        "key_exchange_frame_len": (
            None if probe.key_exchange_frame is None else len(probe.key_exchange_frame.to_bytes())
        ),
        "decrypted_slice0_len": len(probe.decrypted_slice0),
        "decrypted_slice1_len": len(probe.decrypted_slice1),
        "response_frame": response_frame,
        "response_extra16": None if response_extra16 is None else hex(response_extra16),
        "response": response_summary,
    }

    def _render_transmitted() -> None:
        slice0_shape = response_summary["slice0_shape"]
        slice1_shape = response_summary["slice1_shape"]
        seen_names = sorted(
            str(name)
            for shape in (slice0_shape, slice1_shape)
            if isinstance(shape, dict)
            for name in (shape.get("field_name_offsets") or {})
        )
        print_key_values(
            "login probe",
            [
                ("method", method),
                ("error", probe.error or "(none)"),
                ("response_extra16", str(data["response_extra16"])),
                ("decrypted_slice0_len", str(data["decrypted_slice0_len"])),
                ("decrypted_slice1_len", str(data["decrypted_slice1_len"])),
                ("response_code", str(response_summary["code"])),
                ("response_success", str(response_summary["success"])),
                (
                    "response_json_keys",
                    ", ".join(str(key) for key in response_summary["json_keys"] or []) or "(none)",
                ),
                (
                    "token_fields_present",
                    ", ".join(
                        str(name) for name in response_summary["token_fields_present"] or []
                    )
                    or "(none)",
                ),
                (
                    "identifier_fields_present",
                    ", ".join(
                        str(name) for name in response_summary["identifier_fields_present"] or []
                    )
                    or "(none)",
                ),
                ("slice0_shape", _describe_shape(slice0_shape)),
                ("slice1_shape", _describe_shape(slice1_shape)),
                (
                    "response_field_names_seen",
                    ", ".join(seen_names) or "(none in either slice)",
                ),
            ],
        )

    _emit("wmsvr-login-probe", data, _render_transmitted)
