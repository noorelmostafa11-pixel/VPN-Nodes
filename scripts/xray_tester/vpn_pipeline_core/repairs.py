from __future__ import annotations

import base64
import binascii
import json
import re
import urllib.parse
from typing import Any

from .models import TestResult
from .source import protocol_uri_body
from .parsers.common import (
    _normalize_xhttp_integral_numbers,
    _parse_xray_bool,
    _recover_json_plus_whitespace,
    _valid_reality_short_id,
    b64decode_loose,
    json_loads_unique,
    parse_query,
    qfirst,
)


_VLESS_SEMICOLON_RECOVERY_KEYS = {
    "encryption",
    "flow",
    "security",
    "type",
    "network",
    "net",
    "headertype",
    "header-type",
    "pbk",
    "publickey",
    "public-key",
    "sni",
    "servername",
    "server-name",
    "peer",
    "fp",
    "fingerprint",
    "client-fingerprint",
    "sid",
    "shortid",
    "short-id",
    "spx",
    "spiderx",
    "path",
    "wspath",
    "host",
    "authority",
    "alpn",
    "servicename",
    "service-name",
    "grpc-service-name",
    "service_name",
    "mode",
    "extra",
    "fm",
    "finalmask",
    "pqv",
    "mldsa65verify",
    "ech",
    "echconfiglist",
    "ech-config-list",
}

def _replace_share_query(source_raw: str, changes: dict[str, str | None]) -> str:
    url = urllib.parse.urlsplit(source_raw)
    if not url.query and not changes:
        return source_raw
    parts = url.query.split('&') if url.query else []
    out_parts = []
    change_keys = {k.lower(): v for k, v in changes.items()}
    seen = set()
    for part in parts:
        if not part:
            continue
        if '=' in part:
            rkey, rval = part.split('=', 1)
        else:
            rkey, rval = part, ''
        klower = urllib.parse.unquote(rkey).lower()
        if klower in change_keys:
            nval = change_keys[klower]
            if nval is not None and klower not in seen:
                out_parts.append(f"{rkey}={urllib.parse.quote(nval, safe='')}")
                seen.add(klower)
        else:
            out_parts.append(part)
    for klower, nval in change_keys.items():
        if nval is not None and klower not in seen:
            out_parts.append(f"{urllib.parse.quote(klower, safe='')}={urllib.parse.quote(nval, safe='')}")
    new_query = '&'.join(out_parts)
    return urllib.parse.urlunsplit((url.scheme, url.netloc, url.path, new_query, url.fragment))

def _repair_vless_semicolon_query(uri: str) -> str | None:
    """Repair the observed ';key' REALITY query corruption as an explicit URI."""
    url = urllib.parse.urlsplit(uri)
    parsed = urllib.parse.parse_qsl(url.query, keep_blank_values=True)
    q = parse_query(url.query)
    if qfirst(q, "security").strip().lower() != "reality":
        return None
    if qfirst(q, "pbk", "publickey", "public-key"):
        return None
    if not any(
        key.startswith(";") and key.lstrip(";").lower() in {"pbk", "publickey", "public-key"}
        for key, _ in parsed
    ):
        return None

    parts = url.query.split('&') if url.query else []
    changed = False
    out_parts = []
    for part in parts:
        if not part:
            continue
        if '=' in part:
            rkey, rval = part.split('=', 1)
        else:
            rkey, rval = part, ''
        klower = urllib.parse.unquote(rkey).lower()
        if klower.startswith(';'):
            clean = klower.lstrip(';')
            if clean in _VLESS_SEMICOLON_RECOVERY_KEYS:
                new_key = urllib.parse.quote(urllib.parse.unquote(rkey).lstrip(';'), safe='')
                out_parts.append(f"{new_key}={rval}")
                changed = True
                continue
        out_parts.append(part)

    if not changed:
        return None
    new_query = '&'.join(out_parts)
    repaired = urllib.parse.urlunsplit((url.scheme, url.netloc, url.path, new_query, url.fragment))
    repaired_q = parse_query(urllib.parse.urlsplit(repaired).query)
    if not qfirst(repaired_q, "pbk", "publickey", "public-key"):
        return None
    return repaired

def _migrate_legacy_mkcp_finalmask(text: str) -> str | None:
    """Translate the removed mkcp-aes128gcm mask to Xray mkcp-legacy.

    Only the exact old UDP shape with a string password is migrated.  Any
    extra/unknown settings leave the source untouched rather than guessing.
    """
    try:
        value = json_loads_unique(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(value, dict):
        return None
    udp = value.get("udp")
    if not isinstance(udp, list):
        return None

    changed = False
    migrated: list[Any] = []
    for item in udp:
        if not isinstance(item, dict) or str(item.get("type") or "").lower() != "mkcp-aes128gcm":
            migrated.append(item)
            continue
        settings = item.get("settings")
        if not isinstance(settings, dict) or set(settings) != {"password"}:
            return None
        password = settings.get("password")
        if type(password) is not str or not password:
            return None
        migrated.append({
            "type": "mkcp-legacy",
            "settings": {"header": "", "value": password},
        })
        changed = True

    if not changed:
        return None
    output = dict(value)
    output["udp"] = migrated
    return json.dumps(output, ensure_ascii=False, separators=(",", ":"))


def _repair_xhttp_extra_value(text: str) -> tuple[Any, str] | None:
    """Return one non-destructive XHTTP-extra repair and its strategy.

    Original parsing never applies these transformations.  This helper exists
    only for an explicit derived candidate so the source bytes remain the
    identity and the repair can be audited independently.
    """
    try:
        value = json_loads_unique(text)
    except json.JSONDecodeError:
        recovered = _recover_json_plus_whitespace(text)
        if recovered == text:
            return None
        try:
            value = json_loads_unique(recovered)
        except json.JSONDecodeError:
            return None
        normalized = _normalize_xhttp_integral_numbers(value)
        return normalized, "recover_xhttp_extra_json"

    normalized = _normalize_xhttp_integral_numbers(value)
    if json.dumps(normalized, sort_keys=True) != json.dumps(value, sort_keys=True):
        return normalized, "normalize_xhttp_integer_fields"
    return None

def _query_repair_options(protocol: str, source_raw: str) -> dict[str, str]:
    """Generates compatibility-derived candidates or repairs shared stream-query corruption."""
    options: dict[str, str] = {}
    url = urllib.parse.urlsplit(source_raw)
    q = parse_query(url.query)

    # SIP003 plugin semantics own the Shadowsocks transport.  Do not rewrite
    # unrelated native stream fields when an explicit plugin is present.
    if protocol == "ss" and qfirst(q, "plugin"):
        return options

    if protocol == "vmess":
        aid_keys = [k for k in ("aid", "alterid") if q.get(k)]
        if aid_keys:
            has_invalid = False
            has_non_zero = False
            for k in aid_keys:
                try:
                    if int(q[k][0].strip(), 10) != 0:
                        has_non_zero = True
                except ValueError:
                    has_invalid = True
            if has_non_zero and not has_invalid:
                options["vmess_force_alterid_0"] = _replace_share_query(
                    source_raw, {k: "0" for k in aid_keys}
                )

    if protocol == "vless":
        semicolon_repair = _repair_vless_semicolon_query(source_raw)
        if semicolon_repair is not None:
            options["recover_vless_semicolon_query"] = semicolon_repair

    extra_text = qfirst(q, "extra")
    if extra_text:
        repaired_extra = _repair_xhttp_extra_value(extra_text)
        if repaired_extra is not None:
            value, strategy = repaired_extra
            options[strategy] = _replace_share_query(
                source_raw,
                {"extra": json.dumps(value, ensure_ascii=False, separators=(",", ":"))},
            )

    for name in ("sid", "shortid", "short-id"):
        sid = qfirst(q, name)
        trimmed = sid.strip()
        if sid and trimmed != sid and _valid_reality_short_id(trimmed):
            options["trim_reality_short_id"] = _replace_share_query(
                source_raw, {name: trimmed}
            )
            break

    mode = qfirst(q, "mode")
    trimmed_mode = mode.strip()
    if (
        mode
        and trimmed_mode != mode
        and trimmed_mode in ("auto", "packet-up", "stream-up", "stream-one")
    ):
        options["trim_xhttp_mode"] = _replace_share_query(
            source_raw, {"mode": trimmed_mode}
        )

    if protocol == "vless":
        transport = qfirst(q, "type").lower()
        if transport.startswith("tcp#") and qfirst(q, "security").lower() == "reality":
            options["trim_corrupted_tcp_transport"] = _replace_share_query(
                source_raw, {"type": "tcp"}
            )

        encryption = qfirst(q, "encryption")
        if re.fullmatch(
            r"none(?:¬e=.*|=.*|@.*)", encryption, flags=re.IGNORECASE
        ):
            options["normalize_vless_none_encryption"] = _replace_share_query(
                source_raw, {"encryption": "none"}
            )
    return options


def _is_modern_vmess_share(source_raw: str) -> bool:
    try:
        url = urllib.parse.urlsplit(source_raw)
        return bool(url.username is not None and url.hostname and int(url.port or 0))
    except (TypeError, ValueError):
        return False


def repair_uri_options(protocol: str, source_raw: str) -> dict[str, str]:
    """Build only deterministic, non-deleting repair variants.

    Correct legacy/current formats are handled in the parser before Xray. This
    function is reserved for malformed source text whose correction is directly
    inferable from that same text.
    """
    if protocol in ("vless", "trojan", "ss"):
        return _query_repair_options(protocol, source_raw)

    if protocol == "vmess" and _is_modern_vmess_share(source_raw):
        return _query_repair_options(protocol, source_raw)

    options: dict[str, str] = {}
    if protocol == "vmess":
        _, body = protocol_uri_body("vmess", source_raw)
        payload, sep, fragment = body.partition("#")
        try:
            obj = json_loads_unique(b64decode_loose(payload).decode("utf-8-sig"))
        except (ValueError, UnicodeError, binascii.Error):
            return options
        if not isinstance(obj, dict):
            return options

        def variant(strategy: str, key: str, value: Any) -> None:
            modified = dict(obj)
            modified[key] = value
            encoded = base64.urlsafe_b64encode(
                json.dumps(modified, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            ).decode("ascii").rstrip("=")
            options[strategy] = "vmess://" + encoded + ("#" + fragment if sep else "")

        aid_keys = [k for k in ("aid", "alterId") if k in obj]
        if aid_keys:
            has_invalid = False
            has_non_zero = False
            for k in aid_keys:
                try:
                    if int(str(obj[k]).strip(), 10) != 0:
                        has_non_zero = True
                except ValueError:
                    has_invalid = True
            if has_non_zero and not has_invalid:
                modified = dict(obj)
                for k in aid_keys:
                    modified[k] = 0
                encoded = base64.urlsafe_b64encode(
                    json.dumps(modified, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                ).decode("ascii").rstrip("=")
                options["vmess_force_alterid_0"] = "vmess://" + encoded + ("#" + fragment if sep else "")

        if "extra" in obj:
            extra = obj.get("extra")
            if isinstance(extra, str):
                repaired_extra = _repair_xhttp_extra_value(extra)
            else:
                normalized = _normalize_xhttp_integral_numbers(extra)
                repaired_extra = (
                    (normalized, "normalize_xhttp_integer_fields")
                    if json.dumps(normalized, sort_keys=True) != json.dumps(extra, sort_keys=True)
                    else None
                )
            if repaired_extra is not None:
                value, strategy = repaired_extra
                variant(strategy, "extra", value)
    return options


def legacy_repair_uri_options(protocol: str, source_raw: str) -> dict[str, str]:
    """Preserve the previous repair catalogue for backward compatibility only.

    The active production path deliberately does *not* call this function.
    It exists so older tooling/importers and historical run validation keep
    their previous behavior while the new path uses only non-deleting,
    non-guessing repairs from ``repair_uri_options``.
    """
    options: dict[str, str] = {}
    if protocol in ("vless", "trojan"):
        q = parse_query(urllib.parse.urlsplit(source_raw).query)

        if protocol == "vless":
            semicolon_repair = _repair_vless_semicolon_query(source_raw)
            if semicolon_repair is not None:
                options["recover_vless_semicolon_query"] = semicolon_repair

        extra_text = qfirst(q, "extra")
        if extra_text:
            try:
                value = json_loads_unique(extra_text)
                _ = value
            except (ValueError, json.JSONDecodeError):
                options["remove_broken_xhttp_extra"] = _replace_share_query(
                    source_raw, {"extra": None}
                )

        for name in ("fm", "finalmask"):
            value = qfirst(q, name)
            if not value:
                continue
            try:
                json_loads_unique(value)
            except (ValueError, json.JSONDecodeError):
                options["remove_broken_finalmask"] = _replace_share_query(
                    source_raw, {name: None}
                )
                break

        for name in ("fm", "finalmask"):
            value = qfirst(q, name)
            if not value:
                continue
            migrated = _migrate_legacy_mkcp_finalmask(value)
            if migrated is not None:
                options["migrate_legacy_mkcp_finalmask"] = _replace_share_query(
                    source_raw, {name: migrated}
                )
                break

        for name in ("fp", "fingerprint", "client-fingerprint"):
            if qfirst(q, name):
                options["remove_invalid_fingerprint"] = _replace_share_query(
                    source_raw, {name: None}
                )
                break

        for name in ("sid", "shortid", "short-id"):
            sid = qfirst(q, name)
            trimmed = sid.strip()
            if sid and trimmed != sid and _valid_reality_short_id(trimmed):
                options["trim_reality_short_id"] = _replace_share_query(
                    source_raw, {name: trimmed}
                )
                break

        for name in ("spx", "spiderx"):
            spider = qfirst(q, name)
            if spider.startswith("?"):
                options["prefix_reality_spiderx_path"] = _replace_share_query(
                    source_raw, {name: "/" + spider}
                )
                break

        mode = qfirst(q, "mode")
        trimmed_mode = mode.strip()
        if mode and trimmed_mode != mode and trimmed_mode in (
            "auto", "packet-up", "stream-up", "stream-one"
        ):
            options["trim_xhttp_mode"] = _replace_share_query(
                source_raw, {"mode": trimmed_mode}
            )

        if protocol == "vless":
            transport = qfirst(q, "type").lower()
            if transport.startswith("tcp#") and qfirst(q, "security").lower() == "reality":
                options["trim_corrupted_tcp_transport"] = _replace_share_query(
                    source_raw, {"type": "tcp"}
                )

            security = qfirst(q, "security", "tls").strip().lower()
            if security in ("", "none", "0", "false", "off"):
                options["try_vless_tls"] = _replace_share_query(
                    source_raw, {"security": "tls"}
                )

            encryption = qfirst(q, "encryption")
            if (
                re.fullmatch(r"none(?:¬e=.*|=.*|@.*)", encryption, flags=re.IGNORECASE)
                or encryption.lower() == "one"
            ):
                encryption_changes: dict[str, str | None] = {"encryption": "none"}
                if security in ("", "none", "0", "false", "off"):
                    encryption_changes["security"] = "tls"
                options["normalize_vless_none_encryption"] = _replace_share_query(
                    source_raw, encryption_changes
                )

        elif qfirst(q, "security").lower() == "none":
            options["try_trojan_tls"] = _replace_share_query(
                source_raw, {"security": "tls"}
            )

    elif protocol == "vmess":
        _, body = protocol_uri_body("vmess", source_raw)
        payload, sep, fragment = body.partition("#")
        try:
            obj = json_loads_unique(b64decode_loose(payload).decode("utf-8-sig"))
        except (ValueError, UnicodeError, binascii.Error):
            return options
        if not isinstance(obj, dict):
            return options

        def variant(strategy: str, key: str, value: str) -> None:
            modified = dict(obj)
            modified[key] = value
            encoded = base64.urlsafe_b64encode(
                json.dumps(modified, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            ).decode("ascii").rstrip("=")
            options[strategy] = "vmess://" + encoded + ("#" + fragment if sep else "")

        if str(obj.get("tls") or "").lower() in ("auto", "chacha20-poly1305"):
            variant("vmess_explicit_no_tls", "tls", "none")
        if str(obj.get("net") or obj.get("network") or "").lower() == "none":
            variant("vmess_raw_transport", "net", "tcp")
    return options

def compose_repair_candidate(protocol: str, source_raw: str) -> tuple[str, str] | None:
    """Compose all provable source corrections into one explicit derived URI.

    This never deletes a source field and never invents missing credentials,
    security, host names, fingerprints, keys, or transports.  Each step must be
    independently exposed by ``repair_uri_options``.  Re-evaluating after each
    step lets one source contain more than one independently provable corruption
    without recursively guessing from a previously failed Xray result.
    """
    current = source_raw
    applied: list[str] = []
    seen = {current}
    for _ in range(12):
        try:
            options = repair_uri_options(protocol, current)
        except (ValueError, UnicodeError, binascii.Error):
            return None
        if not options:
            break
        # repair_uri_options is insertion-ordered.  Apply one deterministic
        # correction, then recalculate all remaining options on the new text.
        strategy, candidate = next(iter(options.items()))
        if not candidate or candidate == current or candidate in seen:
            break
        current = candidate
        seen.add(current)
        applied.append(strategy)
    if current == source_raw or not applied:
        return None
    return current, "+".join(applied)


_TLS_QUERY_ALIASES = (
    "allowinsecure", "allow_insecure", "allow-insecure", "insecure",
    "skip-cert-verify", "skip_cert_verify",
)
_TLS_LEGACY_VMESS_ALIASES = ("allowInsecure", "insecure", "skip-cert-verify")


def _malformed_finalmask(value: Any) -> bool:
    if isinstance(value, str):
        try:
            value = json_loads_unique(value)
        except (ValueError, UnicodeError):
            return True
    return not isinstance(value, dict)


def _repair_rejected_core_fields(result: TestResult) -> tuple[str, str] | None:
    """Derive one explicit link for fields that this Xray run rejected."""
    reason = (result.error or "").lower()
    removed_tls = (
        "allowinsecure" in reason and "has been removed" in reason
    ) or (
        "streamsettings.tlssettings.allowinsecure" in reason
        and "cannot unmarshal" in reason
    )
    rejected_mask = "streamsettings.finalmask" in reason and "cannot unmarshal" in reason
    if not (removed_tls or rejected_mask):
        return None

    source_raw = result.raw
    if result.protocol == "vmess" and not _is_modern_vmess_share(source_raw):
        _, body = protocol_uri_body("vmess", source_raw)
        payload, sep, fragment = body.partition("#")
        try:
            obj = json_loads_unique(b64decode_loose(payload).decode("utf-8-sig"))
        except (ValueError, UnicodeError, binascii.Error):
            return None
        if not isinstance(obj, dict):
            return None
        changes: list[str] = []
        tls_value = next((obj[k] for k in _TLS_LEGACY_VMESS_ALIASES if k in obj), None)
        tls_is_active = str(obj.get("tls") or "").lower() in ("tls", "1", "true", "on")
        if removed_tls or (rejected_mask and tls_is_active and _parse_xray_bool(tls_value) is True):
            removed = [k for k in _TLS_LEGACY_VMESS_ALIASES if k in obj]
            if removed:
                for key in removed:
                    del obj[key]
                changes.append("omit_removed_tls_override")
        mask_keys = [k for k in ("fm", "finalmask") if k in obj]
        if mask_keys and (rejected_mask or any(_malformed_finalmask(obj[k]) for k in mask_keys)):
            for key in mask_keys:
                del obj[key]
            changes.append("omit_rejected_finalmask")
        if not changes:
            return None
        encoded = base64.urlsafe_b64encode(
            json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ).decode("ascii").rstrip("=")
        return "vmess://" + encoded + ("#" + fragment if sep else ""), "+".join(changes)

    if result.protocol not in ("vless", "trojan", "vmess", "ss"):
        return None
    try:
        q = parse_query(urllib.parse.urlsplit(source_raw).query)
    except ValueError:
        return None
    changes: dict[str, str | None] = {}
    strategies: list[str] = []
    tls_value = qfirst(q, *_TLS_QUERY_ALIASES)
    security = qfirst(
        q, "security", "tls", default="tls" if result.protocol == "trojan" else "none"
    )
    if removed_tls or (
        rejected_mask and security.lower() == "tls" and _parse_xray_bool(tls_value) is True
    ):
        for key in _TLS_QUERY_ALIASES:
            if key in q:
                changes[key] = None
        if changes:
            strategies.append("omit_removed_tls_override")
    mask_keys = [key for key in ("fm", "finalmask") if key in q]
    if mask_keys and (
        rejected_mask or any(_malformed_finalmask(qfirst(q, key)) for key in mask_keys)
    ):
        for key in mask_keys:
            changes[key] = None
        strategies.append("omit_rejected_finalmask")
    if not changes:
        return None
    return _replace_share_query(source_raw, changes), "+".join(strategies)


def repair_candidate_for_failure(result: TestResult) -> tuple[str, str] | None:
    """Return one fully-composed, non-guessing repair for a source/config failure.

    Correctly specified legacy/current share formats belong in the parsers and
    never reach this path.  Only malformed source text that has an explicit,
    auditable correction is eligible here.  Connectivity failures are never
    rewritten.
    """
    if result.stage not in ("source_invalid", "unsupported"):
        return None
    core_repair = _repair_rejected_core_fields(result)
    if core_repair is not None:
        return core_repair
    return compose_repair_candidate(result.protocol, result.raw)
