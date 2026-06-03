# -*- coding: utf-8 -*-
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone

from models import ExposureTier, InventoryItem

ENV_VAR_BLOCKLIST: frozenset[str] = frozenset({
    "PSModulePath", "PATH", "PATHEXT", "TEMP", "TMP", "TMPDIR",
    "APPDATA", "LOCALAPPDATA", "USERPROFILE", "HOMEDRIVE", "HOMEPATH",
    "COMPUTERNAME", "USERDOMAIN", "PROCESSOR_ARCHITECTURE",
    "PROCESSOR_IDENTIFIER", "PROCESSOR_LEVEL", "PROCESSOR_REVISION",
    "NUMBER_OF_PROCESSORS", "SystemRoot", "windir", "ProgramFiles",
    "ProgramData", "CommonProgramFiles", "PUBLIC", "OS", "LOGONSERVER",
    "USERDOMAIN_ROAMINGPROFILE", "ComSpec", "DriverData", "GOARCH",
    "GOOS", "GOPATH", "GOROOT", "VBOX_MSI_INSTALL_PATH",
    "ZES_ENABLE_SYSMAN", "OneDrive", "OneDriveConsumer",
    "ALLUSERSPROFILE", "CommonProgramFiles(x86)", "CommonProgramW6432",
    "ProgramFiles(x86)", "ProgramW6432", "SystemDrive", "Path",
    "USERNAME", "SESSIONNAME", "NUMBER_OF_PROCESSORS",
})

# Matches https://TOKEN@github.com or similar git hosting URLs.
# Tokens embedded in remote URLs are a common credential exposure vector
# that the collector's credential-helper approach may miss.
_EMBEDDED_TOKEN_RE = re.compile(
    r'https://([A-Za-z0-9_-]{10,})@(?:github\.com|gitlab\.com|bitbucket\.org)'
)

_SECRET_PATTERN_RE = re.compile(
    r'(?i)(TOKEN|KEY|SECRET|PASSWORD|PASSWD|APIKEY|API_KEY|ACCESS|BEARER|CREDENTIAL)'
)

_PATH_HEURISTIC_RE = re.compile(r'[/\\]')


def _is_env_secret_false_positive(cred: dict) -> bool:
    ctx = cred.get("context", {})
    var_name = ctx.get("var_name", "")

    if var_name in ENV_VAR_BLOCKLIST:
        return True

    value_redacted = cred.get("value_redacted", "")
    if (
        _PATH_HEURISTIC_RE.search(value_redacted)
        and " " not in value_redacted
        and len(value_redacted) < 500
        and not _SECRET_PATTERN_RE.search(var_name)
    ):
        return True

    return False


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _extract_git_remote_tokens(collection: dict) -> list[dict]:
    """Return synthetic credential dicts for tokens embedded in git remote URLs.

    Tokens embedded in remote URLs are invisible to credential-helper collection
    but are fully accessible to any process that can read the git config.
    """
    found: list[dict] = []
    repos = (collection.get("git") or {}).get("repos") or []

    for repo in repos:
        repo_path = repo.get("path", "")
        for url in (repo.get("remote_urls") or []):
            m = _EMBEDDED_TOKEN_RE.search(url)
            if not m:
                continue
            token = m.group(1)
            # Identify token type by prefix
            cred_type = "github_pat"
            for prefix in ("gho_", "ghp_", "github_pat_", "ghs_"):
                if token.startswith(prefix):
                    cred_type = "github_pat"
                    break

            raw_hash = _sha256(token)
            found.append({
                "id": _sha256(cred_type + "git_remote:" + repo_path),
                "type": cred_type,
                "path": f"git:{repo_path} (embedded in remote URL)",
                "value_redacted": _redact(token),
                "value_hash": raw_hash,
                "found_at": collection.get("meta", {}).get("collected_at", ""),
                "context": {
                    "token_prefix": token[:4] + "_",
                    "source": "git_remote_url",
                    "repo": repo_path,
                    "remote_url_masked": re.sub(r'https://[^@]+@', 'https://***@', url),
                },
                "authority": {},
                "exposure_tier": "",
            })

    return found


def _parse_dt(s: str) -> datetime:
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return datetime.min.replace(tzinfo=timezone.utc)


def build_inventory(collection: dict, definitions: dict) -> tuple[list[InventoryItem], int]:
    """Return (inventory_items, filtered_count).

    Builds the InventoryItem list from collection credentials plus any tokens
    found embedded in git remote URLs. Deduplicates by value_hash.
    """
    def_map: dict[str, dict] = {
        d["type"]: d for d in (definitions.get("credentials") or [])
    }

    meta = collection.get("meta", {})
    window_start_str = meta.get("incident_window_start", "")
    window_defaulted = meta.get("window_defaulted", False)
    window_start = _parse_dt(window_start_str)

    raw_creds: list[dict] = list(collection.get("credentials") or [])
    raw_creds.extend(_extract_git_remote_tokens(collection))

    filtered_count = 0
    # Group by value_hash to deduplicate across locations
    by_hash: dict[str, list[dict]] = {}
    for cred in raw_creds:
        if cred.get("type") == "env_secret" and _is_env_secret_false_positive(cred):
            filtered_count += 1
            continue
        h = cred.get("value_hash", cred.get("id", ""))
        by_hash.setdefault(h, []).append(cred)

    items: list[InventoryItem] = []
    for value_hash, group in by_hash.items():
        primary = group[0]
        cred_type = primary.get("type", "unknown")
        defn = def_map.get(cred_type, {})

        paths = list(dict.fromkeys(c.get("path", "") for c in group if c.get("path")))

        # Earliest found_at across all locations of this credential
        found_at = min((c.get("found_at", "") for c in group if c.get("found_at")),
                       key=_parse_dt, default="")

        in_window = _parse_dt(found_at) >= window_start if found_at else False

        tier_reason = ""
        if window_defaulted and in_window:
            tier_reason = "Janela do incidente definida como padrão (24h atrás) — limite incerto."

        default_tier_str = defn.get("default_tier", "MONITOR")
        try:
            default_tier = ExposureTier(default_tier_str)
        except ValueError:
            default_tier = ExposureTier.MONITOR

        items.append(InventoryItem(
            id=primary.get("id", _sha256(cred_type + paths[0] if paths else cred_type)),
            credential_type=cred_type,
            display_name=defn.get("display_name", cred_type),
            paths=paths,
            value_redacted=primary.get("value_redacted", ""),
            value_hash=value_hash,
            found_at=found_at,
            context=primary.get("context") or {},
            tier=default_tier,
            tier_reason=tier_reason,
            in_incident_window=in_window,
            revocation_url=defn.get("revocation_url", ""),
            revocation_command=defn.get("revocation_command", ""),
        ))

    return items, filtered_count
