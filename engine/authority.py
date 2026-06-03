# -*- coding: utf-8 -*-
from __future__ import annotations

import re

from models import AuthorityResult, ExposureTier, InventoryItem, ResolutionMethod

_GITHUB_TYPES = frozenset({"github_pat", "github_oauth", "github_app_token"})
_UUID_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE,
)


def _clean_prefix(raw: str) -> str:
    """Strip the trailing '...' the collector appends to token prefixes."""
    return raw.rstrip(".")


def _resolve_github(item: InventoryItem, resolve_online: bool) -> AuthorityResult:
    raw_prefix = item.context.get("token_prefix", "")
    prefix = _clean_prefix(raw_prefix)

    if prefix.startswith("gho_"):
        offline_display = "Token OAuth do GitHub (CLI/Desktop). Escopo desconhecido offline."
    elif prefix.startswith("ghp_"):
        offline_display = "PAT Clássico do GitHub. Escopo desconhecido offline."
    elif prefix.startswith("github_pat_"):
        offline_display = "PAT Fine-Grained do GitHub. Escopo codificado no token."
    elif prefix.startswith("ghs_"):
        offline_display = "Token de instalação do GitHub App."
    else:
        offline_display = "Token do GitHub — prefixo não reconhecido."

    if not resolve_online:
        return AuthorityResult(
            method=ResolutionMethod.OFFLINE,
            resolved=False,
            display=offline_display,
        )

    # v0.1 limitation: the collector redacts token values for security.
    # Raw token value is required for live API resolution.
    # GitHub/npm online resolution will be implemented in v0.2 via
    # encrypted token transport. See docs/architecture.md.
    return AuthorityResult(
        method=ResolutionMethod.SKIPPED,
        resolved=False,
        display=offline_display,
        error="Valor bruto do token não disponível na coleta — resolução online requer o valor bruto.",
    )


def _resolve_ssh(item: InventoryItem) -> AuthorityResult:
    has_passphrase = item.context.get("has_passphrase", False)
    known_hosts = item.context.get("known_hosts_sample") or []
    configured_hosts = item.context.get("configured_hosts") or []
    key_type = item.context.get("key_type", "UNKNOWN")

    all_hosts = list(dict.fromkeys(known_hosts + configured_hosts))
    host_list = ", ".join(all_hosts) if all_hosts else "none recorded"
    passphrase_status = "protegida por senha" if has_passphrase else "SEM SENHA"

    display = (
        f"Chave privada {key_type} — {passphrase_status}. "
        f"Conecta a: {host_list}."
    )

    return AuthorityResult(
        method=ResolutionMethod.OFFLINE,
        resolved=True,
        display=display,
        accessible_resources=all_hosts,
    )


def _resolve_npm(item: InventoryItem, resolve_online: bool) -> AuthorityResult:
    value_redacted = item.value_redacted
    has_publish = item.context.get("has_publish_access", False)
    # Infer token format from redacted prefix — value_redacted is first4+***+last4
    token_start = value_redacted[:4] if len(value_redacted) >= 4 else value_redacted

    if token_start.startswith("npm_"):
        offline_display = "npm Granular Access Token."
    elif _UUID_RE.match(value_redacted.replace("*", "0")):
        offline_display = "npm Legacy Token (formato UUID — tipicamente acesso de publicação)."
    else:
        offline_display = "npm token (formato não reconhecido)."

    if has_publish:
        offline_display += " Coletor sinalizou acesso de publicação."

    if not resolve_online:
        return AuthorityResult(
            method=ResolutionMethod.OFFLINE,
            resolved=False,
            display=offline_display,
        )

    # v0.1 limitation: the collector redacts token values for security.
    # Raw token value is required for live API resolution.
    # GitHub/npm online resolution will be implemented in v0.2 via
    # encrypted token transport. See docs/architecture.md.
    return AuthorityResult(
        method=ResolutionMethod.SKIPPED,
        resolved=False,
        display=offline_display,
        error="Valor bruto do token não disponível — resolução online ignorada.",
    )


def _resolve_aws(item: InventoryItem, resolve_online: bool) -> AuthorityResult:
    key_id = item.context.get("key_id_prefix", "")

    if key_id.startswith("AKIA"):
        display = f"Chave IAM AWS de longo prazo ({key_id}****). Não expira."
    elif key_id.startswith("ASIA"):
        display = f"Token de sessão AWS STS ({key_id}****). Expira naturalmente."
    elif not key_id:
        display = "Credencial AWS IAM — prefixo da chave não disponível. Tratar como chave de longo prazo por precaução."
    else:
        display = f"Chave AWS — prefixo não reconhecido ({key_id})."

    if resolve_online:
        return AuthorityResult(
            method=ResolutionMethod.SKIPPED,
            resolved=False,
            display=display,
            error="AWS STS requer assinatura SigV4. Execute 'aws sts get-caller-identity' manualmente.",
        )

    return AuthorityResult(
        method=ResolutionMethod.OFFLINE,
        resolved=False,
        display=display,
    )


def _resolve_azure(item: InventoryItem) -> AuthorityResult:
    tenant_id = item.context.get("tenant_id", "unknown")
    subscription_id = item.context.get("subscription_id", "")
    parts = [f"Token Azure — tenant: {tenant_id}"]
    if subscription_id:
        parts.append(f"assinatura: {subscription_id}")
    display = ". ".join(parts) + "."

    return AuthorityResult(
        method=ResolutionMethod.SKIPPED,
        resolved=False,
        display=display,
        error="Execute 'az account show' para verificar o acesso.",
    )


def _resolve_docker(item: InventoryItem) -> AuthorityResult:
    cred_store = item.context.get("cred_store", "")
    registries = item.context.get("registries") or []

    if cred_store:
        return AuthorityResult(
            method=ResolutionMethod.OFFLINE,
            resolved=False,
            display=(
                f"Credenciais Docker no keychain do sistema ({cred_store}). "
                "Valor inacessível ao coletor — inspeção manual necessária."
            ),
            accessible_resources=registries,
        )

    reg_list = ", ".join(registries) if registries else "nenhum registrado"
    return AuthorityResult(
        method=ResolutionMethod.OFFLINE,
        resolved=True,
        display=f"Credenciais Docker para registros: {reg_list}.",
        accessible_resources=registries,
    )


def _resolve_pypi(item: InventoryItem) -> AuthorityResult:
    value_start = item.value_redacted[:5] if len(item.value_redacted) >= 5 else ""
    if value_start.startswith("pypi-"):
        display = "PyPI API token (prefixo pypi- — acesso de publicação)."
    else:
        display = "PyPI token."

    return AuthorityResult(
        method=ResolutionMethod.SKIPPED,
        resolved=False,
        display=display,
        error="Revogar via https://pypi.org/manage/account/token/",
    )


def _resolve_env_secret(item: InventoryItem) -> AuthorityResult:
    var_name = item.context.get("var_name", item.paths[0] if item.paths else "unknown")
    return AuthorityResult(
        method=ResolutionMethod.OFFLINE,
        resolved=False,
        display=f"Segredo em variável de ambiente: {var_name}.",
    )


def resolve_single(item: InventoryItem, resolve_online: bool) -> AuthorityResult:
    ctype = item.credential_type

    if ctype in _GITHUB_TYPES:
        return _resolve_github(item, resolve_online)
    if ctype == "ssh_key":
        return _resolve_ssh(item)
    if ctype == "npm_token":
        return _resolve_npm(item, resolve_online)
    if ctype in ("aws_longterm_key", "aws_session_token", "aws_key"):
        return _resolve_aws(item, resolve_online)
    if ctype == "azure_token":
        return _resolve_azure(item)
    if ctype == "docker_credential":
        return _resolve_docker(item)
    if ctype == "pypi_token":
        return _resolve_pypi(item)
    if ctype == "env_secret":
        return _resolve_env_secret(item)

    return AuthorityResult(
        method=ResolutionMethod.SKIPPED,
        resolved=False,
        display="Tipo de credencial desconhecido — revisão manual necessária.",
    )


def assign_tier(item: InventoryItem) -> tuple[ExposureTier, str]:
    """Return (tier, tier_reason). Rules evaluated in order — first match wins."""
    ctype = item.credential_type
    ctx = item.context
    auth = item.authority

    # ── REVOKE_NOW ────────────────────────────────────────────────────────────

    if ctype in _GITHUB_TYPES and auth.resolved and any(
        s in auth.scopes for s in ("repo", "workflow", "admin:org", "write:packages", "delete_repo")
    ):
        return ExposureTier.REVOKE_NOW, (
            f"Token do GitHub com escopos de alta autoridade: {', '.join(auth.scopes)}."
        )

    if ctype in _GITHUB_TYPES:
        prefix = _clean_prefix(ctx.get("token_prefix", ""))
        if prefix.startswith(("gho_", "ghp_", "github_pat_", "ghs_")):
            return ExposureTier.REVOKE_NOW, (
                "OAuth/PAT do GitHub — escopo desconhecido offline. "
                "REVOGAR AGORA por padrão conforme NIST SP 800-61 assume-breach."
            )

    if ctype == "ssh_key":
        has_passphrase = ctx.get("has_passphrase", False)
        known_hosts = ctx.get("known_hosts_sample") or []
        configured_hosts = ctx.get("configured_hosts") or []
        all_hosts = known_hosts + configured_hosts
        if not has_passphrase and all_hosts:
            return ExposureTier.REVOKE_NOW, (
                "Chave SSH desprotegida com conexões ativas conhecidas. Revogar imediatamente."
            )

    if ctype in ("aws_longterm_key", "aws_key"):
        key_id = ctx.get("key_id_prefix", "")
        if key_id.startswith("AKIA") or not key_id:
            return ExposureTier.REVOKE_NOW, (
                "Chave IAM AWS de longo prazo — não expira. Revogar imediatamente."
            )

    if ctype == "npm_token":
        has_publish = ctx.get("has_publish_access", False)
        value_redacted = item.value_redacted
        is_uuid = bool(_UUID_RE.match(value_redacted[:36].replace("*", "0")))
        if has_publish or is_uuid:
            return ExposureTier.REVOKE_NOW, "Token npm com provável acesso de publicação."

    if item.in_incident_window and ctype != "env_secret":
        return ExposureTier.REVOKE_NOW, (
            "Credencial encontrada/modificada dentro da janela do incidente."
        )

    # ── ROTATE ────────────────────────────────────────────────────────────────

    if ctype == "ssh_key":
        if ctx.get("has_passphrase", False):
            return ExposureTier.ROTATE, "Chave SSH protegida por senha."
        # No known_hosts — unprotected but no observed usage
        return ExposureTier.ROTATE, "Chave SSH sem senha, mas sem hosts conhecidos registrados."

    if ctype == "aws_session_token":
        return ExposureTier.ROTATE, "Token de sessão AWS STS — expira naturalmente, mas rotacione."

    if ctype in ("azure_token", "gcloud_token"):
        return ExposureTier.ROTATE, f"{ctype} — rotacionar por precaução."

    if ctype == "docker_credential":
        cred_store = ctx.get("cred_store", "")
        if cred_store:
            return ExposureTier.ROTATE, (
                "Credenciais Docker no keychain do sistema — rotacionar por precaução."
            )
        return ExposureTier.ROTATE, "Credenciais Docker encontradas."

    if ctype == "npm_token":
        return ExposureTier.ROTATE, "Token npm sem acesso de publicação confirmado."

    # ── AUDIT ─────────────────────────────────────────────────────────────────

    if ctype == "env_secret":
        return ExposureTier.AUDIT, (
            "Variável de ambiente passou pelo filtro de falso positivo — provavelmente um segredo real."
        )

    if auth.accessible_resources:
        return ExposureTier.AUDIT, (
            "Autoridade resolvida com recursos acessíveis — auditar atividade não autorizada."
        )

    # ── MONITOR ───────────────────────────────────────────────────────────────

    return ExposureTier.MONITOR, "Nenhum indicador de alto risco correspondeu."


def resolve_all(
    items: list[InventoryItem],
    collection: dict,
    resolve_online: bool,
) -> list[InventoryItem]:
    for item in items:
        item.authority = resolve_single(item, resolve_online)
        tier, reason = assign_tier(item)
        item.tier = tier
        # Preserve window-defaulted note from inventory step if present
        if item.tier_reason:
            item.tier_reason = reason + " " + item.tier_reason
        else:
            item.tier_reason = reason

    return items
