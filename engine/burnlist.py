# -*- coding: utf-8 -*-
from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from models import (
    AuthorityResult,
    BurnList,
    ExposureTier,
    InventoryItem,
    PropagationReport,
    ResolutionMethod,
)

DISCLAIMER = (
    "BLAST-RADIUS adota o princípio assume-breach do modelo Zero Trust "
    "(NIST SP 800-207): tudo que era acessível ao processo do usuário "
    "comprometido é tratado como exposto, independentemente de haver "
    "evidência de exfiltração. A revogação priorizada de credenciais "
    "alinha-se à fase de contenção do NIST SP 800-61 (Incident Response). "
    "A ausência de evidências não isenta uma credencial. Os scores de correlação são indicadores "
    "heurísticos derivados da telemetria disponível — score 0 não indica "
    "segurança. Todas as credenciais acessíveis ao processo do usuário "
    "comprometido devem ser tratadas como expostas até serem revogadas. "
    "Este relatório foi gerado exclusivamente para uso em resposta a incidentes."
)


def _sort_key(item: InventoryItem) -> tuple:
    return (-item.correlation_score, item.found_at, item.credential_type)


def _make_audit_item(source_item: InventoryItem) -> InventoryItem:
    """Synthetic InventoryItem representing resources to audit post-revocation.

    These are not credentials themselves — they are the blast radius of a
    REVOKE_NOW credential. The analyst must check them for unauthorized changes
    within the incident window.
    """
    audit_id = hashlib.sha256(("audit:" + source_item.id).encode()).hexdigest()
    return InventoryItem(
        id=audit_id,
        credential_type="audit_target",
        display_name=f"Alvo de auditoria — recursos acessíveis via {source_item.display_name}",
        paths=list(source_item.authority.accessible_resources),
        value_redacted="N/A",
        value_hash="",
        found_at=source_item.found_at,
        context={"source_credential_id": source_item.id},
        authority=AuthorityResult(
            method=ResolutionMethod.SKIPPED,
            resolved=False,
            display=f"Verificar atividade não autorizada dentro da janela do incidente.",
        ),
        tier=ExposureTier.AUDIT,
        tier_reason=(
            f"Recursos acessíveis da credencial REVOGAR AGORA '{source_item.display_name}' — "
            "auditar alterações não autorizadas na janela do incidente."
        ),
        revocation_url="",
        revocation_command="",
    )


def build_burnlist(
    items: list[InventoryItem],
    propagation: PropagationReport,
    collection: dict,
    resolve_online: bool,
) -> BurnList:
    revoke_now = sorted([i for i in items if i.tier == ExposureTier.REVOKE_NOW], key=_sort_key)
    rotate = sorted([i for i in items if i.tier == ExposureTier.ROTATE], key=_sort_key)
    audit_items = sorted([i for i in items if i.tier == ExposureTier.AUDIT], key=_sort_key)
    monitor = sorted(
        [i for i in items if i.tier in (ExposureTier.MONITOR, ExposureTier.UNKNOWN)],
        key=_sort_key,
    )

    # Append synthetic AUDIT entries for resources reachable via REVOKE_NOW credentials
    seen_audit_ids: set[str] = {i.id for i in audit_items}
    for rn_item in revoke_now:
        if rn_item.authority.accessible_resources:
            synthetic = _make_audit_item(rn_item)
            if synthetic.id not in seen_audit_ids:
                audit_items.append(synthetic)
                seen_audit_ids.add(synthetic.id)

    resolution_method = ResolutionMethod.ONLINE if resolve_online else ResolutionMethod.OFFLINE

    return BurnList(
        revoke_now=revoke_now,
        rotate=rotate,
        audit=audit_items,
        monitor=monitor,
        propagation=propagation,
        meta=collection.get("meta") or {},
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        incident_window_start=collection.get("meta", {}).get("incident_window_start", ""),
        resolution_method=resolution_method,
        total_credentials=len(items),
        disclaimer=DISCLAIMER,
    )
