# -*- coding: utf-8 -*-
from __future__ import annotations

import ipaddress
import os
from datetime import datetime, timezone

from models import CorrelationEvidence, InventoryItem

_KNOWN_GOOD_HOSTS = frozenset({
    "github.com", "api.github.com",
    "registry.npmjs.org", "npmjs.org",
    "pypi.org", "files.pythonhosted.org",
    "objects.githubusercontent.com",
    "codeload.github.com",
})

_SUSPICIOUS_PARENT_IMAGES = frozenset({"node.exe", "npm", "Code.exe", "python", "python3"})
_SUSPICIOUS_CHILD_IMAGES = frozenset({"node.exe", "python.exe", "powershell.exe", "cmd.exe"})


def _basename(path: str) -> str:
    """Extract filename from path regardless of separator origin.

    Sysmon events come from Windows hosts (backslash separators) but the engine
    may run on Linux or macOS (forward slash). os.path.basename alone is
    insufficient — on Linux, basename('C:\\Windows\\node.exe') returns the full
    string unchanged, so process names are never matched.
    """
    return path.replace("\\", "/").split("/")[-1].lower()


def _is_rfc1918(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private
    except ValueError:
        return False


def _parse_dt(s: str) -> datetime:
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return datetime.min.replace(tzinfo=timezone.utc)


def _within_window(event_time: str, window_start: str) -> bool:
    return _parse_dt(event_time) >= _parse_dt(window_start)


def _build_evidence(collection: dict, incident_window_start: str) -> CorrelationEvidence:
    events = collection.get("sysmon_events")
    if events is None:
        return CorrelationEvidence()

    suspicious_processes: list[str] = []
    network_egress: list[dict] = []
    file_events: list[dict] = []

    for event in events:
        # SysmonEvent schema: {event_id, time_utc, computer, fields: {Name: Value}}
        event_id = event.get("event_id")
        timestamp = event.get("time_utc", "")
        fields = event.get("fields") or {}

        if event_id == 1:
            parent = fields.get("ParentImage", "")
            child = fields.get("Image", "")
            parent_base = _basename(parent)
            child_base = _basename(child)
            if (
                any(p.lower() in parent_base for p in _SUSPICIOUS_PARENT_IMAGES)
                and any(c.lower() in child_base for c in _SUSPICIOUS_CHILD_IMAGES)
                and _within_window(timestamp, incident_window_start)
            ):
                suspicious_processes.append(f"{parent} → {child}")

        elif event_id == 3:
            image = fields.get("Image", "")
            image_base = _basename(image)
            dest_ip = fields.get("DestinationIp", "")
            dest_host = fields.get("DestinationHostname", "")
            if (
                any(p.lower() in image_base for p in ("node.exe", "python.exe", "code.exe"))
                and _within_window(timestamp, incident_window_start)
                and dest_ip
                and not _is_rfc1918(dest_ip)
                and dest_host not in _KNOWN_GOOD_HOSTS
            ):
                network_egress.append({"image": image, "dest_ip": dest_ip, "dest_host": dest_host, "timestamp": timestamp})

        elif event_id == 11:
            target_path = fields.get("TargetFilename", "")
            if (
                _within_window(timestamp, incident_window_start)
                and any(marker in target_path.lower() for marker in (".ssh", "github cli", ".aws", ".npm"))
            ):
                file_events.append({"path": target_path, "timestamp": timestamp})

    prop = collection.get("propagation") or {}
    propagation_active = bool(
        prop.get("runner_registrations")
        or prop.get("workflow_injections")
        or prop.get("npm_publish")
        or prop.get("suspicious_repos")
    )

    return CorrelationEvidence(
        suspicious_processes=suspicious_processes,
        network_egress_events=network_egress,
        file_events_near_credentials=file_events,
        propagation_active=propagation_active,
    )


def correlate(
    items: list[InventoryItem],
    collection: dict,
    incident_window_start: str,
) -> list[InventoryItem]:
    sysmon_available = collection.get("sysmon_events") is not None
    evidence = _build_evidence(collection, incident_window_start)

    no_telemetry_note = (
        "Sysmon indisponível neste host. Correlação de telemetria ignorada. "
        "Aplicar tier REVOGAR AGORA a todas as credenciais de alta autoridade independentemente."
    )

    for item in items:
        score = 0
        notes: list[str] = []

        if not sysmon_available:
            item.correlation_score = 0
            item.correlation_notes = [
                no_telemetry_note,
                "Score de correlação é heurístico. Score 0 não isenta esta credencial.",
            ]
            continue

        if evidence.suspicious_processes:
            score += 1
            notes.append("Atividade de processo suspeito detectada na janela do incidente.")

        if evidence.network_egress_events:
            score += 1
            notes.append("Eventos de rede de saída de processos suspeitos na janela.")

        if evidence.file_events_near_credentials:
            # Check if any file event is near this credential's paths.
            # Normalize separators: credential paths from a Windows host use backslashes
            # but the engine may run on Linux/macOS.
            cred_dirs = {
                p.replace("\\", "/").rsplit("/", 1)[0].lower()
                for p in item.paths
            }
            near = any(
                any(cd in ev.get("path", "").replace("\\", "/").lower() for cd in cred_dirs)
                for ev in evidence.file_events_near_credentials
            )
            if near:
                score += 1
                notes.append("Eventos de sistema de arquivos próximos ao caminho da credencial na janela.")

        if evidence.propagation_active:
            score += 1
            notes.append("Evidência de propagação encontrada — máquina provavelmente usada como fonte.")

        notes.append("Score de correlação é heurístico. Score 0 não isenta esta credencial.")

        item.correlation_score = score
        item.correlation_notes = notes

    return items
