# -*- coding: utf-8 -*-
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ExposureTier(str, Enum):
    REVOKE_NOW = "REVOKE_NOW"
    ROTATE = "ROTATE"
    AUDIT = "AUDIT"
    MONITOR = "MONITOR"
    UNKNOWN = "UNKNOWN"


class ResolutionMethod(str, Enum):
    OFFLINE = "offline"
    ONLINE = "online"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class AuthorityResult:
    method: ResolutionMethod = ResolutionMethod.SKIPPED
    resolved: bool = False
    display: str = ""
    scopes: list[str] = field(default_factory=list)
    accessible_resources: list[str] = field(default_factory=list)
    raw_response: dict = field(default_factory=dict)
    error: str = ""


@dataclass
class InventoryItem:
    id: str
    credential_type: str
    display_name: str
    paths: list[str]
    value_redacted: str
    value_hash: str
    found_at: str
    context: dict
    authority: AuthorityResult = field(default_factory=AuthorityResult)
    tier: ExposureTier = ExposureTier.UNKNOWN
    tier_reason: str = ""
    correlation_score: int = 0
    correlation_notes: list[str] = field(default_factory=list)
    in_incident_window: bool = False
    revocation_url: str = ""
    revocation_command: str = ""


@dataclass
class PropagationFinding:
    finding_type: str
    severity: str
    path_or_url: str
    timestamp: str
    description: str
    recommended_action: str
    reference: str


@dataclass
class PropagationReport:
    is_propagation_source: bool = False
    downstream_notification_required: bool = False
    findings: list[PropagationFinding] = field(default_factory=list)
    summary: str = "No propagation indicators detected."


@dataclass
class CorrelationEvidence:
    suspicious_processes: list[str] = field(default_factory=list)
    network_egress_events: list[dict] = field(default_factory=list)
    file_events_near_credentials: list[dict] = field(default_factory=list)
    propagation_active: bool = False


@dataclass
class BurnList:
    revoke_now: list[InventoryItem]
    rotate: list[InventoryItem]
    audit: list[InventoryItem]
    monitor: list[InventoryItem]
    propagation: PropagationReport
    meta: dict
    generated_at: str
    incident_window_start: str
    resolution_method: ResolutionMethod
    total_credentials: int
    disclaimer: str
