# -*- coding: utf-8 -*-
from __future__ import annotations

import dataclasses
import os
import sys
from datetime import datetime

import jinja2

from models import BurnList


def _datetime_br(value: str) -> str:
    """ISO 8601 → '02/06/2026 às 18:56 UTC'"""
    if not value:
        return value
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt.strftime("%d/%m/%Y às %H:%M UTC")
    except (ValueError, AttributeError):
        return value


def _tier_label(tier) -> str:
    key = tier.value if hasattr(tier, "value") else str(tier)
    return {
        "REVOKE_NOW": "REVOGAR AGORA",
        "ROTATE": "ROTACIONAR",
        "AUDIT": "AUDITAR",
        "MONITOR": "MONITORAR",
        "UNKNOWN": "DESCONHECIDO",
    }.get(str(key).upper(), str(key))


def _tier_color(tier) -> str:
    key = tier.value if hasattr(tier, "value") else str(tier)
    return {
        "REVOKE_NOW": "revoke",
        "ROTATE": "rotate",
        "AUDIT": "audit",
        "MONITOR": "monitor",
        "UNKNOWN": "monitor",
    }.get(str(key).upper(), "monitor")


def _safe_url(url: str) -> str:
    # collection.json is untrusted. Block javascript:/data:/vbscript: scheme
    # injection so a crafted revocation_url cannot execute code when clicked.
    if not url:
        return ""
    stripped = url.strip().lower()
    if stripped.startswith(("javascript:", "data:", "vbscript:")):
        return "#"
    return url


def render(burnlist: BurnList, output_path: str) -> None:
    template_dir = os.path.normpath(
        os.path.join(os.path.dirname(__file__), "..", "templates")
    )
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(template_dir),
        autoescape=jinja2.select_autoescape(["html"]),
    )
    env.filters["datetime_br"] = _datetime_br
    env.filters["tier_label"] = _tier_label
    env.filters["tier_color"] = _tier_color
    env.filters["safe_url"] = _safe_url
    template = env.get_template("burnlist.html")

    ctx = dataclasses.asdict(burnlist)
    html = template.render(**ctx)

    tmp_path = output_path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(html)
    os.replace(tmp_path, output_path)

    print(f"Burn List gerada em: {output_path}", file=sys.stderr)
