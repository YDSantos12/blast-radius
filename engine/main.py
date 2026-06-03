# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import os
import re
import sys
from datetime import datetime, timezone

import authority
import burnlist as burnlist_mod
import correlation
import inventory as inventory_mod
import loader
import propagation as propagation_mod
import reporter

VERSION = "0.1.0"

# Allowlist for hostname characters in the output filename. Hostname comes from
# collection.json (untrusted), and is used to construct a local file path.
_SAFE_HOSTNAME_RE = re.compile(r'[^A-Za-z0-9_-]')


def _default_out(meta: dict) -> str:
    hostname = meta.get("hostname", "unknown")
    safe_hostname = _SAFE_HOSTNAME_RE.sub('-', hostname)[:64] or "unknown"
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"burnlist-{safe_hostname}-{ts}.html"


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="blast-radius-engine",
        description="BLAST-RADIUS engine — transforms collection.json into a prioritized Burn List.",
    )
    sub = parser.add_subparsers(dest="command")
    analyze = sub.add_parser("analyze", help="Analyze a collection.json file")
    analyze.add_argument("collection_path", help="Path to collection.json")
    analyze.add_argument(
        "--window-start",
        metavar="ISO8601",
        default="",
        help="Override incident window start timestamp (e.g. 2026-01-15T03:00:00Z)",
    )
    analyze.add_argument(
        "--resolve-online",
        action="store_true",
        default=False,
        help=(
            "Ativa resolução de autoridade online para credenciais AWS e Azure "
            "(usa credenciais do ambiente do analista). Tokens GitHub e npm não "
            "podem ser resolvidos online — o coletor não persiste valores brutos "
            "por design de segurança. Limitação conhecida do v0.1."
        ),
    )
    analyze.add_argument(
        "--out",
        metavar="PATH",
        default="",
        help="Output HTML path (default: burnlist-<hostname>-<timestamp>.html)",
    )
    analyze.add_argument(
        "--definitions",
        metavar="PATH",
        default="",
        help="Path to definitions/ directory (default: ../definitions/ relative to engine/)",
    )

    args = parser.parse_args()

    if args.command != "analyze":
        parser.print_help()
        sys.exit(1)

    try:
        _run_analyze(args)
    except PermissionError as e:
        print(f"Erro de permissão: {e}", file=sys.stderr)
        sys.exit(1)
    except (ValueError, FileNotFoundError, OSError) as e:
        print(f"Erro: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("Interrompido.", file=sys.stderr)
        sys.exit(1)


def _run_analyze(args: argparse.Namespace) -> None:
    definitions_dir = args.definitions or os.path.normpath(
        os.path.join(os.path.dirname(__file__), "..", "definitions")
    )

    print(f"BLAST-RADIUS engine v{VERSION}", file=sys.stderr)
    print(f"Coleta: {args.collection_path}", file=sys.stderr)

    collection = loader.load_collection(args.collection_path)
    definitions = loader.load_definitions(definitions_dir)

    meta = collection.get("meta", {})
    window_start = args.window_start or meta.get("incident_window_start", "")
    resolve_online = args.resolve_online

    print(f"Janela do incidente: {window_start}", file=sys.stderr)
    print(f"Resolução de autoridade: {'online' if resolve_online else 'offline'}", file=sys.stderr)

    # [1/5] Inventory
    items, filtered_count = inventory_mod.build_inventory(collection, definitions)
    print(
        f"[1/5] Inventário — {len(items)} credencial(ais) carregada(s), {filtered_count} filtrada(s)",
        file=sys.stderr,
    )

    # [2/5] Authority resolution
    items = authority.resolve_all(items, collection, resolve_online)
    method_label = "online" if resolve_online else "offline"
    print(f"[2/5] Resolução de autoridade ({method_label})", file=sys.stderr)

    # [3/5] Correlation
    sysmon_events = collection.get("sysmon_events")
    sysmon_label = "disponível" if sysmon_events is not None else "indisponível"
    items = correlation.correlate(items, collection, window_start)
    print(f"[3/5] Correlação — sysmon {sysmon_label}", file=sys.stderr)

    # [4/5] Propagation
    prop_report = propagation_mod.analyze_propagation(collection, definitions)
    print(f"[4/5] Análise de propagação — {len(prop_report.findings)} ocorrência(s)", file=sys.stderr)

    # [5/5] Burn List
    bl = burnlist_mod.build_burnlist(items, prop_report, collection, resolve_online)
    print(
        f"[5/5] Burn List — "
        f"REVOGAR_AGORA:{len(bl.revoke_now)} "
        f"ROTACIONAR:{len(bl.rotate)} "
        f"AUDITAR:{len(bl.audit)} "
        f"MONITORAR:{len(bl.monitor)}",
        file=sys.stderr,
    )

    out_path = args.out or _default_out(meta)
    reporter.render(bl, out_path)

    sep = "━" * 42
    print(sep, file=sys.stderr)
    print("BLAST-RADIUS — Análise Concluída", file=sys.stderr)
    print(f"Host:       {meta.get('hostname', 'unknown')}", file=sys.stderr)
    print(f"Burn List:  {out_path}", file=sys.stderr)
    print(sep, file=sys.stderr)
    print(f"REVOGAR AGORA:  {len(bl.revoke_now)} credenciais", file=sys.stderr)
    print(f"ROTACIONAR:     {len(bl.rotate)} credenciais", file=sys.stderr)
    print(f"AUDITAR:        {len(bl.audit)} itens", file=sys.stderr)
    print(f"MONITORAR:      {len(bl.monitor)} credenciais", file=sys.stderr)
    if prop_report.is_propagation_source:
        print(
            "⚠ FONTE DE PROPAGAÇÃO DETECTADA — consulte a Burn List para ações",
            file=sys.stderr,
        )
    print(sep, file=sys.stderr)


if __name__ == "__main__":
    main()
