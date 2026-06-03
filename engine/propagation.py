# -*- coding: utf-8 -*-
from __future__ import annotations

import os

from models import PropagationFinding, PropagationReport


def _safe_filename(name: str) -> str:
    """Sanitize a filename from collection.json before use in path construction.

    collection.json is untrusted input. A weaponized file could include hook names
    or workflow filenames like '../../.ssh/authorized_keys' to mislead the analyst
    via crafted paths in the HTML report.
    """
    safe = os.path.basename(name.replace("\\", "/"))
    return safe if safe else "unknown"


def _runner_path(artifact) -> str:
    """Extract the path string from a runner artifact dict or bare string."""
    if isinstance(artifact, str):
        return artifact
    return artifact.get("path", artifact.get("name", str(artifact)))


def _runner_base_dir(path: str, artifact_type: str = "") -> str:
    """Normalise slashes and return the parent directory used as grouping key."""
    normalized = path.replace("\\", "/")
    if artifact_type == "runner_dir":
        return normalized
    return os.path.dirname(normalized) or normalized


def _runner_has_sha1hulud(artifact) -> bool:
    if isinstance(artifact, str):
        return "sha1hulud" in artifact.lower()
    return any("sha1hulud" in str(v).lower() for v in artifact.values())


def analyze_propagation(collection: dict, definitions: dict) -> PropagationReport:
    findings: list[PropagationFinding] = []
    prop_defs = definitions.get("propagation") or {}
    meta = collection.get("meta") or {}
    incident_window_start = meta.get("incident_window_start", "")

    git_data = collection.get("git") or {}
    prop_data = collection.get("propagation") or {}

    # 1. Runner registration
    runner_artifacts = git_data.get("runner_artifacts") or []
    runner_registrations = prop_data.get("runner_registrations") or []
    runner_defn = prop_defs.get("runner_registration", {})

    # The collector emits one entry per field of the .runner config file from
    # git.runner_artifacts (runner_dir, runner_config, suspicious_runner_name)
    # and a separate entry in propagation.runner_registrations. All entries for
    # the same runner share the same base directory. Combine both sources and
    # group by base directory to produce exactly one finding per runner.
    runner_groups: dict[str, list] = {}
    for artifact in list(runner_artifacts) + list(runner_registrations):
        path = _runner_path(artifact)
        atype = artifact.get("type", "") if isinstance(artifact, dict) else ""
        base = _runner_base_dir(path, atype)
        runner_groups.setdefault(base, []).append(artifact)

    for base_dir, artifacts in runner_groups.items():
        best_path = max((_runner_path(a) for a in artifacts), key=len, default=base_dir)
        is_shai_hulud = any(_runner_has_sha1hulud(a) for a in artifacts)
        ref = runner_defn.get("reference", "")
        desc_name = os.path.basename(base_dir.replace("\\", "/")) or base_dir
        if is_shai_hulud:
            ref = "Shai-Hulud 2.0 TTP — runner auto-hospedado como backdoor persistente"
            desc_name = f"SHA1HULUD em {best_path}"
        findings.append(PropagationFinding(
            finding_type="runner_registration",
            severity="CRITICAL",
            path_or_url=best_path,
            timestamp=incident_window_start,
            description=f"Runner auto-hospedado do GitHub Actions registrado: {desc_name}",
            recommended_action=runner_defn.get("recommended_action", "Remover o runner imediatamente."),
            reference=ref,
        ))

    # 2. Workflow injection
    workflow_defn = prop_defs.get("workflow_injection", {})
    workflow_injections = prop_data.get("workflow_injections") or []

    for injection in workflow_injections:
        path = injection if isinstance(injection, str) else injection.get("path", str(injection))
        ts = "" if isinstance(injection, str) else injection.get("timestamp", incident_window_start)
        findings.append(PropagationFinding(
            finding_type="workflow_injection",
            severity="CRITICAL",
            path_or_url=path,
            timestamp=ts or incident_window_start,
            description=f"Arquivo de workflow suspeito detectado: {path}",
            recommended_action=workflow_defn.get("recommended_action", "Remover o arquivo de workflow imediatamente."),
            reference=workflow_defn.get("reference", ""),
        ))

    # Check repos for discussion.yaml or workflows created within incident window
    repos = git_data.get("repos") or []
    for repo in repos:
        repo_path = repo.get("path", "")
        for wf in (repo.get("workflow_files") or []):
            wf_name = wf if isinstance(wf, str) else wf.get("name", str(wf))
            wf_created = "" if isinstance(wf, str) else wf.get("created_at", "")
            is_suspicious = (
                os.path.basename(wf_name).lower() == "discussion.yaml"
                or (wf_created and wf_created >= incident_window_start)
            )
            if is_suspicious:
                safe_wf = _safe_filename(wf_name)
                path_str = f"{repo_path}/.github/workflows/{safe_wf}"
                findings.append(PropagationFinding(
                    finding_type="workflow_injection",
                    severity="CRITICAL",
                    path_or_url=path_str,
                    timestamp=wf_created or incident_window_start,
                    description=f"Arquivo de workflow suspeito detectado: {path_str}",
                    recommended_action=workflow_defn.get("recommended_action", "Remover o arquivo de workflow imediatamente."),
                    reference=workflow_defn.get("reference", ""),
                ))

    # 3. npm publish
    npm_defn = prop_defs.get("npm_publish", {})
    npm_publishes = prop_data.get("npm_publish") or []
    for pub in npm_publishes:
        if isinstance(pub, str):
            pkg, version = pub, ""
        else:
            pkg = pub.get("package", str(pub))
            version = pub.get("version", "")
        desc = f"Pacote npm publicado durante a janela do incidente: {pkg}"
        if version:
            desc += f"@{version}"
        findings.append(PropagationFinding(
            finding_type="npm_publish",
            severity="HIGH",
            path_or_url=f"https://www.npmjs.com/package/{pkg}",
            timestamp=incident_window_start,
            description=desc,
            recommended_action=npm_defn.get("recommended_action", "Deprecar ou despublicar imediatamente."),
            reference=npm_defn.get("reference", ""),
        ))

    # 4. Exfil repos
    exfil_defn = prop_defs.get("exfil_repo", {})
    suspicious_repos = prop_data.get("suspicious_repos") or []
    for repo_entry in suspicious_repos:
        url = repo_entry if isinstance(repo_entry, str) else repo_entry.get("url", str(repo_entry))
        findings.append(PropagationFinding(
            finding_type="exfil_repo",
            severity="HIGH",
            path_or_url=url,
            timestamp=incident_window_start,
            description=f"Repositório suspeito com possível dado exfiltrado: {url}",
            recommended_action=exfil_defn.get("recommended_action", "Excluir imediatamente."),
            reference=exfil_defn.get("reference", ""),
        ))

    # 5. Git hooks
    hook_defn = prop_defs.get("git_hook", {})
    for repo in repos:
        repo_path = repo.get("path", "")
        for hook in (repo.get("non_default_hooks") or []):
            hook_name = hook if isinstance(hook, str) else hook.get("name", str(hook))
            safe_hook = _safe_filename(hook_name)
            findings.append(PropagationFinding(
                finding_type="git_hook",
                severity="MEDIUM",
                path_or_url=os.path.join(repo_path, ".git", "hooks", safe_hook),
                timestamp=incident_window_start,
                description=f"Hook git não-padrão em {repo_path}: {safe_hook}",
                recommended_action=hook_defn.get("recommended_action", "Inspecionar o conteúdo do hook."),
                reference=hook_defn.get("reference", ""),
            ))

    is_source = any(f.severity in ("CRITICAL", "HIGH") for f in findings)
    needs_notification = any(f.finding_type in ("npm_publish", "runner_registration") for f in findings)

    if findings:
        n = len(findings)
        summary = (
            f"{n} ocorrência(s) de propagação detectada(s). A máquina pode ser fonte de comprometimento adicional. "
            "Consulte os achados para as ações necessárias."
        )
    else:
        summary = "Nenhum indicador de propagação detectado."

    return PropagationReport(
        is_propagation_source=is_source,
        downstream_notification_required=needs_notification,
        findings=findings,
        summary=summary,
    )
