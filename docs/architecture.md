# Arquitetura

## Visão geral

BLAST-RADIUS é composto por dois componentes com um contrato
JSON entre eles.

```
Host comprometido                    Máquina do analista
─────────────────                    ───────────────────
collector (Go)          →            engine (Python)
leitura de artefatos    JSON         análise + decisão
sem modificações        seguro       Burn List HTML
```

## Collector (Go)

Binário estático sem dependências externas. Compila para
Windows e macOS (darwin). Roda no contexto do usuário
comprometido — não requer elevação.

Módulos de coleta:
- credentials: npm, GitHub CLI, SSH, AWS, Azure, PyPI, Docker, env vars
- vscode: extensões, state.vscdb, globalStorage
- git: config, hooks, remote URLs, reflog, runner artifacts
- propagation: npm publish logs, exfil repo patterns, workflow files
- system: registry Run keys, scheduled tasks (Windows)
- sysmon: eventos 1/3/11/13 quando disponível (Windows)

Output: collection-<hostname>-<timestamp>.json
Permissões: 0600 (somente proprietário)

## Engine (Python)

Roda na máquina do analista. Nunca toca o host comprometido.
Recebe o collection.json e produz a Burn List HTML.

Pipeline:
1. inventory.py    — carrega e deduplica credenciais
2. authority.py    — resolve autoridade offline (v0.1) ou online (v0.2)
3. correlation.py  — correlaciona com telemetria Sysmon se disponível
4. propagation.py  — analisa artefatos de propagação
5. burnlist.py     — prioriza em tiers e monta o relatório
6. reporter.py     — renderiza HTML via Jinja2

## Contrato JSON (collection.json)

O schema completo está documentado em CLAUDE.md (arquivo
interno de desenvolvimento, não incluso no repositório).
Os campos principais:

```json
{
  "meta": { "hostname", "username", "os_version",
            "collected_at", "incident_window_start",
            "collector_hash", "window_defaulted" },
  "credentials": [ CredentialItem ],
  "vscode": { "extensions", "state_db_secrets" },
  "git": { "repos", "runner_artifacts" },
  "propagation": { "npm_publish", "suspicious_repos",
                   "workflow_injections", "runner_registrations" },
  "sysmon_events": [ SysmonEvent ] | null,
  "environment": { "env_vars", "registry_run_keys",
                   "scheduled_tasks" }
}
```

## Definições declarativas

Tipos de credencial e padrões de propagação estão em
definitions/ como YAML. Adicionar suporte a um novo tipo
de credencial não requer alteração de código.
