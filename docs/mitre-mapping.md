# Mapeamento ATT&CK

Artefatos detectados pelo BLAST-RADIUS e TTPs correspondentes
do MITRE ATT&CK.

## Detecção de credenciais expostas

| Artefato | Técnica ATT&CK | ID |
|---|---|---|
| npm token em .npmrc | Unsecured Credentials: Credentials In Files | T1552.001 |
| GitHub PAT via credential helper | Unsecured Credentials: Credentials In Files | T1552.001 |
| Chave SSH privada sem passphrase | Unsecured Credentials: Private Keys | T1552.004 |
| AWS credentials em ~/.aws | Unsecured Credentials: Credentials In Files | T1552.001 |
| Secrets em variáveis de ambiente | Unsecured Credentials: Environment Variables | T1552.007 |
| Tokens em VS Code state.vscdb | Unsecured Credentials: Credentials In Files | T1552.001 |

## Detecção de propagação

| Artefato | Técnica ATT&CK | ID |
|---|---|---|
| Runner SHA1HULUD registrado | Valid Accounts: Cloud Accounts | T1078.004 |
| Workflow discussion.yaml injetado | Event Triggered Execution: GitHub Actions | T1053.007 |
| Cache TruffleHog (~/.truffler-cache) | Credential Access: Credentials from Password Stores | T1555 |
| Git hooks não-padrão | Event Triggered Execution: Unix Shell Configuration Modification | T1546.004 |
| npm package publicado na janela | Supply Chain Compromise: Compromise Software Supply Chain | T1195.002 |

## Campanhas mapeadas

| Campanha | Fase | TTPs primários |
|---|---|---|
| Shai-Hulud 2.0 | Credential Access | T1552.001, T1555 |
| Shai-Hulud 2.0 | Persistence | T1053.007, T1078.004 |
| Shai-Hulud 2.0 | Lateral Movement | T1195.002 |
| GlassWorm | Persistence | T1547.001 (Run keys) |
| GlassWorm | Credential Access | T1552.001 |
| GlassWorm | Command and Control | T1102 (Web Service — Solana) |
| TrapDoor | Persistence | T1546.004 (git hooks) |
| TrapDoor | Credential Access | T1552.001 |
