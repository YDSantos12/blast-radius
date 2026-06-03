# Laboratório BLAST-RADIUS — Teste com Malware Real

## Filosofia do laboratório

Este laboratório utiliza amostras reais das campanhas Shai-Hulud 2.0
e GlassWorm em uma VM isolada — não scripts de simulação sintética.

Isso produz:
- Telemetria Sysmon real gerada pelo comportamento do malware
- Artefatos forenses reais nos paths corretos com timestamps reais
- Score de correlação funcionando com evidência genuína
- Uma Burn List construída a partir de incidente real, não simulado

## Requisitos da VM

Hypervisor: VirtualBox ou VMware Workstation
SO: Windows 11 (ISO limpa)
RAM: 4 GB mínimo
Disco: 60 GB
Rede: HOST-ONLY adaptador — sem acesso à internet externa
      O host não deve ter pasta compartilhada com a VM durante infecção

## Software a instalar na VM (antes do snapshot limpo)

- VS Code (com auto-update de extensões HABILITADO — necessário para GlassWorm)
- Node.js LTS + npm
- Python 3.10+ + pip
- Git for Windows
- GitHub CLI (gh)
- Sysmon64 com config de alta cobertura:
  Recomendado: config do Olaf Hartong (sysmon-modular)
  https://github.com/olafhartong/sysmon-modular
- Wazuh agent (opcional — para centralizar logs)

## Credenciais dummy a plantar antes da infecção

Estas credenciais são fake mas estruturalmente válidas — dão ao
malware algo para "roubar" e tornam a Burn List demonstrável:

**~/.npmrc**
```
//registry.npmjs.org/:_authToken=npm_DEMO000000000000000000000000000000000
```

**~/.aws/credentials**
```
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

**~/.ssh/id_ed25519** — gerar par sem passphrase:
```
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ""
ssh-keyscan github.com >> ~/.ssh/known_hosts
```

**Git config com PAT fake na remote URL:**
```
git init ~/demo-repo
cd ~/demo-repo
git remote add origin https://ghp_DEMO0000000000000000000000000000000000@github.com/demo/repo.git
```

**Variável de ambiente** — adicionar ao perfil do usuário:
```
DEMO_API_KEY=sk-demo-0000000000000000000000000000000000000000
```

## Snapshot limpo

Antes de qualquer infecção:

```
VirtualBox: Máquina → Tirar Snapshot → "BASE_LIMPA_PRE_INFECCAO"
```

Sempre voltar a este snapshot antes de um novo teste.

## Fontes para as amostras

### Shai-Hulud 2.0

Os pacotes npm comprometidos foram documentados com versões e hashes
exatos nos seguintes advisories públicos:

- Datadog Security Labs:
  https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/
- Zscaler ThreatLabz:
  https://www.zscaler.com/blogs/security-research/shai-hulud-v2-poses-risk-npm-supply-chain
- Arctic Wolf:
  https://arcticwolf.com/resources/blog/shai-hulud-malware-targets-numerous-npm-packages-second-wave-npm-supply-chain-attack/

Versões comprometidas documentadas incluem pacotes do AsyncAPI,
PostHog, Browserbase e Postman — hashes disponíveis nos advisories.
Instalar a versão comprometida específica via:

```
npm install <package>@<compromised-version>
```

MalwareBazaar (bazaar.abuse.ch):
Buscar por: `shai-hulud`, `sha1hulud`
Tag: `supply-chain`

### GlassWorm

Koi Security publicou IoCs completos incluindo nomes das extensões
comprometidas e hashes:
https://www.truesec.com/hub/blog/glassworm-self-propagating-vscode-extension

Extensões comprometidas podem ser instaladas via VSIX da versão
específica se disponíveis no arquivo do Open VSX Registry.

any.run sandbox:
Buscar: `threat_name:glassworm`
Filtrar por amostras com análise completa disponível

## Procedimento de infecção

1. Verificar que a VM está em snapshot `BASE_LIMPA_PRE_INFECCAO`
2. Confirmar que a rede está em HOST-ONLY (sem internet)
3. Transferir a amostra via pasta compartilhada TEMPORÁRIA
   (desabilitar compartilhamento após transferência)
4. Executar a amostra no contexto do usuário (não administrador):
   - Para Shai-Hulud: `npm install <package>@<version>`
   - Para GlassWorm: instalar extensão VSIX comprometida no VS Code
5. Aguardar execução completa (2–5 minutos)
6. Desabilitar rede da VM imediatamente após execução

## Executar o coletor na VM infectada

Transferir o binário para a VM via pasta compartilhada APÓS
desabilitar a rede:

```
.\blast-radius-collector-windows-amd64.exe -verbose -window <timestamp_infeccao>
```

O timestamp da janela deve ser o momento da instalação do pacote
ou da ativação da extensão.

Transferir o `collection.json` gerado para o host para análise.

## Analisar na máquina do analista (host)

```
cd engine
python main.py analyze ..\vm-collections\collection-<hostname>-<timestamp>.json \
  --window-start <timestamp_infeccao>
```

## O que esperar na Burn List

**Com Shai-Hulud 2.0 real:**
- npm token → REVOGAR AGORA
- AWS credentials → REVOGAR AGORA
- SSH key → REVOGAR AGORA
- GitHub token → REVOGAR AGORA
- Cache TruffleHog em `~/.truffler-cache/` → Propagação ALTO
- Runner SHA1HULUD → Propagação CRÍTICO
- Workflow `discussion.yaml` → Propagação CRÍTICO
- Repos de exfil com padrão "Sha1-Hulud" → Propagação CRÍTICO
- Correlação Sysmon: `node.exe` → network egress → score elevado

**Com GlassWorm real:**
- npm/GitHub/OpenVSX tokens → REVOGAR AGORA
- Extensão com Unicode invisível → detectada no inventário VS Code
- Run keys HKCU/HKLM adicionadas → sistema captura
- `os.node` / `darwin.node` → artefatos no sistema de arquivos
- Conexões Solana blockchain → Sysmon EventID 3

## Iteração da ferramenta

Após cada teste com amostra real, comparar o `collection.json`
com os IoCs publicados nos advisories para verificar:

- O coletor encontrou todos os artefatos esperados?
- Algum path de credencial ficou fora do inventário?
- O engine classificou os tiers corretamente?
- Os artefatos de propagação foram detectados?

Qualquer gap encontrado vira uma issue no GitHub e um fix
nas definitions YAML ou no código do coletor.
Este é o processo correto de desenvolvimento de ferramenta forense:
iteração contra evidência real.

## Nota de segurança

A VM deve permanecer isolada durante toda a infecção.
Nunca executar amostras de malware em máquina host ou em VM
com acesso à internet ou à rede corporativa.
Sempre trabalhar a partir do snapshot limpo para cada novo teste.
O binário do coletor é read-only — não modifica nenhum arquivo
na VM além do `collection.json` de saída.
