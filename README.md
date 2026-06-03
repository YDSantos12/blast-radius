# BLAST-RADIUS

Inventário de credenciais e plano de revogação para estações de desenvolvimento comprometidas.

Às 3h da manhã, quando um desenvolvedor executa um pacote npm malicioso ou instala uma extensão VS Code comprometida, o host está comprometido antes que qualquer alerta dispare. EDRs registram o que executou — processo, hash, linha de comando. Nenhum entrega o que o analista precisa: quais credenciais o usuário tinha, o que cada uma desbloqueia externamente, e em que ordem revogar. Analistas passam entre 2 e 6 horas reconstruindo esse inventário manualmente enquanto os tokens continuam válidos.

## O que faz

O collector enumera cada credencial acessível ao usuário comprometido — o que é, onde está, o que desbloqueia. O engine produz a Burn List: relatório HTML priorizado com passos exatos de revogação por credencial, mais detecção de propagação caso a máquina tenha se tornado fonte de novos comprometimentos.

O inventário cobre:

- tokens npm
- GitHub PATs e tokens OAuth
- chaves SSH privadas
- credenciais AWS IAM
- tokens Azure e GCP
- tokens PyPI
- credenciais de registros Docker
- segredos de extensões VS Code (state.vscdb)
- variáveis de ambiente
- Windows Credential Manager
- URLs remotas de repositórios git com tokens embutidos

## A Burn List

A Burn List é o output do engine — um arquivo HTML que abre em qualquer browser, sem dependência de conexão com internet. Cada credencial recebe um dos quatro tiers abaixo, ordenado por urgência.

- **REVOGAR AGORA** — credenciais de alta autoridade a revogar antes de continuar a investigação: GitHub PATs, chaves SSH sem passphrase com conexões ativas, chaves AWS IAM de longo prazo, tokens npm com acesso de publicação.
- **ROTACIONAR** — autoridade média. Rotacionar na mesma sessão de IR.
- **AUDITAR** — verificar repositórios e pipelines associados por alterações não autorizadas dentro da janela do incidente.
- **MONITORAR** — baixo risco ou sem autoridade externa resolvível no v0.1.

Se a máquina publicou um pacote, registrou um self-hosted runner do GitHub Actions, injetou um arquivo de workflow, ou criou repositórios de exfiltração — o relatório sinaliza em seção separada. Cada ocorrência inclui severidade e ação necessária. Isso é relevante porque a máquina comprometida pode ser a origem da próxima onda.

O BLAST-RADIUS não tenta provar exfiltração. Tudo acessível ao processo do usuário comprometido é tratado como exposto, em conformidade com o modelo assume-breach do NIST SP 800-61.

## Uso

### Coleta (na máquina comprometida)

Transferir o binário para o host isolado. Executar como o usuário comprometido — **não** como SYSTEM ou administrador. Stores de credencial são escopados ao usuário; executar como SYSTEM produz coleta incompleta.

A flag `-window` recebe o timestamp de início da janela do incidente em ISO 8601 UTC. Se omitida, o padrão é 24h atrás — corrigir com o horário real do incidente antes de iniciar.

```powershell
# Windows
.\blast-radius-collector-windows-amd64.exe -verbose -window 2026-06-01T03:00:00Z
```

```bash
# macOS (v0.2)
./blast-radius-collector-darwin-amd64 -verbose -window 2026-06-01T03:00:00Z
```

Transferir o arquivo `collection-<hostname>-<timestamp>.json` para a máquina do analista via canal criptografado. O arquivo contém todas as variáveis de ambiente em texto claro.

### Análise (na máquina do analista)

```bash
pip install -r engine/requirements.txt
cd engine
python main.py analyze ../path/to/collection.json
```

Para sobrescrever a janela do incidente definida na coleta:

```bash
python main.py analyze ../path/to/collection.json \
  --window-start 2026-06-01T03:00:00Z
```

O resultado é `burnlist-<hostname>-<timestamp>.html` no diretório atual.

## Deploy

**Acesso físico.** Pendrive com o binário. Executar localmente como o usuário comprometido.

**EDR Live Response.** A maioria dos EDRs enterprise executa binários remotamente pelo canal do agente: CrowdStrike RTR, Microsoft Defender Live Response, SentinelOne RSO, Kaspersky Execution Task. Fazer upload do binário, executar como o usuário, recuperar o JSON pelo mesmo canal. Adicionar o hash do binário às exclusões do EDR antes da execução — enumeração de credenciais dispara detecções comportamentais.

**WinRM / SSH.** Se o host ainda não está isolado e o gerenciamento remoto está disponível, copiar e executar via `Invoke-Command` ou `ssh`.

Cada coleta inclui `meta.collector_hash` — SHA-256 do binário que executou. Verificar contra o hash publicado na release antes de confiar na coleta.

## Compilação

Para compilar a partir do código-fonte:

### Collector (Go 1.22+)

```bash
git clone https://github.com/<user>/blast-radius
cd blast-radius/collector
go mod tidy
```

```powershell
# Windows
$env:GOOS="windows"; $env:GOARCH="amd64"
go build -ldflags="-s -w" -trimpath `
  -o dist/blast-radius-collector-windows-amd64.exe ./cmd/collector
```

```bash
# macOS (Intel)
GOOS=darwin GOARCH=amd64 \
go build -ldflags="-s -w" -trimpath \
  -o dist/blast-radius-collector-darwin-amd64 ./cmd/collector

# macOS (Apple Silicon)
GOOS=darwin GOARCH=arm64 \
go build -ldflags="-s -w" -trimpath \
  -o dist/blast-radius-collector-darwin-arm64 ./cmd/collector
```

### Engine (Python 3.10+)

```bash
cd engine
pip install -r requirements.txt
python main.py analyze --help
```

## Limitações

**A coleta não prova exfiltração.** O BLAST-RADIUS assume que tudo acessível ao usuário foi lido. Provar que um arquivo específico foi lido por um processo específico não é possível no Windows sem telemetria de file-read — não capturada por configurações padrão do Sysmon. A postura assume-breach é intencional e alinhada ao NIST SP 800-61.

**Resolução de autoridade online não está implementada no v0.1.** O collector não persiste valores brutos de token — valores redatados não podem ser usados para chamar APIs do GitHub ou npm. Tokens GitHub recebem tier REVOGAR AGORA por padrão, independente do escopo real. Resolução online está planejada para o v0.2.

**Fronteira de confiança do collection.json.** O engine confia no collection.json recebido. Um arquivo com campos `context` adulterados — como `has_passphrase: true` em uma chave SSH sem passphrase — afeta diretamente a atribuição de tier. Em um fluxo legítimo de IR isso não é preocupação. Verificar credenciais de alto valor independentemente se a integridade da coleta estiver em dúvida.

**Windows Credential Manager e credenciais de browser.** Credenciais protegidas por DPAPI requerem a sessão do usuário para descriptografar. O collector registra a presença mas não lê os valores sem a chave de descriptografia. Inspeção manual é necessária para esses stores.

**Suporte a macOS está no v0.2.** O collector compila para darwin mas paths específicos do macOS — Keychain e storage nativo do VS Code — não estão implementados no v0.1.

## Contexto

Em novembro de 2025, o worm Shai-Hulud 2.0 comprometeu pacotes npm com scripts `postinstall` que executavam TruffleHog contra o diretório home do desenvolvedor. Os segredos encontrados eram exfiltrados para repositórios públicos com nomes no padrão "Sha1-Hulud: The Second Coming". O host era então registrado como self-hosted runner do GitHub Actions com o nome SHA1HULUD. O BLAST-RADIUS detecta artefatos de runner, padrões de nomes de repositórios de exfiltração e presença de cache do TruffleHog.

Entre outubro de 2025 e 2026, o worm GlassWorm se propagou via extensões VS Code. Caracteres Unicode invisíveis escondiam um loader de segundo estágio. O C2 operava via blockchain Solana e Google Calendar. Persistência via Run keys do Windows. O BLAST-RADIUS inventaria o estado de extensões VS Code e modificações em Run keys.

---

MIT

O BLAST-RADIUS é um auxílio forense, não um instrumento legal. Os tiers da Burn List representam avaliação de risco operacional sob um modelo assume-breach conforme o NIST SP 800-61 — não são prova de comprometimento ou exfiltração. As decisões de revogação são responsabilidade do analista e do incident commander. Não execute o collector em hosts sem autorização.
