# Modelo de Ameaça

## Premissa operacional

BLAST-RADIUS assume comprometimento total (assume-breach)
conforme NIST SP 800-61. A ferramenta não tenta provar
exfiltração — assume que tudo acessível ao processo do
usuário comprometido foi lido e potencialmente exfiltrado.

## Campanhas que motivaram o desenvolvimento

### Shai-Hulud 2.0 (novembro de 2025)

Worm npm que comprometia contas de mantenedores e publicava
versões trojanizadas com scripts postinstall. O payload
executava TruffleHog contra o home directory, exfiltrava
segredos para repositórios públicos com nomes no padrão
"Sha1-Hulud: The Second Coming", e registrava o host como
self-hosted runner do GitHub Actions com nome SHA1HULUD.

Referências:
- Datadog Security Labs
- Unit 42 (Palo Alto Networks)
- Microsoft Security Blog (dezembro 2025)

### GlassWorm (outubro 2025 — 2026)

Worm de extensões VS Code que usava caracteres Unicode
invisíveis (Private Use Area) para esconder um loader de
segundo estágio. C2 via blockchain Solana e Google Calendar.
Persistência via Run keys do Windows. Comprometeu ~35.800
máquinas em múltiplas ondas.

Referências:
- Koi Security
- Socket Research
- Aikido Security
- Step Security

## Superfície de ataque da própria ferramenta

### collection.json como vetor

O engine confia no collection.json recebido. Um arquivo
adulterado com campos context manipulados pode afetar
a atribuição de tier. Em fluxo legítimo de IR isso não
é preocupação — a coleta roda sob controle do analista.
Verificar credenciais de alto valor independentemente se
a integridade da coleta estiver em dúvida.

### path_or_url em findings de propagação

Valores de path_or_url são usados apenas para display no
relatório HTML — nenhuma operação de arquivo é executada
sobre eles. Autoescape Jinja2 previne XSS.

Sanitização aplicada:
- Nomes de arquivo (hooks, workflows) passam por
  os.path.basename via _safe_filename() antes de serem
  incorporados a caminhos de display.
- repo_path provém do host comprometido (não confiável)
  e NÃO é sanitizado — um collection.json adulterado
  pode conter caminhos enganosos (ex: ../../etc/passwd).
  Isso afeta apenas o display; nenhuma operação de I/O
  usa esses valores.

### javascript: scheme em URLs

URLs de revogação passam pelo filtro safe_url no Jinja2,
que bloqueia schemes javascript:, data: e vbscript:.

## Fronteiras de confiança

```
CONFIÁVEL:    binário collector (verificar collector_hash)
              engine Python (código auditável)
              definitions YAML (declarativo, versionado)

NÃO CONFIÁVEL: collection.json (dado externo)
               qualquer campo proveniente do host comprometido
```
