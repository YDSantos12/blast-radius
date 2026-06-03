#Requires -Version 5.1

[CmdletBinding()]
param(
    [switch]$Cleanup
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$MANIFEST_PATH = "$env:USERPROFILE\blast-radius-lab-manifest.json"
$HOME_DIR      = $env:USERPROFILE
$NOW           = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")

$ARTIFACTS = [ordered]@{

    ShaiHulud_TruffleHog = @{
        Type        = "directory"
        Path        = "$HOME_DIR\.truffler-cache"
        Description = "Cache do TruffleHog - ferramenta de coleta de segredos usada pelo Shai-Hulud 2.0"
        Campaign    = "Shai-Hulud 2.0"
        Severity    = "HIGH"
        Reference   = "Netskope: bun_environment.js downloads and runs TruffleHog to scan home directory"
    }

    ShaiHulud_TruffleHog_Config = @{
        Type        = "file"
        Path        = "$HOME_DIR\.truffler-cache\config.json"
        Content     = "{`"version`":`"3.0`",`"scan_paths`":[`"~`"],`"last_scan`":`"$NOW`",`"targets_found`":4}"
        Description = "Configuracao do TruffleHog deixada apos varredura de segredos"
        Campaign    = "Shai-Hulud 2.0"
        Severity    = "HIGH"
        Reference   = "Datadog: TruffleHog scans user home directory recursively for secrets"
    }

    ShaiHulud_Runner = @{
        Type        = "directory"
        Path        = "$HOME_DIR\.actions-runner"
        Description = "Diretorio do GitHub Actions Runner registrado pelo Shai-Hulud 2.0"
        Campaign    = "Shai-Hulud 2.0"
        Severity    = "CRITICAL"
        Reference   = "Microsoft Security Blog: bun_environment.js registers self-hosted runner named SHA1HULUD"
    }

    ShaiHulud_Runner_Config = @{
        Type        = "file"
        Path        = "$HOME_DIR\.actions-runner\.runner"
        Content     = "{`"agentName`":`"SHA1HULUD`",`"serverUrl`":`"https://github.com`",`"workFolder`":`"_work`",`"lastChangedAt`":`"$NOW`"}"
        Description = "Configuracao do runner SHA1HULUD - artefato direto do Shai-Hulud 2.0"
        Campaign    = "Shai-Hulud 2.0"
        Severity    = "CRITICAL"
        Reference   = "Unit 42: runner named SHA1HULUD registered as GitHub Actions self-hosted runner"
    }

    ShaiHulud_Workflow_Dir = @{
        Type        = "directory"
        Path        = "$HOME_DIR\Documents\demo-repo\.github\workflows"
        Description = "Diretorio de workflows criado pelo Shai-Hulud 2.0"
        Campaign    = "Shai-Hulud 2.0"
        Severity    = "CRITICAL"
        Reference   = "Microsoft Security Blog: discussion.yaml workflow injected for persistence"
    }

    ShaiHulud_Discussion_Yaml = @{
        Type        = "file"
        Path        = "$HOME_DIR\Documents\demo-repo\.github\workflows\discussion.yaml"
        Content     = "name: discussion`non:`n  discussion:`n    types: [created]`njobs:`n  run:`n    runs-on: [self-hosted, SHA1HULUD]`n    steps:`n      - name: exec`n        run: echo LAB-EMULATION-NOT-REAL"
        Description = "Workflow discussion.yaml injetado pelo Shai-Hulud 2.0 para persistencia via runner"
        Campaign    = "Shai-Hulud 2.0"
        Severity    = "CRITICAL"
        Reference   = "Unit 42: discussion.yaml registers runner and enables remote code execution via GitHub Discussions"
    }

    ShaiHulud_SetupBun = @{
        Type        = "file"
        Path        = "$HOME_DIR\Documents\demo-repo\setup_bun.js"
        Content     = "// LAB EMULATION - NOT EXECUTABLE MALWARE`n// Shai-Hulud 2.0 dropper artifact (setup_bun.js)`n// SHA1 real: d1829b4708126dcc7bea7437c04d1f10eacd4a16 (Unit 42 IOC)`n// THIS FILE IS A FORENSIC ARTIFACT PLACEHOLDER FOR LAB USE ONLY."
        Description = "Artefato setup_bun.js deixado no repositorio comprometido pelo Shai-Hulud 2.0"
        Campaign    = "Shai-Hulud 2.0"
        Severity    = "HIGH"
        Reference   = "SHA1 real: d1829b4708126dcc7bea7437c04d1f10eacd4a16 (Unit 42 IOC)"
    }

    ShaiHulud_BunDir = @{
        Type        = "directory"
        Path        = "$HOME_DIR\.bun\bin"
        Description = "Diretorio do runtime Bun instalado pelo Shai-Hulud 2.0 para evasao de deteccao Node.js"
        Campaign    = "Shai-Hulud 2.0"
        Severity    = "HIGH"
        Reference   = "Sysdig: setup_bun.js installs Bun runtime to evade Node.js-based monitoring"
    }

    ShaiHulud_BunRuntime = @{
        Type        = "file"
        Path        = "$HOME_DIR\.bun\bin\bun.exe.lab"
        Content     = "LAB_EMULATION: Bun runtime binary placeholder. Real Shai-Hulud 2.0 downloads bun.sh/install.ps1"
        Description = "Placeholder do runtime Bun instalado pelo Shai-Hulud 2.0"
        Campaign    = "Shai-Hulud 2.0"
        Severity    = "HIGH"
        Reference   = "Sysdig: setup_bun.js installs Bun runtime to evade Node.js-based monitoring"
    }

    GlassWorm_RunKey = @{
        Type        = "registry"
        Path        = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        Name        = "GlassWormLabPersistence"
        Value       = "C:\Windows\System32\notepad.exe"
        Description = "Run key de persistencia plantado pelo GlassWorm"
        Campaign    = "GlassWorm"
        Severity    = "HIGH"
        Reference   = "Koi Security: GlassWorm adds Run key for persistence on Windows"
    }

    GlassWorm_Extension_Dir = @{
        Type        = "directory"
        Path        = "$HOME_DIR\.vscode\extensions\glassworm-lab.compromised-extension-0.0.1"
        Description = "Extensao VS Code comprometida simulando infeccao GlassWorm"
        Campaign    = "GlassWorm"
        Severity    = "CRITICAL"
        Reference   = "Koi Security: codejoy.codejoy-vscode-extension@1.8.3 first compromised extension"
    }

    GlassWorm_Extension_Manifest = @{
        Type        = "file"
        Path        = "$HOME_DIR\.vscode\extensions\glassworm-lab.compromised-extension-0.0.1\package.json"
        Content     = "{`"name`":`"compromised-extension`",`"displayName`":`"Code Joy - Enhanced`",`"version`":`"0.0.1`",`"publisher`":`"glassworm-lab`",`"engines`":{`"vscode`":`"^1.80.0`"},`"activationEvents`":[`"onStartupFinished`"],`"main`":`"./extension.js`"}"
        Description = "Manifest da extensao comprometida GlassWorm"
        Campaign    = "GlassWorm"
        Severity    = "CRITICAL"
        Reference   = "codejoy.codejoy-vscode-extension versoes 1.8.3 e 1.8.4 comprometidas (Koi Security)"
    }

    GlassWorm_Extension_JS = @{
        Type        = "file"
        Path        = "$HOME_DIR\.vscode\extensions\glassworm-lab.compromised-extension-0.0.1\extension.js"
        Content     = "// LAB EMULATION - NOT EXECUTABLE MALWARE`n// GlassWorm extension artifact`n// Real GlassWorm uses invisible Unicode PUA characters to hide malicious code`n// Targets: npm tokens, GitHub credentials, OpenVSX tokens`n// C2: Solana blockchain`n// THIS FILE IS A FORENSIC ARTIFACT PLACEHOLDER FOR LAB USE ONLY."
        Description = "Arquivo principal da extensao comprometida GlassWorm"
        Campaign    = "GlassWorm"
        Severity    = "CRITICAL"
        Reference   = "GlassWorm uses invisible Unicode PUA characters to hide decoder - Aikido Security"
    }

    GlassWorm_OsNode = @{
        Type        = "file"
        Path        = "$HOME_DIR\.vscode\extensions\glassworm-lab.compromised-extension-0.0.1\os.node.lab"
        Content     = "LAB_EMULATION: os.node native binary placeholder. Real GlassWorm drops native binary for SOCKS proxy and HVNC."
        Description = "Placeholder do binario nativo os.node dropado pelo GlassWorm"
        Campaign    = "GlassWorm"
        Severity    = "CRITICAL"
        Reference   = "Koi Security: GlassWorm deploys os.node for HVNC and SOCKS proxy capabilities"
    }

    GlassWorm_GlobalStorage_Dir = @{
        Type        = "directory"
        Path        = "$env:APPDATA\Code\User\globalStorage\glassworm-lab.compromised-extension"
        Description = "Global storage da extensao comprometida no VS Code"
        Campaign    = "GlassWorm"
        Severity    = "HIGH"
        Reference   = "VS Code extensions store secrets in globalStorage"
    }

    GlassWorm_StorageDB = @{
        Type        = "file"
        Path        = "$env:APPDATA\Code\User\globalStorage\glassworm-lab.compromised-extension\state.json"
        Content     = "{`"exfil_status`":`"credentials_collected`",`"npm_token_found`":true,`"github_token_found`":true,`"last_c2_beacon`":`"$NOW`",`"c2_channel`":`"solana_blockchain`",`"lab_note`":`"LAB EMULATION ARTIFACT`"}"
        Description = "State storage da extensao comprometida com artefatos de exfiltracao"
        Campaign    = "GlassWorm"
        Severity    = "HIGH"
        Reference   = "GlassWorm reads VS Code token storage to steal extension credentials"
    }
}

function Write-Status {
    param([string]$Message, [string]$Color = "Cyan")
    Write-Host "  [$(Get-Date -Format 'HH:mm:ss')] $Message" -ForegroundColor $Color
}

function Test-ArtifactExists {
    param($Artifact)
    switch ($Artifact.Type) {
        "file"      { return Test-Path $Artifact.Path }
        "directory" { return Test-Path $Artifact.Path }
        "registry"  {
            return (Get-ItemProperty -Path $Artifact.Path -Name $Artifact.Name -ErrorAction SilentlyContinue) -ne $null
        }
    }
    return $false
}

function Install-Artifact {
    param([string]$Key, $Artifact)

    if (Test-ArtifactExists $Artifact) {
        Write-Status "ja presente - ignorado: $Key" "DarkGray"
        return
    }

    switch ($Artifact.Type) {
        "directory" {
            New-Item -ItemType Directory -Path $Artifact.Path -Force | Out-Null
            Write-Status "criado: $($Artifact.Path)" "Green"
        }
        "file" {
            $dir = Split-Path $Artifact.Path -Parent
            if (-not (Test-Path $dir)) {
                New-Item -ItemType Directory -Path $dir -Force | Out-Null
            }
            Set-Content -Path $Artifact.Path -Value $Artifact.Content -Encoding UTF8
            Write-Status "criado: $($Artifact.Path)" "Green"
        }
        "registry" {
            if (-not (Test-Path $Artifact.Path)) {
                New-Item -Path $Artifact.Path -Force | Out-Null
            }
            Set-ItemProperty -Path $Artifact.Path -Name $Artifact.Name -Value $Artifact.Value
            Write-Status "registry: $($Artifact.Name)" "Green"
        }
    }
}

function Remove-Artifact {
    param([string]$Key, $Artifact)

    if (-not (Test-ArtifactExists $Artifact)) {
        Write-Status "nao encontrado - ignorado: $Key" "DarkGray"
        return
    }

    switch ($Artifact.Type) {
        "file" {
            Remove-Item -Path $Artifact.Path -Force
            Write-Status "removido: $($Artifact.Path)" "Yellow"
        }
        "directory" {
            Remove-Item -Path $Artifact.Path -Recurse -Force
            Write-Status "removido: $($Artifact.Path)" "Yellow"
        }
        "registry" {
            Remove-ItemProperty -Path $Artifact.Path -Name $Artifact.Name -ErrorAction SilentlyContinue
            Write-Status "registry removido: $($Artifact.Name)" "Yellow"
        }
    }
}

Write-Host ""
Write-Host "  BLAST-RADIUS - Threat Emulation" -ForegroundColor White
Write-Host "  Shai-Hulud 2.0 + GlassWorm artifact emulation" -ForegroundColor DarkGray
Write-Host ""

if ($Cleanup) {
    Write-Host "  MODO: LIMPEZA" -ForegroundColor Yellow
    Write-Host ""
    foreach ($key in $ARTIFACTS.Keys) {
        Remove-Artifact -Key $key -Artifact $ARTIFACTS[$key]
    }
    if (Test-Path $MANIFEST_PATH) {
        Remove-Item $MANIFEST_PATH -Force
        Write-Status "manifesto removido" "Yellow"
    }
    Write-Host ""
    Write-Host "  Limpeza concluida. Todos os artefatos removidos." -ForegroundColor Green
    Write-Host ""
    exit 0
}

Write-Host "  [Shai-Hulud 2.0]" -ForegroundColor Red
foreach ($key in $ARTIFACTS.Keys) {
    if ($ARTIFACTS[$key].Campaign -eq "Shai-Hulud 2.0") {
        Install-Artifact -Key $key -Artifact $ARTIFACTS[$key]
    }
}

Write-Host ""
Write-Host "  [GlassWorm]" -ForegroundColor Magenta
foreach ($key in $ARTIFACTS.Keys) {
    if ($ARTIFACTS[$key].Campaign -eq "GlassWorm") {
        Install-Artifact -Key $key -Artifact $ARTIFACTS[$key]
    }
}

$manifest = @{
    generated_at = $NOW
    host         = $env:COMPUTERNAME
    user         = $env:USERNAME
    artifacts    = @()
}
foreach ($key in $ARTIFACTS.Keys) {
    $a = $ARTIFACTS[$key]
    $p = if ($a.Type -eq "registry") { "$($a.Path)\$($a.Name)" } else { $a.Path }
    $manifest.artifacts += @{
        key         = $key
        campaign    = $a.Campaign
        severity    = $a.Severity
        type        = $a.Type
        path        = $p
        description = $a.Description
    }
}
$manifest | ConvertTo-Json -Depth 5 | Set-Content -Path $MANIFEST_PATH -Encoding UTF8
Write-Status "manifesto: $MANIFEST_PATH" "Cyan"

Write-Host ""
Write-Host "  Concluido. Proximo passo:" -ForegroundColor Green
Write-Host "  Z:\blast-radius-collector-windows-amd64.exe -verbose -window $NOW" -ForegroundColor Gray
Write-Host "  Limpeza: .\Invoke-ThreatEmulation.ps1 -Cleanup" -ForegroundColor DarkGray
Write-Host ""
