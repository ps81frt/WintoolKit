$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Ce script necessite les droits Administrateur." -ForegroundColor Yellow
    if (-not $PSCommandPath) {
        Write-Host "ERREUR : Lancez ce script depuis un fichier .ps1, pas via iex/irm." -ForegroundColor Red
        Read-Host "Appuyez sur Entree pour quitter"
        exit
    }
    Write-Host "Relancement en mode Administrateur..." -ForegroundColor Yellow
    $argList = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    $launched = $false
    try   { Start-Process pwsh -ArgumentList $argList -Verb RunAs -ErrorAction Stop; $launched = $true } catch {}
    if (-not $launched) {
        try   { Start-Process powershell -ArgumentList $argList -Verb RunAs -ErrorAction Stop; $launched = $true } catch {}
    }
    if (-not $launched) {
        Write-Host "Impossible de relancer en Administrateur." -ForegroundColor Red
        Read-Host "Appuyez sur Entree pour quitter"
    }
    exit
}

Write-Host @"

  ██╗    ██╗██╗███╗   ██╗████████╗ ██████╗  ██████╗ ██╗     ██╗  ██╗██╗████████╗
  ██║    ██║██║████╗  ██║╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██║ ██╔╝██║╚══██╔══╝
  ██║ █╗ ██║██║██╔██╗ ██║   ██║   ██║   ██║██║   ██║██║     █████╔╝ ██║   ██║   
  ██║███╗██║██║██║╚██╗██║   ██║   ██║   ██║██║   ██║██║     ██╔═██╗ ██║   ██║   
  ╚███╔███╔╝██║██║ ╚████║   ██║   ╚██████╔╝╚██████╔╝███████╗██║  ██╗██║   ██║   
   ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝  
"@ -ForegroundColor Cyan

Write-Host ""
Write-Host "Installation de WinToolKit en cours..." -ForegroundColor Yellow
Write-Host ""

do {
    $confirm = Read-Host "Confirmer l'installation ? (O/Y = oui, N = non)"
    if ($confirm -notmatch "^[OoYyNn]$") {
        Write-Host "Entree invalide. Repondez par O, Y ou N." -ForegroundColor Red
        Write-Host ""
    }
} while ($confirm -notmatch "^[OoYyNn]$")

if ($confirm -notmatch "^[OoYy]$") {
    Write-Host "Annule." -ForegroundColor Yellow
    Write-Host ""
    Read-Host "Appuyez sur Entree pour quitter"
    exit
}

Write-Host ""

try {
    $wtkPath   = "C:\Program Files\Wintoolkit"
    $wtkScript = "$wtkPath\Wintoolkit.ps1"
    $zipUrl = "https://github.com/ps81frt/LinuxToolsOnWindows/releases/download/1.0/LinuxToolOn-Windows.zip"
    $tmpZip = Join-Path $env:TEMP "LinuxToolOn-Windows.zip"
    $tmpDir = Join-Path $env:TEMP "LinuxTools_Install"

    New-Item -Path $wtkPath -ItemType Directory -Force | Out-Null

    Add-MpPreference -ExclusionPath $wtkPath -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionProcess "powershell.exe" -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionProcess "pwsh.exe" -ErrorAction SilentlyContinue

    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/ps81frt/WintoolKit/main/Wintoolkit.ps1" -OutFile $wtkScript -UseBasicParsing
    Unblock-File -Path $wtkScript

    $func = "`nfunction Wintoolkit { & `"C:\Program Files\Wintoolkit\Wintoolkit.ps1`" }"
    
    $targets = @(
        "$env:ProgramFiles\PowerShell\7\profile.ps1",
        "$env:SystemRoot\System32\WindowsPowerShell\v1.0\profile.ps1"
    )
    
    foreach ($target in $targets) {
        $parent = Split-Path $target -Parent
        if (!(Test-Path $parent)) {
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
        }
        if (!(Test-Path $target)) {
            New-Item -ItemType File -Path $target -Force | Out-Null
        }
        $content = Get-Content $target -Raw -ErrorAction SilentlyContinue
        if ($content -notlike "*Wintoolkit*") {
            Add-Content -Path $target -Value $func -Encoding UTF8 -Force
            Write-Host "  Ajout fonction dans : $target" -ForegroundColor Green
        }
    }

    Write-Host "Installation des outils Linux..." -ForegroundColor Yellow

    Invoke-WebRequest $zipUrl -OutFile $tmpZip -UseBasicParsing -ErrorAction Stop

    if (Test-Path $tmpDir) { Remove-Item $tmpDir -Recurse -Force }
    Expand-Archive -Path $tmpZip -DestinationPath $tmpDir -Force

    $binDir = "$wtkPath\bin"
    New-Item -ItemType Directory -Force -Path $binDir | Out-Null
    Add-MpPreference -ExclusionPath $binDir -ErrorAction SilentlyContinue

    $binaries = Get-ChildItem -Path $tmpDir -Recurse -Include "*.exe","*.dll"
    foreach ($bin in $binaries) {
        $dest = Join-Path $binDir $bin.Name
        Copy-Item $bin.FullName -Destination $dest -Force -ErrorAction SilentlyContinue
    }

    Remove-Item $tmpZip -Force -ErrorAction SilentlyContinue
    Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue

    Write-Host "Outils Linux installes." -ForegroundColor Green
    Write-Host ""
    Write-Host "Installation terminee !" -ForegroundColor Green
    Write-Host "Relancez PowerShell en mode Administrateur et tapez : Wintoolkit" -ForegroundColor Cyan
    Write-Host ""
} catch {
    Write-Host ""
    Write-Host "Erreur : $_" -ForegroundColor Red
    Write-Host ""
}

Read-Host "Appuyez sur Entree pour quitter"
