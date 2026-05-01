# ============================================================
# Install WinToolKit
# ============================================================

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host ""
    Write-Host "  Ce script necessite les droits Administrateur." -ForegroundColor Yellow
    Write-Host "  Relancement en mode Administrateur..." -ForegroundColor Yellow
    $args2 = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    Start-Process pwsh -ArgumentList $args2 -Verb RunAs -ErrorAction SilentlyContinue
    if (-not $?) {
        Start-Process powershell -ArgumentList $args2 -Verb RunAs
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
Write-Host "  Installation de WinToolKit en cours..." -ForegroundColor Yellow
Write-Host ""
do {
    $confirm = Read-Host "  Confirmer l'installation ? (O/Y = oui, N = non)"
    if ($confirm -notmatch "^[OoYyNn]$") {
        Write-Host ""
        Write-Host "  Entree invalide. Repondez par O, Y ou N." -ForegroundColor Red
        Write-Host ""
    }
} while ($confirm -notmatch "^[OoYyNn]$")

if ($confirm -notmatch "^[OoYy]$") {
    Write-Host ""
    Write-Host "  Annulé." -ForegroundColor Yellow
    Write-Host ""
    Read-Host "  Appuyez sur Entree pour quitter"
    exit
}
Write-Host ""

try {
    $wtkPath = "C:\Program Files\Wintoolkit"
    $wtkScript = "$wtkPath\Wintoolkit.ps1"
    New-Item -Path $wtkPath -ItemType Directory -Force | Out-Null
    Invoke-WebRequest -Uri https://raw.githubusercontent.com/ps81frt/WintoolKit/main/Wintoolkit.ps1 -OutFile $wtkScript
    Unblock-File -Path $wtkScript
    Add-MpPreference -ExclusionPath $wtkPath
    if (!(Test-Path $PROFILE)) {
        New-Item -Type File -Path $PROFILE -Force | Out-Null
    }
    $func = 'function Wintoolkit { & "C:\Program Files\Wintoolkit\Wintoolkit.ps1" }'
    $profileContent = Get-Content $PROFILE -Raw -ErrorAction SilentlyContinue
    if ($profileContent -notlike "*Wintoolkit*") {
        Add-Content $PROFILE $func
    }
    Write-Host ""
    Write-Host "  Installation terminee !" -ForegroundColor Green
    Write-Host "  Relancez PowerShell en mode Administrateur et tapez : Wintoolkit" -ForegroundColor Cyan
    Write-Host ""
} catch {
    Write-Host ""
    Write-Host "  Erreur : $_" -ForegroundColor Red
    Write-Host ""
}

Read-Host "  Appuyez sur Entree pour quitter"