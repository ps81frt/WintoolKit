# ============================================================
# Uninstall WinToolKit
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
  ██╗   ██╗██╗██████╗ ███████╗
  ██║   ██║██║██╔══██╗██╔════╝
  ██║   ██║██║██████╔╝█████╗  
  ╚██╗ ██╔╝██║██╔══██╗██╔══╝  
   ╚████╔╝ ██║██║  ██║███████╗
    ╚═══╝  ╚═╝╚═╝  ╚═╝╚══════╝

  █████╗ 
  ╚════╝ 

  ██╗    ██╗██╗███╗   ██╗████████╗ ██████╗  ██████╗ ██╗     ██╗  ██╗██╗████████╗
  ██║    ██║██║████╗  ██║╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██║ ██╔╝██║╚══██╔══╝
  ██║ █╗ ██║██║██╔██╗ ██║   ██║   ██║   ██║██║   ██║██║     █████╔╝ ██║   ██║   
  ██║███╗██║██║██║╚██╗██║   ██║   ██║   ██║██║   ██║██║     ██╔═██╗ ██║   ██║   
  ╚███╔███╔╝██║██║ ╚████║   ██║   ╚██████╔╝╚██████╔╝███████╗██║  ██╗██║   ██║   
   ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝  
"@ -ForegroundColor Cyan

Write-Host ""
Write-Host "  ======================================================" -ForegroundColor Red
Write-Host "   DESINSTALLATION WINTOOLKIT" -ForegroundColor White
Write-Host "  ======================================================" -ForegroundColor Red
Write-Host ""
Write-Host "  Les elements suivants vont etre supprimes :" -ForegroundColor Yellow
Write-Host ""
Write-Host "    [1] Exclusion Defender : C:\Program Files\Wintoolkit" -ForegroundColor Gray
Write-Host "    [2] Exclusion Defender : Downloads\Wintoolkit.ps1" -ForegroundColor Gray
Write-Host "    [3] Fonction Wintoolkit dans le profil PowerShell" -ForegroundColor Gray
Write-Host "    [4] Dossier : C:\Program Files\Wintoolkit" -ForegroundColor Gray
Write-Host "    [5] Fichier : Downloads\Wintoolkit.ps1" -ForegroundColor Gray
Write-Host "    [6] Binaires Linux (.exe/.dll) installes dans System32" -ForegroundColor Gray
Write-Host "    [7] Entree PATH : C:\Tools\LinuxToolOn-Windows" -ForegroundColor Gray
Write-Host ""
Write-Host "  ======================================================" -ForegroundColor Red
Write-Host ""
$confirm = Read-Host "  Confirmer la desinstallation ? (O/N)"
if ($confirm -notmatch "^[Oo]$") {
    Write-Host ""
    Write-Host "  Annulé." -ForegroundColor Yellow
    exit
}
Write-Host ""

$wtkPath      = "C:\Program Files\Wintoolkit"
$wtkDownloads = "$env:USERPROFILE\Downloads\Wintoolkit.ps1"
$tmpDir       = Join-Path $env:TEMP "LinuxTools_EVC"
$tmpZip       = Join-Path $env:TEMP "LinuxToolOn-Windows.zip"
$sys32        = "$env:SystemRoot\System32"

Write-Host "[1/7] Suppression exclusion Defender (Program Files)..."
Remove-MpPreference -ExclusionPath $wtkPath -ErrorAction SilentlyContinue
Write-Host "[OK]"

Write-Host "[2/7] Suppression exclusion Defender (Downloads)..."
Remove-MpPreference -ExclusionPath $wtkDownloads -ErrorAction SilentlyContinue
Write-Host "[OK]"

Write-Host "[3/7] Nettoyage profil PowerShell..."
if (Test-Path $PROFILE) {
    $content = Get-Content $PROFILE -Raw -ErrorAction SilentlyContinue
    if ($content -like "*Wintoolkit*") {
        $func = 'function Wintoolkit { & "C:\Program Files\Wintoolkit\Wintoolkit.ps1" }'
        $newContent = ($content -replace [regex]::Escape($func), "").TrimEnd()
        Set-Content -Path $PROFILE -Value $newContent -Force
        Write-Host "[OK] Fonction Wintoolkit retirée du profil."
    } else {
        Write-Host "[SKIP] Aucune entrée Wintoolkit dans le profil."
    }
}

Write-Host "[4/7] Suppression du dossier $wtkPath..."
if (Test-Path $wtkPath) {
    Remove-Item -Path $wtkPath -Recurse -Force
    Write-Host "[OK]"
} else {
    Write-Host "[SKIP] Dossier déjà absent."
}

Write-Host "[5/7] Suppression de $wtkDownloads..."
if (Test-Path $wtkDownloads) {
    Remove-Item -Path $wtkDownloads -Force
    Write-Host "[OK]"
} else {
    Write-Host "[SKIP] Fichier déjà absent."
}

Write-Host "[6/7] Suppression des binaires LinuxToolsOnWindows de System32..."
if (-not (Test-Path $tmpZip)) {
    Write-Host "[INFO] Téléchargement du zip pour récupérer la liste exacte des fichiers..."
    try {
        Invoke-WebRequest -Uri "https://github.com/ps81frt/LinuxToolsOnWindows/releases/download/1.0/LinuxToolOn-Windows.zip" `
            -OutFile $tmpZip -UseBasicParsing -ErrorAction Stop
    } catch {
        Write-Host "[ERREUR] Téléchargement échoué : $_"
        Write-Host "[WARN] Étape 6 ignorée."
    }
}

if (Test-Path $tmpZip) {
    if (Test-Path $tmpDir) { Remove-Item $tmpDir -Recurse -Force }
    Expand-Archive -Path $tmpZip -DestinationPath $tmpDir -Force

    $binaries = Get-ChildItem -Path $tmpDir -Recurse -Include "*.exe","*.dll"
    foreach ($bin in $binaries) {
        $target = Join-Path $sys32 $bin.Name
        if (Test-Path $target) {
            try {
                Remove-Item $target -Force
                Write-Host "[OK] Supprimé : $($bin.Name)"
            } catch {
                Write-Host "[WARN] Impossible de supprimer $($bin.Name) : $_"
            }
        } else {
            Write-Host "[SKIP] Absent : $($bin.Name)"
        }
    }

    Remove-Item $tmpZip -Force -ErrorAction SilentlyContinue
    Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "[7/7] Nettoyage PATH..."
$currentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($currentPath -like "*LinuxToolOn-Windows*") {
    $newPath = ($currentPath -split ";" | Where-Object { $_ -notlike "*LinuxToolOn-Windows*" }) -join ";"
    [Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
    Write-Host "[OK] PATH nettoyé."
} else {
    Write-Host "[SKIP] Entrée PATH absente."
}

Write-Host ""
Write-Host "  ======================================================" -ForegroundColor Green
Write-Host "   [DONE] Désinstallation WinToolKit complète." -ForegroundColor Green
Write-Host "  ======================================================" -ForegroundColor Green
Write-Host ""