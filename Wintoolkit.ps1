#Requires -Version 5.1
<#
.SYNOPSIS
    WinToolkit v2 - Suite Diagnostic & Securite Windows

.DESCRIPTION
    Menu principal 11 modules.  TOUS les rapports sur le Bureau.
      1. InfoSys    -> Bureau\InfoSys_<ts>.zip
      2. DiagBoot   -> Bureau\DiagBoot_<ts>.txt
      3. AuditSOC   -> Bureau\AuditSOC_<ts>.txt
      4. EDR/AV     -> Bureau\EDR_<ts>\Rapport_EDR.txt
      5. WinDiag    -> Bureau\WinDiag_<ts>.txt
      6. SFC/DISM   -> Bureau\CBS_SFC_DISM_Report_<ts>.txt/.html
      7. NetShare   -> Bureau\NetShare_<ts>.html
      8. Compare-PC -> Bureau\CPR_<ts>\
      9. EVCDiag    -> Bureau\EVC_Export\
     10. CrashDiag  -> Bureau\CrashDiag_<ts>\*.txt + *.html
     11. GhostWin   -> Bureau\GhostWin_<ts>\*.csv/.html

.PARAMETER Module
    InfoSys | DiagBoot | AuditSOC | EDR | WinDiag | SFC | NetShare | ComparePC | EVCDiag | CrashDiag | GhostWin

.PARAMETER Fix
    (EDR) All | Firewall | SmartScreen | Defender | SMBv1 | LSA

.PARAMETER Query
    (WinDiag) Code hex, DLL, ou mot-cle

.PARAMETER Scan
    (WinDiag) Scanner l Event Log crashes

.PARAMETER Dump
    (WinDiag) Chemin minidump(s)

.PARAMETER Export
    (WinDiag) Exporter dernier resultat

.PARAMETER NetMode
    (NetShare) COMPLET (defaut) ou PUBLIC

.PARAMETER ReportFiles
    (ComparePC) Fichiers *-all.txt de NetShare (2 min, 10 max)

.EXAMPLE
    .\WinToolkit.ps1
    .\WinToolkit.ps1 -Module EDR -Fix All
    .\WinToolkit.ps1 -Module WinDiag -Query 0xc000012f
    .\WinToolkit.ps1 -Module NetShare -NetMode PUBLIC

.AUTHOR ps81frt / https://github.com/ps81frt/wintoolkit
#>
param(
    [ValidateSet("InfoSys","DiagBoot","AuditSOC","EDR","WinDiag","SFC","NetShare","ComparePC","EVCDiag","CrashDiag","GhostWin","")]
    [string]$Module = "",
    [ValidateSet("All","Firewall","SmartScreen","Defender","SMBv1","LSA","None")]
    [string]$Fix = "None",
    [switch]$ShareDpaste,
    [switch]$ShareGofile,
    [string]$Query,
    [switch]$Scan,
    [string]$Dump,
    [string]$Export,
    [switch]$Help,
    [ValidateSet("COMPLET","PUBLIC","")]
    [string]$NetMode = "COMPLET",
    [string[]]$ReportFiles,

    # -------------------------------------------------------------------------
    # DEBUG — mettre a $true pour activer les logs de montage EFI
    # Genere : Bureau\DiagBoot_EFI_Debug_<timestamp>.log
    # -------------------------------------------------------------------------
    [switch]$DebugEFI,

    # -------------------------------------------------------------------------
    # CrashDiag — Analyse BSOD / freezes / WHEA / sessions / app crash
    # -------------------------------------------------------------------------
    [int]$HeuresHistorique = 48,
    [switch]$ExportCSV,
    [switch]$ExportHTML
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

# ===========================================================================
#  SHARED UTILITIES
# ===========================================================================

function Write-Title {
    param([string]$Text, [string]$Color = "Cyan")
    $line = '=' * 70
    Write-Host ""
    Write-Host $line -ForegroundColor $Color
    Write-Host "  $Text" -ForegroundColor White
    Write-Host $line -ForegroundColor $Color
}

function Write-Section {
    param([string]$Text)
    Write-Host ""
    Write-Host "  >> $Text" -ForegroundColor Yellow
    Write-Host "  $('-' * 60)" -ForegroundColor DarkGray
}

function Write-OK   { param([string]$t) Write-Host "  [OK]  $t" -ForegroundColor Green }
function Write-WARN { param([string]$t) Write-Host "  [!!]  $t" -ForegroundColor Yellow }
function Write-INFO { param([string]$t) Write-Host "  [ ]   $t" -ForegroundColor Gray }
function Write-ERR  { param([string]$t) Write-Host "  [XX]  $t" -ForegroundColor Red }
function Write-ACT  { param([string]$t) Write-Host "  [=>]  $t" -ForegroundColor Magenta }

function Format-Size {
    param([long]$Bytes)
    if ($Bytes -ge 1TB) { return "{0:N2} TB" -f ($Bytes / 1TB) }
    if ($Bytes -ge 1GB) { return "{0:N2} GB" -f ($Bytes / 1GB) }
    if ($Bytes -ge 1MB) { return "{0:N2} MB" -f ($Bytes / 1MB) }
    return "{0} B" -f $Bytes
}

function Assert-AdminPrivilege {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host ""
        Write-Host "  Ce module necessite les droits Administrateur." -ForegroundColor Yellow
        Write-Host "  Relancement en mode Administrateur..." -ForegroundColor Yellow
        $args2 = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
        if ($Module)  { $args2 += " -Module $Module" }
        if ($Fix -ne "None") { $args2 += " -Fix $Fix" }
        Start-Process pwsh -ArgumentList $args2 -Verb RunAs -ErrorAction SilentlyContinue
        if (-not $?) {
            Start-Process powershell -ArgumentList $args2 -Verb RunAs
        }
        exit
    }
}

function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  ██╗    ██╗██╗███╗   ██╗    ████████╗ ██████╗  ██████╗ ██╗     ██╗  ██╗██╗████████╗" -ForegroundColor Cyan
    Write-Host "  ██║    ██║██║████╗  ██║    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██║ ██╔╝██║╚══██╔══╝" -ForegroundColor Cyan
    Write-Host "  ██║ █╗ ██║██║██╔██╗ ██║       ██║   ██║   ██║██║   ██║██║     █████╔╝ ██║   ██║   " -ForegroundColor Cyan
    Write-Host "  ██║███╗██║██║██║╚██╗██║       ██║   ██║   ██║██║   ██║██║     ██╔═██╗ ██║   ██║   " -ForegroundColor Cyan
    Write-Host "  ╚███╔███╔╝██║██║ ╚████║       ██║   ╚██████╔╝╚██████╔╝███████╗██║  ██╗██║   ██║   " -ForegroundColor Cyan
    Write-Host "   ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝   " -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Suite Diagnostic & Securite Windows  |  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
    Write-Host "  Machine : $env:COMPUTERNAME  |  User : $env:USERNAME" -ForegroundColor DarkGray
    Write-Host ""
}


# ===========================================================================
#  MODULE 1 — INFOSYS  (Inventaire systeme complet)
# ===========================================================================

function Invoke-InfoSys {
    Assert-AdminPrivilege

    Write-Title "MODULE 1 — INFOSYS : Inventaire Systeme Complet"

    # --- Fonctions internes ---
    function Get-SoftHKCU {
        Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue |
            ForEach-Object { [pscustomobject]@{ DisplayName=$_.GetValue('DisplayName'); DisplayVersion=$_.GetValue('DisplayVersion') } }
    }
    function Get-SoftHKLM {
        Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue |
            ForEach-Object { [pscustomobject]@{ DisplayName=$_.GetValue('DisplayName'); DisplayVersion=$_.GetValue('DisplayVersion') } }
    }

    $timestamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
    $rootPath   = "$env:USERPROFILE\Desktop\InfoSys_$timestamp"
    $null = New-Item -ItemType Directory -Path $rootPath -Force

    # Taches planifiees
    Write-Section "Export taches planifiees (non-Microsoft)"
    $backupPath = "$rootPath\TachesWindows"
    $null = New-Item -ItemType Directory -Path $backupPath -Force
    $taskFolders = (Get-ScheduledTask -ErrorAction SilentlyContinue).TaskPath |
        Where-Object { $_ -notmatch "Microsoft" } | Select-Object -Unique
    foreach ($tf in $taskFolders) {
        $folderPath = "$backupPath$tf"
        if ($tf -ne "\") { $null = New-Item -ItemType Directory -Path $folderPath -Force -ErrorAction SilentlyContinue }
        $tasks = Get-ScheduledTask -TaskPath $tf -ErrorAction SilentlyContinue
        foreach ($task in $tasks) {
            $xml = Export-ScheduledTask -TaskName $task.TaskName -TaskPath $tf -ErrorAction SilentlyContinue
            $xml | Out-File "$backupPath$tf$($task.TaskName).xml" -ErrorAction SilentlyContinue
        }
    }
    Write-OK "Taches exportees dans : $backupPath"

    # Infos systeme generales
    Write-Section "Informations systeme generales"
    $infoFile = "$rootPath\InfoSysGenerale.txt"
    & {
        $OS  = Get-CimInstance Win32_OperatingSystem
        $Enc = Get-CimInstance Win32_SystemEnclosure
        Write-Output "=== OS & Machine ==="
        [PSCustomObject]@{
            PCName         = $OS.CSName
            OS             = $OS.Caption
            Architecture   = $OS.OSArchitecture
            Version        = $OS.Version
            InstallDate    = $OS.InstallDate
            LastBootUpTime = $OS.LastBootUpTime
            Manufacturer   = $Enc.Manufacturer
            SerialNumber   = $Enc.SerialNumber
        } | Format-List

        Write-Output "=== BIOS ==="
        Get-CimInstance Win32_BIOS | Select-Object SMBIOSBIOSVersion,Manufacturer,Name,SerialNumber,Version

        Write-Output "=== GPU ==="
        Get-CimInstance Win32_VideoController | Select-Object Caption,PNPDeviceID,DriverDate,DriverVersion,VideoModeDescription

        Write-Output "=== Moniteurs ==="
        Get-CimInstance wmimonitorID -Namespace root\wmi -ErrorAction SilentlyContinue | ForEach-Object {
            $adapterTypes = @{'-2'='Unknown';'-1'='Unknown';'0'='VGA';'1'='S-Video';'2'='Composite';'3'='Component';'4'='DVI';'5'='HDMI';'6'='LVDS';'8'='D-Jpn';'9'='SDI';'10'='DisplayPort (ext)';'11'='DisplayPort (int)';'12'='UDI';'13'='UDI (emb)';'14'='SDTV';'15'='Miracast';'16'='Internal';'2147483648'='Internal'}
            $inst  = $_.InstanceName
            $sizes = Get-CimInstance -Namespace root\wmi -Class WmiMonitorBasicDisplayParams -ErrorAction SilentlyContinue | Where-Object { $_.instanceName -like $inst }
            $conn  = (Get-CimInstance WmiMonitorConnectionParams -Namespace root/wmi -ErrorAction SilentlyContinue | Where-Object { $_.instanceName -like $inst }).VideoOutputTechnology
            [pscustomobject]@{
                Manufacturer   = [System.Text.Encoding]::ASCII.GetString($_.ManufacturerName).Trim(0x00)
                Name           = [System.Text.Encoding]::ASCII.GetString($_.UserFriendlyName).Trim(0x00)
                Serial         = [System.Text.Encoding]::ASCII.GetString($_.SerialNumberID).Trim(0x00)
                SizeInch       = if($sizes){ [System.Math]::Round(([System.Math]::Sqrt([System.Math]::Pow($sizes.MaxHorizontalImageSize,2)+[System.Math]::Pow($_.MaxVerticalImageSize,2))/2.54),0) } else {"N/A"}
                Connection     = $adapterTypes."$conn"
            }
        }

        Write-Output "=== Disques ==="
        Get-PhysicalDisk | Format-Table -Wrap
        Get-CimInstance Win32_LogicalDisk -Filter "drivetype=3" |
            Format-Table DeviceID,VolumeName,
                @{N="SizeGB";E={[math]::Round($_.Size/1GB)}},
                @{N="FreeGB";E={[math]::Round($_.Freespace/1GB,2)}},
                @{N="Free%";E={[math]::Round(($_.Freespace/$_.Size)*100,2)}} -AutoSize

        Write-Output "=== RAM ==="
        Get-CimInstance Win32_PhysicalMemory | Select-Object Manufacturer,PartNumber,BankLabel,ConfiguredClockSpeed,DeviceLocator,@{N='Capacity';E={"$($_.Capacity/1gb)GB"}},SerialNumber | Format-Table -AutoSize

    } | Out-File $infoFile -Encoding UTF8
    Write-OK "Infos systeme : $infoFile"

    # Reseau
    Write-Section "Reseau"
    $networkPath = "$rootPath\Network"
    $null = New-Item -ItemType Directory -Path $networkPath -Force
    & {
        netsh interface tcp show global
        Get-CimInstance Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue |
            Where-Object { $null -ne $_.IPAddress } |
            Select-Object IPAddress,DefaultIPGateway,DNSServerSearchOrder,IPSubnet,MACAddress,Caption,DHCPEnabled,DHCPServer | Format-List
    } | Out-File "$networkPath\NetworkInfo.txt" -Encoding UTF8
    netsh wlan show wlanreport *>$null
    Move-Item "C:\ProgramData\Microsoft\Windows\WlanReport\wlan-report-*" $networkPath -ErrorAction SilentlyContinue
    Write-OK "Reseau : $networkPath"

    # Demarrage
    Write-Section "Applications au demarrage"
    Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue |
        Select-Object Name,Command,Location,User | Format-Table |
        Out-File "$rootPath\StartupApplication.txt" -Encoding UTF8

    # Logiciels
    Write-Section "Logiciels installes"
    $softPath = "$rootPath\Software"
    $null = New-Item -ItemType Directory -Path $softPath -Force
    Get-SoftHKLM | Out-File "$softPath\InstalledSoftwareHKLM.txt" -Encoding UTF8
    Get-SoftHKCU | Out-File "$softPath\InstalledSoftwareHKCU.txt" -Encoding UTF8
    Get-WinEvent -ProviderName msiinstaller -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -eq 1033 } | Select-Object TimeCreated,Message | Format-List |
        Out-File "$softPath\InstalledSoftwareWinEvent.txt" -Encoding UTF8
    Write-OK "Logiciels : $softPath"

    # Services
    Write-Section "Services Windows"
    $svcPath = "$rootPath\Services"
    $null = New-Item -ItemType Directory -Path $svcPath -Force
    Get-Service | Sort-Object Name | Format-Table Name,Status,StartType,Description |
        Out-File "$svcPath\Services.txt" -Encoding UTF8
    Write-OK "Services : $svcPath"

    # Defender
    Write-Section "Windows Defender"
    $defPath = "$rootPath\Defender"
    $null = New-Item -ItemType Directory -Path $defPath -Force
    Get-MpThreatDetection -ErrorAction SilentlyContinue | Sort-Object RemediationTime -Descending |
        Select-Object RemediationTime,ProcessName,Resources | Format-List |
        Out-File "$defPath\Detection.txt" -Encoding UTF8
    Get-MpThreat -ErrorAction SilentlyContinue | Sort-Object DidThreatExecute -Descending |
        Select-Object ThreatName,SeverityID,DidThreatExecute,IsActive |
        Out-File "$defPath\StatusDetection.txt" -Encoding UTF8
    Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction SilentlyContinue |
        Out-File "$defPath\StatusAntiVirus.txt" -Encoding UTF8
    Write-OK "Defender : $defPath"

    # Pilotes
    Write-Section "Pilotes"
    $pilPath = "$rootPath\Pilotes"
    $null = New-Item -ItemType Directory -Path $pilPath -Force
    Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue |
        Select-Object Status,FriendlyName,InstanceId | Format-Table -GroupBy Status |
        Out-File "$pilPath\DriverVendorID.txt" -Encoding UTF8
    Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue |
        Select-Object Status,Class,FriendlyName,InstanceId | Format-Table -GroupBy Status |
        Out-File "$pilPath\DriverStatus.txt" -Encoding UTF8
    Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue |
        Select-Object DeviceName,Manufacturer,DriverVersion |
        Out-File "$pilPath\DriverVersion.txt" -Encoding UTF8
    Get-CimInstance Win32_PnpEntity -ErrorAction SilentlyContinue |
        Where-Object { $_.ConfigManagerErrorCode -gt 0 } |
        Select-Object ConfigManagerErrorCode,ErrorText,Present,Status,StatusInfo,Caption | Format-List -GroupBy Status |
        Out-File "$pilPath\DriverError.txt" -Encoding UTF8
    Write-OK "Pilotes : $pilPath"

    # Windows Update
    Write-Section "Windows Update"
    $wlogsPath = "$rootPath\WLogs"
    $null = New-Item -ItemType Directory -Path $wlogsPath -Force
    Get-WindowsUpdateLog -ErrorAction SilentlyContinue | Out-Null
    Move-Item "$env:USERPROFILE\Desktop\WindowsUpdate.log" $wlogsPath -ErrorAction SilentlyContinue
    Get-CimInstance Win32_ReliabilityRecords -ErrorAction SilentlyContinue |
        Where-Object { $_.SourceName -eq 'Microsoft-Windows-WindowsUpdateClient' -and $_.Message -match "Erreur" } |
        Select-Object TimeGenerated,@{L="Echec";E={$_.ProductName}} | Format-Table -AutoSize |
        Out-File "$wlogsPath\WindowsUpdateErreur.txt" -Encoding UTF8
    Write-OK "Logs WU : $wlogsPath"

    # ZIP final
    Write-Section "Compression du dossier"
    $zipPath = "$env:USERPROFILE\Desktop\InfoSys_$timestamp.zip"
    Compress-Archive -Path $rootPath -DestinationPath $zipPath -Force
    Remove-Item -Path $rootPath -Recurse -Force -ErrorAction SilentlyContinue
    Write-OK "Archive creee : $zipPath"
    Write-Host ""
    Write-Host "  InfoSys termine ! Archive disponible sur le bureau." -ForegroundColor Green
}


# ===========================================================================
#  MODULE 2 — DIAGBOOT  (Diagnostic Boot / Disques / BCD)
# ===========================================================================

function Invoke-DiagBoot {
    $ts_db  = Get-Date -Format 'yyyyMMdd_HHmmss'
    $rpt_db = "$env:USERPROFILE\Desktop\DiagBoot_$ts_db.txt"
    Start-Transcript -Path $rpt_db -Force -ErrorAction SilentlyContinue | Out-Null
    Assert-AdminPrivilege

    Clear-Host
    Write-Host ""
    Write-Host "  ██████╗ ██╗ █████╗  ██████╗ " -ForegroundColor Cyan
    Write-Host "  ██╔══██╗██║██╔══██╗██╔════╝ " -ForegroundColor Cyan
    Write-Host "  ██║  ██║██║███████║██║  ███╗" -ForegroundColor Cyan
    Write-Host "  ██║  ██║██║██╔══██║██║   ██║" -ForegroundColor Cyan
    Write-Host "  ██████╔╝██║██║  ██║╚██████╔╝" -ForegroundColor Cyan
    Write-Host "  ╚═════╝ ╚═╝╚═╝  ╚═╝ ╚═════╝  Diagnostic Boot & Disques" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Mode : LECTURE SEULE | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray

    $allParts = Get-Partition | Sort-Object DiskNumber,PartitionNumber
    $volumes  = Get-Volume | Where-Object { $_.DriveType -ne 'Unknown' } | Sort-Object DriveLetter
    $disks    = Get-Disk | Sort-Object Number

    # --- 1. FIRMWARE ---
    Write-Title "1. TYPE DE FIRMWARE"
    $uefiTest = [System.IO.File]::Exists("$env:SystemRoot\Boot\EFI\bootmgfw.efi")
    $firmware = "Legacy BIOS"
    try { $null = Confirm-SecureBootUEFI; $firmware = "UEFI" } catch {
        if ($uefiTest) { $firmware = "UEFI (bootmgfw.efi detecte)" }
    }
    if ($firmware -like "UEFI*") { Write-OK "Firmware : $firmware" } else { Write-WARN "Firmware : $firmware" }
    try {
        $sb = Confirm-SecureBootUEFI
        if ($sb) { Write-OK  "Secure Boot : ACTIVE" } else { Write-WARN "Secure Boot : DESACTIVE" }
    } catch { Write-INFO "Secure Boot : Non applicable (Legacy) ou non lisible" }

    # --- 2. VERSION WINDOWS ---
    Write-Title "2. VERSION DE WINDOWS"
    $os = Get-CimInstance Win32_OperatingSystem
    Write-INFO "Nom          : $($os.Caption)"
    Write-INFO "Version      : $($os.Version)"
    Write-INFO "Build        : $($os.BuildNumber)"
    Write-INFO "Architecture : $($os.OSArchitecture)"
    Write-INFO "Installe le  : $($os.InstallDate)"
    $edition = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name EditionID -EA SilentlyContinue).EditionID
    Write-INFO "Edition      : $edition"

    # --- 3. DISQUES ---
    Write-Title "3. DISQUES PHYSIQUES"
    if (-not $disks) { Write-ERR "Aucun disque detecte." } else {
        Write-Host ("  {0,-4} {1,-32} {2,-10} {3,-5} {4,-8} {5}" -f "N","Nom","Taille","Type","Bus","Statut") -ForegroundColor White
        Write-Host "  $('-'*72)" -ForegroundColor DarkGray
        foreach ($d in $disks) {
            $sz   = Format-Size $d.Size
            $pt   = if ($d.PartitionStyle -eq 'GPT') {'GPT'} elseif ($d.PartitionStyle -eq 'MBR') {'MBR'} else {'RAW'}
            $col  = if ($d.OperationalStatus -eq 'Online') {'Green'} else {'Red'}
            $name = if ($d.FriendlyName.Length -gt 30) { $d.FriendlyName.Substring(0,27)+'...' } else { $d.FriendlyName }
            Write-Host ("  {0,-4} {1,-32} {2,-10} {3,-5} {4,-8} {5}" -f $d.Number,$name,$sz,$pt,$d.BusType,$d.OperationalStatus) -ForegroundColor $col
        }
    }

    # --- 4. PARTITIONS ---
    Write-Title "4. PARTITIONS"
    if (-not $allParts) { Write-ERR "Aucune partition lisible." } else {
        Write-Host ("  {0,-4} {1,-4} {2,-10} {3,-22} {4,-7} {5}" -f "Disk","Part","Taille","Type","Lettre","GUID") -ForegroundColor White
        Write-Host "  $('-'*72)" -ForegroundColor DarkGray
        foreach ($p in $allParts) {
            $sz     = Format-Size $p.Size
            $letter = if ($p.DriveLetter) { "$($p.DriveLetter):" } else { "(none)" }
            $typeLabel = switch ($p.Type) { 'EFI'{'EFI System'} 'MSR'{'MSR Reserve'} 'Recovery'{'Recovery'} 'Basic'{'Basic Data'} default{$p.Type} }
            $col    = switch ($p.Type) { 'EFI'{'Magenta'} 'Recovery'{'DarkYellow'} 'MSR'{'DarkCyan'} default{'Gray'} }
            $guid   = if ($p.Guid) { $p.Guid.ToString().Substring(0,8)+'...' } else { '' }
            Write-Host ("  {0,-4} {1,-4} {2,-10} {3,-22} {4,-7} {5}" -f $p.DiskNumber,$p.PartitionNumber,$sz,$typeLabel,$letter,$guid) -ForegroundColor $col
        }
    }

    # --- 5. VOLUMES ---
    Write-Title "5. VOLUMES"
    Write-Host ("  {0,-6} {1,-8} {2,-11} {3,-11} {4,-10} {5}" -f "Lettre","FS","Total","Libre","Type","Label") -ForegroundColor White
    Write-Host "  $('-'*68)" -ForegroundColor DarkGray
    foreach ($vol in $volumes) {
        $letter = if ($vol.DriveLetter) { "$($vol.DriveLetter):" } else { "(-)" }
        $total  = if ($vol.Size)          { Format-Size $vol.Size } else { "N/A" }
        $free   = if ($vol.SizeRemaining) { Format-Size $vol.SizeRemaining } else { "N/A" }
        $fs     = if ($vol.FileSystemType){ $vol.FileSystemType } else { "N/A" }
        $label  = if ($vol.FileSystemLabel){ $vol.FileSystemLabel } else { "(sans label)" }
        $col    = 'Gray'
        if ($vol.FileSystemType -eq 'FAT32') { $col = 'Magenta' }
        if ($vol.DriveType -eq 'Fixed')       { $col = 'White' }
        if ($vol.DriveLetter -eq $env:SystemDrive[0]) { $col = 'Cyan' }
        Write-Host ("  {0,-6} {1,-8} {2,-11} {3,-11} {4,-10} {5}" -f $letter,$fs,$total,$free,$vol.DriveType,$label) -ForegroundColor $col
    }

    # --- 6. EFI ---
    Write-Title "6. PARTITION EFI — ANALYSE DETAILLEE"
    $sysPart    = $allParts | Where-Object { $_.DriveLetter -eq ($env:SystemDrive -replace ':','') }
    $sysDiskNum = if ($sysPart) { $sysPart.DiskNumber } else { -1 }

    # Methode 1 : Type == 'EFI' (GPT standard) OU 'System' (variante selon PS/Windows)
    $efiParts = $allParts | Where-Object { $_.Type -eq 'EFI' -or $_.Type -eq 'System' }

    # Methode 2 (fallback) : partitions FAT32 < 1 Go sans lettre sur disques GPT
    if (-not $efiParts) {
        $gptDisks = (Get-Disk | Where-Object { $_.PartitionStyle -eq 'GPT' }).Number
        $efiParts = $allParts | Where-Object {
            $_.DiskNumber -in $gptDisks -and
            -not $_.DriveLetter -and
            $_.Size -lt 1GB -and
            $_.Size -gt 50MB
        }
        if ($efiParts) { Write-INFO "EFI detectee par fallback FAT32 (Type non retourne par Get-Partition)." }
    }

    # Methode 3 (fallback ultime) : fichier bootmgfw.efi present
    if (-not $efiParts) {
        $uefiFile = [System.IO.File]::Exists("$env:SystemRoot\Boot\EFI\bootmgfw.efi")
        if ($uefiFile) {
            Write-WARN "Aucune partition EFI detectee via Get-Partition."
            Write-INFO  "bootmgfw.efi detecte dans $env:SystemRoot\Boot\EFI\ — le systeme est probablement UEFI."
            Write-INFO  "Cause probable : droits insuffisants sur la table GPT, ou disque dynamique."
        } else {
            Write-WARN "Aucune partition EFI detectee."
            Write-INFO  "Causes possibles :"
            Write-INFO  "  1. Disque en MBR/Legacy BIOS (verifier section 1)"
            Write-INFO  "  2. Get-Partition retourne 'System' au lieu de 'EFI' — essayez DiagBoot complet"
            Write-INFO  "  3. Disque de boot non visible depuis cette session (StorageSpace, RAID)"
        }
    } else {
        # Construire map HarddiskVolumeX -> DiskNumber
        # Chaine : Win32_Volume.DeviceID = \\?\Volume{GUID}\
        #          Get-Partition.Guid     = {GUID}
        #          -> croisement GUID -> DiskNumber
        # bcdedit retourne : device = partition=\Device\HarddiskVolumeX
        # Win32_Volume.DeviceID retourne aussi \\?\Volume{GUID}\ mais pas HarddiskVolumeX directement
        # On utilise la propriete Name ou Caption de Win32_LogicalDisk OU
        # on passe par Get-Volume -> FileSystemLabel/UniqueId -> Get-Partition
        # Methode la plus robuste : Get-Partition possede AccessPaths qui contient \\?\Volume{GUID}\
        # On mappe AccessPath{GUID} -> DiskNumber, puis on resout HarddiskVolumeX via Win32_Volume

        # Map HarddiskVolumeX -> DiskNumber
        # Chaine : Get-Partition.AccessPaths -> Volume{GUID} -> QueryDosDevice -> HarddiskVolumeX
        # Add-Type NativeHelper en dehors du try interne pour eviter conflit si deja declare
        $hdVolToDisk = @{}
        $volGuidToDisk = @{}
        foreach ($p in $allParts) {
            if (-not $p.AccessPaths) { continue }
            foreach ($ap in $p.AccessPaths) {
                if ($ap -match 'Volume\{([0-9a-f\-]+)\}') {
                    $volGuidToDisk[$Matches[1].ToLower()] = $p.DiskNumber
                }
            }
        }
        if ($volGuidToDisk.Count -gt 0) {
            # Declarer QueryDosDevice une seule fois — ignorer si deja present
            if (-not ([System.Management.Automation.PSTypeName]'Win32.NativeHelper').Type) {
                try {
                    Add-Type -Name NativeHelper -Namespace Win32 -MemberDefinition @'
[DllImport("kernel32.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern uint QueryDosDevice(string lpDeviceName, System.Text.StringBuilder lpTargetPath, int ucchMax);
'@ -EA Stop
                } catch {}
            }
            $wmiVols = Get-CimInstance Win32_Volume -EA SilentlyContinue
            foreach ($wv in $wmiVols) {
                if (-not $wv.DeviceID) { continue }
                if ($wv.DeviceID -match 'Volume\{([0-9a-f\-]+)\}') {
                    $vg = $Matches[1].ToLower()
                    if (-not $volGuidToDisk.ContainsKey($vg)) { continue }
                    try {
                        $dosName = $wv.DeviceID -replace '^\\\\\?\\','' -replace '\\$',''
                        $sb = New-Object System.Text.StringBuilder 260
                        $null = [Win32.NativeHelper]::QueryDosDevice($dosName, $sb, 260)
                        $kp = $sb.ToString().ToLower()
                        if ($kp -match '(harddiskvolume\d+)') {
                            $hdVolToDisk[$Matches[1]] = $volGuidToDisk[$vg]
                        }
                    } catch {}
                }
            }
        }

        # Identifier le disque de l'EFI prioritaire dans le firmware
        # bcdedit retourne : device = partition=\Device\HarddiskVolumeX
        $priorityEfiDisk = -1
        $bcdFw  = bcdedit /enum firmware 2>&1
        $bcdAll = bcdedit /enum ALL 2>&1
        if ($LASTEXITCODE -eq 0) {
            # Extraire ordre du {fwbootmgr} — capturer TOUS ids (hex GUIDs ET aliases ex: bootmgr)
            $fwOrderIds = @()
            $inFw = $false
            foreach ($line in $bcdFw) {
                if ($line -match 'identificateur\s+\{fwbootmgr\}') { $inFw = $true; continue }
                if ($inFw -and $line -match 'identificateur\s+\{' -and $line -notmatch 'fwbootmgr') { $inFw = $false }
                if ($inFw -and $line -match '\{([^}]+)\}') { $fwOrderIds += $Matches[1].ToLower() }
            }
            # Resoudre chaque id dans bcdAll (qui contient aliases + GUIDs avec leur device line)
            foreach ($fwId in $fwOrderIds) {
                $inEntry = $false
                foreach ($line in $bcdAll) {
                    if ($line -match "identificateur\s+\{$([regex]::Escape($fwId))\}") { $inEntry = $true; continue }
                    if ($inEntry -and $line -match 'identificateur\s+\{') { $inEntry = $false }
                    if ($inEntry -and $line -match 'device\s+.*\\(HarddiskVolume\d+)') {
                        $hvKey = $Matches[1].ToLower()
                        if ($hdVolToDisk.ContainsKey($hvKey)) { $priorityEfiDisk = $hdVolToDisk[$hvKey]; break }
                    }
                }
                if ($priorityEfiDisk -ge 0) { break }
            }
        }

        foreach ($efi in $efiParts) {
            $efiSize = Format-Size $efi.Size
            Write-OK "EFI : Disque $($efi.DiskNumber)  | Partition $($efi.PartitionNumber)  | Taille : $efiSize  | Type retourne : '$($efi.Type)'"
            if ($efi.DiskNumber -ne $sysDiskNum) {
                # L'EFI n'est pas sur le meme disque que Windows
                # Si l'EFI prioritaire au firmware EST sur le disque systeme -> juste residuelle
                if ($priorityEfiDisk -ge 0 -and $priorityEfiDisk -eq $sysDiskNum) {
                    Write-OK "EFI residuelle sur Disque $($efi.DiskNumber) (ancienne install) — Disque $sysDiskNum est prioritaire au boot."
                } else {
                    Write-ERR "EFI sur Disque $($efi.DiskNumber) != Windows sur Disque $sysDiskNum !"
                    Write-WARN "=> Sans ce disque, le PC ne peut pas demarrer. Voir section 11."
                }
            } else { Write-OK "EFI et Windows sur le meme disque (Disque $sysDiskNum). OK" }

            # Montage lecture seule pour lister le contenu
            Write-Section "Contenu de la partition EFI (lecture via mountvol)"
            Start-Sleep -Milliseconds 800
            $usedLetters = (Get-PSDrive -PSProvider FileSystem).Name
            $freeLetter  = [string]([char[]](72..90) | Where-Object { $usedLetters -notcontains [string]$_ } | Select-Object -First 1)
            if ($freeLetter -and $efi.Guid) {
                $guidClean = $efi.Guid.ToString().Trim('{}')
                $volId = "\\?\Volume{$guidClean}\"

                # ----------------------------------------------------------------
                # ANTI-POPUP : bloquer l'Explorateur avant d'assigner la lettre
                # ----------------------------------------------------------------
                # Chemin debug log
                $efiDbgLog = if ($DebugEFI) {
                    "$env:USERPROFILE\Desktop\DiagBoot_EFI_Debug_$(Get-Date -f 'yyyyMMdd_HHmmss').log"
                } else { $null }
                function _EfiDbg { param([string]$msg)
                    if ($efiDbgLog) { "[$(Get-Date -f 'HH:mm:ss.fff')] $msg" | Out-File -Append -Encoding UTF8 $efiDbgLog }
                }

                # Lire les valeurs registre NoDriveTypeAutoRun (HKLM + HKCU) avant modif
                $regHKLM = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
                $regHKCU = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
                $oldHKLM = (Get-ItemProperty $regHKLM -Name NoDriveTypeAutoRun -EA SilentlyContinue).NoDriveTypeAutoRun
                $oldHKCU = (Get-ItemProperty $regHKCU -Name NoDriveTypeAutoRun -EA SilentlyContinue).NoDriveTypeAutoRun

                _EfiDbg "Avant montage — HKLM NoDriveTypeAutoRun=$oldHKLM  HKCU NoDriveTypeAutoRun=$oldHKCU"

                # 0xFF = desactiver Autorun pour TOUS les types de lecteurs
                Set-ItemProperty -Path $regHKLM -Name NoDriveTypeAutoRun -Value 0xFF -Type DWord -Force -EA SilentlyContinue
                Set-ItemProperty -Path $regHKCU -Name NoDriveTypeAutoRun -Value 0xFF -Type DWord -Force -EA SilentlyContinue

                # Stopper ShellHWDetection (service qui declenche l'Explorateur)
                $svc = Get-Service ShellHWDetection -EA SilentlyContinue
                $svcWasRunning = ($svc -and $svc.Status -eq 'Running')
                if ($svcWasRunning) {
                    Stop-Service ShellHWDetection -Force -EA SilentlyContinue
                    _EfiDbg "ShellHWDetection stoppe."
                }
                # ----------------------------------------------------------------

                _EfiDbg "mountvol montage : lettre=$freeLetter  volId=$volId"
                mountvol "${freeLetter}:" $volId 2>&1 | Out-Null
                _EfiDbg "mountvol exit=$LASTEXITCODE"
                Start-Sleep -Milliseconds 2000

                if (Test-Path "${freeLetter}:\EFI") {
                    Write-OK "EFI montee en ${freeLetter}:"
                    Get-ChildItem -Recurse -Depth 1 "${freeLetter}:\EFI" -EA SilentlyContinue | ForEach-Object {
                        $depth  = $_.FullName.Split('\').Count - 4
                        $indent = "  " * [Math]::Max(0, $depth)
                        $col2   = if ($_.Extension -eq '.efi') {'Green'} else {'Gray'}
                        Write-Host "    $indent$($_.Name)" -ForegroundColor $col2
                    }
                    $bootmgfw = Get-Item "${freeLetter}:\EFI\Microsoft\Boot\bootmgfw.efi" -EA SilentlyContinue
                    if ($bootmgfw) {
                        $bfi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($bootmgfw.FullName)
                        Write-OK "bootmgfw.efi Version : $($bfi.FileVersion)"
                    } else { Write-WARN "bootmgfw.efi absent !" }
                } else {
                    Write-WARN "\EFI\ introuvable sur ${freeLetter}:"
                    _EfiDbg "EFI\ introuvable apres montage."
                }

                _EfiDbg "mountvol demontage lettre=$freeLetter"
                mountvol "${freeLetter}:" /d 2>&1 | Out-Null
                _EfiDbg "demontage exit=$LASTEXITCODE"
                Write-INFO "EFI demontee."

                # ----------------------------------------------------------------
                # RESTAURATION : remettre exactement comme avant
                # ----------------------------------------------------------------
                if ($null -ne $oldHKLM) {
                    Set-ItemProperty -Path $regHKLM -Name NoDriveTypeAutoRun -Value $oldHKLM -Type DWord -Force -EA SilentlyContinue
                } else {
                    Remove-ItemProperty -Path $regHKLM -Name NoDriveTypeAutoRun -EA SilentlyContinue
                }
                if ($null -ne $oldHKCU) {
                    Set-ItemProperty -Path $regHKCU -Name NoDriveTypeAutoRun -Value $oldHKCU -Type DWord -Force -EA SilentlyContinue
                } else {
                    Remove-ItemProperty -Path $regHKCU -Name NoDriveTypeAutoRun -EA SilentlyContinue
                }
                if ($svcWasRunning) {
                    Start-Service ShellHWDetection -EA SilentlyContinue
                    _EfiDbg "ShellHWDetection redémarre."
                }
                _EfiDbg "Restauration registre OK."
                # ----------------------------------------------------------------

                if ($DebugEFI -and $efiDbgLog -and (Test-Path $efiDbgLog)) {
                    Write-INFO "Debug EFI log : $efiDbgLog"
                }

            } elseif (-not $efi.Guid) {
                Write-INFO "GUID de partition absent — montage impossible (normal sur certains disques dynamiques)."
            } else {
                Write-WARN "Aucune lettre libre disponible pour monter l'EFI."
            }
        }
    }

    # --- 7. BITLOCKER ---
    Write-Title "7. BITLOCKER"
    $blVols = Get-BitLockerVolume -EA SilentlyContinue
    if ($blVols) {
        Write-Host ("  {0,-7} {1,-20} {2,-18} {3}" -f "Vol.","Protection","Chiffrement","Methode") -ForegroundColor White
        Write-Host "  $('-'*65)" -ForegroundColor DarkGray
        foreach ($bl in $blVols) {
            $col = switch ($bl.ProtectionStatus) { 'On'{'Green'} 'Off'{'Gray'} default{'Yellow'} }
            Write-Host ("  {0,-7} {1,-20} {2,-18} {3}" -f $bl.MountPoint,$bl.ProtectionStatus,"$($bl.EncryptionPercentage)%",$bl.EncryptionMethod) -ForegroundColor $col
        }
    } else { Write-WARN "BitLocker non disponible ou aucun volume chiffre." }

    # --- 8. BCD ---
    Write-Title "8. CONFIGURATION BCD"
    $bcdRaw = bcdedit /enum ALL 2>&1
    if ($LASTEXITCODE -ne 0) { Write-ERR "bcdedit inaccessible — droits Administrateur requis." } else {
        foreach ($line in $bcdRaw) {
            if     ($line -match '^-{5,}')                                            { Write-Host "  $line" -ForegroundColor DarkGray }
            elseif ($line -match '^identifier')                                       { Write-Host "  $line" -ForegroundColor Cyan }
            elseif ($line -match '^(device|path|description|locale|default|displayorder)') { Write-Host "  $line" -ForegroundColor Yellow }
            elseif ($line -match 'Windows Boot Manager|bootmgr|EFI|\\EFI\\')         { Write-Host "  $line" -ForegroundColor Magenta }
            else                                                                      { Write-Host "  $line" -ForegroundColor Gray }
        }
    }

    # --- 9. MULTI-WINDOWS ---
    Write-Title "9. INSTALLATIONS WINDOWS DETECTEES"
    $windowsInstalls = @()
    foreach ($vol in $volumes) {
        if (-not $vol.DriveLetter) { continue }
        $letter = "$($vol.DriveLetter):"
        $kernel = "$letter\Windows\System32\ntoskrnl.exe"
        if (Test-Path $kernel -EA SilentlyContinue) {
            $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($kernel)
            $diskNum = ($allParts | Where-Object { $_.DriveLetter -eq $vol.DriveLetter } | Select-Object -First 1).DiskNumber
            $windowsInstalls += [PSCustomObject]@{ Lettre=$letter; Version=$vi.ProductVersion; IsSystem=($letter -eq $env:SystemDrive); DiskNum=$diskNum }
        }
    }
    if ($windowsInstalls.Count -eq 0) { Write-WARN "Aucune installation Windows trouvee sur les volumes montes." }
    elseif ($windowsInstalls.Count -eq 1) {
        Write-OK "Une seule installation Windows detectee."
        $i = $windowsInstalls[0]; Write-INFO "Lecteur : $($i.Lettre) | Version : $($i.Version) | Disque $($i.DiskNum)"
    } else {
        Write-WARN "MULTI-BOOT detecte : $($windowsInstalls.Count) installations !"
        foreach ($i in $windowsInstalls) {
            $tag = if ($i.IsSystem) { "[ACTUEL] " } else { "[AUTRE]  " }
            $col = if ($i.IsSystem) { 'Cyan' } else { 'Yellow' }
            Write-Host "  $tag Lecteur : $($i.Lettre) | Disque $($i.DiskNum) | ntoskrnl : $($i.Version)" -ForegroundColor $col
        }
    }

    # --- 10. ENTREES UEFI ---
    Write-Title "10. ENTREES DE BOOT UEFI"
    $bcdFw = bcdedit /enum firmware 2>&1
    if ($LASTEXITCODE -eq 0) {
        foreach ($line in $bcdFw) {
            if     ($line -match '^-{5,}')      { Write-Host "  $line" -ForegroundColor DarkGray }
            elseif ($line -match 'description') { Write-Host "  $line" -ForegroundColor Green }
            elseif ($line -match 'device|path') { Write-Host "  $line" -ForegroundColor Yellow }
            else                                { Write-Host "  $line" -ForegroundColor Gray }
        }
    } else { Write-WARN "Entrees firmware non disponibles (UEFI natif requis)." }

    # --- 11. PLAN NVMe ---
    Write-Title "11. PLAN D'ACTION — RENDRE LE NVME AUTONOME"
    $nvmeDisk    = $disks | Where-Object { $_.BusType -eq 'NVMe' } | Select-Object -First 1
    $nvmeDiskNum = if ($nvmeDisk) { $nvmeDisk.Number } else { "X" }
    $nvmeWin     = if ($nvmeDisk) { $windowsInstalls | Where-Object { $_.DiskNum -eq $nvmeDisk.Number } | Select-Object -First 1 } else { $null }
    $nvmeLetter  = if ($nvmeWin) { $nvmeWin.Lettre } else { $env:SystemDrive }
    $nvmeEfi     = $efiParts | Where-Object { $_.DiskNumber -eq $sysDiskNum }
    $nvmeIsAutonomous = $nvmeDisk -and $nvmeEfi -and ($priorityEfiDisk -eq $sysDiskNum)
    if ($nvmeIsAutonomous) {
        Write-OK "NVMe (Disque $sysDiskNum) autonome — EFI presente et prioritaire au boot."
        Write-INFO "Aucune action requise."
    } else {
        Write-Host "  Cause : EFI (bootloader) sur SSD, pas sur NVMe." -ForegroundColor Yellow
        Write-Host "  Solution : creer une EFI autonome sur NVMe + copier BCD." -ForegroundColor Yellow
        if ($nvmeDisk) { Write-Host "  NVMe detecte -> Disk $($nvmeDisk.Number) : $($nvmeDisk.FriendlyName)" -ForegroundColor Cyan }
        else           { Write-Host "  NVMe -> non detecte (verifiez BusType en section 3)" -ForegroundColor Red }
        Write-Host ""
        Write-Host "  Etapes rapides :" -ForegroundColor White
        Write-Host "  1. diskpart > select disk $nvmeDiskNum > list partition" -ForegroundColor Gray
        Write-Host "  2a. Si pas d EFI : shrink + create partition efi size=300 + format fat32" -ForegroundColor Gray
        Write-Host "  2b. Si EFI existante : assign letter=S" -ForegroundColor Gray
        Write-Host "  3. bcdboot ${nvmeLetter}\Windows /s S: /f UEFI /l fr-FR" -ForegroundColor White
        Write-Host "  4. bcdedit /store S:\EFI\Microsoft\Boot\BCD /enum all" -ForegroundColor Gray
        Write-Host "  5. diskpart > remove letter=S" -ForegroundColor Gray
        Write-Host "  6. Rebooter avec les 2 disques > valider > tester sans SSD" -ForegroundColor Gray
    }

    # --- 12. RESUME ---
    Write-Title "12. RESUME GLOBAL & ALERTES"
    Write-INFO "Firmware              : $firmware"
    Write-INFO "OS actuel             : $($os.Caption) (Build $($os.BuildNumber))"
    Write-INFO "Disques physiques     : $($disks.Count)"
    Write-INFO "Partitions totales    : $($allParts.Count)"
    Write-INFO "Installations Windows : $($windowsInstalls.Count)"
    Write-INFO "Partitions EFI        : $($efiParts.Count)"
    Write-Host ""
    $alertes = 0
    if ($efiParts) {
        $efiOnSysDisk  = $efiParts | Where-Object { $_.DiskNumber -eq $sysDiskNum }
        $efiOffSysDisk = $efiParts | Where-Object { $_.DiskNumber -ne $sysDiskNum }

        if ($efiOnSysDisk) {
            Write-OK "EFI presente sur le disque systeme (Disque $sysDiskNum). OK"
        }

        if ($efiOffSysDisk -and -not $efiOnSysDisk) {
            # EFI uniquement sur un autre disque = probleme reel
            foreach ($efi in $efiOffSysDisk) {
                Write-ERR "CRITIQUE : EFI uniquement sur Disque $($efi.DiskNumber), Windows sur Disque $sysDiskNum !"
                Write-ACT "=> Appliquer plan section 11 pour migrer l'EFI sur le NVMe"
                $alertes++
            }
        } elseif ($efiOffSysDisk -and $efiOnSysDisk) {
            # EFI residuelle sur un autre disque — reutiliser $priorityEfiDisk calcule en section 6
            # $priorityEfiDisk est le disque de l'entree de boot prioritaire selon {fwbootmgr}
            foreach ($efi in $efiOffSysDisk) {
                if ($priorityEfiDisk -ge 0 -and $priorityEfiDisk -eq $efi.DiskNumber) {
                    Write-WARN "EFI residuelle sur Disque $($efi.DiskNumber) est encore prioritaire dans le firmware — verifier ordre UEFI !"
                    $alertes++
                } else {
                    Write-OK "EFI residuelle sur Disque $($efi.DiskNumber) (ancienne install) — non prioritaire au boot. Suppression possible."
                }
            }
        }
    }
    if ($windowsInstalls.Count -gt 1) { Write-WARN "$($windowsInstalls.Count) installations Windows detectees"; $alertes++ }
    if ($firmware -like "UEFI*" -and ($efiParts.Count -eq 0)) { Write-ERR "CRITIQUE : UEFI sans partition EFI !"; $alertes++ }
    if ($alertes -eq 0) { Write-OK "Aucune alerte detectee." }
    Write-Host ""
    Write-Host "  $('='*70)" -ForegroundColor Cyan
    Write-Host "  Diagnostic termine. Mode lecture seule — aucune modification." -ForegroundColor Green
    Write-Host "  $('='*70)" -ForegroundColor Cyan
    try { Stop-Transcript | Out-Null } catch {}
    Write-Host ""
    Write-Host "  Rapport sauvegarde : $rpt_db" -ForegroundColor Green
}


# ===========================================================================
#  MODULE 3 — AUDIT SOC  (Audit securite SOC/DFIR)
# ===========================================================================

function Invoke-AuditSOC {
    Assert-AdminPrivilege

    $outFile = "$env:USERPROFILE\Desktop\AuditSOC_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    Write-Host ""
    Write-Host "  Lancement de l audit SOC/DFIR..." -ForegroundColor Cyan
    Write-Host "  Rapport : $outFile" -ForegroundColor Yellow
    Write-Host ""

    function Sec($title) {
        Write-Host "`n================================================================" -ForegroundColor DarkCyan
        Write-Host "  $title" -ForegroundColor Yellow
        Write-Host "================================================================" -ForegroundColor DarkCyan
    }
    function Sub($title) { Write-Host "`n  >> $title" -ForegroundColor Magenta }

    & {
        Sec "1 - SYSTEME & IDENTITE"
        Sub "Informations systeme"
        try { Get-ComputerInfo -EA Stop | Select-Object CsName,WindowsProductName,WindowsVersion,OsArchitecture,CsProcessors,CsTotalPhysicalMemory,OsLastBootUpTime,OsInstallDate | Format-List } catch { "Get-ComputerInfo : $_" }
        Sub "Utilisateur courant"
        whoami /all
        Sub "Utilisateurs locaux"
        Get-LocalUser -EA SilentlyContinue | Select-Object Name,Enabled,LastLogon,PasswordRequired,PasswordLastSet,AccountExpires,Description | Format-Table -AutoSize
        Sub "Groupes locaux et membres"
        $gr = foreach ($g in (Get-LocalGroup -EA SilentlyContinue)) {
            $m = Get-LocalGroupMember -Group $g.Name -EA SilentlyContinue | Select-Object -ExpandProperty Name
            [PSCustomObject]@{ Groupe=$g.Name; Membres=($m -join ", ") }
        }
        if ($gr) { $gr | Format-Table -AutoSize }
        Sub "Sessions actives"
        query session 2>$null
        Sub "Derniers logons (4624) - 20 derniers"
        Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624]]" -MaxEvents 20 -EA SilentlyContinue | ForEach-Object {
            try {
                $xml  = [xml]$_.ToXml(); $d = $xml.Event.EventData.Data
                [PSCustomObject]@{ Heure=$_.TimeCreated; User=($d|Where-Object{$_.Name -eq "TargetUserName"}).'#text'; LogonType=($d|Where-Object{$_.Name -eq "LogonType"}).'#text'; IP=($d|Where-Object{$_.Name -eq "IpAddress"}).'#text' }
            } catch { $null }
        } | Where-Object { $_ } | Format-Table -AutoSize

        Sec "2 - RESEAU : PROFIL & INTERFACES"
        Sub "Profil reseau"
        Get-NetConnectionProfile -EA SilentlyContinue | Select-Object Name,NetworkCategory,IPv4Connectivity,IPv6Connectivity | Format-Table -AutoSize
        Sub "Interfaces reseau"
        Get-NetIPAddress -EA SilentlyContinue | Select-Object InterfaceAlias,AddressFamily,IPAddress,PrefixLength,SuffixOrigin | Format-Table -AutoSize
        Sub "Routes actives"
        Get-NetRoute -EA SilentlyContinue | Where-Object { $_.RouteMetric -lt 9999 } | Select-Object InterfaceAlias,DestinationPrefix,NextHop,RouteMetric | Format-Table -AutoSize
        Sub "Table ARP"; arp -a
        Sub "DNS Cache"
        Get-DnsClientCache -EA SilentlyContinue | Select-Object Entry,RecordType,Data,TimeToLive | Format-Table -AutoSize
        Sub "DNS Servers"
        Get-DnsClientServerAddress -EA SilentlyContinue | Select-Object InterfaceAlias,AddressFamily,ServerAddresses | Format-Table -AutoSize
        Sub "Adaptateurs reseau binding (IPv6, LLDP, etc)"
        Get-NetAdapterBinding -EA SilentlyContinue | Select-Object Name,ComponentID,DisplayName,Enabled | Format-Table -AutoSize

        Sec "3 - PORTS & CONNEXIONS RESEAU"
        Sub "LISTENING"
        netstat -ano | findstr "LISTENING"
        Sub "ESTABLISHED"
        netstat -ano | findstr "ESTABLISHED"
        Sub "PID -> Processus"
        $pids2 = netstat -ano | Select-String "LISTENING|ESTABLISHED" | ForEach-Object { ($_ -split "\s+")[-1] } | Where-Object { $_ -match '^\d+$' } | Sort-Object -Unique
        $pr = foreach ($p in $pids2) {
            $proc = Get-Process -Id $p -EA SilentlyContinue
            if ($proc) {
                $owner = try { (Get-CimInstance Win32_Process -Filter "ProcessId=$p" -EA SilentlyContinue).GetOwner().User } catch { "N/A" }
                [PSCustomObject]@{ PID=$p; Nom=$proc.Name; Chemin=$proc.Path; User=$owner }
            }
        }
        if ($pr) { $pr | Format-Table -AutoSize }

        Sec "4 - FIREWALL"
        Sub "Etat global"
        Get-NetFirewallProfile -EA SilentlyContinue | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,LogAllowed,LogBlocked | Format-Table -AutoSize
        Sub "Regles INBOUND actives"
        Get-NetFirewallRule -EA SilentlyContinue | Where-Object { $_.Enabled -eq "True" -and $_.Direction -eq "Inbound" } | Select-Object DisplayName,Profile,Action,Direction | Sort-Object DisplayName | Format-Table -AutoSize
        Sub "Regles OUTBOUND Block"
        Get-NetFirewallRule -EA SilentlyContinue | Where-Object { $_.Enabled -eq "True" -and $_.Direction -eq "Outbound" -and $_.Action -eq "Block" } | Select-Object DisplayName,Profile,Action | Format-Table -AutoSize
        Sub "Regles critiques SMB/RDP/WinRM/SSH..."
        Get-NetFirewallRule -EA SilentlyContinue | Where-Object { $_.DisplayName -match "SMB|RDP|Remote Desktop|SSH|WinRM|UPnP|NetBIOS|LLMNR|mDNS|Docker|WSL|Hyper-V|VMware|445|139|3389|5985|22" } | Select-Object DisplayName,Enabled,Profile,Action,Direction | Format-Table -AutoSize

        Sec "5 - SERVICES WINDOWS"
        Sub "Services en cours"
        Get-Service -EA SilentlyContinue | Where-Object { $_.Status -eq "Running" } | Select-Object Name,DisplayName,Status,StartType | Sort-Object Name | Format-Table -AutoSize
        Sub "Services critiques"
        $critiques = @(
            "LanmanServer","LanmanWorkstation","MrxSmb10","MrxSmb20",
            "SSHD","ssh-agent","WinRM","TermService","SessionEnv","UmRdpService",
            "RemoteRegistry","RemoteAccess",
            "VMware NAT Service","VMwareHostd","VMAuthdService","VMnetDHCP","VMUSBArbService",
            "vmms","HvHost","vmicheartbeat","vmicvss",
            "com.docker.service","WslService","LxssManager",
            "Spooler","SSDPSRV","upnphost","FDResPub","fdPHost",
            "lltdsvc","NlaSvc","DNSCache",
            "MpsSvc","SecurityHealthService","wscsvc","WdNisSvc","WinDefend",
            "W32Time","Netlogon","wuauserv","BITS","EventLog","Schedule"
        )
        $cr = foreach ($s in $critiques) { Get-Service -Name $s -EA SilentlyContinue | Select-Object Name,DisplayName,Status,StartType }
        if ($cr) { $cr | Format-Table -AutoSize }
        Sub "Services VMware (detection auto)"
        Get-Service -EA SilentlyContinue | Where-Object { $_.Name -match "VMware|vmware|vmnat|vmnetdhcp|vmx" } | Select-Object Name,DisplayName,Status,StartType | Format-Table -AutoSize
        Sub "Services SSH (detection auto)"
        Get-Service -EA SilentlyContinue | Where-Object { $_.Name -match "ssh|sshd|openssh" } | Select-Object Name,DisplayName,Status,StartType | Format-Table -AutoSize
        Sub "Services Docker/WSL/Hyper-V (detection auto)"
        Get-Service -EA SilentlyContinue | Where-Object { $_.Name -match "docker|wsl|lxss|vmms|HvHost" } | Select-Object Name,DisplayName,Status,StartType | Format-Table -AutoSize
        Sub "Services VPN (detection auto)"
        Get-Service -EA SilentlyContinue | Where-Object { $_.Name -match "vpn|cisco|pulse|globalprotect|ivpn|nordvpn|expressvpn|openvpn|wireguard" } | Select-Object Name,DisplayName,Status,StartType | Format-Table -AutoSize
        Sub "Services chemin non quote (PrivEsc)"
        Get-CimInstance Win32_Service -EA SilentlyContinue | Where-Object { $_.PathName -notmatch '^"' -and $_.PathName -match ' ' } | Select-Object Name,PathName,StartMode

        Sec "6 - PROTOCOLES SMB"
        Sub "SMB via registre"
        $smb1reg = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB1 -EA SilentlyContinue
        $smb2reg = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB2 -EA SilentlyContinue
        if ($smb1reg) { "SMB1 (registre) : $($smb1reg.SMB1)  [0=desactive, 1=actif]" } else { "SMB1 : cle absente => desactive par defaut (W10/W11)" }
        if ($smb2reg) { "SMB2 (registre) : $($smb2reg.SMB2)  [0=desactive, 1=actif]" } else { "SMB2 : cle absente => actif par defaut" }
        Sub "SMB Config"
        try {
            $smb = Get-SmbServerConfiguration -EA Stop
            [PSCustomObject]@{
                SMB1_Actif         = $smb.EnableSMB1Protocol
                SMB2_Actif         = $smb.EnableSMB2Protocol
                SignatureRequise   = $smb.RequireSecuritySignature
                SignatureActivee   = $smb.EnableSecuritySignature
                Chiffrement        = $smb.EncryptData
                NullSessionPipes   = $smb.NullSessionPipes
                NullSessionShares  = $smb.NullSessionShares
            } | Format-List
        } catch { "Get-SmbServerConfiguration : $_" }
        Sub "Partages SMB"
        Get-SmbShare -EA SilentlyContinue | Select-Object Name,Path,Description,CurrentUsers,ShareState,FolderEnumerationMode | Format-Table -AutoSize
        Sub "Sessions SMB"
        Get-SmbSession -EA SilentlyContinue | Select-Object ClientComputerName,ClientUserName,NumOpens,SecondsExists | Format-Table -AutoSize
        Sub "Connexions SMB ouvertes"
        Get-SmbConnection -EA SilentlyContinue | Select-Object ServerName,ShareName,UserName,Dialect,NumOpens | Format-Table -AutoSize

        Sec "7 - RDP / ACCES DISTANT"
        Sub "Etat RDP"
        $rdp = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -EA SilentlyContinue
        if ($rdp) { if ($rdp.fDenyTSConnections -eq 0) { "RDP : ACTIF (fDenyTSConnections=0)" } else { "RDP : DESACTIVE (fDenyTSConnections=$($rdp.fDenyTSConnections))" } } else { "RDP : cle registre introuvable" }
        Sub "NLA (Network Level Authentication)"
        $nla = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name UserAuthentication -EA SilentlyContinue
        if ($nla) { "NLA : $($nla.UserAuthentication)  [1=requis (securise), 0=desactive]" } else { "NLA : cle introuvable (RDP probablement desactive)" }
        Sub "Port RDP"
        $rdpPort = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name PortNumber -EA SilentlyContinue
        if ($rdpPort) { "Port RDP : $($rdpPort.PortNumber)  [defaut=3389]" }
        Sub "WinRM - Etat"
        $winrm = Get-Service -Name WinRM -EA SilentlyContinue
        if ($winrm) { "WinRM Status : $($winrm.Status) | StartType : $($winrm.StartType)" } else { "WinRM : service introuvable" }
        winrm enumerate winrm/config/listener 2>$null
        Sub "RemoteRegistry"
        $rr = Get-Service -Name RemoteRegistry -EA SilentlyContinue
        if ($rr) { "RemoteRegistry : $($rr.Status) | StartType : $($rr.StartType)" } else { "RemoteRegistry : service introuvable" }

        Sec "8 - NetBIOS / LLMNR / mDNS / IPv6"
        Sub "IPv6 par interface"
        Get-NetAdapterBinding -EA SilentlyContinue | Where-Object { $_.ComponentID -eq "ms_tcpip6" } | Select-Object Name,Enabled | Format-Table -AutoSize
        Sub "Teredo"
        netsh interface teredo show state
        Sub "IPHTTPS"
        netsh interface httpstunnel show interfaces
        Sub "NetBIOS"
        $nb = foreach ($a in (Get-CimInstance Win32_NetworkAdapterConfiguration -EA SilentlyContinue | Where-Object { $_.IPEnabled })) {
            [PSCustomObject]@{ Description=$a.Description; NetBIOS=switch($a.TcpipNetbiosOptions){0{"Via DHCP"}1{"ACTIF"}2{"DESACTIVE"}default{"Inconnu ($($a.TcpipNetbiosOptions))"}} }
        }
        if ($nb) { $nb | Format-Table -AutoSize }
        Sub "LLMNR"
        $llmnr = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast -EA SilentlyContinue
        if ($llmnr) { "LLMNR EnableMulticast : $($llmnr.EnableMulticast)  [0=desactive]" } else { "LLMNR : aucune GPO trouvee => probablement ACTIF par defaut" }
        Sub "mDNS"
        $mdns = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name EnableMDNS -EA SilentlyContinue
        if ($mdns) { "mDNS : $($mdns.EnableMDNS)  [0=desactive]" } else { "mDNS : cle absente => actif par defaut" }

        Sec "9 - ICMP / PING"
        Get-NetFirewallRule -EA SilentlyContinue |
            Where-Object { $_.DisplayName -match "ICMP|Ping|Echo" } |
            Select-Object DisplayName,Enabled,Direction,Action,Profile | Format-Table -AutoSize

        Sec "10 - PROCESSUS SUSPECTS"
        Sub "Processus avec connexions reseau"
        $np = netstat -ano | Select-String "ESTABLISHED|LISTENING" | ForEach-Object { ($_ -split "\s+")[-1] } | Where-Object { $_ -match '^\d+$' } | Sort-Object -Unique
        $pr2 = foreach ($p in $np) {
            $proc = Get-Process -Id $p -EA SilentlyContinue
            if ($proc) { [PSCustomObject]@{ PID=$p; Nom=$proc.Name; Chemin=$proc.Path; CPU=[math]::Round($proc.CPU,2); MemMB=[math]::Round($proc.WorkingSet64/1MB,1) } }
        }
        if ($pr2) { $pr2 | Format-Table -AutoSize }
        Sub "Processus sans chemin (suspects)"
        Get-Process -EA SilentlyContinue | Where-Object { $null -eq $_.Path -and $_.Name -notmatch "^(Idle|System|Registry|smss|csrss|wininit|services|lsass|fontdrvhost|dwm|svchost|conhost|WerFault|WUDFHost|NisSrv|MsMpEng)$" } | Select-Object Id,Name,CPU,Handles | Format-Table -AutoSize
        Sub "Taches planifiees actives non-Microsoft"
        Get-ScheduledTask -EA SilentlyContinue | Where-Object { $_.State -eq "Ready" -and $_.TaskPath -notmatch "\\Microsoft\\" } | Select-Object TaskName,TaskPath,State | Sort-Object TaskPath | Format-Table -AutoSize
        Sub "Actions des taches planifiees non-Microsoft"
        $tacheActions = Get-ScheduledTask -EA SilentlyContinue | Where-Object { $_.State -ne "Disabled" -and $_.TaskPath -notmatch "\\Microsoft\\" }
        $actResults = foreach ($t in $tacheActions) {
            foreach ($a in $t.Actions) {
                [PSCustomObject]@{ Tache=$t.TaskName; Execute=$a.Execute; Args=$a.Arguments }
            }
        }
        if ($actResults) { $actResults | Format-Table -AutoSize }

        Sec "11 - REGISTRE : PERSISTANCE & SECURITE"
        Sub "Run Keys (demarrage auto)"
        @(
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
        ) | ForEach-Object {
                $val = Get-ItemProperty $_ -EA SilentlyContinue
                if ($val) { Write-Host "  $_" -ForegroundColor Cyan; $val.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object { "    $($_.Name) = $($_.Value)" } }
            }
        Sub "LSA Protection"
        $lsa = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -EA SilentlyContinue
        if ($lsa) {
            "LmCompatibilityLevel : $($lsa.LmCompatibilityLevel)  [5=NTLMv2 uniquement, recommande]"
            "NoLMHash             : $($lsa.NoLMHash)  [1=pas de hash LM, recommande]"
            "RunAsPPL             : $($lsa.RunAsPPL)  [1=LSA protege, recommande]"
            "RestrictAnonymous    : $($lsa.RestrictAnonymous)"
            "RestrictAnonymousSAM : $($lsa.RestrictAnonymousSAM)"
        } else { "Cle LSA introuvable" }
        Sub "UAC"
        $uac = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -EA SilentlyContinue
        if ($uac) {
            "EnableLUA                      : $($uac.EnableLUA)  [1=UAC actif]"
            "ConsentPromptBehaviorAdmin     : $($uac.ConsentPromptBehaviorAdmin)  [2=credentials, 5=confirmation]"
            "LocalAccountTokenFilterPolicy  : $($uac.LocalAccountTokenFilterPolicy)  [0=recommande]"
        } else { "Cle UAC introuvable" }
        Sub "PowerShell Logging"
        $psl = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -EA SilentlyContinue
        if ($psl) { "ScriptBlock Logging : $($psl.EnableScriptBlockLogging)  [1=actif, recommande]" } else { "ScriptBlock Logging : NON CONFIGURE (desactive)" }
        $psmod = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -EA SilentlyContinue
        if ($psmod) { "Module Logging : $($psmod.EnableModuleLogging)" } else { "Module Logging : NON CONFIGURE (desactive)" }
        $pstrans = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -EA SilentlyContinue
        if ($pstrans) { "Transcription PS : $($pstrans.EnableTranscripting)" } else { "Transcription PS : NON CONFIGURE (desactive)" }
        Sub "AMSI (Antimalware Scan Interface)"
        $amsiReg = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\AMSI" -EA SilentlyContinue
        if ($amsiReg) { $amsiReg | Format-List } else { "Cle AMSI non trouvee (normal si non modifiee)" }

        Sec "12 - WINDOWS DEFENDER / ANTIVIRUS"
        Sub "Etat Windows Defender"
        try {
            Get-MpComputerStatus -EA Stop | Select-Object AMServiceEnabled,AntispywareEnabled,AntivirusEnabled,RealTimeProtectionEnabled,IoavProtectionEnabled,NISEnabled,AntivirusSignatureLastUpdated,QuickScanAge | Format-List
        } catch { "Defender indisponible : $_" }
        Sub "Exclusions Defender (risque potentiel)"
        try {
            $ex = Get-MpPreference -EA Stop
            "Paths    : $(if($ex.ExclusionPath){$ex.ExclusionPath -join ', '}else{'(aucune)'})"
            "Process  : $(if($ex.ExclusionProcess){$ex.ExclusionProcess -join ', '}else{'(aucune)'})"
            "Ext      : $(if($ex.ExclusionExtension){$ex.ExclusionExtension -join ', '}else{'(aucune)'})"
        } catch { "Preferences Defender inaccessibles" }

        Sec "13 - EVENEMENTS SECURITE RECENTS"
        Sub "Echecs connexion (4625) - 10 derniers"
        Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4625]]" -MaxEvents 10 -EA SilentlyContinue | ForEach-Object {
            try { $xml=[xml]$_.ToXml(); $d=$xml.Event.EventData.Data; [PSCustomObject]@{Heure=$_.TimeCreated;User=($d|Where-Object{$_.Name -eq "TargetUserName"}).'#text';IP=($d|Where-Object{$_.Name -eq "IpAddress"}).'#text';LogonType=($d|Where-Object{$_.Name -eq "LogonType"}).'#text'} } catch {$null}
        } | Where-Object { $_ } | Format-Table -AutoSize
        Sub "Connexions reussies (4624) - 10 derniers"
        Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4624]]" -MaxEvents 10 -EA SilentlyContinue | ForEach-Object {
            try { $xml=[xml]$_.ToXml(); $d=$xml.Event.EventData.Data; [PSCustomObject]@{Heure=$_.TimeCreated;User=($d|Where-Object{$_.Name -eq "TargetUserName"}).'#text';LogonType=($d|Where-Object{$_.Name -eq "LogonType"}).'#text';IP=($d|Where-Object{$_.Name -eq "IpAddress"}).'#text'} } catch {$null}
        } | Where-Object { $_ } | Format-Table -AutoSize
        Sub "Services installes recemment (7045)"
        Get-WinEvent -LogName System -FilterXPath "*[System[EventID=7045]]" -MaxEvents 10 -EA SilentlyContinue | ForEach-Object {
            try { $xml=[xml]$_.ToXml(); $d=$xml.Event.EventData.Data; [PSCustomObject]@{Heure=$_.TimeCreated;Service=($d|Where-Object{$_.Name -eq "ServiceName"}).'#text';Chemin=($d|Where-Object{$_.Name -eq "ImagePath"}).'#text';Type=($d|Where-Object{$_.Name -eq "ServiceType"}).'#text'} } catch {$null}
        } | Where-Object { $_ } | Format-Table -AutoSize
        Sub "Effacement logs (1102)"
        Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=1102]]" -MaxEvents 5 -EA SilentlyContinue | Select-Object TimeCreated,Message | Format-List
        Sub "Ajout membres groupes privilegies (4732/4728)"
        Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4732 or EventID=4728]]" -MaxEvents 10 -EA SilentlyContinue | ForEach-Object {
            try { $xml=[xml]$_.ToXml(); $d=$xml.Event.EventData.Data; [PSCustomObject]@{Heure=$_.TimeCreated;EID=$_.Id;Compte=($d|Where-Object{$_.Name -eq "MemberName"}).'#text';Groupe=($d|Where-Object{$_.Name -eq "TargetUserName"}).'#text';Par=($d|Where-Object{$_.Name -eq "SubjectUserName"}).'#text'} } catch {$null}
        } | Where-Object { $_ } | Format-Table -AutoSize

        Sec "14 - MISES A JOUR WINDOWS"
        Sub "Derniers hotfix installes"
        Get-HotFix -EA SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 15 | Select-Object HotFixID,Description,InstalledOn,InstalledBy | Format-Table -AutoSize
        Sub "Windows Update - derniere verification"
        $wudet = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect" -EA SilentlyContinue
        if ($wudet) { "Derniere detection WU : $($wudet.LastSuccessTime)" } else { "Cle WU introuvable" }

        Sec "15 - CHIFFREMENT & CERTIFICATS"
        Sub "BitLocker"
        try { manage-bde -status 2>$null } catch { "manage-bde indisponible" }
        Sub "Certificats Machine expirant dans < 90 jours"
        Get-ChildItem Cert:\LocalMachine\My -EA SilentlyContinue |
            Where-Object { $_.NotAfter -lt (Get-Date).AddDays(90) } |
            Select-Object Subject,NotAfter,Thumbprint | Format-Table -AutoSize
        Sub "Certificats racine non-Microsoft (verification recommandee)"
        Get-ChildItem Cert:\LocalMachine\Root -EA SilentlyContinue |
            Where-Object { $_.Issuer -notmatch "Microsoft|Thawte|DigiCert|Comodo|Sectigo|GlobalSign|VeriSign|Let.s Encrypt|ISRG|Baltimore|Symantec|GeoTrust|AddTrust" } |
            Select-Object Subject,Issuer,NotAfter,Thumbprint | Format-Table -AutoSize

        Write-Host "`n================================================================" -ForegroundColor Green
        Write-Host "  FIN DE L AUDIT SOC/DFIR - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Green
        Write-Host "================================================================`n" -ForegroundColor Green

    } | Tee-Object $outFile

    Write-Host "  Rapport sauvegarde : $outFile" -ForegroundColor Green
    try { notepad $outFile } catch {}
}

function Invoke-EDR {
# ===========================================================================
#  MODULE 4 — EDR/AV  (Audit securite + score + remediation)
# ===========================================================================
param(
    [Alias("FixMode")]
    [ValidateSet("All", "Firewall", "SmartScreen", "Defender", "SMBv1", "LSA", "None")]
    [string]$Fix = "None",
    [switch]$ShareDpaste,
    [switch]$ShareGofile,
    [switch]$Help
)

    Assert-AdminPrivilege

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin -and $Fix -ne "None") {
    Write-Host "`n  [ ACCÈS REFUSÉ ]" -ForegroundColor White -BackgroundColor Red
    Write-Host "   Erreur : Les privilèges Administrateur sont requis pour réparer : -Fix $Fix" -ForegroundColor Red
    Write-Host "   Conseil : Faites un clic droit sur PowerShell > 'Exécuter en tant qu'administrateur'." -ForegroundColor Gray
    exit
}

function Show-Banner {
    Clear-Host
    $banner = @"

                                    ███████╗██████╗ ██████╗ 
                                    ██╔════╝██╔══██╗██╔══██╗
                                    █████╗  ██║  ██║██████╔╝
                                    ██╔══╝  ██║  ██║██╔══██╗
                                    ███████╗██████╔╝██║  ██║
                                    ╚══════╝╚═════╝ ╚═╝  ╚═╝
"@
    Write-Host $banner -ForegroundColor Cyan
}
if ($Help) {

    Show-Banner

    Write-Host "`n                                        [ EDR - AIDE ]" -ForegroundColor Cyan
    Write-Host " ------------------------------------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host " [ COMMANDE ]" -ForegroundColor White
    Write-Host "   .\EDRauditAV.ps1                 -> Audit (Lecture seule)" -ForegroundColor Gray
    Write-Host "   .\EDRauditAV.ps1 -Fix Firewall   -> Répare le Firewall" -ForegroundColor Yellow
    Write-Host "   .\EDRauditAV.ps1 -Fix SmartScreen -> Répare SmartScreen" -ForegroundColor Yellow
    Write-Host "   .\EDRauditAV.ps1 -Fix Defender    -> Répare Windows Defender" -ForegroundColor Yellow
    Write-Host "   .\EDRauditAV.ps1 -Fix SMBv1       -> Répare SMBv1" -ForegroundColor Yellow
    Write-Host "   .\EDRauditAV.ps1 -Fix LSA         -> Répare le LSA" -ForegroundColor Yellow
    Write-Host "   .\EDRauditAV.ps1 -Fix All          -> RÉPARER TOUT" -ForegroundColor Cyan
    Write-Host ""
    Write-Host " [ EXPORT & PARTAGE ]" -ForegroundColor White
    Write-Host ""
    Write-Host "   .\EDRauditAV.ps1 -ShareDpaste    -> Upload vers dpaste (Lecture Web directe)" -ForegroundColor Magenta
    Write-Host "   .\EDRauditAV.ps1 -ShareGofile    -> Upload vers Gofile (Téléchargement fichier)" -ForegroundColor Magenta
    Write-Host ""
    Write-Host " ------------------------------------------------------------------------------------------------" -ForegroundColor Cyan

    exit
}

& {
#----------------------------------------------------
#  START TRANSCRIPTION
#----------------------------------------------------
$script:outDir = "$env:USERPROFILE\Desktop\EDR_$(Get-Date -Format 'yyyyMMdd')"
New-Item -ItemType Directory -Force -Path $script:outDir | Out-Null
$script:PathBureau = "$script:outDir\Rapport_EDR.txt"

if ($ShareDpaste -or $ShareGofile) {
    Start-Transcript -Path $PathBureau -Force -ErrorAction SilentlyContinue | Out-Null
} else {
    # WARN #3 CORRIGÉ : toujours transcrire pour ne pas laisser le rapport vide
    Start-Transcript -Path $PathBureau -Force -ErrorAction SilentlyContinue | Out-Null
}

# Variables pour le score de sécurité global (IDEA #2)
$scoreChecks = [System.Collections.Generic.List[PSCustomObject]]::new()
function Add-ScoreCheck {
    param([string]$Nom, [bool]$OK, [int]$Poids = 10)
    $scoreChecks.Add([PSCustomObject]@{ Nom=$Nom; OK=$OK; Poids=$Poids })
}


Write-Host "`n================ DIAG SECURITE COMPLET =================" -ForegroundColor Cyan

function Invoke-SecurityFix {
    param([string]$Type)
    Write-Host "`n[!] Remédiation DFIR en cours pour : $Type..." -ForegroundColor Cyan
    
    switch ($Type) {
        "Firewall" { 
            Write-Host "Nettoyage des restrictions GPO et reset Firewall..." -ForegroundColor Gray
            Remove-Item "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall" -Recurse -ErrorAction SilentlyContinue
            netsh advfirewall set allprofiles state on; netsh advfirewall reset 
        }
        
        "SmartScreen" { 
            Write-Host "Suppression des blocages GPO et activation SmartScreen..." -ForegroundColor Gray
            $null = Remove-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -ErrorAction SilentlyContinue
            Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "RequireAdmin" -Force
        }

        "Defender" { 
            Write-Host "Réactivation forcée des moteurs Defender..." -ForegroundColor Gray
            # WARN #4 CORRIGÉ : vérifier TamperProtection avant d'appliquer le fix
            $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
            if ($mpStatus -and $mpStatus.IsTamperProtected) {
                Write-Host "⚠ ATTENTION : La protection contre les falsifications (Tamper Protection) est activée." -ForegroundColor Yellow
                Write-Host "   La remédiation automatique peut être bloquée par Windows." -ForegroundColor Yellow
                Write-Host "   >> ACTION MANUELLE : Désactivez temporairement Tamper Protection dans Sécurité Windows > Protection antivirus > Paramètres." -ForegroundColor Gray
            }
            Set-MpPreference -PUAProtection Enabled -RealTimeProtectionEnabled $true -DisableBlockAtFirstSeen $false
        }

        "SMBv1" { 
            Write-Host "Désactivation du protocole vulnérable (CVE-2017-0144)..." -ForegroundColor Gray
            Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
        }

        "LSA" { 
            Write-Host "Application protection LSA (RunAsPPL)..." -ForegroundColor Gray
            Remove-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "LsaCfgFlags" -ErrorAction SilentlyContinue
            Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -PropertyType DWord -Force
        }
    }
    Write-Host "OK : Remédiation terminée." -ForegroundColor Green
}

#----------------------------------------------------
#  1. ANTIVIRUS (Security Center) 
#----------------------------------------------------

Write-Host "`n>>> Antivirus détectés (WMI / Security Center) :" -ForegroundColor Yellow

# --- VendorDB : AV/EDR connus (service = validation presence reelle) ---
$vendorDB = @{
    # AV grand public
    "Norton"              = @{ Type="AV";  ServiceName="NortonSecurity";           PassifAttendu=$false; HorsSecurityCenter=$false }
    "Bitdefender"         = @{ Type="AV";  ServiceName="bdservicehost";            PassifAttendu=$false; HorsSecurityCenter=$false }
    "Malwarebytes"        = @{ Type="AV";  ServiceName="MBAMService";              PassifAttendu=$false; HorsSecurityCenter=$false }
    "McAfee"              = @{ Type="AV";  ServiceName="McShield";                 PassifAttendu=$false; HorsSecurityCenter=$false }
    "ESET"                = @{ Type="AV";  ServiceName="ekrn";                     PassifAttendu=$false; HorsSecurityCenter=$false }
    "Kaspersky"           = @{ Type="AV";  ServiceName="AVP";                      PassifAttendu=$false; HorsSecurityCenter=$false }
    "Avast"               = @{ Type="AV";  ServiceName="avast! Antivirus";         PassifAttendu=$false; HorsSecurityCenter=$false }
    "AVG"                 = @{ Type="AV";  ServiceName="AVGSvc";                   PassifAttendu=$false; HorsSecurityCenter=$false }
    "Sophos"              = @{ Type="AV";  ServiceName="Sophos MCS Agent";         PassifAttendu=$false; HorsSecurityCenter=$false }
    "Trend Micro"         = @{ Type="AV";  ServiceName="TmListen";                 PassifAttendu=$false; HorsSecurityCenter=$false }
    "F-Secure"            = @{ Type="AV";  ServiceName="F-Secure Gatekeeper";      PassifAttendu=$false; HorsSecurityCenter=$false }
    "Panda"               = @{ Type="AV";  ServiceName="PSANToManager";            PassifAttendu=$false; HorsSecurityCenter=$false }
    "G Data"              = @{ Type="AV";  ServiceName="GDScan";                   PassifAttendu=$false; HorsSecurityCenter=$false }
    "Comodo"              = @{ Type="AV";  ServiceName="COMODO Internet Security";  PassifAttendu=$false; HorsSecurityCenter=$false }
    "Webroot"             = @{ Type="AV";  ServiceName="WRSVC";                    PassifAttendu=$false; HorsSecurityCenter=$false }
    "Cylance"             = @{ Type="AV";  ServiceName="CylanceSvc";               PassifAttendu=$false; HorsSecurityCenter=$false }
    # EDR entreprise (hors SecurityCenter)
    "CrowdStrike"         = @{ Type="EDR"; ServiceName="CSFalconService";          PassifAttendu=$false; HorsSecurityCenter=$true  }
    "SentinelOne"         = @{ Type="EDR"; ServiceName="SentinelAgent";            PassifAttendu=$false; HorsSecurityCenter=$true  }
    "Carbon Black"        = @{ Type="EDR"; ServiceName="CbDefense";                PassifAttendu=$false; HorsSecurityCenter=$true  }
    "Cybereason"          = @{ Type="EDR"; ServiceName="CybereasonAV";             PassifAttendu=$false; HorsSecurityCenter=$true  }
    "MDE"                 = @{ Type="EDR"; ServiceName="Sense";                    PassifAttendu=$false; HorsSecurityCenter=$true  }
    "Cortex XDR"          = @{ Type="EDR"; ServiceName="cyserver";                 PassifAttendu=$false; HorsSecurityCenter=$true  }
    "Trellix"             = @{ Type="EDR"; ServiceName="xagt";                     PassifAttendu=$false; HorsSecurityCenter=$true  }
    "Elastic Endpoint"    = @{ Type="EDR"; ServiceName="ElasticEndpoint";          PassifAttendu=$false; HorsSecurityCenter=$true  }
    "Tanium"              = @{ Type="EDR"; ServiceName="Tanium Client";             PassifAttendu=$false; HorsSecurityCenter=$true  }
    "Harfanglab"          = @{ Type="EDR"; ServiceName="HarfangLab";               PassifAttendu=$false; HorsSecurityCenter=$true  }
}

# --- WARN #1 : Get-CimInstance entouré d'un try/catch ---
$avRaw = @()
try {
    $avRaw = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction Stop)
} catch {
    Write-Host "⚠ ATTENTION : WMI SecurityCenter2 inaccessible (domaine restreint ?). Détection AV partielle." -ForegroundColor Yellow
    Write-Host "   Détail : $_" -ForegroundColor Gray
}

$avProducts = $avRaw | ForEach-Object {
    $stateHex = [System.Convert]::ToString($_.productState, 16).PadLeft(6, '0')
    $status = switch ($stateHex.Substring(2,2)) {
        { $_ -in "10","11" }  { "ACTIF" }
        "01"                  { "ACTIF (signatures obsolètes)" }
        "00"                  { "ACTIF (signatures hors-date)" }
        default               { "INACTIF" }
    }

    # FIX FANTOME : un AV dans WMI sans service actif = résidu de désinstallation
    $nomLower = $_.displayName.ToLower()
    $vendorEntry = $vendorDB.GetEnumerator() | Where-Object { $nomLower -like "*$($_.Key.ToLower())*" } | Select-Object -First 1
    $servicePresent = $true
    if ($vendorEntry -and -not $vendorEntry.Value.HorsSecurityCenter) {
        $svc = Get-Service $vendorEntry.Value.ServiceName -ErrorAction SilentlyContinue
        if (-not $svc) { $servicePresent = $false }
    }

    [PSCustomObject]@{
        Nom            = $_.displayName
        Etat           = if (-not $servicePresent) { "FANTOME (desinstalle)" } else { $status }
        EtatBrut       = $_.productState
        state          = if (-not $servicePresent) { "FANTOME" } else { $status }
        displayName    = $_.displayName
        ServicePresent = $servicePresent
    }
}

# Affichage propre sans Format-Table
foreach ($av in $avProducts) {
    $couleur = switch -Wildcard ($av.Etat) {
        "ACTIF*"   { "Green"  }
        "FANTOME*" { "DarkGray" }
        default    { "Red"    }
    }
    $icon = switch -Wildcard ($av.Etat) {
        "ACTIF*"   { "[OK]"  }
        "FANTOME*" { "[--]"  }
        default    { "[KO]"  }
    }
    $fantomeNote = if ($av.Etat -like "FANTOME*") { "  <- service absent, residue WMI a nettoyer" } else { "" }
    Write-Host "   $icon  $($av.Nom)" -ForegroundColor $couleur -NoNewline
    Write-Host "  [$($av.Etat)]$fantomeNote" -ForegroundColor $couleur
}

# Exclure les fantômes des analyses suivantes
$avProducts = @($avProducts | Where-Object { $_.ServicePresent -or $_.Nom -like "*Windows Defender*" })

#----------------------------------------------------
#  2. WINDOWS DEFENDER DETAIL COMPLET 
#----------------------------------------------------
Write-Host "`n>>> Windows Defender (détail complet) :" -ForegroundColor Yellow

$avTiers = ($avProducts | Where-Object { $_.displayName -notlike "*Windows Defender*" }).displayName

try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    $excl = Get-MpPreference -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ExclusionPath
    
    $sigAge = 0
    if ($mp.AntivirusSignatureLastUpdated) {
        $sigAge = (New-TimeSpan -Start $mp.AntivirusSignatureLastUpdated -End (Get-Date)).TotalHours
    }

    $defLines = [ordered]@{
        "Moteur actif"          = $mp.AntivirusEnabled
        "Protection temps reel" = $mp.RealTimeProtectionEnabled
        "Signatures date"       = if($mp.AntivirusSignatureLastUpdated){$mp.AntivirusSignatureLastUpdated}else{"[INDISPONIBLE]"}
        "Signatures age (h)"    = if($sigAge -gt 0){[Math]::Round($sigAge, 1)}else{"N/A"}
        "Tamper Protection"     = $mp.IsTamperProtected
        "Exclusions actives"    = if($excl){"OUI ($($excl -join ', '))"}else{"NON"}
    }
    foreach ($kv in $defLines.GetEnumerator()) {
        $val = $kv.Value
        $color = "Cyan"
        if ($val -is [bool]) { $color = if($val){"Green"}else{"Red"} }
        Write-Host "   $($kv.Key.PadRight(25)) : " -NoNewline -ForegroundColor Gray
        Write-Host "$val" -ForegroundColor $color
    }

    if ($mp.RealTimeProtectionEnabled -eq $false) {
        # BUG #2 CORRIGÉ : vérifier aussi via vendorDB/services si un AV tiers est réellement actif
        $avTiersActifService = $vendorDB.GetEnumerator() | Where-Object {
            -not $_.Value.HorsSecurityCenter -and
            (Get-Service $_.Value.ServiceName -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' })
        } | Select-Object -ExpandProperty Key

        $protectionActive = $avTiers -or $avTiersActifService

        if ($protectionActive) {
            $nomProtection = if ($avTiers) { $avTiers -join ' + ' } else { $avTiersActifService -join ' + ' }
            Write-Host "ℹ INFO : Defender est en mode passif/veille. [$nomProtection] assure la protection active." -ForegroundColor Cyan
        } else {
            Write-Host "⚠ ALERTE : Aucune protection temps réel ! Le système est à découvert." -ForegroundColor Red
        }
    }
    
    if ($sigAge -gt 24 -and $mp.AntivirusEnabled) { 
        Write-Host "⚠ CONSEIL : Signatures obsolètes (+24h). Vérifiez Windows Update." -ForegroundColor Yellow 
    }

} catch {
    $service = Get-Service WinDefend -ErrorAction SilentlyContinue
    if ($avTiers) {
        Write-Host "ℹ INFO : Defender est verrouillé par le système (0x800106ba)." -ForegroundColor Cyan
        Write-Host ">> CAUSE : [$($avTiers -join ', ')] gère la sécurité. C'est un comportement normal." -ForegroundColor Gray
    } else {
        Write-Host "⚠ ERREUR CRITIQUE : Le moteur Defender est injoignable ($($service.Status))." -ForegroundColor Red
        Write-Host ">> FIX : Vérifiez si un malware ne bloque pas le service WinDefend." -ForegroundColor Gray
    }
}
#----------------------------------------------------
#  3. SMARTSCREEN 
#----------------------------------------------------
Write-Host "`n>>> SmartScreen (Analyse des vecteurs d'entrée) :" -ForegroundColor Yellow
try {
    # StrictMode du scope global peut lever des exceptions sur les propriétés nulles — on le désactive localement
    Set-StrictMode -Off
    $regHKLM   = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -ErrorAction SilentlyContinue
    $regHKCU   = Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -ErrorAction SilentlyContinue
    $regGPO    = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -ErrorAction SilentlyContinue
    $smachine  = if ($null -ne $regHKLM)  { $regHKLM.SmartScreenEnabled   } else { $null }
    $suser     = if ($null -ne $regHKCU)  { $regHKCU.SmartScreenEnabled   } else { $null }
    $edge      = if ($null -ne $regGPO)   { $regGPO.EnableSmartScreen      } else { $null }
    Set-StrictMode -Version Latest

    $ssLines = [ordered]@{
        "Registry System (HKLM)" = if($null -ne $smachine){$smachine}else{"[ABSENT/NON-DEFINI]"}
        "Registry User (HKCU)"   = if($null -ne $suser){$suser}else{"[ABSENT/NON-DEFINI]"}
        "GPO Policy (Edge)"      = if($null -ne $edge){$edge}else{"[NON-CONFIGURE]"}
    }
    foreach ($kv in $ssLines.GetEnumerator()) {
        Write-Host "   $($kv.Key.PadRight(28)) : " -NoNewline -ForegroundColor Gray
        Write-Host "$($kv.Value)" -ForegroundColor Cyan
    }

    if ($smachine -match "Off" -or $null -eq $smachine -or $edge -eq 0) {
        Write-Host "⚠ ETAT : INACTIF (Le système ne bloque pas les fichiers non signés)." -ForegroundColor Red
        Add-ScoreCheck -Nom "SmartScreen" -OK $false -Poids 10
    if ($Fix -eq "SmartScreen" -or $Fix -eq "All") {
        Invoke-SecurityFix -Type "SmartScreen" 
    } else {
        Write-Host ">> CONSEIL : Relancez avec -Fix pour réparer ce point." -ForegroundColor Gray
    }        
        if ($edge -eq 0) {
            Write-Host ">> FIX GPO DETECTÉE : Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableSmartScreen' -Force" -ForegroundColor Magenta
        }
        
        Write-Host ">> FIX MANUEL (CLI) : New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'SmartScreenEnabled' -Value 'RequireAdmin' -PropertyType String -Force" -ForegroundColor Gray
        
        Write-Host ">> FIX MANUEL (GUI) : Sécurité Windows > Contrôle des applis > Protection fondée sur la réputation > Activer tout." -ForegroundColor Gray
    } else {
        Write-Host "OK : SmartScreen est configuré sur [$smachine]." -ForegroundColor Green
        Add-ScoreCheck -Nom "SmartScreen" -OK $true -Poids 10
    }
} catch {
    Write-Host "SmartScreen non accessible" -ForegroundColor Red
}

#----------------------------------------------------
# 4. DURCISSEMENT IDENTITÉ (LSA - ANTI-MIMIKATZ) 
#----------------------------------------------------
Write-Host "`n>>> Hardening Identité (LSASS Protection) :" -ForegroundColor Yellow

$lsaRaw = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
$lsaVal = $lsaRaw.RunAsPPL

$lsaPolicy = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -ErrorAction SilentlyContinue
$lsaForcedOff = $null -ne $lsaPolicy.LsaCfgFlags -and $lsaPolicy.LsaCfgFlags -eq 0

Write-Host "Preuve Registry (RunAsPPL) : " -NoNewline
if ($null -eq $lsaVal) { 
    Write-Host "VALEUR ABSENTE (VULNÉRABLE)" -ForegroundColor Red 
} elseif ($lsaVal -eq 1 -or $lsaVal -eq 2) { 
    Write-Host "$lsaVal" -ForegroundColor Green 
} else { 
    Write-Host "$lsaVal" -ForegroundColor Red 
}

if ($lsaVal -eq 1 -or $lsaVal -eq 2) {
    $mode = if($lsaVal -eq 2){"UEFI (Verrouillé)"} else {"Standard"}
    Write-Host "OK : Le processus LSASS tourne en mode PPL ($mode)." -ForegroundColor Green
    Add-ScoreCheck -Nom "Protection LSA (RunAsPPL)" -OK $true -Poids 15
} else {
    Write-Host "⚠ VULNÉRABLE : Les outils type Mimikatz peuvent dumper les credentials en mémoire." -ForegroundColor Red
    Add-ScoreCheck -Nom "Protection LSA (RunAsPPL)" -OK $false -Poids 15
    if ($Fix -eq "LSA" -or $Fix -eq "All") {
        Invoke-SecurityFix -Type "LSA" 
    } else {
        Write-Host ">> CONSEIL : Relancez avec -Fix pour activer la protection LSA." -ForegroundColor Gray
    }    
    if ($lsaForcedOff) {
        Write-Host ">> FIX GPO DETECTÉE : Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -Name 'LsaCfgFlags' -Force" -ForegroundColor Magenta
    }

    Write-Host ">> FIX MANUEL (CLI) : Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -Value 1 -Type DWord" -ForegroundColor Gray
    Write-Host ">> FIX MANUEL (GUI) : Sécurité Windows > Sécurité de l'appareil > Isolation du noyau > Protection de l'autorité de sécurité locale." -ForegroundColor Gray
}

#----------------------------------------------------
# 5. FIREWALL (Dynamique & GPO)
#----------------------------------------------------
Write-Host "`n>>> Pare-feu :" -ForegroundColor Yellow
$fw = Get-NetFirewallProfile
foreach ($profile in $fw) {
    $icon  = if ($profile.Enabled) { "[OK]" } else { "[KO]" }
    $color = if ($profile.Enabled) { "Green" } else { "Red" }
    Write-Host "   $icon  $($profile.Name.PadRight(12)) : $(if($profile.Enabled){'Actif'}else{'DESACTIVE'})" -ForegroundColor $color
}

if ($fw.Enabled -contains $false) {
    Write-Host "⚠ ALERTE : Un profil Firewall est désactivé !" -ForegroundColor Red
    Add-ScoreCheck -Nom "Firewall" -OK $false -Poids 15
    if ($Fix -eq "Firewall" -or $Fix -eq "All") { 
        Invoke-SecurityFix -Type "Firewall" 
    } else {
        Write-Host ">> CONSEIL : Relancez avec -Fix pour activer la protection Firewall." -ForegroundColor Gray
    }    
    $fwPolicies = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -ErrorAction SilentlyContinue
    if ($null -ne $fwPolicies -and $fwPolicies.EnableFirewall -eq 0) {
        Write-Host ">> FIX GPO DETECTÉE : La stratégie force la coupure. Supprimer les clés dans HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall" -ForegroundColor Magenta
    }
    Write-Host ">> FIX MANUEL (CLI) : Set-NetFirewallProfile -All -Enabled True" -ForegroundColor Gray
} else {
    Write-Host "OK : Tous les profils Pare-feu sont actifs." -ForegroundColor Green
    Add-ScoreCheck -Nom "Firewall" -OK $true -Poids 15
}

#----------------------------------------------------
# 6. SERVICES CRITIQUES 
#----------------------------------------------------
Write-Host "`n>>> Services sécurité (Système & Tiers) :" -ForegroundColor Yellow
$secServices = "WinDefend","SecurityHealthService","BFE","bdservicehost","mfevtp","McShield","avast","MBAMService","SentinelAgent","CSFalconService","CbDefense","ekrn","AVP","CybereasonAV"
Get-Service $secServices -ErrorAction SilentlyContinue | ForEach-Object {
    $icon  = if ($_.Status -eq "Running") { "[OK]" } else { "[--]" }
    $color = if ($_.Status -eq "Running") { "Green" } else { "Gray" }
    Write-Host "   $icon  $($_.Name.PadRight(25)) $($_.Status.ToString().PadRight(10)) StartType: $($_.StartType)" -ForegroundColor $color
}

# IDEA #3 / WARN #2 : Détection EDR hors SecurityCenter2, croisé avec vendorDB
Write-Host "`n>>> EDR / AV hors SecurityCenter (CrowdStrike, SentinelOne, Carbon Black...) :" -ForegroundColor Yellow
$edrHorsWMI = [System.Collections.Generic.List[PSCustomObject]]::new()
foreach ($vendor in $vendorDB.GetEnumerator()) {
    if ($vendor.Value.HorsSecurityCenter) {
        $svc = Get-Service $vendor.Value.ServiceName -ErrorAction SilentlyContinue
        if ($svc) {
            $edrHorsWMI.Add([PSCustomObject]@{
                Nom     = $vendor.Key
                Service = $svc.Name
                Statut  = $svc.Status
                Type    = $vendor.Value.Type
            })
        }
    }
}

if ($edrHorsWMI.Count -gt 0) {
    foreach ($edr in $edrHorsWMI) {
        $icon  = if ($edr.Statut -eq "Running") { "[OK]" } else { "[KO]" }
        $color = if ($edr.Statut -eq "Running") { "Green" } else { "Red" }
        Write-Host "   $icon  $($edr.Nom.PadRight(25)) [$($edr.Type)]  Service: $($edr.Service)  Statut: $($edr.Statut)" -ForegroundColor $color
    }
    Write-Host "ℹ INFO : $($edrHorsWMI.Count) solution(s) EDR/AV hors SecurityCenter détectée(s). Ces agents seront inclus dans la synthèse." -ForegroundColor Cyan
} else {
    Write-Host "ℹ INFO : Aucun EDR entreprise hors SecurityCenter détecté." -ForegroundColor Gray
}

#----------------------------------------------------
# 7. ANALYSE VULNÉRABILITÉ RÉSEAU (SMBv1 & LLMNR) 
#----------------------------------------------------

Write-Host "`n>>> Analyse vulnérabilité réseau (Surface d'attaque) :" -ForegroundColor Yellow

# 1. SMBv1
$smb1 = Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSMB1Protocol
if ($smb1 -eq $true) {
    Write-Host "⚠ DANGER : SMBv1 est activé (Vecteur Ransomware/WannaCry)." -ForegroundColor Red
    Add-ScoreCheck -Nom "SMBv1 désactivé" -OK $false -Poids 15
    if ($Fix -eq "SMBv1" -or $Fix -eq "All") {
        Invoke-SecurityFix -Type "SMBv1"
    } else {
        Write-Host ">> CONSEIL : Relancez avec -Fix pour réparer ce point." -ForegroundColor Gray
    }
    Write-Host ">> FIX MANUEL (CLI) : Set-SmbServerConfiguration -EnableSMB1Protocol `$false -Force" -ForegroundColor Gray
} else {
    Write-Host "OK : SMBv1 est désactivé." -ForegroundColor Green
    Add-ScoreCheck -Nom "SMBv1 désactivé" -OK $true -Poids 15
}

# 2. LLMNR (Anticipation dynamique via GPO)
$llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
$llmnrVal = (Get-ItemProperty $llmnrPath -ErrorAction SilentlyContinue).EnableMulticast

if ($null -eq $llmnrVal -or $llmnrVal -ne 0) {
    Write-Host "⚠ ATTENTION : LLMNR est actif (Risque d'empoisonnement NTLM/Responder)." -ForegroundColor Yellow
    Write-Host ">> FIX MANUEL (GPO) : New-ItemProperty -Path '$llmnrPath' -Name 'EnableMulticast' -Value 0 -PropertyType DWord -Force" -ForegroundColor Gray
    Add-ScoreCheck -Nom "LLMNR désactivé" -OK $false -Poids 10
} else {
    Write-Host "OK : LLMNR est désactivé via stratégie." -ForegroundColor Green
    Add-ScoreCheck -Nom "LLMNR désactivé" -OK $true -Poids 10
}

#----------------------------------------------------
# 8. SYNTHÈSE MULTI-AV 
#----------------------------------------------------

Write-Host "`n>>> Check multi-antivirus & Conflits :" -ForegroundColor Yellow

# WARN #2 CORRIGÉ : inclure les EDR hors SecurityCenter dans la synthèse
$activeAV = @($avProducts | Where-Object { $_.state -like "ACTIF*" })
$edrActifs = @($edrHorsWMI | Where-Object { $_.Statut -eq 'Running' })
$totalActifs = $activeAV.Count + $edrActifs.Count

if ($edrActifs.Count -gt 0) {
    Write-Host "ℹ INFO : EDR actifs (hors WMI) : [$($edrActifs.Nom -join ' / ')]" -ForegroundColor Cyan
}

if ($avProducts.Count -gt 1) {

    Write-Host "ℹ INFO : $($avProducts.Count) solutions installées : [$($avProducts.displayName -join ' / ')]." -ForegroundColor Cyan

    if ($activeAV.Count -gt 1) {
        Write-Host "⚠ DANGER : $($activeAV.Count) antivirus sont ACTIFS simultanément !" -ForegroundColor Red
        Write-Host "   RISQUE : Conflits critiques de pilotes (BSOD), ralentissements et exclusions mutuelles." -ForegroundColor Red
        Write-Host "   >> ACTION : Désinstallez l'une des solutions ou vérifiez le mode passif." -ForegroundColor Gray
        Add-ScoreCheck -Nom "Multi-AV sans conflit" -OK $false -Poids 15

    } elseif ($activeAV.Count -eq 1) {
        Write-Host "OK : Cohabitation propre détectée. Seul [$($activeAV[0].displayName)] assure la protection temps réel." -ForegroundColor Green
        Add-ScoreCheck -Nom "Multi-AV sans conflit" -OK $true -Poids 15

    # BUG #1 CORRIGÉ : cas Count -eq 0 (aucun actif parmi plusieurs installés)
    } else {
        $edrCompense = $edrActifs.Count -gt 0
        if ($edrCompense) {
            Write-Host "ℹ INFO : Aucun AV SecurityCenter actif, mais EDR hors-WMI actif(s) : [$($edrActifs.Nom -join ' / ')]." -ForegroundColor Cyan
            Add-ScoreCheck -Nom "Protection active (EDR)" -OK $true -Poids 15
        } else {
            Write-Host "⚠ CRITIQUE : $($avProducts.Count) solutions installées mais AUCUNE n'est active !" -ForegroundColor Red
            Write-Host "   Installés : [$($avProducts.displayName -join ' / ')]" -ForegroundColor Gray
            Write-Host "   >> ACTION : Vérifiez l'état de chaque solution ou réinstallez-en une." -ForegroundColor Gray
            Add-ScoreCheck -Nom "Protection active" -OK $false -Poids 15
        }
    }

} elseif ($avProducts.Count -eq 1) {

    if ($activeAV.Count -eq 1) {
        Write-Host "OK : Protection mono-source active ($($avProducts[0].displayName))." -ForegroundColor Green
        Add-ScoreCheck -Nom "Protection AV active" -OK $true -Poids 15
    } else {
        if ($edrActifs.Count -gt 0) {
            Write-Host "ℹ INFO : $($avProducts[0].displayName) inactif, compensé par EDR : [$($edrActifs.Nom -join ' / ')]." -ForegroundColor Cyan
            Add-ScoreCheck -Nom "Protection active (EDR)" -OK $true -Poids 15
        } else {
            Write-Host "⚠ ATTENTION : $($avProducts[0].displayName) est installé mais INACTIF." -ForegroundColor Yellow
            Write-Host "   >> ACTION : Vérifiez la licence ou réactivez la protection temps réel." -ForegroundColor Gray
            Add-ScoreCheck -Nom "Protection AV active" -OK $false -Poids 15
        }
    }

} else {
    # BUG #1 CORRIGÉ : Count -eq 0 sans EDR
    if ($edrActifs.Count -gt 0) {
        Write-Host "ℹ INFO : Aucun AV dans SecurityCenter mais EDR actif(s) détecté(s) : [$($edrActifs.Nom -join ' / ')]." -ForegroundColor Cyan
        Add-ScoreCheck -Nom "Protection active (EDR)" -OK $true -Poids 15
    } else {
        Write-Host "⚠ CRITIQUE : Aucun antivirus enregistré dans le Security Center et aucun EDR hors-WMI actif." -ForegroundColor Red
        Write-Host "   >> FIX : Vérifiez l'état du service WinDefend ou réinstallez votre solution de sécurité." -ForegroundColor Gray
        Add-ScoreCheck -Nom "Protection AV/EDR active" -OK $false -Poids 15
    }
}

#----------------------------------------------------
# 9. SCORE DE SÉCURITÉ GLOBAL /100 (IDEA #2)
#----------------------------------------------------

Write-Host "`n================ SCORE DE SÉCURITÉ GLOBAL =================" -ForegroundColor Cyan

$totalPoids  = ($scoreChecks | Measure-Object -Property Poids -Sum).Sum
$poidsOK     = ($scoreChecks | Where-Object { $_.OK } | Measure-Object -Property Poids -Sum).Sum
$score       = if ($totalPoids -gt 0) { [Math]::Round(($poidsOK / $totalPoids) * 100) } else { 0 }

$couleurScore = if ($score -ge 80) { "Green" } elseif ($score -ge 50) { "Yellow" } else { "Red" }
$jauge = [Math]::Floor($score / 5)
$jaugeVide = 20 - $jauge
$barre = ("[" + ("█" * $jauge) + ("░" * $jaugeVide) + "]")

Write-Host ""
Write-Host ("   Score Global : " + $score + "/100  " + $barre) -ForegroundColor $couleurScore
Write-Host ""
Write-Host "   Détail des points de contrôle :" -ForegroundColor Gray
foreach ($chk in $scoreChecks) {
    $icon   = if ($chk.OK) { "  [OK]" } else { "  [KO]" }
    $couleur = if ($chk.OK) { "Green" } else { "Red" }
    Write-Host ("$icon  $($chk.Nom) (poids $($chk.Poids))") -ForegroundColor $couleur
}

if ($score -ge 80) {
    Write-Host "`n   RESULTAT : Posture de securite SATISFAISANTE. Maintenir les mises a jour." -ForegroundColor Green
} elseif ($score -ge 50) {
    Write-Host "`n   RESULTAT : Posture de securite PARTIELLE. Corriger les points KO rapidement." -ForegroundColor Yellow
} else {
    Write-Host "`n   RESULTAT : Posture de securite CRITIQUE. Des vecteurs d'attaque sont ouverts." -ForegroundColor Red
}

# --- RECOMMANDATIONS DYNAMIQUES ---
$pointsKO = @($scoreChecks | Where-Object { -not $_.OK })
if ($pointsKO.Count -gt 0) {
    Write-Host "`n>>> Recommandations prioritaires :" -ForegroundColor Yellow
    foreach ($ko in $pointsKO | Sort-Object Poids -Descending) {
        $reco = switch -Wildcard ($ko.Nom) {
            "Firewall*"          { "Activez tous les profils : Set-NetFirewallProfile -All -Enabled True  |  ou relancez avec -Fix Firewall" }
            "SmartScreen*"       { "Activez SmartScreen : Securite Windows > Controle des applis > Protection fondee sur la reputation  |  ou -Fix SmartScreen" }
            "Protection LSA*"    { "Activez RunAsPPL (anti-Mimikatz) : Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa RunAsPPL 1  |  ou -Fix LSA" }
            "SMBv1*"             { "Desactivez SMBv1 (vecteur WannaCry) : Set-SmbServerConfiguration -EnableSMB1Protocol `$false -Force  |  ou -Fix SMBv1" }
            "LLMNR*"             { "Desactivez LLMNR (Responder/NTLM relay) : New-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' EnableMulticast 0 DWord -Force" }
            "Protection AV*"     { "Reactivez ou reinstallez votre solution antivirus. Verifiez le service WinDefend." }
            "Multi-AV*"          { "Conservez un seul AV actif. Desinstallez les solutions en conflit ou forcez le mode passif." }
            "Defender*"          { "Verifiez la protection temps reel Defender : Set-MpPreference -RealTimeProtectionEnabled `$true  |  ou -Fix Defender" }
            default              { "Verifiez manuellement ce point dans Securite Windows." }
        }
        Write-Host "   [!] $($ko.Nom) (poids $($ko.Poids))" -ForegroundColor Red
        Write-Host "       >> $reco" -ForegroundColor Gray
    }
}

Write-Host "`n============================================================" -ForegroundColor Cyan

#----------------------------------------------------
# STOP TRANSCRIPTION 
#----------------------------------------------------

if ($ShareDpaste -or $ShareGofile) {
    try { Stop-Transcript | Out-Null } catch { }
} else {
    # WARN #3 CORRIGÉ : toujours arrêter la transcription pour finaliser le rapport
    try { Stop-Transcript | Out-Null } catch { }
}

    if (Test-Path $PathBureau) {
        $cleanContent = Get-Content $PathBureau |
            Select-Object -Skip 20 |
            Select-Object -SkipLast 4
        $cleanContent | Out-File $PathBureau -Force -Encoding UTF8
    }
}

#----------------------------------------------------
# PARTAGE DE RAPPORT (DPASTE ET/OU GOFILE)
#----------------------------------------------------

$file = $script:PathBureau

if ($ShareDpaste -or $ShareGofile) {

    if (-not (Test-Path $file)) {
        "Rapport de sécurité EDR - $(Get-Date)" | Out-File $file -Encoding UTF8
    }

    Write-Host "`n=== PHASE D'UPLOAD ===" -ForegroundColor Cyan

    #  DPASTE 
    if ($ShareDpaste) {
        Write-Host "[cloud] Envoi vers dpaste..." -ForegroundColor Magenta -NoNewline
        try {
            if (-not (Test-Path $file)) {
                throw "Fichier rapport introuvable : $file"
            }

            $rapportContenu = [System.IO.File]::ReadAllText($file, [System.Text.Encoding]::UTF8)

            if ([string]::IsNullOrWhiteSpace($rapportContenu)) {
                throw "Le fichier rapport est vide."
            }

            Write-Host " [$($rapportContenu.Length) chars]" -NoNewline -ForegroundColor DarkGray

            $encodedContent = [System.Uri]::EscapeDataString($rapportContenu)
            $bodyString = "content=$encodedContent&expiry_days=7&syntax=text"

            $response = Invoke-RestMethod -Uri "https://dpaste.com/api/v2/" `
                                          -Method Post `
                                          -Body $bodyString `
                                          -ContentType "application/x-www-form-urlencoded"

            $urlD = $response.Trim()

            if ($urlD -match "https://dpaste\.com/") {
                Write-Host " -> OK" -ForegroundColor Green
                Write-Host " LIEN DPASTE : " -NoNewline
                Write-Host $urlD -ForegroundColor Yellow
                "$(Get-Date) : DPASTE -> $urlD" | Out-File "$script:outDir\liens_upload.txt" -Append
            } else {
                Write-Host " -> ERREUR (réponse inattendue)" -ForegroundColor Red
                Write-Host " Détail : $urlD" -ForegroundColor Gray
            }

        } catch {
            Write-Host " -> ERREUR CRITIQUE : $_" -ForegroundColor Red
        }
    }

    # --- GOFILE ---
    if ($ShareGofile) {
        Write-Host "[cloud] Envoi vers Gofile..." -ForegroundColor Cyan -NoNewline
        try {
            $uploadJson = curl.exe -s -F "file=@$file" "https://store1.gofile.io/contents/uploadfile" | ConvertFrom-Json
            if ($uploadJson.status -eq "ok") {
                $dl = $uploadJson.data.downloadPage
                Write-Host " -> OK" -ForegroundColor Green
                Write-Host " LIEN GOFILE : " -NoNewline
                Write-Host $dl -ForegroundColor Yellow
                "$(Get-Date) : GOFILE  -> $dl" | Out-File "$script:outDir\liens_upload.txt" -Append
            } else {
                Write-Host " -> ERREUR : $($uploadJson.status)" -ForegroundColor Red
            }
        } catch {
            Write-Host " -> ERREUR CRITIQUE : $_" -ForegroundColor Red
        }
    }

    function Write-ClickableLink {
        param([string]$Label, [string]$Path)
        $esc = [char]27
        Write-Host "${esc}]8;;file://$Path${esc}\$Label${esc}]8;;${esc}\" -ForegroundColor Yellow
    }

    Write-Host "`n=== Emplacements ===" -ForegroundColor Cyan
    Write-Host "Rapport :"
    Write-ClickableLink -Label $file -Path $file
    Write-Host "Dossier source :"
    Write-ClickableLink -Label $script:outDir -Path $script:outDir
}
}

# ===========================================================================
#  MODULE 5 — WINDIAG  (Diagnostic codes erreur Windows)
# ===========================================================================

function Invoke-WinDiag {
    param([string]$QueryIn, [switch]$ScanLog, [string]$DumpPath, [string]$ExportPath, [switch]$ShowHelp)
    Assert-AdminPrivilege
    $ts_wd  = Get-Date -Format 'yyyyMMdd_HHmmss'
    $rpt_wd = "$env:USERPROFILE\Desktop\WinDiag_$ts_wd.txt"

    $script:WD_LastResult = $null
    $script:WD_DB = @{
        # --- NTSTATUS ---
        "0xc000012f"=@{N="STATUS_INVALID_IMAGE_FORMAT";Cat="NTSTATUS";Sev="Critical";Cause="EXE or DLL is corrupt, wrong architecture (32/64-bit mismatch), or a required section is missing.";Sol="1) Check Event Viewer for faulting module name. 2) Reinstall VC++ Redistributable (all versions x86+x64). 3) Run: sfc /scannow. 4) Use Dependencies.exe to check missing imports."}
        "0xc0000005"=@{N="STATUS_ACCESS_VIOLATION";Cat="NTSTATUS";Sev="Critical";Cause="Process tried to read/write memory it does not own. Bad pointer, use-after-free, buffer overflow, or corrupt heap.";Sol="1) Update or reinstall the faulting app. 2) Run memory test (mdsched.exe). 3) Check for driver conflicts. 4) Disable DEP override if app is legacy."}
        "0xc0000034"=@{N="STATUS_OBJECT_NAME_NOT_FOUND";Cat="NTSTATUS";Sev="High";Cause="A file, registry key, or device object referenced by the app does not exist.";Sol="1) Check if a required DLL or config file is missing. 2) Reinstall the application. 3) Check registry paths referenced by the app."}
        "0xc0000135"=@{N="STATUS_DLL_NOT_FOUND";Cat="NTSTATUS";Sev="Critical";Cause="A required DLL cannot be located in the search path.";Sol="1) Identify missing DLL via Event Viewer. 2) Reinstall app or the runtime providing that DLL. 3) Check PATH environment variable."}
        "0xc0000139"=@{N="STATUS_ENTRYPOINT_NOT_FOUND";Cat="NTSTATUS";Sev="Critical";Cause="A DLL is present but the required exported function does not exist — version mismatch.";Sol="1) Wrong version of DLL installed. 2) Reinstall the app or runtime. 3) Check if another app replaced a system DLL (DLL hijacking)."}
        "0xc000013a"=@{N="STATUS_CONTROL_C_EXIT";Cat="NTSTATUS";Sev="Low";Cause="Process terminated by Ctrl+C or programmatic signal.";Sol="Normal termination signal. No action needed unless unexpected."}
        "0xc0000142"=@{N="STATUS_DLL_INIT_FAILED";Cat="NTSTATUS";Sev="Critical";Cause="A DLL failed to initialize — corrupt runtime, missing dependency, or insufficient resources at load time.";Sol="1) Reboot (resource exhaustion). 2) Reinstall VC++ Redistributable and .NET. 3) Run sfc /scannow. 4) Check Event Log for which DLL failed."}
        "0xc00000fd"=@{N="STATUS_STACK_OVERFLOW";Cat="NTSTATUS";Sev="Critical";Cause="Thread exhausted its stack space — infinite recursion or extremely deep call chain.";Sol="1) Bug in app (infinite recursion). 2) If system DLL: update or reinstall. 3) Check for corrupt stack via WinDbg !analyze -v."}
        "0xc0000022"=@{N="STATUS_ACCESS_DENIED";Cat="NTSTATUS";Sev="High";Cause="Insufficient privileges to access a resource (file, registry, device).";Sol="1) Run as Administrator. 2) Check ACL on the target resource. 3) Check UAC settings."}
        "0xc000001d"=@{N="STATUS_ILLEGAL_INSTRUCTION";Cat="NTSTATUS";Sev="Critical";Cause="CPU encountered an instruction it cannot execute — wrong CPU target (AVX2 binary on old CPU), or corrupt code.";Sol="1) Check minimum CPU requirements for the app. 2) Verify download integrity (hash). 3) Run memory diagnostic."}
        "0xc0000006"=@{N="STATUS_IN_PAGE_ERROR";Cat="NTSTATUS";Sev="Critical";Cause="Page fault could not be satisfied — disk read error, corrupt pagefile, or network resource unavailable.";Sol="1) Run chkdsk /f /r. 2) Check disk health (CrystalDiskInfo). 3) Check pagefile integrity."}
        "0xc000009a"=@{N="STATUS_INSUFFICIENT_RESOURCES";Cat="NTSTATUS";Sev="High";Cause="Kernel could not allocate required resources — low RAM, handle leak, or pool exhaustion.";Sol="1) Reboot to free resources. 2) Check for memory/handle leaks with Process Explorer. 3) Increase pagefile."}
        "0xc0000017"=@{N="STATUS_NO_MEMORY";Cat="NTSTATUS";Sev="Critical";Cause="System or process ran out of virtual memory.";Sol="1) Close other apps. 2) Increase pagefile. 3) Add RAM. 4) Check for memory leaks."}
        "0xc000007b"=@{N="STATUS_INVALID_IMAGE_WIN_32";Cat="NTSTATUS";Sev="Critical";Cause="32-bit app trying to load 64-bit DLL or vice versa. Architecture mismatch.";Sol="1) Ensure all DLLs match app architecture. 2) Reinstall VC++ both x86 and x64. 3) Use Dependencies.exe to identify mismatch."}
        "0xc000007e"=@{N="STATUS_RANGE_NOT_LOCKED";Cat="NTSTATUS";Sev="Medium";Cause="Attempt to unlock a memory range that was not locked.";Sol="Application bug or driver error. Update drivers and the application."}
        "0xc0000185"=@{N="STATUS_IO_DEVICE_ERROR";Cat="NTSTATUS";Sev="Critical";Cause="Hardware I/O error — failing disk, cable issue, or bad sector.";Sol="1) Run chkdsk /f /r. 2) Check SMART data. 3) Replace cable or drive."}
        "0xc0000043"=@{N="STATUS_SHARING_VIOLATION";Cat="NTSTATUS";Sev="Medium";Cause="File or resource locked by another process.";Sol="1) Use Process Explorer to find which process holds the lock. 2) Close conflicting app."}
        "0xc000003b"=@{N="STATUS_OBJECT_PATH_INVALID";Cat="NTSTATUS";Sev="Medium";Cause="Object path syntax is invalid or references a non-existent namespace.";Sol="Check path format and that all parent directories/keys exist."}
        "0xc0000010"=@{N="STATUS_INVALID_DEVICE_REQUEST";Cat="NTSTATUS";Sev="High";Cause="IOCTL sent to a device that does not support it — driver/firmware mismatch.";Sol="Update device driver. Check device compatibility."}
        "0xc0000023"=@{N="STATUS_BUFFER_TOO_SMALL";Cat="NTSTATUS";Sev="Medium";Cause="Buffer provided is smaller than required data.";Sol="Application or driver bug. Update to latest version."}
        "0xc000009c"=@{N="STATUS_DEVICE_DATA_ERROR";Cat="NTSTATUS";Sev="Critical";Cause="Unrecoverable data error on device — bad sector or hardware failure.";Sol="1) Run chkdsk. 2) Check SMART. 3) Backup data immediately and replace drive."}
        "0xc0000374"=@{N="STATUS_HEAP_CORRUPTION";Cat="NTSTATUS";Sev="Critical";Cause="Heap memory corrupted — buffer overflow, double free, or use-after-free in app or loaded DLL.";Sol="1) Enable Application Verifier to locate the bug. 2) Update or reinstall app. 3) Check for malware."}
        "0xc0000409"=@{N="STATUS_STACK_BUFFER_OVERRUN";Cat="NTSTATUS";Sev="Critical";Cause="Stack-based buffer overrun detected by security cookie (/GS). Potential exploit or app bug.";Sol="1) Update app immediately. 2) Scan for malware. 3) Check for memory corruption."}
        "0xc0000420"=@{N="STATUS_ASSERTION_FAILURE";Cat="NTSTATUS";Sev="High";Cause="Internal assertion in code failed — usually debug/checked build or corrupted state.";Sol="Update or reinstall application. Report to vendor if persists."}
        "0x00000103"=@{N="STATUS_PENDING";Cat="NTSTATUS";Sev="Info";Cause="Operation is pending/asynchronous. Not an error.";Sol="No action needed."}
        "0x80000005"=@{N="STATUS_BUFFER_OVERFLOW";Cat="NTSTATUS";Sev="Medium";Cause="Output buffer too small — data truncated (informational in some APIs).";Sol="Application should handle this gracefully. Update if it does not."}
        # --- Win32 Error Codes ---
        "0x00000002"=@{N="ERROR_FILE_NOT_FOUND";Cat="Win32";Sev="High";Cause="Referenced file does not exist.";Sol="Check path, reinstall app, or restore missing file."}
        "0x00000003"=@{N="ERROR_PATH_NOT_FOUND";Cat="Win32";Sev="High";Cause="Directory path does not exist.";Sol="Check directory structure, reinstall app."}
        "0x00000005"=@{N="ERROR_ACCESS_DENIED";Cat="Win32";Sev="High";Cause="Insufficient permissions.";Sol="Run as Administrator, check ACL."}
        "0x0000006e"=@{N="ERROR_OPEN_FAILED";Cat="Win32";Sev="High";Cause="Cannot open file or device.";Sol="Check file existence, permissions, and that it is not locked."}
        "win32:0x0000007e"=@{N="ERROR_MOD_NOT_FOUND";Cat="Win32";Sev="Critical";Cause="DLL or EXE module not found in search path.";Sol="1) Identify missing module via Event Viewer. 2) Reinstall app or runtime."}
        "win32:0x0000007f"=@{N="ERROR_PROC_NOT_FOUND";Cat="Win32";Sev="Critical";Cause="Exported function not found in DLL — version mismatch.";Sol="Reinstall app and all runtimes. Check for DLL replacement."}
        "0x000000c1"=@{N="ERROR_BAD_EXE_FORMAT";Cat="Win32";Sev="Critical";Cause="EXE format is invalid or architecture mismatch (32/64-bit).";Sol="Same as 0xc000012f — architecture mismatch or corrupt binary."}
        "0x000000b7"=@{N="ERROR_ALREADY_EXISTS";Cat="Win32";Sev="Low";Cause="Object already exists.";Sol="Usually informational. Check if app handles this case."}
        "0x00000008"=@{N="ERROR_NOT_ENOUGH_MEMORY";Cat="Win32";Sev="Critical";Cause="Insufficient memory.";Sol="Free RAM, increase pagefile, add RAM."}
        "0x000003e3"=@{N="ERROR_OPERATION_ABORTED";Cat="Win32";Sev="Medium";Cause="I/O operation aborted.";Sol="Check device health, drivers, and cables."}
        "0x000003e5"=@{N="ERROR_IO_PENDING";Cat="Win32";Sev="Info";Cause="Async I/O operation pending.";Sol="Not an error. Informational."}
        "0x00000020"=@{N="ERROR_SHARING_VIOLATION";Cat="Win32";Sev="Medium";Cause="File locked by another process.";Sol="Use Process Explorer to identify locking process."}
        "0x00000070"=@{N="ERROR_DISK_FULL";Cat="Win32";Sev="Critical";Cause="Target disk has no free space.";Sol="Free disk space or target a different drive."}
        "0x0000001f"=@{N="ERROR_GEN_FAILURE";Cat="Win32";Sev="High";Cause="Device general failure.";Sol="Update driver, check device health."}
        "0x00000057"=@{N="ERROR_INVALID_PARAMETER";Cat="Win32";Sev="Medium";Cause="Invalid parameter passed to function.";Sol="App or driver bug. Update to latest version."}
        "0x00000032"=@{N="ERROR_NOT_SUPPORTED";Cat="Win32";Sev="Medium";Cause="Operation not supported by device or OS version.";Sol="Check OS compatibility requirements."}
        # --- HRESULT ---
        "0x80000003"=@{N="E_UNEXPECTED (Breakpoint)";Cat="HRESULT";Sev="High";Cause="Unexpected condition or hardcoded breakpoint hit.";Sol="Debug build artifact or app crash. Update app."}
        "0x80004001"=@{N="E_NOTIMPL";Cat="HRESULT";Sev="Medium";Cause="Method not implemented.";Sol="Feature not supported in this version. Update app."}
        "0x80004002"=@{N="E_NOINTERFACE";Cat="HRESULT";Sev="Medium";Cause="COM interface not supported by object.";Sol="Version mismatch of COM component. Re-register or reinstall."}
        "0x80004003"=@{N="E_POINTER";Cat="HRESULT";Sev="High";Cause="Null pointer passed where valid pointer required.";Sol="Application bug. Update or reinstall."}
        "0x80004004"=@{N="E_ABORT";Cat="HRESULT";Sev="Medium";Cause="Operation aborted.";Sol="Check for cancellation logic or resource contention."}
        "0x80004005"=@{N="E_FAIL";Cat="HRESULT";Sev="High";Cause="Unspecified COM failure.";Sol="Check Event Log for more details. Reinstall COM component."}
        "0x8000ffff"=@{N="E_UNEXPECTED";Cat="HRESULT";Sev="High";Cause="Catastrophic unexpected failure.";Sol="Reinstall app. Check for corruption with sfc /scannow."}
        "0x80070002"=@{N="HRESULT_FILE_NOT_FOUND";Cat="HRESULT";Sev="High";Cause="File not found (COM/Shell context).";Sol="Reinstall app or restore missing component."}
        "0x80070005"=@{N="HRESULT_ACCESS_DENIED";Cat="HRESULT";Sev="High";Cause="Access denied in COM/Shell context.";Sol="Run as Administrator, check ACL."}
        "0x80070006"=@{N="HRESULT_INVALID_HANDLE";Cat="HRESULT";Sev="High";Cause="Invalid handle used.";Sol="App bug or resource exhaustion. Reboot and update app."}
        "0x8007000e"=@{N="HRESULT_OUTOFMEMORY";Cat="HRESULT";Sev="Critical";Cause="Out of memory in COM context.";Sol="Free RAM, increase pagefile."}
        "0x80070057"=@{N="HRESULT_INVALID_ARG";Cat="HRESULT";Sev="Medium";Cause="Invalid argument.";Sol="App or driver bug. Update."}
        "0x8007007e"=@{N="HRESULT_MOD_NOT_FOUND";Cat="HRESULT";Sev="Critical";Cause="Module/DLL not found.";Sol="Reinstall app and runtimes."}
        # --- BSOD Stop Codes ---
        "0x0000001a"=@{N="MEMORY_MANAGEMENT";Cat="BSOD";Sev="Critical";Cause="Severe memory management error — corrupt RAM, driver writing to wrong address, or pagefile corruption.";Sol="1) Run Windows Memory Diagnostic (mdsched.exe). 2) Run MemTest86. 3) Update all drivers. 4) Check pagefile."}
        "0x0000003b"=@{N="SYSTEM_SERVICE_EXCEPTION";Cat="BSOD";Sev="Critical";Cause="Exception in kernel-mode code — usually a driver bug.";Sol="1) Check minidump for driver name. 2) Update or rollback suspect driver. 3) Run Driver Verifier."}
        "0x0000007e"=@{N="SYSTEM_THREAD_EXCEPTION_NOT_HANDLED";Cat="BSOD";Sev="Critical";Cause="Kernel thread threw unhandled exception — driver error or hardware fault.";Sol="1) Check minidump. 2) Update drivers, especially GPU and storage."}
        "0x0000007f"=@{N="UNEXPECTED_KERNEL_MODE_TRAP";Cat="BSOD";Sev="Critical";Cause="CPU trap in kernel mode — hardware failure (RAM, CPU) or driver bug.";Sol="1) Run MemTest86. 2) Check CPU temps. 3) Update BIOS/firmware."}
        "0x000000ef"=@{N="CRITICAL_PROCESS_DIED";Cat="BSOD";Sev="Critical";Cause="Critical system process (smss, csrss, wininit, lsass) terminated unexpectedly.";Sol="1) Run sfc /scannow and DISM. 2) Check for malware. 3) Repair Windows installation."}
        "0x0000009f"=@{N="DRIVER_POWER_STATE_FAILURE";Cat="BSOD";Sev="Critical";Cause="Driver did not complete power transition (sleep/hibernate/wake).";Sol="1) Update all drivers. 2) Identify driver via minidump. 3) Disable problematic device."}
        "0x000000d1"=@{N="DRIVER_IRQL_NOT_LESS_OR_EQUAL";Cat="BSOD";Sev="Critical";Cause="Driver accessed memory at incorrect IRQL — classic driver bug.";Sol="1) Identify driver via minidump. 2) Update or uninstall driver. 3) Run Driver Verifier."}
        "0x0000000a"=@{N="IRQL_NOT_LESS_OR_EQUAL";Cat="BSOD";Sev="Critical";Cause="Kernel or driver accessed paged memory at high IRQL.";Sol="Update drivers, run MemTest86, check hardware."}
        "0x00000050"=@{N="PAGE_FAULT_IN_NONPAGED_AREA";Cat="BSOD";Sev="Critical";Cause="Page fault in non-pageable area — corrupt driver, bad RAM, or corrupt system file.";Sol="1) Run MemTest86. 2) Check drivers via minidump. 3) Run sfc /scannow."}
        "0x000000c5"=@{N="DRIVER_CORRUPTED_EXPOOL";Cat="BSOD";Sev="Critical";Cause="Driver corrupted kernel pool — serious driver bug.";Sol="Enable Driver Verifier to identify culprit driver."}
        "0x000000c2"=@{N="BAD_POOL_CALLER";Cat="BSOD";Sev="Critical";Cause="Driver made illegal pool allocation request.";Sol="Run Driver Verifier, check minidump for driver name."}
        "0x0000001e"=@{N="KMODE_EXCEPTION_NOT_HANDLED";Cat="BSOD";Sev="Critical";Cause="Kernel mode exception not handled — driver or hardware issue.";Sol="Update drivers, run hardware diagnostics."}
        "0x000000be"=@{N="ATTEMPTED_WRITE_TO_READONLY_MEMORY";Cat="BSOD";Sev="Critical";Cause="Driver attempted to write to read-only memory.";Sol="Identify driver via minidump and update/remove it."}
        "0x00000116"=@{N="VIDEO_TDR_FAILURE";Cat="BSOD";Sev="Critical";Cause="GPU driver crash — driver timeout, overheating, or hardware failure.";Sol="1) Update GPU driver (clean install via DDU). 2) Check GPU temps. 3) Test GPU stability."}
        "0x00000133"=@{N="DPC_WATCHDOG_VIOLATION";Cat="BSOD";Sev="Critical";Cause="DPC routine took too long — driver or hardware not responding in time.";Sol="1) Update storage and GPU drivers. 2) Check SSD firmware. 3) Run sfc /scannow."}
        "0x00000154"=@{N="UNEXPECTED_STORE_EXCEPTION";Cat="BSOD";Sev="Critical";Cause="Storage device error — failing SSD/HDD or driver issue.";Sol="1) Run chkdsk /f /r. 2) Check SMART data. 3) Update storage driver/firmware."}
        # --- DirectX / D3D ---
        "0x88760b59"=@{N="DXGI_ERROR_UNSUPPORTED";Cat="DirectX";Sev="High";Cause="GPU or driver does not support requested DirectX feature.";Sol="1) Update GPU driver. 2) Check DirectX feature level requirements. 3) Verify GPU meets minimum spec."}
        "0x887a0002"=@{N="DXGI_ERROR_NOT_FOUND";Cat="DirectX";Sev="High";Cause="Requested adapter/output not found.";Sol="Update GPU driver. Check display connection."}
        "0x887a0004"=@{N="DXGI_ERROR_INVALID_CALL";Cat="DirectX";Sev="High";Cause="Invalid DirectX API call — app bug or driver issue.";Sol="Update GPU driver and DirectX runtime."}
        "0x887a0005"=@{N="DXGI_ERROR_DEVICE_REMOVED";Cat="DirectX";Sev="Critical";Cause="GPU device was removed or reset — driver crash, overheating, power issue, or hardware failure.";Sol="1) Update GPU driver (use DDU first). 2) Check GPU temps. 3) Check PSU stability. 4) Test GPU."}
        "0x887a0006"=@{N="DXGI_ERROR_DEVICE_HUNG";Cat="DirectX";Sev="Critical";Cause="GPU stopped responding — driver timeout, overclocking instability, or hardware fault.";Sol="1) Revert any GPU overclock. 2) Update driver. 3) Check GPU temps and PSU."}
        "0x887a0007"=@{N="DXGI_ERROR_DEVICE_RESET";Cat="DirectX";Sev="High";Cause="GPU was reset due to driver error.";Sol="Update GPU driver. Run with default GPU settings."}
        "0x887a000a"=@{N="DXGI_ERROR_ACCESS_LOST";Cat="DirectX";Sev="Medium";Cause="Desktop access was lost (UAC, screen lock, fullscreen switch).";Sol="Minimize/restore app. Use windowed mode."}
        # --- COM / OLE ---
        "0x800401f0"=@{N="CO_E_NOTINITIALIZED";Cat="COM";Sev="High";Cause="CoInitialize() was not called before using COM.";Sol="App bug — must call CoInitialize first. Update or reinstall app."}
        "0x800401f3"=@{N="CO_E_CLASSSTRING";Cat="COM";Sev="High";Cause="CLSID string is invalid or COM class is not registered.";Sol="Re-register COM component: regsvr32 component.dll"}
        "0x80040154"=@{N="REGDB_E_CLASSNOTREG";Cat="COM";Sev="Critical";Cause="COM class not registered — missing registry entry.";Sol="1) Reinstall app. 2) Re-register: regsvr32 component.dll. 3) Check 32/64-bit COM registration."}
        "0x80040155"=@{N="REGDB_E_IIDNOTREG";Cat="COM";Sev="High";Cause="COM interface not registered.";Sol="Reinstall component providing the interface."}
        "0x8004016a"=@{N="CO_E_SERVER_EXEC_FAILURE";Cat="COM";Sev="Critical";Cause="COM server failed to launch or initialize.";Sol="Check permissions, reinstall the COM server app."}
        # --- Known DLL modules ---
        "ntdll.dll"=@{N="NT Layer DLL";Cat="Module";Sev="Variable";Cause="Core NT system DLL. Faults here usually indicate: heap corruption, stack overflow, loader issues, or a misbehaving calling app.";Sol="Rarely ntdll itself. Find the caller: check Event Log for full crash context. Run sfc /scannow."}
        "kernel32.dll"=@{N="Windows Kernel Base";Cat="Module";Sev="Variable";Cause="Core Win32 API. Issues here indicate a fundamental Win32 call failure from the crashing app.";Sol="Run sfc /scannow. Identify the calling module in Event Viewer."}
        "kernelbase.dll"=@{N="Kernel Base API";Cat="Module";Sev="Variable";Cause="Refactored kernel base. Same as kernel32 — find the true caller.";Sol="sfc /scannow. Check Event Log for exception code."}
        "ucrtbase.dll"=@{N="Universal C Runtime";Cat="Module";Sev="High";Cause="C runtime crash — abort(), assertion failure, or stack overflow in app using Universal CRT.";Sol="Reinstall VC++ Redistributable (all versions). Update Windows."}
        "vcruntime140.dll"=@{N="VC++ 2015-2022 Runtime";Cat="Module";Sev="Critical";Cause="Missing or corrupt Visual C++ 2015-2022 runtime.";Sol="Install/repair VC++ Redistributable 2015-2022 x64 and x86 from Microsoft."}
        "msvcp140.dll"=@{N="VC++ 2015 C++ Runtime";Cat="Module";Sev="Critical";Cause="Missing or corrupt C++ runtime DLL.";Sol="Install VC++ Redistributable 2015-2022."}
        "msvcp120.dll"=@{N="VC++ 2013 C++ Runtime";Cat="Module";Sev="Critical";Cause="Missing VC++ 2013 runtime.";Sol="Install VC++ Redistributable 2013 x64 and x86."}
        "msvcr120.dll"=@{N="VC++ 2013 C Runtime";Cat="Module";Sev="Critical";Cause="Missing VC++ 2013 C runtime.";Sol="Install VC++ Redistributable 2013."}
        "msvcp100.dll"=@{N="VC++ 2010 C++ Runtime";Cat="Module";Sev="Critical";Cause="Missing VC++ 2010 runtime.";Sol="Install VC++ Redistributable 2010 x64 and x86."}
        "d3d11.dll"=@{N="Direct3D 11";Cat="Module";Sev="High";Cause="DirectX 11 component issue — driver or feature level mismatch.";Sol="Update GPU driver. Run DirectX Diagnostic (dxdiag)."}
        "d3d12.dll"=@{N="Direct3D 12";Cat="Module";Sev="High";Cause="DirectX 12 component issue.";Sol="Update GPU driver. Verify GPU supports DX12."}
        "opengl32.dll"=@{N="OpenGL Runtime";Cat="Module";Sev="High";Cause="OpenGL runtime failure.";Sol="Update GPU driver."}
        "clr.dll"=@{N=".NET Common Language Runtime";Cat="Module";Sev="High";Cause=".NET runtime crash.";Sol="Repair or reinstall .NET Runtime/Framework."}
        "coreclr.dll"=@{N=".NET Core CLR";Cat="Module";Sev="High";Cause=".NET Core runtime crash.";Sol="Reinstall .NET Runtime from Microsoft."}
        "xaudio2_9.dll"=@{N="XAudio2 9 (DirectX Audio)";Cat="Module";Sev="High";Cause="Audio runtime missing or corrupt.";Sol="Install/repair DirectX End-User Runtime."}
        "physxloader.dll"=@{N="NVIDIA PhysX";Cat="Module";Sev="High";Cause="PhysX runtime missing or wrong version.";Sol="Install NVIDIA PhysX System Software."}
        "steam_api64.dll"=@{N="Steam API 64-bit";Cat="Module";Sev="High";Cause="Steam API DLL missing, wrong version, or game not launched via Steam.";Sol="Launch via Steam. Verify game files integrity in Steam."}
        "xinput1_3.dll"=@{N="XInput 1.3 (DirectX)";Cat="Module";Sev="High";Cause="XInput DLL missing — gamepad input runtime.";Sol="Install DirectX End-User Runtime (June 2010)."}
        "xinput1_4.dll"=@{N="XInput 1.4";Cat="Module";Sev="High";Cause="XInput 1.4 missing — requires Windows 8+.";Sol="Windows 8/10/11 only. Update Windows."}
        "dxgi.dll"=@{N="DirectX Graphics Infrastructure";Cat="Module";Sev="High";Cause="DXGI component failure.";Sol="Update GPU driver. Run sfc /scannow."}
        "user32.dll"=@{N="Win32 User Interface";Cat="Module";Sev="Variable";Cause="UI subsystem fault — find the caller in Event Log.";Sol="sfc /scannow. Check calling app."}
        "gdi32.dll"=@{N="GDI Graphics";Cat="Module";Sev="Variable";Cause="GDI rendering fault.";Sol="Update GPU driver. sfc /scannow."}
        "ole32.dll"=@{N="OLE/COM Core";Cat="Module";Sev="High";Cause="COM infrastructure fault.";Sol="sfc /scannow. Re-register COM components."}
        "shell32.dll"=@{N="Windows Shell";Cat="Module";Sev="High";Cause="Shell extension or Explorer crash.";Sol="Disable shell extensions via ShellExView. sfc /scannow."}
        "comctl32.dll"=@{N="Common Controls";Cat="Module";Sev="High";Cause="UI control library fault.";Sol="sfc /scannow. Update Windows."}
        # --- Common EXE targets ---
        "explorer.exe"=@{N="Windows Explorer / Shell";Cat="Process";Sev="High";Cause="Shell crash — corrupt shell extension, bad context menu handler, or corrupted user profile.";Sol="1) Disable shell extensions (ShellExView). 2) sfc /scannow. 3) Create new user profile."}
        "svchost.exe"=@{N="Service Host";Cat="Process";Sev="High";Cause="A Windows service inside svchost crashed. The specific service is the real culprit.";Sol="Check Event Log for which service failed. Restart that specific service."}
        "lsass.exe"=@{N="Local Security Authority";Cat="Process";Sev="Critical";Cause="Authentication subsystem crash — malware, corrupt Active Directory, or driver issue.";Sol="1) Scan for malware immediately. 2) sfc /scannow. 3) Check for rogue LSA plugins."}
        "csrss.exe"=@{N="Client Server Runtime";Cat="Process";Sev="Critical";Cause="Core Windows subsystem crash — triggers BSOD. Malware or severe corruption.";Sol="1) Scan for malware. 2) sfc /scannow and DISM. 3) Consider OS repair."}
        "werfault.exe"=@{N="Windows Error Reporting";Cat="Process";Sev="Info";Cause="This is the crash reporter, not the cause. Look for the app it was reporting on.";Sol="Check Event Log for the actual faulting application."}
        "dwm.exe"=@{N="Desktop Window Manager";Cat="Process";Sev="High";Cause="Compositor crash — GPU driver issue, low VRAM, or incompatible app.";Sol="Update GPU driver. Check VRAM usage."}
    }

    function ConvertTo-WDNormalized { param([string]$raw)
        $s = $raw.Trim().ToLower() -replace '^0x',''
        if ($s -match '^[0-9a-f]+$') { return "0x" + $s.PadLeft(8,'0') }
        return $raw.Trim().ToLower()
    }

    function Find-WDEntry { param([string]$key)
        $n = ConvertTo-WDNormalized $key
        if ($script:WD_DB.ContainsKey($n)) { return $script:WD_DB[$n], $n }
        $lo = $key.Trim().ToLower()
        if ($script:WD_DB.ContainsKey($lo)) { return $script:WD_DB[$lo], $lo }
        return $null, $n
    }

    function Search-WD { param([string]$kw)
        $kw = $kw.ToLower().Trim() -replace '[^a-z0-9 ]',' ' -replace '\s+',' '
        $results = @()
        foreach ($k in $script:WD_DB.Keys) {
            $e = $script:WD_DB[$k]
            $searchable = "$k $($e.N) $($e.Cause) $($e.Sol)".ToLower() -replace '[^a-z0-9 ]',' '
            if ($searchable -like "*$kw*") { $results += [PSCustomObject]@{ Key=$k; Entry=$e } }
        }
        return $results
    }

    function Format-WD { param($e, $key)
        if (-not $e) { return $null }
        $lines = @("","$('='*60)","  RESULT","$('='*60)",
            "  Input    : $key","  Name     : $($e.N)","  Category : $($e.Cat)","  Severity : $($e.Sev)","$('-'*60)","  CAUSE","","  $($e.Cause)","","$('-'*60)","  SOLUTION","")
        $e.Sol -split '\s+(?=\d+\))' | Where-Object { $_.Trim() } | ForEach-Object { $lines += "  $($_.Trim())" }
        $lines += "$('='*60)"; $lines += ""
        return $lines -join "`n"
    }

    function Invoke-WDQuery { param([string]$q)
        $r = Find-WDEntry $q; $entry=$r[0]; $norm=$r[1]
        if ($entry) {
            $out = Format-WD $entry $norm; $script:WD_LastResult = $out; Write-Host $out
        try { $script:WD_LastResult | Out-File $rpt_wd -Encoding UTF8 -Append } catch {}
        } else {
            $matches2 = Search-WD $q
            if ($matches2.Count -gt 0) {
                Write-Host ""; Write-Host "  Pas de correspondance exacte. Entrees proches :" -ForegroundColor Yellow; Write-Host ""
                $i=1; foreach ($m in ($matches2 | Select-Object -First 10)) { Write-Host ("  {0,2}. [{1}] {2} - {3}" -f $i,$m.Entry.Cat,$m.Key,$m.Entry.N); $i++ }
                Write-Host ""; $sel = Read-Host "  Numero a afficher (ou ENTREE pour ignorer)"
                if ($sel -match '^\d+$') { $idx=[int]$sel-1; if ($idx -ge 0 -and $idx -lt $matches2.Count) { $out=Format-WD $matches2[$idx].Entry $matches2[$idx].Key; $script:WD_LastResult=$out; Write-Host $out } }
            } else {
                Write-Host ""; Write-Host "  Non trouve : $q" -ForegroundColor Yellow
                Write-Host "  Essayez : un code hex (0xc000012f), un nom DLL (ntdll.dll), ou un mot-cle." -ForegroundColor Gray
            }
        }
    }

    function Invoke-WDScan {
        Write-Host ""; Write-Host "  Scan Event Log pour crashes recents..." -ForegroundColor Cyan; Write-Host ""
        $crashes = Get-WinEvent -LogName Application -MaxEvents 1000 2>$null |
            Where-Object { $_.Id -in @(1000,1001,1002) } | Select-Object -First 30
        if (-not $crashes) { Write-Host "  Aucun crash trouve dans le log Application."; return }
        $parsed = foreach ($ev in $crashes) {
            $msg = $ev.Message
            $app  = if ($msg -match "(?:Faulting application name|Nom de l.application)[:\s]+([^\r\n,]+)") { $matches[1].Trim() } else { "Unknown" }
            $mod  = if ($msg -match "(?:Faulting module name|Nom du module)[:\s]+([^\r\n,]+)") { $matches[1].Trim() } else { "Unknown" }
            $code = if ($msg -match "Exception code[:\s]+(0x[0-9a-fA-F]+)") { $matches[1].Trim() } else { "" }
            [PSCustomObject]@{ Time=$ev.TimeCreated; App=$app; Module=$mod; Code=$code }
        }
        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.AppendLine("$('='*70)")
        [void]$sb.AppendLine("  CRASHES RECENTS — Event Log")
        [void]$sb.AppendLine("$('='*70)")
        [void]$sb.AppendLine(("{0,-22} {1,-28} {2,-18} {3}" -f "Heure","Application","Module","Code"))
        [void]$sb.AppendLine("$('-'*70)")
        foreach ($c in $parsed) {
            $appStr = if ($c.App.Length -gt 26) { $c.App.Substring(0,23)+"..." } else { $c.App }
            $modStr = if ($c.Module.Length -gt 16) { $c.Module.Substring(0,13)+"..." } else { $c.Module }
            [void]$sb.AppendLine(("{0,-22} {1,-28} {2,-18} {3}" -f $c.Time.ToString("yyyy-MM-dd HH:mm:ss"),$appStr,$modStr,$c.Code))
        }
        [void]$sb.AppendLine("$('='*70)")
        $out = $sb.ToString(); $script:WD_LastResult = $out; Write-Host $out
        try { $script:WD_LastResult | Out-File $rpt_wd -Encoding UTF8 -Append } catch {}
        $codes = $parsed | Where-Object { $_.Code } | Select-Object -ExpandProperty Code -Unique
        $mods  = $parsed | Where-Object { $_.Module -ne "Unknown" } | Select-Object -ExpandProperty Module -Unique
        if ($codes.Count -gt 0 -or $mods.Count -gt 0) {
            Write-Host "  Lookup rapide disponible :" -ForegroundColor Yellow
            $all=@(); $i=1
            foreach ($c in ($codes | Select-Object -First 5)) { Write-Host ("  {0,2}. Code   : {1}" -f $i,$c); $all+=$c; $i++ }
            foreach ($m in ($mods  | Select-Object -First 5)) { Write-Host ("  {0,2}. Module : {1}" -f $i,$m); $all+=$m; $i++ }
            Write-Host ""; $sel = Read-Host "  Numero a analyser (ou ENTREE)"
            if ($sel -match '^\d+$') { $idx=[int]$sel-1; if ($idx -ge 0 -and $idx -lt $all.Count) { Invoke-WDQuery $all[$idx] } }
        }
    }

    function Export-WDResult { param([string]$Path)
        if (-not $script:WD_LastResult) { Write-Host "  Rien a exporter. Lancez une recherche d abord."; return }
        try { "$('='*50)`nWinDiag Export - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n$($env:COMPUTERNAME)`n$('='*50)`n$script:WD_LastResult" | Out-File $Path -Encoding UTF8; Write-Host "  Exporte : $Path" } catch { Write-Host "  Echec export : $_" }
    }

    function Show-WDHelp {
        Write-Host @"

  WinDiag — Diagnostic Codes Erreur Windows
  ==========================================
  USAGE (en standalone) :
    .\WinToolkit.ps1 -Module WinDiag -Query 0xc000012f
    .\WinToolkit.ps1 -Module WinDiag -Scan
    .\WinToolkit.ps1 -Module WinDiag -Scan -Export C:\rapport.txt
    .\WinToolkit.ps1 -Module WinDiag -Dump "C:\Windows\Minidump\*.dmp"

  FORMATS ACCEPTES (Query) :
    Code hex    : 0xc000012f
    Hex court   : c000012f
    Nom DLL     : ntdll.dll | vcruntime140.dll
    Nom process : explorer.exe | lsass.exe
    Mot-cle     : access violation | heap | stack overflow

  BASES INCLUSES : NTSTATUS, Win32, HRESULT, BSOD, DirectX, COM, Modules
"@
    }

    function Show-WDMenu {
        while ($true) {
            Write-Host ""; Write-Host "  WinDiag — Diagnostic Codes Erreur Windows" -ForegroundColor Cyan
            Write-Host "  ------------------------------------------"
            Write-Host "   1. Analyser un code / module / mot-cle"
            Write-Host "   2. Scanner l Event Log (crashes recents)"
            Write-Host "   3. Analyser fichier minidump"
            Write-Host "   4. Exporter le dernier resultat"
            Write-Host "   5. Aide"
            Write-Host "   0. Retour au menu principal"
            Write-Host ""; $choice = Read-Host "  Choix"
            switch ($choice) {
                "1" { Write-Host ""; $q = Read-Host "  Code / module / mot-cle"; if ($q) { Invoke-WDQuery $q } }
                "2" { Invoke-WDScan }
                "3" { Write-Host ""; $p = Read-Host "  Chemin dump (ex: C:\Windows\Minidump\*.dmp)"; if ($p) { $files = Get-Item $p -EA SilentlyContinue; if ($files) { foreach ($f in $files) { Write-Host "  Fichier : $($f.FullName) ($([math]::Round($f.Length/1KB,1)) KB) - $($f.LastWriteTime)" } $script:WD_LastResult = "Dump(s) listes ci-dessus. Utilisez WinDbg : windbg -z `"$p`" puis !analyze -v" } } }
                "4" { Write-Host ""; $f2 = Read-Host "  Fichier de sortie"; if ($f2) { Export-WDResult $f2 } }
                "5" { Show-WDHelp }
                "0" { Write-Host "  Rapport : $rpt_wd" -ForegroundColor DarkGray; return }
                default { Write-Host "  Choix invalide." }
            }
        }
    }

    if ($ShowHelp) { Show-WDHelp; return }
    if ($QueryIn)  { Invoke-WDQuery $QueryIn; if ($ExportPath) { Export-WDResult $ExportPath }; return }
    if ($ScanLog)  { Invoke-WDScan;  if ($ExportPath) { Export-WDResult $ExportPath }; return }
    if ($DumpPath) {
        $files = Get-Item $DumpPath -EA SilentlyContinue
        if ($files) { foreach ($f in $files) { Write-Host "  Fichier : $($f.FullName) ($([math]::Round($f.Length/1KB,1)) KB)" } }
        else { Write-Host "  Aucun fichier trouve : $DumpPath" }
        if ($ExportPath) { Export-WDResult $ExportPath }
        return
    }
    Show-WDMenu
}

# ===========================================================================
#  MODULE 6 — SFC/DISM  (Verification & reparation integrite Windows)
# ===========================================================================

function Invoke-SFC {
    Assert-AdminPrivilege
    Write-Title 'MODULE 6 — SFC/DISM : Verification Integrite Windows'

 #----------- Config -----------
$CBSLog       = "C:\Windows\Logs\CBS\CBS.log"
$timestamp    = (Get-Date -Format "yyyyMMdd_HHmmss")
$FilteredLog  = "$env:USERPROFILE\Desktop\CBS_SFC_DISM_Report_$timestamp.txt"
$HtmlReport   = "$env:USERPROFILE\Desktop\CBS_SFC_DISM_Report_$timestamp.html"
$Patterns     = "corrupt|repaired|restored|cannot repair|failed|abort"

# ----------- Nettoyage anciens rapports (> 7 jours) -----------
$reportPattern = "$env:USERPROFILE\Desktop\CBS_SFC_DISM_Report_*"
$daysToKeep    = 7
Get-ChildItem -Path $reportPattern -File |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$daysToKeep) } |
    Remove-Item -Force

# ----------- 0 Vérifier droits admin -----------
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Exécutez ce script en tant qu'administrateur pour que SFC/DISM fonctionnent correctement."
}

# ----------- 1 DISM CheckHealth & ScanHealth -----------
Write-Host "`n🔹 Vérification DISM CheckHealth..." -ForegroundColor Cyan
$checkResult = Dism /Online /Cleanup-Image /CheckHealth 2>&1
Write-Host "🔹 DISM CheckHealth terminé, analyse DISM ScanHealth en cours..." -ForegroundColor Cyan
$scanResult  = Dism /Online /Cleanup-Image /ScanHealth 2>&1
Write-Host "$(Get-Date -Format 'HH:mm:ss') 🔹 ScanHealth terminé." -ForegroundColor Cyan

# ----------- 2 Analyse résultats DISM -----------
if ($LASTEXITCODE -eq 0) {
    Write-Host "`n✅ Aucun problème détecté par DISM. RestoreHealth pas nécessaire." -ForegroundColor Green
    $launchRestore = $false
} else {
    Write-Host "`n⚠️  Corruption détectée ou réparation possible." -ForegroundColor Yellow
    $launchRestore = $true
}

# ----------- 3 Confirmation RestoreHealth -----------
if ($launchRestore) {
    $restoreConfirm = Read-Host "⚠️  Lancer DISM RestoreHealth ? (O/N)"
    if ($restoreConfirm -match "^[Oo]") {
        Write-Host "🔹 Lancement DISM RestoreHealth..." -ForegroundColor Cyan
        Dism /Online /Cleanup-Image /RestoreHealth

        $rebootConfirm = Read-Host "`n⚠️  Redémarrer maintenant ? (O/N)"
        if ($rebootConfirm -match "^[Oo]") {
            Write-Host "🔹 Redémarrage en cours..." -ForegroundColor Yellow
            Restart-Computer
            return
        } else {
            Write-Host "🔹 Redémarrage reporté." -ForegroundColor Yellow
        }
    } else {
        Write-Host "🔹 RestoreHealth annulé par l'utilisateur." -ForegroundColor Yellow
    }
}

# ----------- 4 Lancer SFC -----------
$runSfc = Read-Host "⚠️  Voulez-vous lancer SFC /scannow maintenant ? (O/N)"
if ($runSfc -match "^[Oo]") {
    Write-Host "`n🔹 Lancement SFC /scannow..." -ForegroundColor Cyan
    sfc /scannow
} else {
    Write-Host "`n🔹 SFC /scannow non lancé (mode lecture seule)." -ForegroundColor Yellow
}

# ----------- 5 Filtrage CBS + DISM -----------
$DISMLog = "C:\Windows\Logs\DISM\dism.log"
Write-Host "`n🔹 Filtrage CBS + DISM pour terminal et TXT..." -ForegroundColor Cyan

$CBSFiltered  = if (Test-Path $CBSLog)  { Select-String -Path $CBSLog  -Pattern $Patterns } else { Write-Warning "CBS.log introuvable";  @() }
$DISMFiltered = if (Test-Path $DISMLog) { Select-String -Path $DISMLog -Pattern $Patterns } else { Write-Warning "dism.log introuvable"; @() }

$AllFiltered  = @()
$AllFiltered += $CBSFiltered  | ForEach-Object { [PSCustomObject]@{ Source = "CBS";  Line = $_.Line } }
$AllFiltered += $DISMFiltered | ForEach-Object { [PSCustomObject]@{ Source = "DISM"; Line = $_.Line } }

# Affichage terminal
$AllFiltered | ForEach-Object { Write-Host "[$($_.Source)] $($_.Line)" }

# Sauvegarde TXT
$AllFiltered | ForEach-Object { "[{0}] {1}" -f $_.Source, $_.Line } | Out-File -Encoding UTF8 $FilteredLog

# ----------- 6 Résumé terminal -----------
$ErrorCount   = ($AllFiltered | Where-Object { $_.Line -match "cannot repair|failed|abort" }).Count
$WarningCount = ($AllFiltered | Where-Object { $_.Line -match "corrupt" }).Count
$SuccessCount = ($AllFiltered | Where-Object { $_.Line -match "repaired|restored" }).Count
$TotalCount   = $AllFiltered.Count
Write-Host "`n🔹 Résumé :" -ForegroundColor Cyan
Write-Host "   ✅ Succès         : $SuccessCount" -ForegroundColor Green
Write-Host "   ⚠️   Avertissements : $WarningCount" -ForegroundColor Yellow
Write-Host "   ❌ Erreurs        : $ErrorCount"   -ForegroundColor Red
Write-Host "   Total lignes      : $TotalCount`n"

# ----------- 7 Parsing lignes pour HTML -----------
$parsed = $AllFiltered | ForEach-Object {
    $line = $_.Line
    if ($line -match '^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\s*([^ ]+)\s+([^ ]+)\s+(.*)$') {
        [PSCustomObject]@{ Date = $matches[1]; Level = $matches[2]; Source = $_.Source; Message = $matches[4] }
    } elseif ($line -match '^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\s*([^ ]+)\s+(.*)$') {
        [PSCustomObject]@{ Date = $matches[1]; Level = $matches[2]; Source = $_.Source; Message = $matches[3] }
    } else {
        [PSCustomObject]@{ Date = ""; Level = ""; Source = $_.Source; Message = $line }
    }
}

# ----------- Fonction HtmlEncode -----------
function HtmlEncode {
    param($text)
    try   { return [System.Net.WebUtility]::HtmlEncode($text) }
    catch { try { return [System.Web.HttpUtility]::HtmlEncode($text) } catch { return $text } }
}

# ----------- Variables rapport -----------
$hostname   = $env:COMPUTERNAME
$reportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# ----------- 8 Génération HTML -----------
$HtmlHeader = @"
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SFC·DISM Report — $timestamp</title>
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
:root {
  --bg:      #0d1117;
  --surf:    #161b22;
  --surf2:   #1c2128;
  --border:  #30363d;
  --text:    #c9d1d9;
  --muted:   #8b949e;
  --cyan:    #58a6ff;
  --green:   #3fb950;
  --yellow:  #d29922;
  --red:     #f85149;
  --purple:  #bc8cff;
  --font:    'Cascadia Code', Consolas, 'Courier New', monospace;
}
body { font-family: var(--font); background: var(--bg); color: var(--text); font-size: 13px; line-height: 1.5; min-height: 100vh; }
a { color: var(--cyan); text-decoration: none; }
a:hover { text-decoration: underline; }

/* Top bar */
.top-bar {
  display: flex; align-items: center; justify-content: space-between;
  padding: 10px 24px; background: var(--surf); border-bottom: 1px solid var(--border);
  flex-wrap: wrap; gap: 8px; position: sticky; top: 0; z-index: 100;
}
.brand { font-size: 14px; font-weight: 700; color: var(--cyan); letter-spacing: .05em; }
.ver-badge {
  display: inline-block; padding: 1px 8px; border-radius: 20px;
  border: 1px solid var(--border); font-size: 11px; color: var(--muted); margin-left: 8px;
}
.top-right { display: flex; align-items: center; gap: 16px; color: var(--muted); font-size: 12px; }
.gh-link {
  display: inline-flex; align-items: center; gap: 5px; padding: 4px 10px;
  border: 1px solid var(--border); border-radius: 6px; font-size: 12px; color: var(--text);
  background: var(--surf2); transition: border-color .15s, color .15s;
}
.gh-link:hover { border-color: var(--cyan); color: var(--cyan); text-decoration: none; }

/* Cards */
.cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; padding: 20px 24px 0; }
@media (max-width: 680px) { .cards { grid-template-columns: repeat(2, 1fr); } }
@media (max-width: 360px) { .cards { grid-template-columns: 1fr; } }
.card {
  background: var(--surf); border: 1px solid var(--border); border-radius: 8px;
  padding: 16px 18px; display: flex; flex-direction: column; gap: 6px;
  transition: border-color .15s;
}
.card:hover { border-color: var(--muted); }
.card .num { font-size: 32px; font-weight: 700; line-height: 1; }
.card .lbl { font-size: 11px; text-transform: uppercase; letter-spacing: .08em; color: var(--muted); }
.card.total   { border-left: 3px solid var(--cyan);   } .card.total   .num { color: var(--cyan);   }
.card.success { border-left: 3px solid var(--green);  } .card.success .num { color: var(--green);  }
.card.warning { border-left: 3px solid var(--yellow); } .card.warning .num { color: var(--yellow); }
.card.error   { border-left: 3px solid var(--red);    } .card.error   .num { color: var(--red);    }

/* Meta bar */
.meta-bar {
  display: flex; gap: 20px; flex-wrap: wrap;
  padding: 10px 24px; color: var(--muted); font-size: 12px;
  border-top: 1px solid var(--border); border-bottom: 1px solid var(--border); margin-top: 16px;
}

/* Toolbar */
.toolbar { display: flex; align-items: center; gap: 12px; padding: 14px 24px 8px; flex-wrap: wrap; }
.search-wrap { position: relative; flex: 1; max-width: 400px; min-width: 180px; }
.search-wrap svg { position: absolute; left: 10px; top: 50%; transform: translateY(-50%); color: var(--muted); pointer-events: none; }
.toolbar input {
  width: 100%; background: var(--surf); border: 1px solid var(--border);
  color: var(--text); font-family: var(--font); font-size: 13px;
  padding: 7px 12px 7px 32px; border-radius: 6px; outline: none; transition: border-color .15s;
}
.toolbar input:focus { border-color: var(--cyan); }
.toolbar input::placeholder { color: var(--muted); }
.row-count { font-size: 12px; color: var(--muted); white-space: nowrap; }

/* Table */
.table-wrap { padding: 0 24px 24px; overflow-x: auto; }
table { width: 100%; border-collapse: collapse; min-width: 640px; }
thead tr { position: sticky; top: 41px; z-index: 9; }
th {
  background: var(--surf2); color: var(--muted); font-size: 11px;
  text-transform: uppercase; letter-spacing: .08em;
  padding: 9px 12px; text-align: left;
  border-bottom: 2px solid var(--border); white-space: nowrap;
  user-select: none; cursor: pointer; transition: color .15s;
}
th:hover { color: var(--text); }
th.sorted-asc  .si::after { content: ' ▲'; color: var(--cyan); }
th.sorted-desc .si::after { content: ' ▼'; color: var(--cyan); }
.si { font-size: 10px; color: var(--border); }
td {
  padding: 7px 12px; border-bottom: 1px solid var(--surf2);
  vertical-align: top;
}
td.td-date    { white-space: nowrap; color: var(--muted); font-size: 12px; min-width: 145px; }
td.td-level   { white-space: nowrap; min-width: 90px; }
td.td-source  { white-space: nowrap; min-width: 70px; }
td.td-msg     { word-break: break-word; }
tr:hover td   { background: var(--surf2); }
tr.row-error   td { background: rgba(248,81,73,.05);  }
tr.row-warning td { background: rgba(210,153,34,.05); }
tr.row-success td { background: rgba(63,185,80,.05);  }
tr.row-error:hover   td { background: rgba(248,81,73,.10);  }
tr.row-warning:hover td { background: rgba(210,153,34,.10); }
tr.row-success:hover td { background: rgba(63,185,80,.10);  }

/* Badges */
.badge { display: inline-block; padding: 2px 8px; border-radius: 20px; font-size: 11px; font-weight: 600; }
.b-err  { background: rgba(248,81,73,.18);  color: #f85149; border: 1px solid rgba(248,81,73,.35); }
.b-warn { background: rgba(210,153,34,.18); color: #e3b341; border: 1px solid rgba(210,153,34,.35); }
.b-ok   { background: rgba(63,185,80,.18);  color: #56d364; border: 1px solid rgba(63,185,80,.35); }
.b-info { background: rgba(88,166,255,.12); color: #79c0ff; border: 1px solid rgba(88,166,255,.25); }
.b-neu  { background: rgba(139,148,158,.12); color: var(--muted); border: 1px solid rgba(139,148,158,.25); }

.src-cbs  { color: #79c0ff; font-weight: 600; }
.src-dism { color: #d2a8ff; font-weight: 600; }
.msg-err  { color: #f85149; }
.msg-warn { color: #e3b341; }
.msg-ok   { color: #56d364; }

.no-data { text-align: center; padding: 56px 24px; color: var(--muted); }
.no-data .icon { font-size: 36px; display: block; margin-bottom: 10px; }

/* Footer */
footer {
  display: flex; justify-content: space-between; align-items: center;
  flex-wrap: wrap; gap: 8px; padding: 12px 24px;
  border-top: 1px solid var(--border); color: var(--muted); font-size: 11px;
}
</style>
<script>
var _sc = -1, _sd = 1;
function sortTable(n) {
  var tbody = document.querySelector('#rt tbody');
  var rows  = Array.from(tbody.querySelectorAll('tr.dr'));
  _sd = (_sc === n) ? -_sd : 1;
  _sc = n;
  rows.sort(function(a,b){
    var A = a.cells[n].innerText.trim(), B = b.cells[n].innerText.trim();
    var da = Date.parse(A), db = Date.parse(B);
    if (!isNaN(da) && !isNaN(db)) return (da - db) * _sd;
    return A.localeCompare(B, 'fr', {numeric: true}) * _sd;
  });
  rows.forEach(function(r){ tbody.appendChild(r); });
  document.querySelectorAll('th').forEach(function(th,i){
    th.classList.remove('sorted-asc','sorted-desc');
    if (i === n) th.classList.add(_sd === 1 ? 'sorted-asc' : 'sorted-desc');
  });
}
function filterTable() {
  var q   = document.getElementById('si').value.toLowerCase();
  var rows = document.querySelectorAll('#rt tbody tr.dr');
  var vis = 0;
  rows.forEach(function(r){
    var show = r.innerText.toLowerCase().indexOf(q) !== -1;
    r.style.display = show ? '' : 'none';
    if (show) vis++;
  });
  var nd = document.getElementById('nd');
  if (nd) nd.style.display = vis === 0 ? '' : 'none';
  document.getElementById('rc').textContent = vis + ' / ' + rows.length + ' entrées';
}
window.addEventListener('load', filterTable);
</script>
</head>
<body>

<div class="top-bar">
  <div>
    <span class="brand">⚙ SFC·DISM Checker</span>
    <span class="ver-badge">v1.1</span>
  </div>
  <div class="top-right">
    <span>Auteur : <strong style="color:var(--text)">ps81frt</strong></span>
    <a class="gh-link" href="https://github.com/ps81frt/SFC_DISM" target="_blank">
      <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38l-.01-1.49c-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48l-.01 2.2c0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>
      GitHub
    </a>
    <span>MIT License</span>
  </div>
</div>

<div class="cards">
  <div class="card total">
    <span class="num">$TotalCount</span>
    <span class="lbl">Total entrées</span>
  </div>
  <div class="card success">
    <span class="num">$SuccessCount</span>
    <span class="lbl">✅ Succès</span>
  </div>
  <div class="card warning">
    <span class="num">$WarningCount</span>
    <span class="lbl">⚠️ Avertissements</span>
  </div>
  <div class="card error">
    <span class="num">$ErrorCount</span>
    <span class="lbl">❌ Erreurs</span>
  </div>
</div>

<div class="meta-bar">
  <span>🖥 $hostname</span>
  <span>📅 $reportDate</span>
  <span>📂 CBS.log · dism.log</span>
  <span>🔍 Patterns : corrupt · repaired · restored · cannot repair · failed · abort</span>
</div>

<div class="toolbar">
  <div class="search-wrap">
    <svg width="14" height="14" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="2"><circle cx="8.5" cy="8.5" r="5.5"/><line x1="13" y1="13" x2="18" y2="18"/></svg>
    <input type="text" id="si" placeholder="Filtrer les entrées..." oninput="filterTable()">
  </div>
  <span class="row-count" id="rc"></span>
</div>

<div class="table-wrap">
<table id="rt">
  <thead>
    <tr>
      <th onclick="sortTable(0)">Date <span class="si"></span></th>
      <th onclick="sortTable(1)">Niveau <span class="si"></span></th>
      <th onclick="sortTable(2)">Source <span class="si"></span></th>
      <th onclick="sortTable(3)">Message <span class="si"></span></th>
    </tr>
  </thead>
  <tbody>
"@

# ----------- Body HTML -----------
$HtmlBody = ""
foreach ($entry in $parsed) {
    # Classe de ligne et badge de niveau
    if ($entry.Message -match "cannot repair|failed|abort") {
        $rowClass  = "row-error"
        $msgClass  = "msg-err"
        $lvlBadge  = if ($entry.Level) { "<span class='badge b-err'>$($entry.Level)</span>" } else { "<span class='badge b-err'>ERROR</span>" }
    } elseif ($entry.Message -match "corrupt") {
        $rowClass  = "row-warning"
        $msgClass  = "msg-warn"
        $lvlBadge  = if ($entry.Level) { "<span class='badge b-warn'>$($entry.Level)</span>" } else { "<span class='badge b-warn'>WARN</span>" }
    } elseif ($entry.Message -match "repaired|restored") {
        $rowClass  = "row-success"
        $msgClass  = "msg-ok"
        $lvlBadge  = if ($entry.Level) { "<span class='badge b-ok'>$($entry.Level)</span>" } else { "<span class='badge b-ok'>OK</span>" }
    } else {
        $rowClass  = ""
        $msgClass  = ""
        $lvlBadge  = if ($entry.Level) { "<span class='badge b-neu'>$($entry.Level)</span>" } else { "" }
    }

    $srcClass = if ($entry.Source -eq "CBS") { "src-cbs" } else { "src-dism" }
    $encMsg   = HtmlEncode $entry.Message

    $HtmlBody += "<tr class='dr $rowClass'>
<td class='td-date'>$($entry.Date)</td>
<td class='td-level'>$lvlBadge</td>
<td class='td-source'><span class='$srcClass'>$($entry.Source)</span></td>
<td class='td-msg'><span class='$msgClass'>$encMsg</span></td>
</tr>`n"
}

$HtmlFooter = @"
    <tr id="nd" style="display:none"><td colspan="4" class="no-data"><span class="icon">🔍</span>Aucune entrée ne correspond au filtre.</td></tr>
  </tbody>
</table>
</div>

<footer>
  <span>SFC·DISM Checker v1.1 — <a href="https://github.com/ps81frt/SFC_DISM" target="_blank">github.com/ps81frt/SFC_DISM</a> — MIT License</span>
  <span>Auteur : <strong>ps81frt</strong> · $reportDate</span>
</footer>
</body>
</html>
"@

$HtmlHeader + $HtmlBody + $HtmlFooter | Out-File -Encoding UTF8 $HtmlReport

# ----------- 9 Sortie finale -----------
Write-Host "`n🔹 Rapport TXT  : $FilteredLog" -ForegroundColor Cyan
Write-Host "🔹 Rapport HTML : $HtmlReport"  -ForegroundColor Cyan
Write-Host "`n✅ Terminé. Analyse complète.`n" -ForegroundColor Green
}
# ===========================================================================
#  MODULE 7 — NETSHARE  (Diagnostic partages reseau SMB)
# ===========================================================================

function Invoke-NetShare {
    param([string]$NSDMode = "COMPLET")

    Assert-AdminPrivilege
    Write-Title 'MODULE 7 — NETSHARE : Diagnostic Partages Reseau SMB'

    $OutputPath = "$env:USERPROFILE\Desktop"
    $Mode       = if ($NSDMode -eq 'PUBLIC') { 'PUBLIC' } else { 'COMPLET' }
    $IsAdmin    = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $IsAdmin) { Write-WARN 'Non admin - certaines donnees seront indisponibles.' }

    Write-Host "  [MODE] $Mode | Rapport -> $OutputPath" -ForegroundColor $(if($Mode -eq 'COMPLET'){'Green'}else{'Cyan'})
    Write-Host ''

    $ScriptStartTime = Get-Date

    function Set-Mask-IP {
    param([string]$IP)
    if ($Mode -eq 'PUBLIC' -and $IP -match '^\d+\.\d+\.\d+\.\d+$') {
    $parts = $IP.Split('.')
    return "$($parts[0]).$($parts[1]).x.xxx"
    }
    return $IP
    }

    function Set-Mask-MAC {
    param([string]$MAC)
    if ($Mode -eq 'PUBLIC') { return 'XX:XX:XX:XX:XX:XX' }
    return $MAC
    }

    function Set-Mask-Host {
    param([string]$Hostname)
    if ($Mode -eq 'PUBLIC' -and $Hostname -ne '' -and $Hostname -ne 'N/A') {
    if ($Hostname.Length -gt 3) { return $Hostname.Substring(0,3) + ('*' * [Math]::Min(5,$Hostname.Length-3)) }
    return '***'
    }
    return $Hostname
    }

    function Set-Mask-SID {
    param([string]$SID)
    if ($Mode -eq 'PUBLIC') { return 'S-1-5-***-***' }
    return $SID
    }

    function Get-StatusBadge {
    param([string]$Status)
    switch ($Status) {
    'OK'       { return '<span class="badge ok">✅ OK</span>' }
    'WARN'     { return '<span class="badge warn">⚠️ AVERT.</span>' }
    'CRITICAL' { return '<span class="badge critical">❌ CRITIQUE</span>' }
    'INFO'     { return '<span class="badge info">ℹ️ INFO</span>' }
    default    { return "<span class='badge info'>$Status</span>" }
    }
    }

    function Write-Step {
    Write-Host "  → $Message" -ForegroundColor DarkCyan
    }

    function Set-Safe-Get {
    param([scriptblock]$Block, $Default = $null)
    try { return (& $Block) }
    catch { return $Default }
    }

    function Set-Safe-String {
    param($Value, [string]$Default = 'N/A')
    if ($null -eq $Value -or "$Value" -eq '') { return $Default }
    return "$Value"
    }

    function HtmlEncode {
    param([string]$s)
    $s = $s -replace '&','&amp;'
    $s = $s -replace '<','&lt;'
    $s = $s -replace '>','&gt;'
    $s = $s -replace '"','&quot;'
    return $s
    }

    function Get-RegValue {
    param([string]$Path, [string]$Name)
    try { return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name }
    catch { return 'NON DEFINI' }
    }

    # ─────────────────────────────────────────────────────────────────────────────
    # REGION: COLLECTE DES DONNEES
    # ─────────────────────────────────────────────────────────────────────────────

    # 1. IDENTITE MACHINE
    Write-Step "Collecte de l'identite machine..."
    $OS = Set-Safe-Get { Get-CimInstance Win32_OperatingSystem }
    $CS = Set-Safe-Get { Get-CimInstance Win32_ComputerSystem }
    $Identity = [PSCustomObject]@{
    Hostname     = $env:COMPUTERNAME
    Domaine      = if ($CS -and $CS.PartOfDomain) { $CS.Domain } else { "WORKGROUP: $(if($CS){$CS.Workgroup}else{'N/A'})" }
    OS           = if ($OS) { $OS.Caption }         else { 'N/A' }
    Build        = if ($OS) { $OS.BuildNumber }     else { 'N/A' }
    Version      = if ($OS) { $OS.Version }         else { 'N/A' }
    Architecture = if ($OS) { $OS.OSArchitecture }  else { 'N/A' }
    Uptime       = if ($OS) { (New-TimeSpan -Start $OS.LastBootUpTime -End (Get-Date)).ToString("dd'd 'hh'h 'mm'm'") } else { 'N/A' }
    DernierBoot  = if ($OS) { $OS.LastBootUpTime.ToString("yyyy-MM-dd HH:mm:ss") } else { 'N/A' }
    Utilisateur  = "$env:USERDOMAIN\$env:USERNAME"
    SID          = Set-Mask-SID (Set-Safe-Get { [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value } 'N/A')
    EstAdmin     = $IsAdmin
    PSVersion    = $PSVersionFull
    PSEdition    = $PSVersionTable.PSEdition
    }

    # 2. INTERFACES RESEAU
    Write-Step "Collecte des interfaces reseau..."
    $NetAdapters   = Set-Safe-Get { Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } } @()
    $NetInterfaces = foreach ($Adapter in $NetAdapters) {
    try {
    $IPConfig  = Get-NetIPConfiguration -InterfaceIndex $Adapter.InterfaceIndex
    $IPAddr    = ($IPConfig.IPv4Address | Where-Object { $_.IPAddress -notmatch '^169\.' } | Select-Object -First 1)
    $DNS       = ($IPConfig.DNSServer | Where-Object { $_.AddressFamily -eq 2 } | ForEach-Object { $_.ServerAddresses }) -join ', '
    $IsVirtual = $Adapter.InterfaceDescription -match 'Hyper-V|VMware|VirtualBox|TAP|Loopback|Miniport|WAN|VPN|Tunnel'
    $MTU       = Set-Safe-Get { (Get-NetIPInterface -InterfaceIndex $Adapter.InterfaceIndex -AddressFamily IPv4).NlMtu } 'N/A'
    [PSCustomObject]@{
    Nom         = $Adapter.Name
    Description = $Adapter.InterfaceDescription
    MAC         = Set-Mask-MAC ($Adapter.MacAddress)
    IP          = if ($IPAddr) { SET-Mask-IP $IPAddr.IPAddress } else { 'N/A' }
    Masque      = if ($IPAddr) { $IPAddr.PrefixLength }      else { 'N/A' }
    Passerelle  = if ($IPConfig.IPv4DefaultGateway) { SET-Mask-IP $IPConfig.IPv4DefaultGateway.NextHop } else { 'N/A' }
    DNS         = if ($Mode -eq 'PUBLIC') { ($DNS -replace '\d+\.\d+\.\d+\.\d+','x.x.x.x') } else { $DNS }
    DHCP        = if ($IPConfig.NetIPv4Interface.Dhcp -eq 'Enabled') { 'DHCP' } else { 'Statique' }
    Vitesse     = Set-Safe-String $Adapter.LinkSpeed
    Type        = if ($IsVirtual) { '⚠️ Virtuel/VPN' } else { 'Physique' }
    MTU         = $MTU
    Statut      = $Adapter.Status
    }
    } catch {
    [PSCustomObject]@{
    Nom='N/A'; Description=$Adapter.InterfaceDescription; MAC='N/A'; IP='N/A'
    Masque='N/A'; Passerelle='N/A'; DNS='N/A'; DHCP='N/A'
    Vitesse='N/A'; Type='N/A'; MTU='N/A'; Statut='Erreur'
    }
    }
    }

    # 3. PROFILS RESEAU
    Write-Step "Collecte des profils reseau..."
    $NetProfiles = Set-Safe-Get {
    Get-NetConnectionProfile | ForEach-Object {
    [PSCustomObject]@{
    Interface = $_.InterfaceAlias
    Nom       = $_.Name
    Profil    = $_.NetworkCategory
    IPv4      = $_.IPv4Connectivity
    IPv6      = $_.IPv6Connectivity
    Risque    = switch ($_.NetworkCategory) {
    'Public'  { 'CRITICAL' }
    'Private' { 'OK' }
    'Domain'  { 'OK' }
    default   { 'WARN' }
    }
    }
    }
    } @()

    # 4. LECTEURS MAPPES & HISTORIQUE MRU
    Write-Step "Collecte des lecteurs mappes et historique MRU..."
    $MappedDrives = Set-Safe-Get {
    Get-PSDrive -PSProvider FileSystem | Where-Object { $_.DisplayRoot -like '\\*' } | ForEach-Object {
    [PSCustomObject]@{
    Lecteur = $_.Name
    Cible   = if ($Mode -eq 'PUBLIC') { ($_.DisplayRoot -replace '\\\\[^\\]+','\\***') } else { $_.DisplayRoot }
    Utilise = if ($_.Used) { [Math]::Round($_.Used/1GB,2).ToString() + ' Go' } else { 'N/A' }
    Libre   = if ($_.Free) { [Math]::Round($_.Free/1GB,2).ToString() + ' Go' } else { 'N/A' }
    }
    }
    } @()

    # Lecteurs reseau persistants depuis HKCU:\Network
    $PersistentDrives = Set-Safe-Get {
    $netKey = 'HKCU:\Network'
    if (Test-Path $netKey) {
    Get-ChildItem $netKey | ForEach-Object {
    $props = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{
    Lecteur     = $_.PSChildName + ':'
    Cible       = if ($Mode -eq 'PUBLIC') { ($props.RemotePath -replace '\\\\[^\\]+','\\***') } else { Set-Safe-String $props.RemotePath }
    Fournisseur = Set-Safe-String $props.ProviderName
    Utilisateur = if ($Mode -eq 'PUBLIC') { '***' } else { Set-Safe-String $props.UserName }
    Source      = 'Registre HKCU:\Network'
    }
    }
    }
    } @()

    $MRUKeys = @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU',
    'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Network\Persistent Connections'
    )
    $MRUEntries = foreach ($Key in $MRUKeys) {
    try {
    if (Test-Path $Key) {
    $props = Get-ItemProperty $Key
    $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
    [PSCustomObject]@{
    Source = $Key.Split('\')[-1]
    Cle    = $_.Name
    Valeur = if ($Mode -eq 'PUBLIC') { ($_.Value -replace '\\\\[^\\]+','\\***') } else { "$($_.Value)" }
    }
    }
    }
    } catch { }
    }

    # 5. CONFIGURATION SMB SERVEUR
    Write-Step "Collecte de la configuration SMB serveur..."
    $SMBServerConfig = $null
    $SMBv1Server     = $false
    $SMBv2Server     = $true
    try {
    $SMBServerConfig = Get-SmbServerConfiguration -ErrorAction Stop
    $SMBv1Server     = $SMBServerConfig.EnableSMB1Protocol
    $SMBv2Server     = $SMBServerConfig.EnableSMB2Protocol
    } catch {
    Write-Host "  [AVERT.] Get-SmbServerConfiguration inaccessible : $($_.Exception.Message)" -ForegroundColor Yellow
    }

    $SMBServerItems = if ($SMBServerConfig) {
    @(
    [PSCustomObject]@{ Parametre='SMBv1 (Serveur)';            Valeur=if($SMBv1Server){'ACTIVE'}else{'Desactive'};            Risque=if($SMBv1Server){'CRITICAL'}else{'OK'}; Note='Obsolete - vulnerable EternalBlue/MS17-010' }
    [PSCustomObject]@{ Parametre='SMBv2/v3 (Serveur)';         Valeur=if($SMBv2Server){'Active'}else{'DESACTIVE'};            Risque=if($SMBv2Server){'OK'}else{'CRITICAL'}; Note='Requis pour le partage modern' }
    [PSCustomObject]@{ Parametre='Signature requise (Serveur)'; Valeur=if($SMBServerConfig.RequireSecuritySignature){'Requise'}else{'Non requise'}; Risque=if($SMBServerConfig.RequireSecuritySignature){'OK'}else{'WARN'}; Note='Previent les attaques MITM/relay' }
    [PSCustomObject]@{ Parametre='Signature activee (Serveur)'; Valeur=if($SMBServerConfig.EnableSecuritySignature){'Activee'}else{'Desactivee'}; Risque=if($SMBServerConfig.EnableSecuritySignature){'OK'}else{'WARN'}; Note='' }
    [PSCustomObject]@{ Parametre='Chiffrement (Serveur)';       Valeur=if($SMBServerConfig.EncryptData){'Active'}else{'Desactive'}; Risque=if($SMBServerConfig.EncryptData){'OK'}else{'INFO'}; Note='Chiffrement SMB3' }
    [PSCustomObject]@{ Parametre='Protocole Maximum';           Valeur=Set-Safe-String $SMBServerConfig.MaxProtocol;              Risque='INFO'; Note='' }
    [PSCustomObject]@{ Parametre='Protocole Minimum';           Valeur=Set-Safe-String $SMBServerConfig.MinProtocol;              Risque=if($SMBServerConfig.MinProtocol -eq 'SMB1'){'CRITICAL'}else{'OK'}; Note='' }
    [PSCustomObject]@{ Parametre='Deconnexion auto (min)';      Valeur=Set-Safe-String $SMBServerConfig.AutoDisconnectTimeout;    Risque='INFO'; Note='' }
    [PSCustomObject]@{ Parametre='Sessions null (pipes)';       Valeur=if($SMBServerConfig.NullSessionPipes){'Configure'}else{'Aucun'}; Risque='INFO'; Note='' }
    [PSCustomObject]@{ Parametre='Partages null';               Valeur=if($SMBServerConfig.NullSessionShares){'Configure'}else{'Aucun'}; Risque='INFO'; Note='' }
    )
    } else {
    @([PSCustomObject]@{ Parametre='Erreur'; Valeur='Get-SmbServerConfiguration indisponible'; Risque='WARN'; Note='Verifier droits admin et module SMB' })
    }

    # 6. CONFIGURATION SMB CLIENT
    Write-Step "Collecte de la configuration SMB client..."
    $SMBClientConfig = $null
    $SMBClientSource = 'cmdlet'
    try {
    $SMBClientConfig = Get-SmbClientConfiguration -ErrorAction Stop
    } catch {
    $SMBClientSource = 'registre'

    $regPath   = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
    $clientReg = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue -ErrorVariable err -PSProvider Registry::HKEY_LOCAL_MACHINE
    if ($clientReg) {
    $SMBClientConfig = [PSCustomObject]@{
    RequireSecuritySignature = $clientReg.RequireSecuritySignature
    EnableSecuritySignature  = $clientReg.EnableSecuritySignature
    MaxProtocol              = $clientReg.MaxProtocol
    MinProtocol              = $clientReg.MinProtocol
    SessionTimeout           = $clientReg.SessionTimeout
    DirectoryCacheLifetime   = $clientReg.DirectoryCacheLifetime
    FileInfoCacheLifetime    = $clientReg.FileInfoCacheLifetime
    WindowSizeThreshold      = $clientReg.WindowSizeThreshold
    }
    }

    if (-not $SMBClientConfig) {
    Write-Host "  [AVERT.] Registre LanmanWorkstation inaccessible ou LongPathsEnabled non actif." -ForegroundColor Yellow
    Write-Host "           Relancer en Administrateur et verifier :" -ForegroundColor DarkYellow
    Write-Host "           reg add HKLM\SYSTEM\CurrentControlSet\Control\FileSystem /v LongPathsEnabled /t REG_DWORD /d 1 /f" -ForegroundColor DarkYellow
    Write-Host "           ⚠️ Un redemarrage peut etre necessaire pour que la modification soit effective." -ForegroundColor DarkYellow
    }
    }

    $SMBClientItems = if ($SMBClientConfig) {
    $sourceNote = if ($SMBClientSource -eq 'registre') { ' (source: registre)' } else { '' }
    @(
    [PSCustomObject]@{ Parametre='Signature requise (Client)';  Valeur=if($SMBClientConfig.RequireSecuritySignature){'Requise'}else{'Non requise'}; Risque=if($SMBClientConfig.RequireSecuritySignature){'OK'}else{'WARN'}; Note="Application cote client$sourceNote" }
    [PSCustomObject]@{ Parametre='Signature activee (Client)';  Valeur=if($SMBClientConfig.EnableSecuritySignature){'Activee'}else{'Desactivee'}; Risque=if($SMBClientConfig.EnableSecuritySignature){'OK'}else{'WARN'}; Note=$sourceNote.Trim() }
    [PSCustomObject]@{ Parametre='Protocole Max (Client)';      Valeur=Set-Safe-String $SMBClientConfig.MaxProtocol 'N/A';      Risque='INFO'; Note='' }
    [PSCustomObject]@{ Parametre='Protocole Min (Client)';      Valeur=Set-Safe-String $SMBClientConfig.MinProtocol 'N/A';      Risque=if((Set-Safe-String $SMBClientConfig.MinProtocol 'N/A') -eq 'SMB1'){'CRITICAL'}else{'OK'}; Note='' }
    [PSCustomObject]@{ Parametre='Delai session (s)';           Valeur=Set-Safe-String $SMBClientConfig.SessionTimeout 'N/A';   Risque='INFO'; Note='' }
    [PSCustomObject]@{ Parametre='Duree cache repertoire (s)';  Valeur=Set-Safe-String $SMBClientConfig.DirectoryCacheLifetime 'N/A'; Risque='INFO'; Note='' }
    [PSCustomObject]@{ Parametre='Cache entrees fichier (s)';   Valeur=Set-Safe-String $SMBClientConfig.FileInfoCacheLifetime 'N/A'; Risque='INFO'; Note='' }
    [PSCustomObject]@{ Parametre='Windows pour Large Reads';    Valeur=Set-Safe-String $SMBClientConfig.WindowSizeThreshold 'N/A'; Risque='INFO'; Note='' }
    )
    } else {
    @([PSCustomObject]@{ Parametre='Erreur'; Valeur='Registre LanmanWorkstation inaccessible ou LongPathsEnabled non actif'; Risque='WARN'; Note='' })
    }

    # 6.1 VERIFICATION DE LA DISPONIBILITE DES SERVICES SMB

    $SMBServerAvailable = (Get-Service -Name LanmanServer -ErrorAction SilentlyContinue).Status -eq 'Running'
    $SMBClientAvailable = (Get-Service -Name LanmanWorkstation -ErrorAction SilentlyContinue).Status -eq 'Running'

    # 7 PARTAGES SMB (parametres etendus)
    Write-Step "Collecte des partages SMB (parametres etendus)..."
    if ($SMBServerAvailable) {
    $SMBShares     = @()
    $SMBSharesTemp = @()
    $rawShares     = Set-Safe-Get { Get-SmbShare -ErrorAction Stop } @()

    $hasShareConfig = [bool](Get-Command Get-SmbShareConfiguration -ErrorAction SilentlyContinue)
    if (-not $hasShareConfig) {
    Write-Host "  [INFO] Get-SmbShareConfiguration absent sur cette version de Windows. ABE/Cache_HS non disponibles." -ForegroundColor Yellow
    }

    Write-DebugHost "DEBUG: rawShares=$(@($rawShares).Count) hasShareConfig=$hasShareConfig"

    if (-not $rawShares) {
    Write-Host "  [AVERT.] Aucun partage SMB lu ou Get-SmbShare a echoue." -ForegroundColor Yellow
    }

    foreach ($share in $rawShares) {
    $sName = $share.Name
    Write-DebugHost "DEBUG: traitant share $sName"

    $perms = Set-Safe-Get {
    Get-SmbShareAccess -Name $sName -ErrorAction Stop |
    ForEach-Object { "$($_.AccountName):$($_.AccessRight)" }
    } @()

    $sConf = $null
    if ($hasShareConfig) {
    $sConf = Set-Safe-Get { Get-SmbShareConfiguration -Name $sName -ErrorAction Stop } $null
    }

    Write-DebugHost "DEBUG RAW SHARE: Name='$($share.Name)' Path='$($share.Path)'"

    $maxAllowed = if ($share.PSObject.Properties['MaximumAllowed']) { $share.MaximumAllowed } else { [uint32]::MaxValue }

    try {
    $entry = [PSCustomObject]@{
    Nom             = $sName
    Chemin          = Set-Safe-String $share.Path
    Description     = Set-Safe-String $share.Description
    Type            = if ($share.Special) { 'Systeme' } else { 'Utilisateur' }
    Permissions     = ($perms -join ' | ')
    ABE             = if ($sConf) { if ($sConf.FolderEnumerationMode -eq 'AccessBased') {'Actif'} else {'Inactif'} } else { 'N/A' }
    Cache_HS        = if ($sConf) { Set-Safe-String $sConf.CachingMode } else { 'N/A' }
    MaxUtilisateurs = if ($null -eq $maxAllowed -or $maxAllowed -eq [uint32]::MaxValue) { 'Illimite' } else { "$maxAllowed" }
    Disponibilite   = if ($share.ContinuouslyAvailable) { 'Oui' } else { 'Non' }
    }
    } catch {
    Write-DebugHost "DEBUG: entry creation failed for $sName : $($_.Exception.Message)" -ForegroundColor Red
    continue
    }

    Write-DebugHost "DEBUG ENTRY TYPE: $($entry.GetType().FullName)"
    Write-DebugHost "DEBUG ENTRY PROPS: $($entry.PSObject.Properties.Name -join ', ')"
    Write-DebugHost "DEBUG ENTRY VALUES: $($entry.Nom) | $($entry.Chemin) | $($entry.Permissions)"

    $SMBSharesTemp += $entry
    Write-DebugHost "DEBUG: added $sName, tempCount=$($SMBSharesTemp.Count)"
    }

    $SMBShares = $SMBSharesTemp
    Write-DebugHost "DEBUG: firstShare=$($SMBShares[0].Nom) path=$($SMBShares[0].Chemin)"
    } else {
    $SMBShares = @()
    Write-Host "  [AVERT.] Collecte des partages SMB annulee : LanmanServer n'est pas demarre." -ForegroundColor Yellow
    }


    # DEBUG : Affichage du nombre d'objets collectes pour SMB (pour aider a identifier les erreurs d'acces aux cmdlets)
    Write-DebugHost "DEBUG: SMBShares=$(@($SMBShares).Count) SMBSessions=$(@($SMBSessions).Count) SMBConnections=$(@($SMBConnections).Count)"

    # 8. SESSIONS SMB ACTIVES
    Write-Step "Collecte des sessions SMB actives..."
    if ($SMBServerAvailable) {
    $SMBSessions = @()
    try {
    $rawSessions = Get-SmbSession -ErrorAction Stop
    } catch {
    Write-DebugHost "DEBUG: Get-SmbSession failed: $($_.Exception.Message)" -ForegroundColor Yellow
    $rawSessions = @()
    }

    Write-DebugHost "DEBUG: rawSessions=$(@($rawSessions).Count)"

    if ($rawSessions) {
    $SMBSessions = foreach ($session in $rawSessions) {
    try {
    [PSCustomObject]@{
    Client      = if ($Mode -eq 'PUBLIC') { SET-Mask-IP $session.ClientComputerName } else { $session.ClientComputerName }
    Utilisateur = if ($Mode -eq 'PUBLIC') { ($session.ClientUserName -replace '^[^\\]+\\','***\') } else { $session.ClientUserName }
    Dialecte    = $session.Dialect
    Signe       = if ($session.PSObject.Properties['IsSigned'])    { $session.IsSigned }    else { 'N/A' }
    Chiffre     = if ($session.PSObject.Properties['IsEncrypted']) { $session.IsEncrypted } else { 'N/A' }
    Duree_s     = $session.SecondsExists
    }
    } catch {
    Write-DebugHost "DEBUG: session object failed: $($_.Exception.Message)" -ForegroundColor Yellow
    continue
    }
    }
    }
    } else {
    $SMBSessions = @()
    Write-Host "  [AVERT.] Collecte des sessions SMB annulee : LanmanServer n'est pas demarre." -ForegroundColor Yellow
    }

    # 9. CONNEXIONS SMB ACTIVES
    Write-Step "Collecte des connexions SMB actives..."
    if ($SMBClientAvailable) {
    $SMBConnections = @()
    try {
    $rawConnections = Get-SmbConnection -ErrorAction Stop
    } catch {
    Write-DebugHost "DEBUG: Get-SmbConnection failed: $($_.Exception.Message)" -ForegroundColor Yellow
    $rawConnections = @()
    }

    Write-DebugHost "DEBUG: rawConnections=$(@($rawConnections).Count)"

    if ($rawConnections) {
    $SMBConnections = foreach ($conn in $rawConnections) {
    try {
    [PSCustomObject]@{
    Serveur     = if ($Mode -eq 'PUBLIC') { Set-Mask-Host $conn.ServerName } else { $conn.ServerName }
    Partage     = if ($Mode -eq 'PUBLIC') { ($conn.ShareName -replace '(?<=\\).*','***') } else { $conn.ShareName }
    Dialecte    = $conn.Dialect
    Signe       = if ($conn.PSObject.Properties['IsSigned'])    { $conn.IsSigned }    else { 'N/A' }
    Chiffre     = if ($conn.PSObject.Properties['IsEncrypted']) { $conn.IsEncrypted } else { 'N/A' }
    Utilisateur = if ($Mode -eq 'PUBLIC') { '***' } else { $conn.UserName }
    }
    } catch {
    Write-DebugHost "DEBUG: connection object failed: $($_.Exception.Message)" -ForegroundColor Yellow
    continue
    }
    }
    }
    } else {
    $SMBConnections = @()
    Write-Host "  [AVERT.] Collecte des connexions SMB annulee : LanmanWorkstation n'est pas demarre." -ForegroundColor Yellow
    }

    Write-DebugHost "DEBUG: SMBSessions=$(@($SMBSessions).Count) SMBConnections=$(@($SMBConnections).Count)"

    # 9.1 RESOLUTION DES INTERFACES LOCALES POUR LES CONNEXIONS SMB
    function Set-Parse-UNCPath { # modified
    param([string]$Path)
    $result = [PSCustomObject]@{ Serveur='N/A'; Partage='N/A' }
    if ($Path -match '^\\\\([^\\]+)\\([^\\]+)') {
    $result.Serveur = $matches[1]
    $result.Partage = $matches[2]
    }
    return $result
    }

    function Get-LocalInterfaceForHost {
    param([string]$RemoteHost)
    $info = [PSCustomObject]@{ Interface='N/A'; LocalIP='N/A' }
    try {
    $addresses = @()
    if ($RemoteHost -match '^\d{1,3}(?:\.\d{1,3}){3}$') {
    $addresses = @($RemoteHost)
    } else {
    $addresses = [System.Net.Dns]::GetHostAddresses($RemoteHost) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | ForEach-Object { $_.IPAddressToString }
    }
    foreach ($addr in $addresses) {
    if (-not $addr) { continue }
    $route = Get-NetRoute -DestinationPrefix "$addr/32" -ErrorAction SilentlyContinue | Sort-Object -Property RouteMetric | Select-Object -First 1
    if ($route) {
    $iface = Get-NetIPConfiguration -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue
    if ($iface) {
    $info.Interface = Set-Safe-String $iface.InterfaceAlias 'N/A'
    $info.LocalIP   = if ($iface.IPv4Address) { $iface.IPv4Address[0].IPAddress } else { 'N/A' }
    }
    break
    }
    }
    } catch {
    # Ignore failures, keep N/A values
    }
    return $info
    }

    $RemoteSMBShares = @()

    $MappedDrives | ForEach-Object {
    $unc = Set-Parse-UNCPath $_.Cible
    $RemoteSMBShares += [PSCustomObject]@{
    Source      = 'Lecteur mappe'
    Serveur     = $unc.Serveur
    Partage     = $unc.Partage
    Cible       = $_.Cible
    Utilisateur = 'N/A'
    Type        = 'Lecteur mappe'
    }
    }

    $PersistentDrives | ForEach-Object {
    $unc = Set-Parse-UNCPath $_.Cible
    $RemoteSMBShares += [PSCustomObject]@{
    Source      = 'Lecteur persistant'
    Serveur     = $unc.Serveur
    Partage     = $unc.Partage
    Cible       = $_.Cible
    Utilisateur = $_.Utilisateur
    Type        = 'Persistant'
    }
    }

    $SMBConnections | ForEach-Object {
    $RemoteSMBShares += [PSCustomObject]@{
    Source      = 'Connexion active'
    Serveur     = $_.Serveur
    Partage     = $_.Partage
    Cible       = "$($_.Serveur)\$($_.Partage)"
    Utilisateur = $_.Utilisateur
    Type        = 'Session SMB'
    }
    }

    # 10. AUDIT SMB DES PARTAGES DE FICHIERS
    $SMBShareAuditStatus = 'Unknown'
    try {
    $auditOutput = (auditpol /get /subcategory:"Partage de fichiers" 2>$null) -join "`n"
    foreach ($line in $auditOutput -split "`n") {
    if ($line -match '^\s*(?:Partage de fichiers|File Share)\s+(.*)$') {
    $SMBShareAuditStatus = $matches[1].Trim()
    break
    }
    }
    } catch {
    $SMBShareAuditStatus = 'Inaccessible'
    }
    Write-DebugHost "DEBUG: SMBShareAuditStatus='$SMBShareAuditStatus'"

    # 10.1 HISTORIQUE DES CONNEXIONS RESEAU
    Write-Step "Collecte de l'historique des connexions reseau (7 derniers jours)..."
    $ConnHistory = @()
    try {
    $histStart  = (Get-Date).AddDays(-7)
    $histEvents = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    StartTime = $histStart
    Id        = @(5140, 5142, 5143, 5144)
    } -MaxEvents 150 -ErrorAction SilentlyContinue
    $ConnHistory = $histEvents | ForEach-Object {
    $msg   = $_.Message
    $ip    = if ($msg -match '(?:Adresse reseau source|Source Address)\s*:\s*(\S+)') { $matches[1] } else { 'N/A' }
    $share = if ($msg -match '(?:Nom du partage|Share Name)\s*:\s*(\S+)') { $matches[1] } else { 'N/A' }
    $user  = if ($msg -match '(?:Nom du compte|Account Name)\s*:\s*(\S+)') { $matches[1] } else { 'N/A' }
    [PSCustomObject]@{
    Horodatage  = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
    EventID     = $_.Id
    TypeEvenemt = switch ($_.Id) {
    5140 { 'Acces partage' }
    5142 { 'Ajout partage' }
    5143 { 'Modif. partage' }
    5144 { 'Suppression partage' }
    default { 'Autre' }
    }
    Partage     = if ($Mode -eq 'PUBLIC') { ($share -replace '\\\\[^\\]+','\\***') } else { $share }
    IPSource    = if ($Mode -eq 'PUBLIC') { SET-Mask-IP $ip } else { $ip }
    Compte      = if ($Mode -eq 'PUBLIC') { '***' } else { $user }
    }
    }
    } catch {
    $ConnHistory = @([PSCustomObject]@{
    Horodatage='N/A'; EventID='N/A'; TypeEvenemt='Acces admin requis'
    Partage='Journaux de securite inaccessibles sans elevation'
    IPSource='N/A'; Compte='N/A'
    })
    }

    # Connexions net use en temps reel
    $NetUseRaw     = Set-Safe-Get { & net use 2>$null } @()
    $NetUseEntries = @()
    if ($NetUseRaw) {
    $NetUseRaw | Where-Object { $_ -match '\\\\' } | ForEach-Object {
    $parts = $_.Trim() -split '\s{2,}'
    if ($parts.Count -ge 2) {
    $NetUseEntries += [PSCustomObject]@{
    Statut  = Set-Safe-String $parts[0]
    Local   = if ($parts.Count -ge 3) { $parts[1] } else { 'N/A' }
    Distant = if ($Mode -eq 'PUBLIC') { ($parts[-1] -replace '\\\\[^\\]+','\\***') } else { $parts[-1] }
    }
    }
    }
    }

    # 11. PARE-FEU
    Write-Step "Collecte de la configuration du pare-feu..."
    $FWProfiles = Set-Safe-Get {
    Get-NetFirewallProfile | ForEach-Object {
    [PSCustomObject]@{
    Profil         = $_.Name
    Active         = $_.Enabled
    EntreeDefaut   = $_.DefaultInboundAction
    SortieDefaut   = $_.DefaultOutboundAction
    LogAutorise    = $_.LogAllowed
    LogBloque      = $_.LogBlocked
    Risque         = if (-not $_.Enabled) { 'WARN' } else { 'OK' }
    }
    }
    } @()

    $SmbPorts = @(445, 139, 137, 138)
    $FWRules = Set-Safe-Get {
    Get-NetFirewallRule | Where-Object {
    $_.Enabled -eq $true -and
    ($_.DisplayName -match 'SMB|File|Share|Network Discovery|NetBIOS|Partage|Fichiers' -or
    ($_.Direction -eq 'Inbound' -and ($_ | Get-NetFirewallPortFilter | Where-Object { $_.LocalPort -in $SmbPorts })))
    } | ForEach-Object {
    $pf = $_ | Get-NetFirewallPortFilter
    [PSCustomObject]@{
    Nom       = $_.DisplayName
    Direction = $_.Direction
    Action    = $_.Action
    Profil    = $_.Profile
    Protocole = $pf.Protocol
    Port      = $pf.LocalPort
    Active    = $_.Enabled
    Risque    = if ($_.Action -eq 'Block' -and $_.Direction -eq 'Inbound') { 'WARN' } else { 'OK' }
    }
    }
    } @()

    # 12. POLITIQUE D'AUTHENTIFICATION
    Write-Step "Collecte de la politique d'authentification..."
    $RegPaths = @{
    Lsa     = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    MSV1_0  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
    Policies= 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    DNS     = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
    }

    $LmLevel = Get-RegValue $RegPaths.Lsa 'LmCompatibilityLevel'
    $LATFP   = Get-RegValue $RegPaths.Policies 'LocalAccountTokenFilterPolicy'

    $AuthPolicy = @(
    [PSCustomObject]@{ Cle='LmCompatibilityLevel';         Valeur=$LmLevel; Recommande='5'; Risque=if($LmLevel-eq'NON DEFINI'){'WARN'}elseif([int]$LmLevel-lt 3){'CRITICAL'}elseif([int]$LmLevel-ge 5){'OK'}else{'WARN'}; Note='NTLMv2 uniquement (5=optimal). Valeur basse = capture hash LM/NTLMv1' }
    [PSCustomObject]@{ Cle='RestrictAnonymous';            Valeur=(Get-RegValue $RegPaths.Lsa 'RestrictAnonymous'); Recommande='1'; Risque=if((Get-RegValue $RegPaths.Lsa 'RestrictAnonymous')-eq'0'){'WARN'}else{'OK'}; Note='Bloque enumeration anonyme partages/comptes' }
    [PSCustomObject]@{ Cle='RestrictAnonymousSAM';         Valeur=(Get-RegValue $RegPaths.Lsa 'RestrictAnonymousSAM'); Recommande='1'; Risque=if((Get-RegValue $RegPaths.Lsa 'RestrictAnonymousSAM')-eq'0'){'WARN'}else{'OK'}; Note='Bloque enumeration anonyme des comptes SAM' }
    [PSCustomObject]@{ Cle='LocalAccountTokenFilterPolicy'; Valeur=$LATFP; Recommande='1 (admin distant)'; Risque=if($LATFP-ne'1'){'WARN'}else{'OK'}; Note='Doit etre 1 pour acces distant avec compte local' }
    [PSCustomObject]@{ Cle='NoLMHash';                    Valeur=(Get-RegValue $RegPaths.Lsa 'NoLMHash'); Recommande='1'; Risque=if((Get-RegValue $RegPaths.Lsa 'NoLMHash')-ne'1'){'WARN'}else{'OK'}; Note='Empeche stockage hash LM (vol de credentials)' }
    [PSCustomObject]@{ Cle='EnableLUA (UAC)';             Valeur=(Get-RegValue $RegPaths.Policies 'EnableLUA'); Recommande='1'; Risque=if((Get-RegValue $RegPaths.Policies 'EnableLUA')-eq'0'){'WARN'}else{'OK'}; Note='Etat du Controle de Compte Utilisateur' }
    [PSCustomObject]@{ Cle='NTLMMinClientSecurity'; Valeur=(Get-RegValue $RegPaths.MSV1_0 'NTLMMinClientSec'); Recommande='537395200'; Risque= if ([int](Get-RegValue $RegPaths.MSV1_0 'NTLMMinClientSec') -lt 537395200) {'WARN'} else {'OK'}; Note='NTLMv2 activé, compatible W10 mais 537395200 reste recommandé pour le chiffrement 128 bits' }
    [PSCustomObject]@{ Cle='NTLMMinServerSecurity'; Valeur=(Get-RegValue $RegPaths.MSV1_0 'NTLMMinServerSec'); Recommande='537395200'; Risque= if ([int](Get-RegValue $RegPaths.MSV1_0 'NTLMMinServerSec') -lt 537395200) {'WARN'} else {'OK'}; Note='NTLMv2 activé, compatible W10 mais 537395200 reste recommandé pour le chiffrement 128 bits' }
    )

    $LocalAccounts = Set-Safe-Get {
    Get-LocalUser | ForEach-Object {
    # Definir un booleen si le compte a un mot de passe
    $HasPassword = [bool]$_.PasswordLastSet

    [PSCustomObject]@{
    Nom           = if ($Mode -eq 'PUBLIC') { ($_.Name.Substring(0,[Math]::Min(3,$_.Name.Length))+'***') } else { $_.Name }
    Active        = $_.Enabled
    DernConnexion = if ($_.LastLogon) { $_.LastLogon.ToString('yyyy-MM-dd HH:mm') } else { 'Jamais' }
    MdpRequis     = $HasPassword
    MdpExpire     = if ($_.PasswordExpires) { $_.PasswordExpires.ToString('yyyy-MM-dd') } else { 'N/A' }
    SID           = Set-Mask-SID $_.SID.Value
    Risque        = if ($_.Enabled -and -not $HasPassword) { 'CRITICAL' } elseif ($_.Enabled) { 'INFO' } else { 'OK' }
    }
    }
    } @()

    $CredmanOutput = Set-Safe-Get { & cmdkey /list 2>$null } @()
    $CredEntries = if ($CredmanOutput) {
    $CredmanOutput | Where-Object { $_ -match 'Target|Cible' } | ForEach-Object {
    $target = ($_ -replace '.*(?:Target|Cible):\s*','').Trim()
    [PSCustomObject]@{
    Cible = if ($Mode -eq 'PUBLIC') { ($target -replace '(?<=\\\\)[^\\]+','***') } else { $target }
    Type  = if ($target -match '\\\\') { 'Reseau' } else { 'Generique' }
    }
    }
    } else { @() }



    # 13. SERVICES & PROTOCOLES DE DECOUVERTE
    Write-Step "Collecte des services et protocoles de decouverte..."
    $CriticalServices = @(
    @{Name='LanmanServer';    Friendly='Serveur SMB (LanmanServer)';             Risk='CRITICAL'}
    @{Name='LanmanWorkstation'; Friendly='Client SMB (Workstation)';             Risk='CRITICAL'}
    @{Name='MrxSmb';          Friendly='Mini-redirecteur SMB';                   Risk='WARN'}
    @{Name='Browser';         Friendly='Explorateur reseau (Computer Browser)';  Risk='INFO'}
    @{Name='FDResPub';        Friendly='Publication ressources (FDResPub)';       Risk='WARN'}
    @{Name='SSDPSRV';         Friendly='Decouverte SSDP';                         Risk='WARN'}
    @{Name='upnphost';        Friendly='Hote peripherique UPnP';                 Risk='INFO'}
    @{Name='Dnscache';        Friendly='Client DNS';                              Risk='WARN'}
    @{Name='WinRM';           Friendly='Gestion a distance Windows (WinRM)';     Risk='INFO'}
    @{Name='NlaSvc';          Friendly='Detection reseau (NLA)';                 Risk='WARN'}
    @{Name='netlogon';        Friendly='Ouverture de session reseau';             Risk='INFO'}
    @{Name='mpsdrv';          Friendly='Pilote Pare-feu Windows';                Risk='WARN'}
    @{Name='BFE';             Friendly='Moteur de filtrage de base (BFE)';       Risk='CRITICAL'}
    @{Name='mpssvc';          Friendly='Service Pare-feu Windows';               Risk='WARN'}
    @{Name='Spooler';         Friendly='Spouleur impression';                     Risk='INFO'}
    )

    $ServicesData = foreach ($Svc in $CriticalServices) {
    $s = Set-Safe-Get { Get-Service -Name $Svc.Name -ErrorAction Stop } $null
    [PSCustomObject]@{
    Nom       = $Svc.Name
    Libelle   = $Svc.Friendly
    Statut    = if ($s) { "$($s.Status)" } else { 'Introuvable' }
    Demarrage = if ($s) { "$($s.StartType)" } else { 'N/A' }
    Risque    = if (-not $s) { 'INFO' }
    elseif ($s.Status -ne 'Running' -and $Svc.Risk -eq 'CRITICAL') { 'CRITICAL' }
    elseif ($s.Status -ne 'Running' -and $Svc.Risk -eq 'WARN') { 'WARN' }
    else { 'OK' }
    }
    }

    $DNSClientPath   = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
    $DNSClientParent = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT'
    $LLMNRVal        = Get-RegValue $RegPaths.DNS 'EnableMulticast'
    $DNSClientExists = Test-Path $DNSClientPath
    $NetBIOSAdapters = Set-Safe-Get { Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.TcpipNetbiosOptions -ne $null } } @()
    $NetBIOSStatus = ($NetBIOSAdapters | ForEach-Object {
    switch ($_.TcpipNetbiosOptions) { 0{'Par defaut (DHCP)'} 1{'Active'} 2{'Desactive'} }
    }) | Select-Object -Unique

    $DiscoveryItems = @(
    [PSCustomObject]@{ Protocole='LLMNR';              Etat=if($LLMNRVal -eq '0'){'Desactive'}else{'Active (defaut)'}; Risque=if($LLMNRVal -eq '0'){'OK'}else{'WARN'}; Note='Nom multicast local - risque MITM (Responder)' }
    [PSCustomObject]@{ Protocole='NetBIOS over TCP/IP'; Etat=($NetBIOSStatus -join ', '); Risque='INFO'; Note='Resolution noms legacy' }
    [PSCustomObject]@{ Protocole='mDNS';               Etat='Active (defaut)'; Risque='INFO'; Note='DNS multicast - protocole Bonjour' }
    [PSCustomObject]@{ Protocole='WSD (Web Services)'; Etat=if((Set-Safe-Get{(Get-Service FDResPub).Status}'Stopped') -eq 'Running'){'En cours'}else{'Arrete'}; Risque='INFO'; Note='Publication decouverte reseau' }
    )


    # 14. JOURNAL D'EVENEMENTS — 24H
    Write-Step "Collecte des evenements (24 dernieres heures)..."
    $EventStart = (Get-Date).AddHours(-24)
    $EventIDs   = @(4625, 4648, 4776, 5140, 5145, 7036, 7045)
    $EventLogs  = @()
    try {
    $EventLogs = Get-WinEvent -FilterHashtable @{
    LogName   = @('Security','System','Application')
    StartTime = $EventStart
    Id        = $EventIDs
    } -MaxEvents 200 -ErrorAction Stop | ForEach-Object {
    [PSCustomObject]@{
    Horodatage = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
    Journal    = $_.LogName
    EventID    = $_.Id
    Niveau     = $_.LevelDisplayName
    Source     = $_.ProviderName
    Message    = ($_.Message -replace '\r?\n',' ').Substring(0,[Math]::Min(200,$_.Message.Length)) + '...'
    Categorie  = switch ($_.Id) {
    4625 { 'Echec auth.' }
    4648 { 'Session explicite' }
    4776 { 'Auth. NTLM' }
    5140 { 'Acces partage' }
    5145 { 'Acces objet partage' }
    7036 { 'Etat service' }
    7045 { 'Nouveau service' }
    default { 'Autre' }
    }
    }
    }
    } catch {
    $EventLogs = @([PSCustomObject]@{
    Horodatage='N/A'; Journal='N/A'; EventID='N/A'; Niveau='N/A'
    Source='Droits admin requis'; Message="Acces aux journaux d'evenements necessite une elevation de droits"; Categorie='N/A'
    })
    }

    # 15. TABLE ARP
    Write-Step "Collecte de la table ARP..."
    $ArpOutput = Set-Safe-Get { & arp -a 2>$null } @()
    $ArpEntries = @()
    if ($ArpOutput) {
    $ArpOutput | Where-Object { $_ -match '^\s+\d' } | ForEach-Object {
    $parts = $_.Trim() -split '\s+'
    if ($parts.Count -ge 3) {
    $ArpEntries += [PSCustomObject]@{
    IP   = if ($Mode -eq 'PUBLIC') { SET-Mask-IP $parts[0] } else { $parts[0] }
    MAC  = Set-Mask-MAC ($parts[1])
    Type = $parts[2]
    }
    }
    }
    }

    # 16. FICHIER HOSTS
    Write-Step "Collecte du fichier hosts..."
    $HostsPath    = "$env:SystemRoot\System32\drivers\etc\hosts"
    $HostsEntries = @()
    if (Test-Path $HostsPath) {
    try {
    Get-Content $HostsPath | Where-Object { $_ -notmatch '^\s*#' -and $_ -match '\S' } | ForEach-Object {
    $parts = $_.Trim() -split '\s+'
    if ($parts.Count -ge 2) {
    $HostsEntries += [PSCustomObject]@{
    IP       = if ($Mode -eq 'PUBLIC') { SET-Mask-IP $parts[0] } else { $parts[0] }
    Hostname = if ($Mode -eq 'PUBLIC') { Set-Mask-Host $parts[1] } else { $parts[1] }
    Note     = if ($parts.Count -gt 2) { $parts[2..($parts.Count-1)] -join ' ' } else { '' }
    }
    }
    }
    } catch { }
    }

    # 17. TESTS DE CONNECTIVITE
    Write-Step "Execution des tests de connectivite..."

    $Neighbors = @()
    $ArpEntries | Where-Object {
    $_.Type -eq 'dynamic' -and
    $_.IP -notmatch '^(224\.|255\.|169\.|fe80:|ff[0-9a-fA-F]*:|::1$)'
    } | ForEach-Object { $Neighbors += $_.IP }

    $SMBSessions | Where-Object {
    $_.Client -and $_.Client -notmatch '^fe80:'
    } | ForEach-Object { $Neighbors += $_.Client }

    $Neighbors = $Neighbors | Where-Object { $_ -ne '' } | Sort-Object -Unique | Select-Object -First 10

    $ConnTests = @()
    foreach ($Target in $Neighbors) {
    try {
    $DisplayTarget = if ($Mode -eq 'PUBLIC') { SET-Mask-IP $Target } else { $Target }

    # Ping
    $PingResult = Test-Connection -ComputerName $Target -Count 1 -Quiet

    # Port 445
    $PortResult = Set-Safe-Get { Test-NetConnection -ComputerName $Target -Port 445 -InformationLevel Quiet -WarningAction SilentlyContinue } $false

    # UNC IPC
    $UNCResult = 'N/A'
    if ($PortResult) {
    try {
    $null = [System.IO.Directory]::GetDirectories("\\$Target\IPC$")
    $UNCResult = 'OK'
    } catch {
    $UNCResult = $_.Exception.Message.Substring(0,[Math]::Min(60,$_.Exception.Message.Length))
    }
    }

    # Resultat global
    $Overall = if ($PingResult -and $PortResult -and $UNCResult -eq 'OK') { 'OK' }
    elseif ($PingResult -and $PortResult) { 'WARN' }
    elseif ($PingResult) { 'WARN' }
    else { 'CRITICAL' }

    $ConnTests += [PSCustomObject]@{
    Cible   = $DisplayTarget
    Ping    = if ($PingResult) { 'OK' } else { 'ECHEC' }
    Port445 = if ($PortResult) { 'OUVERT' } else { 'FERME/FILTRE' }
    UNC_IPC = if ($Mode -eq 'PUBLIC') { ($UNCResult -replace '\\\\[^\\]+','\\***') } else { $UNCResult }
    Resultat= $Overall
    }

    } catch {
    $ConnTests += [PSCustomObject]@{
    Cible   = $Target
    Ping    = 'N/A'
    Port445 = 'N/A'
    UNC_IPC = 'Erreur'
    Resultat= 'WARN'
    }
    }
    }

    # 18. PARTAGES SMB
    Write-Step "Collecte des partages SMB..."
    if ($SMBServerAvailable) {
    $Shares = Set-Safe-Get {
    Get-SmbShare -ErrorAction Stop | ForEach-Object {
    $ShareName = $_.Name
    $Path      = $_.Path

    $Permissions = Get-SmbShareAccess -Name $ShareName -ErrorAction SilentlyContinue

    $Folders = if (Test-Path $Path) {
    Get-ChildItem -Path $Path -Directory -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty Name
    } else { @() }

    [PSCustomObject]@{
    Nom        = if ($Mode -eq 'PUBLIC') { ($ShareName.Substring(0,[Math]::Min(3,$ShareName.Length))+'***') } else { $ShareName }
    Chemin     = $Path
    Acces      = ($Permissions | ForEach-Object {
    "$($_.AccountName) ($($_.AccessRight))"
    }) -join "; "
    Dossiers   = if ($Folders) { $Folders -join ", " } else { "Aucun / inaccessible" }
    Risque     = if ($Permissions.AccountName -match 'Everyone') { 'WARN' } else { 'OK' }
    }
    }
    } @()
    } else {
    $Shares = @()
    Write-Host "  [AVERT.] Collecte des partages SMB annulee : LanmanServer n'est pas demarre." -ForegroundColor Yellow
    }


    # DEBUG: Affichage des compteurs de donnees collectees
    Write-DebugHost "DEBUG: Shares=$(@($Shares).Count) SMBShares=$(@($SMBShares).Count) SMBSessions=$(@($SMBSessions).Count) SMBConnections=$(@($SMBConnections).Count)"
    Write-DebugHost "DEBUG: SMBServerAvailable=$SMBServerAvailable SMBClientAvailable=$SMBClientAvailable"


    # Fallback si aucun voisin detecte
    if (-not $ConnTests -or $ConnTests.Count -eq 0) {
    $ConnTests = foreach ($Target in $Neighbors) {
    [PSCustomObject]@{
    Cible   = if ($Mode -eq 'PUBLIC') { SET-Mask-IP $Target } else { $Target }
    Ping    = 'N/A'
    Port445 = 'N/A'
    UNC_IPC = 'N/A'
    Resultat= 'WARN'
    }
    }
    }

    # ─────────────────────────────────────────────────────────────────────────────
    # REGION: MOTEUR D'ANALYSE & RECOMMANDATIONS
    # ─────────────────────────────────────────────────────────────────────────────
    Write-Step "Analyse des resultats et generation des recommandations..."
    $Findings = @()

    # SMBv1 SERVEUR
    if ($SMBv1Server) {
    $Findings += [PSCustomObject]@{ Severite='CRITICAL'; Categorie='Protocole SMB'; Constat='SMBv1 est ACTIVE (serveur)'; Detail='SMBv1 obsolete et vulnerable (EternalBlue/MS17-010). Desactiver immediatement.'; Correction='Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force' }
    }

    # SMBv2 SERVEUR
    if (-not $SMBv2Server) {
    $Findings += [PSCustomObject]@{ Severite='CRITICAL'; Categorie='Protocole SMB'; Constat='SMBv2 est DESACTIVE (serveur)'; Detail='SMBv2/v3 doit etre active pour le partage Windows moderne.'; Correction='Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force' }
    }

    # SMBv1 CLIENT
    if ($SMBClientConfig -and "$($SMBClientConfig.MinProtocol)" -eq 'SMB1') {
    $Findings += [PSCustomObject]@{ Severite='CRITICAL'; Categorie='Protocole SMB'; Constat='SMBv1 autorise cote CLIENT'; Detail='Le client SMB accepte SMB1. Risque identique cote serveur.'; Correction='Set-SmbClientConfiguration -MinimumProtocol SMB2 -Force' }
    }

    # PROFIL RESEAU PUBLIC
    foreach ($P in $NetProfiles) {
    if ($P.Profil -eq 'Public') {
    $Findings += [PSCustomObject]@{ Severite='CRITICAL'; Categorie='Profil reseau'; Constat="Interface '$($P.Interface)' sur profil PUBLIC"; Detail='Le profil Public bloque le partage de fichiers. Passer en Prive.'; Correction="Set-NetConnectionProfile -InterfaceAlias '$($P.Interface)' -NetworkCategory Private" }
    }
    }

    # LmCompatibilityLevel
    if ($LmLevel -eq 'NON DEFINI') {
    $Findings += [PSCustomObject]@{ Severite='WARN'; Categorie='Authentification'; Constat='LmCompatibilityLevel absent du registre'; Detail='Valeur par defaut differente entre W10 et W11, peut causer des echecs de partage reseau entre machines mixtes.'; Correction='Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name LmCompatibilityLevel -Value 3 -Type DWord' }
    } elseif ([int]$LmLevel -lt 3) {
    $Findings += [PSCustomObject]@{ Severite='CRITICAL'; Categorie='Authentification'; Constat="LmCompatibilityLevel = $LmLevel (trop bas)"; Detail='Authentification LM/NTLMv1 autorisee. Risque majeur de vol de credentials.'; Correction='Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name LmCompatibilityLevel -Value 5 -Type DWord' }
    } elseif ([int]$LmLevel -lt 5) {
    $Findings += [PSCustomObject]@{
    Severite='WARN'
    Categorie='Authentification'
    Constat="LmCompatibilityLevel = $LmLevel (trop bas)"
    Detail='NTLMv2 uniquement recommandé. Valeur 5 est optimale.'
    Correction='Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name LmCompatibilityLevel -Value 5 -Type DWord'
    }
    }
    # RestrictAnonymous
    if ((Get-RegValue $RegPaths.Lsa 'restrictanonymous') -eq '0') {
    $Findings += [PSCustomObject]@{ Severite='WARN'; Categorie='Authentification'; Constat='RestrictAnonymous = 0'; Detail='Enumeration anonyme des partages autorisee.'; Correction='Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name restrictanonymous -Value 1 -Type DWord' }
    }

    # LocalAccountTokenFilterPolicy
    if ($LATFP -ne '1') {
    $Findings += [PSCustomObject]@{ Severite='WARN'; Categorie='Authentification'; Constat='LocalAccountTokenFilterPolicy non defini a 1'; Detail='Connexions distantes avec compte local peuvent echouer (restriction UAC distante active).'; Correction='New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name LocalAccountTokenFilterPolicy -Value 1 -PropertyType DWORD -Force' }
    }

    # UAC DESACTIVE
    if ((Get-RegValue $RegPaths.Policies 'EnableLUA') -eq '0') {
    $Findings += [PSCustomObject]@{ Severite='WARN'; Categorie='Authentification'; Constat='UAC desactive (EnableLUA=0)'; Detail='Controle de compte utilisateur desactive. Risque elevation silencieuse de privileges.'; Correction='Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLUA -Value 1' }
    }

    # PARE-FEU DESACTIVE
    foreach ($FWP in $FWProfiles) {
    if (-not $FWP.Active) {
    $Findings += [PSCustomObject]@{ Severite='WARN'; Categorie='Pare-feu'; Constat="Pare-feu DESACTIVE sur le profil : $($FWP.Profil)"; Detail='Pare-feu Windows desactive. Verifier presence pare-feu tiers.'; Correction="Set-NetFirewallProfile -Profile $($FWP.Profil) -Enabled True" }
    }
    }

    # SERVICES CRITICAL ARRETES
    foreach ($Svc in $ServicesData) {
    if ($Svc.Statut -ne 'Running' -and $Svc.Risque -eq 'CRITICAL') {
    if ($Svc.Demarrage -eq 'Disabled') {
    $Findings += [PSCustomObject]@{
    Severite  = 'CRITICAL'
    Categorie = 'Services'
    Constat   = "Service DESACTIVE : $($Svc.Libelle)"
    Detail    = "$($Svc.Nom) est desactive et ne peut pas demarrer sans changer son type de demarrage."
    Correction= "Set-Service -Name $($Svc.Nom) -StartupType Automatic; Start-Service -Name $($Svc.Nom)"
    }
    } else {
    $Findings += [PSCustomObject]@{
    Severite  = 'CRITICAL'
    Categorie = 'Services'
    Constat   = "Service ARRETE : $($Svc.Libelle)"
    Detail    = "$($Svc.Nom) doit etre actif pour le partage SMB."
    Correction= "Start-Service -Name $($Svc.Nom)"
    }
    }
    }
    }

    # SERVICES WARN ARRETES
    foreach ($Svc in $ServicesData) {
    if ($Svc.Statut -ne 'Running' -and $Svc.Risque -eq 'WARN') {
    $Findings += [PSCustomObject]@{ Severite='WARN'; Categorie='Services'; Constat="Service arrete : $($Svc.Libelle)"; Detail="$($Svc.Nom) arrete peut degrader la decouverte reseau ou les performances SMB."; Correction="Start-Service -Name $($Svc.Nom)" }
    }
    }

    # SIGNATURE SMB SERVEUR
    if ($SMBServerConfig -and -not $SMBServerConfig.EnableSecuritySignature) {
    $Findings += [PSCustomObject]@{ Severite='WARN'; Categorie='Securite SMB'; Constat='Signature SMB non activee cote serveur'; Detail='Sans signature, attaques SMB relay (NTLM relay) possibles.'; Correction='Set-SmbServerConfiguration -EnableSecuritySignature $true -Force' }
    }

    # COMPTES LOCAUX SANS MOT DE PASSE
    foreach ($Acct in $LocalAccounts) {
    if ($Acct.Active -and $Acct.MdpRequis -eq $false) {
    $Findings += [PSCustomObject]@{ Severite='CRITICAL'; Categorie='Comptes locaux'; Constat="Compte sans mot de passe requis : $($Acct.Nom)"; Detail='Compte active sans exigence de mot de passe.'; Correction="Set-LocalUser -Name '$($Acct.Nom)' -PasswordRequired `$true" }
    }
    }

    # PARTAGES OUVERTS A EVERYONE
    foreach ($Share in $Shares) {
    if ($Share.Risque -eq 'WARN') {
    $Findings += [PSCustomObject]@{ Severite='WARN'; Categorie='Partages'; Constat="Partage accessible a Everyone : $($Share.Nom)"; Detail='Acces non restreint au partage. Tout utilisateur du reseau peut y acceder.'; Correction="Revoir les permissions : Set-SmbShareAccess -Name '$($Share.Nom)'" }
    }
    }

    # LLMNR ACTIVE
    if ($LLMNRVal -ne '0') {
    if (-not $DNSClientExists) {
    $Correction = "New-Item -Path '$DNSClientParent' -Name 'DNSClient' -Force; New-ItemProperty -Path '$DNSClientPath' -Name EnableMulticast -PropertyType DWORD -Value 0 -Force"
    } else {
    $Correction = "Set-ItemProperty -Path '$DNSClientPath' -Name EnableMulticast -Value 0 -Type DWord"
    }
    $Findings += [PSCustomObject]@{ Severite='WARN'; Categorie='Protocoles decouverte'; Constat='LLMNR est active'; Detail='LLMNR exploitable pour capturer credentials (outil Responder).'; Correction=$Correction }
    }

    # CONNECTIVITE
    if ($ConnTests -and $ConnTests.Count -gt 0) {
    $ConnTests | Where-Object { $_.Resultat -eq 'CRITICAL' } | ForEach-Object {
    $Findings += [PSCustomObject]@{ Severite='WARN'; Categorie='Connectivite'; Constat="Impossible de joindre $($_.Cible)"; Detail="Ping : $($_.Ping) | Port 445 : $($_.Port445) | UNC : $($_.UNC_IPC)"; Correction='Verifier regles pare-feu, profil reseau et service SMB sur la machine cible.' }
    }
    }

    # AUTRES VERIFICATIONS
    $RestrictNullSessAccess = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RestrictNullSessAccess'
    if ($RestrictNullSessAccess -ne '0') {
    $Findings += [PSCustomObject]@{
    Severite  = 'WARN'
    Categorie = 'SMB / Sécurité'
    Constat   = "RestrictNullSessAccess = $RestrictNullSessAccess"
    Detail    = 'Les sessions nulles sont autorisées côté serveur SMB.'
    Correction= 'Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name RestrictNullSessAccess -Value 0 -Type DWord -Force'
    }
    }

    $EveryoneIncludesAnonymous = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'everyoneincludesanonymous'
    if ($EveryoneIncludesAnonymous -ne '1') {
    $Findings += [PSCustomObject]@{
    Severite  = 'WARN'
    Categorie = 'SMB / Sécurité'
    Constat   = "everyoneincludesanonymous = $EveryoneIncludesAnonymous"
    Detail    = "Acces anonyme global n'est pas activé, ce qui peut bloquer certains partages Windows légitimes en environnement local"
    Correction= 'Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name everyoneincludesanonymous -Value 1 -Type DWord -Force'
    }
    }

    $SMB2Feature      = Set-Safe-Get { Get-WindowsOptionalFeature -Online -FeatureName FS-SMB2 -ErrorAction Stop } $null
    $SMBDirectFeature = Set-Safe-Get { Get-WindowsOptionalFeature -Online -FeatureName FS-SMBDIRECT -ErrorAction Stop } $null

    if ($SMB2Feature -and $SMB2Feature.State -ne 'Enabled') {
    $Findings += [PSCustomObject]@{
    Severite  = 'INFO'
    Categorie = 'SMB'
    Constat   = 'Feature FS-SMB2 non activée'
    Detail    = 'Le support SMB2/SMB3 peut ne pas être entièrement disponible.'
    Correction= 'Enable-WindowsOptionalFeature -Online -FeatureName FS-SMB2 -NoRestart'
    }
    }

    if ($SMBDirectFeature -and $SMBDirectFeature.State -ne 'Enabled') {
    $Findings += [PSCustomObject]@{
    Severite  = 'INFO'
    Categorie = 'SMB'
    Constat   = 'Feature FS-SMBDIRECT non activée'
    Detail    = 'Le support SMB Direct est pas activé.'
    Correction= 'Enable-WindowsOptionalFeature -Online -FeatureName FS-SMBDIRECT -NoRestart'
    }
    }

    $FWNetworkDiscovery = Set-Safe-Get {
    Get-NetFirewallRule | Where-Object {
    $_.DisplayGroup -match 'Network Discovery|Découverte' -and $_.Enabled -eq $false
    }
    } @()
    if ($FWNetworkDiscovery.Count -gt 0) {
    $Findings += [PSCustomObject]@{
    Severite  = 'WARN'
    Categorie = 'Pare-feu'
    Constat   = "Règles de découverte réseau désactivées : $($FWNetworkDiscovery.Count)"
    Detail    = 'Les règles de découverte réseau doivent être activées pour que la découverte SMB fonctionne correctement.'
    Correction= 'Get-NetFirewallRule | Where-Object { $_.DisplayGroup -match "Network Discovery|Découverte" } | Set-NetFirewallRule -Enabled True'
    }
    }

    $FWFileAndPrinter = Set-Safe-Get {
    Get-NetFirewallRule | Where-Object {
    $_.DisplayGroup -match 'File and Printer Sharing|Partage' -and $_.Enabled -eq $false
    }
    } @()

    if ($FWFileAndPrinter.Count -gt 0) {
    $Findings += [PSCustomObject]@{
    Severite  = 'WARN'
    Categorie = 'Pare-feu'
    Constat   = "Règles File and Printer Sharing désactivées : $($FWFileAndPrinter.Count)"
    Detail    = 'Les règles de partage de fichiers et imprimantes doivent être activées pour SMB.'
    Correction= 'Get-NetFirewallRule | Where-Object { $_.DisplayGroup -match "File and Printer Sharing|Partage" } | Set-NetFirewallRule -Enabled True'
    }
    }

    $ExistingBlockRules = Set-Safe-Get {
    Get-NetFirewallRule | Where-Object { $SMBBlockRules -contains $_.DisplayName -and $_.Action -eq 'Block' }
    } @()
    if ($ExistingBlockRules.Count -gt 0) {
    $Findings += [PSCustomObject]@{
    Severite  = 'WARN'
    Categorie = 'Pare-feu'
    Constat   = "Règles de blocage SMB détectées : $($ExistingBlockRules.DisplayName -join ', ')"
    Detail    = 'Des règles de blocage SMB explicites peuvent empêcher les connexions réseau.'
    Correction= 'Remove-NetFirewallRule -DisplayName "Bloquer SMB entrant 445","Bloquer SMB entrant 139","Bloquer NetBIOS entrant","Bloquer SMB sortant 445","Bloquer SMB sortant 139"'
    }
    }

    $NetBIOSProps = Set-Safe-Get {
    Get-NetAdapterAdvancedProperty -DisplayName 'NetBIOS over Tcpip' -ErrorAction Stop
    } @()
    $NonDefaultNetBIOS = $NetBIOSProps | Where-Object {
    $_.DisplayValue -notin 'Default','Par défaut','Default'
    }
    if ($NetBIOSProps.Count -gt 0 -and $NonDefaultNetBIOS.Count -gt 0) {
    $Findings += [PSCustomObject]@{
    Severite  = 'INFO'
    Categorie = 'SMB / Réseau'
    Constat   = "NetBIOS over Tcpip non en mode Default sur certains adaptateurs"
    Detail    = 'Pour un comportement standard SMB, NetBIOS devrait être en mode Default si possible.'
    Correction= 'Get-NetAdapterAdvancedProperty -DisplayName "NetBIOS over Tcpip" | Set-NetAdapterAdvancedProperty -DisplayValue "Default"'
    }
    }

    $NmClient = Get-RegValue $RegPaths.MSV1_0 'NTLMMinClientSec'
    if ($NmClient -ne 'NON DEFINI' -and [int]$NmClient -lt 537395200) {
    $Findings += [PSCustomObject]@{
    Severite  = 'WARN'
    Categorie = 'Authentification'
    Constat   = "NTLMMinClientSec = $NmClient"
    Detail = 'NTLMv2 est activé, mais la valeur est inférieure à la recommandation NTLMv2 + chiffrement 128 bits. Valeur 536870912 compatible W10 mais pas optimale.'
    Correction= 'Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0 -Name NtlmMinClientSec -Value 537395200 -Type DWord -Force'
    }
    }

    $NmServer = Get-RegValue $RegPaths.MSV1_0 'NTLMMinServerSec'
    if ($NmServer -ne 'NON DEFINI' -and [int]$NmServer -lt 537395200) {
    $Findings += [PSCustomObject]@{
    Severite  = 'WARN'
    Categorie = 'Authentification'
    Constat   = "NTLMMinServerSec = $NmServer"
    Detail = 'NTLMv2 est activé, mais la valeur est inférieure à la recommandation NTLMv2 + chiffrement 128 bits. Valeur 536870912 compatible W10 mais pas optimale.'
    Correction= 'Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0 -Name NtlmMinServerSec -Value 537395200 -Type DWord -Force'
    }
    }

    $SMBBlockRules = @(
    'Bloquer SMB entrant 445',
    'Bloquer SMB entrant 139',
    'Bloquer NetBIOS entrant',
    'Bloquer SMB sortant 445',
    'Bloquer SMB sortant 139'
    )

    if ($SMBShareAuditStatus -in @("Pas d'audit", "No auditing")) {
    $Findings += [PSCustomObject]@{
    Severite  = 'WARN'
    Categorie = 'Audit SMB'
    Constat   = 'Audit des partages de fichiers non activé'
    Detail    = 'Sans audit SMB actif, les événements 5140/5142/5143/5144 ne sont pas collectés.'
    Correction= 'auditpol /set /subcategory:"Partage de fichiers" /success:enable /failure:enable'
    }
    }
    # AUCUN PROBLEME
    if ($Findings.Count -eq 0) {
    $Findings += [PSCustomObject]@{ Severite='OK'; Categorie='General'; Constat='Aucun probleme critique detecte'; Detail='Configuration correcte pour le partage de fichiers en reseau local.'; Correction='N/A' }
    }

    $CriticalCount = ($Findings | Where-Object { $_.Severite -eq 'CRITICAL' }).Count
    $WarnCount     = ($Findings | Where-Object { $_.Severite -eq 'WARN' }).Count
    $OKCount       = ($Findings | Where-Object { $_.Severite -eq 'OK' }).Count
    $Score         = [Math]::Max(0, 100 - ($CriticalCount*20) - ($WarnCount*5))
    $ScoreStatus   = if ($Score -ge 80) { 'Sain' } elseif ($Score -ge 50) { 'Degrade' } else { 'Critique' }
    $ScoreColor    = if ($Score -ge 80) { '#22c55e' } elseif ($Score -ge 50) { '#f59e0b' } else { '#ef4444' }
    $ScriptEndTime = Get-Date
    $ScriptDuration= (New-TimeSpan -Start $ScriptStartTime -End $ScriptEndTime).TotalSeconds
    $ConnOK        = if ($ConnTests) { ($ConnTests | Where-Object { $_.Resultat -eq 'OK' }).Count } else { 0 }
    $ConnTotal     = if ($ConnTests) { @($ConnTests).Count } else { 0 }

    Write-Step "Generation du rapport HTML..."

    # ─────────────────────────────────────────────────────────────────────────────
    # REGION: GENERATION HTML
    # ─────────────────────────────────────────────────────────────────────────────

    function Build-Table {
    param([string]$ID, [array]$Data, [string[]]$Columns, [string]$RiskColumn = 'Risque')
    if (-not $Data -or $Data.Count -eq 0) { return "<p class='no-data'>Aucune donnee disponible</p>" }
    $h  = "<div class='table-wrap'><div class='table-toolbar'>"
    $h += "<input type='text' class='search-input' placeholder='Filtrer...' oninput='filterTable(this, &quot;$ID&quot;)'>"
    $h += "<button class='export-btn' onclick='exportCSV(&quot;$ID&quot;)'>CSV</button><button class='export-btn' onclick='exportTXT(&quot;$ID&quot;)'>TXT</button></div>"
    $h += "<table id='$ID' class='data-table'><thead><tr>"
    foreach ($Col in $Columns) { $h += "<th onclick='sortTable(this, &quot;$ID&quot;)'>$Col <span class='sort-arrow'>⇅</span></th>" }
    $h += "</tr></thead><tbody>"
    foreach ($Row in $Data) {
    $rClass = ''
    if ($Row.PSObject.Properties[$RiskColumn]) {
    $rClass = switch ($Row.$RiskColumn) { 'CRITICAL'{'row-critical'} 'WARN'{'row-warn'} 'OK'{'row-ok'} default{''} }
    }
    $h += "<tr class='$rClass'>"
    foreach ($Col in $Columns) {
    $val  = if ($Row.PSObject.Properties[$Col]) { "$($Row.$Col)" } else { '' }
    $cell = if ($Col -eq $RiskColumn -or $Col -eq 'Severite') { Get-StatusBadge $val } else { HtmlEncode $val }
    $h += "<td>$cell</td>"
    }
    $h += "</tr>"
    }
    $h += "</tbody></table></div>"
    return $h
    }

    function Build-Section {
    param([string]$ID, [string]$Title, [string]$Icon, [string]$Content, [string]$BadgeCount = '')
    $badge = if ($BadgeCount) { "<span class='section-badge'>$BadgeCount</span>" } else { '' }
    return @"
    <section class="section" id="sec-$ID">
    <div class="section-header" onclick="toggleSection('$ID')">
    <span class="section-icon">$Icon</span>
    <span class="section-title">$Title</span>
    $badge
    <span class="section-toggle" id="tog-$ID">▼</span>
    </div>
    <div class="section-body" id="body-$ID">$Content</div>
    </section>
"@
    }

    $ReportDate  = $ScriptStartTime.ToString("yyyy-MM-dd HH:mm:ss")
    $ModeDisplay = $Mode
    $SafeHost    = $env:COMPUTERNAME -replace '[^A-Za-z0-9\.-]','_'
    $SafeUser    = ($env:USERNAME -replace '[^A-Za-z0-9\.-]','_')
    $BaseName    = "PC-$SafeHost-$SafeUser-report"
    $Timestamp   = $ScriptStartTime.ToString("yyyyMMdd_HH'h'mm'm'ss's'")
    $FileName    = "$BaseName-$Timestamp.html"
    $OutputFile  = Join-Path $OutputPath $FileName

    $SMBSrvHTML  = "<h4>Configuration Serveur SMB</h4>" + (Build-Table -ID 'tbl-smb-srv' -Data $SMBServerItems -Columns @('Parametre','Valeur','Risque','Note'))
    $SMBCliHTML  = "<h4>Configuration Client SMB</h4>"  + (Build-Table -ID 'tbl-smb-cli' -Data $SMBClientItems -Columns @('Parametre','Valeur','Risque','Note'))
    $SMBShrHTML  = "<h4>Partages</h4>"                  + (Build-Table -ID 'tbl-shares'  -Data $SMBShares      -Columns @('Nom','Chemin','Type','Description','Permissions','ABE','Cache_HS','MaxUtilisateurs','Disponibilite'))
    $SMBShrHTML2 = "<h4>Partages SMB</h4>" + 
    (Build-Table -ID 'tbl-shares' -Data $Shares -Columns @('Nom','Chemin','Acces','Dossiers','Risque') -RiskColumn 'Risque')
    $SMBSesHTML  = "<h4>Sessions actives</h4>"           + (Build-Table -ID 'tbl-sessions'-Data $SMBSessions    -Columns @('Client','Utilisateur','Dialecte','Signe','Chiffre','Duree_s'))
    $SMBConHTML  = "<h4>Connexions actives</h4>"         + (Build-Table -ID 'tbl-conn'    -Data $SMBConnections -Columns @('Serveur','Partage','Utilisateur','Dialecte','Signe','Chiffre'))

    $RemoteSMBHTML = "<h4>Partages SMB distants / par interface</h4>" + (Build-Table -ID 'tbl-remote-smb' -Data $RemoteSMBShares -Columns @('Source','Type','Serveur','Partage','Interface','LocalIP','Cible','Utilisateur'))

    $HistHTML    = "<h4>Evenements acces partage (7 derniers jours - IDs 5140/5142/5143/5144)</h4>" + (Build-Table -ID 'tbl-hist'    -Data $ConnHistory    -Columns @('Horodatage','EventID','TypeEvenemt','Partage','IPSource','Compte'))
    $NetUseHTML  = "<h4>Connexions actives (net use)</h4>" + (if ($NetUseEntries.Count -gt 0) { Build-Table -ID 'tbl-netuse' -Data $NetUseEntries -Columns @('Statut','Local','Distant') } else { "<p class='no-data'>Aucune connexion net use active</p>" })
    $PersHTML    = "<h4>Lecteurs persistants (HKCU:\Network)</h4>" + (if ($PersistentDrives.Count -gt 0) { Build-Table -ID 'tbl-persist' -Data $PersistentDrives -Columns @('Lecteur','Cible','Fournisseur','Utilisateur') } else { "<p class='no-data'>Aucun lecteur persistant enregistre</p>" })

    $HTML = @"
    <!DOCTYPE html>
    <html lang="fr">
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Diagnostic Reseau - $($Identity.Hostname) - $ReportDate</title>
    <style>
    :root{--bg:#0d1117;--surface:#161b22;--surface2:#21262d;--border:#30363d;--text:#e6edf3;--muted:#8b949e;--accent:#58a6ff;--ok:#22c55e;--warn:#f59e0b;--critical:#ef4444;--info:#3b82f6;--radius:8px;--font:'Consolas','Cascadia Code','Fira Code',monospace}
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    body{background:var(--bg);color:var(--text);font-family:var(--font);font-size:13px;line-height:1.6}
    body.light{--bg:#f0f4f8;--surface:#fff;--surface2:#e8ecf0;--border:#d0d7de;--text:#1f2328;--muted:#636c76}
    .topbar{background:var(--surface);border-bottom:1px solid var(--border);padding:12px 24px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100}
    .topbar-left{display:flex;align-items:center;gap:12px}
    .topbar-title{font-size:15px;font-weight:700;color:var(--accent)}
    .mode-badge{padding:2px 10px;border-radius:99px;font-size:11px;font-weight:700;text-transform:uppercase}
    .mode-complet{background:rgba(239,68,68,.15);color:#ef4444;border:1px solid rgba(239,68,68,.3)}
    .mode-public{background:rgba(88,166,255,.15);color:#58a6ff;border:1px solid rgba(88,166,255,.3)}
    .topbar-right{display:flex;gap:8px}
    .topbar-btn{background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:5px 12px;border-radius:var(--radius);cursor:pointer;font-family:var(--font);font-size:12px;transition:all .2s}
    .topbar-btn:hover{border-color:var(--accent);color:var(--accent)}
    .nav{background:var(--surface);border-bottom:1px solid var(--border);padding:0 24px;display:flex;gap:4px;overflow-x:auto;position:sticky;top:45px;z-index:99}
    .nav-tab{padding:8px 14px;cursor:pointer;border-bottom:2px solid transparent;color:var(--muted);font-size:12px;white-space:nowrap;transition:all .2s}
    .nav-tab:hover,.nav-tab.active{color:var(--accent);border-bottom-color:var(--accent)}
    .main{max-width:1400px;margin:0 auto;padding:20px 24px}
    .dashboard{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:24px}
    .dash-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:14px 16px}
    .dash-card-icon{font-size:22px;margin-bottom:6px}
    .dash-card-label{font-size:10px;text-transform:uppercase;letter-spacing:1px;color:var(--muted);margin-bottom:4px}
    .dash-card-value{font-size:14px;font-weight:700;color:var(--text)}
    .dash-card-sub{font-size:11px;color:var(--muted);margin-top:2px}
    .score-bar-wrap{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px 20px;margin-bottom:24px}
    .score-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:10px}
    .score-title{font-size:13px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:1px}
    .score-value{font-size:28px;font-weight:800}
    .score-bar-bg{background:var(--surface2);border-radius:99px;height:10px;overflow:hidden}
    .score-bar-fill{height:100%;border-radius:99px;transition:width 1s ease}
    .score-label{font-size:11px;color:var(--muted);margin-top:6px}
    .findings-summary{display:flex;gap:16px;margin-top:12px}
    .finding-chip{padding:4px 12px;border-radius:99px;font-size:12px;font-weight:600}
    .chip-critical{background:rgba(239,68,68,.15);color:#ef4444}
    .chip-warn{background:rgba(245,158,11,.15);color:#f59e0b}
    .chip-ok{background:rgba(34,197,94,.15);color:#22c55e}
    .filter-bar{display:flex;gap:8px;margin-bottom:20px;flex-wrap:wrap}
    .filter-btn{background:var(--surface);border:1px solid var(--border);color:var(--muted);padding:5px 14px;border-radius:99px;cursor:pointer;font-family:var(--font);font-size:12px;transition:all .2s}
    .filter-btn:hover,.filter-btn.active{border-color:var(--accent);color:var(--accent)}
    .filter-btn.f-critical.active{border-color:var(--critical);color:var(--critical)}
    .filter-btn.f-warn.active{border-color:var(--warn);color:var(--warn)}
    .filter-btn.f-ok.active{border-color:var(--ok);color:var(--ok)}
    .section{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);margin-bottom:12px;overflow:hidden}
    .section-header{display:flex;align-items:center;gap:10px;padding:12px 16px;cursor:pointer;user-select:none;transition:background .2s}
    .section-header:hover{background:var(--surface2)}
    .section-icon{font-size:16px}
    .section-title{font-size:13px;font-weight:600;flex:1}
    .section-badge{background:var(--surface2);border:1px solid var(--border);padding:1px 8px;border-radius:99px;font-size:11px;color:var(--muted)}
    .section-toggle{font-size:11px;color:var(--muted);transition:transform .3s}
    .section-toggle.collapsed{transform:rotate(-90deg)}
    .section-body{padding:16px;border-top:1px solid var(--border)}
    .section-body.hidden{display:none}
    h4{font-size:12px;text-transform:uppercase;letter-spacing:1px;color:var(--muted);margin:16px 0 8px}
    h4:first-child{margin-top:0}
    .table-wrap{overflow-x:auto;margin-bottom:12px}
    .table-toolbar{display:flex;gap:8px;margin-bottom:8px;align-items:center}
    .search-input{background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:5px 10px;border-radius:var(--radius);font-family:var(--font);font-size:12px;flex:1;outline:none}
    .search-input:focus{border-color:var(--accent)}
    .export-btn{background:var(--surface2);border:1px solid var(--border);color:var(--muted);padding:5px 12px;border-radius:var(--radius);cursor:pointer;font-family:var(--font);font-size:12px;white-space:nowrap;transition:all .2s}
    .export-btn:hover{border-color:var(--accent);color:var(--accent)}
    .data-table{width:100%;border-collapse:collapse;font-size:12px}
    .data-table th{background:var(--surface2);padding:8px 12px;text-align:left;font-weight:600;border-bottom:1px solid var(--border);cursor:pointer;white-space:nowrap;user-select:none;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.5px}
    .data-table th:hover{color:var(--accent)}
    .data-table td{padding:7px 12px;border-bottom:1px solid var(--border);vertical-align:top;word-break:break-all}
    .data-table tr:last-child td{border-bottom:none}
    .data-table tr:hover td{background:rgba(88,166,255,.04)}
    .row-critical td{border-left:3px solid var(--critical)}
    .row-warn td{border-left:3px solid var(--warn)}
    .row-ok td{border-left:3px solid var(--ok)}
    .sort-arrow{font-size:10px;opacity:.5}
    .badge{padding:2px 8px;border-radius:99px;font-size:11px;font-weight:600;display:inline-block}
    .badge.ok{background:rgba(34,197,94,.15);color:#22c55e}
    .badge.warn{background:rgba(245,158,11,.15);color:#f59e0b}
    .badge.critical{background:rgba(239,68,68,.15);color:#ef4444}
    .badge.info{background:rgba(59,130,246,.15);color:#3b82f6}
    .no-data{color:var(--muted);font-size:12px;padding:12px 0}
    .id-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:8px}
    .id-row{display:flex;gap:8px;background:var(--surface2);padding:8px 12px;border-radius:var(--radius)}
    .id-key{color:var(--muted);font-size:11px;min-width:150px}
    .id-val{color:var(--text);font-size:12px;font-weight:500;word-break:break-all}
    .footer{margin-top:32px;padding:20px 24px;border-top:1px solid var(--border);text-align:center;color:var(--muted);font-size:11px;line-height:2}
    .footer a{color:var(--accent);text-decoration:none}
    @media print{.topbar,.nav,.filter-bar,.table-toolbar,.topbar-btn{display:none!important}.section-body.hidden{display:block!important}body{background:#fff;color:#000}}
    </style>
    </head>
    <body>

    <div class="topbar">
    <div class="topbar-left">
    <span class="topbar-title">🔍 Diagnostic Reseau &amp; Partages SMB</span>
    <span class="mode-badge mode-$(if($Mode -eq 'COMPLET'){'complet'}else{'public'})">Mode $ModeDisplay</span>
    </div>
    <div class="topbar-right">
    <button class="topbar-btn" onclick="exportAllTXT()">⬇ TXT global</button>
    <button class="topbar-btn" onclick="exportAllCSV()">⬇ CSV global</button>
    <button class="topbar-btn" onclick="expandAll()">⊞ Tout deplier</button>
    <button class="topbar-btn" onclick="collapseAll()">⊟ Tout replier</button>
    <button class="topbar-btn" onclick="toggleTheme()">🌓 Theme</button>
    <button class="topbar-btn" onclick="copyReport()">📋 Copier</button>
    </div>
    </div>

    <div class="nav">
    <div class="nav-tab active" onclick="scrollToSection('sec-dashboard')">📊 Tableau de bord</div>
    <div class="nav-tab" onclick="scrollToSection('sec-identity')">🖥️ Identite</div>
    <div class="nav-tab" onclick="scrollToSection('sec-interfaces')">🌐 Interfaces</div>
    <div class="nav-tab" onclick="scrollToSection('sec-profiles')">📡 Profils</div>
    <div class="nav-tab" onclick="scrollToSection('sec-drives')">🗂️ Lecteurs</div>
    <div class="nav-tab" onclick="scrollToSection('sec-history')">🕐 Historique</div>
    <div class="nav-tab" onclick="scrollToSection('sec-smb')">📁 SMB</div>
    <div class="nav-tab" onclick="scrollToSection('sec-remote-shares')">🌍 Partages distants</div>
    <div class="nav-tab" onclick="scrollToSection('sec-firewall')">🔥 Pare-feu</div>
    <div class="nav-tab" onclick="scrollToSection('sec-auth')">🔐 Auth.</div>
    <div class="nav-tab" onclick="scrollToSection('sec-services')">⚙️ Services</div>
    <div class="nav-tab" onclick="scrollToSection('sec-events')">📋 Evenements</div>
    <div class="nav-tab" onclick="scrollToSection('sec-arp')">🔗 ARP</div>
    <div class="nav-tab" onclick="scrollToSection('sec-hosts')">📝 Hosts</div>
    <div class="nav-tab" onclick="scrollToSection('sec-connectivity')">🧪 Tests</div>
    <div class="nav-tab" onclick="scrollToSection('sec-findings')">⚠️ Recommandations</div>
    </div>

    <div class="main">

    <div class="score-bar-wrap" id="sec-dashboard">
    <div class="score-header">
    <span class="score-title">Score de sante global</span>
    <span class="score-value" style="color:$ScoreColor">$Score / 100 — $ScoreStatus</span>
    </div>
    <div class="score-bar-bg"><div class="score-bar-fill" id="scoreFill" style="width:0%;background:$ScoreColor" data-target="$Score"></div></div>
    <div class="findings-summary">
    <span class="finding-chip chip-critical">❌ Critiques : $CriticalCount</span>
    <span class="finding-chip chip-warn">⚠️ Avertissements : $WarnCount</span>
    <span class="finding-chip chip-ok">✅ OK : $OKCount</span>
    </div>
    <div class="score-label">Duree du scan : $($ScriptDuration.ToString('0.0'))s — Genere le : $ReportDate — Hote : $($Identity.Hostname) — PS : $($Identity.PSVersion)</div>
    </div>

    <div class="dashboard">
    <div class="dash-card"><div class="dash-card-icon">🖥️</div><div class="dash-card-label">Machine</div><div class="dash-card-value">$($Identity.Hostname)</div><div class="dash-card-sub">$($Identity.OS.Replace('Microsoft ',''))</div><div class="dash-card-sub">Build $($Identity.Build) | Uptime : $($Identity.Uptime)</div></div>
    <div class="dash-card"><div class="dash-card-icon">🌐</div><div class="dash-card-label">Reseau</div><div class="dash-card-value">$(@($NetInterfaces).Count) interface(s) active(s)</div><div class="dash-card-sub">$(($NetProfiles | ForEach-Object { $_.Profil } | Select-Object -Unique) -join ' / ')</div></div>
    <div class="dash-card"><div class="dash-card-icon">📁</div><div class="dash-card-label">SMB</div><div class="dash-card-value">v1 : $(if($SMBv1Server){'⚠️ ACTIVE'}else{'✅ Desactive'}) | v2 : $(if($SMBv2Server){'✅ Active'}else{'❌ Desactive'})</div><div class="dash-card-sub">Signature : $(if($SMBServerConfig -and $SMBServerConfig.EnableSecuritySignature){'Activee'}else{'⚠️ Desactivee'})</div></div>
    <div class="dash-card"><div class="dash-card-icon">🗂️</div><div class="dash-card-label">Partages</div><div class="dash-card-value">$(@($SMBShares).Count) partage(s) SMB</div><div class="dash-card-sub">$(@($MappedDrives).Count) lecteur(s) mappe(s)</div></div>
    <div class="dash-card"><div class="dash-card-icon">🔥</div><div class="dash-card-label">Pare-feu</div><div class="dash-card-value">$(($FWProfiles | Where-Object {$_.Active}).Count)/$(@($FWProfiles).Count) profils actifs</div><div class="dash-card-sub">$(@($FWRules).Count) regles SMB actives</div></div>
    <div class="dash-card"><div class="dash-card-icon">🔐</div><div class="dash-card-label">Authentification</div><div class="dash-card-value">LmLevel : $LmLevel</div><div class="dash-card-sub">LATFP : $LATFP</div></div>
    <div class="dash-card"><div class="dash-card-icon">🧪</div><div class="dash-card-label">Connectivite</div><div class="dash-card-value">$ConnOK / $ConnTotal joignable(s)</div><div class="dash-card-sub">Port 445 ouvert : $(($ConnTests | Where-Object {$_.Port445 -eq 'OUVERT'}).Count) / $ConnTotal</div></div>
    <div class="dash-card"><div class="dash-card-icon">👤</div><div class="dash-card-label">Contexte</div><div class="dash-card-value">$(if($IsAdmin){'✅ Administrateur'}else{'⚠️ Non admin'})</div><div class="dash-card-sub">$($Identity.Utilisateur)</div></div>
    </div>

    <div class="filter-bar">
    <span style="color:var(--muted);font-size:12px;padding:5px 4px">Filtrer :</span>
    <button class="filter-btn active" onclick="document.querySelectorAll('.data-table tbody tr').forEach(r => r.style.display='');">Tout afficher</button>
    <button class="filter-btn f-critical" onclick="filterSections('critical',this)">❌ Critiques</button>
    <button class="filter-btn f-warn" onclick="filterSections('warn',this)">⚠️ Avertissements</button>
    <button class="filter-btn f-ok" onclick="filterSections('ok',this)">✅ OK</button>
    </div>

    $(Build-Section 'identity' "Identite de la machine" '🖥️' @"
    <div class='id-grid'>
    <div class='id-row'><span class='id-key'>Nom d'hote</span><span class='id-val'>$($Identity.Hostname)</span></div>
    <div class='id-row'><span class='id-key'>Domaine / Workgroup</span><span class='id-val'>$($Identity.Domaine)</span></div>
    <div class='id-row'><span class='id-key'>Systeme d'exploitation</span><span class='id-val'>$($Identity.OS)</span></div>
    <div class='id-row'><span class='id-key'>Build</span><span class='id-val'>$($Identity.Build) — $($Identity.Version)</span></div>
    <div class='id-row'><span class='id-key'>Architecture</span><span class='id-val'>$($Identity.Architecture)</span></div>
    <div class='id-row'><span class='id-key'>Dernier demarrage</span><span class='id-val'>$($Identity.DernierBoot)</span></div>
    <div class='id-row'><span class='id-key'>Uptime</span><span class='id-val'>$($Identity.Uptime)</span></div>
    <div class='id-row'><span class='id-key'>Utilisateur courant</span><span class='id-val'>$($Identity.Utilisateur)</span></div>
    <div class='id-row'><span class='id-key'>SID</span><span class='id-val'>$($Identity.SID)</span></div>
    <div class='id-row'><span class='id-key'>Droits administrateur</span><span class='id-val'>$(if($Identity.EstAdmin){'✅ Oui'}else{'⚠️ Non (donnees limitees)'})</span></div>
    <div class='id-row'><span class='id-key'>PowerShell</span><span class='id-val'>$($Identity.PSVersion) ($($Identity.PSEdition))</span></div>
    </div>
"@)

    $(Build-Section 'interfaces' 'Interfaces reseau' '🌐' (Build-Table -ID 'tbl-ifaces' -Data $NetInterfaces -Columns @('Nom','IP','Masque','Passerelle','DNS','MAC','DHCP','MTU','Vitesse','Type','Statut')))

    $(Build-Section 'profiles' 'Profils reseau' '📡' (Build-Table -ID 'tbl-profiles' -Data $NetProfiles -Columns @('Interface','Nom','Profil','IPv4','IPv6','Risque')))

    $(Build-Section 'drives' 'Lecteurs mappes et historique MRU' '🗂️' @"
    <h4>Lecteurs mappes actifs</h4>
    $(if ($MappedDrives) { Build-Table -ID 'tbl-drives' -Data $MappedDrives -Columns @('Lecteur','Cible','Utilise','Libre') } else { "<p class='no-data'>Aucun lecteur reseau mappe actif</p>" })
    <h4>Registre MRU (connexions passees)</h4>
    $(if ($MRUEntries) { Build-Table -ID 'tbl-mru' -Data $MRUEntries -Columns @('Source','Cle','Valeur') } else { "<p class='no-data'>Aucune entree MRU </p>" })
"@)

    $(Build-Section 'history' 'Historique des connexions reseau' '🕐' ($HistHTML + $NetUseHTML + $PersHTML) "$(@($ConnHistory).Count) evenement(s)")

    $(Build-Section 'smb' 'Configuration SMB' '📁' ($SMBSrvHTML + $SMBCliHTML + $SMBShrHTML + $SMBSesHTML + $SMBConHTML) "$(@($Shares).Count) partage(s)")

    $(Build-Section 'shares' 'Partages SMB' '📂' ($SMBShrHTML2) "$(@($Shares).Count) partage(s)")
    $(Build-Section 'remote-shares' 'Partages SMB distants' '🌍' ($RemoteSMBHTML) "$(@($RemoteSMBShares).Count) partage(s) distants")
    $(Build-Section 'firewall' 'Pare-feu Windows' '🔥' @"
    <h4>Profils</h4>
    $(Build-Table -ID 'tbl-fw-profiles' -Data $FWProfiles -Columns @('Profil','Active','EntreeDefaut','SortieDefaut','LogAutorise','LogBloque','Risque'))
    <h4>Regles actives (SMB / Partage)</h4>
    $(Build-Table -ID 'tbl-fw-rules' -Data $FWRules -Columns @('Nom','Direction','Action','Profil','Protocole','Port','Active','Risque'))
"@)

    $(Build-Section 'auth' 'Authentification et politique de securite' '🔐' @"
    <h4>Politique d'authentification (registre)</h4>
    $(Build-Table -ID 'tbl-auth' -Data $AuthPolicy -Columns @('Cle','Valeur','Recommande','Risque','Note'))
    <h4>Comptes locaux</h4>
    $(Build-Table -ID 'tbl-accounts' -Data $LocalAccounts -Columns @('Nom','Active','DernConnexion','MdpRequis','MdpExpire','SID','Risque'))
    <h4>Gestionnaire d'informations d'identification</h4>
    $(if ($CredEntries) { Build-Table -ID 'tbl-cred' -Data $CredEntries -Columns @('Cible','Type') } else { "<p class='no-data'>Aucune entree dans le gestionnaire de credentials</p>" })
"@)

    $(Build-Section 'services' 'Services et protocoles de decouverte' '⚙️' @"
    <h4>Services critiques</h4>
    $(Build-Table -ID 'tbl-services' -Data $ServicesData -Columns @('Nom','Libelle','Statut','Demarrage','Risque'))
    <h4>Protocoles de decouverte reseau</h4>
    $(Build-Table -ID 'tbl-discovery' -Data $DiscoveryItems -Columns @('Protocole','Etat','Risque','Note'))
"@)

    $(Build-Section 'events' "Journal d'evenements - 24 dernieres heures (Auth/Partage)" '📋' (Build-Table -ID 'tbl-events' -Data $EventLogs -Columns @('Horodatage','Journal','EventID','Niveau','Categorie','Source','Message')) "$(@($EventLogs).Count) evenement(s)")

    $(Build-Section 'arp' 'Table ARP' '🔗' (Build-Table -ID 'tbl-arp' -Data $ArpEntries -Columns @('IP','MAC','Type')) "$(@($ArpEntries).Count) entree(s)")

    $(Build-Section 'hosts' 'Fichier Hosts' '📝' (Build-Table -ID 'tbl-hosts' -Data $HostsEntries -Columns @('IP','Hostname','Note')))

    $(Build-Section 'connectivity' 'Tests de connectivite' '🧪' (Build-Table -ID 'tbl-conn-tests' -Data @(if ($ConnTests) { $ConnTests } else { @() }) -Columns @('Cible','Ping','Port445','UNC_IPC','Resultat') -RiskColumn 'Resultat'))

    $(Build-Section 'findings' 'Constats et Recommandations' '⚠️' (Build-Table -ID 'tbl-findings' -Data $Findings -Columns @('Severite','Categorie','Constat','Detail','Correction') -RiskColumn 'Severite') "$CriticalCount critique(s) / $WarnCount avertissement(s)")

    </div>

    <div class="footer">
    <strong>NetworkShareDiagnostic v1.1.0</strong> par
    <a href="https://github.com/ps81frt/NetworkShareDiagnostic" target="_blank">ps81frt</a> —
    Licence MIT<br>
    Genere le $ReportDate — Hote : $($Identity.Hostname) — Mode : $ModeDisplay — PS : $($Identity.PSVersion)<br>
    Scan en lecture seule. Aucune modification systeme effectuee.
    </div>
    <script>
    function toggleTheme(){document.body.classList.toggle('light');localStorage.setItem('theme',document.body.classList.contains('light')?'light':'dark')}
    if(localStorage.getItem('theme')==='light')document.body.classList.add('light');
    function toggleSection(id){var b=document.getElementById('body-'+id),t=document.getElementById('tog-'+id);b.classList.toggle('hidden');t.classList.toggle('collapsed')}
    function expandAll(){document.querySelectorAll('.section-body').forEach(b=>b.classList.remove('hidden'));document.querySelectorAll('.section-toggle').forEach(t=>t.classList.remove('collapsed'))}
    function collapseAll(){document.querySelectorAll('.section-body').forEach(b=>b.classList.add('hidden'));document.querySelectorAll('.section-toggle').forEach(t=>t.classList.add('collapsed'))}
    function scrollToSection(id){var el=document.getElementById(id);if(el)el.scrollIntoView({behavior:'smooth',block:'start'});document.querySelectorAll('.nav-tab').forEach(t=>t.classList.remove('active'));event.target.classList.add('active')}
    function sortTable(th,tableId){var table=document.getElementById(tableId),col=Array.from(th.parentNode.children).indexOf(th),rows=Array.from(table.querySelectorAll('tbody tr')),asc=th.dataset.sort!=='asc';rows.sort(function(a,b){var A=(a.cells[col]?a.cells[col].textContent:'').trim(),B=(b.cells[col]?b.cells[col].textContent:'').trim();return asc?A.localeCompare(B,'fr',{numeric:true}):B.localeCompare(A,'fr',{numeric:true})});th.dataset.sort=asc?'asc':'desc';var tbody=table.querySelector('tbody');rows.forEach(r=>tbody.appendChild(r))}
    function filterTable(input,tableId){var filter=input.value.toLowerCase(),rows=document.getElementById(tableId).querySelectorAll('tbody tr');rows.forEach(function(row){row.style.display=row.textContent.toLowerCase().includes(filter)?'':'none'})}
    function globalSearch(val){var filter=val.toLowerCase();document.querySelectorAll('.data-table tbody tr').forEach(function(row){row.style.display=(!filter||row.textContent.toLowerCase().includes(filter))?'':'none'});if(filter)expandAll()}
    function getExportText(cell){var clone=cell.cloneNode(true);var arrow=clone.querySelector('.sort-arrow');if(arrow)arrow.remove();var text=clone.textContent.trim();text=text.replace(/✅/g,'').replace(/⚠️/g,'').replace(/❌/g,'').replace(/ℹ️/g,'').replace(/\s{2,}/g,' ').trim();return text}
    function formatDateTime(){var d=new Date();return d.getFullYear().toString()+('0'+(d.getMonth()+1)).slice(-2)+('0'+d.getDate()).slice(-2)+'_'+d.getHours()+'h'+d.getMinutes()+'m'+d.getSeconds()+'s'}
    function exportCSV(tableId){var table=document.getElementById(tableId);if(!table)return;var rows=table.querySelectorAll('tr'),csv=[];rows.forEach(function(row){var cells=Array.from(row.querySelectorAll('th,td'));csv.push(cells.map(function(c){return '"'+getExportText(c).replace(/"/g,'""')+'"'}).join(','))});var blob=new Blob(['\uFEFF'+csv.join('\n')],{type:'text/csv;charset=utf-8'});var a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=tableId+'_'+formatDateTime()+'.csv';a.click()}
    function exportTXT(tableId){var table=document.getElementById(tableId);if(!table)return;var headers=Array.from(table.querySelectorAll('thead th')).map(function(th){return getExportText(th)});var rows=Array.from(table.querySelectorAll('tbody tr')).filter(function(row){return row.style.display!=='none'});var lines=[];rows.forEach(function(row,index){var cells=Array.from(row.querySelectorAll('th,td')).map(function(cell){return getExportText(cell)});var title=cells[0]||('Ligne '+(index+1));var separator='======= '+title+' =======';lines.push(separator);headers.forEach(function(h,i){lines.push(h+': '+(cells[i]||''))});lines.push('')} );if(lines.length>0){lines.pop()}else{lines.push('Aucune donnee disponible')}var blob=new Blob([lines.join('\r\n')],{type:'text/plain;charset=utf-8'});var a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=tableId+'_'+formatDateTime()+'.txt';a.click()}
    function exportAllTXT(){var baseName='$BaseName';var l=[],d=new Date(),dt=d.getFullYear().toString()+('0'+(d.getMonth()+1)).slice(-2)+('0'+d.getDate()).slice(-2)+'_'+d.getHours()+'h'+d.getMinutes()+'m'+d.getSeconds()+'s';document.querySelectorAll('.data-table').forEach(function(t){var ti=(t.closest('.section')&&t.closest('.section').querySelector('.section-title')?t.closest('.section').querySelector('.section-title').textContent.trim():t.id||'report');l.push('======= '+ti+' =======');var he=Array.from(t.querySelectorAll('thead th')).map(function(th){return getExportText(th)});Array.from(t.querySelectorAll('tbody tr')).filter(function(r){return r.style.display!=='none'}).forEach(function(r){var c=Array.from(r.querySelectorAll('th,td')).map(function(cell){return getExportText(cell)}),rl=[];he.forEach(function(h,i){if(c[i])rl.push(h+': '+c[i])});if(rl.length){l.push(rl.join('\r\n'));l.push('')}});l.push('')});if(l.length===0)l.push('Aucune donnee disponible');var b=new Blob([l.join('\r\n')],{type:'text/plain;charset=utf-8'}),a=document.createElement('a');a.href=URL.createObjectURL(b);a.download=baseName+'-all-'+dt+'.txt';a.click()}
    function exportAllCSV(){var baseName='$BaseName';var SEP=';',rows=[],now=new Date(),total=0,esc=function(v){return'"'+(v===undefined||v===null?'':String(v).replace(/"/g,'""'))+'"'},fmtDate=function(d){return d.toLocaleDateString('fr-FR')+' '+d.toLocaleTimeString('fr-FR')},fmtFile=function(d){return d.getFullYear()+'-'+(d.getMonth()+1)+'-'+d.getDate()+'_'+d.getHours()+'h'+d.getMinutes()+'m'+d.getSeconds()+'s'};document.querySelectorAll('.data-table').forEach(function(t){total+=t.querySelectorAll('tbody tr:not([style*="display: none"])').length});rows.push(['Rapport','Export complet',fmtDate(now),total+' ligne(s)'].join(SEP));document.querySelectorAll('.data-table').forEach(function(t,i){var title=(t.closest('.section')&&t.closest('.section').querySelector('.section-title')?t.closest('.section').querySelector('.section-title').textContent.trim():t.id||'sans_titre')||'section';var headers=Array.from(t.querySelectorAll('thead th')).map(function(th){return esc(th.textContent.trim())});rows.push(esc('['+(i+1)+'] '+title));if(headers.length)rows.push(headers.join(SEP));Array.from(t.querySelectorAll('tbody tr')).filter(function(r){return r.style.display!=='none'}).forEach(function(tr){var cells=Array.from(tr.querySelectorAll('td')).map(function(td){return esc(td.textContent.trim())});rows.push(cells.join(SEP))});if(i<document.querySelectorAll('.data-table').length-1)rows.push('')});if(rows.length===2)rows.push(esc('Aucune donnée'));var blob=new Blob(['\uFEFF'+rows.join('\n')],{type:'text/csv;charset=utf-8'});var a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=baseName+'-all-'+fmtFile(now)+'.csv';a.click()}
    function filterSections(level,btn){document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));btn.classList.add('active');if(level==='all'){expandAll();return}document.querySelectorAll('.data-table tbody tr').forEach(function(row){var show=false;if(level==='critical'&&row.classList.contains('row-critical'))show=true;if(level==='warn'&&row.classList.contains('row-warn'))show=true;if(level==='ok'&&row.classList.contains('row-ok'))show=true;row.style.display=show?'':'none'});expandAll()}
    function copyReport(){navigator.clipboard.writeText(document.body.innerText).then(function(){alert('Texte du rapport copie dans le presse-papiers.')})}
    window.addEventListener('load',function(){var f=document.getElementById('scoreFill');if(f){var t=f.dataset.target;setTimeout(function(){f.style.width=t+'%'},150)}});
    </script>
    </body>
    </html>
"@

    $ReportSections = @(
    [PSCustomObject]@{ Title='Identite'; Data=@($Identity); Columns=@('Hostname','Domaine','OS','Build','Version','Architecture','Uptime','DernierBoot','Utilisateur','SID','EstAdmin','PSVersion','PSEdition') },
    [PSCustomObject]@{ Title='Interfaces reseau'; Data=$NetInterfaces; Columns=@('Nom','IP','Masque','Passerelle','DNS','MAC','DHCP','MTU','Vitesse','Type','Statut') },
    [PSCustomObject]@{ Title='Profils reseau'; Data=$NetProfiles; Columns=@('Interface','Nom','Profil','IPv4','IPv6','Risque') },
    [PSCustomObject]@{ Title='Lecteurs mappes'; Data=$MappedDrives; Columns=@('Lecteur','Cible','Utilise','Libre') },
    [PSCustomObject]@{ Title='Lecteurs persistants'; Data=$PersistentDrives; Columns=@('Lecteur','Cible','Fournisseur','Utilisateur','Source') },
    [PSCustomObject]@{ Title='Partages SMB (etendus)'; Data=$SMBShares; Columns=@('Nom','Chemin','Description','Type','Permissions','ABE','Cache_HS','MaxUtilisateurs','Disponibilite') },
    [PSCustomObject]@{ Title='Sessions SMB actives'; Data=$SMBSessions; Columns=@('Client','Utilisateur','Dialecte','Signe','Chiffre','Duree_s') },
    [PSCustomObject]@{ Title='Connexions SMB actives'; Data=$SMBConnections; Columns=@('Serveur','Partage','Utilisateur','Dialecte','Signe','Chiffre') },
    [PSCustomObject]@{ Title='Partages SMB distants'; Data=$RemoteSMBShares; Columns=@('Source','Type','Serveur','Partage','Interface','LocalIP','Cible','Utilisateur') },
    [PSCustomObject]@{ Title='Historique connectivite'; Data=$ConnHistory; Columns=@('Horodatage','EventID','TypeEvenemt','Partage','IPSource','Compte') },
    [PSCustomObject]@{ Title='Connexions net use'; Data=$NetUseEntries; Columns=@('Statut','Local','Distant') },
    [PSCustomObject]@{ Title='Services pare-feu'; Data=$FWProfiles; Columns=@('Profil','Active','EntreeDefaut','SortieDefaut','LogAutorise','LogBloque','Risque') },
    [PSCustomObject]@{ Title='Regles firewall'; Data=$FWRules; Columns=@('Nom','Direction','Action','Profil','Protocole','Port','Active','Risque') },
    [PSCustomObject]@{ Title='Politique SMB client'; Data=$SMBClientItems; Columns=@('Parametre','Valeur','Risque','Note') },
    [PSCustomObject]@{ Title='Politique SMB serveur'; Data=$SMBServerItems; Columns=@('Parametre','Valeur','Risque','Note') },
    [PSCustomObject]@{ Title='Authentification'; Data=$AuthPolicy; Columns=@('Cle','Valeur','Recommande','Risque','Note') },
    [PSCustomObject]@{ Title='Comptes locaux'; Data=$LocalAccounts; Columns=@('Nom','Active','DernConnexion','MdpRequis','MdpExpire','SID','Risque') },
    [PSCustomObject]@{ Title='Entrées credentials'; Data=$CredEntries; Columns=@('Cible','Type') },
    [PSCustomObject]@{ Title='Services critiques'; Data=$ServicesData; Columns=@('Nom','Libelle','Statut','Demarrage','Risque') },
    [PSCustomObject]@{ Title='Protocoles de decouverte'; Data=$DiscoveryItems; Columns=@('Protocole','Etat','Risque','Note') },
    [PSCustomObject]@{ Title='Evenements'; Data=$EventLogs; Columns=@('Horodatage','Journal','EventID','Niveau','Categorie','Source','Message') },
    [PSCustomObject]@{ Title='Table ARP'; Data=$ArpEntries; Columns=@('IP','MAC','Type') },
    [PSCustomObject]@{ Title='Hosts'; Data=$HostsEntries; Columns=@('IP','Hostname','Note') },
    [PSCustomObject]@{ Title='Tests connectivite'; Data=$ConnTests; Columns=@('Cible','Ping','Port445','UNC_IPC','Resultat') },
    [PSCustomObject]@{ Title='Constats'; Data=$Findings; Columns=@('Severite','Categorie','Constat','Detail','Correction') }
    )

    function Export-TableText {
    param([string]$Title, [array]$Data, [string[]]$Columns)
    $lines = @()
    $lines += "======= $Title ======="
    foreach ($row in $Data) {
    foreach ($column in $Columns) {
    $value = if ($row.PSObject.Properties[$column]) { $row.$column } else { '' }
    $lines += "${column}: $value"
    }
    $lines += ''
    }
    return $lines
    }

    function Export-ReportAllText {
    $allLines = @()
    $AllTxtFile = Join-Path $OutputPath "$BaseName-all.txt"
    foreach ($section in $ReportSections) {
    $allLines += Export-TableText -Title $section.Title -Data $section.Data -Columns $section.Columns
    $allLines += ''
    }
    [System.IO.File]::WriteAllLines($AllTxtFile, $allLines, [System.Text.Encoding]::UTF8)
    }

    function Export-ReportAllCsv {
    $rows = @('Section,Row,Field,Value')
    $AllCsvFile = Join-Path $OutputPath "$BaseName-all.csv"
    foreach ($section in $ReportSections) {
    $rowIndex = 0
    foreach ($row in $section.Data) {
    $rowIndex++
    foreach ($column in $section.Columns) {
    $value = if ($row.PSObject.Properties[$column]) { $row.$column } else { '' }
    $escaped = '"' + ($section.Title -replace '"','""') + '",' + $rowIndex + ',"' + ($column -replace '"','""') + '","' + ($value -replace '"','""') + '"'
    $rows += $escaped
    }
    }
    }
    [System.IO.File]::WriteAllLines($AllCsvFile, $rows, [System.Text.Encoding]::UTF8)
    }

    # Ensure analyzer recognizes that ReportSections is intentionally used by export helpers
    $null = $ReportSections

    Write-DebugHost "DEBUG: HTML block created"
    Write-DebugHost "DEBUG: HTML length = $($HTML.Length)"
    Write-DebugHost "DEBUG: HTML variable defined? $([bool](Get-Variable HTML -ErrorAction SilentlyContinue))"

    try {
    [System.IO.File]::WriteAllText($OutputFile, $HTML, [System.Text.Encoding]::UTF8)
    } catch {
    Write-Host "[ERREUR] Impossible d'ecrire le rapport : $($_.Exception.Message)" -ForegroundColor Red
    $OutputPath = $env:TEMP
    $OutputFile = Join-Path $OutputPath $FileName

    try {
    [System.IO.File]::WriteAllText($OutputFile, $HTML, [System.Text.Encoding]::UTF8)
    Write-Host "[INFO] Rapport ecrit dans le dossier temporaire : $OutputFile" -ForegroundColor Yellow
    } catch {
    Write-Host "[CRITIQUE] Ecriture impossible meme dans $env:TEMP : $($_.Exception.Message)" -ForegroundColor Red
    exit 1
    }
    }

    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  ✅ Rapport genere avec succes" -ForegroundColor Green
    Write-Host ""
    Write-Host "  📄 Fichier      : $OutputFile" -ForegroundColor White
    Write-Host "  🎯 Mode         : $ModeDisplay" -ForegroundColor $(if($Mode -eq 'COMPLET'){'Red'}else{'Cyan'})
    Write-Host "  ⏱  Duree        : $($ScriptDuration.ToString('0.0'))s" -ForegroundColor Gray
    Write-Host "  ❌ Critiques    : $CriticalCount" -ForegroundColor Red
    Write-Host "  ⚠️  Avert.       : $WarnCount" -ForegroundColor Yellow
    Write-Host "  ✅ OK           : $OKCount" -ForegroundColor Green
    Write-Host "  🏆 Score        : $Score/100 ($ScoreStatus)" -ForegroundColor $(if($Score -ge 80){'Green'}elseif($Score -ge 50){'Yellow'}else{'Red'})
    Write-Host ""
    Write-Host "  Ouverture du rapport dans le navigateur par defaut..." -ForegroundColor Gray
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan

    try {
    Start-Process -FilePath $OutputFile -ErrorAction Stop
    } catch {
    Write-Host "[ERREUR] Impossible d'ouvrir le rapport : $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "         Ouvrez manuellement : $OutputFile" -ForegroundColor Yellow
    }
}

# ===========================================================================
#  MODULE 8 — COMPARE-PC  (Analyse differentielle rapports NetShare)
# ===========================================================================

function Invoke-ComparePC {
    param([string[]]$InputFiles)
    Assert-AdminPrivilege

    Write-Title 'MODULE 8 — COMPARE-PC : Analyse Differentielle Multi-Machines'

    $Script:VERSION   = '3.1.0'
    $Script:RUNDATE   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $Script:TIMESTAMP = Get-Date -Format 'yyyyMMdd_HHmmss'
    $Script:OUTDIR    = "$env:USERPROFILE\Desktop\CPR_$Script:TIMESTAMP"
    $Script:SEUIL_4625   = 10
    $Script:SEUIL_INVITE = 1
    $Script:RFC1918 = @(
        '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.',
        '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
        '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
        '127.'
    )

    $ReportFiles = $InputFiles
    if (-not $ReportFiles -or $ReportFiles.Count -lt 2) {
        Write-Host ''
        Write-Host '  Entrez les chemins des fichiers *-all.txt (2 minimum).' -ForegroundColor Yellow
        Write-Host '  Exemple : C:\Users\X\Desktop\PC-A-all.txt' -ForegroundColor DarkGray
        Write-Host '  Laissez vide et appuyez ENTREE pour terminer.' -ForegroundColor DarkGray
        $ReportFiles = @()
        do {
            $f = Read-Host "  Fichier $($ReportFiles.Count + 1)"
            if ($f -and (Test-Path $f)) { $ReportFiles += $f }
            elseif ($f) { Write-Host '  Fichier introuvable.' -ForegroundColor Red }
        } while ($f -or $ReportFiles.Count -lt 2)
        if ($ReportFiles.Count -lt 2) { Write-ERR 'Minimum 2 fichiers requis. Abandon.'; return }
    }

    function Set-Clean-RawInput {
    param([string]$Raw)
    $s = $Raw -replace "`r", ''
    $s = $s.Trim()
    if ($s.Length -ge 2 -and $s[0] -eq '"' -and $s[-1] -eq '"') {
    $s = $s.Substring(1, $s.Length - 2)
    } elseif ($s.Length -ge 2 -and $s[0] -eq "'" -and $s[-1] -eq "'") {
    $s = $s.Substring(1, $s.Length - 2)
    }
    return $s.Trim()
    }

    function Split-PathTokens {
    param([string]$Raw)
    $result = [System.Collections.Generic.List[string]]::new()
    if ([string]::IsNullOrWhiteSpace($Raw)) { return $result }

    $remaining = $Raw -replace "`r", ''

    # 1. Tokens entre guillemets doubles
    $quoteRegex = [regex]'"([^"]+)"'
    foreach ($m in $quoteRegex.Matches($remaining)) {
    $val = $m.Groups[1].Value.Trim()
    if ($val -ne '') { [void]$result.Add($val) }
    }
    $remaining = $quoteRegex.Replace($remaining, ' ')

    # 2. Tokens entre apostrophes
    $sqRegex = [regex]"'([^']+)'"
    foreach ($m in $sqRegex.Matches($remaining)) {
    $val = $m.Groups[1].Value.Trim()
    if ($val -ne '') { [void]$result.Add($val) }
    }
    $remaining = $sqRegex.Replace($remaining, ' ')

    # 3. Decoupe sur espaces, puis tente separation chemins colles
    $parts = $remaining -split '\s+' | Where-Object { $_ -ne '' }
    foreach ($part in $parts) {
    $subPaths = [regex]::Matches($part, '(?:[A-Za-z]:\\[^\s"'']*|\\\\[^\s"'']+)')
    if ($subPaths.Count -gt 1) {
    foreach ($sp in $subPaths) { [void]$result.Add($sp.Value.Trim()) }
    } else {
    [void]$result.Add($part.Trim())
    }
    }
    return $result
    }

    function Resolve-ReportFiles {
    param([object[]]$Inputs)
    $resolved = [System.Collections.Generic.List[string]]::new()
    foreach ($raw in $Inputs) {
    if ($null -eq $raw) { continue }
    $path = Set-Clean-RawInput -Raw "$raw"
    if ([string]::IsNullOrWhiteSpace($path)) { continue }

    # URI file:// (drag depuis certains explorateurs)
    if ($path -match '^file://') {
    try { $uri = [uri]$path; if ($uri.IsFile) { $path = $uri.LocalPath } } catch { }
    }

    # Wildcard
    if ($path -match '[*?]') {
    $found = Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
    if ($found) { foreach ($f in $found) { [void]$resolved.Add($f) } }
    else { Write-Host "  [AVERT] Aucun fichier pour le motif : $path" -ForegroundColor Yellow }
    continue
    }

    # Dossier -> tous les *-all.txt dedans
    if (Test-Path $path -PathType Container) {
    $found = Get-ChildItem -Path $path -Filter '*-all.txt' -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
    if ($found) { foreach ($f in $found) { [void]$resolved.Add($f) } }
    else { Write-Host "  [AVERT] Aucun *-all.txt dans : $path" -ForegroundColor Yellow }
    continue
    }

    # Fichier direct (ou chemin inconnu garde pour erreur ulterieure)
    if (Test-Path $path -PathType Leaf) {
    [void]$resolved.Add((Get-Item $path).FullName)
    } else {
    [void]$resolved.Add($path)
    }
    }
    return $resolved.ToArray()
    }

    function Set-Prompt-ReportFiles {
    Write-Host ""
    Write-Host "  ------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  Aucun fichier fourni. Entrez les chemins des fichiers *-all.txt." -ForegroundColor Yellow
    Write-Host "  -> Drag & drop des fichiers directement dans cette fenetre" -ForegroundColor Cyan
    Write-Host "  -> Ou copiez-collez le chemin complet (avec ou sans guillemets)" -ForegroundColor Cyan
    Write-Host "  -> Plusieurs fichiers sur la meme ligne : OK" -ForegroundColor Cyan
    Write-Host "  -> Ligne vide + Entree pour terminer (2 fichiers minimum requis)" -ForegroundColor DarkGray
    Write-Host "  ------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host ""

    $files = [System.Collections.Generic.List[string]]::new()
    $lineNum = 0

    while ($true) {
    $lineNum++
    $suffix = if ($files.Count -ge 2) { " [Entree = terminer]" } else { "" }
    $raw = Read-Host "  Entree $lineNum$suffix"

    if ([string]::IsNullOrWhiteSpace($raw)) {
    if ($files.Count -ge 2) { break }
    if ($files.Count -eq 0) {
    Write-Host "  Aucun fichier saisi. Abandon." -ForegroundColor Red
    exit 1
    }
    Write-Host "  Il faut au moins 2 fichiers (actuellement : $($files.Count))." -ForegroundColor Yellow
    continue
    }

    $tokens   = Split-PathTokens -Raw $raw
    $newPaths = Resolve-ReportFiles -Inputs $tokens

    $added = 0
    foreach ($p in $newPaths) {
    if ([string]::IsNullOrWhiteSpace($p)) { continue }
    if (-not (Test-Path $p)) {
    Write-Host "  [AVERT] Introuvable : $p" -ForegroundColor Yellow
    } else {
    [void]$files.Add($p)
    $added++
    Write-Host "  [OK] $(Split-Path $p -Leaf)" -ForegroundColor Green
    }
    }

    if ($added -eq 0 -and $newPaths.Count -gt 0) {
    Write-Host "  Aucun chemin valide reconnu dans cette saisie." -ForegroundColor Yellow
    }

    if ($files.Count -ge 10) {
    Write-Host "  Maximum 10 fichiers atteint." -ForegroundColor Yellow
    break
    }

    if ($files.Count -ge 2) {
    Write-Host "  ($($files.Count) fichier(s) valide(s) — continuez ou Entree pour lancer)" -ForegroundColor DarkGray
    }
    }

    Write-Host ""
    return $files.ToArray()
    }


    # ─────────────────────────────────────────────
    # VALIDATION ENTREES
    # ─────────────────────────────────────────────
    $ReportFiles = @($ReportFiles) | Where-Object { $_ -ne $null }
    if (-not $ReportFiles -or @($ReportFiles).Count -eq 0) {
    $ReportFiles = Set-Prompt-ReportFiles
    }
    $ReportFiles = Resolve-ReportFiles -Inputs $ReportFiles
    $ReportFiles = @($ReportFiles) | Where-Object { $_ -ne $null }
    if (@($ReportFiles).Count -lt 2) {
    Write-Error "Minimum 2 fichiers requis. Usage: .\Compare-PCReports.ps1 fichier1.txt fichier2.txt"
    exit 1
    }
    if (@($ReportFiles).Count -gt 10) {
    Write-Error "Maximum 10 fichiers supportes."
    exit 1
    }
    foreach ($f in $ReportFiles) {
    if (-not (Test-Path $f)) {
    Write-Error "Fichier introuvable : $f"
    exit 1
    }
    }
    if (-not (Test-Path $Script:OUTDIR)) {
    New-Item -ItemType Directory -Path $Script:OUTDIR -Force | Out-Null
    }

    # ─────────────────────────────────────────────
    # HELPERS
    # ─────────────────────────────────────────────
    function Get-MachineName {
    [OutputType([string])]
    param([string]$FilePath)
    $base = [System.IO.Path]::GetFileNameWithoutExtension($FilePath)
    if ($base -match '^([^_\-]+(?:[\-_][^_\-]+)*?)(?:[\-_]report[\-_]|[\-_]\d{8}|[\-_]all[\-_])') {
    return $Matches[1].ToUpper()
    }
    return $base.ToUpper()
    }

    function Test-IsPrivateIP {
    [OutputType([bool])]
    param([string]$IP)
    if ([string]::IsNullOrWhiteSpace($IP)) { return $false }
    foreach ($prefix in $Script:RFC1918) {
    if ($IP.StartsWith($prefix)) { return $true }
    }
    return $false
    }

    function Get-FieldValue {
    [OutputType([string])]
    param([string[]]$Lines, [string]$Key)
    foreach ($line in $Lines) {
    if ($line -match "^$([regex]::Escape($Key)):\s*(.+)$") {
    return $Matches[1].Trim()
    }
    }
    return ''
    }

    function Split-IntoBlocks {
    [OutputType([System.Collections.ArrayList])]
    param([string[]]$Lines)
    $blocks  = [System.Collections.ArrayList]::new()
    $current = [System.Collections.Generic.List[string]]::new()
    foreach ($line in $Lines) {
    if ([string]::IsNullOrWhiteSpace($line)) {
    if ($current.Count -gt 0) {
    [void]$blocks.Add($current.ToArray())
    $current = [System.Collections.Generic.List[string]]::new()
    }
    } else {
    $current.Add($line)
    }
    }
    if ($current.Count -gt 0) { [void]$blocks.Add($current.ToArray()) }
    return $blocks
    }

    function ConvertTo-SectionMap {
    [OutputType([hashtable])]
    param([string[]]$AllLines)
    $map     = @{}
    $current = ''
    $buf     = [System.Collections.Generic.List[string]]::new()
    foreach ($line in $AllLines) {
    $clean = $line.Trim()
    if ($clean -match '^=======\s+(.+?)\s+=======') {
    if ($current -ne '' -and $buf.Count -gt 0) {
    if (-not $map.ContainsKey($current)) { $map[$current] = [System.Collections.ArrayList]::new() }
    [void]$map[$current].Add($buf.ToArray())
    $buf = [System.Collections.Generic.List[string]]::new()
    }
    $current = $Matches[1].Trim()
    } elseif ($current -ne '') {
    $buf.Add($clean)
    }
    }
    if ($current -ne '' -and $buf.Count -gt 0) {
    if (-not $map.ContainsKey($current)) { $map[$current] = [System.Collections.ArrayList]::new() }
    [void]$map[$current].Add($buf.ToArray())
    }
    return $map
    }

    function Get-SectionLines {
    [OutputType([string[]])]
    param([hashtable]$SectionMap, [string]$SectionName)
    if ($SectionMap.ContainsKey($SectionName)) {
    $all = [System.Collections.Generic.List[string]]::new()
    foreach ($chunk in $SectionMap[$SectionName]) { foreach ($l in $chunk) { $all.Add($l) } }
    return $all.ToArray()
    }
    return @()
    }

    # ─────────────────────────────────────────────
    # PARSERS METIER
    # ─────────────────────────────────────────────
    function Get-NetworkInterfaces {
    [OutputType([System.Collections.ArrayList])]
    param([hashtable]$SectionMap)
    $lines  = Get-SectionLines -SectionMap $SectionMap -SectionName 'Interfaces reseau'
    $blocks = Split-IntoBlocks -Lines $lines
    $result = [System.Collections.ArrayList]::new()
    foreach ($block in $blocks) {
    $block = @($block)
    if ($block.Count -eq 0) { continue }
    $iface = @{
    Nom        = Get-FieldValue -Lines $block -Key 'Nom'
    IP         = Get-FieldValue -Lines $block -Key 'IP'
    Masque     = Get-FieldValue -Lines $block -Key 'Masque'
    Passerelle = Get-FieldValue -Lines $block -Key 'Passerelle'
    DNS        = Get-FieldValue -Lines $block -Key 'DNS'
    MAC        = Get-FieldValue -Lines $block -Key 'MAC'
    Type       = Get-FieldValue -Lines $block -Key 'Type'
    Statut     = Get-FieldValue -Lines $block -Key 'Statut'
    DHCP       = Get-FieldValue -Lines $block -Key 'DHCP'
    MTU        = Get-FieldValue -Lines $block -Key 'MTU'
    IsVPN      = $false
    IsPhysique = $false
    }
    $nomLow  = $iface.Nom.ToLower()
    $typeLow = $iface.Type.ToLower()
    $iface.IsVPN      = ($nomLow -match 'wintun|vpn|tun|tap|wireguard|openvpn|nordvpn|cyberghost|expressvpn|proton') -or ($typeLow -match 'virtuel|vpn|tunnel')
    $iface.IsPhysique = ($typeLow -match 'physique|physical') -and (-not $iface.IsVPN)
    [void]$result.Add($iface)
    }
    return $result
    }

    function Get-LocalAccounts {
    [OutputType([System.Collections.ArrayList])]
    param([hashtable]$SectionMap)

    # Accepte plusieurs noms de section possibles (NetworkShareDiagnostic v1.x vs legacy)
    $candidateSections = @(
    'Comptes locaux',                          # NSD v1.1 export title
    'Authentification et politique de securite', # legacy / ancienne version CPR
    'Authentification'                          # NSD v1.1 auth policy (contient aussi les comptes dans certaines versions)
    )

    $allChunks = [System.Collections.ArrayList]::new()
    foreach ($sec in $candidateSections) {
    if ($SectionMap.ContainsKey($sec)) {
    foreach ($c in $SectionMap[$sec]) { [void]$allChunks.Add($c) }
    }
    }

    $result  = [System.Collections.ArrayList]::new()
    $seenSID = [System.Collections.Generic.HashSet[string]]::new()

    foreach ($chunk in $allChunks) {
    $blocks = Split-IntoBlocks -Lines $chunk
    foreach ($block in $blocks) {
    $nom = Get-FieldValue -Lines $block -Key 'Nom'
    $sid = Get-FieldValue -Lines $block -Key 'SID'
    # Filtre : SID local S-1-5-21-* et nom non vide et pas de doublon
    if ($sid -match 'S-1-5-21' -and $nom -ne '' -and -not $seenSID.Contains($sid)) {
    [void]$seenSID.Add($sid)
    $acc = @{
    Nom          = $nom
    Active       = (Get-FieldValue -Lines $block -Key 'Active') -eq 'True'
    DernConnexion= Get-FieldValue -Lines $block -Key 'DernConnexion'
    MdpRequis    = (Get-FieldValue -Lines $block -Key 'MdpRequis') -eq 'True'
    MdpExpire    = Get-FieldValue -Lines $block -Key 'MdpExpire'
    SID          = $sid
    Risque       = Get-FieldValue -Lines $block -Key 'Risque'
    IsInvite     = ($nom -match '^Inv[iî]t[eé]$|^Guest$')
    IsAdmin      = ($nom -match '^Administrateur$|^Administrator$')
    IsSysteme    = ($nom -match '^DefaultAccount$|^WDAGUtility')
    }
    [void]$result.Add($acc)
    }
    }
    }
    return $result
    }

    function Get-StoredCredentials {
    [OutputType([System.Collections.ArrayList])]
    param([hashtable]$SectionMap)
    $allChunks = if ($SectionMap.ContainsKey('Authentification et politique de securite')) {
    $SectionMap['Authentification et politique de securite']
    } else { @() }

    $result = [System.Collections.ArrayList]::new()
    foreach ($chunk in $allChunks) {
    foreach ($line in $chunk) {
    if ($line -match 'Domain:target=(.+)') {
    $target = $Matches[1] -replace '"','' -replace "'",'' -replace '\s',''
    if ($target -ne '') { [void]$result.Add($target) }
    }
    }
    }
    return $result
    }

    function Get-SmbRemoteSessions {
    [OutputType([System.Collections.ArrayList])]
    param([hashtable]$SectionMap)
    $lines  = Get-SectionLines -SectionMap $SectionMap -SectionName 'Partages SMB distants'
    $blocks = Split-IntoBlocks -Lines $lines
    $result = [System.Collections.ArrayList]::new()
    foreach ($block in $blocks) {
    $srv = Get-FieldValue -Lines $block -Key 'Serveur'
    if ($srv -ne '') {
    [void]$result.Add(@{
    Serveur    = $srv.ToUpper()
    Partage    = Get-FieldValue -Lines $block -Key 'Partage'
    Utilisateur= Get-FieldValue -Lines $block -Key 'Utilisateur'
    Dialecte   = Get-FieldValue -Lines $block -Key 'Dialecte'
    Source     = Get-FieldValue -Lines $block -Key 'Source'
    })
    }
    }
    return $result
    }

    function Get-SmbShareHistory {
    [OutputType([hashtable])]
    param([hashtable]$SectionMap)
    # NSD v1.1 : 'Historique connectivite' ; legacy : 'Historique des connexions reseau'
    $sectionName = if ($SectionMap.ContainsKey('Historique connectivite')) { 'Historique connectivite' } `
    else { 'Historique des connexions reseau' }
    $lines      = Get-SectionLines -SectionMap $SectionMap -SectionName $sectionName
    $blocks     = Split-IntoBlocks -Lines $lines
    $inviteCount= 0
    $userCount  = 0
    $machineCount=0
    foreach ($block in $blocks) {
    $compte = Get-FieldValue -Lines $block -Key 'Compte'
    if ($compte -match 'Inv[iî]t[eé]|Guest') { $inviteCount++ }
    elseif ($compte -match '\$$') { $machineCount++ }
    elseif ($compte -ne '') { $userCount++ }
    }
    return @{ InviteCount = $inviteCount; UserCount = $userCount; MachineCount = $machineCount; Total = $blocks.Count }
    }

    function Get-SecurityEvents {
    [OutputType([hashtable])]
    param([hashtable]$SectionMap)
    # NSD v1.1 : 'Evenements' ; legacy : "Journal d'evenements - 24 dernieres heures (Auth/Partage)"
    $sectionName = if ($SectionMap.ContainsKey('Evenements')) { 'Evenements' } `
    else { "Journal d'evenements - 24 dernieres heures (Auth/Partage)" }
    $lines   = Get-SectionLines -SectionMap $SectionMap -SectionName $sectionName
    $c4625   = 0; $c4648 = 0; $c4624 = 0; $c5140 = 0
    foreach ($line in $lines) {
    if ($line -match 'EventID:\s*(\d+)') {
    switch ($Matches[1]) {
    '4625' { $c4625++ }
    '4648' { $c4648++ }
    '4624' { $c4624++ }
    '5140' { $c5140++ }
    }
    }
    }
    return @{ Echecs4625 = $c4625; SessionsExplicites4648 = $c4648; Connexions4624 = $c4624; AccesPartage5140 = $c5140 }
    }

    function Get-SmbConfig {
    [OutputType([hashtable])]
    param([hashtable]$SectionMap)
    # NSD v1.1 : 'Politique SMB client', 'Politique SMB serveur', 'Authentification'
    # Legacy   : 'Configuration SMB'
    $allLines = [System.Collections.Generic.List[string]]::new()
    foreach ($sec in @('Configuration SMB','Politique SMB client','Politique SMB serveur','Authentification','Authentification et politique de securite')) {
    foreach ($l in (Get-SectionLines -SectionMap $SectionMap -SectionName $sec)) { $allLines.Add($l) }
    }
    $lines = $allLines.ToArray()
    $cfg   = @{
    SMBv1Serveur          = 'Inconnu'
    SMBv2Serveur          = 'Inconnu'
    SignatureRequiseServeur= 'Inconnu'
    SignatureRequiseClient = 'Inconnu'
    ChiffrementServeur    = 'Inconnu'
    LmCompatibility       = 'Inconnu'
    RestrictAnonymous     = 'Inconnu'
    LocalAccountTokenFilter='Inconnu'
    NoLMHash              = 'Inconnu'
    UAC                   = 'Inconnu'
    }
    $blocks = Split-IntoBlocks -Lines $lines
    foreach ($block in $blocks) {
    $param = Get-FieldValue -Lines $block -Key 'Parametr'
    if (-not $param) { $param = Get-FieldValue -Lines $block -Key 'Parametre' }
    $val   = Get-FieldValue -Lines $block -Key 'Valeur'
    $cle   = Get-FieldValue -Lines $block -Key 'Cle'
    if ($param -match 'SMBv1.*Serveur')            { $cfg.SMBv1Serveur = $val }
    elseif ($param -match 'SMBv2|SMBv3.*Serveur')  { $cfg.SMBv2Serveur = $val }
    elseif ($param -match 'Signature requise.*Serveur') { $cfg.SignatureRequiseServeur = $val }
    elseif ($param -match 'Signature requise.*Client')  { $cfg.SignatureRequiseClient  = $val }
    elseif ($param -match 'Chiffrement.*Serveur')  { $cfg.ChiffrementServeur = $val }
    if ($cle -eq 'LmCompatibilityLevel')           { $cfg.LmCompatibility = $val }
    elseif ($cle -eq 'RestrictAnonymous')          { $cfg.RestrictAnonymous = $val }
    elseif ($cle -eq 'LocalAccountTokenFilterPolicy') { $cfg.LocalAccountTokenFilter = $val }
    elseif ($cle -eq 'NoLMHash')                   { $cfg.NoLMHash = $val }
    elseif ($cle -eq 'EnableLUA')                  { $cfg.UAC = $val }
    }
    return $cfg
    }

    function Get-FirewallStatus {
    [OutputType([hashtable])]
    param([hashtable]$SectionMap)
    # NSD v1.1 : 'Services pare-feu' + 'Regles firewall' ; legacy : 'Pare-feu Windows'
    $lines = [System.Collections.Generic.List[string]]::new()
    foreach ($sec in @('Pare-feu Windows','Services pare-feu','Regles firewall')) {
    foreach ($l in (Get-SectionLines -SectionMap $SectionMap -SectionName $sec)) { $lines.Add($l) }
    }
    $blocks  = Split-IntoBlocks -Lines $lines.ToArray()
    $profils = @{}
    $has445  = $false; $has139 = $false
    foreach ($block in $blocks) {
    $profil = Get-FieldValue -Lines $block -Key 'Profil'
    $active = Get-FieldValue -Lines $block -Key 'Active'
    if ($profil -ne '' -and $active -ne '') { $profils[$profil] = $active }
    $port   = Get-FieldValue -Lines $block -Key 'Port'
    $action = Get-FieldValue -Lines $block -Key 'Action'
    $dir    = Get-FieldValue -Lines $block -Key 'Direction'
    if ($port -eq '445' -and $action -eq 'Allow' -and $dir -eq 'Inbound') { $has445 = $true }
    if ($port -eq '139' -and $action -eq 'Allow' -and $dir -eq 'Inbound') { $has139 = $true }
    }
    return @{ Profils = $profils; Regle445 = $has445; Regle139 = $has139 }
    }

    function Get-ServicesStatus {
    [OutputType([hashtable])]
    param([hashtable]$SectionMap)
    # NSD v1.1 : 'Services critiques' + 'Protocoles de decouverte' ; legacy : 'Services et protocoles de decouverte'
    $lines = [System.Collections.Generic.List[string]]::new()
    foreach ($sec in @('Services et protocoles de decouverte','Services critiques','Protocoles de decouverte')) {
    foreach ($l in (Get-SectionLines -SectionMap $SectionMap -SectionName $sec)) { $lines.Add($l) }
    }
    $blocks   = Split-IntoBlocks -Lines $lines.ToArray()
    $services = @{}
    $protocols= @{}
    foreach ($block in $blocks) {
    $nom    = Get-FieldValue -Lines $block -Key 'Nom'
    $statut = Get-FieldValue -Lines $block -Key 'Statut'
    $proto  = Get-FieldValue -Lines $block -Key 'Protocole'
    $etat   = Get-FieldValue -Lines $block -Key 'Etat'
    if ($nom -ne '' -and $statut -ne '') { $services[$nom] = $statut }
    if ($proto -ne '' -and $etat -ne '') { $protocols[$proto] = $etat }
    }
    return @{ Services = $services; Protocols = $protocols }
    }

    function Get-ConnectivityTests {
    [OutputType([System.Collections.ArrayList])]
    param([hashtable]$SectionMap)
    # NSD v1.1 : 'Tests connectivite' ; legacy : 'Tests de connectivite'
    $sectionName = if ($SectionMap.ContainsKey('Tests connectivite')) { 'Tests connectivite' } else { 'Tests de connectivite' }
    $lines  = Get-SectionLines -SectionMap $SectionMap -SectionName $sectionName
    $blocks = Split-IntoBlocks -Lines $lines
    $result = [System.Collections.ArrayList]::new()
    foreach ($block in $blocks) {
    $cible = Get-FieldValue -Lines $block -Key 'Cible'
    if ($cible -ne '') {
    [void]$result.Add(@{
    Cible    = $cible
    Ping     = Get-FieldValue -Lines $block -Key 'Ping'
    Port445  = Get-FieldValue -Lines $block -Key 'Port445'
    UNC_IPC  = Get-FieldValue -Lines $block -Key 'UNC_IPC'
    Resultat = Get-FieldValue -Lines $block -Key 'Resultat'
    })
    }
    }
    return $result
    }

    function Get-HostsEntries {
    [OutputType([System.Collections.ArrayList])]
    param([hashtable]$SectionMap)
    # NSD v1.1 : 'Hosts' ; legacy : 'Fichier Hosts'
    $sectionName = if ($SectionMap.ContainsKey('Hosts')) { 'Hosts' } else { 'Fichier Hosts' }
    $lines  = Get-SectionLines -SectionMap $SectionMap -SectionName $sectionName
    $blocks = Split-IntoBlocks -Lines $lines
    $result = [System.Collections.ArrayList]::new()
    foreach ($block in $blocks) {
    $ip   = Get-FieldValue -Lines $block -Key 'IP'
    $hostname = Get-FieldValue -Lines $block -Key 'Hostname'
    if ($ip -ne '' -and $hostname -ne '') {
    [void]$result.Add(@{ IP = $ip; Hostname = $hostname })
    }
    }
    return $result
    }

    function Get-NetworkProfiles {
    [OutputType([System.Collections.ArrayList])]
    param([hashtable]$SectionMap)
    $lines  = Get-SectionLines -SectionMap $SectionMap -SectionName 'Profils reseau'
    $blocks = Split-IntoBlocks -Lines $lines
    $result = [System.Collections.ArrayList]::new()
    foreach ($block in $blocks) {
    $nom = Get-FieldValue -Lines $block -Key 'Nom'
    if ($nom -ne '') {
    [void]$result.Add(@{
    Nom     = $nom
    Profil  = Get-FieldValue -Lines $block -Key 'Profil'
    IPv4    = Get-FieldValue -Lines $block -Key 'IPv4'
    Risque  = Get-FieldValue -Lines $block -Key 'Risque'
    })
    }
    }
    return $result
    }

    function Get-ArpTable {
    [OutputType([System.Collections.ArrayList])]
    param([hashtable]$SectionMap)
    $lines  = Get-SectionLines -SectionMap $SectionMap -SectionName 'Table ARP'
    $blocks = Split-IntoBlocks -Lines $lines
    $result = [System.Collections.ArrayList]::new()
    foreach ($block in $blocks) {
    $ip  = Get-FieldValue -Lines $block -Key 'IP'
    $mac = Get-FieldValue -Lines $block -Key 'MAC'
    $type= Get-FieldValue -Lines $block -Key 'Type'
    if ($ip -ne '' -and $mac -ne '' -and $type -eq 'dynamique') {
    [void]$result.Add(@{ IP = $ip; MAC = $mac })
    }
    }
    return $result
    }

    function Get-SmbShares {
    [OutputType([System.Collections.ArrayList])]
    param([hashtable]$SectionMap)
    # NSD v1.1 exporte 'Partages SMB (etendus)', ancienne version 'Partages SMB'
    $sectionName = if ($SectionMap.ContainsKey('Partages SMB (etendus)')) { 'Partages SMB (etendus)' } else { 'Partages SMB' }
    $lines  = Get-SectionLines -SectionMap $SectionMap -SectionName $sectionName
    $blocks = Split-IntoBlocks -Lines $lines
    $result = [System.Collections.ArrayList]::new()
    foreach ($block in $blocks) {
    $nom  = Get-FieldValue -Lines $block -Key 'Nom'
    $acces= Get-FieldValue -Lines $block -Key 'Acces'
    if ($nom -ne '') {
    [void]$result.Add(@{
    Nom    = $nom
    Chemin = Get-FieldValue -Lines $block -Key 'Chemin'
    Acces  = $acces
    Risque = Get-FieldValue -Lines $block -Key 'Risque'
    EveryoneFull = ($acces -match 'Tout le monde.*Full|Everyone.*Full')
    })
    }
    }
    return $result
    }

    # ─────────────────────────────────────────────
    # AGREGATION COMPLETE D'UNE MACHINE
    # ─────────────────────────────────────────────
    function Get-MachineProfile {
    [OutputType([hashtable])]
    param([string]$FilePath)

    $name     = Get-MachineName -FilePath $FilePath
    $rawLines = Get-Content -Path $FilePath -Encoding UTF8 -ErrorAction SilentlyContinue
    if (-not $rawLines) {
    $rawLines = Get-Content -Path $FilePath -Encoding Default -ErrorAction SilentlyContinue
    }
    $secMap   = ConvertTo-SectionMap -AllLines $rawLines

    $ifaces   = Get-NetworkInterfaces    -SectionMap $secMap
    $physIface = $ifaces | Where-Object { $_.IsPhysique -and $_.Statut -eq 'Up' } | Select-Object -First 1
    # Fallback : si aucune interface physique Up, prendre n'importe quelle iface Up avec IP privée
    if (-not $physIface) {
    $physIface = $ifaces | Where-Object { $_.Statut -eq 'Up' -and (Test-IsPrivateIP -IP $_.IP) -and -not $_.IsVPN } | Select-Object -First 1
    }
    if (-not $physIface) {
    $physIface = $ifaces | Where-Object { $_.Statut -eq 'Up' -and (Test-IsPrivateIP -IP $_.IP) } | Select-Object -First 1
    }
    $vpnIfaces = @($ifaces | Where-Object { $_.IsVPN })

    # Extraction date du rapport depuis le nom de fichier (format: yyyyMMdd_HHhMMmSSs)
    $reportDate = ''
    if ($FilePath -match '(\d{8})_(\d+)h(\d+)m(\d+)s') {
    $d=$Matches[1]; $H=$Matches[2]; $M=$Matches[3].PadLeft(2,'0'); $S=$Matches[4].PadLeft(2,'0')
    $reportDate = "$($d.Substring(0,4))-$($d.Substring(4,2))-$($d.Substring(6,2)) ${H}:${M}:${S}"
    } elseif ($FilePath -match '(\d{8})') {
    $d=$Matches[1]
    $reportDate = "$($d.Substring(0,4))-$($d.Substring(4,2))-$($d.Substring(6,2))"
    }
    if ($reportDate -eq '') {
    try { $reportDate = (Get-Item $FilePath).LastWriteTime.ToString('yyyy-MM-dd HH:mm') } catch {}
    }

    $accounts  = Get-LocalAccounts       -SectionMap $secMap
    $creds     = Get-StoredCredentials   -SectionMap $secMap
    $smbRemote = Get-SmbRemoteSessions   -SectionMap $secMap
    $smbHisto  = Get-SmbShareHistory     -SectionMap $secMap
    $events    = Get-SecurityEvents      -SectionMap $secMap
    $smbCfg    = Get-SmbConfig           -SectionMap $secMap
    $firewall  = Get-FirewallStatus      -SectionMap $secMap
    $services  = Get-ServicesStatus      -SectionMap $secMap
    $connTests = Get-ConnectivityTests   -SectionMap $secMap
    $hosts     = Get-HostsEntries        -SectionMap $secMap
    $netProf   = Get-NetworkProfiles     -SectionMap $secMap
    $arp       = Get-ArpTable            -SectionMap $secMap
    $shares    = Get-SmbShares          -SectionMap $secMap

    $inviteAccount = $accounts | Where-Object { $_.IsInvite } | Select-Object -First 1
    $adminAccount  = $accounts | Where-Object { $_.IsAdmin  } | Select-Object -First 1
    $userAccounts  = @($accounts | Where-Object { -not $_.IsSysteme -and -not $_.IsInvite -and -not $_.IsAdmin })

    $physIP  = if ($physIface) { $physIface.IP  } else { '' }
    $physDNS = if ($physIface) { $physIface.DNS } else { '' }

    $hasVPN      = $vpnIfaces.Count -gt 0
    $dnsIsVPN    = $hasVPN -and $physDNS -ne '' -and (-not (Test-IsPrivateIP -IP $physDNS))
    $inviteActif = $inviteAccount -and $inviteAccount.Active
    $adminActif  = $adminAccount  -and $adminAccount.Active
    $smbv1Actif  = $smbCfg.SMBv1Serveur -match 'Activ'
    $llmnrActif  = -not ($services.Protocols.ContainsKey('LLMNR') -and $services.Protocols['LLMNR'] -match 'Desactiv')

    # Cibles SMB sortantes
    $smbTargets = @($smbRemote | ForEach-Object { $_.Serveur } | Sort-Object -Unique)

    return @{
    Name            = $name
    FilePath        = $FilePath
    SectionMap      = $secMap
    RawLineCount    = $rawLines.Count

    # Reseau
    PhysIP          = $physIP
    PhysDNS         = $physDNS
    PhysGateway     = if ($physIface) { $physIface.Passerelle } else { '' }
    PhysIface       = $physIface
    AllIfaces       = $ifaces
    VpnIfaces       = $vpnIfaces
    HasVPN          = $hasVPN
    DNSisVPN        = $dnsIsVPN
    ArpTable        = $arp
    NetProfiles     = $netProf

    # Comptes
    Accounts        = $accounts        # TOUS les comptes (admin, invite, user, systeme)
    InviteAccount   = $inviteAccount
    AdminAccount    = $adminAccount
    UserAccounts    = $userAccounts
    InviteActif     = $inviteActif
    AdminActif      = $adminActif

    # Auth & Securite
    StoredCreds     = $creds
    SmbConfig       = $smbCfg
    SMBv1Actif      = $smbv1Actif
    LLMNRActif      = $llmnrActif

    # SMB
    SmbRemote       = $smbRemote
    SmbTargets      = $smbTargets
    SmbHistory      = $smbHisto
    SmbShares       = $shares

    # Evenements
    Events          = $events

    # Firewall & Services
    Firewall        = $firewall
    Services        = $services

    # Tests
    ConnTests       = $connTests

    # Hosts
    HostsEntries    = $hosts

    # Metadata
    ReportDate      = $reportDate
    }
    }

    # ─────────────────────────────────────────────
    # MOTEUR D'ANOMALIES
    # ─────────────────────────────────────────────
    function Get-MachineAnomalies {
    [OutputType([System.Collections.ArrayList])]
    param(
    [hashtable]$Machine,
    [hashtable[]]$AllMachines
    )

    $anomalies = [System.Collections.ArrayList]::new()

    function Add-Anomaly {
    param([string]$Code, [string]$Severite, [string]$Message, [string]$Correctif)
    [void]$anomalies.Add([ordered]@{
    Code      = $Code
    Severite  = $Severite
    Message   = $Message
    Correctif = $Correctif
    Machine   = $Machine.Name
    })
    }

    # VPN actif
    if ($Machine.HasVPN) {
    $vpnNames = ($Machine.VpnIfaces | ForEach-Object { $_.Nom }) -join ', '
    Add-Anomaly -Code 'VPN_ACTIF' -Severite 'CRITIQUE' `
    -Message "VPN actif detecte sur $($Machine.Name) : $vpnNames. Le VPN reroute le trafic hors du LAN — les partages SMB vers les autres PC deviennent inaccessibles. Desactiver le VPN ou configurer un split-tunnel pour exclure 192.168.x.x." `
    -Correctif "Get-NetAdapter | Where-Object {`$_.Name -match 'VPN|Wintun|TUN|TAP'} | Disable-NetAdapter -Confirm:`$false"
    }

    # DNS non-local sur interface physique
    if ($Machine.DNSisVPN) {
    Add-Anomaly -Code 'DNS_VPN' -Severite 'CRITIQUE' `
    -Message "Le DNS de $($Machine.Name) pointe vers $($Machine.PhysDNS) (adresse non-locale, probablement DNS du VPN). La resolution des noms LAN est impossible. La passerelle detectee est $($Machine.PhysGateway) — c'est generalement aussi le DNS local a utiliser." `
    -Correctif "netsh interface ip set dns `"$($Machine.PhysIface.Nom)`" static $($Machine.PhysGateway)"
    }

    # Compte Invite actif
    if ($Machine.InviteActif) {
    Add-Anomaly -Code 'INVITE_ACTIF' -Severite 'CRITIQUE' `
    -Message "Compte Invité (Guest) ACTIF. Windows force les connexions SMB sans credentials vers ce compte degrade. Executer la commande ci-dessous sur $($Machine.Name) (adapter si OS en anglais : remplacer 'Invite' par 'Guest')." `
    -Correctif "net user Invité /active:no"
    }

    # Acces SMB sous Invite
    if ($Machine.SmbHistory.InviteCount -ge $Script:SEUIL_INVITE) {
    Add-Anomaly -Code 'INVITE_SMB' -Severite 'CRITIQUE' `
    -Message "$($Machine.SmbHistory.InviteCount) acces SMB entrants sous compte Invité detectes. Cause : Windows redirige vers Invité faute de credentials valides. Etapes : 1) Desactiver Invité  2) Vider credentials en cache  3) S'assurer que le meme compte utilisateur (meme nom, meme mdp) existe sur les deux machines." `
    -Correctif "net user Invité /active:no`r`ncmdkey /delete:* `r`nnet use * /delete /y"
    }

    # Echecs auth 4625 — logique croisee inter-machines
    if ($Machine.Events.Echecs4625 -ge $Script:SEUIL_4625) {
    # Les 4625 sont des echecs entrants ET sortants.
    # Sources entrantes : autres machines qui ont $Machine dans leurs SmbTargets → elles tapent sur nous avec mauvais creds
    # Cibles sortantes  : $Machine.SmbTargets → on tape sur elles avec mauvais creds
    $sourcesEntrantes = @($AllMachines | Where-Object {
    $_.Name -ne $Machine.Name -and $_.SmbTargets -contains $Machine.Name
    })
    # Reunir toutes les machines impliquees (sans doublon)
    $allImpliques = [System.Collections.Generic.List[string]]::new()
    foreach ($s in $sourcesEntrantes) { if (-not $allImpliques.Contains($s.Name)) { $allImpliques.Add($s.Name) } }
    foreach ($t in $Machine.SmbTargets) { if (-not $allImpliques.Contains($t)) { $allImpliques.Add($t) } }

    $cmdkeyLines = "# Sur $($Machine.Name) - vider credentials en cache :`r`ncmdkey /list"
    $detailCibles = @()
    foreach ($tName in $allImpliques) {
    $tMach = $AllMachines | Where-Object { $_.Name -eq $tName } | Select-Object -First 1
    $tIP   = if ($tMach -and $tMach.PhysIP) { $tMach.PhysIP } else { '' }
    $cmdkeyLines += "`r`ncmdkey /delete:TERMSRV/$tName"
    if ($tIP -and $tIP -ne $tName) { $cmdkeyLines += "`r`ncmdkey /delete:TERMSRV/$tIP" }
    $detailCibles += if ($tIP) { "$tName ($tIP)" } else { $tName }
    }
    if ($allImpliques.Count -eq 0) {
    $cmdkeyLines += "`r`ncmdkey /delete:TERMSRV/<nom_ou_ip_cible>"
    }
    $contextMsg = if ($sourcesEntrantes.Count -gt 0) {
    " Machines identifiees qui tentent de se connecter a $($Machine.Name) : $(($sourcesEntrantes | ForEach-Object { $_.Name }) -join ', ')."
    } else { "" }
    $ciblesMsg = if ($detailCibles.Count -gt 0) { " Cibles concernees : $($detailCibles -join ', ')." } else { "" }
    Add-Anomaly -Code 'AUTH_4625_ELEVE' -Severite 'CRITIQUE' `
    -Message "$($Machine.Events.Echecs4625) echecs d'authentification (4625) en 24h sur $($Machine.Name) — Windows utilise un mot de passe en cache incorrect.$contextMsg$ciblesMsg Les commandes ci-dessous suppriment les credentials incorrects." `
    -Correctif $cmdkeyLines
    }

    # Compte Administrateur actif
    if ($Machine.AdminActif) {
    Add-Anomaly -Code 'ADMIN_ACTIF' -Severite 'WARNING' `
    -Message "Compte Administrateur builtin ACTIF. Risque de securite eleve." `
    -Correctif "net user Administrateur /active:no"
    }

    # SMBv1
    if ($Machine.SMBv1Actif) {
    Add-Anomaly -Code 'SMBv1_ACTIF' -Severite 'CRITIQUE' `
    -Message "SMBv1 ACTIVE. Vulnerable EternalBlue (MS17-010). Protocole obsolete." `
    -Correctif "Set-SmbServerConfiguration -EnableSMB1Protocol `$false -Force"
    }

    # Signature SMB
    if ($Machine.SmbConfig.SignatureRequiseServeur -match 'Non') {
    Add-Anomaly -Code 'SMB_SIG_SERVEUR' -Severite 'WARNING' `
    -Message "Signature SMB non requise cote serveur. Risque d'attaque MITM/relay." `
    -Correctif "Set-SmbServerConfiguration -RequireSecuritySignature `$true -Force"
    }
    if ($Machine.SmbConfig.SignatureRequiseClient -match 'Non') {
    Add-Anomaly -Code 'SMB_SIG_CLIENT' -Severite 'WARNING' `
    -Message "Signature SMB non requise cote client. Risque d'attaque MITM/relay." `
    -Correctif "Set-SmbClientConfiguration -RequireSecuritySignature `$true -Force"
    }

    # LLMNR actif
    if ($Machine.LLMNRActif) {
    Add-Anomaly -Code 'LLMNR_ACTIF' -Severite 'WARNING' `
    -Message "LLMNR actif sur $($Machine.Name). Permet a un attaquant sur le meme reseau d'intercepter des credentials (attaque Responder). Desactiver via GPO (Computer Config > Admin Templates > Network > DNS Client > Turn off multicast name resolution) ou par registre ci-dessous." `
    -Correctif "reg add `"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`" /v EnableMulticast /t REG_DWORD /d 0 /f"
    }

    # Pare-feu port 445
    if (-not $Machine.Firewall.Regle445) {
    Add-Anomaly -Code 'FW_445_MANQUANT' -Severite 'WARNING' `
    -Message "Regle pare-feu entrant port 445 (SMB) non detectee. Partage SMB peut etre bloque." `
    -Correctif "netsh advfirewall firewall add rule name='SMB-In' dir=in action=allow protocol=TCP localport=445"
    }

    # LanmanServer
    $svcStatus = $Machine.Services.Services
    if ($svcStatus.ContainsKey('LanmanServer') -and $svcStatus['LanmanServer'] -ne 'Running') {
    Add-Anomaly -Code 'LANMAN_ARRETE' -Severite 'CRITIQUE' `
    -Message "Service LanmanServer (serveur SMB) n'est pas Running : $($svcStatus['LanmanServer'])." `
    -Correctif "Start-Service LanmanServer ; Set-Service LanmanServer -StartupType Automatic"
    }

    # Partages Everyone:Full
    $everyoneShares = @($Machine.SmbShares | Where-Object { $_.EveryoneFull -and $_.Nom -notmatch '^\w\$$|^ADMIN\$|^IPC\$' })
    if ($everyoneShares.Count -gt 0) {
    $noms = ($everyoneShares | ForEach-Object { $_.Nom }) -join ', '
    Add-Anomaly -Code 'SHARE_EVERYONE' -Severite 'WARNING' `
    -Message "Partages avec acces 'Tout le monde : Full' : $noms. Acces non restreint." `
    -Correctif "Restreindre les permissions via : icacls ou les proprietes du partage > Securite"
    }

    # Hosts non-standard
    $nonStdHosts = @($Machine.HostsEntries | Where-Object { $_.IP -notin @('127.0.0.1','::1','0.0.0.0') })
    if ($nonStdHosts.Count -gt 0) {
    $entries = ($nonStdHosts | ForEach-Object { "$($_.IP) -> $($_.Hostname)" }) -join ' | '
    Add-Anomaly -Code 'HOSTS_NONSTANDARD' -Severite 'INFO' `
    -Message "Entrees non-standard dans fichier HOSTS : $entries" `
    -Correctif "Verifier C:\Windows\System32\drivers\etc\hosts - supprimer si non intentionnel"
    }

    # Tests de connectivite echoues
    foreach ($test in $Machine.ConnTests) {
    if ($test.Resultat -match 'AVERT|FAIL|ERREUR|KO') {
    Add-Anomaly -Code 'CONN_TEST_FAIL' -Severite 'CRITIQUE' `
    -Message "Test de connectivite vers $($test.Cible) echoue — Ping: $($test.Ping) | Port 445: $($test.Port445) | UNC: $($test.UNC_IPC). Verifier : pare-feu de la cible, service LanmanServer actif, compte valide sur la cible." `
    -Correctif "Test-NetConnection $($test.Cible) -Port 445"
    }
    }

    # Croisement : credential manquant pour une cible SMB
    foreach ($target in $Machine.SmbTargets) {
    $hasCredForTarget = $false
    foreach ($cred in $Machine.StoredCreds) {
    if ($cred.ToUpper() -like "*$target*") { $hasCredForTarget = $true; break }
    }
    if (-not $hasCredForTarget) {
    Add-Anomaly -Code 'CRED_MANQUANT' -Severite 'WARNING' `
    -Message "Connexion SMB active vers $target detectable mais aucun credential Windows en cache. Au prochain redemarrage la connexion sera perdue. Remplacer <utilisateur> et <MotDePasse> par le compte existant sur $target." `
    -Correctif "cmdkey /add:$target /user:<utilisateur> /pass:<MotDePasse>"
    }
    }

    # Croisement inter-machines : compte utilisateur present sur cible
    foreach ($target in $Machine.SmbTargets) {
    $targetMachine = $AllMachines | Where-Object { $_.Name -eq $target } | Select-Object -First 1
    if ($targetMachine) {
    $usersOnSource = @($Machine.UserAccounts | ForEach-Object { $_.Nom })
    foreach ($usr in $usersOnSource) {
    $existsOnTarget = $targetMachine.UserAccounts | Where-Object { $_.Nom -eq $usr -and $_.Active }
    if (-not $existsOnTarget) {
    Add-Anomaly -Code 'COMPTE_ABSENT_CIBLE' -Severite 'CRITIQUE' `
    -Message "Compte '$usr' present sur $($Machine.Name) mais absent/inactif sur $target. Pour partager sans serveur central, le meme nom de compte avec le meme mot de passe doit exister sur les deux machines. Executer sur $target :" `
    -Correctif "net user $usr MotDePasse /add"
    }
    }
    }
    }

    return $anomalies
    }

    # ─────────────────────────────────────────────
    # MOTEUR DE DIFF ENTRE 2 MACHINES
    # ─────────────────────────────────────────────
    function Get-MachineDiff {
    [OutputType([System.Collections.ArrayList])]
    param([hashtable]$MachineA, [hashtable]$MachineB)

    $diffs = [System.Collections.ArrayList]::new()

    function Add-Diff {
    param([string]$Categorie, [string]$Champ, $ValA, $ValB, [string]$Impact)
    if ("$ValA" -ne "$ValB") {
    [void]$diffs.Add([ordered]@{
    Categorie = $Categorie
    Champ     = $Champ
    ValA      = "$ValA"
    ValB      = "$ValB"
    Impact    = $Impact
    })
    }
    }

    # Reseau
    Add-Diff 'Reseau' 'IP physique'     $MachineA.PhysIP  $MachineB.PhysIP  'Adressage'
    Add-Diff 'Reseau' 'DNS'             $MachineA.PhysDNS $MachineB.PhysDNS 'Resolution noms'
    Add-Diff 'Reseau' 'VPN actif'       $MachineA.HasVPN  $MachineB.HasVPN  'Routage SMB'
    Add-Diff 'Reseau' 'DNS non-local'   $MachineA.DNSisVPN $MachineB.DNSisVPN 'Resolution noms LAN'

    # Sous-reseau
    $subA = if ($MachineA.PhysIP -match '^(\d+\.\d+\.\d+)\.') { $Matches[1] } else { '' }
    $subB = if ($MachineB.PhysIP -match '^(\d+\.\d+\.\d+)\.') { $Matches[1] } else { '' }
    if ($subA -ne '' -and $subB -ne '' -and $subA -ne $subB) {
    [void]$diffs.Add([ordered]@{
    Categorie = 'Reseau'
    Champ     = 'Sous-reseau /24'
    ValA      = "$subA.x"
    ValB      = "$subB.x"
    Impact    = 'CRITIQUE - machines sur segments differents, SMB peut etre bloque par routeur'
    })
    }

    # Comptes
    Add-Diff 'Comptes' 'Invite actif'       $MachineA.InviteActif $MachineB.InviteActif 'Auth SMB entrante degradee'
    Add-Diff 'Comptes' 'Administrateur actif' $MachineA.AdminActif $MachineB.AdminActif 'Securite'

    # Comptes utilisateurs communs
    $usersA = @($MachineA.UserAccounts | ForEach-Object { $_.Nom })
    $usersB = @($MachineB.UserAccounts | ForEach-Object { $_.Nom })
    $onlyA  = @($usersA | Where-Object { $_ -notin $usersB })
    $onlyB  = @($usersB | Where-Object { $_ -notin $usersA })
    if ($onlyA.Count -gt 0) {
    [void]$diffs.Add([ordered]@{
    Categorie = 'Comptes'
    Champ     = "Comptes uniquement sur $($MachineA.Name)"
    ValA      = $onlyA -join ', '
    ValB      = '(absent)'
    Impact    = 'Authentification SMB impossible depuis/vers ces comptes'
    })
    }
    if ($onlyB.Count -gt 0) {
    [void]$diffs.Add([ordered]@{
    Categorie = 'Comptes'
    Champ     = "Comptes uniquement sur $($MachineB.Name)"
    ValA      = '(absent)'
    ValB      = $onlyB -join ', '
    Impact    = 'Authentification SMB impossible depuis/vers ces comptes'
    })
    }

    # SMB Config
    Add-Diff 'SMB' 'SMBv1 Serveur'               $MachineA.SmbConfig.SMBv1Serveur           $MachineB.SmbConfig.SMBv1Serveur           'Securite protocole'
    Add-Diff 'SMB' 'Signature requise (Serveur)'  $MachineA.SmbConfig.SignatureRequiseServeur $MachineB.SmbConfig.SignatureRequiseServeur 'MITM protection'
    Add-Diff 'SMB' 'Signature requise (Client)'   $MachineA.SmbConfig.SignatureRequiseClient  $MachineB.SmbConfig.SignatureRequiseClient  'MITM protection'
    Add-Diff 'SMB' 'Chiffrement SMB3'             $MachineA.SmbConfig.ChiffrementServeur      $MachineB.SmbConfig.ChiffrementServeur      'Confidentialite'
    Add-Diff 'SMB' 'LmCompatibilityLevel'         $MachineA.SmbConfig.LmCompatibility         $MachineB.SmbConfig.LmCompatibility         'Authentification NTLM'
    Add-Diff 'SMB' 'UAC (EnableLUA)'              $MachineA.SmbConfig.UAC                     $MachineB.SmbConfig.UAC                     'Privilege elevation'
    Add-Diff 'SMB' 'NoLMHash'                     $MachineA.SmbConfig.NoLMHash                $MachineB.SmbConfig.NoLMHash                'Stockage hash LM'

    # Pare-feu
    Add-Diff 'Pare-feu' 'Regle SMB 445 (In)' $MachineA.Firewall.Regle445 $MachineB.Firewall.Regle445 'Acces SMB entrant'
    Add-Diff 'Pare-feu' 'Regle NetBIOS 139 (In)' $MachineA.Firewall.Regle139 $MachineB.Firewall.Regle139 'Acces NetBIOS'

    # Services critiques
    $critSvcs = @('LanmanServer','LanmanWorkstation','MrxSmb','Dnscache','mpssvc')
    foreach ($svc in $critSvcs) {
    $stA = if ($MachineA.Services.Services.ContainsKey($svc)) { $MachineA.Services.Services[$svc] } else { 'N/A' }
    $stB = if ($MachineB.Services.Services.ContainsKey($svc)) { $MachineB.Services.Services[$svc] } else { 'N/A' }
    Add-Diff 'Services' "Service $svc" $stA $stB 'Disponibilite SMB/reseau'
    }

    # Evenements
    Add-Diff 'Evenements' 'Echecs auth 4625 (24h)' $MachineA.Events.Echecs4625 $MachineB.Events.Echecs4625 'Volume erreurs auth'
    Add-Diff 'Evenements' 'Acces Invite SMB (histori)' $MachineA.SmbHistory.InviteCount $MachineB.SmbHistory.InviteCount 'Degradation auth'

    # LLMNR
    Add-Diff 'Protocoles' 'LLMNR actif' $MachineA.LLMNRActif $MachineB.LLMNRActif 'Risque poisoning'

    return $diffs
    }

    # ─────────────────────────────────────────────
    # MATRICE RESEAU
    # ─────────────────────────────────────────────
    function Get-NetworkMatrix {
    [OutputType([hashtable])]
    param([hashtable[]]$Machines)

    $matrix = @{}
    foreach ($ma in $Machines) {
    $matrix[$ma.Name] = @{}
    foreach ($mb in $Machines) {
    if ($ma.Name -eq $mb.Name) {
    $matrix[$ma.Name][$mb.Name] = @{ Statut='SELF'; Detail='-' }
    continue
    }

    $aToB = $ma.SmbTargets -contains $mb.Name
    $bToA = $mb.SmbTargets -contains $ma.Name

    if ($aToB -or $bToA) {
    # Connexion detectee - evaluer qualite
    $issues = @()
    if ($mb.InviteActif)                    { $issues += 'Invite actif sur cible' }
    if ($ma.Events.Echecs4625 -ge $Script:SEUIL_4625) { $issues += "$($ma.Events.Echecs4625) echecs 4625" }
    if ($mb.SmbHistory.InviteCount -ge 1)   { $issues += "$($mb.SmbHistory.InviteCount) acces Invite" }
    if ($ma.DNSisVPN)                       { $issues += 'DNS VPN source' }

    # Test connectivite si disponible
    $connTest = $ma.ConnTests | Where-Object { $_.Cible -eq $mb.PhysIP -or $_.Cible.ToUpper() -eq $mb.Name } | Select-Object -First 1
    if ($connTest -and $connTest.Resultat -match 'AVERT|FAIL') { $issues += "Test UNC echoue" }

    if ($issues.Count -gt 0) {
    $matrix[$ma.Name][$mb.Name] = @{ Statut='WARN'; Detail=$issues -join ' | ' }
    } else {
    $matrix[$ma.Name][$mb.Name] = @{ Statut='OK'; Detail='Connexion SMB active confirmee' }
    }
    } else {
    # Verifier ARP pour savoir si au moins visibles
    $mbInArp = $ma.ArpTable | Where-Object { $_.IP -eq $mb.PhysIP }
    $credToB = $ma.StoredCreds | Where-Object { $_ -like "*$($mb.Name)*" -or $_ -eq $mb.PhysIP }
    if ($mbInArp -or $credToB) {
    $matrix[$ma.Name][$mb.Name] = @{ Statut='NO_SESS'; Detail='Machine visible (ARP/cred) mais pas de session SMB active' }
    } else {
    $matrix[$ma.Name][$mb.Name] = @{ Statut='UNKN'; Detail='Aucune donnee de connexion' }
    }
    }
    }
    }
    return $matrix
    }

    # ─────────────────────────────────────────────
    # EXPORT TEXTE
    # ─────────────────────────────────────────────
    function Export-TextReport {
    param([hashtable[]]$Machines, [hashtable]$Matrix, [hashtable]$AllAnomalies, [hashtable[]]$AllDiffs, [string]$OutPath)

    $sb = [System.Text.StringBuilder]::new()
    $line80 = '=' * 80

    [void]$sb.AppendLine($line80)
    [void]$sb.AppendLine("  RAPPORT DIFFERENTIEL PC - Compare-PCReports v$Script:VERSION")
    [void]$sb.AppendLine("  Genere le : $Script:RUNDATE")
    [void]$sb.AppendLine("  Machines  : $(($Machines | ForEach-Object {$_.Name}) -join ', ')")
    [void]$sb.AppendLine($line80)
    [void]$sb.AppendLine()

    # Synthese
    [void]$sb.AppendLine('>>> SYNTHESE PAR MACHINE')
    [void]$sb.AppendLine('-' * 60)
    foreach ($m in $Machines) {
    $anoms = $AllAnomalies[$m.Name]
    $crit  = @($anoms | Where-Object { $_.Severite -eq 'CRITIQUE' }).Count
    $warn  = @($anoms | Where-Object { $_.Severite -eq 'WARNING' }).Count
    $info  = @($anoms | Where-Object { $_.Severite -eq 'INFO' }).Count
    $score = if ($crit -gt 0) { 'CRITIQUE' } elseif ($warn -gt 0) { 'WARNING' } else { 'OK' }
    [void]$sb.AppendLine("  $($m.Name.PadRight(20)) IP:$($m.PhysIP.PadRight(16)) DNS:$($m.PhysDNS.PadRight(16)) Statut:$score  [CRIT:$crit WARN:$warn INFO:$info]")
    }
    [void]$sb.AppendLine()

    # Matrice
    [void]$sb.AppendLine('>>> MATRICE RESEAU')
    [void]$sb.AppendLine('-' * 60)
    $names = $Machines | ForEach-Object { $_.Name }
    $colW  = 12
    $header = 'SOURCE\CIBLE'.PadRight(22)
    foreach ($n in $names) { $header += $n.PadRight($colW) }
    [void]$sb.AppendLine($header)
    foreach ($src in $names) {
    $row = $src.PadRight(22)
    foreach ($dst in $names) {
    $cell = $Matrix[$src][$dst].Statut
    $row += $cell.PadRight($colW)
    }
    [void]$sb.AppendLine($row)
    }
    [void]$sb.AppendLine()
    [void]$sb.AppendLine("  Legende: OK=Connexion OK | WARN=Connexion avec anomalies | NO_SESS=Visible sans session | UNKN=Inconnu | SELF=Meme machine")
    [void]$sb.AppendLine()

    # Anomalies par machine
    [void]$sb.AppendLine('>>> ANOMALIES PAR MACHINE')
    [void]$sb.AppendLine('-' * 60)
    foreach ($m in $Machines) {
    $anoms = $AllAnomalies[$m.Name]
    [void]$sb.AppendLine()
    [void]$sb.AppendLine("  [ $($m.Name) ]  IP:$($m.PhysIP)  DNS:$($m.PhysDNS)")
    if ($anoms.Count -eq 0) {
    [void]$sb.AppendLine("    OK - Aucune anomalie detectee")
    } else {
    foreach ($a in ($anoms | Sort-Object { @('CRITIQUE','WARNING','INFO').IndexOf($_.Severite) })) {
    [void]$sb.AppendLine("    [$($a.Severite)] $($a.Code) : $($a.Message)")
    [void]$sb.AppendLine("    => $($a.Correctif)")
    [void]$sb.AppendLine()
    }
    }
    }

    # Diffs par paire
    [void]$sb.AppendLine('>>> DIFFERENTIELS PAR PAIRE')
    [void]$sb.AppendLine('-' * 60)
    foreach ($diffEntry in $AllDiffs) {
    [void]$sb.AppendLine()
    [void]$sb.AppendLine("  $($diffEntry.PairName)")
    if (@($diffEntry.Diffs).Count -eq 0) {
    [void]$sb.AppendLine("    Aucune difference detectee sur les champs surveilles")
    } else {
    foreach ($d in $diffEntry.Diffs) {
    [void]$sb.AppendLine("    [$($d.Categorie)] $($d.Champ)")
    [void]$sb.AppendLine("      $($diffEntry.NameA): $($d.ValA)")
    [void]$sb.AppendLine("      $($diffEntry.NameB): $($d.ValB)")
    if ($d.Impact) { [void]$sb.AppendLine("      Impact: $($d.Impact)") }
    }
    }
    }

    [void]$sb.AppendLine()
    [void]$sb.AppendLine($line80)
    [void]$sb.AppendLine("  FIN DU RAPPORT - Compare-PCReports v$Script:VERSION")
    [void]$sb.AppendLine($line80)

    $sb.ToString() | Out-File -FilePath $OutPath -Encoding UTF8 -Force
    Write-Host "  [TXT] $OutPath" -ForegroundColor Cyan
    }

    # ─────────────────────────────────────────────
    # EXPORT CSV
    # ─────────────────────────────────────────────
    function Export-CsvReports {
    param([hashtable[]]$Machines, [hashtable]$AllAnomalies, [hashtable[]]$AllDiffs, [string]$BaseDir)

    # CSV Synthese machines
    $synthPath = Join-Path $BaseDir "synthese_machines_$Script:TIMESTAMP.csv"
    $rows = foreach ($m in $Machines) {
    $anoms = $AllAnomalies[$m.Name]
    [PSCustomObject]@{
    Machine          = $m.Name
    IP               = $m.PhysIP
    DNS              = $m.PhysDNS
    VPN              = $m.HasVPN
    DNS_non_local    = $m.DNSisVPN
    Invite_actif     = $m.InviteActif
    Admin_actif      = $m.AdminActif
    SMBv1            = $m.SMBv1Actif
    LLMNR            = $m.LLMNRActif
    Echecs_4625      = $m.Events.Echecs4625
    Acces_Invite_SMB = $m.SmbHistory.InviteCount
    Cibles_SMB       = $m.SmbTargets -join ';'
    Nb_Critique      = @($anoms | Where-Object { $_.Severite -eq 'CRITIQUE' }).Count
    Nb_Warning       = @($anoms | Where-Object { $_.Severite -eq 'WARNING' }).Count
    Nb_Info          = @($anoms | Where-Object { $_.Severite -eq 'INFO' }).Count
    Score_Global     = if (@($anoms | Where-Object { $_.Severite -eq 'CRITIQUE' }).Count -gt 0) { 'CRITIQUE' } elseif (@($anoms | Where-Object { $_.Severite -eq 'WARNING' }).Count -gt 0) { 'WARNING' } else { 'OK' }
    }
    }
    $rows | Export-Csv -Path $synthPath -NoTypeInformation -Encoding UTF8 -Delimiter ';'
    Write-Host "  [CSV] $synthPath" -ForegroundColor Cyan

    # CSV Anomalies
    $anomPath = Join-Path $BaseDir "anomalies_$Script:TIMESTAMP.csv"
    $anomRows = foreach ($m in $Machines) {
    foreach ($a in $AllAnomalies[$m.Name]) {
    [PSCustomObject]@{
    Machine      = $m.Name
    IP           = $m.PhysIP
    Severite     = $a.Severite
    Code         = $a.Code
    Message      = $a.Message
    Correctif    = $a.Correctif
    Executer_Sur = if ($a.Correctif -match " sur ($($m.Name)|[A-Z][A-Z0-9-]+)") { $Matches[1] } else { $m.Name }
    }
    }
    }
    if ($anomRows) {
    $anomRows | Export-Csv -Path $anomPath -NoTypeInformation -Encoding UTF8 -Delimiter ';'
    } else {
    "Machine;Severite;Code;Message;Correctif" | Out-File $anomPath -Encoding UTF8
    }
    Write-Host "  [CSV] $anomPath" -ForegroundColor Cyan

    # CSV Diffs
    $diffPath = Join-Path $BaseDir "diffs_$Script:TIMESTAMP.csv"
    $diffRows = foreach ($entry in $AllDiffs) {
    foreach ($d in $entry.Diffs) {
    [PSCustomObject]@{
    Paire      = $entry.PairName
    MachineA   = $entry.NameA
    MachineB   = $entry.NameB
    Categorie  = $d.Categorie
    Champ      = $d.Champ
    Valeur_A   = $d.ValA
    Valeur_B   = $d.ValB
    Impact     = $d.Impact
    }
    }
    }
    if ($diffRows) {
    $diffRows | Export-Csv -Path $diffPath -NoTypeInformation -Encoding UTF8 -Delimiter ';'
    } else {
    "Paire;MachineA;MachineB;Categorie;Champ;Valeur_A;Valeur_B;Impact" | Out-File $diffPath -Encoding UTF8
    }
    Write-Host "  [CSV] $diffPath" -ForegroundColor Cyan
    }

    # ─────────────────────────────────────────────
    # GENERATION HTML
    # ─────────────────────────────────────────────
    function Export-HtmlDashboard {
    param(
    [hashtable[]]$Machines,
    [hashtable]$Matrix,
    [hashtable]$AllAnomalies,
    [hashtable[]]$AllDiffs,
    [string]$OutPath
    )

    # Serialisation JSON pour JS
    $machinesJson = @()
    foreach ($m in $Machines) {
    $anoms = $AllAnomalies[$m.Name]
    $machinesJson += [ordered]@{
    name         = $m.Name
    ip           = $m.PhysIP
    dns          = $m.PhysDNS
    hasVpn       = $m.HasVPN
    dnsIsVpn     = $m.DNSisVPN
    inviteActif  = $m.InviteActif
    adminActif   = $m.AdminActif
    smbv1        = $m.SMBv1Actif
    llmnr        = $m.LLMNRActif
    echecs4625   = $m.Events.Echecs4625
    inviteSmb    = $m.SmbHistory.InviteCount
    smbTargets   = $m.SmbTargets
    vpnNames     = @($m.VpnIfaces | ForEach-Object { $_.Nom })
    accounts     = @($m.Accounts | ForEach-Object { [ordered]@{
    nom=$_.Nom; active=$_.Active; dernConn=$_.DernConnexion
    isAdmin=$_.IsAdmin; isInvite=$_.IsInvite; isSysteme=$_.IsSysteme
    mdpRequis=$_.MdpRequis; risque=$_.Risque } })
    reportDate   = $m.ReportDate
    shares       = @($m.SmbShares | ForEach-Object { [ordered]@{ nom=$_.Nom; chemin=$_.Chemin; acces=$_.Acces; everyoneFull=$_.EveryoneFull } })
    fw445        = $m.Firewall.Regle445
    smbSigSrv    = $m.SmbConfig.SignatureRequiseServeur
    smbSigClt    = $m.SmbConfig.SignatureRequiseClient
    smbChiffr    = $m.SmbConfig.ChiffrementServeur
    lmLevel      = $m.SmbConfig.LmCompatibility
    uac          = $m.SmbConfig.UAC
    hostsEntries = @($m.HostsEntries | ForEach-Object { [ordered]@{ ip=$_.IP; hostname=$_.Hostname } })
    connTests    = @($m.ConnTests | ForEach-Object { [ordered]@{ cible=$_.Cible; ping=$_.Ping; port445=$_.Port445; unc=$_.UNC_IPC; resultat=$_.Resultat } })
    storedCreds  = $m.StoredCreds
    anomalies    = @($anoms | ForEach-Object { [ordered]@{ code=$_.Code; severite=$_.Severite; message=$_.Message; correctif=$_.Correctif } })
    nbCrit       = @($anoms | Where-Object { $_.Severite -eq 'CRITIQUE' }).Count
    nbWarn       = @($anoms | Where-Object { $_.Severite -eq 'WARNING' }).Count
    nbInfo       = @($anoms | Where-Object { $_.Severite -eq 'INFO' }).Count
    }
    }

    $matrixJson = @{}
    foreach ($src in $Matrix.Keys) {
    $matrixJson[$src] = @{}
    foreach ($dst in $Matrix[$src].Keys) {
    $matrixJson[$src][$dst] = [ordered]@{ statut=$Matrix[$src][$dst].Statut; detail=$Matrix[$src][$dst].Detail }
    }
    }

    $diffsJson = @()
    foreach ($entry in $AllDiffs) {
    $diffsJson += [ordered]@{
    pairName = $entry.PairName
    nameA    = $entry.NameA
    nameB    = $entry.NameB
    diffs    = @($entry.Diffs | ForEach-Object { [ordered]@{ categorie=$_.Categorie; champ=$_.Champ; valA=$_.ValA; valB=$_.ValB; impact=$_.Impact } })
    }
    }

    $machinesJsonStr = $machinesJson | ConvertTo-Json -Depth 10 -Compress
    $matrixJsonStr   = $matrixJson   | ConvertTo-Json -Depth 5  -Compress
    $diffsJsonStr    = $diffsJson    | ConvertTo-Json -Depth 8  -Compress

    $html = @'
    <!DOCTYPE html>
    <html lang="fr" data-theme="dark">
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Compare-PCReports — Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
    /* ═══════════════════════════════════════════════════════
    THEME — aligné sur NetworkShareDiagnostic palette
    ═══════════════════════════════════════════════════════ */
    :root[data-theme="dark"] {
    --bg:        #0d1117;
    --bg2:       #161b22;
    --bg3:       #21262d;
    --border:    #30363d;
    --border2:   #3d444d;
    --text:      #e6edf3;
    --text2:     #8b949e;
    --text3:     #484f58;
    --accent:    #58a6ff;
    --accent2:   #1f6feb;
    --ok:        #3fb950;
    --ok-bg:     #0d4a1a;
    --warn:      #d29922;
    --warn-bg:   #3d2f00;
    --crit:      #f85149;
    --crit-bg:   #4a0d0a;
    --info:      #79c0ff;
    --info-bg:   #0d2a4a;
    --unkn:      #484f58;
    --self:      #21262d;
    --card:      #161b22;
    --card2:     #21262d;
    --shadow:    0 4px 20px rgba(0,0,0,.4);
    --radius:    8px;
    --font-mono: 'JetBrains Mono', monospace;
    --font-ui:   'Inter', sans-serif;
    }
    :root[data-theme="light"] {
    --bg:        #f6f8fa;
    --bg2:       #ffffff;
    --bg3:       #f0f3f6;
    --border:    #d0d7de;
    --border2:   #b1bac4;
    --text:      #1f2328;
    --text2:     #656d76;
    --text3:     #9198a1;
    --accent:    #0969da;
    --accent2:   #0550ae;
    --ok:        #1a7f37;
    --ok-bg:     #d2f4db;
    --warn:      #9a6700;
    --warn-bg:   #fff8c5;
    --crit:      #cf222e;
    --crit-bg:   #ffebe9;
    --info:      #0550ae;
    --info-bg:   #ddf4ff;
    --unkn:      #9198a1;
    --self:      #f0f3f6;
    --card:      #ffffff;
    --card2:     #f6f8fa;
    --shadow:    0 2px 12px rgba(0,0,0,.08);
    --radius:    8px;
    --font-mono: 'JetBrains Mono', monospace;
    --font-ui:   'Inter', sans-serif;
    }

    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html { font-size: 14px; scroll-behavior: smooth; }
    body { background: var(--bg); color: var(--text); font-family: var(--font-ui); min-height: 100vh; transition: background .25s, color .25s; }

    /* ── EXECUTIVE BANNER ── */
    .exec-banner {
    background: var(--bg2); border-bottom: 2px solid var(--border);
    padding: 10px 20px; display: flex; align-items: center; gap: 14px; flex-wrap: wrap;
    }
    .exec-banner-title { font-size: .78rem; font-weight: 600; color: var(--text2); text-transform: uppercase; letter-spacing: .06em; white-space: nowrap; }
    .exec-pill {
    display: inline-flex; align-items: center; gap: 5px;
    font-size: .75rem; font-weight: 700; padding: 3px 10px; border-radius: 20px;
    letter-spacing: .03em;
    }
    .exec-pill.crit { background: var(--crit-bg); color: var(--crit); border: 1px solid var(--crit); }
    .exec-pill.warn { background: var(--warn-bg); color: var(--warn); border: 1px solid var(--warn); }
    .exec-pill.ok   { background: var(--ok-bg);   color: var(--ok);   border: 1px solid var(--ok);   }
    .exec-pill.info { background: var(--info-bg);  color: var(--info); border: 1px solid var(--info); }
    .exec-date { font-size: .72rem; color: var(--text3); margin-left: auto; white-space: nowrap; font-family: var(--font-mono); }

    /* ── TOPBAR ── */
    .topbar {
    position: sticky; top: 0; z-index: 100;
    display: flex; align-items: center; gap: 12px; padding: 8px 20px;
    background: var(--bg2); border-bottom: 1px solid var(--border);
    box-shadow: 0 2px 8px rgba(0,0,0,.2); flex-wrap: wrap;
    }
    .topbar-brand { font-family: var(--font-ui); font-size: .95rem; font-weight: 700; color: var(--accent); white-space: nowrap; }
    .topbar-brand span { color: var(--text2); font-weight: 400; font-size: .8rem; margin-left: 5px; }
    .topbar-search {
    flex: 1; min-width: 180px; display: flex; align-items: center; gap: 8px;
    background: var(--bg3); border: 1px solid var(--border2); border-radius: 6px; padding: 5px 10px;
    }
    .topbar-search input { border: none; background: none; outline: none; color: var(--text); font-family: var(--font-mono); font-size: .82rem; width: 100%; }
    .topbar-search input::placeholder { color: var(--text3); }
    .topbar-actions { display: flex; gap: 6px; align-items: center; margin-left: auto; }
    .btn { font-family: var(--font-ui); font-size: .75rem; padding: 5px 11px; border-radius: 6px; border: 1px solid var(--border2); background: var(--bg3); color: var(--text2); cursor: pointer; transition: all .15s; white-space: nowrap; }
    .btn:hover { border-color: var(--accent); color: var(--accent); }
    .btn-accent { background: var(--accent); color: #fff; border-color: var(--accent); font-weight: 600; }
    .btn-accent:hover { background: var(--accent2); border-color: var(--accent2); }

    /* ── NAV TABS ── */
    .nav-tabs { display: flex; background: var(--bg2); border-bottom: 1px solid var(--border); overflow-x: auto; padding: 0 16px; }
    .nav-tab { padding: 10px 16px; cursor: pointer; font-size: .82rem; font-weight: 500; color: var(--text2); border-bottom: 2px solid transparent; white-space: nowrap; transition: all .15s; user-select: none; }
    .nav-tab:hover { color: var(--text); }
    .nav-tab.active { color: var(--accent); border-bottom-color: var(--accent); font-weight: 600; }
    .tab-badge { display: inline-block; font-size: .65rem; font-weight: 700; padding: 1px 6px; border-radius: 20px; margin-left: 5px; background: var(--crit-bg); color: var(--crit); border: 1px solid var(--crit); }
    .tab-badge.ok   { background: var(--ok-bg);   color: var(--ok);   border-color: var(--ok); }
    .tab-badge.warn { background: var(--warn-bg);  color: var(--warn); border-color: var(--warn); }

    /* ── LAYOUT ── */
    .content { padding: 18px; max-width: 1600px; margin: 0 auto; }
    .tab-panel { display: none; }
    .tab-panel.active { display: block; animation: fadeIn .2s ease; }
    @keyframes fadeIn { from { opacity:0; transform:translateY(4px); } to { opacity:1; transform:none; } }

    /* ── CARDS ── */
    .card { background: var(--card); border: 1px solid var(--border); border-radius: var(--radius); box-shadow: var(--shadow); margin-bottom: 14px; overflow: hidden; }
    .card-header { display: flex; align-items: center; justify-content: space-between; padding: 11px 15px; background: var(--card2); border-bottom: 1px solid var(--border); cursor: pointer; user-select: none; }
    .card-header:hover { background: var(--bg3); }
    .card-title { font-weight: 600; font-size: .88rem; color: var(--text); display: flex; align-items: center; gap: 7px; }
    .card-body { padding: 14px; }
    .card-toggle { color: var(--text3); font-size: .75rem; transition: transform .2s; }
    .card.collapsed .card-toggle { transform: rotate(-90deg); }
    .card.collapsed .card-body { display: none; }

    /* ── SCORE BADGES ── */
    .score { display: inline-flex; align-items: center; gap: 4px; font-weight: 700; font-size: .72rem; padding: 2px 9px; border-radius: 20px; letter-spacing: .04em; text-transform: uppercase; }
    .score.CRITIQUE { background: var(--crit-bg); color: var(--crit); border: 1px solid var(--crit); }
    .score.WARNING  { background: var(--warn-bg); color: var(--warn); border: 1px solid var(--warn); }
    .score.OK       { background: var(--ok-bg);   color: var(--ok);   border: 1px solid var(--ok); }
    .score.INFO     { background: var(--info-bg); color: var(--info); border: 1px solid var(--info); }
    .score.UNKN     { background: var(--bg3);     color: var(--unkn); border: 1px solid var(--unkn); }

    /* ── MACHINE GRID ── */
    .machine-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(270px,1fr)); gap: 14px; }
    .machine-card { background: var(--card); border: 1px solid var(--border); border-radius: var(--radius); padding: 14px; transition: border-color .15s, transform .1s; cursor: pointer; }
    .machine-card:hover { border-color: var(--accent); transform: translateY(-2px); }
    .machine-card.crit { border-left: 3px solid var(--crit); }
    .machine-card.warn { border-left: 3px solid var(--warn); }
    .machine-card.ok   { border-left: 3px solid var(--ok); }
    .machine-name { font-weight: 700; font-size: 1.05rem; color: var(--accent); margin-bottom: 5px; }
    .machine-meta { font-size: .78rem; color: var(--text2); margin-bottom: 8px; font-family: var(--font-mono); }
    .missing { color: var(--warn); font-style: italic; font-weight: 600; }
    .machine-meta .missing { color: var(--warn); font-weight: 600; }
    .machine-tags { display: flex; flex-wrap: wrap; gap: 5px; margin-bottom: 8px; }
    .tag { font-size: .68rem; font-weight: 600; padding: 2px 7px; border-radius: 4px; text-transform: uppercase; letter-spacing: .04em; }
    .tag-vpn  { background: var(--crit-bg); color: var(--crit);  border: 1px solid var(--crit); }
    .tag-inv  { background: var(--crit-bg); color: var(--crit);  border: 1px solid var(--crit); }
    .tag-dns  { background: var(--warn-bg); color: var(--warn);  border: 1px solid var(--warn); }
    .tag-ok   { background: var(--ok-bg);   color: var(--ok);    border: 1px solid var(--ok); }
    .machine-counters { display: flex; gap: 8px; margin-top: 8px; }
    .counter { text-align: center; flex: 1; }
    .counter-val { font-size: 1.2rem; font-weight: 700; }
    .counter-lbl { font-size: .62rem; color: var(--text2); text-transform: uppercase; }
    .counter.crit .counter-val { color: var(--crit); }
    .counter.warn .counter-val { color: var(--warn); }
    .counter.info .counter-val { color: var(--info); }
    .machine-date { font-size: .68rem; color: var(--text3); margin-top: 8px; font-family: var(--font-mono); }

    /* ── MATRICE ── */
    .matrix-wrap { overflow-x: auto; }
    .matrix-table { border-collapse: collapse; min-width: 360px; }
    .matrix-table th, .matrix-table td { padding: 9px 13px; text-align: center; border: 1px solid var(--border); font-size: .78rem; }
    .matrix-table th { background: var(--bg3); font-weight: 600; color: var(--text2); white-space: nowrap; }
    .matrix-table th.row-header { text-align: left; min-width: 110px; }
    .matrix-cell { font-weight: 700; letter-spacing: .04em; cursor: pointer; transition: transform .1s; border-radius: 3px; }
    .matrix-cell:hover { transform: scale(1.08); }
    /* Cellules matrice : fond neutre, seul le texte est coloré + une fine bordure left */
    .cell-OK       { color: var(--ok);   background: var(--card2); border-left: 3px solid var(--ok) !important; }
    .cell-WARN     { color: var(--warn); background: var(--card2); border-left: 3px solid var(--warn) !important; }
    .cell-NO_SESS  { color: var(--info); background: var(--card2); border-left: 3px solid var(--info) !important; }
    .cell-UNKN     { color: var(--text3); background: var(--card2); }
    .cell-SELF     { color: var(--text3); background: var(--bg3); }
    .cell-AUTH_FAIL{ color: var(--crit); background: var(--card2); border-left: 3px solid var(--crit) !important; }

    /* ── TABLEAU LIAISONS ── */
    .conn-list-table { width: 100%; border-collapse: collapse; font-size: .8rem; }
    .conn-list-table th { background: var(--bg3); color: var(--text2); padding: 7px 12px; text-align: left; font-weight: 600; border-bottom: 1px solid var(--border2); white-space: nowrap; }
    .conn-list-table td { padding: 9px 12px; border-bottom: 1px solid var(--border); vertical-align: middle; }
    .conn-list-table tr:hover td { background: var(--bg3); }
    .conn-list-table tr:last-child td { border-bottom: none; }
    .conn-machine { font-weight: 700; font-size: .85rem; font-family: var(--font-mono); color: var(--text); }
    .conn-arrow { color: var(--text3); font-size: .9rem; padding: 0 4px; }
    .conn-status { display: inline-flex; align-items: center; gap: 5px; font-size: .72rem; font-weight: 700; padding: 3px 10px; border-radius: 20px; white-space: nowrap; }
    .conn-status.ok      { background: var(--ok-bg);   color: var(--ok);   border: 1px solid var(--ok); }
    .conn-status.warn    { background: var(--warn-bg);  color: var(--warn); border: 1px solid var(--warn); }
    .conn-status.nosess  { background: var(--info-bg);  color: var(--info); border: 1px solid var(--info); }
    .conn-status.unkn    { background: var(--bg3);      color: var(--text3);border: 1px solid var(--border2); }
    .conn-status.fail    { background: var(--crit-bg);  color: var(--crit); border: 1px solid var(--crit); }
    .conn-detail { font-size: .75rem; color: var(--text2); line-height: 1.5; }
    .conn-summary { display: flex; gap: 10px; flex-wrap: wrap; padding: 10px 14px; background: var(--card2); border-bottom: 1px solid var(--border); font-size: .78rem; }
    .conn-sum-pill { display: inline-flex; align-items: center; gap: 4px; font-weight: 600; padding: 2px 8px; border-radius: 12px; }
    .anom-table { width: 100%; border-collapse: collapse; font-size: .8rem; }
    .anom-table th { background: var(--bg3); color: var(--text2); padding: 7px 11px; text-align: left; font-weight: 600; border-bottom: 1px solid var(--border2); white-space: nowrap; }
    .anom-table td { padding: 9px 11px; border-bottom: 1px solid var(--border); vertical-align: top; }
    .anom-table tr:hover td { background: var(--bg3); }
    .anom-machine { font-weight: 700; color: var(--accent); font-size: .82rem; }
    /* Code technique : puce neutre, pas de couleur criarde */
    .anom-code { font-size: .66rem; background: var(--bg3); color: var(--text3); padding: 2px 6px; border-radius: 4px; white-space: nowrap; font-family: var(--font-mono); border: 1px solid var(--border2); }
    .anom-label { font-size: .82rem; color: var(--text); line-height: 1.5; font-weight: 500; }
    .anom-msg { color: var(--text2); font-size: .78rem; line-height: 1.5; margin-top: 2px; }
    /* Correctif cliquable : fond neutre foncé, texte lisible, accent sur la bordure */
    .anom-fix {
    margin-top: 7px; font-size: .73rem;
    color: var(--text); background: var(--bg3);
    padding: 6px 30px 6px 10px; border-radius: 5px;
    border: 1px solid var(--border2); border-left: 3px solid var(--accent);
    cursor: pointer; font-family: var(--font-mono); white-space: pre-wrap; word-break: break-all;
    position: relative; transition: border-color .15s, background .15s;
    }
    .anom-fix::after { content: '📋'; position: absolute; right: 7px; top: 5px; font-size: .68rem; opacity: .5; }
    .anom-fix:hover { background: var(--bg2); border-left-color: var(--ok); }

    /* ── DIFF VIEW ── */
    .diff-selector { display: flex; gap: 10px; margin-bottom: 14px; flex-wrap: wrap; align-items: center; }
    .diff-selector select { background: var(--bg3); color: var(--text); border: 1px solid var(--border2); border-radius: 6px; padding: 6px 10px; font-family: var(--font-mono); font-size: .82rem; cursor: pointer; }
    .diff-selector select:focus { outline: none; border-color: var(--accent); }
    .diff-table { width: 100%; border-collapse: collapse; font-size: .78rem; }
    .diff-table th { background: var(--bg3); color: var(--text2); padding: 7px 11px; text-align: left; font-weight: 600; border-bottom: 1px solid var(--border2); }
    .diff-table td { padding: 9px 11px; border-bottom: 1px solid var(--border); vertical-align: top; }
    .diff-table tr:hover td { background: var(--bg3); }
    /* Catégorie diff : neutre, pas de fond coloré */
    .diff-cat { font-size: .68rem; background: var(--bg3); color: var(--text3); padding: 2px 6px; border-radius: 4px; border: 1px solid var(--border2); }
    /* Valeurs diff A/B : fond neutre subtil, texte lisible — pas de vert/orange vif */
    .diff-val-a { background: var(--warn-bg); color: var(--text); font-weight: 500; border-radius: 3px; }
    .diff-val-b { background: var(--ok-bg);   color: var(--text); font-weight: 500; border-radius: 3px; }

    /* ── DETAIL MACHINE ── */
    .detail-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(230px,1fr)); gap: 10px; margin-bottom: 14px; }
    .detail-stat { background: var(--card2); border: 1px solid var(--border); border-radius: 7px; padding: 10px 13px; }
    .detail-stat-label { font-size: .67rem; color: var(--text2); text-transform: uppercase; letter-spacing: .07em; margin-bottom: 3px; }
    .detail-stat-value { font-size: .88rem; font-weight: 600; color: var(--text); word-break: break-all; font-family: var(--font-mono); }
    /* Indicateurs état : icône ✓/✗ porte la couleur, le texte reste lisible */
    .detail-stat-value.ok   { color: var(--text); }
    .detail-stat-value.crit { color: var(--crit); }
    .detail-stat-value.warn { color: var(--warn); }
    .detail-stat-value.missing { color: var(--text3); font-style: italic; font-weight: 400; }

    .kv-table { width: 100%; border-collapse: collapse; font-size: .78rem; }
    .kv-table td { padding: 5px 9px; border-bottom: 1px solid var(--border); }
    .kv-table td:first-child { color: var(--text2); width: 40%; font-weight: 500; }
    .kv-table td:last-child { color: var(--text); word-break: break-all; font-family: var(--font-mono); font-size: .75rem; }
    .kv-table tr:hover td { background: var(--bg3); }

    /* ── MACHINE TABS ── */
    .machine-tabs { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 14px; }
    .machine-tab-btn { padding: 6px 13px; border-radius: 6px; cursor: pointer; font-size: .82rem; font-weight: 600; border: 1px solid var(--border2); background: var(--bg3); color: var(--text2); transition: all .15s; }
    .machine-tab-btn:hover { border-color: var(--accent); color: var(--accent); }
    .machine-tab-btn.active { background: var(--accent); color: #fff; border-color: var(--accent); }

    /* ── SIDEBAR NAV PARTAGÉE ── */
    .sidebar-layout {
    display: grid; grid-template-columns: 200px 1fr; gap: 16px; align-items: start;
    }
    .sidebar-nav {
    position: sticky; top: 60px;
    background: var(--card); border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden;
    }
    .sidebar-nav-title {
    padding: 9px 13px; font-size: .7rem; font-weight: 700; text-transform: uppercase;
    letter-spacing: .06em; color: var(--text3); background: var(--card2); border-bottom: 1px solid var(--border);
    }
    .sidebar-nav-item {
    padding: 9px 13px; cursor: pointer; font-size: .82rem; font-weight: 500; color: var(--text2);
    border-bottom: 1px solid var(--border); transition: background .12s;
    display: flex; align-items: center; gap: 8px;
    }
    .sidebar-nav-item:last-child { border-bottom: none; }
    .sidebar-nav-item:hover { background: var(--bg3); color: var(--text); }
    .sidebar-nav-item.active { background: var(--bg3); color: var(--accent); font-weight: 700; border-left: 3px solid var(--accent); padding-left: 10px; }
    .sidebar-nav-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
    .sidebar-nav-dot.crit { background: var(--crit); }
    .sidebar-nav-dot.warn { background: var(--warn); }
    .sidebar-nav-dot.ok   { background: var(--ok); }
    @media (max-width: 860px) {
    .sidebar-layout { grid-template-columns: 1fr; }
    .sidebar-nav { position: static; }
    }

    /* ── TOAST ── */
    .toast { position: fixed; bottom: 22px; right: 22px; z-index: 9999; background: var(--ok); color: #fff; font-weight: 700; padding: 9px 18px; border-radius: 7px; font-size: .82rem; opacity: 0; transform: translateY(8px); transition: opacity .25s, transform .25s; pointer-events: none; }
    .toast.show { opacity: 1; transform: none; }

    /* ── LEGEND ── */
    .legend { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 14px; }
    .legend-item { display: flex; align-items: center; gap: 5px; font-size: .73rem; color: var(--text2); }
    .legend-dot { width: 9px; height: 9px; border-radius: 2px; }

    /* ── MISC ── */
    .highlight { background: rgba(210,153,34,.3); border-radius: 2px; }
    ::-webkit-scrollbar { width: 5px; height: 5px; }
    ::-webkit-scrollbar-track { background: var(--bg2); }
    ::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 3px; }
    ::-webkit-scrollbar-thumb:hover { background: var(--accent2); }

    @media (max-width: 768px) {
    .topbar { padding: 7px 10px; gap: 7px; }
    .content { padding: 10px; }
    .machine-grid { grid-template-columns: 1fr; }
    .detail-grid  { grid-template-columns: 1fr; }
    .exec-date { display: none; }
    }
    @media print {
    * { -webkit-print-color-adjust: exact !important; print-color-adjust: exact !important; }
    body { background: #fff !important; color: #000 !important; font-size: 11px; }
    .topbar, .nav-tabs, .exec-banner, .topbar-actions { display: none !important; }
    .tab-panel { display: block !important; page-break-before: always; }
    .tab-panel:first-of-type { page-break-before: avoid; }
    .card { box-shadow: none !important; border: 1px solid #ccc !important; margin-bottom: 6px !important; page-break-inside: avoid; }
    .card-body { display: block !important; }
    .card.collapsed .card-body { display: block !important; }
    .card-toggle { display: none !important; }
    .machine-tabs { display: none !important; }
    .print-only { display: block !important; }
    }
    .print-only { display: none; }
    </style>
    </head>
    <body>

    <!-- BANDEAU EXECUTIF -->
    <div class="exec-banner" id="exec-banner">
    <span class="exec-banner-title">🖥 CPR</span>
    <span id="exec-pill-crit" class="exec-pill crit" style="display:none"></span>
    <span id="exec-pill-warn" class="exec-pill warn" style="display:none"></span>
    <span id="exec-pill-ok"   class="exec-pill ok"   style="display:none"></span>
    <span id="exec-pill-machines" class="exec-pill info"></span>
    <span class="exec-date" id="exec-date">##RUNDATE##</span>
    </div>

    <!-- TOPBAR -->
    <div class="topbar">
    <div class="topbar-brand">Compare-PCReports <span>v##VERSION##</span></div>
    <div class="topbar-search">
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
    <input type="text" id="searchInput" placeholder="Rechercher machine, IP, anomalie..." autocomplete="off">
    </div>
    <div class="topbar-actions">
    <button class="btn" onclick="exportCsvFromJs()">⬇ CSV</button>
    <button class="btn btn-accent" onclick="printReport()">🖨 Imprimer</button>
    <button class="btn" onclick="toggleTheme()" id="themeBtn" title="Changer thème">🌙</button>
    </div>
    </div>

    <!-- NAV TABS -->
    <div class="nav-tabs">
    <div class="nav-tab active" data-tab="resume">📋 Résumé technicien</div>
    <div class="nav-tab" data-tab="synthese">Synthèse</div>
    <div class="nav-tab" data-tab="matrice">Matrice réseau</div>
    <div class="nav-tab" data-tab="anomalies">Anomalies &amp; Correctifs <span class="tab-badge" id="badge-anom">0</span></div>
    <div class="nav-tab" data-tab="diff">Différentiel</div>
    <div class="nav-tab" data-tab="machines">Détail machines</div>
    <div class="nav-tab" data-tab="connectivite">Connectivité <span class="tab-badge" id="badge-conn">?</span></div>
    </div>

    <div class="content">

    <!-- ═══ RESUME TECHNICIEN ═══ -->
    <div class="tab-panel active" id="tab-resume">
    <div id="resume-area"></div>
    </div>

    <!-- ═══ SYNTHESE ═══ -->
    <div class="tab-panel" id="tab-synthese">
    <div id="synthese-grid" class="machine-grid"></div>
    </div>

    <!-- ═══ MATRICE ═══ -->
    <div class="tab-panel" id="tab-matrice">
    <div class="card" style="margin-bottom:14px">
    <div class="card-header" onclick="toggleCard(this)">
    <div class="card-title">🌐 Matrice de connectivité réseau</div>
    <div class="card-toggle">▼</div>
    </div>
    <div class="card-body">
    <div class="legend">
    <div class="legend-item"><div class="legend-dot" style="background:var(--ok)"></div> OK — Session SMB active</div>
    <div class="legend-item"><div class="legend-dot" style="background:var(--warn)"></div> WARN — Session avec anomalies</div>
    <div class="legend-item"><div class="legend-dot" style="background:var(--info)"></div> NO_SESS — Visible sans session</div>
    <div class="legend-item"><div class="legend-dot" style="background:var(--unkn)"></div> UNKN — Données insuffisantes</div>
    </div>
    <div class="matrix-wrap"><table class="matrix-table" id="matrix-table"></table></div>
    </div>
    </div>
    <div class="card">
    <div class="card-header" onclick="toggleCard(this)">
    <div class="card-title">🔗 État des liaisons paire par paire <span id="conn-list-badge" class="tab-badge" style="margin-left:6px"></span></div>
    <div class="card-toggle">▼</div>
    </div>
    <div class="card-body" style="padding:0">
    <div id="conn-list-area"></div>
    </div>
    </div>
    </div>

    <!-- ═══ ANOMALIES + CORRECTIFS (fusionnés) ═══ -->
    <div class="tab-panel" id="tab-anomalies">
    <div id="anomalies-correctifs-area"></div>
    </div>

    <!-- ═══ DIFF ═══ -->
    <div class="tab-panel" id="tab-diff">
    <div class="diff-selector">
    <span style="color:var(--text2);font-size:.85rem;">Comparer</span>
    <select id="diffSelA" onchange="renderDiff()"></select>
    <span style="color:var(--text2)">↔</span>
    <select id="diffSelB" onchange="renderDiff()"></select>
    </div>
    <div class="card">
    <div class="card-header" onclick="toggleCard(this)">
    <div class="card-title">🔄 Différentiel entre les deux machines</div>
    <div class="card-toggle">▼</div>
    </div>
    <div class="card-body" style="padding:0;overflow-x:auto">
    <table class="diff-table" id="diff-table">
    <thead><tr>
    <th style="width:110px">Catégorie</th><th>Champ</th>
    <th id="diff-head-a">Machine A</th><th id="diff-head-b">Machine B</th><th>Impact</th>
    </tr></thead>
    <tbody id="diff-tbody"></tbody>
    </table>
    </div>
    </div>
    </div>

    <!-- ═══ MACHINES ═══ -->
    <div class="tab-panel" id="tab-machines">
    <div class="machine-tabs" id="machine-tabs"></div>
    <div id="machine-detail-area"></div>
    </div>

    <!-- ═══ CONNECTIVITE ═══ -->
    <div class="tab-panel" id="tab-connectivite">
    <div class="card" style="margin-bottom:14px">
    <div class="card-header" onclick="toggleCard(this)">
    <div class="card-title">🗂️ Plan d'action par machine</div>
    <div class="card-toggle">▼</div>
    </div>
    <div class="card-body" style="padding:0"><div id="action-plan-area"></div></div>
    </div>
    <div class="card">
    <div class="card-header" onclick="toggleCard(this)">
    <div class="card-title">📡 Détail connectivité paire par paire</div>
    <div class="card-toggle">▼</div>
    </div>
    <div class="card-body" style="padding:0"><div id="conn-report-area"></div></div>
    </div>
    </div>

    </div><!-- /content -->

    <div class="toast" id="toast">✅ Copié dans le presse-papier</div>

    <script>
    // ═══════════════════════════════════════════
    // DONNÉES
    // ═══════════════════════════════════════════
    const MACHINES = ##MACHINES_JSON##;
    const MATRIX   = ##MATRIX_JSON##;
    const DIFFS    = ##DIFFS_JSON##;

    // ═══════════════════════════════════════════
    // LIBELLÉS LISIBLES (codes → texte humain)
    // ═══════════════════════════════════════════
    const CODE_LABELS = {
    VPN_ACTIF:          'VPN actif — perturbe le réseau local',
    DNS_VPN:            'DNS VPN — résolution de noms défaillante',
    INVITE_ACTIF:       'Compte Invité activé — risque de sécurité',
    INVITE_SMB:         'Connexions SMB sous compte Invité détectées',
    AUTH_4625_ELEVE:    'Nombreux échecs de connexion (mauvais mot de passe en cache)',
    SMBv1_ACTIF:        'Protocole réseau obsolète activé (SMBv1)',
    SMB_SIG_SERVEUR:    'Signature SMB non obligatoire (côté serveur)',
    SMB_SIG_CLIENT:     'Signature SMB non obligatoire (côté client)',
    LLMNR_ACTIF:        'LLMNR actif — risque d\'interception réseau',
    FW_445_MANQUANT:    'Règle pare-feu port 445 manquante',
    LANMAN_ARRETE:      'Service partage réseau arrêté (LanmanServer)',
    SHARE_EVERYONE:     'Partages accessibles par tout le monde',
    CRED_MANQUANT:      'Identifiants SMB manquants en cache',
    COMPTE_ABSENT_CIBLE:'Compte utilisateur absent sur machine cible',
    ADMIN_ACTIF:        'Compte Administrateur intégré actif',
    };

    function getLabel(code) { return CODE_LABELS[code] || code; }

    // ═══════════════════════════════════════════
    // THÈME
    // ═══════════════════════════════════════════
    function toggleTheme() {
    const html = document.documentElement;
    const isDark = html.getAttribute('data-theme') === 'dark';
    html.setAttribute('data-theme', isDark ? 'light' : 'dark');
    document.getElementById('themeBtn').textContent = isDark ? '🌙' : '☀️';
    localStorage.setItem('cpr-theme', isDark ? 'light' : 'dark');
    }
    (function initTheme() {
    const saved = localStorage.getItem('cpr-theme') || 'dark';
    document.documentElement.setAttribute('data-theme', saved);
    document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('themeBtn').textContent = saved === 'dark' ? '☀️' : '🌙';
    });
    })();

    // ═══════════════════════════════════════════
    // TABS
    // ═══════════════════════════════════════════
    document.querySelectorAll('.nav-tab').forEach(tab => {
    tab.addEventListener('click', () => {
    document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById('tab-' + tab.dataset.tab).classList.add('active');
    });
    });
    function toggleCard(h) { h.closest('.card').classList.toggle('collapsed'); }
    function sidebarScrollTo(id, el) {
    el.closest('.sidebar-nav').querySelectorAll('.sidebar-nav-item').forEach(x => x.classList.remove('active'));
    el.classList.add('active');
    const target = document.getElementById(id);
    if (target) target.scrollIntoView({behavior:'smooth', block:'start'});
    }

    // ═══════════════════════════════════════════
    // SIDEBAR NAV PARTAGÉE
    // ═══════════════════════════════════════════
    function renderSidebar(prefix) {
    let html = `<div class="sidebar-nav">
    <div class="sidebar-nav-title">Machines</div>`;
    MACHINES.forEach((m, i) => {
    const dotCls = m.nbCrit > 0 ? 'crit' : m.nbWarn > 0 ? 'warn' : 'ok';
    const count  = m.nbCrit > 0 ? m.nbCrit + ' crit.' : m.nbWarn > 0 ? m.nbWarn + ' avert.' : 'OK';
    html += `<div class="sidebar-nav-item${i===0?' active':''}" onclick="sidebarScrollTo('${prefix}-${esc(m.name)}', this)">
    <span class="sidebar-nav-dot ${dotCls}"></span>
    <span style="flex:1">${esc(m.name)}</span>
    <span style="font-size:.68rem;color:var(--text3)">${esc(count)}</span>
    </div>`;
    });
    html += '</div>';
    return html;
    }

    // ═══════════════════════════════════════════
    // HELPERS
    // ═══════════════════════════════════════════
    function scoreClass(m) {
    if (m.nbCrit > 0) return 'CRITIQUE';
    if (m.nbWarn > 0) return 'WARNING';
    return 'OK';
    }
    function scoreEmoji(s) { return s==='CRITIQUE'?'❌':s==='WARNING'?'⚠️':'✅'; }
    function boolIcon(v)    { return v ? '<span style="color:var(--crit)">✗</span>' : '<span style="color:var(--ok)">✓</span>'; }
    function boolIconInv(v) { return v ? '<span style="color:var(--ok)">✓</span>'  : '<span style="color:var(--warn)">✗</span>'; }
    function esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
    function showToast(msg) {
    const t = document.getElementById('toast');
    t.textContent = msg || '✅ Copié';
    t.classList.add('show');
    setTimeout(() => t.classList.remove('show'), 2200);
    }
    function copyText(txt) {
    if (navigator.clipboard) {
    navigator.clipboard.writeText(txt).then(() => showToast('✅ Copié dans le presse-papier'));
    } else {
    const ta = document.createElement('textarea');
    ta.value = txt; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta);
    showToast('✅ Copié');
    }
    }
    function valDisplay(v) {
    if (v === '' || v === null || v === undefined) return '<span class="missing">Non collecté</span>';
    return esc(v);
    }

    // ═══════════════════════════════════════════
    // BANDEAU EXÉCUTIF
    // ═══════════════════════════════════════════
    function renderExecBanner() {
    let totalCrit = 0, totalWarn = 0;
    MACHINES.forEach(m => { totalCrit += m.nbCrit; totalWarn += m.nbWarn; });
    const pc = document.getElementById('exec-pill-crit');
    const pw = document.getElementById('exec-pill-warn');
    const po = document.getElementById('exec-pill-ok');
    const pm = document.getElementById('exec-pill-machines');
    pm.textContent = `🖥 ${MACHINES.length} machine(s)`;
    if (totalCrit > 0) { pc.textContent = `❌ ${totalCrit} critique(s)`; pc.style.display = ''; }
    if (totalWarn > 0) { pw.textContent = `⚠️ ${totalWarn} avert.`;      pw.style.display = ''; }
    if (totalCrit === 0 && totalWarn === 0) { po.textContent = '✅ Aucun problème'; po.style.display = ''; }
    // Dates rapport par machine
    const dates = MACHINES.filter(m => m.reportDate).map(m => `${m.name}: ${m.reportDate}`).join(' — ');
    if (dates) {
    const el = document.getElementById('exec-date');
    el.title = dates;
    el.textContent = 'Rapports : ' + dates;
    }
    }

    // ═══════════════════════════════════════════
    // SYNTHESE
    // ═══════════════════════════════════════════
    function renderSynthese() {
    const grid = document.getElementById('synthese-grid');
    grid.innerHTML = '';
    MACHINES.forEach(m => {
    const sc = scoreClass(m);
    const tags = [];
    if (m.hasVpn)      tags.push('<span class="tag tag-vpn">VPN</span>');
    if (m.inviteActif) tags.push('<span class="tag tag-inv">Invité actif</span>');
    if (m.dnsIsVpn)    tags.push('<span class="tag tag-dns">DNS VPN</span>');
    if (!m.hasVpn && !m.inviteActif && !m.dnsIsVpn && m.nbCrit===0) tags.push('<span class="tag tag-ok">Clean</span>');
    const ipDisplay = m.ip
    ? `📍 ${esc(m.ip)}`
    : `📍 <span class="missing">IP non collectée</span>`;
    const dnsDisplay = m.dns
    ? `DNS: ${esc(m.dns)}`
    : `DNS: <span class="missing">non collecté</span>`;
    const card = document.createElement('div');
    card.className = 'machine-card ' + (sc==='CRITIQUE'?'crit':sc==='WARNING'?'warn':'ok');
    card.innerHTML = `
    <div class="machine-name">${esc(m.name)}</div>
    <div class="machine-meta">${ipDisplay} &nbsp;|&nbsp; ${dnsDisplay}</div>
    <div class="machine-tags">${tags.join('')}</div>
    <div style="margin-bottom:8px"><span class="score ${sc}">${scoreEmoji(sc)} ${sc}</span></div>
    <div class="machine-counters">
    <div class="counter crit"><div class="counter-val">${m.nbCrit}</div><div class="counter-lbl">Critique</div></div>
    <div class="counter warn"><div class="counter-val">${m.nbWarn}</div><div class="counter-lbl">Warning</div></div>
    <div class="counter info"><div class="counter-val">${m.nbInfo}</div><div class="counter-lbl">Info</div></div>
    </div>
    <div style="margin-top:8px;font-size:.7rem;color:var(--text2)">
    SMB→ ${m.smbTargets.length>0?m.smbTargets.join(', '):'aucune session'} &nbsp;|&nbsp; 4625: ${m.echecs4625}
    </div>
    ${m.reportDate ? `<div class="machine-date">📅 Rapport du ${esc(m.reportDate)}</div>` : ''}`;
    card.addEventListener('click', () => {
    document.querySelector('[data-tab="machines"]').click();
    selectMachine(m.name);
    });
    grid.appendChild(card);
    });
    }

    // ═══════════════════════════════════════════
    // MATRICE
    // ═══════════════════════════════════════════
    function renderMatrix() {
    const tbl = document.getElementById('matrix-table');
    const names = MACHINES.map(m => m.name);
    let html = '<thead><tr><th class="row-header">SOURCE \\ CIBLE</th>';
    names.forEach(n => { html += `<th>${esc(n)}</th>`; });
    html += '</tr></thead><tbody>';
    names.forEach(src => {
    html += `<tr><th class="row-header" style="text-align:left">${esc(src)}</th>`;
    names.forEach(dst => {
    const cell = (MATRIX[src]&&MATRIX[src][dst]) ? MATRIX[src][dst] : {statut:'UNKN',detail:''};
    html += `<td class="matrix-cell cell-${cell.statut}" title="${esc(cell.detail)}" onclick="showMatrixDetail('${esc(src)}','${esc(dst)}')">${cell.statut}</td>`;
    });
    html += '</tr>';
    });
    html += '</tbody>';
    tbl.innerHTML = html;
    }
    function showMatrixDetail(src, dst) {
    if (src === dst) return;
    document.querySelector('[data-tab="diff"]').click();
    const selA = document.getElementById('diffSelA');
    const selB = document.getElementById('diffSelB');
    for (let i=0; i<selA.options.length; i++) {
    if (selA.options[i].value === src) selA.selectedIndex = i;
    if (selB.options[i].value === dst) selB.selectedIndex = i;
    }
    renderDiff();
    }

    // ═══════════════════════════════════════════
    // TABLEAU LIAISONS PAIRE PAR PAIRE
    // ═══════════════════════════════════════════
    function renderConnectionsTable() {
    const area = document.getElementById('conn-list-area');
    if (!area) return;

    const SORT = { 'NO_SESS':0, 'AUTH_FAIL':0, 'WARN':1, 'UNKN':2, 'OK':3 };
    const pairs = [];

    MACHINES.forEach(src => {
    MACHINES.forEach(dst => {
    if (src.name === dst.name) return;
    const cell = (MATRIX[src.name] && MATRIX[src.name][dst.name])
    ? MATRIX[src.name][dst.name]
    : { statut: 'UNKN', detail: 'Aucune donnée de connexion' };
    if (cell.statut === 'SELF') return;
    pairs.push({ src: src.name, dst: dst.name, statut: cell.statut, detail: cell.detail || '' });
    });
    });

    pairs.sort((a, b) => (SORT[a.statut] ?? 2) - (SORT[b.statut] ?? 2));

    const okCount   = pairs.filter(p => p.statut === 'OK').length;
    const warnCount = pairs.filter(p => p.statut === 'WARN').length;
    const koCount   = pairs.filter(p => p.statut === 'NO_SESS' || p.statut === 'AUTH_FAIL').length;
    const unknCount = pairs.filter(p => p.statut === 'UNKN').length;

    // Badge global dans le titre du card
    const badge = document.getElementById('conn-list-badge');
    if (badge) {
    if (koCount > 0)       { badge.textContent = koCount + ' KO'; badge.className = 'tab-badge'; }
    else if (warnCount > 0){ badge.textContent = warnCount + ' ⚠'; badge.className = 'tab-badge warn'; }
    else                   { badge.textContent = '✓'; badge.className = 'tab-badge ok'; }
    }

    function statusHtml(statut) {
    switch (statut) {
    case 'OK':        return '<span class="conn-status ok">✅ OK</span>';
    case 'WARN':      return '<span class="conn-status warn">⚠️ Partiel</span>';
    case 'NO_SESS':   return '<span class="conn-status nosess">🔵 Visible — pas de session</span>';
    case 'AUTH_FAIL': return '<span class="conn-status fail">❌ Échec auth</span>';
    default:          return '<span class="conn-status unkn">❓ Inconnu</span>';
    }
    }

    let html = `<div class="conn-summary">`;
    if (koCount)   html += `<span class="conn-sum-pill" style="color:var(--crit)">❌ ${koCount} KO</span>`;
    if (warnCount) html += `<span class="conn-sum-pill" style="color:var(--warn)">⚠️ ${warnCount} partiel(s)</span>`;
    if (okCount)   html += `<span class="conn-sum-pill" style="color:var(--ok)">✅ ${okCount} OK</span>`;
    if (unknCount) html += `<span class="conn-sum-pill" style="color:var(--text3)">❓ ${unknCount} inconnu(s)</span>`;
    html += `</div>`;

    html += `<table class="conn-list-table">
    <thead><tr>
    <th>Source</th>
    <th></th>
    <th>Destination</th>
    <th>État</th>
    <th>Détail</th>
    </tr></thead>
    <tbody>`;

    pairs.forEach(p => {
    html += `<tr>
    <td><span class="conn-machine">${esc(p.src)}</span></td>
    <td><span class="conn-arrow">→</span></td>
    <td><span class="conn-machine">${esc(p.dst)}</span></td>
    <td>${statusHtml(p.statut)}</td>
    <td><span class="conn-detail">${esc(p.detail)}</span></td>
    </tr>`;
    });

    html += '</tbody></table>';
    area.innerHTML = html;
    }


    function renderAnomaliesCorrectifs(filter) {
    const area = document.getElementById('anomalies-correctifs-area');
    let allAnoms = [];
    MACHINES.forEach(m => m.anomalies.forEach(a => allAnoms.push({...a, machineName: m.name})));
    allAnoms.sort((a,b) => ({'CRITIQUE':0,'WARNING':1,'INFO':2}[a.severite]||9) - ({'CRITIQUE':0,'WARNING':1,'INFO':2}[b.severite]||9));

    if (filter) {
    const q = filter.toLowerCase();
    allAnoms = allAnoms.filter(a =>
    a.machineName.toLowerCase().includes(q) ||
    a.code.toLowerCase().includes(q) ||
    a.message.toLowerCase().includes(q) ||
    getLabel(a.code).toLowerCase().includes(q)
    );
    }

    if (allAnoms.length === 0) {
    area.innerHTML = '<div class="card"><div class="card-body" style="text-align:center;padding:40px;color:var(--text3)">✅ Aucune anomalie — Aucun correctif nécessaire</div></div>';
    return;
    }

    // Grouper par sévérité
    const grouped = {};
    allAnoms.forEach(a => {
    if (!grouped[a.severite]) grouped[a.severite] = [];
    grouped[a.severite].push(a);
    });

    let html = '';
    ['CRITIQUE','WARNING','INFO'].forEach(sev => {
    if (!grouped[sev]) return;
    html += `
    <div class="card">
    <div class="card-header" onclick="toggleCard(this)">
    <div class="card-title"><span class="score ${sev}">${scoreEmoji(sev)} ${sev}</span> &nbsp; ${grouped[sev].length} élément(s)</div>
    <div class="card-toggle">▼</div>
    </div>
    <div class="card-body" style="padding:0;overflow-x:auto">
    <table class="anom-table">
    <thead><tr><th>Machine</th><th>Sévérité</th><th>Problème</th><th>Diagnostic &amp; Correctif</th></tr></thead>
    <tbody>`;
    grouped[sev].forEach(a => {
    html += `
    <tr>
    <td><span class="anom-machine">${esc(a.machineName)}</span></td>
    <td><span class="score ${a.severite}">${scoreEmoji(a.severite)} ${a.severite}</span></td>
    <td>
    <div class="anom-label">${esc(getLabel(a.code))}</div>
    <span class="anom-code">${esc(a.code)}</span>
    </td>
    <td>
    <div class="anom-msg">${esc(a.message)}</div>
    <div class="anom-fix" onclick="copyText(this.dataset.cmd)" data-cmd="${esc(a.correctif)}" title="Cliquer pour copier">${esc(a.correctif)}</div>
    </td>
    </tr>`;
    });
    html += '</tbody></table></div></div>';
    });
    area.innerHTML = html;
    }

    // ═══════════════════════════════════════════
    function generateResume() {
    const area = document.getElementById('resume-area');
    if (!area) return;

    const nbMachines = MACHINES.length;
    const allAnoms = [];
    MACHINES.forEach(m => m.anomalies.forEach(a => allAnoms.push({...a, machineName: m.name})));
    const nbCrit = allAnoms.filter(a => a.severite === 'CRITIQUE').length;
    const nbWarn = allAnoms.filter(a => a.severite === 'WARNING').length;

    let situationEmoji = nbCrit > 0 ? '🔴' : nbWarn > 0 ? '🟠' : '🟢';
    let situationTexte;
    if (nbCrit === 0 && nbWarn === 0) {
    situationTexte = `Les ${nbMachines} machines analysées ne présentent aucun problème bloquant.`;
    } else if (nbCrit === 0) {
    situationTexte = `Les ${nbMachines} machines fonctionnent globalement bien, mais ${nbWarn} point(s) de vigilance méritent attention.`;
    } else {
    situationTexte = `L'analyse révèle ${nbCrit} problème(s) critique(s) sur ${nbMachines} machines qui expliquent les difficultés de communication réseau.`;
    }

    const okPairs = [], failPairs = [], warnPairs = [];
    MACHINES.forEach(src => {
    MACHINES.forEach(dst => {
    if (src.name === dst.name) return;
    const cell = (MATRIX[src.name]&&MATRIX[src.name][dst.name]) ? MATRIX[src.name][dst.name] : {statut:'UNKN'};
    if (cell.statut==='OK') okPairs.push(src.name+' → '+dst.name);
    else if (cell.statut==='WARN') warnPairs.push(src.name+' → '+dst.name);
    else if (cell.statut!=='SELF') failPairs.push(src.name+' → '+dst.name);
    });
    });

    const machinesSummary = MACHINES.map(m => {
    const lines = [];
    m.anomalies.forEach(a => {
    lines.push({
    sev: a.severite, icon: a.severite==='CRITIQUE'?'❌':'⚠️',
    titre: getLabel(a.code),
    code: a.code,
    explication: a.message,
    action: a.correctif
    });
    });
    return { machine: m, lines, nbCrit: m.nbCrit, nbWarn: m.nbWarn };
    });

    const machinesParImpact = [...MACHINES].sort((a,b) => {
    const ai = (a.inviteActif?10:0)+(a.echecs4625>=10?5:0);
    const bi = (b.inviteActif?10:0)+(b.echecs4625>=10?5:0);
    return bi - ai;
    });
    const ordreIntervention = [];
    machinesParImpact.forEach((m, idx) => {
    const steps = [];
    if (m.inviteActif) steps.push('Désactiver le compte Invité (impact immédiat sur toutes les connexions entrantes)');
    if (m.echecs4625 >= 10) steps.push(`Vider les credentials en cache (${m.echecs4625} échecs 4625 enregistrés)`);
    if (m.hasVpn) steps.push('Désactiver le VPN pour les tests SMB');
    if (m.smbv1) steps.push('Désactiver SMBv1');
    if (steps.length > 0) ordreIntervention.push({ name: m.name, ip: m.ip, steps, ordre: idx+1 });
    });

    let html = `
    <div style="padding:18px 22px;background:linear-gradient(135deg,var(--card2),var(--card));border-bottom:2px solid var(--border);border-radius:var(--radius);margin-bottom:14px">
    <div style="font-size:1.3rem;font-weight:700;margin-bottom:7px">${situationEmoji} Situation générale</div>
    <div style="font-size:.92rem;line-height:1.7;color:var(--text);max-width:820px">${situationTexte}</div>
    <div style="display:flex;gap:12px;margin-top:12px;flex-wrap:wrap">
    ${nbCrit>0?`<span style="background:var(--crit);color:#fff;padding:3px 12px;border-radius:20px;font-weight:700;font-size:.82rem">${nbCrit} critique(s)</span>`:''}
    ${nbWarn>0?`<span style="background:var(--warn);color:#fff;padding:3px 12px;border-radius:20px;font-weight:700;font-size:.82rem">${nbWarn} avert.</span>`:''}
    ${okPairs.length>0?`<span style="background:var(--ok);color:#fff;padding:3px 12px;border-radius:20px;font-weight:700;font-size:.82rem">${okPairs.length} liaison(s) OK</span>`:''}
    ${failPairs.length>0?`<span style="background:var(--crit);color:#fff;padding:3px 12px;border-radius:20px;font-weight:700;font-size:.82rem">${failPairs.length} liaison(s) KO</span>`:''}
    </div>
    </div>`;

    if (okPairs.length>0||failPairs.length>0||warnPairs.length>0) {
    html += `<div class="card" style="margin-bottom:14px"><div class="card-header" onclick="toggleCard(this)"><div class="card-title">🔗 État des liaisons réseau</div><div class="card-toggle">▼</div></div><div class="card-body">`;
    if (okPairs.length>0)   html += `<div style="margin-bottom:5px"><span style="color:var(--ok);font-weight:600">✅ Fonctionnelles :</span> <span style="color:var(--text)">${okPairs.join(' &nbsp;•&nbsp; ')}</span></div>`;
    if (warnPairs.length>0) html += `<div style="margin-bottom:5px"><span style="color:var(--warn);font-weight:600">⚠️ Partielles :</span> <span style="color:var(--text)">${warnPairs.join(' &nbsp;•&nbsp; ')}</span></div>`;
    if (failPairs.length>0) html += `<div style="margin-bottom:5px"><span style="color:var(--crit);font-weight:600">❌ En échec :</span> <span style="color:var(--text)">${failPairs.join(' &nbsp;•&nbsp; ')}</span></div>`;
    html += '</div></div>';
    }

    if (ordreIntervention.length>0) {
    html += `<div class="card" style="margin-bottom:14px"><div class="card-header" onclick="toggleCard(this)"><div class="card-title">🗓️ Ordre d'intervention recommandé</div><div class="card-toggle">▼</div></div><div class="card-body">
    <div style="font-size:.78rem;color:var(--text3);margin-bottom:10px">Trié par impact — en premier = débloque le plus de liaisons</div>`;
    ordreIntervention.forEach(o => {
    html += `<div style="display:flex;gap:10px;margin-bottom:9px;padding:9px 13px;background:var(--card2);border-radius:7px;align-items:flex-start;border:1px solid var(--border)">
    <div style="font-size:1.3rem;font-weight:900;color:var(--accent);flex-shrink:0;min-width:26px">${o.ordre}</div>
    <div>
    <div style="font-weight:700;font-size:.9rem">Intervenir sur <span style="color:var(--accent)">${esc(o.name)}</span>
    ${o.ip ? `<span style="color:var(--text3);font-size:.75rem;font-family:var(--font-mono)"> (${esc(o.ip)})</span>` : ''}
    </div>
    ${o.steps.map(s=>`<div style="font-size:.8rem;color:var(--text);margin-top:3px">→ ${esc(s)}</div>`).join('')}
    </div>
    </div>`;
    });
    html += '</div></div>';
    }

    machinesSummary.forEach(ms => {
    html += `<div class="card" id="resume-card-${esc(ms.machine.name)}" style="margin-bottom:14px;scroll-margin-top:70px">
    <div class="card-header" onclick="toggleCard(this)">
    <div class="card-title">🖥 ${esc(ms.machine.name)}
    ${ms.machine.ip
    ? `<span style="font-family:var(--font-mono);font-size:.75rem;color:var(--text3)">${esc(ms.machine.ip)}</span>`
    : `<span style="font-size:.72rem;color:var(--warn);font-weight:600">⚠ IP non collectée</span>`}
    ${ms.nbCrit>0?`<span style="font-size:.7rem;background:var(--crit);color:#fff;padding:1px 7px;border-radius:10px">${ms.nbCrit} critique(s)</span>`:''}
    ${ms.nbWarn>0?`<span style="font-size:.7rem;background:var(--warn);color:#fff;padding:1px 7px;border-radius:10px">${ms.nbWarn} avert.</span>`:''}
    ${ms.machine.reportDate?`<span style="font-size:.68rem;color:var(--text3);font-family:var(--font-mono);margin-left:8px">📅 ${esc(ms.machine.reportDate)}</span>`:''}
    </div>
    <div class="card-toggle">▼</div>
    </div>
    <div class="card-body">`;

    if (ms.lines.length===0) {
    html += `<div style="color:var(--ok);font-size:.88rem">✅ Aucune anomalie. Configuration correcte.</div>`;
    } else {
    ms.lines.forEach(l => {
    html += `<div style="margin-bottom:12px;padding:12px;background:var(--card2);border-radius:8px;border-left:4px solid ${l.sev==='CRITIQUE'?'var(--crit)':'var(--warn)'}">
    <div style="display:flex;gap:7px;align-items:center;margin-bottom:6px">
    <span>${l.icon}</span>
    <span style="font-weight:700;font-size:.88rem">${esc(l.titre)}</span>
    <span class="anom-code">${esc(l.code)}</span>
    </div>
    <div style="font-size:.82rem;line-height:1.6;color:var(--text2);margin-bottom:8px">${esc(l.explication)}</div>
    <div style="font-size:.75rem;font-weight:600;color:var(--text3);margin-bottom:3px">✏️ Correctif :</div>
    <div class="anom-fix" onclick="copyText(this.dataset.cmd)" data-cmd="${esc(l.action)}" title="Cliquer pour copier">${esc(l.action)}</div>
    </div>`;
    });
    }
    html += '</div></div>';
    });
    area.innerHTML = `<div class="sidebar-layout">${renderSidebar('resume-card')}<div>${html}</div></div>`;
    }
    // ═══════════════════════════════════════════
    function initDiffSelectors() {
    const selA = document.getElementById('diffSelA');
    const selB = document.getElementById('diffSelB');
    MACHINES.forEach(m => {
    selA.add(new Option(m.name, m.name));
    selB.add(new Option(m.name, m.name));
    });
    if (MACHINES.length > 1) selB.selectedIndex = 1;
    renderDiff();
    }
    function renderDiff() {
    const selA = document.getElementById('diffSelA').value;
    const selB = document.getElementById('diffSelB').value;
    document.getElementById('diff-head-a').textContent = selA;
    document.getElementById('diff-head-b').textContent = selB;
    const entry = DIFFS.find(d => (d.nameA===selA&&d.nameB===selB)||(d.nameA===selB&&d.nameB===selA));
    const tbody = document.getElementById('diff-tbody');
    if (!entry||entry.diffs.length===0) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;padding:30px;color:var(--text3)">✅ Aucune différence détectée entre ces deux machines</td></tr>`;
    return;
    }
    const reversed = entry.nameA !== selA;
    tbody.innerHTML = entry.diffs.map(d => {
    const vA = reversed ? d.valB : d.valA;
    const vB = reversed ? d.valA : d.valB;
    return `<tr>
    <td><span class="diff-cat">${esc(d.categorie)}</span></td>
    <td style="font-weight:500">${esc(d.champ)}</td>
    <td class="diff-val-a">${esc(vA)}</td>
    <td class="diff-val-b">${esc(vB)}</td>
    <td style="color:var(--text2);font-size:.76rem;font-style:italic">${esc(d.impact)}</td>
    </tr>`;
    }).join('');
    }

    // ═══════════════════════════════════════════
    // DÉTAIL MACHINE
    // ═══════════════════════════════════════════
    function initMachineTabs() {
    const container = document.getElementById('machine-tabs');
    MACHINES.forEach((m, i) => {
    const btn = document.createElement('button');
    btn.className = 'machine-tab-btn' + (i===0?' active':'');
    btn.textContent = m.name;
    btn.addEventListener('click', () => selectMachine(m.name));
    container.appendChild(btn);
    });
    if (MACHINES.length > 0) renderMachineDetail(MACHINES[0]);
    }
    function selectMachine(name) {
    const m = MACHINES.find(x => x.name===name);
    if (!m) return;
    document.querySelectorAll('.machine-tab-btn').forEach(b => b.classList.toggle('active', b.textContent===name));
    renderMachineDetail(m);
    }
    function renderMachineDetail(m) {
    const area = document.getElementById('machine-detail-area');
    const sc = scoreClass(m);
    const ifaceRows = (m.vpnNames||[]).map(v => `<tr><td>Interface VPN</td><td style="color:var(--crit)">${esc(v)}</td></tr>`).join('');

    // Tous les comptes (admin, invité, user, système)
    const accountRows = (m.accounts||[]).map(a => {
    let cls = '';
    if (a.active && a.isInvite) cls = 'crit';
    else if (a.active && a.isAdmin) cls = 'warn';
    else if (!a.active) cls = 'ok';
    const badge = a.isAdmin ? ' <span class="anom-code">ADMIN</span>' : a.isInvite ? ' <span class="anom-code" style="color:var(--crit)">INVITÉ</span>' : a.isSysteme ? ' <span class="anom-code">SYSTÈME</span>' : '';
    return `<tr>
    <td>${esc(a.nom)}${badge}</td>
    <td class="${cls}">${a.active ? '✓ ACTIF' : '✗ inactif'}</td>
    <td style="font-family:var(--font-mono);font-size:.73rem">${esc(a.dernConn||'Jamais')}</td>
    <td><span class="score ${a.risque==='CRITICAL'?'CRITIQUE':a.risque||'UNKN'}">${a.risque||'N/A'}</span></td>
    </tr>`;
    }).join('');

    const shareRows = (m.shares||[]).map(s =>
    `<tr><td>${esc(s.nom)}</td><td style="font-family:var(--font-mono);font-size:.72rem">${esc(s.chemin)}</td><td class="${s.everyoneFull?'warn':''}" style="font-size:.72rem">${esc(s.acces)}</td></tr>`
    ).join('');
    const credRows = (m.storedCreds||[]).map(c => `<tr><td colspan="2">${esc(c)}</td></tr>`).join('');
    const testRows = (m.connTests||[]).map(t => {
    const cls = (t.resultat||'').match(/AVERT|FAIL/i) ? 'crit' : 'ok';
    return `<tr><td style="font-family:var(--font-mono)">${esc(t.cible)}</td><td>${esc(t.ping)}</td><td>${esc(t.port445)}</td><td class="${cls}">${esc(t.resultat)}</td></tr>`;
    }).join('');
    const hostsRows = (m.hostsEntries||[]).slice(0,20).map(h =>
    `<tr><td style="font-family:var(--font-mono)">${esc(h.ip)}</td><td style="font-family:var(--font-mono);font-size:.72rem">${esc(h.hostname)}</td></tr>`
    ).join('');

    function statCell(label, value, cls, suffix) {
    const isEmpty = !value && value !== 0 && value !== false;
    const dispVal = isEmpty
    ? `<span class="detail-stat-value missing">⚠ Non collecté</span>`
    : `<div class="detail-stat-value ${cls||''}">${esc(String(value))}${suffix?` <span style="font-size:.7rem;color:var(--text3)">${suffix}</span>`:''}`;
    return `<div class="detail-stat"><div class="detail-stat-label">${label}</div>${isEmpty ? dispVal : dispVal + '</div>'}</div>`;
    }

    area.innerHTML = `
    <div class="card">
    <div class="card-header">
    <div class="card-title" style="font-size:1rem">
    🖥 ${esc(m.name)}
    <span class="score ${sc}" style="margin-left:7px">${scoreEmoji(sc)} ${sc}</span>
    ${m.reportDate
    ? `<span style="font-size:.7rem;color:var(--text3);font-family:var(--font-mono)">📅 ${esc(m.reportDate)}</span>`
    : `<span style="font-size:.7rem;color:var(--warn);font-family:var(--font-mono)">📅 <span class="missing">Date rapport inconnue</span></span>`}
    </div>
    </div>
    <div class="card-body">
    <div class="detail-grid">
    ${statCell('Adresse IP', m.ip, '', '')}
    ${statCell('DNS', m.dns, m.dnsIsVpn?'crit':'ok', m.dnsIsVpn?'⚠ DNS VPN':'')}
    ${statCell('VPN', m.hasVpn?'✗ ACTIF':'✓ Aucun', m.hasVpn?'crit':'ok', '')}
    ${statCell('Compte Invité', m.inviteActif?'✗ ACTIF':'✓ Désactivé', m.inviteActif?'crit':'ok', '')}
    ${statCell('SMBv1', m.smbv1?'✗ ACTIVÉ':'✓ Désactivé', m.smbv1?'crit':'ok', '')}
    <div class="detail-stat"><div class="detail-stat-label">Échecs 4625 (24h)</div><div class="detail-stat-value ${m.echecs4625>=10?'crit':m.echecs4625>0?'warn':'ok'}">${m.echecs4625}</div></div>
    <div class="detail-stat"><div class="detail-stat-label">Accès SMB Invité</div><div class="detail-stat-value ${m.inviteSmb>0?'crit':'ok'}">${m.inviteSmb}</div></div>
    ${statCell('Sig. SMB Serveur', m.smbSigSrv, (m.smbSigSrv&&m.smbSigSrv.match(/Non/))?'warn':'ok', '')}
    <div class="detail-stat"><div class="detail-stat-label">Pare-feu port 445</div><div class="detail-stat-value ${m.fw445?'ok':'warn'}">${m.fw445?'✓ Ouvert':'✗ Non détecté'}</div></div>
    <div class="detail-stat"><div class="detail-stat-label">LLMNR</div><div class="detail-stat-value ${m.llmnr?'warn':'ok'}">${m.llmnr?'⚠ Actif':'✓ Désactivé'}</div></div>
    ${statCell('LM Compat. Level', m.lmLevel, '', '')}
    <div class="detail-stat"><div class="detail-stat-label">UAC</div><div class="detail-stat-value ${m.uac==='1'?'ok':'warn'}">${m.uac==='1'?'✓ Activé':'✗ Désactivé'}</div></div>
    </div>

    ${ifaceRows ? `
    <div class="card" style="margin-bottom:10px">
    <div class="card-header" onclick="toggleCard(this)"><div class="card-title">🔌 Interfaces VPN</div><div class="card-toggle">▼</div></div>
    <div class="card-body" style="padding:0"><table class="kv-table">${ifaceRows}</table></div>
    </div>` : ''}

    <div class="card" style="margin-bottom:10px">
    <div class="card-header" onclick="toggleCard(this)"><div class="card-title">👤 Comptes locaux</div><div class="card-toggle">▼</div></div>
    <div class="card-body" style="padding:0">
    <table class="kv-table">
    <thead><tr style="background:var(--bg3)">
    <td><b>Compte</b></td><td><b>État</b></td><td><b>Dernière connexion</b></td><td><b>Risque</b></td>
    </tr></thead>
    <tbody>${accountRows||'<tr><td colspan="4" style="color:var(--text3);padding:14px">⚠ Aucun compte collecté</td></tr>'}</tbody>
    </table>
    </div>
    </div>

    <div class="card" style="margin-bottom:10px">
    <div class="card-header" onclick="toggleCard(this)"><div class="card-title">📁 Partages SMB</div><div class="card-toggle">▼</div></div>
    <div class="card-body" style="padding:0">
    <table class="kv-table">
    <thead><tr style="background:var(--bg3)"><td><b>Nom</b></td><td><b>Chemin</b></td><td><b>Accès</b></td></tr></thead>
    <tbody>${shareRows||'<tr><td colspan="3" style="color:var(--text3);padding:14px">Aucun partage</td></tr>'}</tbody>
    </table>
    </div>
    </div>

    ${credRows ? `
    <div class="card" style="margin-bottom:10px">
    <div class="card-header" onclick="toggleCard(this)"><div class="card-title">🔑 Credentials stockés</div><div class="card-toggle">▼</div></div>
    <div class="card-body" style="padding:0"><table class="kv-table"><tbody>${credRows}</tbody></table></div>
    </div>` : ''}

    ${testRows ? `
    <div class="card" style="margin-bottom:10px">
    <div class="card-header" onclick="toggleCard(this)"><div class="card-title">🔗 Tests de connectivité</div><div class="card-toggle">▼</div></div>
    <div class="card-body" style="padding:0">
    <table class="kv-table">
    <thead><tr style="background:var(--bg3)"><td><b>Cible</b></td><td><b>Ping</b></td><td><b>Port 445</b></td><td><b>Résultat</b></td></tr></thead>
    <tbody>${testRows}</tbody>
    </table>
    </div>
    </div>` : ''}

    ${hostsRows ? `
    <div class="card" style="margin-bottom:10px">
    <div class="card-header" onclick="toggleCard(this)"><div class="card-title">📋 Fichier HOSTS (non-standard)</div><div class="card-toggle">▼</div></div>
    <div class="card-body" style="padding:0"><table class="kv-table"><tbody>${hostsRows}</tbody></table></div>
    </div>` : ''}

    <div class="card">
    <div class="card-header" onclick="toggleCard(this)"><div class="card-title">⚠️ Anomalies de cette machine</div><div class="card-toggle">▼</div></div>
    <div class="card-body" style="padding:0;overflow-x:auto">
    <table class="anom-table">
    <thead><tr><th>Sévérité</th><th>Problème</th><th>Diagnostic &amp; Correctif</th></tr></thead>
    <tbody>${
    m.anomalies.length===0
    ? '<tr><td colspan="3" style="text-align:center;padding:18px;color:var(--text3)">✅ Aucune anomalie</td></tr>'
    : m.anomalies.map(a => `
    <tr>
    <td><span class="score ${a.severite}">${scoreEmoji(a.severite)} ${a.severite}</span></td>
    <td>
    <div class="anom-label">${esc(getLabel(a.code))}</div>
    <span class="anom-code">${esc(a.code)}</span>
    </td>
    <td>
    <div class="anom-msg">${esc(a.message)}</div>
    <div class="anom-fix" onclick="copyText(this.dataset.cmd)" data-cmd="${esc(a.correctif)}">${esc(a.correctif)}</div>
    </td>
    </tr>`).join('')
    }</tbody>
    </table>
    </div>
    </div>
    </div>
    </div>`;
    }

    // ═══════════════════════════════════════════
    // PLAN D'ACTION + CONNECTIVITÉ
    // ═══════════════════════════════════════════
    function renderActionPlan() {
    const area = document.getElementById('action-plan-area');
    if (!area) return;
    const planByMachine = {};
    MACHINES.forEach(m => { planByMachine[m.name] = []; });
    MACHINES.forEach(src => {
    MACHINES.forEach(dst => {
    if (src.name === dst.name) return;
    if (src.echecs4625 >= 10) {
    planByMachine[src.name].push({
    priorite:1, icon:'🔑', cible:dst.name,
    action:'Vider les credentials en cache vers '+dst.name,
    cmd:'cmdkey /list\ncmdkey /delete:'+dst.name+'\nnet use * /delete /y',
    raison:src.echecs4625+' échecs 4625 en 24h'
    });
    }
    if (src.hasVpn) {
    planByMachine[src.name].push({
    priorite:2, icon:'🔒', cible:dst.name,
    action:'Désactiver le VPN avant de tester SMB vers '+dst.name,
    cmd:'# Désactiver le VPN puis retester la connexion',
    raison:'VPN actif reroute le trafic SMB hors du LAN'
    });
    }
    });
    MACHINES.forEach(dst => {
    if (src.name===dst.name) return;
    if (dst.inviteActif) {
    planByMachine[dst.name].push({
    priorite:1, icon:'👤', cible:src.name,
    action:'Désactiver le compte Invité (impact sur '+src.name+' → '+dst.name+')',
    cmd:'net user Invité /active:no',
    raison:'Compte Invité actif dégrade les auth SMB entrantes'
    });
    }
    });
    });
    const allSeen = new Set();
    let html = '';
    Object.keys(planByMachine).forEach(machineName => {
    const actions = planByMachine[machineName].filter(a => {
    const key = machineName+'|'+a.action;
    if (allSeen.has(key)) return false;
    allSeen.add(key); return true;
    });
    if (actions.length===0) return;
    html += `<div style="border-bottom:1px solid var(--border);padding:14px 16px">
    <div style="font-weight:700;color:var(--accent);margin-bottom:8px;font-size:.9rem">🖥 ${esc(machineName)}</div>
    ${actions.map(a => `
    <div style="display:flex;gap:8px;margin-bottom:8px;padding:9px 11px;background:var(--card2);border-radius:6px;border-left:3px solid var(--warn);align-items:flex-start">
    <span style="flex-shrink:0;font-size:1rem">${a.icon}</span>
    <div style="flex:1">
    <div style="font-size:.83rem;font-weight:600;margin-bottom:3px">${esc(a.action)}</div>
    <div style="font-size:.75rem;color:var(--text3);margin-bottom:5px">${esc(a.raison)}</div>
    <div class="anom-fix" onclick="copyText(this.dataset.cmd)" data-cmd="${esc(a.cmd)}">${esc(a.cmd)}</div>
    </div>
    </div>`).join('')}
    </div>`;
    });
    area.innerHTML = html || '<div style="padding:22px;text-align:center;color:var(--text3)">✅ Aucune action spécifique requise</div>';
    }

    function renderConnectivite() {
    const area = document.getElementById('conn-report-area');
    if (!area) return;
    let html = '', okCount=0, warnCount=0, failCount=0;
    MACHINES.forEach(src => {
    MACHINES.forEach(dst => {
    if (src.name===dst.name) return;
    const cell = (MATRIX[src.name]&&MATRIX[src.name][dst.name]) ? MATRIX[src.name][dst.name] : {statut:'UNKN'};
    if (cell.statut==='SELF') return;
    const causes = [];
    if (dst.inviteActif) causes.push({icon:'👤', msg:'Compte Invité actif sur '+dst.name+' — Windows dégrade toutes les connexions SMB entrantes vers ce compte sans droits', fix:'# A executer sur '+dst.name+' :\nnet user Invité /active:no'});
    if (src.echecs4625>=10) {
    const fixLines = ['# A executer sur '+src.name+' :','cmdkey /list','cmdkey /delete:TERMSRV/'+dst.name];
    if (dst.ip && dst.ip !== dst.name) fixLines.push('cmdkey /delete:TERMSRV/'+dst.ip);
    causes.push({icon:'🔑', msg:src.echecs4625+' échecs 4625 sur '+src.name+' — Windows utilise un mauvais mot de passe en cache pour atteindre '+dst.name+(dst.ip?' ('+dst.ip+')':''), fix:fixLines.join('\n')});
    }
    if (src.hasVpn) causes.push({icon:'🔒', msg:'VPN actif sur '+src.name+' perturbe le routage SMB', fix:'Désactiver le VPN sur '+src.name});
    const srcUsers = (src.accounts||[]).filter(a => !a.isSysteme && !a.isInvite).map(a => a.nom);
    const dstUsers = (dst.accounts||[]).filter(a => !a.isSysteme && !a.isInvite).map(a => a.nom);
    const missing = srcUsers.filter(u => !dstUsers.includes(u));
    if (missing.length>0) {
    const userCmds = missing.map(u => 'net user '+u+' MotDePasse /add').join('\n');
    causes.push({icon:'🧑‍💻', msg:'Comptes présents sur '+src.name+' absents de '+dst.name+' : '+missing.join(', ')+' — sans ce(s) compte(s) identique(s), Windows ne peut pas authentifier la connexion SMB', fix:'# A executer sur '+dst.name+' :\n'+userCmds});
    }
    const statut = cell.statut;
    let statusLabel;
    if (statut==='OK')       { statusLabel='✅ CONNECTÉ';    okCount++;   }
    else if (statut==='WARN'){ statusLabel='⚠️ PARTIEL';     warnCount++; }
    else                     { statusLabel='❌ NON CONNECTÉ'; failCount++; }
    const statusColor = statut==='OK'?'var(--ok)':statut==='WARN'?'var(--warn)':'var(--crit)';
    html += `<div style="border-bottom:1px solid var(--border);padding:12px 16px">
    <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:${causes.length?'9px':'0'}">
    <span style="font-weight:700">${esc(src.name)}</span>
    <span style="color:var(--text3)">→</span>
    <span style="font-weight:700">${esc(dst.name)}</span>
    <span style="font-size:.73rem;font-weight:700;padding:2px 9px;border-radius:12px;background:${statusColor};color:#fff">${statusLabel}</span>
    ${src.ip&&dst.ip?`<span style="color:var(--text3);font-size:.75rem;font-family:var(--font-mono)">${esc(src.ip)} → ${esc(dst.ip)}</span>`:''}
    </div>
    ${causes.length===0?'':causes.map(c=>`
    <div style="display:flex;gap:7px;margin-bottom:5px;padding:7px 9px;background:var(--card2);border-radius:5px;border-left:3px solid var(--warn);align-items:flex-start">
    <span style="flex-shrink:0">${c.icon}</span>
    <div>
    <div style="font-size:.8rem;color:var(--text)">${esc(c.msg)}</div>
    <div class="anom-fix" onclick="copyText(this.dataset.cmd)" data-cmd="${esc(c.fix)}" style="margin-top:4px">🔧 ${esc(c.fix)}</div>
    </div>
    </div>`).join('')}
    </div>`;
    });
    });
    area.innerHTML = html || '<div style="padding:22px;text-align:center;color:var(--text3)">Aucune paire trouvée</div>';
    const badge = document.getElementById('badge-conn');
    if (badge) {
    badge.textContent = failCount>0 ? failCount+' KO' : warnCount>0 ? warnCount+' ⚠' : '✓';
    badge.className = 'tab-badge '+(failCount>0?'':warnCount>0?'warn':'ok');
    }
    }

    // ═══════════════════════════════════════════
    // RECHERCHE
    // ═══════════════════════════════════════════
    document.getElementById('searchInput').addEventListener('input', function() {
    const q = this.value.toLowerCase().trim();
    renderAnomaliesCorrectifs(q || '');
    });

    // ═══════════════════════════════════════════
    // EXPORT CSV
    // ═══════════════════════════════════════════
    function exportCsvFromJs() {
    const rows = [['Machine','IP','DNS','VPN','DNS_VPN','Invite','Admin','SMBv1','4625','Invite_SMB','Crit','Warn','Info','Score','Date_Rapport']];
    MACHINES.forEach(m => {
    rows.push([m.name,m.ip||'',m.dns||'',m.hasVpn,m.dnsIsVpn,m.inviteActif,m.adminActif,m.smbv1,m.echecs4625,m.inviteSmb,m.nbCrit,m.nbWarn,m.nbInfo,scoreClass(m),m.reportDate||'']);
    });
    const csv = rows.map(r => r.map(c => '"'+String(c||'').replace(/"/g,'""')+'"').join(';')).join('\n');
    const blob = new Blob(['\uFEFF'+csv], {type:'text/csv;charset=utf-8'});
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'compare_pcreports.csv'; a.click();
    showToast('✅ CSV exporté');
    }

    // ═══════════════════════════════════════════
    // IMPRESSION
    // ═══════════════════════════════════════════
    function printReport() {
    const panels = document.querySelectorAll('.tab-panel');
    const cards  = document.querySelectorAll('.card');
    const panelState = Array.from(panels).map(p => p.classList.contains('active'));
    const cardState  = Array.from(cards).map(c => c.classList.contains('collapsed'));
    panels.forEach(p => p.classList.add('active'));
    cards.forEach(c => c.classList.remove('collapsed'));
    window.print();
    panels.forEach((p, i) => { if (!panelState[i]) p.classList.remove('active'); });
    cards.forEach((c, i)  => { if (cardState[i])  c.classList.add('collapsed'); });
    }

    // ═══════════════════════════════════════════
    // INIT
    // ═══════════════════════════════════════════
    document.addEventListener('DOMContentLoaded', () => {
    renderExecBanner();
    generateResume();
    renderSynthese();
    renderMatrix();
    renderConnectionsTable();
    renderAnomaliesCorrectifs('');
    initDiffSelectors();
    initMachineTabs();
    renderActionPlan();
    renderConnectivite();

    // Badge anomalies totales
    let totalCrit = 0;
    MACHINES.forEach(m => totalCrit += m.nbCrit);
    const badge = document.getElementById('badge-anom');
    badge.textContent = totalCrit > 0 ? totalCrit : '✓';
    badge.className = 'tab-badge ' + (totalCrit>0?'':'ok');
    });
    </script>
    <div id="print-machines-area" class="print-only"></div>
    </body>
    </html>
'@
    $html = $html.Replace('##MACHINES_JSON##', $machinesJsonStr)
    $html = $html.Replace('##MATRIX_JSON##',   $matrixJsonStr)
    $html = $html.Replace('##DIFFS_JSON##',     $diffsJsonStr)
    $html = $html.Replace('##VERSION##',         $Script:VERSION)
    $html = $html.Replace('##RUNDATE##',         $Script:RUNDATE)

    $html | Out-File -FilePath $OutPath -Encoding UTF8 -Force
    Write-Host "  [HTML] $OutPath" -ForegroundColor Cyan
    }

    # ─────────────────────────────────────────────

    # ---- MAIN ----
    Write-Host ''
    Write-Host "  Compare-PCReports v$Script:VERSION" -ForegroundColor Cyan
    Write-Host "  $Script:RUNDATE" -ForegroundColor DarkGray
    Write-Host "  Fichiers : $($ReportFiles.Count)" -ForegroundColor DarkGray
    Write-Host ''

    Write-Host '[1/5] Chargement et parsing des rapports...' -ForegroundColor Yellow
    $machines = @()
    foreach ($f in $ReportFiles) {
        Write-Host "  -> $(Split-Path $f -Leaf)" -ForegroundColor DarkGray
        $machines += Get-MachineProfile -FilePath $f
    }
    Write-Host "  $($machines.Count) machines chargees" -ForegroundColor Green

    Write-Host '[2/5] Detection des anomalies...' -ForegroundColor Yellow
    $allAnomalies = @{}
    foreach ($m in $machines) {
        $anoms = Get-MachineAnomalies -Machine $m -AllMachines $machines
        $allAnomalies[$m.Name] = $anoms
        $crit8 = @($anoms | Where-Object { $_.Severite -eq 'CRITIQUE' }).Count
        $warn8 = @($anoms | Where-Object { $_.Severite -eq 'WARNING' }).Count
        Write-Host "  $($m.Name.PadRight(20)) CRIT:$crit8 WARN:$warn8" -ForegroundColor $(if($crit8 -gt 0){'Red'}elseif($warn8 -gt 0){'Yellow'}else{'Green'})
    }

    Write-Host '[3/5] Calcul des differentiels...' -ForegroundColor Yellow
    $allDiffs = @()
    for ($i8 = 0; $i8 -lt $machines.Count; $i8++) {
        for ($j8 = $i8 + 1; $j8 -lt $machines.Count; $j8++) {
            $ma8 = $machines[$i8]; $mb8 = $machines[$j8]
            $diffs8 = Get-MachineDiff -MachineA $ma8 -MachineB $mb8
            $allDiffs += @{ PairName="$($ma8.Name) <-> $($mb8.Name)"; NameA=$ma8.Name; NameB=$mb8.Name; Diffs=$diffs8 }
            Write-Host "  $($ma8.Name) <-> $($mb8.Name) : $(@($diffs8).Count) difference(s)" -ForegroundColor DarkGray
        }
    }

    Write-Host '[4/5] Construction de la matrice reseau...' -ForegroundColor Yellow
    $matrix8 = Get-NetworkMatrix -Machines $machines

    Write-Host '[5/5] Generation des exports...' -ForegroundColor Yellow
    $null = New-Item -ItemType Directory -Path $Script:OUTDIR -Force
    $txtPath8  = Join-Path $Script:OUTDIR "rapport_diff_$Script:TIMESTAMP.txt"
    $htmlPath8 = Join-Path $Script:OUTDIR "dashboard_diff_$Script:TIMESTAMP.html"
    Export-TextReport    -Machines $machines -Matrix $matrix8 -AllAnomalies $allAnomalies -AllDiffs $allDiffs -OutPath $txtPath8
    Export-CsvReports    -Machines $machines -AllAnomalies $allAnomalies -AllDiffs $allDiffs -BaseDir $Script:OUTDIR
    Export-HtmlDashboard -Machines $machines -Matrix $matrix8 -AllAnomalies $allAnomalies -AllDiffs $allDiffs -OutPath $htmlPath8
    Write-Host ''
    Write-Host "  Ouverture du dashboard..." -ForegroundColor Cyan
    Start-Process $htmlPath8
    Write-Host ''
    Write-Host "  TERMINE -> $Script:OUTDIR" -ForegroundColor Green
    Write-Host ''
}

# ===========================================================================
#  MENU PRINCIPAL
# ===========================================================================

# ===========================================================================
#  MODULE 9 — EVCDiag : Crashes / Kernel / IO / Drivers
#  Intégré depuis EVCDiag.ps1 (ps81frt — MIT)
# ===========================================================================
function Invoke-EVCDiag {
    Assert-AdminPrivilege

    $outputFolder = Join-Path $env:USERPROFILE "Desktop\EVC_Export"
    $inputFile    = Join-Path $outputFolder "3_Kernel_Diagnostics.txt"
    if (-not (Test-Path $outputFolder)) {
        New-Item -Path $outputFolder -ItemType Directory | Out-Null
    }

    # ── Install awk ──────────────────────────────────────────────────────────
    function Install-Awk {
        $awkDest = "$env:SystemRoot\System32\awk.exe"
        if (Test-Path $awkDest) { return $awkDest }

        $awkInPath = Get-Command awk -ErrorAction SilentlyContinue
        if ($awkInPath) { return $awkInPath.Source }

        Write-Host "[INFO] awk non trouve. Telechargement depuis GitHub..."

        $zipUrl = "https://github.com/ps81frt/EVC/raw/main/Evc/LinuxToolOn-Windows.zip"
        $tmpZip = Join-Path $env:TEMP "LinuxToolOn-Windows.zip"
        $tmpDir = Join-Path $env:TEMP "LinuxTools_EVC"

        try {
            Invoke-WebRequest -Uri $zipUrl -OutFile $tmpZip -UseBasicParsing -ErrorAction Stop
            Write-Host "[INFO] Telechargement OK -> $tmpZip"
        } catch {
            Write-Host "[ERREUR] Telechargement echoue : $_"
            return $null
        }

        if (Test-Path $tmpDir) { Remove-Item $tmpDir -Recurse -Force }
        Expand-Archive -Path $tmpZip -DestinationPath $tmpDir -Force

        $allBinaries = Get-ChildItem -Path $tmpDir -Recurse -Include "*.exe","*.dll"

        if (-not $allBinaries) {
            Write-Host "[ERREUR] Aucun binaire trouve dans l'archive."
            Get-ChildItem $tmpDir -Recurse | ForEach-Object { Write-Host "    $($_.FullName)" }
            return $null
        }

        $awkDestPath  = $null
        $installErrors = @()

        foreach ($bin in $allBinaries) {
            $dest = Join-Path "$env:SystemRoot\System32" $bin.Name
            try {
                Copy-Item $bin.FullName -Destination $dest -Force
                Write-Host "[OK] $($bin.Name)"
                if ($bin.Name -eq "awk.exe") { $awkDestPath = $dest }
            } catch {
                Write-Host "[WARN] $($bin.Name) -> $_"
                $installErrors += $bin
                if ($bin.Name -eq "awk.exe") { $awkDestPath = $bin.FullName }
            }
        }

        if ($installErrors.Count -gt 0) {
            Write-Host ""
            Write-Host "[WARN] $($installErrors.Count) fichier(s) non installe(s) (relancer en admin) :"
            $installErrors | ForEach-Object { Write-Host "  - $($_.Name)" }
        }

        if (-not $awkDestPath) {
            Write-Host "[ERREUR] awk.exe introuvable dans l'archive."
            return $null
        }

        return $awkDestPath
    }

    # ── Analyse IO > 10000ms ─────────────────────────────────────────────────
    function Invoke-ListErrors($inputFile) {
        $awkBin = Install-Awk
        if (-not $awkBin) {
            Write-Host "[ERREUR] awk introuvable."
            return
        }

        $outFile = Join-Path $outputFolder "IO_Errors.txt"

        $awkScript = @'
/^TimeCreated :/ { bloc = $0; getline; while ($0 !~ /^TimeCreated :/ && !/^$/) { bloc = bloc "\n" $0; getline } }
bloc ~ /IO success counts are/ {
    match(bloc, /IO success counts are [0-9, ]+\./)
    line = substr(bloc, RSTART, RLENGTH)
    gsub(/[^0-9,]/, "", line)
    split(line, valeurs, ",")
    if (valeurs[13] != 0 || valeurs[14] != 0) {
        match(bloc, /TimeCreated : [0-9\/: ]+/); date = substr(bloc, RSTART, RLENGTH)
        match(bloc, /Guid is \{([^}]+)\}/); guid = substr(bloc, RSTART+9, RLENGTH-10)
        print date, guid, "->", valeurs[13], "IO en 10000 ms,", valeurs[14], "IO en 10000+ ms"
    }
}
'@

        $awkScriptFile = Join-Path $env:TEMP "evc_errors.awk"
        $awkScript | Set-Content $awkScriptFile -Encoding ASCII

        $result = & $awkBin -f $awkScriptFile $inputFile 2>&1

        if ($result) {
            $result | Out-File $outFile -Encoding UTF8
            $result | ForEach-Object { Write-Host $_ }
            Write-Host ""
            Write-Host "$($result.Count) evenement(s) -> $outFile"
        } else {
            Write-Host "[OK] Aucun IO >= 10000 ms detecte."
        }
    }

    # ── Affichage complet d'un evenement (tableau IO buckets — identique a EVCDiag.ps1) ──
    function Invoke-EVCShowEntry($bloc, $tc, $outDir, $doExport) {

        function Get-RawArray2($pattern, $text) {
            $m = [regex]::Match($text, $pattern, "Singleline")
            if (-not $m.Success) { return @() }
            $vals = $m.Groups[1].Value.Trim() -replace '\s+',''
            return $vals.Split(",") | ForEach-Object {
                $v = ($_ -replace "[^\d]","")
                if ($v -eq "") { 0 } else { [int64]$v }
            }
        }

        function Get-AvgLatency2($total, $count) {
            if ($count -le 0 -or $total -le 0) { return "-" }
            return [math]::Round(($total / $count) / 10000, 3)
        }

        function Write-WrappedLine2($label, $text, $width) {
            $prefix = "| $label"
            $words  = $text -split ' '
            $line   = $prefix
            foreach ($word in $words) {
                if ($line.Length + 1 + $word.Length -gt $width) {
                    Write-Host $line
                    $line = "| " + (' ' * ($label.Length)) + " $word"
                } else { $line += " $word" }
            }
            Write-Host $line
        }

        $bucketLabels = @("128 us","256 us","512 us","1 ms","4 ms","16 ms","64 ms","128 ms","256 ms","512 ms","1000 ms","2000 ms","10000 ms","> 10000 ms")

        $success = Get-RawArray2 "IO success counts are ([\d,\s]+)" $bloc
        $failed  = Get-RawArray2 "IO failed counts are ([\d,\s]+)"  $bloc
        $latency = Get-RawArray2 "IO total latency.*?are ([\d,\s]+)" $bloc
        $totalIO = ([regex]::Match($bloc, "Total IO:\s*(\d+)")).Groups[1].Value -as [int64]

        $max = 14
        while ($success.Count -lt $max) { $success += 0 }
        while ($failed.Count  -lt $max) { $failed  += 0 }
        while ($latency.Count -lt $max) { $latency += 0 }

        $sumSuccess = ($success | Measure-Object -Sum).Sum

        $guid    = ([regex]::Match($bloc, "(?:Guid is|Corresponding Class Disk Device Guid is) \{(.*?)\}")).Groups[1].Value
        $device  = [regex]::Match($bloc, "Port = (\d+), Path = (\d+), Target = (\d+), Lun = (\d+)")
        $portVal = $device.Groups[1].Value
        $pathVal = $device.Groups[2].Value

        $highLatencyIO = $success[7]+$success[8]+$success[9]+$success[10]+$success[11]+$success[12]+$success[13]

        if ($sumSuccess -ne $totalIO) {
            Write-Host ""
            Write-Host "  [WARN] MISMATCH: success sum ($sumSuccess) != Total IO ($totalIO)" -ForegroundColor Yellow
        }

        $logNameValue = ([regex]::Match($bloc, "LogName\s*:\s*(.+)")).Groups[1].Value
        $messageValue = ([regex]::Match($bloc, "Message\s*:\s*(.+)")).Groups[1].Value
        $messageValue = $messageValue -replace 'whose Corresponding Class Disk Device Guid is \{[^}]+\}:?',''
        $messageValue = $messageValue.Trim()

        $reportFile = $null
        if ($doExport) {
            $safeDate  = $tc -replace '[/: ]','-'
            $safeGuid  = ($guid -replace '[{}]','').Substring(0, [math]::Min(8, $guid.Length))
            $reportFile = Join-Path $outDir "Report_${safeDate}_${safeGuid}.txt"
            Start-Transcript -Path $reportFile -Force | Out-Null
        }

        Write-Host ""
        Write-Host "+---------------------------------------------------------------+"
        Write-Host "| TimeCreated : $tc"
        if ($logNameValue) { Write-WrappedLine2 "LogName     :" $logNameValue 104 }
        if ($messageValue) { Write-WrappedLine2 "Message     :" $messageValue 104 }
        Write-Host "| Guid        : {$guid}"
        if ($portVal) { Write-Host "| Port=$portVal  Path=$pathVal" }
        Write-Host "+---------------------------------------------------------------+"
        Write-Host ""
        Write-Host "+-----------------------------------------------------------------------------------------------------------+"
        Write-Host "| REPARTITION DES OPERATIONS IO (ZERO LOSS VERIFIED)                                                        |"
        Write-Host "+----------------+----------------+----------------+----------------+----------------+--------------------+"
        Write-Host "| Bucket         | IO Reussies     | % du Total     | Latence Moy.   | IO Echouees    | Statut             |"
        Write-Host "+----------------+----------------+----------------+----------------+----------------+--------------------+"

        for ($i = 0; $i -lt 14; $i++) {
            $ok   = $success[$i]
            $fail = $failed[$i]
            $pct  = if ($totalIO -gt 0) { "{0,7:N1}%" -f [math]::Round(($ok / $totalIO) * 100, 1) } else { "     0%" }
            $lat  = Get-AvgLatency2 $latency[$i] $ok
            $status = if     ($ok -eq 0 -and $fail -eq 0)  { "Aucun"              }
                      elseif ($i -le 2)                     { "Optimal"            }
                      elseif ($i -le 3)                     { "Normal"             }
                      elseif ($i -le 5)                     { "Acceptable"         }
                      elseif ($i -eq 6  -and $ok -gt 0)    { "[!] A surveiller"   }
                      elseif ($i -le 10 -and $ok -gt 0)    { "[!!] Degradee"      }
                      elseif ($i -eq 11 -and $ok -gt 0)    { "[!!] Critique"      }
                      elseif ($i -eq 12 -and $ok -gt 0)    { "[!!!] 10s ($ok IO)" }
                      elseif ($i -eq 13 -and $ok -gt 0)    { "[!!!] EXTREME"      }
                      else                                  { "OK"                 }

            $color = if ($i -ge 12 -and $ok -gt 0) { "Red" } elseif ($i -ge 7 -and $ok -gt 0) { "Yellow" } else { "Gray" }
            Write-Host ("| {0,-14} | {1,14:N0} | {2,14} | {3,14} | {4,14:N0} | {5,-18} |" -f $bucketLabels[$i], $ok, $pct, $lat, $fail, $status) -ForegroundColor $color
        }

        Write-Host "+----------------+----------------+----------------+----------------+----------------+--------------------+"
        $totalLatency = ($latency | Measure-Object -Sum).Sum
        $totalOps     = $sumSuccess + ($failed | Measure-Object -Sum).Sum
        $globalAvg    = if ($totalOps -gt 0) { [math]::Round(($totalLatency / $totalOps) / 10000, 6) } else { 0 }
        Write-Host ""
        Write-Host "+---------------------------------------------------------------+"
        Write-Host ("| Latence Globale Moyenne : {0} ms (ponderee)" -f $globalAvg)
        Write-Host ("| IO totales verifiees    : {0:N0} / {1:N0}" -f $sumSuccess, $totalIO)
        if ($highLatencyIO -gt 0) {
            Write-Host ("| [!] IO > 128ms          : {0:N0} operations" -f $highLatencyIO) -ForegroundColor Yellow
        }
        Write-Host "+---------------------------------------------------------------+"

        if ($doExport -and $reportFile) {
            Stop-Transcript | Out-Null
            Write-Host ""
            Write-OK "Rapport exporte -> $reportFile"
        }
        Write-Host ""
        Write-Host "  >>> Appuyez sur ENTREE pour revenir au menu..." -ForegroundColor DarkGray
        $null = Read-Host
    }

    # ── Menu EVCDiag ─────────────────────────────────────────────────────────
    while ($true) {
        Write-Host ""
        Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor DarkCyan
        Write-Host "  ║           MODULE 9 — EVCDiag  (Crashes / IO / Drivers)       ║" -ForegroundColor DarkCyan
        Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor DarkCyan
        Write-Host "  ║  C.  Collect   — Collecte tous les logs (genere EVC_Export)  ║" -ForegroundColor White
        Write-Host "  ║  E.  Errors    — Analyse IO > 10000ms depuis EVC_Export       ║" -ForegroundColor White
        Write-Host "  ║  R.  Reader    — Lire un evenement (TimeCreated + filtres)    ║" -ForegroundColor White
        Write-Host "  ║  0.  Retour menu principal                                   ║" -ForegroundColor DarkGray
        Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor DarkCyan
        Write-Host "  Export : $outputFolder" -ForegroundColor DarkGray
        Write-Host ""
        $evcChoice = (Read-Host "  Votre choix").ToUpper().Trim()

        switch ($evcChoice) {

            "C" {
                Write-Title "9. EVCDiag — COLLECTE"

                # 1. Crashes applicatifs
                $appCrashFile = Join-Path $outputFolder "1_Application_Crashes.txt"
                Write-Section "1. Crashes applicatifs (Event ID 1000/1001)"
                "===== CRASHES D'APPLICATIONS (Event ID 1000) =====" | Out-File $appCrashFile -Encoding UTF8
                Get-WinEvent -LogName "Application" | Where-Object {$_.Id -eq 1000} | Sort-Object TimeCreated |
                    Select-Object TimeCreated,
                        @{N="Application";E={$_.Properties[0].Value}},
                        @{N="Version";E={$_.Properties[1].Value}},
                        @{N="Module";E={$_.Properties[3].Value}},
                        @{N="Code";E={$_.Properties[6].Value}},
                        @{N="Offset";E={$_.Properties[7].Value}} |
                    Format-List | Out-File $appCrashFile -Append -Encoding UTF8
                "`n===== ERREURS D'APPLICATIONS (Event ID 1001) =====" | Out-File $appCrashFile -Append -Encoding UTF8
                Get-WinEvent -LogName "Application" | Where-Object {$_.Id -eq 1001} | Sort-Object TimeCreated |
                    Select-Object TimeCreated, @{N="Message";E={$_.Message}} |
                    Format-List | Out-File $appCrashFile -Append -Encoding UTF8
                Write-OK "1_Application_Crashes.txt"

                # 2. Erreurs systeme critiques
                $systemCrashFile = Join-Path $outputFolder "2_System_Crashes.txt"
                Write-Section "2. Erreurs systeme critiques"
                "===== ERREURS SYSTEME @(41,1001,7023,7034,157,153,7000,7001,7009,7011,7026,7045) =====" | Out-File $systemCrashFile -Encoding UTF8
                Get-WinEvent -LogName "System" | Where-Object {$_.Id -in @(41,1001,7023,7034,157,153,7000,7001,7009,7011,7026,7045)} | Sort-Object TimeCreated |
                    Select-Object TimeCreated, Id, @{N="Message";E={$_.Message}} |
                    Format-List | Out-File $systemCrashFile -Append -Encoding UTF8
                Write-OK "2_System_Crashes.txt"

                # 3. Logs kernel
                $kernelDiagFile = Join-Path $outputFolder "3_Kernel_Diagnostics.txt"
                Write-Section "3. Logs kernel (WHEA, Dump, Storport...)"
                $logNames = @(
                    "Microsoft-Windows-Kernel-WHEA/Operational",
                    "Microsoft-Windows-Kernel-WHEA/Errors",
                    "Microsoft-Windows-Kernel-Dump/Operational",
                    "Microsoft-Windows-Diagnostics-Performance/Operational",
                    "Microsoft-Windows-Resource-Exhaustion-Detector/Operational",
                    "Microsoft-Windows-Kernel-PnP/Driver Watchdog",
                    "Microsoft-Windows-Fault-Tolerant-Heap/Operational",
                    "Microsoft-Windows-WerKernel/Operational",
                    "Microsoft-Windows-CodeIntegrity/Operational",
                    "Microsoft-Windows-Security-Mitigations/KernelMode",
                    "Microsoft-Windows-Kernel-Boot/Operational",
                    "Microsoft-Windows-Storage-Storport/Operational",
                    "Microsoft-Windows-Ntfs/Operational"
                )
                "===== LOGS KERNEL (WHEA, Dump, Storport, etc.) =====" | Out-File $kernelDiagFile -Encoding UTF8
                foreach ($logName in $logNames) {
                    try {
                        Get-WinEvent -LogName $logName -ErrorAction Stop | Sort-Object TimeCreated |
                            Select-Object TimeCreated, LogName, @{N="Message";E={$_.Message}} |
                            Format-List | Out-File $kernelDiagFile -Append -Encoding UTF8
                    } catch { Write-WARN "Impossible de lire $logName" }
                }
                Write-OK "3_Kernel_Diagnostics.txt"

                # 4. Informations disques
                $diskInfoFile = Join-Path $outputFolder "4_Disk_Information.txt"
                Write-Section "4. Informations disques + SMART"
                "===== INFORMATIONS MATERIELLES DES DISQUES =====" | Out-File $diskInfoFile -Encoding UTF8
                $physDisks   = Get-PhysicalDisk
                $reliability = $physDisks | Get-StorageReliabilityCounter
                $volsDisk    = Get-Volume | Where-Object { $_.DriveLetter } | Select-Object DiskNumber, DriveLetter
                $diskInfo = foreach ($disk in $physDisks) {
                    $rel = $reliability | Where-Object { $_.DeviceId -eq $disk.DeviceId } | Select-Object -First 1
                    $storportGuid = "N/A"
                    if ($rel -and $rel.UniqueId) {
                        $allGuids = [regex]::Matches($rel.UniqueId, '\{[0-9A-Fa-f-]+\}')
                        if ($allGuids.Count -gt 0) { $storportGuid = $allGuids[-1].Value.Trim('{}') }
                    }
                    $driveLetters = ($volsDisk | Where-Object { $_.DiskNumber -eq $disk.DeviceId -and $_.DriveLetter }).DriveLetter -join ","
                    if ([string]::IsNullOrEmpty($driveLetters)) {
                        $parts = Get-Partition -DiskNumber $disk.DeviceId -EA SilentlyContinue | Where-Object DriveLetter
                        $driveLetters = if ($parts) { $parts.DriveLetter -join "," } else { "Aucune" }
                    }
                    [PSCustomObject]@{
                        DiskNumber             = $disk.DeviceId
                        DriveLetter            = $driveLetters
                        Name                   = $disk.FriendlyName
                        BusType                = $disk.BusType
                        SerialNumber           = $disk.SerialNumber
                        SizeGB                 = [math]::Round($disk.Size / 1GB, 2)
                        HealthStatus           = $disk.HealthStatus
                        ReadErrorsUncorrected  = if ($rel) { $rel.ReadErrorsUncorrected  } else { 0 }
                        WriteErrorsUncorrected = if ($rel) { $rel.WriteErrorsUncorrected } else { 0 }
                        ReadLatencyMax_ms      = if ($rel) { $rel.ReadLatencyMax  } else { 0 }
                        WriteLatencyMax_ms     = if ($rel) { $rel.WriteLatencyMax } else { 0 }
                        WearPercent            = if ($rel) { $rel.Wear        } else { 0 }
                        Temperature_C          = if ($rel) { $rel.Temperature } else { 0 }
                        StorportGuid           = $storportGuid
                    }
                }
                $diskInfo | Select-Object DiskNumber, DriveLetter, Name, BusType, SizeGB, HealthStatus, Temperature_C, WearPercent |
                    Format-Table -AutoSize | Out-File $diskInfoFile -Append -Encoding UTF8
                $diskInfo | Select-Object DiskNumber, SerialNumber, ReadErrorsUncorrected, WriteErrorsUncorrected, ReadLatencyMax_ms, WriteLatencyMax_ms, StorportGuid |
                    Format-Table -AutoSize | Out-File $diskInfoFile -Append -Encoding UTF8
                $diskInfo | Format-Table -AutoSize | Out-File $diskInfoFile -Append -Encoding UTF8

                # Identification disque(s) defaillant(s)
                $candidateDisks = $diskInfo | Where-Object { $_.ReadErrorsUncorrected -gt 0 -or $_.WriteErrorsUncorrected -gt 0 }
                if (-not $candidateDisks) { $candidateDisks = $diskInfo | Where-Object { $_.ReadLatencyMax_ms -ge 100 -or $_.WriteLatencyMax_ms -ge 100 } }
                if ($candidateDisks) {
                    Write-Host ""
                    Write-Host "  ===== DISQUE(S) POTENTIELLEMENT DEFAILLANT(S) =====" -ForegroundColor Red
                    foreach ($bd in $candidateDisks) {
                        Write-Host "  GUID Storport  : $($bd.StorportGuid)" -ForegroundColor Red
                        Write-Host "  Nom            : $($bd.Name)" -ForegroundColor Red
                        Write-Host "  Erreurs R/W    : $($bd.ReadErrorsUncorrected) / $($bd.WriteErrorsUncorrected)" -ForegroundColor Red
                        Write-Host "  Latence max    : $($bd.ReadLatencyMax_ms) ms / $($bd.WriteLatencyMax_ms) ms" -ForegroundColor Red
                    }
                } else { Write-OK "Aucun disque avec signes clairs de defaillance." }
                Write-OK "4_Disk_Information.txt"

                # 5. Erreurs drivers
                $driverErrorFile = Join-Path $outputFolder "5_Driver_Errors.txt"
                Write-Section "5. Erreurs drivers (219, 7000, 7001, 7011, 7026)"
                "===== ERREURS DE DRIVERS =====" | Out-File $driverErrorFile -Encoding UTF8
                Get-WinEvent -LogName "System" | Where-Object {$_.Id -in @(219,7000,7001,7011,7026)} | Sort-Object TimeCreated |
                    Select-Object TimeCreated, Id, @{N="Message";E={$_.Message}} |
                    Format-List | Out-File $driverErrorFile -Append -Encoding UTF8
                $driverLogs = @(
                    "Microsoft-Windows-DriverFrameworks-UserMode/Operational",
                    "Microsoft-Windows-DriverFrameworks-KernelMode/Operational",
                    "Microsoft-Windows-Kernel-PnP/Configuration",
                    "Microsoft-Windows-DeviceSetupManager/Admin",
                    "Microsoft-Windows-DeviceSetupManager/Operational"
                )
                foreach ($logName in $driverLogs) {
                    try {
                        Get-WinEvent -LogName $logName -EA Stop | Sort-Object TimeCreated |
                            Select-Object TimeCreated, LogName, @{N="Message";E={$_.Message}} |
                            Format-List | Out-File $driverErrorFile -Append -Encoding UTF8
                    } catch {}
                }
                Write-OK "5_Driver_Errors.txt"

                # 5.1 setupapi logs
                $driverLogFile = Join-Path $outputFolder "5_1_Driver_Logs.txt"
                $setupApiLogs  = @("C:\Windows\INF\setupapi.dev.log","C:\Windows\INF\setupapi.setup.log")
                $cutoff = (Get-Date).AddDays(-10)
                "===== DRIVER LOGS - setupapi (10 derniers jours) =====" | Out-File $driverLogFile -Encoding UTF8
                foreach ($sl in $setupApiLogs) {
                    "--- $sl ---" | Out-File $driverLogFile -Append -Encoding UTF8
                    if (Test-Path $sl) {
                        $lines = Get-Content $sl -Encoding UTF8
                        $inSec = $false; $secBuf = @(); $pendHdr = $null
                        foreach ($line in $lines) {
                            if ($line -match "^>>>\s+\[.+\]\s*$") {
                                if ($inSec -and $secBuf.Count -gt 0) { $secBuf | Out-File $driverLogFile -Append -Encoding UTF8 }
                                $inSec = $false; $secBuf = @(); $pendHdr = $line
                            } elseif ($pendHdr -and $line -match ">>>\s+Section start\s+(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})") {
                                try { $ts = [datetime]::ParseExact($matches[1], "yyyy/MM/dd HH:mm:ss", $null); $inSec = ($ts -ge $cutoff) } catch { $inSec = $false }
                                $secBuf = @($pendHdr, $line); $pendHdr = $null
                            } elseif ($inSec) { $secBuf += $line }
                        }
                        if ($inSec -and $secBuf.Count -gt 0) { $secBuf | Out-File $driverLogFile -Append -Encoding UTF8 }
                    } else { "[WARN] $sl introuvable." | Out-File $driverLogFile -Append -Encoding UTF8 }
                }
                Write-OK "5_1_Driver_Logs.txt"

                # 6. IO Errors auto
                Write-Section "6. Analyse IO > 10000ms"
                Invoke-ListErrors $kernelDiagFile

                Write-Host ""
                Write-OK "Collecte terminee -> $outputFolder"
                $ioErrorsFile = Join-Path $outputFolder "IO_Errors.txt"
                notepad $appCrashFile
                notepad $systemCrashFile
                notepad $kernelDiagFile
                notepad $diskInfoFile
                notepad $driverErrorFile
                if (Test-Path $driverLogFile) { notepad $driverLogFile }
                if (Test-Path $ioErrorsFile)  { notepad $ioErrorsFile  }
                Write-Host ""
                Write-Host "  Appuyez sur ENTREE pour revenir au menu..." -ForegroundColor DarkGray
                $null = Read-Host
            }

            "E" {
                Write-Title "9. EVCDiag — IO ERRORS"
                if (-not (Test-Path $inputFile)) {
                    Write-ERR "Fichier $inputFile introuvable. Lancez d'abord l'option C (Collect)."
                } else {
                    Invoke-ListErrors $inputFile
                }
                Write-Host ""
                Write-Host "  Appuyez sur ENTREE pour revenir au menu..." -ForegroundColor DarkGray
                $null = Read-Host
            }

            "R" {
                Write-Title "9. EVCDiag — READER"
                $ioErrorsFile = Join-Path $outputFolder "IO_Errors.txt"
                if (-not (Test-Path $ioErrorsFile)) {
                    Write-ERR "IO_Errors.txt introuvable. Lancez d'abord E."
                } elseif (-not (Test-Path $inputFile)) {
                    Write-ERR "3_Kernel_Diagnostics.txt introuvable. Lancez d'abord C."
                } else {
                    $ioLines = Get-Content $ioErrorsFile
                    Write-Host ""
                    $i = 1
                    foreach ($line in $ioLines) {
                        Write-Host ("  [{0}] {1}" -f $i, $line) -ForegroundColor Red
                        $i++
                    }
                    Write-Host ""
                    $pick = Read-Host "  Numero (ENTREE = retour menu)"
                    if ([string]::IsNullOrWhiteSpace($pick)) { break }

                    $picked = $ioLines[[int]$pick - 1]
                    # Extraire TimeCreated et Guid depuis la ligne choisie
                    $evc_tc   = if ($picked -match "TimeCreated : (\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2})") { $matches[1] } else { "" }
                    $evc_guid = if ($picked -match "([0-9a-f]{8})\s") { $matches[1] } else { "" }
                    $evc_exp  = Read-Host "  Export vers fichier ? [O/n]"

                    # Parser 3_Kernel_Diagnostics.txt
                    $evc_lines = Get-Content $inputFile
                    $evc_blocs = @(); $evc_cur = ""
                    foreach ($evc_l in $evc_lines) {
                        if ($evc_l -match "^TimeCreated\s*:") {
                            if ($evc_cur -ne "") { $evc_blocs += $evc_cur }
                            $evc_cur = $evc_l
                        } else { $evc_cur += "`n" + $evc_l }
                    }
                    if ($evc_cur -ne "") { $evc_blocs += $evc_cur }

                    $evc_sel = $evc_blocs | Where-Object { $_ -like "*$evc_tc*" -and $_ -match 'Performance summary for Storport Device' }
                    if ($evc_guid -ne "") { $evc_sel = @($evc_sel | Where-Object { $_ -like "*$evc_guid*" }) }

                    function Get-EvcDeviceInfo($bloc) {
                        $p = if ($bloc -match "Port = (\d+),") { $matches[1] } else { "" }
                        $pa= if ($bloc -match "Path = (\d+),") { $matches[1] } else { "" }
                        $g = if ($bloc -match "(?:Guid is|Corresponding Class Disk Device Guid is) \{([^}]+)\}") { $matches[1] } else { "" }
                        $t = if ($bloc -match "Total IO:(\d+)") { $matches[1] } else { "0" }
                        return [pscustomobject]@{ Port=$p; Path=$pa; Guid=$g; Total=$t; Bloc=$bloc }
                    }

                    if ($evc_sel.Count -eq 0) {
                        Write-WARN "Aucun evenement trouve pour cette ligne."
                    } elseif ($evc_sel.Count -gt 1) {
                        $evc_devs = $evc_sel | ForEach-Object { Get-EvcDeviceInfo $_ }
                        $evc_devs = $evc_devs | Group-Object -Property { "$($_.Guid)|$($_.Port)|$($_.Path)" } | ForEach-Object { $_.Group[-1] }
                        if ($evc_devs.Count -gt 1) {
                            Write-Host ""
                            Write-Host "  [INFO] $($evc_devs.Count) peripheriques trouves. Precisez :" -ForegroundColor Yellow
                            foreach ($d in $evc_devs) {
                                Write-Host ("  Port {0}  Path {1}  TotalIO={2}  Guid={3}" -f $d.Port, $d.Path, $d.Total, $d.Guid) -ForegroundColor Cyan
                            }
                        } else {
                            Invoke-EVCShowEntry $evc_devs[0].Bloc $evc_tc $outputFolder ($evc_exp -match '^[Oo]')
                        }
                    } else {
                        Invoke-EVCShowEntry (Get-EvcDeviceInfo $evc_sel[0]).Bloc $evc_tc $outputFolder ($evc_exp -match '^[Oo]')
                    }
                }
            }
            "0" { return }
            default { Write-WARN "Choix invalide." }
        }
    }
}

# ===========================================================================
#  MODULE 10 — CrashDiag : Crashes / BSOD / Sessions / Freezes / WHEA
#  Integre depuis PC_Monitor_Diagnostic (ps81frt — MIT)
# ===========================================================================
function Invoke-CrashDiag {
    param(
        [int]$HeuresHistorique = 48,
        [switch]$ExportCSV,
        [switch]$HTML
    )
    Assert-AdminPrivilege

    $Bureau    = [Environment]::GetFolderPath("Desktop")
    $ts        = Get-Date -Format "yyyyMMdd_HHmmss"
    $outDir    = Join-Path $Bureau "CrashDiag_$ts"
    if (-not (Test-Path $outDir)) { New-Item -Path $outDir -ItemType Directory | Out-Null }
    $FichierLog  = Join-Path $outDir "CrashDiag_$ts.txt"
    $FichierHTML = Join-Path $outDir "CrashDiag_$ts.html"

    $DossierMinidump = "$env:SystemRoot\Minidump"
    $DossierCrash    = "$env:SystemRoot\LiveKernelReports"

    # Plage nuit (pas d alerte gap)
    $H24         = $false
    $NuitDebut   = 22
    $NuitFin     = 8
    $GapSeuilMin = 45

    # ── Helpers Write adaptes aux conventions WT ─────────────────────────────
    function _CDInfo  { param($m) Write-INFO  $m }
    function _CDOk    { param($m) Write-OK    $m }
    function _CDWarn  { param($m) Write-WARN  $m }

    # ── 1. EVENEMENTS SYSTEME ─────────────────────────────────────────────────
    function _GetEvenementsSysteme {
        param([datetime]$Depuis)
        $r = @()
        try {
            $evts = Get-WinEvent -FilterHashtable @{ LogName='System'; Level=1,2; StartTime=$Depuis } -EA SilentlyContinue
            foreach ($e in $evts) {
                $sev  = if ($e.Level -eq 1) { "CRITIQUE" } else { "ERREUR" }
                $flag = ""
                if ($e.Id -in @(41,6008))       { $flag = "ARRET_BRUTAL" }
                elseif ($e.Id -eq 1001)          { $flag = "BSOD" }
                elseif ($e.Id -eq 6001)          { $flag = "WATCHDOG" }
                elseif ($e.Id -in @(153))        { $flag = "DISQUE" }
                elseif ($e.Id -eq 55)            { $flag = "CORRUPTION_FS" }
                elseif ($e.ProviderName -match "nvlddmkm|amdkmdap|igfx|display|video|dxgkrnl") { $flag = "GPU" }
                $r += [PSCustomObject]@{
                    Date    = $e.TimeCreated
                    Sev     = $sev
                    Source  = $e.ProviderName
                    ID      = $e.Id
                    Message = ($e.Message -split "`n")[0].Trim()
                    Flag    = $flag
                    Journal = "System"
                }
            }
        } catch { _CDWarn "Journal System inaccessible : $_" }
        # WHEA
        try {
            $whea = Get-WinEvent -FilterHashtable @{ LogName='System'; StartTime=$Depuis } -EA SilentlyContinue |
                Where-Object { $_.ProviderName -match "WHEA" }
            foreach ($e in $whea) {
                $r += [PSCustomObject]@{
                    Date    = $e.TimeCreated
                    Sev     = "WHEA-MATERIEL"
                    Source  = $e.ProviderName
                    ID      = $e.Id
                    Message = ($e.Message -split "`n")[0].Trim()
                    Flag    = "WHEA"
                    Journal = "System-WHEA"
                }
            }
        } catch { _CDWarn "Erreur lecture WHEA : $_" }
        return $r | Sort-Object Date -Descending
    }

    # ── 2. SESSIONS UTILISATEUR ───────────────────────────────────────────────
    function _GetSessions {
        param([datetime]$Depuis)
        $s = @()
        $ids = @(4634,4647,4624,4625,4800,4801,4802,4803,1074,1076)
        try {
            $evts = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=$ids; StartTime=$Depuis } -EA SilentlyContinue
            foreach ($e in $evts) {
                $type = switch ($e.Id) {
                    4634 {"DECONNEXION"} 4647 {"DECONNEXION-VOLONTAIRE"} 4624 {"CONNEXION"}
                    4625 {"ECHEC-CONNEXION"} 4800 {"VERROUILLAGE"} 4801 {"DEVERROUILLAGE"}
                    4802 {"ECRAN-VEILLE-ON"} 4803 {"ECRAN-VEILLE-OFF"}
                    1074 {"ARRET-INITIE"} 1076 {"ARRET-NON-PLANIFIE"} default {"SESSION"}
                }
                $user = ""
                if ($e.Message -match "Nom du compte[^\n]*:\s*(\S+)")  { $user = $Matches[1] }
                elseif ($e.Message -match "Account Name[^\n]*:\s*(\S+)") { $user = $Matches[1] }
                $s += [PSCustomObject]@{
                    Date    = $e.TimeCreated; Type=$type; User=$user
                    ID=$e.Id; TypeSession=""; IPSource=""; SessionID=""
                    Message=($e.Message -split "`n")[0].Trim()
                }
            }
        } catch { _CDWarn "Journal Security inaccessible (besoin admin) : $_" }
        try {
            $sys = Get-WinEvent -FilterHashtable @{ LogName='System'; Id=@(1074,1076,7002); StartTime=$Depuis } -EA SilentlyContinue
            foreach ($e in $sys) {
                $type = switch ($e.Id) { 1074{"ARRET-INITIE"} 1076{"ARRET-NON-PLANIFIE"} 7002{"SESSION-FIN"} default{"SESSION-SYS"} }
                $u=""; $sid=""; $ts2=""; $ip=""
                if ($e.Id -eq 7002 -and $e.Message -match "(?i)session\s+(\d+)") { $sid=$Matches[1] }
                $s += [PSCustomObject]@{
                    Date=$e.TimeCreated; Type=$type; User=$u
                    ID=$e.Id; TypeSession=$ts2; IPSource=$ip; SessionID=$sid
                    Message=($e.Message -split "`n")[0].Trim()
                }
            }
        } catch { _CDWarn "Erreur sessions System : $_" }
        return $s | Sort-Object Date -Descending
    }

    # ── 3. FICHIERS .DMP ─────────────────────────────────────────────────────
    function _GetDumps {
        param([datetime]$Depuis)
        $d = @()
        if (Test-Path $DossierMinidump) {
            Get-ChildItem $DossierMinidump -Filter "*.dmp" -EA SilentlyContinue |
                Where-Object { $_.LastWriteTime -ge $Depuis } | Sort-Object LastWriteTime -Descending |
                ForEach-Object { $d += [PSCustomObject]@{
                    Date=$_.LastWriteTime; Type="MINIDUMP-BSOD"; Nom=$_.Name
                    TailleKB=[math]::Round($_.Length/1KB,0); Chemin=$_.FullName } }
        }
        if (Test-Path $DossierCrash) {
            Get-ChildItem $DossierCrash -Filter "*.dmp" -Recurse -EA SilentlyContinue |
                Where-Object { $_.LastWriteTime -ge $Depuis } | Sort-Object LastWriteTime -Descending |
                ForEach-Object {
                    $t = "LIVE-KERNEL"
                    if ($_.Name -match "Watchdog") { $t="WATCHDOG-TIMEOUT" }
                    if ($_.Name -match "TDR")       { $t="TDR-GPU-TIMEOUT" }
                    if ($_.Name -match "WHEA")      { $t="WHEA-MATERIEL" }
                    if ($_.Name -match "Bugcheck")  { $t="BUGCHECK" }
                    $d += [PSCustomObject]@{
                        Date=$_.LastWriteTime; Type=$t; Nom=$_.Name
                        TailleKB=[math]::Round($_.Length/1KB,0); Chemin=$_.FullName }
                }
        }
        $m = "$env:SystemRoot\MEMORY.DMP"
        if ((Test-Path $m) -and (Get-Item $m).LastWriteTime -ge $Depuis) {
            $f=$m | Get-Item
            $d += [PSCustomObject]@{
                Date=$f.LastWriteTime; Type="MEMORY-DUMP-COMPLET"; Nom=$f.Name
                TailleKB=[math]::Round($f.Length/1MB,0); Chemin=$f.FullName }
        }
        return $d | Sort-Object Date -Descending
    }

    # ── 4. SCREEN FREEZE ─────────────────────────────────────────────────────
    function _GetFreezes {
        param([datetime]$Depuis)
        $r = @()
        try {
            Get-WinEvent -FilterHashtable @{ LogName='System'; StartTime=$Depuis } -EA SilentlyContinue |
                Where-Object { $_.Id -in @(4101,4117) -or $_.Message -match "TDR|display.*not responding|nvlddmkm|atikmpag|dxgkrnl.*timeout" } |
                ForEach-Object { $r += [PSCustomObject]@{
                    Date=$_.TimeCreated; Type="TDR-SCREEN-FREEZE"
                    Detail="Ecran gele recupere par Windows (pilote GPU relance)"
                    Source=$_.ProviderName; Message=($_.Message -split "`n")[0].Trim() } }
        } catch {}
        if (Test-Path $DossierCrash) {
            Get-ChildItem $DossierCrash -Recurse -Include "*.dmp","*.cab" -EA SilentlyContinue |
                Where-Object { $_.LastWriteTime -ge $Depuis -and $_.Name -match "TDR|Hang|Freeze|Watchdog" } |
                ForEach-Object { $r += [PSCustomObject]@{
                    Date=$_.LastWriteTime; Type="LIVEKERNELREPORT-FREEZE"
                    Detail="Fichier : $($_.Name) ($([math]::Round($_.Length/1KB,0)) Ko)"
                    Source=$_.FullName
                    Message="Rapport kernel genere lors d un freeze (analysable avec WinDbg/WhoCrashed)" } }
        }
        try {
            $all = Get-WinEvent -FilterHashtable @{ LogName='System'; StartTime=$Depuis } -EA SilentlyContinue | Sort-Object TimeCreated
            if ($all.Count -gt 2) {
                for ($i=1; $i -lt $all.Count; $i++) {
                    $gap = ($all[$i].TimeCreated - $all[$i-1].TimeCreated).TotalMinutes
                    $h   = $all[$i-1].TimeCreated.Hour
                    $nuit = (-not $H24) -and ($h -ge $NuitDebut -or $h -lt $NuitFin)
                    if ($gap -gt $GapSeuilMin -and -not $nuit) {
                        $note = if ($gap -gt 120) { " (ou mise en veille prolongee)" } else { "" }
                        $r += [PSCustomObject]@{
                            Date=$all[$i-1].TimeCreated; Type="GAP-LOG-SUSPECT"
                            Detail="Silence journal de $([math]::Round($gap,0)) min  ($($all[$i-1].TimeCreated.ToString('HH:mm')) -> $($all[$i].TimeCreated.ToString('HH:mm')))$note"
                            Source="Analyse gaps"
                            Message="Possible freeze$note : aucun log pendant $([math]::Round($gap,0)) minutes" }
                    }
                }
            }
        } catch {}
        return $r | Sort-Object Date -Descending
    }

    # ── 5. WATCHDOG / TDR / APP CRASH ────────────────────────────────────────
    function _GetWatchdog {
        param([datetime]$Depuis)
        $r = @()
        try {
            Get-WinEvent -FilterHashtable @{ LogName='System'; StartTime=$Depuis } -EA SilentlyContinue |
                Where-Object { $_.Id -in @(4101,4117) -or $_.Message -match "TDR|Watchdog|timeout.*display|display.*timeout|dxgkrnl|hung" } |
                ForEach-Object { $r += [PSCustomObject]@{
                    Date=$_.TimeCreated; Type=if($_.Id -eq 4101){"TDR-GPU-TIMEOUT"}else{"WATCHDOG"}
                    Source=$_.ProviderName; ID=$_.Id; Message=($_.Message -split "`n")[0].Trim()
                    ProcFautif=""; ProcModule=""; ProcChemin=""; ProcPid=""; ProcParent=""
                    Evenement=""; CodeErreur=""; ProcsVoisins=""; SourceEnrichie=""; MsgComplet="" } }
        } catch {}
        try {
            Get-WinEvent -FilterHashtable @{ LogName='Application'; Id=@(1002,1000,1001); StartTime=$Depuis } -EA SilentlyContinue |
                Where-Object { $_.ProviderName -notmatch "vmauthd|vmware|MsiInstaller|Software Protection|WMI|SecurityCenter" } |
                ForEach-Object {
                    $type = switch ($_.Id) { 1002{"APP-HANG"} 1000{"APP-CRASH"} 1001{"APP-CRASH-WERFAULT"} default{"APP-ERREUR"} }
                    $m2   = $_.Message
                    $pf=""; $pm=""; $pc=""; $pp=""; $par=""; $ce=""; $ev=""; $dbg=""
                    if ($m2 -match "(?mi)Nom de l(?:'|')application[^:]*:\s*([^\r\n,]+)")    { $pf=$Matches[1].Trim() }
                    elseif ($m2 -match "(?mi)Faulting application name:\s*([^\r\n,]+)")      { $pf=$Matches[1].Trim() }
                    if ($m2 -match "(?mi)Nom du module[^:]*:\s*([^\r\n,]+)")                 { $pm=$Matches[1].Trim() }
                    elseif ($m2 -match "(?mi)Faulting module name:\s*([^\r\n,]+)")           { $pm=$Matches[1].Trim() }
                    if ($m2 -match "(?mi)Chemin de l(?:'|')application[^:]*:\s*([^\r\n]+)") { $pc=$Matches[1].Trim() }
                    elseif ($m2 -match "(?mi)Faulting application path:\s*([^\r\n]+)")      { $pc=$Matches[1].Trim() }
                    if ($m2 -match "(?mi)Process Id\s*:\s*(\d+)")                            { $pp=$Matches[1].Trim() }
                    if ($m2 -match "Code d.exception\s*:\s*(0x[0-9a-fA-F]+)")               { $ce=$Matches[1] }
                    elseif ($m2 -match "Exception code:\s*(0x[0-9a-fA-F]+)")               { $ce=$Matches[1] }
                    if ($m2 -match "(?mi)Nom d.év[eé]nement\s*:\s*([^\r\n]+)")              { $ev=$Matches[1].Trim() }
                    elseif ($m2 -match "(?mi)Event Name\s*:\s*([^\r\n]+)")                  { $ev=$Matches[1].Trim() }
                    if ($_.ProviderName -match "Winlogon|WerFault") { $dbg=$m2 }
                    $src = if ($pf) { "$pf ($($_.ProviderName))" } else { $_.ProviderName }
                    $r += [PSCustomObject]@{
                        Date=$_.TimeCreated; Type=$type; Source=$_.ProviderName; ID=$_.Id
                        Message=($_.Message -split "`n")[0].Trim()
                        ProcFautif=$pf; ProcModule=$pm; ProcChemin=$pc; ProcPid=$pp; ProcParent=$par
                        Evenement=$ev; CodeErreur=$ce; ProcsVoisins=""; SourceEnrichie=$src; MsgComplet=$dbg }
                }
        } catch {}
        return $r | Sort-Object Date -Descending
    }

    # ── 6. CONTEXTE PRE-CRASH ────────────────────────────────────────────────
    function _GetPreCrash {
        param($EvtSys)
        $r = @()
        $brutaux = $EvtSys | Where-Object { $_.Flag -eq "ARRET_BRUTAL" } | Sort-Object Date
        foreach ($crash in $brutaux) {
            $tFin   = $crash.Date
            $tDebut = $crash.Date.AddSeconds(-90)
            try {
                $evts = Get-WinEvent -FilterHashtable @{ LogName='System','Application'; StartTime=$tDebut } -EA SilentlyContinue |
                    Where-Object { $_.TimeCreated -le $tFin } | Sort-Object TimeCreated
                if (-not $evts -or $evts.Count -eq 0) { continue }
                $groupes = $evts | Group-Object { "$($_.ProviderName)|$($_.Id)" }
                $lignes = @()
                foreach ($g in $groupes | Sort-Object { ($_.Group | Select-Object -First 1).TimeCreated }) {
                    $first = $g.Group | Sort-Object TimeCreated | Select-Object -First 1
                    $last  = $g.Group | Sort-Object TimeCreated | Select-Object -Last  1
                    $nb    = $g.Count
                    $msg   = ($first.Message -split "`n")[0].Trim()
                    if ($msg.Length -gt 80) { $msg = $msg.Substring(0,77)+"..." }
                    if ($nb -eq 1) { $lignes += "  [$($first.TimeCreated.ToString('HH:mm:ss'))]  $($first.ProviderName) (ID $($first.Id))"; $lignes += "    $msg" }
                    else           { $lignes += "  [$($first.TimeCreated.ToString('HH:mm:ss')) -> $($last.TimeCreated.ToString('HH:mm:ss'))]  $($first.ProviderName) (ID $($first.Id))  x$nb"; $lignes += "    $msg" }
                }
                $r += [PSCustomObject]@{ CrashDate=$crash.Date; FenetreDebut=$tDebut; FenetreFin=$tFin; NbEvts=$evts.Count; Lignes=$lignes; Groupes=$groupes }
            } catch {}
        }
        return $r
    }

    # ── 7. ETAT SYSTEME ──────────────────────────────────────────────────────
    function _GetInfoSys {
        $i = @{}
        try {
            $os = Get-CimInstance Win32_OperatingSystem
            $rT = [math]::Round($os.TotalVisibleMemorySize/1MB,1)
            $rL = [math]::Round($os.FreePhysicalMemory/1MB,1)
            $pct= [math]::Round((($rT-$rL)/$rT)*100,0)
            $i["RAM"]       = "$rT Go total | $rL Go libre | $pct% utilise"
            $i["RAM_Alerte"]= ($pct -gt 90)
            $up = (Get-Date) - $os.LastBootUpTime
            $i["Uptime"]    = "$($up.Days)j $($up.Hours)h $($up.Minutes)min  (boot: $($os.LastBootUpTime.ToString('dd/MM/yyyy HH:mm')))"
            $i["Hostname"]  = $env:COMPUTERNAME
            $i["OS"]        = "$($os.Caption) (Build $($os.BuildNumber)) — $($os.OSArchitecture)"
        } catch { $i["RAM"]="N/A"; $i["Uptime"]="N/A" }
        try {
            $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
            $i["CPU"]       = "$($cpu.Name.Trim()) | Charge : $($cpu.LoadPercentage)%"
            $i["CPU_Alerte"]= ($cpu.LoadPercentage -gt 95)
        } catch { $i["CPU"]="N/A" }
        try {
            $d  = Get-PSDrive C
            $lb = [math]::Round($d.Free/1GB,1); $tot=[math]::Round(($d.Used+$d.Free)/1GB,1)
            $i["Disque"]       = "C: $lb Go libres / $tot Go"
            $i["Disque_Alerte"]= ($lb -lt 5)
        } catch { $i["Disque"]="N/A" }
        try { $i["Processus"]="$((Get-Process).Count) processus actifs" } catch {}
        try {
            $ram = Get-CimInstance Win32_PhysicalMemory -EA SilentlyContinue
            $xmp = $false; $xd=""
            $std = @(800,1066,1333,1600,1866,2133,2400,2667,2933,3200,4800,5200,5600,6000,6400)
            foreach ($m3 in $ram) {
                if ($m3.Speed -and $m3.Speed -notin $std -and $m3.Speed -gt 2133) {
                    $xmp=$true; $xd="RAM a $($m3.Speed) MHz (profil XMP/EXPO actif probable)"
                }
            }
            if ($ram) { $i["RAM_Detail"]="$($ram.Count)x $([math]::Round(($ram|Select-Object -First 1).Capacity/1GB,0))Go @ $(($ram|Select-Object -First 1).Speed)MHz — $(($ram|Select-Object -First 1).Manufacturer)" }
            $i["XMP_Detecte"]=$xmp; $i["XMP_Detail"]=$xd
        } catch { $i["XMP_Detecte"]=$false }
        try {
            $qu = query user 2>$null
            $uc = if ($qu) { ($qu | Select-Object -Skip 1 | ForEach-Object { ($_ -split '\s{2,}')[0].Trim().TrimStart('>') }) -join ", " } else { $env:USERNAME }
            $i["UsersConnectes"]=$uc
        } catch { $i["UsersConnectes"]=$env:USERNAME }
        return $i
    }

    # ── 8. TRADUCTION CODES EXCEPTION ────────────────────────────────────────
    function _ExLabel { param($code)
        switch ($code) {
            "0xc0000005" { "(Violation acces memoire)" }    "0xc000007b" { "(Appli 32/64 bits incompatible)" }
            "0xc0000409" { "(Stack buffer overflow)" }      "0xe0434352" { "(.NET runtime crash)" }
            "0x80000003" { "(Breakpoint inattendu)" }       "0xc0000374" { "(Corruption heap)" }
            "0xc00000fd" { "(Stack overflow)" }             "0xc0000135" { "(DLL introuvable)" }
            "0xc0000142" { "(Echec init DLL)" }             "0xe06d7363" { "(Exception C++ non geree)" }
            default { "" }
        }
    }

    # ── 9. GENERATION RAPPORT TXT ────────────────────────────────────────────
    function _WriteRapport {
        param($EvtSys,$Sessions,$Dumps,$Watchdog,$Freezes,$InfoSys,[datetime]$Depuis,$PreCrash)
        $now=$now=Get-Date; $L="="*68; $l="-"*68; $c=@()
        $nbF  = $Freezes.Count
        $nbB  = ($EvtSys|Where-Object{$_.Flag -eq "ARRET_BRUTAL"}).Count
        $nbBS = ($EvtSys|Where-Object{$_.Flag -eq "BSOD"}).Count
        $nbW  = ($EvtSys|Where-Object{$_.Flag -eq "WATCHDOG"}).Count + ($Watchdog|Where-Object{$_.Type -match "WATCHDOG|TDR"}).Count
        $nbWH = ($EvtSys|Where-Object{$_.Flag -eq "WHEA"}).Count
        $nbG  = ($EvtSys|Where-Object{$_.Flag -eq "GPU"}).Count
        $nbD  = $Dumps.Count
        $nbDe = ($Sessions|Where-Object{$_.Type -match "DECONNEXION|ARRET-NON-PLANIFIE"}).Count
        $nbH  = ($Watchdog|Where-Object{$_.Type -match "HANG|CRASH"}).Count
        $score= ($nbB*3)+($nbBS*5)+($nbWH*4)+($nbW*2)+($nbG*2)+($nbD*3)
        $grav = if($score -ge 15){"[!!] CRITIQUE - Panne materielle probable"}
                elseif($score -ge 6){"[!!] SERIEUX  - Instabilite significative"}
                elseif($score -ge 2){"[>>] ATTENTION - Anomalies a surveiller"}
                else{"[OK] Aucune anomalie grave detectee"}

        $c += $L; $c += "  RAPPORT CRASHDIAG — WinToolkit"
        $c += "  Genere le  : $($now.ToString('dd/MM/yyyy HH:mm:ss'))"
        $c += "  Periode    : $($Depuis.ToString('dd/MM/yyyy HH:mm'))  ->  maintenant"
        $c += "  Machine    : $($InfoSys['Hostname'])"
        $c += "  OS         : $($InfoSys['OS'])"
        $c += "  User(s)    : $($InfoSys['UsersConnectes'])"
        $c += $L; $c += ""
        $c += "[ RESUME — ALERTES DETECTEES ]"; $c += $l
        $c += "  Screen freeze / gaps logs     : $nbF"
        $c += "  Arrets brutaux (ID 41/6008)  : $nbB"
        $c += "  BSOD / BugCheck              : $nbBS"
        $c += "  Watchdog / TDR GPU           : $nbW"
        $c += "  Erreurs materielles (WHEA)   : $nbWH"
        $c += "  Problemes GPU/pilote         : $nbG"
        $c += "  Fichiers .DMP trouves        : $nbD"
        $c += "  Deconnexions/arrets          : $nbDe"
        $c += "  Applis plantees (hang/crash) : $nbH"
        $c += ""; $c += "  NIVEAU DE GRAVITE : $grav"; $c += ""
        $c += $L; $c += "[ ETAT DU SYSTEME ]"; $c += $l
        $c += "  CPU    : $($InfoSys['CPU'])"
        $c += "  RAM    : $($InfoSys['RAM'])"
        if ($InfoSys['RAM_Detail']) { $c += "  RAM Det: $($InfoSys['RAM_Detail'])" }
        $c += "  Disque : $($InfoSys['Disque'])"
        $c += "  Uptime : $($InfoSys['Uptime'])"
        $c += "  Procs  : $($InfoSys['Processus'])"
        if ($InfoSys["XMP_Detecte"]) { $c += "  /!\ XMP/EXPO : $($InfoSys['XMP_Detail'])" }
        if ($InfoSys["RAM_Alerte"])   { $c += "  /!\ ALERTE RAM : memoire quasi saturee !" }
        if ($InfoSys["Disque_Alerte"]){ $c += "  /!\ ALERTE DISQUE : C: presque plein !" }
        $c += ""

        # DUMPS
        $c += $L; $c += "[ FICHIERS .DMP ]"; $c += $l
        if ($Dumps.Count -eq 0) { $c += "  Aucun fichier .dmp recent." }
        else {
            $c += "  ATTENTION : $($Dumps.Count) fichier(s) crash detecte(s) !"; $c += ""
            foreach ($d in $Dumps) {
                $c += "  DATE   : $($d.Date.ToString('dd/MM/yyyy HH:mm:ss'))"
                $c += "  TYPE   : $($d.Type)"; $c += "  FICHIER: $($d.Nom)  ($($d.TailleKB) Ko)"
                $c += "  CHEMIN : $($d.Chemin)"; $c += ""
            }
        }
        $c += ""

        # ARRETS BRUTAUX
        $brutaux = $EvtSys | Where-Object { $_.Flag -eq "ARRET_BRUTAL" }
        $c += $L; $c += "[ ARRETS BRUTAUX ]"; $c += $l
        if ($brutaux.Count -eq 0) { $c += "  Aucun arret brutal detecte." }
        else {
            foreach ($e in $brutaux) {
                $c += "  DATE : $($e.Date.ToString('dd/MM/yyyy HH:mm:ss'))  |  $($e.Source) (ID $($e.ID))"
                $c += "  MSG  : $($e.Message)"; $c += ""
            }
        }

        # PRE-CRASH
        if ($PreCrash -and $PreCrash.Count -gt 0) {
            $c += $L; $c += "[ CONTEXTE PRE-CRASH (90s avant chaque arret brutal) ]"; $c += $l
            foreach ($pc in $PreCrash) {
                $c += "  Arret : $($pc.CrashDate.ToString('dd/MM/yyyy HH:mm:ss'))"
                $c += "  Fenetre : $($pc.FenetreDebut.ToString('HH:mm:ss')) -> $($pc.FenetreFin.ToString('HH:mm:ss'))  ($($pc.NbEvts) evts)"
                $c += "  "+("-"*60)
                $pc.Lignes | ForEach-Object { $c += $_ }
                $c += ""
            }
        }

        # BSOD
        $bsods = $EvtSys | Where-Object { $_.Flag -eq "BSOD" }
        $c += $L; $c += "[ BSOD / ECRANS BLEUS ]"; $c += $l
        if ($bsods.Count -eq 0) { $c += "  Aucun BSOD detecte." }
        else { foreach ($e in $bsods) { $c += "  DATE : $($e.Date.ToString('dd/MM/yyyy HH:mm:ss'))"; $c += "  CODE : $($e.Message)"; $c += "" } }

        # WATCHDOG / TDR
        $wdE  = $EvtSys | Where-Object { $_.Flag -eq "WATCHDOG" }
        $tdrE = $Watchdog | Where-Object { $_.Type -match "WATCHDOG|TDR" }
        $c += $L; $c += "[ WATCHDOG / TDR GPU ]"; $c += $l
        if ($wdE.Count -eq 0 -and $tdrE.Count -eq 0) { $c += "  Aucun Watchdog/TDR detecte." }
        else {
            $tous = @()
            $wdE  | ForEach-Object { $tous += [PSCustomObject]@{Date=$_.Date;Type="WATCHDOG-KERNEL";Msg=$_.Message} }
            $tdrE | ForEach-Object { $tous += [PSCustomObject]@{Date=$_.Date;Type=$_.Type;Msg=$_.Message} }
            foreach ($e in $tous | Sort-Object Date -Descending) {
                $c += "  DATE : $($e.Date.ToString('dd/MM/yyyy HH:mm:ss'))  |  TYPE : $($e.Type)"
                $c += "  MSG  : $($e.Msg)"; $c += ""
            }
        }

        # WHEA
        $whea = $EvtSys | Where-Object { $_.Flag -eq "WHEA" }
        $c += $L; $c += "[ ERREURS MATERIELLES WHEA ]"; $c += $l
        if ($whea.Count -eq 0) { $c += "  Aucune erreur WHEA." }
        else { foreach ($e in $whea|Select-Object -First 10) { $c += "  DATE : $($e.Date.ToString('dd/MM/yyyy HH:mm:ss'))  |  $($e.Source)"; $c += "  MSG  : $($e.Message)"; $c += "" } }

        # GPU
        $gpu = $EvtSys | Where-Object { $_.Flag -eq "GPU" }
        $c += $L; $c += "[ PROBLEMES PILOTE GPU ]"; $c += $l
        if ($gpu.Count -eq 0) { $c += "  Aucun probleme GPU detecte." }
        else { foreach ($e in $gpu|Select-Object -First 15) { $c += "  DATE : $($e.Date.ToString('dd/MM/yyyy HH:mm:ss'))  |  $($e.Source)"; $c += "  MSG  : $($e.Message)"; $c += "" } }

        # SCREEN FREEZE
        $c += $L; $c += "[ SCREEN FREEZE ]"; $c += $l
        if ($Freezes.Count -eq 0) { $c += "  Aucun freeze detecte." }
        else {
            foreach ($f in $Freezes) {
                $c += "  DATE   : $($f.Date.ToString('dd/MM/yyyy HH:mm:ss'))"
                $c += "  TYPE   : $($f.Type)"; $c += "  DETAIL : $($f.Detail)"; $c += ""
            }
        }

        # SESSIONS
        $c += $L; $c += "[ SESSIONS UTILISATEUR ]"; $c += $l
        if ($Sessions.Count -eq 0) { $c += "  Aucune session (journal Security peut necessiter droits admin)." }
        else {
            $decoSusp = $Sessions | Where-Object { $_.Type -match "ARRET-NON-PLANIFIE|DECONNEXION$" }
            if ($decoSusp.Count -gt 0) {
                $c += "  DECONNEXIONS NON PLANIFIEES :"
                foreach ($s in $decoSusp|Select-Object -First 20) {
                    $c += "  $($s.Date.ToString('dd/MM/yyyy HH:mm:ss'))  [$($s.Type)]$(if($s.User){" | $($s.User)"})"
                }
                $c += ""
            }
            $c += "  HISTORIQUE COMPLET :"
            foreach ($s in $Sessions|Select-Object -First 30) {
                $c += "  $($s.Date.ToString('dd/MM/yyyy HH:mm:ss'))  [$($s.Type)]$(if($s.User){" | $($s.User)"})"
            }
        }
        $c += ""

        # APP CRASH
        $crashes = $Watchdog | Where-Object { $_.Type -match "HANG|CRASH" } | Select-Object -First 15
        $c += $L; $c += "[ APPLICATIONS PLANTEES ]"; $c += $l
        if ($crashes.Count -eq 0) { $c += "  Aucun crash applicatif detecte." }
        else {
            foreach ($e in $crashes) {
                $c += "  $($e.Date.ToString('dd/MM/yyyy HH:mm:ss'))  [$($e.Type)]"
                if ($e.ProcFautif)  { $c += "  COUPABLE : $($e.ProcFautif)" }
                if ($e.ProcModule)  { $c += "  MODULE   : $($e.ProcModule)" }
                if ($e.CodeErreur) { $c += "  CODE ERR : $($e.CodeErreur)  $(_ExLabel $e.CodeErreur)" }
                $c += "  MSG      : $($e.Message)"; $c += ""
            }
        }

        # RECOMMANDATIONS
        $c += $L; $c += "[ RECOMMANDATIONS ]"; $c += $l
        $r2=@()
        if ($nbB -gt 0 -or $nbBS -gt 0) {
            $r2 += "  [ARRET BRUTAL / BSOD]"
            $r2 += "  -> RAM : tapez 'mdsched' dans Windows"
            $r2 += "  -> Temp CPU : HWMonitor (> 90C = probleme)"
            $r2 += "  -> Analysez les .dmp avec WhoCrashed"; $r2 += ""
        }
        if ($nbD -gt 0) { $r2 += "  [.DMP TROUVES] -> WhoCrashed : https://www.resplendence.com/whocrashed"; $r2 += "" }
        if ($nbW -gt 0 -or $nbG -gt 0) {
            $r2 += "  [WATCHDOG / TDR / GPU]"
            $r2 += "  -> Mise a jour pilotes GPU (GeForce Experience / AMD Adrenalin)"
            $r2 += "  -> Si recent : desinstallez avec DDU (Display Driver Uninstaller)"
            $r2 += "  -> Temp GPU : MSI Afterburner (> 85C = probleme)"; $r2 += ""
        }
        if ($nbWH -gt 0) {
            $r2 += "  [WHEA = MATERIEL DEFAILLANT]"
            $r2 += "  -> RAM : MemTest86 (boot USB, test long)"
            $r2 += "  -> CPU : verifiez si OC actif"; $r2 += ""
        }
        if ($InfoSys["XMP_Detecte"]) {
            $r2 += "  [XMP/EXPO] -> $($InfoSys['XMP_Detail'])"
            $r2 += "  -> Desactivez XMP dans le BIOS pour tester"; $r2 += ""
        }
        if ($r2.Count -eq 0) {
            $r2 += "  Aucune anomalie grave dans la periode analysee."
            $r2 += "  Si les plantages continuent : -HeuresHistorique $($HeuresHistorique*2)"
        }
        $c += $r2; $c += ""; $c += $L
        $c += "  Auteur : ps81frt — https://github.com/ps81frt/"
        $c += "  Outils : WhoCrashed / HWMonitor / MemTest86 / DDU"
        $c += $L
        $c | Out-File -FilePath $FichierLog -Encoding UTF8 -Force
        return $c
    }

    # ── 10. RAPPORT HTML ─────────────────────────────────────────────────────
    function _WriteHTML {
        param($EvtSys,$Sessions,$Dumps,$Watchdog,$Freezes,$InfoSys,[datetime]$Depuis,$PreCrash)
        $now=Get-Date
        $nbF=$Freezes.Count
        $nbB=($EvtSys|Where-Object{$_.Flag -eq "ARRET_BRUTAL"}).Count
        $nbBS=($EvtSys|Where-Object{$_.Flag -eq "BSOD"}).Count
        $nbW=($EvtSys|Where-Object{$_.Flag -eq "WATCHDOG"}).Count+($Watchdog|Where-Object{$_.Type -match "WATCHDOG|TDR"}).Count
        $nbWH=($EvtSys|Where-Object{$_.Flag -eq "WHEA"}).Count
        $nbG=($EvtSys|Where-Object{$_.Flag -eq "GPU"}).Count
        $nbD=$Dumps.Count
        $nbDe=($Sessions|Where-Object{$_.Type -match "DECONNEXION|ARRET-NON-PLANIFIE"}).Count
        $nbH=($Watchdog|Where-Object{$_.Type -match "HANG|CRASH"}).Count
        $score=($nbB*3)+($nbBS*5)+($nbWH*4)+($nbW*2)+($nbG*2)+($nbD*3)+($nbH*1)
        $gL=if($score -ge 15){"CRITIQUE"}elseif($score -ge 6){"SERIEUX"}elseif($score -ge 2){"ATTENTION"}else{"OK"}
        $gC=switch($gL){"CRITIQUE"{"#e74c3c"}"SERIEUX"{"#e67e22"}"ATTENTION"{"#f1c40f"}default{"#2ecc71"}}

        # sections HTML
        $secRes=@"
<div class='summary-grid'>
  <div class='card $(if($nbF -gt 0){"card-warn"})'><div class='card-val'>$nbF</div><div class='card-lbl'>Screen Freeze</div></div>
  <div class='card $(if($nbB -gt 0){"card-crit"})'><div class='card-val'>$nbB</div><div class='card-lbl'>Arrets Brutaux</div></div>
  <div class='card $(if($nbBS -gt 0){"card-crit"})'><div class='card-val'>$nbBS</div><div class='card-lbl'>BSOD</div></div>
  <div class='card $(if($nbW -gt 0){"card-warn"})'><div class='card-val'>$nbW</div><div class='card-lbl'>Watchdog/TDR</div></div>
  <div class='card $(if($nbWH -gt 0){"card-crit"})'><div class='card-val'>$nbWH</div><div class='card-lbl'>WHEA</div></div>
  <div class='card $(if($nbG -gt 0){"card-warn"})'><div class='card-val'>$nbG</div><div class='card-lbl'>GPU/Pilote</div></div>
  <div class='card $(if($nbD -gt 0){"card-warn"})'><div class='card-val'>$nbD</div><div class='card-lbl'>Fichiers .DMP</div></div>
  <div class='card $(if($nbDe -gt 0){"card-warn"})'><div class='card-val'>$nbDe</div><div class='card-lbl'>Deconnexions</div></div>
  <div class='card $(if($nbH -gt 0){"card-warn"})'><div class='card-val'>$nbH</div><div class='card-lbl'>App Plantees</div></div>
</div>
<div class='gravite-bar' style='border-left:4px solid $gC'>
  <span style='color:$gC;font-weight:700'>&#9679; $gL</span>
  &nbsp;&mdash;&nbsp; Score : $score &nbsp;|&nbsp; Periode : $($Depuis.ToString('dd/MM/yyyy HH:mm')) &rarr; $($now.ToString('dd/MM/yyyy HH:mm'))
</div>
"@
        $secSys=@"
<table>
  <tr><td>Hostname</td><td><strong>$($InfoSys['Hostname'])</strong></td></tr>
  <tr><td>OS</td><td>$($InfoSys['OS'])</td></tr>
  <tr><td>User(s)</td><td>$($InfoSys['UsersConnectes'])</td></tr>
  <tr><td>CPU</td><td>$($InfoSys['CPU'])</td></tr>
  <tr><td>RAM</td><td>$($InfoSys['RAM'])</td></tr>
  $(if($InfoSys['RAM_Detail']){"<tr><td>RAM Detail</td><td>$($InfoSys['RAM_Detail'])</td></tr>"})
  <tr><td>Disque</td><td>$($InfoSys['Disque'])</td></tr>
  <tr><td>Uptime</td><td>$($InfoSys['Uptime'])</td></tr>
  <tr><td>Processus</td><td>$($InfoSys['Processus'])</td></tr>
  $(if($InfoSys['XMP_Detecte']){"<tr class='row-warn'><td>XMP/EXPO</td><td>&#9888; $($InfoSys['XMP_Detail'])</td></tr>"})
</table>
"@
        # Crashes
        $crashRows=$Watchdog|Where-Object{$_.Type -match "HANG|CRASH"}
        if ($crashRows.Count -eq 0) { $secCrash="<p class='ok-msg'>&#10003; Aucun crash applicatif detecte.</p>" }
        else {
            $secCrash=""
            foreach ($e in $crashRows) {
                $bt=if($e.Type -match "CRASH"){"badge-crit"}else{"badge-warn"}
                $secCrash+="<div class='event-card'><div class='event-header'><span class='badge $bt'>$($e.Type)</span> <span class='event-date'>$($e.Date.ToString('dd/MM/yyyy HH:mm:ss'))</span></div>"
                if($e.ProcFautif){$secCrash+="<div><span class='lbl'>COUPABLE</span> <strong>$($e.ProcFautif)</strong></div>"}
                if($e.ProcModule){$secCrash+="<div><span class='lbl'>MODULE</span> <code>$($e.ProcModule)</code></div>"}
                if($e.CodeErreur){$secCrash+="<div><span class='lbl'>CODE ERR</span> <code>$($e.CodeErreur)</code></div>"}
                $secCrash+="<div><span class='lbl'>MSG</span> $([System.Web.HttpUtility]::HtmlEncode($e.Message))</div></div>"
            }
        }
        # Sessions
        if ($Sessions.Count -eq 0) { $secSess="<p class='ok-msg'>Aucune session (journal Security requis).</p>" }
        else {
            $rows=@()
            foreach ($s in $Sessions|Select-Object -First 50) {
                $u=if($s.User){$s.User}else{"-"}
                $cls=if($s.Type -match "ARRET-NON-PLANIFIE|DECONNEXION$"){" class='row-warn'"}else{""}
                $rows+="<tr$cls><td>$($s.Date.ToString('dd/MM/yyyy HH:mm:ss'))</td><td>$($s.Type)</td><td>$u</td></tr>"
            }
            $secSess="<table><thead><tr><th>Date</th><th>Type</th><th>User</th></tr></thead><tbody>"+($rows -join "")+"</tbody></table>"
        }
        # Freezes
        if ($Freezes.Count -eq 0) { $secFrz="<p class='ok-msg'>&#10003; Aucun freeze detecte.</p>" }
        else {
            $rows=@()
            foreach ($f in $Freezes) { $rows+="<tr><td>$($f.Date.ToString('dd/MM/yyyy HH:mm:ss'))</td><td><span class='badge badge-warn'>$($f.Type)</span></td><td>$($f.Detail)</td></tr>" }
            $secFrz="<table><thead><tr><th>Date</th><th>Type</th><th>Detail</th></tr></thead><tbody>"+($rows -join "")+"</tbody></table>"
        }
        # Evt systeme
        $evtC=$EvtSys|Where-Object{$_.Flag -ne ""}
        if ($evtC.Count -eq 0) { $secEvt="<p class='ok-msg'>&#10003; Aucun evenement critique.</p>" }
        else {
            $rows=@()
            foreach ($e in $evtC|Select-Object -First 50) {
                $cls=if($e.Sev -eq "CRITIQUE"){" class='row-crit'"}else{" class='row-warn'"}
                $rows+="<tr$cls><td>$($e.Date.ToString('dd/MM/yyyy HH:mm:ss'))</td><td>$($e.Flag)</td><td>$($e.Source)</td><td>$($e.ID)</td><td>$([System.Web.HttpUtility]::HtmlEncode($e.Message))</td></tr>"
            }
            $secEvt="<table><thead><tr><th>Date</th><th>Flag</th><th>Source</th><th>ID</th><th>Message</th></tr></thead><tbody>"+($rows -join "")+"</tbody></table>"
        }
        # Pre-crash
        if ($PreCrash -and $PreCrash.Count -gt 0) {
            $secPC=""
            foreach ($pc in $PreCrash) {
                $secPC+="<div class='event-card'><div class='event-header'><span class='badge badge-crit'>ARRET BRUTAL</span> <span class='event-date'>$($pc.CrashDate.ToString('dd/MM/yyyy HH:mm:ss'))</span></div>"
                $secPC+="<div style='font-size:.82em;color:var(--text2);margin-bottom:8px'>$($pc.FenetreDebut.ToString('HH:mm:ss')) &rarr; $($pc.FenetreFin.ToString('HH:mm:ss')) &mdash; $($pc.NbEvts) evts</div>"
                $secPC+="<table><thead><tr><th>Heure</th><th>Source</th><th>ID</th><th>x</th><th>Message</th></tr></thead><tbody>"
                foreach ($g in $pc.Groupes|Sort-Object{($_.Group|Select-Object -First 1).TimeCreated}) {
                    $first=$g.Group|Sort-Object TimeCreated|Select-Object -First 1
                    $last=$g.Group|Sort-Object TimeCreated|Select-Object -Last 1
                    $nb=$g.Count; $msg=($first.Message -split "`n")[0].Trim()
                    if($msg.Length -gt 90){$msg=$msg.Substring(0,87)+"..."}
                    $per=if($nb -gt 1){"$($first.TimeCreated.ToString('HH:mm:ss')) &rarr; $($last.TimeCreated.ToString('HH:mm:ss'))"}else{$first.TimeCreated.ToString('HH:mm:ss')}
                    $cls=if($first.Id -in @(41,6008,1001,153,55)){" class='row-crit'"}elseif($nb -ge 5){" class='row-warn'"}else{""}
                    $secPC+="<tr$cls><td>$per</td><td>$([System.Web.HttpUtility]::HtmlEncode($first.ProviderName))</td><td>$($first.Id)</td><td><strong>$nb</strong></td><td>$([System.Web.HttpUtility]::HtmlEncode($msg))</td></tr>"
                }
                $secPC+="</tbody></table></div>"
            }
        } else { $secPC="<p class='ok-msg'>&#10003; Aucun arret brutal — pas de contexte pre-crash.</p>" }
        # Dumps
        if ($Dumps.Count -eq 0) { $secDmp="<p class='ok-msg'>&#10003; Aucun fichier .dmp recent.</p>" }
        else {
            $rows=@()
            foreach ($d in $Dumps) { $rows+="<tr class='row-warn'><td>$($d.Date.ToString('dd/MM/yyyy HH:mm:ss'))</td><td>$($d.Type)</td><td>$($d.Nom)</td><td>$($d.TailleKB) Ko</td><td><code>$($d.Chemin)</code></td></tr>" }
            $secDmp="<table><thead><tr><th>Date</th><th>Type</th><th>Fichier</th><th>Taille</th><th>Chemin</th></tr></thead><tbody>"+($rows -join "")+"</tbody></table>"
        }
        # Recos
        $ri=@()
        if ($nbB -gt 0 -or $nbBS -gt 0) { $ri+="<div class='reco-item reco-crit'><strong>ARRET BRUTAL / BSOD</strong><ul><li>Testez la RAM : <code>mdsched</code></li><li>Verifiez temp CPU (HWMonitor &gt;90C)</li><li>Analysez .dmp avec WhoCrashed</li></ul></div>" }
        if ($nbD -gt 0)  { $ri+="<div class='reco-item reco-warn'><strong>FICHIERS .DMP</strong><ul><li><a href='https://www.resplendence.com/whocrashed' target='_blank'>WhoCrashed</a></li></ul></div>" }
        if ($nbW -gt 0 -or $nbG -gt 0) { $ri+="<div class='reco-item reco-warn'><strong>WATCHDOG / TDR / GPU</strong><ul><li>Mise a jour pilotes GPU</li><li>DDU si recent</li><li>Temp GPU MSI Afterburner (&gt;85C)</li></ul></div>" }
        if ($nbWH -gt 0) { $ri+="<div class='reco-item reco-crit'><strong>WHEA</strong><ul><li>RAM : MemTest86</li><li>CPU OC : desactiver</li></ul></div>" }
        if ($InfoSys["XMP_Detecte"]) { $ri+="<div class='reco-item reco-warn'><strong>XMP/EXPO</strong><ul><li>$($InfoSys['XMP_Detail'])</li><li>Desactiver XMP dans BIOS pour tester</li></ul></div>" }
        if ($ri.Count -eq 0) { $ri+="<div class='reco-item reco-ok'><strong>&#10003; Aucune anomalie grave</strong><p>Augmentez la fenetre si besoin : <code>-HeuresHistorique $($HeuresHistorique*2)</code></p></div>" }
        $secReco=$ri -join ""

        $html=@"
<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CrashDiag — $($InfoSys['Hostname']) — $($now.ToString('dd/MM/yyyy HH:mm'))</title>
<style>
:root{--bg:#f4f6f9;--surface:#fff;--surface2:#f0f2f5;--border:#e0e4ea;--text:#1a1d23;--text2:#555;--accent:#3b82f6;--ok:#2ecc71;--warn:#f1c40f;--crit:#e74c3c;--sidebar:#1e2533;--sidebar-text:#a8b3c8;--sidebar-active:#3b82f6;--shadow:0 2px 8px rgba(0,0,0,.08)}
[data-theme="dark"]{--bg:#0f1117;--surface:#1a1d27;--surface2:#222636;--border:#2d3147;--text:#e8eaf0;--text2:#8b95a8;--accent:#60a5fa;--sidebar:#0d1018;--sidebar-text:#8b95a8;--sidebar-active:#60a5fa;--shadow:0 2px 8px rgba(0,0,0,.4)}
*{box-sizing:border-box;margin:0;padding:0}body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);display:flex;min-height:100vh;font-size:14px}a{color:var(--accent)}
#sidebar{width:220px;min-width:220px;background:var(--sidebar);display:flex;flex-direction:column;position:sticky;top:0;height:100vh;overflow-y:auto}
#sidebar-header{padding:18px 14px 10px;border-bottom:1px solid rgba(255,255,255,.06)}#sidebar-header h2{color:#fff;font-size:.9em;font-weight:600}#sidebar-header p{color:var(--sidebar-text);font-size:.72em;margin-top:3px}
#sidebar nav{padding:6px 0;flex:1}#sidebar nav a{display:flex;align-items:center;gap:8px;padding:8px 14px;color:var(--sidebar-text);text-decoration:none;font-size:.82em;border-left:3px solid transparent;transition:all .15s}
#sidebar nav a:hover,#sidebar nav a.active{color:#fff;background:rgba(255,255,255,.06);border-left-color:var(--sidebar-active)}
#sidebar nav a .nb{margin-left:auto;background:var(--crit);color:#fff;border-radius:10px;padding:1px 6px;font-size:.72em;font-weight:700}.nb.ok{background:transparent;color:var(--sidebar-text)}.nb.warn{background:#e67e22}
#sidebar-footer{padding:10px 14px;border-top:1px solid rgba(255,255,255,.06);font-size:.7em;color:var(--sidebar-text)}#sidebar-footer a{color:var(--sidebar-active)}
#main{flex:1;display:flex;flex-direction:column;min-width:0}
#topbar{background:var(--surface);border-bottom:1px solid var(--border);padding:9px 20px;display:flex;align-items:center;gap:10px;position:sticky;top:0;z-index:10;box-shadow:var(--shadow)}
#topbar h1{font-size:.95em;font-weight:600;flex:1}.gp{padding:3px 12px;border-radius:20px;font-size:.78em;font-weight:700;color:#fff;background:var(--crit)}.gp.ok{background:var(--ok)}.gp.warn{background:var(--warn);color:#333}.gp.attention{background:#f1c40f;color:#333}
.btn{padding:6px 12px;border-radius:5px;border:1px solid var(--border);background:var(--surface2);color:var(--text);cursor:pointer;font-size:.8em;font-weight:500;display:inline-flex;align-items:center;gap:5px;transition:all .15s}.btn:hover{background:var(--accent);color:#fff;border-color:var(--accent)}.btn-group{display:flex;gap:5px}
#content{padding:20px;flex:1;overflow-y:auto}.section{display:none}.section.active{display:block}.section-title{font-size:1.05em;font-weight:700;margin-bottom:14px;padding-bottom:7px;border-bottom:2px solid var(--border)}
.summary-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:10px;margin-bottom:14px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:14px 10px;text-align:center;box-shadow:var(--shadow)}.card-val{font-size:1.9em;font-weight:800;line-height:1}.card-lbl{font-size:.72em;color:var(--text2);margin-top:3px}
.card-warn{border-color:var(--warn);background:rgba(241,196,15,.08)}.card-warn .card-val{color:#e67e22}.card-crit{border-color:var(--crit);background:rgba(231,76,60,.08)}.card-crit .card-val{color:var(--crit)}
.gravite-bar{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:10px 14px;margin-bottom:8px;font-size:.85em;color:var(--text2)}
table{width:100%;border-collapse:collapse;background:var(--surface);border-radius:8px;overflow:hidden;box-shadow:var(--shadow);font-size:.82em}th{background:var(--surface2);padding:9px 11px;text-align:left;font-weight:600;font-size:.78em;text-transform:uppercase;letter-spacing:.4px;color:var(--text2);border-bottom:1px solid var(--border)}td{padding:8px 11px;border-bottom:1px solid var(--border);vertical-align:top}tr:last-child td{border-bottom:none}tr:hover td{background:var(--surface2)}
.row-warn td{background:rgba(241,196,15,.06)}.row-warn:hover td{background:rgba(241,196,15,.12)}.row-crit td{background:rgba(231,76,60,.06)}.row-crit:hover td{background:rgba(231,76,60,.12)}
.event-card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:14px;margin-bottom:10px;box-shadow:var(--shadow)}.event-header{display:flex;align-items:center;gap:8px;margin-bottom:8px}.event-date{color:var(--text2);font-size:.8em}.lbl{display:inline-block;background:var(--surface2);border:1px solid var(--border);border-radius:4px;padding:1px 6px;font-size:.72em;font-weight:600;margin-right:5px;color:var(--text2)}.event-card>div{margin-bottom:5px;font-size:.85em}
.badge{display:inline-block;padding:2px 9px;border-radius:20px;font-size:.72em;font-weight:700;background:var(--surface2);color:var(--text2);border:1px solid var(--border)}.badge-crit{background:rgba(231,76,60,.15);color:var(--crit);border-color:rgba(231,76,60,.3)}.badge-warn{background:rgba(241,196,15,.15);color:#b7860a;border-color:rgba(241,196,15,.4)}
.reco-item{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:14px;margin-bottom:10px}.reco-item ul{margin:7px 0 0 18px;font-size:.85em;color:var(--text2)}.reco-item ul li{margin-bottom:3px}.reco-crit{border-left:4px solid var(--crit)}.reco-warn{border-left:4px solid var(--warn)}.reco-ok{border-left:4px solid var(--ok)}.reco-item strong{font-size:.9em}
.ok-msg{color:var(--ok);font-weight:600;padding:10px;background:rgba(46,204,113,.08);border-radius:8px;border:1px solid rgba(46,204,113,.2)}
code{background:var(--surface2);border:1px solid var(--border);border-radius:4px;padding:1px 5px;font-size:.83em;font-family:'Cascadia Code','Consolas',monospace}
pre{background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:10px;font-size:.76em;overflow-x:auto;margin-top:7px;white-space:pre-wrap;word-break:break-word;color:var(--text2)}
</style></head>
<body data-theme="light">
<aside id="sidebar">
  <div id="sidebar-header"><h2>&#9673; CrashDiag</h2><p>$($InfoSys['Hostname'])</p></div>
  <nav>
    <a href="#" onclick="show('resume')" class="active" id="nav-resume"><span>&#8801;</span><span>Resume</span><span class="nb $(if($score -eq 0){'ok'}elseif($score -lt 6){'warn'}else{''})">$gL</span></a>
    <a href="#" onclick="show('systeme')" id="nav-systeme"><span>&#9881;</span><span>Systeme</span></a>
    <a href="#" onclick="show('crashes')" id="nav-crashes"><span>&#128165;</span><span>App Plantees</span>$(if($nbH -gt 0){"<span class='nb'>$nbH</span>"})</a>
    <a href="#" onclick="show('sessions')" id="nav-sessions"><span>&#128100;</span><span>Sessions</span>$(if($nbDe -gt 0){"<span class='nb warn'>$nbDe</span>"})</a>
    <a href="#" onclick="show('freezes')" id="nav-freezes"><span>&#10052;</span><span>Freezes</span>$(if($nbF -gt 0){"<span class='nb warn'>$nbF</span>"})</a>
    <a href="#" onclick="show('evtsys')" id="nav-evtsys"><span>&#9888;</span><span>Evt Systeme</span>$(if($evtC.Count -gt 0){"<span class='nb'>$($evtC.Count)</span>"})</a>
    <a href="#" onclick="show('precrash')" id="nav-precrash"><span>&#128269;</span><span>Pre-Crash</span>$(if($PreCrash -and $PreCrash.Count -gt 0){"<span class='nb'>$($PreCrash.Count)</span>"})</a>
    <a href="#" onclick="show('dumps')" id="nav-dumps"><span>&#128190;</span><span>Dumps .DMP</span>$(if($nbD -gt 0){"<span class='nb'>$nbD</span>"})</a>
    <a href="#" onclick="show('reco')" id="nav-reco"><span>&#128161;</span><span>Recommandations</span></a>
  </nav>
  <div id="sidebar-footer"><a href="https://github.com/ps81frt/" target="_blank">ps81frt</a> — WinToolkit</div>
</aside>
<div id="main">
  <div id="topbar">
    <h1>&#9673; $($InfoSys['Hostname']) &mdash; $($now.ToString('dd/MM/yyyy HH:mm:ss'))</h1>
    <span class="gp $(if($gL -eq 'OK'){'ok'}elseif($gL -eq 'ATTENTION'){'attention'}elseif($gL -eq 'SERIEUX'){'warn'}else{''})">$gL</span>
    <div class="btn-group">
      <button class="btn" onclick="toggleTheme()">&#9790; Theme</button>
      <button class="btn" onclick="window.print()">&#128438; Imprimer</button>
    </div>
  </div>
  <div id="content">
    <div id="sec-resume" class="section active"><div class="section-title">Resume des alertes</div>$secRes</div>
    <div id="sec-systeme" class="section"><div class="section-title">Etat du systeme</div>$secSys</div>
    <div id="sec-crashes" class="section"><div class="section-title">Applications plantees</div>$secCrash</div>
    <div id="sec-sessions" class="section"><div class="section-title">Sessions utilisateur</div>$secSess</div>
    <div id="sec-freezes" class="section"><div class="section-title">Screen Freeze / Gaps logs</div>$secFrz</div>
    <div id="sec-evtsys" class="section"><div class="section-title">Evenements systeme critiques</div>$secEvt</div>
    <div id="sec-precrash" class="section"><div class="section-title">Contexte Pre-Crash</div>$secPC</div>
    <div id="sec-dumps" class="section"><div class="section-title">Fichiers .DMP</div>$secDmp</div>
    <div id="sec-reco" class="section"><div class="section-title">Recommandations</div>$secReco</div>
  </div>
</div>
<script>
function show(id){document.querySelectorAll('.section').forEach(s=>s.classList.remove('active'));document.querySelectorAll('#sidebar nav a').forEach(a=>a.classList.remove('active'));document.getElementById('sec-'+id).classList.add('active');document.getElementById('nav-'+id).classList.add('active');return false}
function toggleTheme(){const b=document.body;b.dataset.theme=b.dataset.theme==='dark'?'light':'dark'}
document.querySelectorAll('#sidebar nav a').forEach(a=>a.addEventListener('click',e=>e.preventDefault()))
</script>
</body></html>
"@
        $html | Out-File -FilePath $FichierHTML -Encoding UTF8 -Force
        return $FichierHTML
    }

    # ── ORCHESTRATION ─────────────────────────────────────────────────────────
    Write-Title "10. CRASHDIAG — Crashes / BSOD / Sessions / Freezes / WHEA"
    $depuis = (Get-Date).AddHours(-$HeuresHistorique)
    Write-INFO "Periode : $HeuresHistorique dernieres heures (depuis $($depuis.ToString('dd/MM/yyyy HH:mm')))"
    Write-INFO "Dossier sortie : $outDir"
    Write-INFO ""

    Write-INFO "Lecture evenements systeme..."
    $evtSys  = _GetEvenementsSysteme -Depuis $depuis
    Write-INFO "Lecture sessions utilisateur..."
    $sess    = _GetSessions          -Depuis $depuis
    Write-INFO "Recherche fichiers .dmp..."
    $dumps   = _GetDumps             -Depuis $depuis
    Write-INFO "Detection screen freeze / gaps..."
    $freezes = _GetFreezes           -Depuis $depuis
    Write-INFO "Analyse Watchdog / TDR / App crash..."
    $wdog    = _GetWatchdog          -Depuis $depuis
    Write-INFO "Contexte pre-crash..."
    $preCrash= _GetPreCrash          -EvtSys $evtSys
    Write-INFO "Etat systeme..."
    $infoSys = _GetInfoSys

    Write-INFO "Generation rapport TXT..."
    $null = _WriteRapport -EvtSys $evtSys -Sessions $sess -Dumps $dumps -Watchdog $wdog -Freezes $freezes -InfoSys $infoSys -Depuis $depuis -PreCrash $preCrash
    Write-OK  "Rapport TXT : $FichierLog"

    Write-INFO "Generation rapport HTML..."
    $htmlPath = _WriteHTML -EvtSys $evtSys -Sessions $sess -Dumps $dumps -Watchdog $wdog -Freezes $freezes -InfoSys $infoSys -Depuis $depuis -PreCrash $preCrash
    Write-OK  "Rapport HTML : $htmlPath"

    if ($ExportCSV) {
        $csvPath = Join-Path $outDir "CrashDiag_$ts.csv"
        $rows = @()
        foreach ($e in $evtSys)  { $rows += [PSCustomObject]@{Date=$e.Date.ToString('dd/MM/yyyy HH:mm:ss');Cat="SYSTEME";Type=$e.Flag;Source=$e.Source;Coupable="";Message=$e.Message} }
        foreach ($e in ($wdog|Where-Object{$_.Type -match "HANG|CRASH"})) { $rows += [PSCustomObject]@{Date=$e.Date.ToString('dd/MM/yyyy HH:mm:ss');Cat="APP-CRASH";Type=$e.Type;Source=$e.Source;Coupable=$e.ProcFautif;Message=$e.Message} }
        foreach ($s in $sess)    { $rows += [PSCustomObject]@{Date=$s.Date.ToString('dd/MM/yyyy HH:mm:ss');Cat="SESSION";Type=$s.Type;Source=$s.TypeSession;Coupable=$s.User;Message=$s.Message} }
        $rows | Export-Csv -Path $csvPath -Encoding UTF8 -NoTypeInformation -Force
        Write-OK "Rapport CSV  : $csvPath"
    }

    Write-INFO ""
    Write-OK  "Dossier complet : $outDir"
    Write-INFO "Ouvrez le HTML dans votre navigateur pour le rapport interactif."
}

# ===========================================================================
#  MODULE 11 — GhostWin : Detection fenetres fantomes / zones mortes ecran
#  Diagnostique les fenetres invisibles qui interceptent le curseur
# ===========================================================================
function Invoke-GhostWin {
    Assert-AdminPrivilege
    Write-Title "MODULE 11 — GhostWin : Detection fenetres fantomes"

    # Chargement API Win32
    if (-not ([System.Management.Automation.PSTypeName]'GW_Win32').Type) {
        Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public class GW_Win32 {
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc f, IntPtr l);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] public static extern int  GetWindowText(IntPtr h, System.Text.StringBuilder s, int m);
    [DllImport("user32.dll")] public static extern int  GetClassName(IntPtr h, System.Text.StringBuilder s, int m);
    [DllImport("user32.dll")] public static extern int  GetWindowThreadProcessId(IntPtr h, out int p);
    [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr h);
    [DllImport("user32.dll")] public static extern int  GetWindowLong(IntPtr h, int idx);
    [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint msg, IntPtr w, IntPtr l);
    public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
    public struct RECT { public int L, T, R, B; }
    public const int GWL_EXSTYLE       = -20;
    public const int WS_EX_TRANSPARENT = 0x00000020;
    public const int WS_EX_LAYERED     = 0x00080000;
    public const int WS_EX_TOOLWINDOW  = 0x00000080;
    public const uint WM_CLOSE         = 0x0010;
}
"@
    }

    $classesSuspectes = @(
        'Shell_TrayWnd','Shell_SecondaryTrayWnd',
        'Windows.UI.Core.CoreWindow','TopLevelWindowForOverflowXamlIsland',
        'XamlExplorerHostIslandWindow','TaskListThumbnailWnd',
        'NativeHWNDHost','ApplicationFrameWindow',
        'Windows.UI.Composition.DesktopWindowContentBridge'
    )

    function Get-AllGhostWindows {
        param([switch]$IncludeInvisible)
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
        $screenW = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width
        $screenH = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height
        $clsSusp = $script:classesSuspectes
        $list    = [System.Collections.Generic.List[object]]::new()

        # Collecte des HWND via EnumWindows dans un scriptblock standard (pas de $using:)
        $hwndList = [System.Collections.Generic.List[IntPtr]]::new()
        $cb = [GW_Win32+EnumWindowsProc]{ param($h,$l); $hwndList.Add($h); return $true }
        [GW_Win32]::EnumWindows($cb, [IntPtr]::Zero) | Out-Null

        foreach ($hwnd in $hwndList) {
            $visible = [GW_Win32]::IsWindowVisible($hwnd)
            if (-not $visible -and -not $IncludeInvisible) { continue }

            $rect = New-Object GW_Win32+RECT
            [GW_Win32]::GetWindowRect($hwnd, [ref]$rect) | Out-Null
            $w = $rect.R - $rect.L; $h = $rect.B - $rect.T
            if ($w -le 0 -or $h -le 0) { continue }

            $sbT = New-Object System.Text.StringBuilder 256
            $sbC = New-Object System.Text.StringBuilder 256
            [GW_Win32]::GetWindowText($hwnd, $sbT, 256) | Out-Null
            [GW_Win32]::GetClassName($hwnd,  $sbC, 256) | Out-Null

            $pid2 = 0
            [GW_Win32]::GetWindowThreadProcessId($hwnd, [ref]$pid2) | Out-Null
            $proc = ""
            $procPath = ""
            $procFolder = ""
            $parentPid = 0
            $parentProcess = ""
            try {
                $procObj = Get-CimInstance Win32_Process -Filter "ProcessId = $pid2" -ErrorAction Stop
                if ($procObj) {
                    $proc = $procObj.Name
                    $procPath = $procObj.ExecutablePath
                    $procFolder = if ($procPath) { Split-Path $procPath } else { "" }
                    $parentPid = $procObj.ParentProcessId
                    if ($parentPid) {
                        $parentProcess = (Get-Process -Id $parentPid -ErrorAction SilentlyContinue).Name
                    }
                }
            } catch {
                $proc = (Get-Process -Id $pid2 -ErrorAction SilentlyContinue).Name
            }

            $exStyle     = [GW_Win32]::GetWindowLong($hwnd, [GW_Win32]::GWL_EXSTYLE)
            $layered     = ($exStyle -band [GW_Win32]::WS_EX_LAYERED)     -ne 0
            $transparent = ($exStyle -band [GW_Win32]::WS_EX_TRANSPARENT) -ne 0
            $toolwin     = ($exStyle -band [GW_Win32]::WS_EX_TOOLWINDOW)  -ne 0
            $minimise    = [GW_Win32]::IsIconic($hwnd)

            $score  = 0
            $raisons = [System.Collections.Generic.List[string]]::new()
            if ($layered -and $transparent) { $score += 3; $raisons.Add("Layered+Transparent") }
            elseif ($layered)               { $score += 1; $raisons.Add("Layered") }
            if ($sbT.ToString() -eq "")     { $score += 1; $raisons.Add("SansTitre") }
            if ($visible -and $minimise)    { $score += 2; $raisons.Add("Visible+Minimisee") }
            if ($rect.T -lt 0 -or $rect.L -lt 0) { $score += 1; $raisons.Add("HorsEcran") }

            $cls = $sbC.ToString()
            foreach ($cs in $clsSusp) {
                if ($cls -eq $cs) { $score += 2; $raisons.Add("ClasseSuspecte:$cs"); break }
            }

            $zoneMorte = $false
            if ($visible -and -not $minimise -and
                $rect.B -gt ($screenH - 200) -and $rect.T -lt $screenH -and
                $rect.L -ge -50 -and $rect.R -le ($screenW + 50)) {
                $score += 2; $raisons.Add("ZoneBasEcran"); $zoneMorte = $true
            }

            $list.Add([PSCustomObject]@{
                HWND           = "0x{0:X}" -f $hwnd.ToInt64()
                HWNDInt        = $hwnd.ToInt64()
                Titre          = $sbT.ToString()
                Classe         = $cls
                Process        = $proc
                PID            = $pid2
                ExecutablePath = $procPath
                ProcessFolder  = $procFolder
                ParentPID      = $parentPid
                ParentProcess  = $parentProcess
                Visible        = $visible
                Layered        = $layered
                Transparent    = $transparent
                ToolWin        = $toolwin
                Minimise       = $minimise
                Left           = $rect.L
                Top            = $rect.T
                Right          = $rect.R
                Bottom         = $rect.B
                Largeur        = $w
                Hauteur        = $h
                Score          = $score
                Raisons        = ($raisons -join ' | ')
                ZoneMorte      = $zoneMorte
            })
        }
        return $list
    }

    while ($true) {
        Write-Host ""
        Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor DarkCyan
        Write-Host "  ║     MODULE 11 — GhostWin  (Fenetres fantomes / zones)       ║" -ForegroundColor DarkCyan
        Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor DarkCyan
        Write-Host "  ║  S.  Scan       — Toutes les fenetres + score de suspicion  ║" -ForegroundColor White
        Write-Host "  ║  Z.  ZoneMorte  — Fenetres suspectes bas d ecran seulement  ║" -ForegroundColor Yellow
        Write-Host "  ║  E.  Export     — CSV + rapport HTML sur le Bureau          ║" -ForegroundColor White
        Write-Host "  ║  R.  Reset DWM  — Equivalent Win+Ctrl+Shift+B              ║" -ForegroundColor Magenta
        Write-Host "  ║  K.  Kill       — Fermer une fenetre par son HWND           ║" -ForegroundColor Red
        Write-Host "  ║  0.  Retour menu principal                                  ║" -ForegroundColor DarkGray
        Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor DarkCyan
        Write-Host ""
        $gwChoice = (Read-Host "  Votre choix").ToUpper().Trim()
        $skipPause = $false

        switch ($gwChoice) {

            "S" {
                Write-Title "GhostWin — SCAN COMPLET"
                Write-INFO "Enumeration des fenetres..."
                $wins = Get-AllGhostWindows
                Write-Host ""
                Write-Host ("  {0,-12} {1,-20} {2,-35} {3,-28} {4,-16} {5,5}  {6}" -f "HWND","Process","Path","Classe","Titre","Score","Raisons") -ForegroundColor DarkCyan
                Write-Host ("  " + "-"*140) -ForegroundColor DarkGray
                foreach ($ww in ($wins | Sort-Object Score -Descending)) {
                    $t = if ($ww.Titre.Length -gt 15)  { $ww.Titre.Substring(0,15)  + "~" } else { $ww.Titre }
                    $c = if ($ww.Classe.Length -gt 29) { $ww.Classe.Substring(0,29) + "~" } else { $ww.Classe }
                    $p = if ($ww.Process -and $ww.Process.Length -gt 19) { $ww.Process.Substring(0,19)+"~" } else { $ww.Process }
                    $path = if ($ww.ExecutablePath -and $ww.ExecutablePath.Length -gt 35) { $ww.ExecutablePath.Substring(0,32) + "..." } else { $ww.ExecutablePath }
                    $col = if ($ww.Score -ge 5) { "Red" } elseif ($ww.Score -ge 3) { "Yellow" } else { "Gray" }
                    Write-Host ("  {0,-12} {1,-20} {2,-35} {3,-28} {4,-16} {5,5}  {6}" -f $ww.HWND,$p,$path,$c,$t,$ww.Score,$ww.Raisons) -ForegroundColor $col
                }
                Write-Host ""; Write-INFO "$($wins.Count) fenetres  |  Rouge=Score>=5 (tres suspect)  |  Jaune=Score>=3"
                $skipPause = $true
                return
            }

            "Z" {
                Write-Title "GhostWin — ZONE MORTE BAS D ECRAN"
                Write-INFO "Recherche fenetres suspectes..."
                $wins = Get-AllGhostWindows
                $suspects = $wins | Where-Object { $_.Score -ge 3 } | Sort-Object Score -Descending
                if ($suspects.Count -eq 0) {
                    Write-OK "Aucune fenetre suspecte dans la zone basse."
                } else {
                    Write-WARN "$($suspects.Count) fenetre(s) suspecte(s) :"
                    Write-Host ""
                    foreach ($ww in $suspects) {
                        $col = if ($ww.Score -ge 5) { "Red" } else { "Yellow" }
                        Write-Host ("  [{0}]  Score={1}  Process={2}  Classe={3}" -f $ww.HWND,$ww.Score,$ww.Process,$ww.Classe) -ForegroundColor $col
                        Write-Host ("         Titre=`"{0}`"  Pos=({1},{2})->({3},{4})  Taille={5}x{6}" -f $ww.Titre,$ww.Left,$ww.Top,$ww.Right,$ww.Bottom,$ww.Largeur,$ww.Hauteur) -ForegroundColor DarkGray
                        Write-Host ("         Raisons : {0}" -f $ww.Raisons) -ForegroundColor $col
                        Write-Host ""
                    }
                    Write-WARN "Utilisez K pour fermer par HWND, ou R pour reset DWM."
                }
            }

            "E" {
                Write-Title "GhostWin — EXPORT CSV + HTML"
                Write-INFO "Collecte (toutes fenetres, y compris invisibles)..."
                $wins = Get-AllGhostWindows -IncludeInvisible
                $ts2  = Get-Date -Format "yyyyMMdd_HHmmss"
                $outDir2 = "$env:USERPROFILE\Desktop\GhostWin_$ts2"
                $null = New-Item -ItemType Directory -Path $outDir2 -Force

                # CSV
                $csvPath = "$outDir2\GhostWin_$ts2.csv"
                $wins | Sort-Object Score -Descending |
                    Select-Object HWND,Titre,Classe,Process,PID,ExecutablePath,ProcessFolder,ParentPID,ParentProcess,Visible,Layered,Transparent,
                        ToolWin,Minimise,Left,Top,Right,Bottom,Largeur,Hauteur,Score,Raisons,ZoneMorte |
                    Export-Csv $csvPath -NoTypeInformation -Encoding UTF8
                Write-OK "CSV : $csvPath"
                $skipPause = $true

                # HTML — tableau interactif tri + filtre
                $htmlPath = "$outDir2\GhostWin_$ts2.html"
                $rows = ($wins | Sort-Object Score -Descending | ForEach-Object {
                    $scoreVal = $_.Score
                    if ($scoreVal -ge 5) {
                        $badge = "<span class='badge badge-crit'>&#9888; $scoreVal CRITIQUE</span>"
                        $rowCls = "row-crit"
                    } elseif ($scoreVal -ge 3) {
                        $badge = "<span class='badge badge-warn'>&#9888; $scoreVal SUSPECT</span>"
                        $rowCls = "row-warn"
                    } else {
                        $badge = "<span class='badge badge-ok'>$scoreVal OK</span>"
                        $rowCls = "row-ok"
                    }
                    $zm = if ($_.ZoneMorte) { "<span class='badge badge-crit'>&#9632; ZONE</span>" } else { "" }
                    $lay = if ($_.Layered -and $_.Transparent) { "<span class='badge badge-warn'>L+T</span>" } elseif ($_.Layered) { "<span class='badge badge-info'>L</span>" } else { "" }
                    $details = "PID=$($_.PID) ParentPID=$($_.ParentPID) Parent=$($_.ParentProcess) Folder=$($_.ProcessFolder) Visible=$($_.Visible) Layered=$($_.Layered) Transparent=$($_.Transparent) ToolWin=$($_.ToolWin) Minimise=$($_.Minimise) ZoneMorte=$($_.ZoneMorte)"
                    "<tr class='$rowCls row-clickable' data-score='$scoreVal' data-pid='$($_.PID)' data-parentpid='$($_.ParentPID)' data-parentprocess='$($_.ParentProcess)' data-folder='$($_.ProcessFolder)' data-visible='$($_.Visible)' data-layered='$($_.Layered)' data-transparent='$($_.Transparent)' data-toolwin='$($_.ToolWin)' data-minimise='$($_.Minimise)'>
                      <td class='mono'>$($_.HWND)</td>
                      <td><b>$($_.Process)</b></td>
                      <td class='mono small'>$($_.ExecutablePath)</td>
                      <td class='mono small'>$($_.ParentProcess)</td>
                      <td class='mono small'>$($_.Classe)</td>
                      <td>$($_.Titre)</td>
                      <td>$badge $zm</td>
                      <td class='mono small'>$($_.Left),$($_.Top)<br>$($_.Right),$($_.Bottom)</td>
                      <td class='mono'>$($_.Largeur)&times;$($_.Hauteur)</td>
                      <td class='small'>$lay $($_.Raisons)</td>
                      <td class='small'>$details</td>
                    </tr>"
                }) -join "`n"

                $machine = $env:COMPUTERNAME
                $dateNow = Get-Date -Format "dd/MM/yyyy HH:mm:ss"
                $total   = $wins.Count
                $nCrit   = ($wins | Where-Object { $_.Score -ge 5 }).Count
                $nWarn   = ($wins | Where-Object { $_.Score -ge 3 -and $_.Score -lt 5 }).Count
                $nOk     = ($wins | Where-Object { $_.Score -lt 3 }).Count

                @"
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>GhostWin — $ts2</title>
<style>
  :root {
    --bg:      #0f1117;
    --bg2:     #1a1d27;
    --bg3:     #22263a;
    --border:  #2e3250;
    --text:    #e2e8f0;
    --muted:   #7c87a6;
    --blue:    #60a5fa;
    --crit-bg: #2d1515;
    --crit-fg: #f87171;
    --crit-bd: #7f1d1d;
    --warn-bg: #1e1a0a;
    --warn-fg: #fb923c;
    --warn-bd: #78350f;
    --ok-bg:   #0a1a12;
    --ok-fg:   #4ade80;
    --ok-bd:   #14532d;
    --info-fg: #818cf8;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 13px; padding: 24px; }
  h1 { font-size: 22px; font-weight: 700; color: var(--blue); margin-bottom: 4px; letter-spacing: -.3px; }
  .meta { color: var(--muted); font-size: 12px; margin-bottom: 20px; }
  .stats { display: flex; gap: 12px; margin-bottom: 20px; flex-wrap: wrap; }
  .stat { background: var(--bg2); border: 1px solid var(--border); border-radius: 10px; padding: 12px 20px; min-width: 120px; }
  .stat-val { font-size: 28px; font-weight: 700; line-height: 1; }
  .stat-lbl { font-size: 11px; color: var(--muted); margin-top: 3px; text-transform: uppercase; letter-spacing: .5px; }
  .stat-crit .stat-val { color: var(--crit-fg); }
  .stat-warn .stat-val { color: var(--warn-fg); }
  .stat-ok   .stat-val { color: var(--ok-fg); }
  .stat-tot  .stat-val { color: var(--blue); }
  .toolbar { display: flex; gap: 10px; margin-bottom: 16px; align-items: center; flex-wrap: wrap; }
  .toolbar input { background: var(--bg2); color: var(--text); border: 1px solid var(--border); border-radius: 8px; padding: 8px 14px; font-size: 13px; width: 280px; outline: none; }
  .toolbar input:focus { border-color: var(--blue); }
  .toolbar select { background: var(--bg2); color: var(--text); border: 1px solid var(--border); border-radius: 8px; padding: 8px 12px; font-size: 13px; outline: none; cursor: pointer; }
  .toolbar label { color: var(--muted); font-size: 12px; }
  .wrap { overflow-x: auto; overflow-y: hidden; width: 100%; border-radius: 10px; border: 1px solid var(--border); }
  .detail-pane { margin-bottom: 16px; padding: 16px; background: var(--bg2); border: 1px solid var(--border); border-radius: 10px; }
  .detail-pane.hidden { display: none; }
  .detail-title { font-size: 13px; font-weight: 700; color: var(--blue); margin-bottom: 10px; }
  .detail-row { display: grid; grid-template-columns: 170px 1fr; gap: 8px; padding: 4px 0; border-bottom: 1px solid rgba(255,255,255,.06); }
  .detail-row:last-child { border-bottom: none; }
  .detail-key { color: var(--muted); font-size: 12px; text-transform: uppercase; }
  .detail-value { font-family: 'Cascadia Code', 'Consolas', monospace; font-size: 12px; color: var(--text); word-break: break-all; }
  .row-clickable:hover { cursor: pointer; filter: brightness(1.08); }
  table { border-collapse: collapse; width: max-content; min-width: 900px; }
  thead th { background: var(--bg3); color: var(--blue); padding: 10px 12px; text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: .6px; position: sticky; top: 0; cursor: pointer; user-select: none; white-space: nowrap; border-bottom: 1px solid var(--border); }
  thead th:hover { background: #2a2f47; }
  thead th.sorted-asc::after  { content: ' ▲'; font-size: 10px; }
  thead th.sorted-desc::after { content: ' ▼'; font-size: 10px; }
  tbody tr { border-bottom: 1px solid var(--border); transition: background .1s; }
  tbody tr:hover td { filter: brightness(1.15); }
  tbody tr:last-child { border-bottom: none; }
  td { padding: 8px 12px; vertical-align: middle; }
  .row-crit { background: var(--crit-bg); }
  .row-warn { background: var(--warn-bg); }
  .row-ok   { background: var(--bg); }
  .badge { display: inline-block; border-radius: 5px; padding: 2px 7px; font-size: 10px; font-weight: 700; letter-spacing: .3px; white-space: nowrap; }
  .badge-crit { background: var(--crit-bg); color: var(--crit-fg); border: 1px solid var(--crit-bd); }
  .badge-warn { background: var(--warn-bg); color: var(--warn-fg); border: 1px solid var(--warn-bd); }
  .badge-ok   { background: var(--ok-bg);   color: var(--ok-fg);   border: 1px solid var(--ok-bd);   }
  .badge-info { background: #1e1b4b; color: var(--info-fg); border: 1px solid #312e81; }
  .mono  { font-family: 'Cascadia Code', 'Consolas', monospace; }
  .small { font-size: 11px; color: var(--muted); }
  .hidden { display: none !important; }
  .footer { margin-top: 20px; color: var(--muted); font-size: 11px; }
</style>
</head>
<body>
<h1>&#128123; GhostWin — Rapport fenetres fantomes</h1>
<div class="meta">Machine : <b>$machine</b> &nbsp;&bull;&nbsp; $dateNow &nbsp;&bull;&nbsp; WinToolkit ps81frt</div>

<div class="stats">
  <div class="stat stat-tot"><div class="stat-val">$total</div><div class="stat-lbl">Total fenetres</div></div>
  <div class="stat stat-crit"><div class="stat-val">$nCrit</div><div class="stat-lbl">&#9888; Critiques (≥5)</div></div>
  <div class="stat stat-warn"><div class="stat-val">$nWarn</div><div class="stat-lbl">&#9888; Suspectes (≥3)</div></div>
  <div class="stat stat-ok"><div class="stat-val">$nOk</div><div class="stat-lbl">&#10003; Normales</div></div>
</div>

<div class="toolbar">
  <input type="text" id="search" placeholder="&#128269; Filtrer process, classe, HWND, raisons..." oninput="applyFilters()">
  <label>Niveau min :
    <select id="minScore" onchange="applyFilters()">
      <option value="0">Tout afficher</option>
      <option value="3">Suspect (≥3)</option>
      <option value="5">Critique (≥5)</option>
    </select>
  </label>
  <label><input type="checkbox" id="onlyZone" onchange="applyFilters()"> Zone morte seulement</label>
</div>

<div class="wrap">
<div class="detail-pane hidden" id="detailPane">
  <div class="detail-title">Détails de la ligne sélectionnée</div>
  <div id="detailContent"></div>
</div>
<table id="gwTable">
  <thead>
    <tr>
      <th onclick="sortTable(0)">HWND</th>
      <th onclick="sortTable(1)">Process</th>
      <th onclick="sortTable(2)">ExecutablePath</th>
      <th onclick="sortTable(3)">ParentProcess</th>
      <th onclick="sortTable(4)">Classe</th>
      <th onclick="sortTable(5)">Titre</th>
      <th onclick="sortTable(6)">Score</th>
      <th onclick="sortTable(7)">Position</th>
      <th onclick="sortTable(8)">Taille</th>
      <th>Raisons</th>
      <th>Infos</th>
    </tr>
  </thead>
  <tbody>
$rows
  </tbody>
</table>
</div>
<div class="footer" id="countLine"></div>

<script>
var sortCol = 6, sortDir = -1;

function applyFilters() {
  var q    = document.getElementById('search').value.toLowerCase();
  var minS = parseInt(document.getElementById('minScore').value) || 0;
  var onlyZ = document.getElementById('onlyZone').checked;
  var rows = document.querySelectorAll('#gwTable tbody tr');
  var vis = 0;
  rows.forEach(function(r) {
    var score = parseInt(r.dataset.score) || 0;
    var text  = r.innerText.toLowerCase();
    var zone  = r.querySelector('.badge-crit') && r.querySelector('.badge-crit').textContent.includes('ZONE');
    var show  = score >= minS && text.includes(q) && (!onlyZ || zone);
    r.classList.toggle('hidden', !show);
    if (show) vis++;
  });
  document.getElementById('countLine').textContent = vis + ' fenetre(s) affichee(s)';
}

function showDetail(row) {
  var detail = document.getElementById('detailPane');
  var content = document.getElementById('detailContent');
  var fields = [
    ['HWND', row.cells[0].innerText],
    ['Process', row.cells[1].innerText],
    ['ExecutablePath', row.cells[2].innerText],
    ['ParentProcess', row.cells[3].innerText],
    ['Classe', row.cells[4].innerText],
    ['Titre', row.cells[5].innerText],
    ['Score', row.cells[6].innerText],
    ['Position', row.cells[7].innerText],
    ['Taille', row.cells[8].innerText],
    ['Raisons', row.cells[9].innerText],
    ['PID', row.dataset.pid],
    ['ParentPID', row.dataset.parentpid],
    ['ProcessFolder', row.dataset.folder],
    ['Visible', row.dataset.visible],
    ['Layered', row.dataset.layered],
    ['Transparent', row.dataset.transparent],
    ['ToolWin', row.dataset.toolwin],
    ['Minimise', row.dataset.minimise],
    ['ZoneMorte', row.dataset.zonemorte]
  ];
  content.innerHTML = fields.map(function(f) {
    return '<div class="detail-row"><div class="detail-key">' + f[0] + '</div><div class="detail-value">' + (f[1] || '') + '</div></div>';
  }).join('');
  detail.classList.remove('hidden');
  detail.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function attachRowHandlers() {
  var rows = document.querySelectorAll('#gwTable tbody tr');
  rows.forEach(function(r) {
    r.addEventListener('dblclick', function() { showDetail(r); });
  });
}

function sortTable(col) {
  var tbody = document.querySelector('#gwTable tbody');
  var rows  = Array.from(tbody.querySelectorAll('tr'));
  if (sortCol === col) { sortDir *= -1; } else { sortCol = col; sortDir = col === 4 ? -1 : 1; }
  rows.sort(function(a, b) {
    var ta = a.cells[col] ? a.cells[col].innerText.trim() : '';
    var tb = b.cells[col] ? b.cells[col].innerText.trim() : '';
    var na = parseFloat(ta); var nb = parseFloat(tb);
    if (!isNaN(na) && !isNaN(nb)) return (na - nb) * sortDir;
    return ta.localeCompare(tb) * sortDir;
  });
  rows.forEach(function(r) { tbody.appendChild(r); });
  document.querySelectorAll('thead th').forEach(function(th, i) {
    th.classList.remove('sorted-asc','sorted-desc');
    if (i === sortCol) th.classList.add(sortDir === 1 ? 'sorted-asc' : 'sorted-desc');
  });
}

window.onload = function() { applyFilters(); sortTable(6); attachRowHandlers(); };
</script>
</body>
</html>
"@ | Out-File $htmlPath -Encoding UTF8
                Write-OK "HTML : $htmlPath"
                Write-OK "Dossier : $outDir2"
                Start-Process $htmlPath
                return
            }

            "R" {
                Write-Title "GhostWin — RESET DWM"
                Write-WARN "L ecran va clignoter ~1 seconde. Aucun programme ne se fermera."
                $confirm = (Read-Host "  Confirmer ? [O/n]").ToUpper().Trim()
                if ($confirm -ne "N") {
                    Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
                    [System.Windows.Forms.SendKeys]::SendWait("%^+{B}")
                    Start-Sleep -Milliseconds 1500
                    Write-OK "Reset DWM envoye."
                    Write-INFO "Zone morte disparue -> bug pilote/DWM confirme -> MAJ pilote NVIDIA recommandee."
                    Write-INFO "Zone morte toujours la -> processus tiers -> utilisez Z puis K."
                }
            }

            "K" {
                Write-Title "GhostWin — KILL FENETRE"
                Write-WARN "Attention : fermer une fenetre systeme peut destabiliser Windows."
                $hwndStr = (Read-Host "  HWND a fermer (ex: 0x1A2B3C, ENTREE pour annuler)").Trim()
                if ([string]::IsNullOrWhiteSpace($hwndStr)) { break }
                $hwndHex = $hwndStr -replace '^0[xX]', ''
                try {
                    $hwndVal = [Convert]::ToInt64($hwndHex, 16)
                    $hwndPtr = [IntPtr]$hwndVal
                    [GW_Win32]::PostMessage($hwndPtr, [GW_Win32]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
                    Write-OK "WM_CLOSE envoye a $hwndStr — Relancez Z pour verifier."
                } catch { Write-ERR "HWND invalide : $_" }
            }

            "0" { return }
            default { Write-WARN "Choix invalide." }
        }
        if (-not $skipPause) {
        Write-Host ""; Write-Host "  Appuyez sur ENTREE pour revenir au menu GhostWin..." -ForegroundColor DarkGray
        $null = Read-Host
        }
    }
}

function Show-MainMenu {
    while ($true) {
        Show-Banner

        # ── Encadre principal ──────────────────────────────────────────────────
        Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor DarkCyan
        Write-Host "  ║                    CHOISISSEZ UN MODULE                      ║" -ForegroundColor DarkCyan
        Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor DarkCyan
        Write-Host "  ║  1.  InfoSys    — Inventaire complet systeme/logiciels       ║" -ForegroundColor White
        Write-Host "  ║  2.  DiagBoot   — Boot, disques, BCD, EFI, partitions        ║" -ForegroundColor White
        Write-Host "  ║  3.  AuditSOC   — Audit securite SOC / DFIR                  ║" -ForegroundColor White
        Write-Host "  ║  4.  EDR/AV     — Securite, score de durcissement, fix       ║" -ForegroundColor White
        Write-Host "  ║  5.  WinDiag    — Diagnostic codes erreur / crashes          ║" -ForegroundColor White
        Write-Host "  ║  6.  SFC/DISM   — Verification integrite Windows             ║" -ForegroundColor White
        Write-Host "  ║  7.  NetShare   — Diagnostic partages reseau SMB             ║" -ForegroundColor White
        Write-Host "  ║  8.  Compare-PC — Analyse differentielle multi-machines      ║" -ForegroundColor White
        Write-Host "  ║  9.  EVCDiag    — Crashes, kernel, IO latences, drivers      ║" -ForegroundColor White
        Write-Host "  ║  10. CrashDiag  — BSOD, freezes, WHEA, sessions, app crash   ║" -ForegroundColor White
        Write-Host "  ║  11. GhostWin   — Fenetres fantomes / zones mortes ecran     ║" -ForegroundColor Cyan
        Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor DarkCyan
        Write-Host "  ║  H.  Aide       — Detail de chaque module                    ║" -ForegroundColor DarkGray
        Write-Host "  ║  0.  Quitter                                                 ║" -ForegroundColor DarkGray
        Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor DarkCyan
        Write-Host ""
        Write-Host "  [!] Tous les modules requierent les droits Administrateur." -ForegroundColor DarkYellow
        Write-Host ""

        $choice = Read-Host "  Votre choix"
        switch ($choice.ToUpper()) {

            "1" { Invoke-InfoSys }

            "2" { Invoke-DiagBoot }

            "3" { Invoke-AuditSOC }

            "4" {
                Write-Host ""
                Write-Host "  ┌─ MODULE EDR/AV ───────────────────────────────────────────┐" -ForegroundColor Yellow
                Write-Host "  │  Audit seul     : appuyez ENTREE (aucune modification)    │" -ForegroundColor Gray
                Write-Host "  │  Remediation    : entrez une option ci-dessous            │" -ForegroundColor Gray
                Write-Host "  │                                                           │" -ForegroundColor Gray
                Write-Host "  │  All           Toutes les corrections disponibles         │" -ForegroundColor Cyan
                Write-Host "  │  Firewall      Activer le pare-feu Windows                │" -ForegroundColor Cyan
                Write-Host "  │  SmartScreen   Activer SmartScreen                        │" -ForegroundColor Cyan
                Write-Host "  │  Defender      Activer Windows Defender                   │" -ForegroundColor Cyan
                Write-Host "  │  SMBv1         Desactiver SMBv1 (dangereux)               │" -ForegroundColor Cyan
                Write-Host "  │  LSA           Activer LSA Protected Process              │" -ForegroundColor Cyan
                Write-Host "  └───────────────────────────────────────────────────────────┘" -ForegroundColor Yellow
                Write-Host ""
                $fixChoice = Read-Host "  -Fix [None = audit seul]"
                if ([string]::IsNullOrWhiteSpace($fixChoice)) { $fixChoice = "None" }
                Write-Host ""
                Write-Host "  ┌─ EXPORT / PARTAGE ────────────────────────────────────────┐" -ForegroundColor DarkCyan
                Write-Host "  │  D   Upload vers dpaste.com  (lecture web directe)        │" -ForegroundColor Magenta
                Write-Host "  │  G   Upload vers Gofile      (telechargement fichier)     │" -ForegroundColor Magenta
                Write-Host "  │  ENTREE  Pas d'upload (rapport local uniquement)          │" -ForegroundColor Gray
                Write-Host "  └───────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
                Write-Host ""
                $shareChoice = (Read-Host "  Export [D/G/ENTREE]").ToUpper().Trim()
                $edrDpaste = $shareChoice -eq "D"
                $edrGofile = $shareChoice -eq "G"
                if ($edrDpaste) {
                    Invoke-EDR -Fix $fixChoice -ShareDpaste
                } elseif ($edrGofile) {
                    Invoke-EDR -Fix $fixChoice -ShareGofile
                } else {
                    Invoke-EDR -Fix $fixChoice
                }
            }

            "5" { Invoke-WinDiag }

            "6" { Invoke-SFC }

            "7" {
                Write-Host ""
                Write-Host "  ┌─ MODULE NETSHARE ────────────────────────────────────────┐" -ForegroundColor Yellow
                Write-Host "  │  COMPLET  Toutes les donnees (IPs, MACs, comptes...)     │" -ForegroundColor Cyan
                Write-Host "  │  PUBLIC   Donnees anonymisees pour partage externe       │" -ForegroundColor Cyan
                Write-Host "  │                                                          │" -ForegroundColor Gray
                Write-Host "  │  Sortie : Bureau\PC-<MACHINE>-<USER>-report-all-<ts>.txt │" -ForegroundColor Gray
                Write-Host "  │  Ce fichier TXT est utilise par Compare-PC (module 8)    │" -ForegroundColor DarkYellow
                Write-Host "  └──────────────────────────────────────────────────────────┘" -ForegroundColor Yellow
                Write-Host ""
                $modeChoice = Read-Host "  Mode [COMPLET]"
                if ([string]::IsNullOrWhiteSpace($modeChoice)) { $modeChoice = "COMPLET" }
                Invoke-NetShare -NSDMode $modeChoice
            }

            "8" {
                Write-Host ""
                Write-Host "  ┌─ MODULE COMPARE-PC ───────────────────────────────────────────────────┐" -ForegroundColor Yellow
                Write-Host "  │  Analyse les differences de configuration entre 2 a 10 machines.      │" -ForegroundColor Gray
                Write-Host "  │                                                                       │" -ForegroundColor Gray
                Write-Host "  │  PREREQUIS : fichiers *-all.txt generes par le module 7 (NetShare)    │" -ForegroundColor DarkYellow
                Write-Host "  │                                                                       │" -ForegroundColor Gray
                Write-Host "  │  WORKFLOW :                                                           │" -ForegroundColor White
                Write-Host "  │    1. Lancer le module 7 (NetShare) sur chaque machine a comparer     │" -ForegroundColor Cyan
                Write-Host "  │    2. Recuperer les fichiers *-all.txt generes sur le Bureau          │" -ForegroundColor Cyan
                Write-Host "  │    3. Lancer ce module et fournir les chemins des fichiers TXT        │" -ForegroundColor Cyan
                Write-Host "  │                                                                       │" -ForegroundColor Gray
                Write-Host "  │  FORMAT DU FICHIER :                                                  │" -ForegroundColor White
                Write-Host "  │    PC-<HOSTNAME>-<USER>-report-all-<timestamp>.txt                    │" -ForegroundColor Gray
                Write-Host "  │    Ex: PC-SERVEUR01-jdupont-report-all-20260419_143012.txt            │" -ForegroundColor DarkGray
                Write-Host "  │                                                                       │" -ForegroundColor Gray
                Write-Host "  │  [!] CONSEIL : lancez le module 7 sur CHAQUE machine a comparer,      │" -ForegroundColor DarkYellow
                Write-Host "  │      copiez les *-all.txt sur cette machine, puis lancez le 8.        │" -ForegroundColor DarkYellow
                Write-Host "  │                                                                       │" -ForegroundColor Gray
                Write-Host "  │  SORTIE : Bureau\CPR_<timestamp>\                                     │" -ForegroundColor Gray
                Write-Host "  │    - dashboard_diff_*.html  (rapport interactif navigateur)           │" -ForegroundColor Gray
                Write-Host "  │    - rapport_diff_*.txt     (rapport texte)                           │" -ForegroundColor Gray
                Write-Host "  │    - *.csv                  (donnees brutes)                          │" -ForegroundColor Gray
                Write-Host "  └───────────────────────────────────────────────────────────────────────┘" -ForegroundColor Yellow
                Write-Host ""
                Invoke-ComparePC -InputFiles @()
            }

            "H" {
                Write-Host ""
                Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
                Write-Host "  ║                    AIDE — MODULES                            ║" -ForegroundColor Cyan
                Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
                Write-Host "  ║  1. InfoSys    Inventaire materiel, logiciels, taches,       ║" -ForegroundColor White
                Write-Host "  ║                services, pilotes, registre, reseau.          ║" -ForegroundColor Gray
                Write-Host "  ║                Sortie : Bureau\InfoSys_<ts>.zip              ║" -ForegroundColor DarkGray
                Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor DarkCyan
                Write-Host "  ║  2. DiagBoot   Analyse disques, partitions, BCD, EFI,        ║" -ForegroundColor White
                Write-Host "  ║                plan d'action NVMe.                           ║" -ForegroundColor Gray
                Write-Host "  ║                Sortie : Bureau\DiagBoot_<ts>.txt             ║" -ForegroundColor DarkGray
                Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor DarkCyan
                Write-Host "  ║  3. AuditSOC   Audit complet securite : comptes, groupes,    ║" -ForegroundColor White
                Write-Host "  ║                GPO, pare-feu, audit policy, DFIR.            ║" -ForegroundColor Gray
                Write-Host "  ║                Sortie : Bureau\AuditSOC_<ts>.txt             ║" -ForegroundColor DarkGray
                Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor DarkCyan
                Write-Host "  ║  4. EDR/AV     Score de durcissement 0-100, detection AV/    ║" -ForegroundColor White
                Write-Host "  ║                EDR, Defender, SmartScreen, LSA, SMBv1.       ║" -ForegroundColor Gray
                Write-Host "  ║                Sortie : Bureau\EDR_<ts>\Rapport_EDR.txt      ║" -ForegroundColor DarkGray
                Write-Host "  ║                Fix    : -Fix All|Firewall|Defender|...       ║" -ForegroundColor DarkGray
                Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor DarkCyan
                Write-Host "  ║  5. WinDiag    Recherche codes erreur NTSTATUS/Win32/        ║" -ForegroundColor White
                Write-Host "  ║                HRESULT, DLL, scan crashes Event Log.         ║" -ForegroundColor Gray
                Write-Host "  ║                Sortie : Bureau\WinDiag_<ts>.txt              ║" -ForegroundColor DarkGray
                Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor DarkCyan
                Write-Host "  ║  6. SFC/DISM   Verification + reparation integrite Windows.  ║" -ForegroundColor White
                Write-Host "  ║                Lance DISM CheckHealth/ScanHealth/Restore     ║" -ForegroundColor Gray
                Write-Host "  ║                puis SFC /scannow. Rapport HTML+TXT.          ║" -ForegroundColor Gray
                Write-Host "  ║                Sortie : Bureau\CBS_SFC_DISM_Report_<ts>.*    ║" -ForegroundColor DarkGray
                Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor DarkCyan
                Write-Host "  ║  7. NetShare   Audit partages SMB, interfaces reseau,        ║" -ForegroundColor White
                Write-Host "  ║                pare-feu, sessions, ARP, hosts, events.       ║" -ForegroundColor Gray
                Write-Host "  ║                Sortie : Bureau\PC-<HOST>-<USER>-report-*     ║" -ForegroundColor DarkGray
                Write-Host "  ║                  -> *-all.txt  requis pour Compare-PC !      ║" -ForegroundColor DarkYellow
                Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor DarkCyan
                Write-Host "  ║  8. Compare-PC Compare 2 a 10 rapports *-all.txt de          ║" -ForegroundColor White
                Write-Host "  ║                NetShare. Detecte differences SMB/VPN/DNS.    ║" -ForegroundColor Gray
                Write-Host "  ║                WORKFLOW : lancer module 7 sur chaque PC,     ║" -ForegroundColor DarkYellow
                Write-Host "  ║                copier les *-all.txt ici, lancer module 8.    ║" -ForegroundColor DarkYellow
                Write-Host "  ║                Sortie : Bureau\CPR_<ts>\dashboard*.html      ║" -ForegroundColor DarkGray
                Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor DarkCyan
                Write-Host "  ║  9. EVCDiag    Collecte crashes, kernel, IO > 10000ms,       ║" -ForegroundColor White
                Write-Host "  ║                SMART disques, erreurs drivers.               ║" -ForegroundColor Gray
                Write-Host "  ║                Sortie : Bureau\EVC_Export\                   ║" -ForegroundColor DarkGray
                Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor DarkCyan
                Write-Host "  ║  10. CrashDiag BSOD, arrets brutaux, freezes, WHEA,         ║" -ForegroundColor White
                Write-Host "  ║                app crash, sessions, contexte pre-crash.      ║" -ForegroundColor Gray
                Write-Host "  ║                Sortie : Bureau\CrashDiag_<ts>\*.txt+*.html   ║" -ForegroundColor DarkGray
                Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor DarkYellow
                Write-Host "  ║            PARAMETRES AVANCES (ligne de commande)            ║" -ForegroundColor Yellow
                Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor DarkYellow
                Write-Host "  ║  -Module <nom>     Lancer directement un module sans menu    ║" -ForegroundColor White
                Write-Host "  ║                   Ex: .\WT.ps1 -Module DiagBoot              ║" -ForegroundColor DarkGray
                Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor DarkYellow
                Write-Host "  ║  MODULE DiagBoot                                             ║" -ForegroundColor Cyan
                Write-Host "  ║    -DebugEFI       Active le log de debug du montage EFI     ║" -ForegroundColor White
                Write-Host "  ║                   Genere : Bureau\DiagBoot_EFI_Debug_<ts>   ║" -ForegroundColor DarkGray
                Write-Host "  ║                   Utile si popup ou erreur montage partition ║" -ForegroundColor DarkGray
                Write-Host "  ║                   Ex: .\WT.ps1 -Module DiagBoot -DebugEFI   ║" -ForegroundColor DarkGray
                Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor DarkYellow
                Write-Host "  ║  MODULE EDR                                                  ║" -ForegroundColor Cyan
                Write-Host "  ║    -Fix <cible>    Applique un correctif de securite         ║" -ForegroundColor White
                Write-Host "  ║                   Valeurs : All | Firewall | SmartScreen     ║" -ForegroundColor DarkGray
                Write-Host "  ║                             Defender | SMBv1 | LSA           ║" -ForegroundColor DarkGray
                Write-Host "  ║                   Ex: .\WT.ps1 -Module EDR -Fix All          ║" -ForegroundColor DarkGray
                Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor DarkYellow
                Write-Host "  ║  MODULE WinDiag                                              ║" -ForegroundColor Cyan
                Write-Host "  ║    -Query <val>    Recherche code erreur / DLL / mot-cle     ║" -ForegroundColor White
                Write-Host "  ║                   Ex: .\WT.ps1 -Module WinDiag -Query 0xc0  ║" -ForegroundColor DarkGray
                Write-Host "  ║    -Scan           Scanner les crashes dans l Event Log      ║" -ForegroundColor White
                Write-Host "  ║    -Dump <chemin>  Analyser un fichier minidump .dmp         ║" -ForegroundColor White
                Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor DarkYellow
                Write-Host "  ║  MODULE NetShare                                             ║" -ForegroundColor Cyan
                Write-Host "  ║    -NetMode <mode> COMPLET (defaut) ou PUBLIC (anonymise)   ║" -ForegroundColor White
                Write-Host "  ║                   Ex: .\WT.ps1 -Module NetShare -NetMode    ║" -ForegroundColor DarkGray
                Write-Host "  ║                       PUBLIC                                ║" -ForegroundColor DarkGray
                Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor DarkYellow
                Write-Host "  ║  MODULE ComparePC                                            ║" -ForegroundColor Cyan
                Write-Host "  ║    -ReportFiles    Chemins des *-all.txt (2 a 10 fichiers)   ║" -ForegroundColor White
                Write-Host "  ║                   Ex: .\WT.ps1 -Module ComparePC \           ║" -ForegroundColor DarkGray
                Write-Host "  ║                    -ReportFiles pc1.txt,pc2.txt              ║" -ForegroundColor DarkGray
                Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor DarkYellow
                Write-Host "  ║  MODULE CrashDiag                                            ║" -ForegroundColor Cyan
                Write-Host "  ║    -HeuresHistorique <n>  Fenetre d'analyse (defaut : 48h)   ║" -ForegroundColor White
                Write-Host "  ║                          Ex: .\WT.ps1 -Module CrashDiag \   ║" -ForegroundColor DarkGray
                Write-Host "  ║                              -HeuresHistorique 96            ║" -ForegroundColor DarkGray
                Write-Host "  ║    -ExportCSV             Generer aussi un fichier CSV       ║" -ForegroundColor White
                Write-Host "  ║    -ExportHTML            Forcer la sortie HTML              ║" -ForegroundColor White
                Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor DarkYellow
                Write-Host ""
                Write-Host "  [!] Tous les modules requierent les droits Administrateur." -ForegroundColor DarkYellow
                Write-Host "      Le script se relance automatiquement en Administrateur si necessaire." -ForegroundColor Gray
                Write-Host ""
            }

            "9" { Invoke-EVCDiag }

            "10" {
                Write-Host ""
                Write-Host "  ┌─ MODULE CRASHDIAG ────────────────────────────────────────┐" -ForegroundColor Yellow
                Write-Host "  │  Analyse BSOD, arrets brutaux, freezes, WHEA, app crash   │" -ForegroundColor Gray
                Write-Host "  │  Periode par defaut : 48 dernieres heures                 │" -ForegroundColor Gray
                Write-Host "  │                                                           │" -ForegroundColor Gray
                Write-Host "  │  Sortie : Bureau\CrashDiag_<ts>\  (TXT + HTML interactif) │" -ForegroundColor Gray
                Write-Host "  └───────────────────────────────────────────────────────────┘" -ForegroundColor Yellow
                Write-Host ""
                $cdHeures = Read-Host "  Heures d'historique [48]"
                if ([string]::IsNullOrWhiteSpace($cdHeures) -or $cdHeures -notmatch '^\d+$') { $cdHeures = 48 }
                $cdCSV = (Read-Host "  Exporter aussi en CSV ? [o/N]").ToUpper().Trim()
                if ($cdCSV -eq "O") {
                    Invoke-CrashDiag -HeuresHistorique ([int]$cdHeures) -HTML -ExportCSV
                } else {
                    Invoke-CrashDiag -HeuresHistorique ([int]$cdHeures) -HTML
                }
            }

            "11" { Invoke-GhostWin }

            "0" { Write-Host ""; Write-Host "  Au revoir !" -ForegroundColor Cyan; Write-Host ""; exit }

            default { Write-Host "  Choix invalide. Tapez un numero de 1 a 11, H pour l'aide, ou 0 pour quitter." -ForegroundColor Red }
        }
        Write-Host ""
        Write-Host "  Appuyez sur ENTREE pour revenir au menu..." -ForegroundColor DarkGray
        $null = Read-Host
    }
}

# ===========================================================================
#  POINT D'ENTREE
# ===========================================================================

if ($Help) {
    Get-Help $PSCommandPath -Full 2>$null
    if (-not $?) { Get-Help $MyInvocation.MyCommand.Name }
    exit
}

switch ($Module) {
    "InfoSys"   { Invoke-InfoSys }
    "DiagBoot"  { Invoke-DiagBoot }
    "AuditSOC"  { Invoke-AuditSOC }
    "EDR"       { Invoke-EDR }
    "WinDiag"   { Invoke-WinDiag -QueryIn $Query -ScanLog:$Scan -DumpPath $Dump -ExportPath $Export -ShowHelp:$Help }
    "SFC"       { Invoke-SFC }
    "NetShare"  { Invoke-NetShare -NSDMode $NetMode }
    "ComparePC" { Invoke-ComparePC -InputFiles $ReportFiles }
    "EVCDiag"   { Invoke-EVCDiag }
    "CrashDiag" { Invoke-CrashDiag -HeuresHistorique $HeuresHistorique -HTML:$ExportHTML -ExportCSV:$ExportCSV }
    "GhostWin"  { Invoke-GhostWin }
    default     { Show-MainMenu }
}
