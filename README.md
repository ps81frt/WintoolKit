# WinToolkit v2 — Suite Diagnostic & Sécurité Windows

## 📊 Statut

![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11%20x64-brightgreen)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue)
![Language](https://img.shields.io/badge/language-PowerShell%20100%25-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Stars](https://img.shields.io/github/stars/ps81frt/WintoolKit)
![Last commit](https://img.shields.io/github/last-commit/ps81frt/WintoolKit)
[![Release](https://img.shields.io/github/v/release/ps81frt/WintoolKit)](https://github.com/ps81frt/WintoolKit/releases)
![Downloads](https://img.shields.io/github/downloads/ps81frt/WintoolKit/total)
[![Download](https://img.shields.io/badge/Download%20ZIP-1.0-blue)](https://github.com/ps81frt/WintoolKit/releases/download/1.0/Wintoolkit.zip)

<!--

![Downloads](https://img.shields.io/github/downloads/ps81frt/WintoolKit/total)

-->

---

Script PowerShell 5.1+ autonome, 11 modules, tous les rapports générés sur le Bureau.  
Requiert les droits **Administrateur**. Auto-élévation intégrée via `Start-Process -Verb RunAs`.

---

## Prérequis

- Windows 10 / 11 (PowerShell 5.1 minimum)
- Droits Administrateur local
- `Set-ExecutionPolicy` : `Bypass` ou `RemoteSigned` au minimum sur le scope Process

---

## Installation

### Utilisation directe (sans installation)

```powershell
&{
Invoke-WebRequest https://raw.githubusercontent.com/ps81frt/WintoolKit/main/Wintoolkit.ps1 -OutFile "$env:USERPROFILE\Downloads\Wintoolkit.ps1"
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
Unblock-File -Path "$env:USERPROFILE\Downloads\Wintoolkit.ps1"
Add-MpPreference -ExclusionPath "$env:USERPROFILE\Downloads\Wintoolkit.ps1"
cd "$env:USERPROFILE\Downloads"
.\Wintoolkit.ps1
}
```

### Installation permanente

```powershell
&{
Invoke-WebRequest https://raw.githubusercontent.com/ps81frt/WintoolKit/refs/heads/main/install.ps1 -OutFile "$env:USERPROFILE\Downloads\Install.ps1 -UseBasicParsing"
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
& "$env:USERPROFILE\Downloads\Install.ps1"
}
```

### Désinstallation

```powershell
&{
Invoke-WebRequest https://raw.githubusercontent.com/ps81frt/WintoolKit/main/Uninstall.ps1 -OutFile "$env:USERPROFILE\Downloads\Uninstall.ps1"
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
& "$env:USERPROFILE\Downloads\Uninstall.ps1"
}
```

---

## Utilisation en ligne de commande

```powershell
# Menu interactif
.\Wintoolkit.ps1

# Appel direct d'un module
.\Wintoolkit.ps1 -Module <NomModule> [options]
```

Modules disponibles via `-Module` :

| Valeur        | Module                        |
|---------------|-------------------------------|
| `InfoSys`     | Inventaire système complet    |
| `DiagBoot`    | Diagnostic boot / disques     |
| `AuditSOC`    | Audit sécurité SOC/DFIR       |
| `EDR`         | Audit AV/EDR + remédiation    |
| `WinDiag`     | Diagnostic codes d'erreur     |
| `SFC`         | SFC + DISM                    |
| `NetShare`    | Audit partages réseau         |
| `ComparePC`   | Comparaison entre deux postes |
| `EVCDiag`     | Diagnostic Event Log          |
| `CrashDiag`   | Analyse BSOD / freezes        |
| `GhostWin`    | Détection installations ghost |

---

## Modules — détail technique

### Module 1 — InfoSys `→ Bureau\InfoSys_<ts>.zip`

Inventaire complet du système, compressé en archive ZIP :

- **OS / Machine** : `Win32_OperatingSystem`, `Win32_SystemEnclosure`, BIOS via `Win32_BIOS`
- **GPU & moniteurs** : `Win32_VideoController`, `WmiMonitorID` (connexion, taille diagonale, serial)
- **Disques** : `Get-PhysicalDisk`, `Win32_LogicalDisk` (taille, espace libre, pourcentage)
- **RAM** : `Win32_PhysicalMemory` (fabricant, part number, bank, fréquence configurée)
- **Réseau** : `Get-NetIPConfiguration`, `netsh interface tcp show global`, rapport WLAN (`netsh wlan show wlanreport`)
- **Logiciels installés** : registre `HKLM` + `HKCU` (`\Software\Microsoft\Windows\CurrentVersion\Uninstall`), événements MSI (Event ID 1033)
- **Tâches planifiées** : export XML de toutes les tâches non-Microsoft via `Export-ScheduledTask`
- **Services** : `Get-Service` complet (nom, statut, type de démarrage)
- **Defender** : `Get-MpThreatDetection`, `Get-MpThreat`, `AntivirusProduct` (SecurityCenter2)
- **Pilotes** : `Get-PnpDevice`, `Win32_PnPSignedDriver`, `Win32_PnpEntity` (codes erreur `ConfigManagerErrorCode`)
- **Windows Update** : `Get-WindowsUpdateLog`, `Win32_ReliabilityRecords` (filtré sur erreurs WUClient)
- **Démarrage** : `Win32_StartupCommand`

---

### Module 2 — DiagBoot `→ Bureau\DiagBoot_<ts>.txt`

Analyse en **lecture seule** de la chaîne de démarrage. Génère une transcription complète.

- **Firmware** : détection UEFI via `Confirm-SecureBootUEFI` + présence `bootmgfw.efi`, état Secure Boot
- **Disques physiques** : `Get-Disk` (bus type, partition style GPT/MBR, statut opérationnel)
- **Partitions** : `Get-Partition` (type EFI/MSR/Recovery/Basic, GUID, lettre)
- **Volumes** : `Get-Volume` (filesystem, espace, type de lecteur)
- **Partition EFI** :
  - Détection primaire via `Type == 'EFI'` ou `'System'`
  - Fallback : partitions FAT32 < 1 Go sans lettre sur disques GPT
  - Montage temporaire via `mountvol` avec lettre libre (H→Z)
  - Suppression du popup Explorateur : `NoDriveTypeAutoRun = 0xFF` + arrêt `ShellHWDetection` pendant le montage, restauration exacte après
  - Résolution `HarddiskVolumeX → DiskNumber` via `QueryDosDevice` (P/Invoke kernel32)
  - Croisement avec `bcdedit /enum firmware` pour identifier l'EFI prioritaire dans le firmware
  - Vérification version `bootmgfw.efi` via `FileVersionInfo`
- **BitLocker** : `Get-BitLockerVolume` (statut, méthode, pourcentage de chiffrement)
- **BCD** : `bcdedit /enum ALL` avec colorisation syntaxique
- **Multi-boot** : détection par présence de `ntoskrnl.exe` sur chaque volume monté
- **Entrées UEFI** : `bcdedit /enum firmware`
- **Plan NVMe autonome** : génère les commandes `diskpart` + `bcdboot` adaptées si l'EFI n'est pas sur le NVMe

> `-DebugEFI` : active un log détaillé du montage EFI (`Bureau\DiagBoot_EFI_Debug_<ts>.log`)

---

### Module 3 — AuditSOC `→ Bureau\AuditSOC_<ts>.txt`

Audit SOC/DFIR en 15 sections, sortie via `Tee-Object` (console + fichier simultanément) :

1. Identité : `whoami /all`, utilisateurs/groupes locaux, sessions actives (`query session`), Event ID 4624 (30 derniers)
2. Réseau : profils, interfaces, routes, cache ARP, cache DNS, binding adaptateurs
3. Ports ouverts : `netstat -ano` (LISTENING + ESTABLISHED), résolution PID → chemin processus + owner
4. Firewall : profils (`Get-NetFirewallProfile`), règles INBOUND actives, règles OUTBOUND Block, règles critiques (SMB/RDP/WinRM/SSH/445/3389/5985)
5. Services : services running, liste ciblée (LanmanServer, TermService, WinRM, RemoteRegistry, Spooler, Docker, WSL…), services avec chemin non quoté (vecteur PrivEsc)
6. SMB : registre (`SMB1`/`SMB2`), `Get-SmbServerConfiguration` (signature, chiffrement, null sessions), partages, sessions, connexions ouvertes
7. RDP : `fDenyTSConnections`, NLA (`UserAuthentication`), port RDP, WinRM (`winrm enumerate`), RemoteRegistry
8. Protocoles latéraux : IPv6 par interface, Teredo, IPHTTPS, NetBIOS (`TcpipNetbiosOptions`), LLMNR (GPO `EnableMulticast`), mDNS (`EnableMDNS`)
9. ICMP : règles firewall filtrant sur ICMP/Ping/Echo
10. Processus suspects : processus avec connexions réseau, processus sans chemin (hors liste blanche noyau), tâches planifiées actives non-Microsoft + leurs actions
11. Registre persistance : Run Keys (5 emplacements HKCU/HKLM), LSA (`RunAsPPL`, `LmCompatibilityLevel`, `NoLMHash`, `RestrictAnonymous`), UAC (`EnableLUA`, `ConsentPromptBehaviorAdmin`), PowerShell logging (ScriptBlock, Module, Transcription), AMSI
12. Defender : `Get-MpComputerStatus`, exclusions (paths, process, extensions)
13. Événements sécurité : 4625 (échecs logon), 4624 (succès), 7045 (service installé), 1102 (log effacé), 4732/4728 (ajout groupe privilégié)
14. Mises à jour : `Get-HotFix` (15 derniers), dernière détection WU (registre)
15. Certificats : BitLocker via `manage-bde`, certificats machine expirant < 90 jours, certificats racine non-Microsoft

---

### Module 4 — EDR `→ Bureau\EDR_<ts>\Rapport_EDR.txt`

Audit AV/EDR avec score de sécurité pondéré et remédiation optionnelle.

**Détection AV/EDR** :
- `AntivirusProduct` (WMI `SecurityCenter2`) : décodage du champ `productState` (hex, bits 2-3 = état)
- Base vendeurs intégrée (16 AV grand public + 10 EDR entreprise) : CrowdStrike (`CSFalconService`), SentinelOne (`SentinelAgent`), MDE (`Sense`), Carbon Black, Cybereason, Cortex XDR, Trellix, Harfanglab…
- EDR hors SecurityCenter détectés par présence de service Windows

**Score de sécurité** : chaque vérification a un poids (10–15 pts). Score final en pourcentage avec liste des points KO et recommandations ciblées.

**Remédiation** via `-Fix <cible>` :

| Cible         | Action                                                                                     |
|---------------|--------------------------------------------------------------------------------------------|
| `Firewall`    | Supprime GPO `WindowsFirewall`, `netsh advfirewall reset`, réactive tous les profils       |
| `SmartScreen` | Supprime GPO `EnableSmartScreen`, force `RequireAdmin` dans le registre                    |
| `Defender`    | `Set-MpPreference -RealTimeProtectionEnabled $true`, vérifie Tamper Protection avant       |
| `SMBv1`       | `Set-SmbServerConfiguration -EnableSMB1Protocol $false` (CVE-2017-0144 / WannaCry)        |
| `LSA`         | `RunAsPPL = 1` dans `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa`                          |
| `All`         | Applique les 5 remédiations dans l'ordre                                                   |

**Partage de rapport** :
- `-ShareDpaste` : upload vers `dpaste.com/api/v2/` (expiry 7 jours, `application/x-www-form-urlencoded`)
- `-ShareGofile` : upload multipart vers `store1.gofile.io/contents/uploadfile`

---

### Module 5 — WinDiag `→ Bureau\WinDiag_<ts>.txt`

Résolution de codes d'erreur Windows avec base interne (~60 entrées) couvrant :

- **NTSTATUS** : `0xC000012F` (IMAGE_FORMAT), `0xC0000005` (ACCESS_VIOLATION), `0xC0000142` (DLL_INIT_FAILED), `0xC0000374` (HEAP_CORRUPTION), `0xC0000409` (STACK_BUFFER_OVERRUN)…
- **Win32** : `0x00000002` (FILE_NOT_FOUND), `0x00000070` (DISK_FULL), `0x000000C1` (BAD_EXE_FORMAT)…
- **HRESULT** : `0x80004005` (E_FAIL), `0x80070057` (INVALID_ARG), `0x8007007E` (MOD_NOT_FOUND)…
- **BSOD Stop Codes** : `0x0000001A` (MEMORY_MANAGEMENT), `0x000000EF` (CRITICAL_PROCESS_DIED), `0x000000D1` (DRIVER_IRQL_NOT_LESS_OR_EQUAL), `0x00000050` (PAGE_FAULT_IN_NONPAGED_AREA)…

Chaque entrée contient : nom symbolique, catégorie, sévérité, cause technique, solution étape par étape.

Paramètres :
- `-Query <code|DLL|mot-clé>` : recherche directe
- `-Scan` : scan de l'Event Log pour extraire les crash récents
- `-Dump <chemin>` : analyse de fichier(s) minidump
- `-Export` : réexporte le dernier résultat

---

### Module 6 — SFC/DISM `→ Bureau\CBS_SFC_DISM_Report_<ts>.txt` + `.html`

- `sfc /scannow` avec capture de la sortie
- `DISM /Online /Cleanup-Image /CheckHealth` + `/ScanHealth` + `/RestoreHealth`
- Parsing du log `CBS.log` pour extraire uniquement les lignes d'erreur
- Rapport HTML avec code couleur sur les résultats

---

### Module 7 — NetShare `→ Bureau\NetShare_<ts>.html`

Audit des partages réseau et de la surface d'exposition :

- `Get-SmbShare` : partages actifs, chemins, permissions
- `Get-SmbServerConfiguration` : SMB signing, chiffrement, null sessions
- `Get-NetFirewallRule` : règles firewall relatives aux ports SMB (445, 139)
- Mode `PUBLIC` (`-NetMode PUBLIC`) : restreint aux informations sans chemins locaux

---

### Module 8 — Compare-PC `→ Bureau\CPR_<ts>\`

Comparaison de deux postes à partir de fichiers `*-all.txt` générés par NetShare (2 fichiers minimum, 10 maximum via `-ReportFiles`) :

- Diff sur logiciels installés, services, tâches planifiées, partages, ports ouverts
- Identification des éléments présents sur un poste et absents sur l'autre

---

### Module 9 — EVCDiag `→ Bureau\EVC_Export\`

Export et analyse de l'Event Log Windows :

- Extraction par canal (System, Application, Security, Setup)
- Filtrage par niveau (Error, Critical, Warning)
- Détection de patterns récurrents (même source, même Event ID)

---

### Module 10 — CrashDiag `→ Bureau\CrashDiag_<ts>\*.txt + *.html`

Analyse BSOD, freezes, WHEA et crashs applicatifs :

- Event IDs : 41 (Kernel-Power / reboot inopiné), 1001 (BugCheck BSOD), WHEA Logger (erreurs matérielles)
- Historique configurable : `-HeuresHistorique <n>` (défaut : 48h)
- Crashs applicatifs : Event ID 1000 (Application Error), 1002 (Application Hang)
- Sessions Windows : Event IDs 6005/6006/6008 (démarrages, arrêts, arrêts inattendus)
- Export : `-ExportCSV` et/ou `-ExportHTML`

---

### Module 11 — GhostWin `→ Bureau\GhostWin_<ts>\*.csv + *.html`

Détection d'installations Windows résiduelles ou fantômes :

- Scan de tous les volumes montés à la recherche de `\Windows\System32\ntoskrnl.exe`
- Comparaison des versions (`FileVersionInfo`) avec l'installation active
- Détection de profils utilisateurs orphelins (`C:\Users\*`) sur volumes secondaires
- Export CSV + HTML des installations trouvées

---

## Sorties — récapitulatif

| Module     | Fichier(s) générés                                  |
|------------|-----------------------------------------------------|
| InfoSys    | `Bureau\InfoSys_<ts>.zip`                           |
| DiagBoot   | `Bureau\DiagBoot_<ts>.txt`                          |
| AuditSOC   | `Bureau\AuditSOC_<ts>.txt`                          |
| EDR        | `Bureau\EDR_<ts>\Rapport_EDR.txt`                   |
| WinDiag    | `Bureau\WinDiag_<ts>.txt`                           |
| SFC        | `Bureau\CBS_SFC_DISM_Report_<ts>.txt` + `.html`     |
| NetShare   | `Bureau\NetShare_<ts>.html`                         |
| ComparePC  | `Bureau\CPR_<ts>\`                                  |
| EVCDiag    | `Bureau\EVC_Export\`                                |
| CrashDiag  | `Bureau\CrashDiag_<ts>\*.txt` + `*.html`            |
| GhostWin   | `Bureau\GhostWin_<ts>\*.csv` + `*.html`             |

---

## ⚠️ Warning

Le script effectue les opérations suivantes susceptibles de déclencher un antivirus :
- Lecture de `Win32_PhysicalMemory`, `Win32_PnPEntity`, `WmiMonitorID` via WMI
- Accès à `root/SecurityCenter2` (namespace WMI AV)
- Appel de `QueryDosDevice` via P/Invoke (kernel32.dll) pour la résolution des volumes EFI
- Écriture temporaire dans `HKLM:\SOFTWARE\...\Policies\Explorer` (NoDriveTypeAutoRun) pendant le montage EFI, restaurée immédiatement après
- Appel à `bcdedit /enum firmware` et `mountvol` (nécessite droits Admin)
- `Add-MpPreference -ExclusionPath` lors de l'installation (modifie la configuration Defender)

Aucune connexion réseau sortante n'est établie sauf si `-ShareDpaste` ou `-ShareGofile` est passé explicitement.

---

## ❗ Important

- **`Set-StrictMode -Version Latest`** est actif. Toute variable non initialisée lève une erreur.
- **`$ErrorActionPreference = 'SilentlyContinue'`** sur les appels WMI/CIM non critiques — les erreurs sont silencieuses par design pour les postes avec configurations restreintes.
- Si Defender bloque le script en cours d'exécution, la transcription en cours (`Start-Transcript`) sera tronquée. Le rapport partiel est conservé sur le Bureau.
- Le module DiagBoot arrête temporairement le service `ShellHWDetection` pendant le montage de la partition EFI. Il est redémarré automatiquement. Si le script est interrompu pendant cette phase, relancer `Start-Service ShellHWDetection` manuellement.
- Les modules de remédiation EDR (`-Fix`) modifient le registre système et la configuration SMB. Ces changements sont persistants et ne sont pas annulés automatiquement.
