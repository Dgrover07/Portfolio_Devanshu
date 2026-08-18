# 🗺️ MITRE ATT&CK Matrix & TTP Mapping
## Operation BlackByte Threat Attribution & Coverage

This document outlines the complete MITRE ATT&CK enterprise mapping for the **Operation BlackByte** intrusion, detailing tactics, techniques, sub-techniques, specific observables, and defensive detection strategies.

---

## 📊 High-Level MITRE ATT&CK Matrix

| Tactic | Technique ID | Technique Name | Threat Observable | Detection Mechanism |
| :--- | :--- | :--- | :--- | :--- |
| **Initial Access** | `T1566.001` | Spearphishing Attachment | `Invoice_Q3_9942.xlsm` sent to `jdoe@apex-fin.com` | Email Gateway / Sysmon EID 15 |
| **Execution** | `T1204.002` | User Execution: Malicious File | User opened macro-enabled Excel sheet | Process creation logs |
| **Execution** | `T1059.001` | PowerShell | Base64-encoded download cradle | Sysmon EID 1, PS EID 4104 |
| **Persistence** | `T1053.005` | Scheduled Task | Scheduled Task `WindowsAppUpdate` registered | WinEventLog EID 4698 |
| **Privilege Escalation** | `T1543.003` | Windows Service | Service `PSEXESVC.exe` running as `SYSTEM` | WinEventLog EID 7045 |
| **Defense Evasion** | `T1562.001` | Impair Defenses: Modify Tools | Added Defender exclusion for `C:\Windows\Temp` | Defender EID 5007 |
| **Defense Evasion** | `T1564.003` | Hidden Window | PowerShell executed with `-w hidden` flag | Sysmon EID 1 CommandLine |
| **Credential Access** | `T1003.001` | LSASS Memory Dumping | `rundll32.exe comsvcs.dll MiniDump` | Sysmon EID 10 (`0x1010` access) |
| **Discovery** | `T1087.002` | Domain Account Discovery | `net user /domain`, `whoami /groups` | Sysmon EID 1 |
| **Discovery** | `T1069.002` | Domain Groups Discovery | `net group "Domain Admins" /domain` | Sysmon EID 1 |
| **Discovery** | `T1018` | Remote System Discovery | `ping -n 1 10.100.10.20`, `nltest /dclist` | Sysmon EID 1 |
| **Lateral Movement** | `T1021.002` | SMB / Windows Admin Shares | Authenticated network pivot using `svc_backup` | WinEventLog EID 4624 (Type 3) |
| **Lateral Movement** | `T1570` | Lateral Tool Transfer | Dropping `PSEXESVC.exe` on `FS-DATA-01` | Sysmon EID 11 |
| **Collection** | `T1560.001` | Archive via Utility | `7z.exe a -p"ExfilPass2026!"` | Sysmon EID 1 |
| **Collection** | `T1074.001` | Local Data Staging | `C:\Windows\Temp\Finance_2026_Export.7z` | Sysmon EID 11 |
| **Command & Control** | `T1071.001` | Web Protocols (HTTP/HTTPS) | C2 beaconing to `198.51.100.77:443` | `stream:http` / Firewall logs |
| **Command & Control** | `T1573.001` | Symmetric Encryption | Password-protected encrypted archive header | Process arguments analysis |
| **Exfiltration** | `T1041` | Exfiltration Over C2 Channel | 88.4 MB HTTP POST upload to `/upload` | `stream:http` `bytes_out` |
| **Impact** | `T1490` | Inhibit System Recovery | `vssadmin delete shadows /all /quiet` | Sysmon EID 1 |

---

## 🛡️ Detailed Defensive Mitigations

### 1. Initial Access & Execution Controls
* **M1049 (Antivirus / Antimalware):** Enforce Microsoft Defender Exploit Guard and Attack Surface Reduction (ASR) rules.
* **M1040 (Behavior Prevention on Endpoint):** Block Office applications from creating executable or script child processes.

### 2. Credential Access Protection
* **M1027 (Credential Guard):** Enable Windows Defender Credential Guard (Virtualization-based security) to protect the LSASS memory space against dumping by unauthorized processes.
* **M1026 (Privileged Account Management):** Eliminate shared service account passwords and implement Group Managed Service Accounts (gMSA).

### 3. Lateral Movement Restrictions
* **M1030 (Network Segmentation):** Restrict SMB (TCP 445) communication between endpoints using host-based firewalls and VLAN isolation.
* **M1038 (Execution Prevention):** Disable remote service creation via group policy for non-administrative workstations.
