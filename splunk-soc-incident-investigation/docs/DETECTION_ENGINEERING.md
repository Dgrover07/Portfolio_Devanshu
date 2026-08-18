# ⚙️ Detection Engineering & Sigma Rule Catalog
## Enterprise SIEM Alerting Logic & Correlation Rules

This catalog documents the production-grade **Splunk Correlation Searches** and vendor-agnostic **Sigma Rules** engineered from the **Operation BlackByte** investigation findings.

---

## 🚨 Production Splunk Correlation Searches

### 1. Alert: Suspicious Office Child Process Spawning Script Interpreters
* **Severity:** High
* **Risk Score:** 80
* **Mitre ATT&CK:** T1059.001, T1204.002
* **Cron Schedule:** `*/5 * * * *` (Every 5 minutes)

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search ParentImage IN ("*\\excel.exe", "*\\winword.exe", "*\\powerpnt.exe", "*\\outlook.exe")
| search Image IN ("*\\powershell.exe", "*\\cmd.exe", "*\\wscript.exe", "*\\cscript.exe", "*\\mshta.exe", "*\\certutil.exe")
| eval AlertTitle="Suspicious Office Child Process Spawning Scripting Engine"
| eval RiskScore=80
| table _time, Computer, User, ParentImage, Image, CommandLine, RiskScore
```

---

### 2. Alert: LSASS Process Memory Access with Dump Rights
* **Severity:** Critical
* **Risk Score:** 95
* **Mitre ATT&CK:** T1003.001
* **Cron Schedule:** `*/5 * * * *` (Every 5 minutes)

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10
| search TargetImage="*\\lsass.exe" GrantedAccess IN ("0x1010", "0x1410", "0x143a", "0x1FFFFF", "0x1F3FFF")
| search NOT SourceImage IN ("*\\MsMpEng.exe", "*\\csrss.exe", "*\\svchost.exe")
| eval AlertTitle="Potential LSASS Credential Dumping Attempt"
| eval RiskScore=95
| table _time, Computer, SourceUser, SourceImage, TargetImage, GrantedAccess, CallTrace, RiskScore
```

---

### 3. Alert: Volume Shadow Copy Deletion (Ransomware Pre-Cursor)
* **Severity:** Critical
* **Risk Score:** 100
* **Mitre ATT&CK:** T1490
* **Cron Schedule:** `*/2 * * * *` (Every 2 minutes)

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search (Image="*\\vssadmin.exe" AND CommandLine="*delete*shadows*")
      OR (Image="*\\wmic.exe" AND CommandLine="*shadowcopy*delete*")
      OR (Image="*\\wbadmin.exe" AND CommandLine="*delete*catalog*")
| eval AlertTitle="Volume Shadow Copy Deletion Detected (Ransomware Inhibiting Recovery)"
| eval RiskScore=100
| table _time, Computer, User, Image, CommandLine, RiskScore
```

---

## 📜 Vendor-Agnostic Sigma Rules

### Sigma Rule 1: Suspicious Execution from Office Applications
```yaml
title: Office Application Spawning Script Interpreter
id: 7b8c9d0e-1f23-4567-890a-bcdef1234567
status: production
description: Detects Microsoft Office applications (Excel, Word, PowerPoint) spawning command-line interpreters or scripting hosts.
references:
    - https://attack.mitre.org/techniques/T1059/001/
    - https://attack.mitre.org/techniques/T1204/002/
author: Devanshu Grover (MSc Cybersecurity)
date: 2026/08/18
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\excel.exe'
            - '\winword.exe'
            - '\powerpnt.exe'
            - '\outlook.exe'
    selection_child:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\cmd.exe'
            - '\wscript.exe'
            - '\cscript.exe'
            - '\mshta.exe'
            - '\certutil.exe'
    condition: selection_parent and selection_child
fields:
    - ComputerName
    - User
    - ParentImage
    - Image
    - CommandLine
falsepositives:
    - Rare legacy administrative macros (must be signed)
level: high
tags:
    - attack.execution
    - attack.t1059.001
    - attack.initial_access
    - attack.t1566.001
```

---

### Sigma Rule 2: Memory Dumping of LSASS via Comsvcs DLL
```yaml
title: LSASS Memory Dump via Comsvcs DLL
id: 8c9d0e1f-2345-6789-0abc-def123456789
status: production
description: Detects process memory dumping of lsass.exe using rundll32.exe and comsvcs.dll MiniDump export.
references:
    - https://attack.mitre.org/techniques/T1003/001/
    - https://attack.mitre.org/techniques/T1218/011/
author: Devanshu Grover (MSc Cybersecurity)
date: 2026/08/18
logsource:
    category: process_creation
    product: windows
detection:
    selection_process:
        Image|endswith: '\rundll32.exe'
    selection_command:
        CommandLine|contains|all:
            - 'comsvcs'
            - 'MiniDump'
    condition: selection_process and selection_command
fields:
    - ComputerName
    - User
    - CommandLine
    - ProcessId
falsepositives:
    - None observed in production environments
level: critical
tags:
    - attack.credential_access
    - attack.t1003.001
    - attack.defense_evasion
    - attack.t1218.011
```

---

### Sigma Rule 3: Volume Shadow Copy Deletion via Vssadmin
```yaml
title: Volume Shadow Copy Deletion
id: 9d0e1f23-4567-890a-bcde-f1234567890a
status: production
description: Detects deletion of volume shadow copies using vssadmin.exe to inhibit system recovery during ransomware attacks.
references:
    - https://attack.mitre.org/techniques/T1490/
author: Devanshu Grover (MSc Cybersecurity)
date: 2026/08/18
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\vssadmin.exe'
        CommandLine|contains|all:
            - 'delete'
            - 'shadows'
    condition: selection
fields:
    - ComputerName
    - User
    - CommandLine
falsepositives:
    - Automated backup software (rare, should use API not CLI)
level: critical
tags:
    - attack.impact
    - attack.t1490
```
