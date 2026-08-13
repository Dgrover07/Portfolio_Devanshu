const projectData = {
  'home-siem-lab': {
    id: 'home-siem-lab',
    badge: 'LIVE LAB',
    category: '01 · SIEM & LOGGING',
    name: 'Home SIEM & Windows Monitoring Lab',
    summary: 'Built a home SIEM environment and ingested Windows Event Logs and Sysmon telemetry into Splunk for centralized security monitoring.',
    description: 'This lab focused on designing a practical security monitoring stack within a home environment. I configured a Windows endpoint to emit security telemetry, then centralized the output into Splunk for correlation, triage, and investigation.',
    repo: 'https://github.com/Dgrover07/Home-SIEM-Windows-Lab',
    tags: ['Splunk', 'Sysmon', 'Windows 11', 'Kali Linux', 'VirtualBox'],
    points: [
      'Built a log collection workflow that fed Windows security events and Sysmon telemetry into Splunk.',
      'Created targeted dashboards and searches for authentication, process execution, and suspicious activity.',
      'Documented incident-style investigations covering evidence, indicators of compromise, and remediation actions.'
    ],
    tech: ['Windows Event Logs', 'Sysmon', 'Splunk', 'VirtualBox', 'Kali Linux']
  },
  'honeypot-dashboard': {
    id: 'honeypot-dashboard',
    badge: 'ACTIVE HONEYPOT',
    category: '02 · ADVERSARY TELEMETRY',
    name: 'Honeypot with Live Attacker Dashboard',
    summary: 'Deployed a Linux-based honeypot in an isolated lab and configured logging to capture unauthorized connection attempts and authentication activity.',
    description: 'This project simulated a vulnerable host to observe adversarial behavior and capture attack patterns in real time. The goal was to understand source activity, authentication attempts, and recurring scan or brute-force behavior in a lab-safe environment.',
    repo: 'https://github.com/Dgrover07/Honeypot-Attacker-Dashboard',
    tags: ['Linux', 'Docker', 'Network Analytics', 'Dashboarding'],
    points: [
      'Configured a Linux honeypot to monitor attempted access, source IP activity, and credential testing behavior.',
      'Collected and filtered suspicious traffic patterns to identify the most common attack signatures.',
      'Built a dashboard to communicate attacker activity and support technical reporting.'
    ],
    tech: ['Linux', 'Docker', 'Netstat', 'Logs & Monitoring', 'Dashboarding']
  },
  'phishing-osint': {
    id: 'phishing-osint',
    badge: 'ANALYSIS',
    category: '03 · THREAT INVESTIGATION',
    name: 'Phishing Email Investigation & OSINT',
    summary: 'Investigated suspicious emails through headers, senders, domains, URLs, and message content for phishing and spoofing indicators.',
    description: 'This project focused on threat investigation from a triage perspective: reviewing suspicious email metadata, analyzing malicious infrastructure, and verifying whether links or domains were related to phishing or impersonation tactics.',
    repo: 'https://github.com/Dgrover07/Phishing-OSINT-Investigation',
    tags: ['VirusTotal', 'URLScan.io', 'MXToolbox', 'CyberChef', 'WHOIS'],
    points: [
      'Reviewed email headers and domain metadata to identify potential spoofing or malicious infrastructure.',
      'Used OSINT and public scanning services to validate suspicious URLs and domain reputation.',
      'Produced structured investigation notes with risk findings and containment recommendations.'
    ],
    tech: ['Email Header Analysis', 'OSINT', 'Threat Intelligence', 'CyberChef', 'WHOIS']
  },
  'tpot-soc-assessment': {
    id: 'tpot-soc-assessment',
    badge: 'THREAT TELEMETRY',
    category: '04 · SOC THREAT INTELLIGENCE',
    name: 'T-Pot Multi-Honeypot SOC Threat Intelligence Assessment',
    summary: 'Deployed an enterprise-scale multi-honeypot SOC environment using T-Pot and Suricata NIDS to capture, analyze and investigate real-world threat telemetry across 141 attack events.',
    description: `EXECUTIVE SUMMARY
141 honeypot attack events | 12.229 avg daily attack rate | 57 unique threat actors | 6 attack vectors mapped | 1,601 DoublePulsar alerts | 4 critical CVEs identified

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PHASE 1: DEPLOYMENT & INFRASTRUCTURE
├─ T-Pot v24.04 on Ubuntu 22.04 LTS (Cloud VM, isolated network)
├─ 6 Containerized Honeypot Daemons:
│  ├─ Cowrie (SSH/Telnet Ports 22/23): Brute-force & malware binary capture
│  ├─ Dionaea (SMB Port 445): EternalBlue/MS17-010 exploitation trapping
│  ├─ RDPHoneypot (Port 3389): Windows RDP credential spraying & DoS
│  ├─ Tanner & H0neytr4p (HTTP/HTTPS 80/443): Web scanner detection
│  ├─ Ciscoasa (VPN Port 500): Cisco ASA firewall simulation
│  └─ Suricata NIDS: Real-time network intrusion detection (ET rulesets)
└─ Architecture: Public Internet → Edge Firewall → Port Mirror TAP → NIDS → Docker Container Cluster

PHASE 2: LOG COLLECTION & NORMALIZATION
├─ Elastic Stack Pipeline: Filebeat → Logstash → Elasticsearch → Kibana
├─ Elastic Common Schema (ECS) Standardization:
│  ├─ source.ip, destination.port, event.dataset, suricata.signature normalized
│  ├─ GeoIP & ASN enrichment via MaxMind GeoLite2
│  └─ Daily index rotation with 30-day hot/warm retention
└─ Output: Unified log storage across all honeypot + NIDS telemetry

PHASE 3: DETECTION ENGINEERING
├─ Custom Suricata NIDS Signatures (rules/suricata_custom.rules):
│  ├─ SID 9000001: DoublePulsar SMB Backdoor Communication
│  ├─ SID 9000002: Nmap Stealth SYN Scans (WinSize 1024)
│  ├─ SID 9000003: RDP Syn-Reset DoS (CVE-2012-0152)
│  └─ SID 9000004: Telnet Botnet High-Frequency Probes
├─ Sigma YAML Rules: Portable logic for Splunk/Elastic/Sentinel
└─ Kibana KQL Queries: Production SOC analyst triage dashboards

PHASE 4: THREAT ANALYSIS & FORENSICS (6 Attack Vectors Identified)
├─ Vector A: DoublePulsar NSA Backdoor Probing (1,601 Alerts | SID 2024766)
│  └─ Shadow Brokers leak | Ring-0 kernel payload | SMB Port 445 sweeps
│
├─ Vector B: Telnet IoT Botnet Ingress (33 Attacks | Port 23)
│  └─ Mirai/Qbot signatures | Weak default credentials (admin/admin, root/12345)
│
├─ Vector C: SSH Password Spraying (13 Sessions | Port 22)
│  └─ Dictionary attacks | High-frequency brute force targeting shell access
│
├─ Vector D: RDP DoS Exploitation (5 Alerts | CVE-2012-0152 / MS12-020)
│  └─ Malformed TCP packets | Remote Desktop Service crash attempts
│
├─ Vector E: Web Application Reconnaissance (20 Attacks | Ports 80/443)
│  └─ Directory listing probes | Admin panel scanning | SSL/TLS cipher enumeration
│
└─ Vector F: Nmap SYN Stealth Scanning (20 Alerts | SID 2009582)
   └─ Pre-exploitation network mapping | Open port identification

PHASE 5: THREAT ACTOR ATTRIBUTION & MITRE ATT&CK MAPPING
Autonomous System Breakdown:
├─ AS5089 Virgin Media (UK): 18 attacks | TOP SOURCE IP: 80.195.138.223
├─ AS4134 Chinanet (China): 10 attacks
├─ AS210558 1337 Services GmbH: 9 attacks | IP: 185.241.208.245
├─ AS8151 UNINET (Mexico): 8 attacks | IP: 187.132.237.112
├─ AS8517 Academic Network (Turkey): 6 attacks | IP: 193.140.142.9
└─ AS9121 Turk Telekom (Turkey): 6 attacks | IP: 81.214.142.193

MITRE ATT&CK Lifecycle Mapping:
├─ Reconnaissance (T1595.001): Active port scanning (Nmap SYN sweeps)
├─ Credential Access (T1110.001): Brute force password guessing (SSH/Telnet)
├─ Initial Access (T1210): Remote service exploitation (DoublePulsar/EternalBlue)
└─ Impact (T1499.002): OS exhaustion DoS attacks (RDP malformed packets)

PHASE 6: DEFENSIVE RECOMMENDATIONS & SECURITY HARDENING
├─ Network Controls:
│  ├─ BLOCK: Port 445 (SMB) & Port 23 (Telnet) at edge firewall
│  └─ RESTRICT: Port 3389 (RDP) behind Zero-Trust Network Access (ZTNA)
│
├─ Host Hardening:
│  ├─ Disable SMBv1 | Enforce SMBv2/SMBv3 with signing
│  ├─ SSH: Disable password auth | Ed25519 keys mandatory
│  └─ Apply: MS12-020, MS17-010 patches immediately
│
├─ Automated Response:
│  ├─ Fail2ban: Drop IPs after 5 failed attempts in 60s
│  └─ UFW blocklist: Auto-block top threat actor IPs
│
└─ Endpoint Detection & Response (EDR): Monitor process execution, network connections, malware payloads

DELIVERABLES:
├─ soc_analytics.py / .ps1: Python & PowerShell SOC parsing engines
├─ Suricata/Sigma/KQL rules: Production-ready detection artifacts
├─ dashboard/index.html: Interactive SOC executive dashboard (Chart.js + live IOC search)
└─ iocs.json: Extracted threat intelligence export`,
    repo: 'https://github.com/Dgrover07/Honey_pot_project',
    tags: ['T-Pot v24.04', 'Suricata NIDS', 'Elastic Stack', 'Sigma Rules', 'MITRE ATT&CK', 'Threat Intelligence', 'SOC Operations', 'Incident Analysis'],
    points: [
      'Phase 1-2: Designed & deployed 6-container honeypot framework (Cowrie, Dionaea, RDPHoneypot, Tanner, Ciscoasa) + Suricata NIDS capturing 141 real-world attacks; normalized to Elastic Stack with ECS schema & GeoIP enrichment.',
      'Phase 3-4: Engineered custom Suricata signatures, Sigma YAML rules, and Kibana KQL queries; identified 6 attack vectors including 1,601 DoublePulsar alerts (SID 2024766), Telnet botnet (Port 23), RDP DoS (CVE-2012-0152), web reconnaissance, and Nmap stealth scans.',
      'Phase 5-6: Mapped threat actors across 6 autonomous systems (AS5089 Virgin Media UK leading with 18 attacks); correlated attacks to MITRE ATT&CK lifecycle (Reconnaissance → Initial Access → Impact); documented network, host, and EDR hardening controls.',
      'Delivered production-ready detection artifacts (Suricata/Sigma/KQL rules), Python & PowerShell SOC analytics engines, interactive executive dashboard (Chart.js), and extracted threat intelligence IOC inventory.'
    ],
    tech: ['T-Pot v24.04', 'Suricata NIDS', 'Docker', 'Ubuntu 22.04', 'Elastic Stack', 'Filebeat', 'Logstash', 'Elasticsearch', 'Kibana', 'ECS Schema', 'MaxMind GeoIP', 'Sigma Rules', 'KQL', 'Python', 'PowerShell', 'Chart.js', 'MITRE ATT&CK', 'Threat Intelligence', 'SOC Operations']
  }
};

function renderProjectDetail() {
  const root = document.body.dataset.page === 'project-detail';
  if (!root) return;

  const projectId = new URLSearchParams(window.location.search).get('project') || 'home-siem-lab';
  const project = projectData[projectId] || projectData['home-siem-lab'];

  const nameEl = document.getElementById('project-name');
  const summaryEl = document.getElementById('project-summary');
  const descriptionEl = document.getElementById('project-description');
  const badgeEl = document.getElementById('project-status');
  const repoLink = document.getElementById('project-repo');
  const repoSecondary = document.getElementById('project-repo-secondary');
  const tagWrap = document.getElementById('project-tags');
  const pointsList = document.getElementById('project-points');
  const techList = document.getElementById('project-tech');

  if (!nameEl || !summaryEl || !descriptionEl || !badgeEl) return;

  document.title = `${project.name} | Devanshu Grover`;
  nameEl.textContent = project.name;
  summaryEl.textContent = project.summary;
  descriptionEl.textContent = project.description;
  badgeEl.textContent = project.badge;

  if (repoLink) repoLink.href = project.repo;
  if (repoSecondary) repoSecondary.href = project.repo;

  tagWrap.innerHTML = project.tags.map(tag => `<span>${tag}</span>`).join('');
  pointsList.innerHTML = project.points.map(point => `<li>${point}</li>`).join('');
  techList.innerHTML = project.tech.map(item => `<li>${item}</li>`).join('');
}

/* ── Mobile menu toggle ── */
const menu = document.querySelector('.menu');
const navBar = document.querySelector('.nav');
menu?.addEventListener('click', () => navBar.classList.toggle('open'));
document.querySelectorAll('nav a').forEach(a =>
  a.addEventListener('click', () => navBar.classList.remove('open'))
);

/* ── Scroll-reveal & stagger observer ── */
const revealObserver = new IntersectionObserver(
  entries => entries.forEach(e => {
    if (e.isIntersecting) e.target.classList.add('visible');
  }),
  { threshold: 0.08, rootMargin: '0px 0px -50px 0px' }
);
document.querySelectorAll('.reveal, .stagger').forEach(el => revealObserver.observe(el));

/* ── Active nav section highlight ── */
const sections = document.querySelectorAll('section[id]');
const navLinks = document.querySelectorAll('nav a[href^="#"]');
const sectionObserver = new IntersectionObserver(
  entries => entries.forEach(entry => {
    if (entry.isIntersecting) {
      const id = entry.target.id;
      navLinks.forEach(link =>
        link.classList.toggle('active', link.getAttribute('href') === '#' + id)
      );
    }
  }),
  { threshold: 0.2, rootMargin: '-76px 0px -50% 0px' }
);
sections.forEach(s => sectionObserver.observe(s));

/* ── Animated stat counters ── */
function animateStats() {
  const statNumbers = document.querySelectorAll('.stat-number');
  const observerStats = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const el = entry.target;
        const target = parseInt(el.dataset.count);
        let current = 0;
        const increment = Math.ceil(target / 50);
        const timer = setInterval(() => {
          current += increment;
          if (current >= target) {
            el.textContent = target;
            clearInterval(timer);
          } else {
            el.textContent = current;
          }
        }, 30);
        observerStats.unobserve(el);
      }
    });
  }, { threshold: 0.5 });
  
  statNumbers.forEach(el => observerStats.observe(el));
}

/* ── Project filtering ── */
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
          setTimeout(() => {
            project.style.animation = '';
          }, 10);
        } else {
          project.classList.add('hidden');
        }
      });
    });
  });
}

/* ── Subtle header border glow on scroll ── */
let ticking = false;
window.addEventListener('scroll', () => {
  if (!ticking) {
    requestAnimationFrame(() => {
      navBar.style.borderBottomColor = window.scrollY > 60
        ? 'rgba(216,164,71,.15)'
        : '';
      ticking = false;
    });
    ticking = true;
  }
});

animateStats();
setupProjectFilters();
renderProjectDetail();
