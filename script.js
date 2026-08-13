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
    description: 'This comprehensive SOC project applied the 6-phase threat intelligence lifecycle: from infrastructure deployment through detection, analysis, and defensive recommendations. Using T-Pot v24.04 (Cowrie, Dionaea, RDPHoneypot, Tanner, Ciscoasa) and Suricata NIDS, I captured and analyzed real-world attack patterns including Telnet credential sweeps, SMB exploitation attempts, RDP DoS attacks, and backdoor installation signatures. The analysis identified top threat CVEs (CVE-2012-0152), threat actors by autonomous system, and actionable defensive controls.',
    repo: 'https://github.com/Dgrover07/Honey_pot_project',
    tags: ['T-Pot', 'Suricata', 'Docker', 'NIDS', 'Threat Intelligence', 'Incident Analysis'],
    points: [
      'Deployed and configured a containerized multi-honeypot framework capturing 141 attack events with an average daily attack rate of 12.229 events/day.',
      'Analyzed Telnet (Port 23), SMB (Port 445), and RDP (Port 3389) attack patterns to identify top threat actors and exploitation techniques.',
      'Identified critical CVEs (CVE-2012-0152 MS12-020, DoublePulsar backdoor signatures) and produced threat actor intelligence by autonomous system analysis.',
      'Documented the 6-phase SOC threat intelligence lifecycle with deployment topology, detection rules, threat analysis, and defensive security engineering recommendations.'
    ],
    tech: ['T-Pot v24.04', 'Suricata NIDS', 'Docker', 'Ubuntu 22.04', 'Cowrie', 'Dionaea', 'Network Telemetry', 'Threat Intelligence', 'SOC Operations']
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

renderProjectDetail();
