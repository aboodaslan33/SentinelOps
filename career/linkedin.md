# LinkedIn Project Description

Add under *Projects* on your LinkedIn profile, or use as the body of a post. No emojis, no
exaggerated claims — technical and realistic, as requested.

---

## Project entry (LinkedIn "Projects" section)

**Title:** SentinelOps — Windows Threat Detection, SIEM Monitoring & Incident Response Lab

**Description:**

SentinelOps is a self-built Security Operations Center laboratory that simulates the monitoring
environment of a small organisation. I built it to practise practical SOC Analyst (L1) skills
end to end: log collection, detection engineering, alert triage, investigation, and incident
documentation.

The lab uses Wazuh as the SIEM/XDR platform, monitoring a Windows 11 endpoint instrumented with
Sysmon and PowerShell script-block logging. I wrote 30 custom Wazuh detection rules covering
five realistic scenarios — brute-force authentication, suspicious PowerShell, unauthorised
account creation, host reconnaissance, and privilege escalation — and mapped each detection to
the corresponding MITRE ATT&CK technique.

To validate the detections I wrote safe PowerShell scripts that generate the telemetry each
technique produces (no malware or real payloads, entirely inside an isolated host-only network),
then triaged the resulting alerts and documented five complete incident reports using a
structured investigation and incident-response workflow. I also built Wazuh dashboards for
authentication, endpoint activity, alert timelines and ATT&CK coverage, and wrote analyst
playbooks and full setup documentation.

Key skills demonstrated: SIEM operations, Windows security monitoring, detection engineering,
alert triage, incident investigation, incident response, and MITRE ATT&CK mapping.

All testing was performed in an isolated laboratory environment. No production systems, public
IP addresses, real organisations or real users were involved.

Tools: Wazuh, Sysmon, Windows 10/11, Windows Event Logs, PowerShell, MITRE ATT&CK.

**Link:** <your GitHub repository URL>

---

## Short version (for a feed post)

I built SentinelOps, a hands-on SOC lab for practising Blue Team / SOC Analyst L1 skills.

Stack: Wazuh (SIEM/XDR) monitoring a Windows 11 endpoint with Sysmon and PowerShell logging.

What is in it:
- 30 custom Wazuh detection rules across 5 attack scenarios, all mapped to MITRE ATT&CK
- Safe attack-simulation scripts to validate every detection
- 5 full incident reports following a triage-to-closure investigation workflow
- Wazuh dashboards, 5 analyst playbooks, and complete setup documentation

Everything was done in an isolated lab environment — no production systems or real targets.

Skills: SIEM, detection engineering, alert triage, incident investigation, incident response,
MITRE ATT&CK, Windows event log analysis.

Repository: <your GitHub repository URL>

#SOC #BlueTeam #Wazuh #SIEM #Sysmon #ThreatDetection #IncidentResponse #MITREATTACK #CyberSecurity

---

## Writing notes

- Keep the numbers accurate (30 rules, 5 scenarios, 5 incident reports) — they match the repo.
- Do not use words like "enterprise", "production" or "real-world attacks". You built a lab; say so.
- If you add screenshots to the post, use the redacted images from `/screenshots`.
- Pin the repository to your GitHub profile so the link in your posts always resolves.
