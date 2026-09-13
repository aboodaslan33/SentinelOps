# CV / Résumé Project Entry

Copy the version that fits your CV format. Everything here describes what you actually built in
this lab — no enterprise or production experience is claimed.

---

## Standard entry

**SentinelOps — Windows Threat Detection & Incident Response Lab**
*Personal SOC project · Wazuh, Sysmon, Windows Event Logs, MITRE ATT&CK*

- Built a self-contained SOC monitoring lab on virtualised infrastructure, deploying **Wazuh**
  (manager, indexer, dashboard) as the SIEM/XDR and instrumenting a Windows 11 endpoint with
  **Sysmon** and PowerShell script-block logging for high-fidelity endpoint telemetry.
- Engineered **30 custom Wazuh detection rules** across five attack scenarios (brute force,
  suspicious PowerShell, backdoor account creation, host reconnaissance, privilege escalation),
  using correlation (frequency/timeframe/same-field) and mapping every detection to **MITRE
  ATT&CK** techniques.
- Validated detections end to end with safe, self-authored PowerShell simulation scripts, then
  triaged and documented the resulting alerts as **five full incident reports** following a
  structured investigation workflow (triage → validate → investigate → contain → document).
- Designed **Wazuh dashboards** for authentication, endpoint activity, alert timeline and ATT&CK
  coverage, and wrote **five SOC analyst playbooks** plus installation, detection-engineering
  and incident-response documentation.
- Achieved a measured ~21 s mean time-to-detect across the five scenarios in the lab, and
  documented false positives, tuning decisions and honest detection-coverage gaps.

---

## Compact entry (3 bullets, for a one-page CV)

**SentinelOps — Windows Threat Detection & Incident Response Lab** · Wazuh · Sysmon · MITRE ATT&CK

- Deployed a Wazuh SIEM lab monitoring a Sysmon-instrumented Windows endpoint, and wrote **30
  custom detection rules** across five attack scenarios, each mapped to MITRE ATT&CK.
- Simulated attacks safely, then **triaged and documented five incident reports** using a
  structured SOC investigation and incident-response workflow.
- Built authentication, endpoint and ATT&CK **dashboards** and authored five analyst playbooks
  and full setup/detection-engineering documentation.

---

## One-line entry (skills summary or LinkedIn headline support)

> Built **SentinelOps**, a Wazuh + Sysmon SOC lab with 30 MITRE-mapped detection rules, five
> documented incident investigations, dashboards and analyst playbooks.

---

## Skills this project evidences (for a skills section)

`Wazuh` · `SIEM` · `Sysmon` · `Windows Event Logs` · `Log Analysis` · `Detection Engineering` ·
`Alert Triage` · `Incident Investigation` · `Incident Response` · `MITRE ATT&CK` ·
`Threat Detection` · `PowerShell` · `Security Documentation`

---

## Honesty checklist (before you paste this into your CV)

- [ ] I actually built the lab and ran the simulations — I can demo it or walk through it.
- [ ] I can explain **every** rule, event ID and MITRE technique I list here.
- [ ] The GitHub link works and the screenshots are populated.
- [ ] I described a **lab**, not production/enterprise experience.
- [ ] I can answer the interview questions in [`interview-questions.md`](interview-questions.md).

> The strongest version of this entry is the one you can defend in detail. If you cannot yet
> explain a bullet in an interview, either learn it or remove it.
