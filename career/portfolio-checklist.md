# SentinelOps — Portfolio Ready

The complete checklist to work through before adding SentinelOps to your CV. Tick each box only
when it is genuinely true — a portfolio's value is that everything in it is real and defensible.

---

## A. Lab is built and working

- [ ] Wazuh manager, indexer and dashboard installed and reachable at `https://<manager-ip>`
- [ ] Default `admin` password changed and stored **only** in a password manager (not in git)
- [ ] Windows endpoint VM built with a static lab IP on a host-only network
- [ ] Wazuh agent installed and showing **Active** in the dashboard
- [ ] Windows audit policy applied (`auditpol` — Logon, Account/Group Mgmt, Process Creation, etc.)
- [ ] Command-line auditing enabled for Event ID 4688
- [ ] PowerShell script-block logging enabled (Event ID 4104 confirmed working)
- [ ] Sysmon installed with this repo's config; `Sysmon64.exe -c` shows it active
- [ ] Agent collecting Security, System, Application, Sysmon and PowerShell channels
- [ ] End-to-end smoke test passes: a failed-logon burst produces rule `100101` on the dashboard

## B. Detections deployed and validated

- [ ] `local_rules.xml` deployed to `/var/ossec/etc/rules/` and the manager restarted cleanly
- [ ] `wazuh-logtest -t` passes with no rule-loading errors
- [ ] All five simulation scripts run successfully (see `/scripts/README.md`)
- [ ] Each of the five scenarios produced its expected alert(s):
  - [ ] SO-DET-001 brute force → `100101`
  - [ ] SO-DET-002 PowerShell → `100111` / `100113`
  - [ ] SO-DET-003 account creation → `100120` / `100121`
  - [ ] SO-DET-004 suspicious process → `100131` / `100134`
  - [ ] SO-DET-005 privilege escalation → `100140` / `100143`
- [ ] MITRE ATT&CK view in Wazuh shows the detected techniques

## C. Dashboards built

- [ ] Overview dashboard (metrics, timeline, top rules) populated with data
- [ ] Authentication dashboard (failed/successful, top source IPs, targeted accounts)
- [ ] Endpoint Activity dashboard (process ancestry, PowerShell, accounts)
- [ ] MITRE ATT&CK dashboard or the built-in matrix
- [ ] At least three saved searches created for investigation

## D. Documentation complete

- [ ] `README.md` reads well and every section is filled in
- [ ] Architecture diagram present and accurate to your build
- [ ] Five detection-rule documents match your deployed rules
- [ ] Five incident reports completed with your lab's real timestamps
- [ ] Five playbooks reviewed
- [ ] Installation, detection-engineering, investigation and incident-response docs read through
- [ ] MITRE mapping table verified against attack.mitre.org

## E. Screenshots captured (see `/screenshots/README.md`)

- [ ] 01 Wazuh dashboard overview
- [ ] 02 Connected Windows agent (Active)
- [ ] 03 Sysmon logs arriving
- [ ] 04 Brute-force alert
- [ ] 05 PowerShell alert (with 4104 script block visible)
- [ ] 06 Account-creation alert
- [ ] 07 Suspicious-process alert
- [ ] 08 MITRE ATT&CK mapping
- [ ] 09 Incident investigation view
- [ ] 10 Final populated dashboard
- [ ] All screenshots redacted (no real users, public IPs, passwords, personal info)

## F. Security and hygiene (before pushing to GitHub)

- [ ] No passwords, API keys, tokens or certificates committed (`git log -p | grep -iE "password|secret|token"`)
- [ ] No `wazuh-install-files.tar`, `.evtx` exports or raw alert JSON committed
- [ ] `.gitignore` in place and effective
- [ ] Repository is public (so recruiters can see it) **and** contains nothing sensitive
- [ ] LICENSE present
- [ ] The lab disclaimer is clear in the README

## G. Career materials

- [ ] CV entry adapted from `career/cv-entry.md` (and every bullet is defensible)
- [ ] LinkedIn project description added from `career/linkedin.md`
- [ ] Repository pinned on your GitHub profile
- [ ] You can answer all 15 questions in `career/interview-questions.md` out loud
- [ ] You can give a 3-minute live walkthrough of the lab

## H. Final self-test

- [ ] I can explain every rule, event ID and MITRE technique in this repo in my own words
- [ ] I can reproduce any of the five incidents on demand
- [ ] I have described this honestly as a **laboratory** project, claiming no production experience
- [ ] I would be comfortable screen-sharing this repo during an interview

---

**When every box is ticked, SentinelOps is portfolio ready.** Add it to your CV, pin it on
GitHub, and be ready to walk an interviewer through it — that walkthrough is where a lab project
turns into a job offer.
