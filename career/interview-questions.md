# SOC Interview Preparation — 15 Questions on SentinelOps

Fifteen questions an interviewer could ask about this project. Each has an **ideal answer** you
should be able to give in your own words, and a note on **why the interviewer asks it**. Answer
from what you actually built — the strength of a project portfolio is that every answer is
backed by something you can show.

---

### 1. What is a SIEM, and what does it do?

**Ideal answer.** A SIEM (Security Information and Event Management) platform centrally
collects logs and events from across an environment, normalises and correlates them, applies
detection rules to raise alerts, and presents the results to analysts through search and
dashboards. It gives a SOC a single place to detect, investigate and report on security
activity. In SentinelOps I used **Wazuh** as the SIEM: the Wazuh agent forwards Windows and
Sysmon events to the manager, which decodes them, matches them against rules, enriches them with
MITRE ATT&CK, and stores them in the indexer for the analyst to view on the dashboard.

**Why they ask.** It is the foundational concept of the role. They want to know you understand
the collect → normalise → correlate → alert → investigate pipeline, not just a tool name.

---

### 2. Why did you choose Wazuh?

**Ideal answer.** Wazuh is free and open source, and it combines log collection, a rule-based
correlation engine, agent management, file-integrity monitoring and dashboards in one platform,
with native MITRE ATT&CK mapping. That let me practise the whole SOC workflow without licensing
cost, and it is used by real small-organisation SOCs, so the skills transfer. It also exposes
its detection logic as editable XML rules, which is exactly what I wanted for learning detection
engineering — I could read, write and test rules directly.

**Why they ask.** To hear that you made a reasoned tool choice and understand trade-offs, rather
than picking the first thing you found. Bonus points for naming what Wazuh does *not* give you
(no built-in network IDS, single-node in my lab).

---

### 3. Why use Sysmon when Windows already logs process creation (Event ID 4688)?

**Ideal answer.** Native 4688 tells you a process started and its parent's name, but Sysmon
Event ID 1 adds the full command line, the parent's command line, the SHA256 hash, the integrity
level, and a unique ProcessGuid that links related events. Sysmon also gives network connections
(EID 3), file creation (EID 11), DNS queries (EID 22) and LSASS access (EID 10), which native
auditing does not. In my lab this was the difference between "powershell.exe ran" and "cmd.exe
spawned powershell.exe with an encoded command that then connected out" — the context that makes
a detection actionable. I did enable command-line auditing for 4688 as well, as a fallback in
case Sysmon is tampered with.

**Why they ask.** Sysmon knowledge is a strong signal of hands-on endpoint detection experience.
They also want to see you understand *defence in depth* between the two sources.

---

### 4. What is Windows Event ID 4625, and how is it different from 4624?

**Ideal answer.** 4625 is "an account failed to log on"; 4624 is "an account was successfully
logged on". The key fields in both are the target user name, the source network address, and the
logon type (3 = network/SMB, 10 = RDP, 2 = interactive). In 4625 the sub-status code tells you
*why* it failed: `0xC000006A` means the account exists but the password was wrong, while
`0xC0000064` means the user name does not exist. That distinction matters — all wrong-password
failures against one account is targeted guessing, whereas many unknown-user failures is
enumeration or spraying. In my brute-force detection, a burst of 4625 from one IP raises the
alert, and a 4624 from that same IP afterwards is what escalates it to High, because it means the
guessing may have succeeded.

**Why they ask.** 4625 is *the* SOC L1 event. Knowing the sub-status codes and the failed →
successful pivot shows real triage ability, not memorisation.

---

### 5. Walk me through how you would investigate a brute-force alert.

**Ideal answer.** First I triage: how many failures, over what time, from which source IP,
against which account, what logon type and sub-status. Then the decisive question — did any
attempt succeed? I search for a 4624 from that source IP and account across the burst window and
the following 30 minutes. If there is no success and the source is known, it is likely a tuning
case or a stale credential. If there is no success but the source is unknown, I block it and
treat it as a contained low/medium incident. If there **is** a success, I escalate: I take the
logon ID from the 4624 and pivot to everything that session did — process creation, account
changes, file access — and check for follow-on activity like new accounts or scheduled tasks. I
document the timeline in UTC with evidence throughout. That is exactly the flow in my
INC-2026-001 report.

**Why they ask.** This is a day-one L1 task. They want a structured, repeatable method that ends
in a clear decision, and they are listening for "did it succeed?" as the pivot.

---

### 6. What is MITRE ATT&CK and how did you use it in this project?

**Ideal answer.** MITRE ATT&CK is a public knowledge base of real-world adversary tactics
(the *why* — e.g. Credential Access) and techniques (the *how* — e.g. T1110 Brute Force). It
gives detection engineers, analysts and reports a common language. In SentinelOps every one of
my 30 detection rules carries a verified ATT&CK technique ID in a `<mitre>` block, so alerts are
automatically mapped in Wazuh's ATT&CK view. I also built a coverage matrix showing which of the
14 tactics my detections address — nine of them — and, importantly, which they do not, because
one workstation cannot observe things like exfiltration or lateral movement across hosts.

**Why they ask.** ATT&CK fluency is expected in modern SOCs. Naming your *coverage gaps* honestly
is a senior-sounding answer that stands out.

---

### 7. What is alert triage, and how do you prioritise?

**Ideal answer.** Triage is the rapid first assessment of an alert to decide whether it needs
work now, later, or not at all — ideally in under two minutes. I prioritise on severity and
asset value: in my lab I map Wazuh levels to bands (12+ High = immediately, 8–11 Medium = within
an hour, 4–7 Low = within the shift, 0–3 informational = context only) and raise priority when
multiple alerts fire on one host in a short window, because that clustering is one of the
strongest early signals of a real intrusion. I also check whether the alert is a duplicate or a
known, documented tuning case before spending time on it.

**Why they ask.** SOCs run on alert volume. They need to know you can separate signal from noise
quickly and consistently, not investigate everything equally.

---

### 8. What makes an alert a false positive, and how do you handle one?

**Ideal answer.** A false positive is when the rule fired correctly but the underlying activity
is legitimate — for example, encoded PowerShell launched by a management agent, or failed logons
from a user whose saved password expired. It is *not* "an alert I do not understand" — unclear
alerts get investigated, not closed. When I confirm a false positive I identify the exact
benign source and tune **narrowly** — excluding a specific parent process and script path, never
a whole category like "all PowerShell from admins". I implement the exclusion as a level-0 child
rule so the parent detection stays intact, and I document what was excluded, why, who approved it,
and a review date. Undocumented tuning is how detections silently die.

**Why they ask.** False-positive handling is most of the job. They want discipline: narrow
tuning, documentation, and the maturity not to just suppress alerts you find annoying.

---

### 9. How would you investigate a suspicious PowerShell alert?

**Ideal answer.** I read the command line first; if it is Base64 (`-enc`) I decode it offline,
which is safe because decoding is not executing. Then I get the authoritative version from Event
ID 4104 script-block logging, which shows the de-obfuscated code even when the command line was
encoded — that is why I enabled it. I build the process tree from the ProcessGuid to see the
parent: explorer.exe means a user action, winword.exe means phishing, a service means possible
lateral movement. I check for a network connection (Sysmon EID 3), DNS query (EID 22) and any
dropped file (EID 11) from the same process, and I check whether downloaded content was actually
executed (an IEX of the result) versus just fetched. Then persistence, then ask the user. That is
my INC-2026-002 investigation.

**Why they ask.** PowerShell abuse is one of the most common real alerts. They want to see you
know script-block logging exists and that process ancestry drives the verdict.

---

### 10. You have confirmed a real incident. What do you do next?

**Ideal answer.** I move from analysis into the response process. First contain without
destroying evidence: isolate the host, disable (not delete) affected accounts, block the source,
and capture evidence first — logs exported, files hashed, a VM snapshot taken. Then I escalate
with a complete handover: what fired, what I verified, the UTC timeline, the evidence locations,
the IOCs, and the actions I have already taken. Eradication and recovery follow — remove
persistence, reset all credentials that touched the host, and if an attacker reached SYSTEM the
honest recommendation is rebuild, because you cannot prove a host clean after that. Finally, a
lessons-learned step that produces at least one concrete improvement: a tuned rule, a new
detection, or a hardening change.

**Why they ask.** They are checking you know the L1 boundary — contain and escalate cleanly —
and that you preserve evidence rather than rushing to "fix" it.

---

### 11. Why do you correlate events instead of alerting on single ones?

**Ideal answer.** Single events are usually ambiguous. One failed logon is a typo; one `whoami`
is an admin. Correlation turns weak signals into strong ones. My rules use frequency and
timeframe (e.g. 8 failures in 120 seconds), `same_field` to require they share a source IP so I
do not merge two unrelated users, `different_field` to require variety (many usernames = spraying,
many distinct binaries = recon), and `if_matched_sid` to link across event types — for example,
an account created and then added to Administrators within five minutes fires a High alert that
neither event would raise alone. Correlation is also what keeps the alert queue readable: I can
keep the noisy base events at informational level and only alert on the meaningful pattern.

**Why they ask.** Correlation is the core of detection engineering. It separates someone who can
write a `contains` filter from someone who can build a detection.

---

### 12. How did you set your detection thresholds — for example, 8 failed logons in 120 seconds?

**Ideal answer.** From measurement, not from a blog. I ran the lab for 48 hours of normal use
with no simulation and baselined it: the highest legitimate failed-logon burst was three in two
minutes (a user with an expired password), and normal use never produced more than two distinct
discovery binaries in a minute. So I set brute force to eight in 120 seconds and the recon burst
to five distinct binaries in 60 seconds — comfortably above the observed maximum but low enough
to catch a real attacker. I also documented the weakness: a fixed 120-second window is evaded by
a slow attacker, so a longer, lower-severity companion rule is on my backlog.

**Why they ask.** Thresholds separate copied rules from engineered ones. Baselining plus naming
the limitation is exactly the reasoning they want.

---

### 13. What is the difference between Event ID 4720 and 4732, and why did you correlate them?

**Ideal answer.** 4720 is a local user account being created; 4732 is a member being added to a
security-enabled local group. A field trap worth knowing: in 4732 the `TargetUserName` field is
the *group*, and the account added is in `MemberName` — the opposite of 4720. I correlated them
because creation alone might be routine IT provisioning, but a brand-new account being promoted
to Administrators within five minutes is the classic backdoor-admin pattern, so my rule 100121
raises that combination to High. In my INC-2026-003 report the correlation is what made the
intent undeniable, and pivoting on the creator's logon ID showed the account was created from a
*remote* session — which was the real root cause.

**Why they ask.** Precise event-ID knowledge plus the correlation reasoning shows genuine
hands-on work. The 4732 field trap is something only someone who actually wrote the rule knows.

---

### 14. What are living-off-the-land binaries (LOLBins), and how do you detect their misuse?

**Ideal answer.** LOLBins are legitimate, signed Windows tools that attackers abuse so their
activity blends in and is not flagged as malware — for example `certutil.exe` to download files,
`bitsadmin.exe` to transfer, `mshta.exe` or `regsvr32.exe` to execute remote scripts,
`rundll32.exe` to run code. The detection challenge is that these tools have legitimate uses, so
alerting on the binary name alone is a false-positive factory. My rule 100132 pairs the binary
with the specific dangerous argument — `certutil` **and** `-urlcache`, `regsvr32` **and**
`/i:http` — which has no benign explanation on a workstation. I map these to T1218 System Binary
Proxy Execution and corroborate with Sysmon network and file events.

**Why they ask.** LOLBin awareness is a modern-threat indicator. Pairing binary with argument
shows you understand precision in detection, not just keyword matching.

---

### 15. What are the limitations of your lab, and what would you add next?

**Ideal answer.** I am deliberately honest about scope. The lab is one Windows workstation, one
Wazuh node and an attack simulator — so it demonstrates endpoint telemetry, detection
engineering, triage, investigation and documentation, but it does **not** cover Active Directory
attacks, network IDS/NDR, email security, EDR response actions, or lateral movement across
hosts, because a single endpoint cannot observe them. My thresholds are tuned to an idle
workstation and would need re-baselining elsewhere. Next I would add a domain controller to
practise AD detections like Kerberoasting, a second endpoint to detect lateral movement (my
Sysmon config already collects the named-pipe and SMB telemetry for it), a network sensor such as
Suricata, and Wazuh Active Response for automated containment. I would also add a correlation
rule linking privilege escalation to subsequent persistence.

**Why they ask.** This is the maturity question. Candidates who oversell get caught; naming your
limits and a concrete roadmap signals honesty and genuine understanding — which is what gets a
junior hired.

---

## How to use this document

- Practise **out loud** — reading is not the same as answering under pressure.
- For every answer, be ready to **show the artefact** in the repo (the rule, the incident report,
  the dashboard). "Let me show you" is the strongest possible interview move.
- If asked something you did not implement, say so and describe how you *would* — never bluff a
  technique or a MITRE ID.
- Re-read your own `local_rules.xml`, the five detection docs, and the MITRE mapping before the
  interview. The questions above are drawn straight from them.
