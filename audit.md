# SentinelOps — Coverage Audit

Pessimistic comparison of the 16-phase project specification against what actually exists on
disk. "Present" means the file exists; it does **not** mean the content has been executed,
tested or verified.

> ## The single most important finding
>
> **The lab has never been built and nothing in this repository has been run.** No Wazuh
> manager, no agent, no Sysmon, no events, no alerts, no dashboards, no screenshots. Therefore:
>
> - Every detection rule is **unproven** (see `tests/run-logtest.sh` — not yet executed).
> - Every incident report is a **template**, not a record of an event that happened.
> - Every metric (MTTD, baseline counts) is **unmeasured**.
> - The Sysmon config, dashboards and scripts have **never run on a real host**.
>
> The repository is an honest, well-structured **blueprint + templates + validation harness**.
> It is *not* evidence that any detection works. Do not present it as such until
> `run-logtest.sh` passes on a live manager and real screenshots exist.

---

## Phase-by-phase

| # | Phase | Files present | Status | Gaps / thin / stubbed |
|---|-------|---------------|--------|-----------------------|
| 1 | Project structure | Full tree (`README`, `LICENSE`, `.gitignore`, all folders) | **Present** | Layout deviates from the spec: adds `career/`, `playbooks/`, `tests/` (improvements, but not the exact spec tree). No functional gap. |
| 2 | Lab setup | `documentation/installation.md` | **Present, unexecuted** | Step-by-step only. Never followed end to end; version-specific commands (Wazuh assistant, agent MSI URL, Sysmon schema) unverified against a real install. |
| 3 | Sysmon | `sysmon/sysmon-config.xml`, `sysmon/README.md` | **Present, unvalidated** | `schemaversion="4.90"` may not match the installed Sysmon build; config has never been loaded with `Sysmon64.exe -c`. Noise/tuning claims unmeasured. |
| 4 | Detection scenarios (≥5) | 5 docs in `detection-rules/` + `local_rules.xml` (30 rules) | **Present, UNPROVEN** | No rule has fired once. 19 rules now carry `NEEDS-LOGTEST-VERIFICATION`. Regex engine mismatch was a real bug (now: PCRE2 fields declared `type="pcre2"`; backslash count still unverified). |
| 5 | Detection engineering | `documentation/detection-engineering.md` | **Present** | Methodology is sound. Baseline table was fabricated as "recorded" — now marked NOT YET MEASURED. Thresholds are first-draft assumptions. |
| 6 | Dashboard | `documentation/dashboard.md` | **Present, thinnest as evidence** | Build *instructions* only. No dashboard exists, no saved-objects `.ndjson` exported, no screenshots. Cannot be shown working. |
| 7 | Investigation workflow | `documentation/investigation-process.md` | **Present** | Solid and generic. Not exercised against a real alert. |
| 8 | Incident reports (5) | `incidents/incident-001..005`, `incidents/README.md` | **Present as TEMPLATES** | Converted this pass from fabricated "captured" data to explicitly-marked templates with placeholders. No real evidence in any of them. |
| 9 | Playbooks (5) | `playbooks/playbook-01..05`, `playbooks/README.md` | **Present** | Good operational structure. Untested in practice. |
| 10 | MITRE ATT&CK | `documentation/mitre-attack-mapping.md` + `<mitre>` in rules | **Present, verify IDs** | Technique IDs look correct but were not re-checked against attack.mitre.org this pass. Wazuh will reject any ID missing from its bundled DB at load — untested. Coverage gaps are stated honestly. |
| 11 | Automation | 6 `scripts/*.ps1` + `scripts/README.md` | **Present, unrun** | Brace/paren balance checked only. **No PowerShell interpreter available here** — never parsed by `pwsh`, never executed. Behaviour unverified. |
| 12 | README | `README.md` | **Present** | Good. Had 1 fabricated "measured over 48h" claim — softened this pass. Screenshot links point to files that do not exist yet. |
| 13 | Screenshots | `screenshots/README.md` only | **Stubbed** | **Zero images.** Capture guide exists; not a single PNG. README image links are dead until captured. |
| 14 | CV entry | `career/cv-entry.md` | **Present** | Fabricated "~21 s measured MTTD" bullet removed this pass and replaced with a do-not-claim-unmeasured note. |
| 15 | LinkedIn | `career/linkedin.md` | **Present** | Reasonable and non-exaggerated. |
| 16 | Interview prep | `career/interview-questions.md` | **Present, 1 flag** | Q12/others model answers in the first person ("I ran the lab for 48 hours…"). Accurate only *after* the lab is built — currently aspirational. Left as guidance; flagged here. |

---

## Cross-cutting findings (most to least severe)

1. **Nothing executed.** No component has run. The whole repo is blueprint + templates until
   `tests/run-logtest.sh` passes on a live manager and screenshots exist. (Severity: highest —
   it is the difference between "I built and validated" and "I designed".)
2. **Detections unproven and partly engine-risky.** 19/30 rules are `NEEDS-LOGTEST-VERIFICATION`.
   The PCRE2-vs-OS_Regex mismatch that would have stopped `(?i)` rules from matching is fixed
   (fields now declare `type="pcre2"`), but the decoded-path backslash count is still unverified.
3. **No screenshots at all** (Phase 13). This is the most visible gap on a portfolio page and
   the easiest for a reviewer to notice.
4. **No dashboard artefacts** (Phase 6). Instructions only; nothing exported or captured.
5. **Scripts never parsed by PowerShell** (Phase 11). Syntax-balanced only; real execution,
   parameter validation and cleanup logic are unverified.
6. **MITRE IDs not re-verified** against the live ATT&CK source or a Wazuh load this pass.
7. **Interview answers assert lab experience** that does not yet exist (Phase 16, Q12).

## What this pass changed

- Incident reports 001–005 + `incidents/README.md`: fabricated captured data → explicit
  templates (banners, `<PLACEHOLDER>` tokens, "EXPECTED EVIDENCE (not yet captured)" sections,
  metrics → `<NOT YET MEASURED>`).
- `detection-engineering.md`, `README.md`, `incident-response.md`, `career/cv-entry.md`:
  fabricated "measured" figures neutralised.
- `detection-rules/local_rules.xml`: `type="pcre2"` added to all 21 `(?i)` fields; a
  per-rule `REGEX AUDIT` comment added to all 30 rules; header engine note added.
- Added `tests/logtest/` (30 sample events + `expected_results.md`) and `tests/run-logtest.sh`
  as the harness that must prove the rules on a live manager.

## Definition of done (not yet met)

- [ ] `tests/run-logtest.sh` prints PASS for all 30 rules on a live manager.
- [ ] 10 real, redacted screenshots exist in `screenshots/`.
- [ ] Dashboards built and exported (`.ndjson`) or screenshotted.
- [ ] Sysmon config loaded (`Sysmon64.exe -c`) on a real endpoint.
- [ ] Scripts run once each in the lab and confirmed to self-clean.
- [ ] Baseline actually measured; thresholds confirmed or retuned.
- [ ] MITRE IDs confirmed loaded (no manager startup errors).
