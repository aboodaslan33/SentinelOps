# SOC Analyst Playbooks

Short, operational playbooks for the five detection scenarios in SentinelOps. Each one is
designed to be read **during** an alert, not before it — one page, seven fixed sections, no
theory.

| Playbook | Trigger rules | Severity |
|---|---|---|
| [PB-01 — Brute Force](playbook-01-brute-force.md) | `100100`, `100101`, `100102`, `100103`, `100104` | Medium → High |
| [PB-02 — Suspicious PowerShell](playbook-02-powershell.md) | `100110`–`100115` | Medium → High |
| [PB-03 — New Account Creation](playbook-03-account-creation.md) | `100120`–`100123`, `100140` | Medium → High |
| [PB-04 — Suspicious Process](playbook-04-suspicious-process.md) | `100130`–`100134` | Medium → High |
| [PB-05 — Privilege Escalation](playbook-05-privilege-escalation.md) | `100140`–`100145`, `100151` | High |

**Every playbook has the same seven sections:** Detection · Initial Triage · Investigation ·
Evidence · Containment · Escalation · Closure.

**Standing rules that apply to all five**

1. All timestamps in **UTC**.
2. **Disable, never delete** — accounts, tasks and services are evidence.
3. Capture evidence **before** you change anything you are not forced to change.
4. If you are unsure whether to escalate, **escalate**. Over-escalation costs minutes;
   under-escalation costs the environment.
5. Every closed alert leaves behind one of: a tuned rule, a new detection, or a hardening
   recommendation.
