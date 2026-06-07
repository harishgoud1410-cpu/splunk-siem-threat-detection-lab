# MITRE ATT&CK Framework Mapping

This document maps each detection use case in this project to the MITRE ATT&CK Enterprise framework.

## Tactic: Credential Access

### T1110 — Brute Force
- **Detection:** Use Case 1 — Brute Force / Password Spray
- **Event IDs:** 4625 (Failed Logon)
- **Sub-techniques detected:**
  - T1110.001 — Password Guessing
  - T1110.003 — Password Spraying
- **Indicator:** High-volume EventID 4625 from same source IP within short time window
- **SPL File:** `detections/UC1_brute_force.spl`

## Tactic: Persistence

### T1136 — Create Account
- **Detection:** Use Case 3 — Unauthorized Local Administrator Account Creation
- **Event IDs:** 4720 (Account Created) + 4732 (Added to Group)
- **Sub-technique:** T1136.001 — Local Account
- **Indicator:** Account creation followed by admin group assignment within 5 minutes
- **SPL File:** `detections/UC3_new_admin_account.spl`

### T1053 — Scheduled Task/Job
- **Detection:** Use Case 4 — Scheduled Task Persistence
- **Event IDs:** 4698 (Task Created) + Sysmon EID 1 (schtasks.exe process)
- **Sub-technique:** T1053.005 — Scheduled Task
- **Indicator:** schtasks.exe executing with /create + /onstart + SYSTEM privileges
- **SPL File:** `detections/UC4_scheduled_task_persistence.spl`

## Tactic: Privilege Escalation

### T1098 — Account Manipulation
- **Detection:** Use Case 3 — Unauthorized Local Administrator Account Creation
- **Event IDs:** 4732 (Member Added to Security-Enabled Local Group)
- **Indicator:** New account added to Administrators group
- **SPL File:** `detections/UC3_new_admin_account.spl`

## Summary Table

| Tactic | Technique ID | Technique Name | Use Case | Key Event IDs |
|---|---|---|---|---|
| Credential Access | T1110 | Brute Force | UC1 | 4625 |
| Credential Access | T1110.003 | Password Spraying | UC1, UC2 | 4625, 4740 |
| Persistence | T1136 | Create Account | UC3 | 4720 |
| Persistence | T1136.001 | Local Account | UC3 | 4720, 4732 |
| Persistence | T1053.005 | Scheduled Task | UC4 | 4698, Sysmon EID 1 |
| Privilege Escalation | T1098 | Account Manipulation | UC3 | 4732 |

## References

- [MITRE ATT&CK Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
- [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)
- [T1136 — Create Account](https://attack.mitre.org/techniques/T1136/)
- [T1053 — Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/)
- [T1098 — Account Manipulation](https://attack.mitre.org/techniques/T1098/)
