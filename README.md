# 🔵 Splunk SIEM Threat Detection Lab

> **Blue Team | SOC Analyst | Detection Engineering**  
> A hands-on home lab simulating a real-world Security Operations Center (SOC) environment — built to demonstrate practical threat detection, log analysis, and SIEM operations skills.

---

## 📌 Project Summary

This project deploys a full SIEM pipeline from endpoint telemetry collection to centralized detection and alerting. It mirrors the workflows a SOC Analyst performs daily: ingesting logs, writing detection rules, simulating attacks, and investigating alerts.

| Component | Role |
|---|---|
| Windows 10 VM | Endpoint — attack simulation target |
| Sysmon (SwiftOnSecurity config) | Advanced endpoint telemetry |
| Splunk Universal Forwarder | Log shipping agent |
| Splunk Enterprise (Linux) | Centralized SIEM platform |

---

## 🏗️ Lab Architecture

```
┌─────────────────────────────────┐         TCP :9997        ┌─────────────────────────────────┐
│         Windows 10 VM           │ ─────────────────────▶  │       Linux (Ubuntu)            │
│                                 │                          │                                 │
│  ┌──────────────────────────┐   │                          │  ┌──────────────────────────┐   │
│  │  Sysmon (EID 1,3,11,13)  │   │                          │  │   Splunk Enterprise       │   │
│  │  Process, Network, File  │   │                          │  │   Indexer + Search Head   │   │
│  └──────────┬───────────────┘   │                          │  └──────────┬────────────────┘   │
│             │                   │                          │             │                   │
│  ┌──────────▼───────────────┐   │                          │  ┌──────────▼────────────────┐   │
│  │  Windows Security Logs   │   │                          │  │   SPL Detection Queries   │   │
│  │  EventIDs: 4624,4625,    │   │                          │  │   Dashboards + Alerts     │   │
│  │  4720,4732,4740,4698     │   │                          │  └───────────────────────────┘   │
│  └──────────┬───────────────┘   │                          └─────────────────────────────────┘
│             │                   │
│  ┌──────────▼───────────────┐   │
│  │ Universal Forwarder       │   │
│  │ inputs.conf + outputs.conf│   │
│  └───────────────────────────┘   │
└─────────────────────────────────┘
```

---

## 🎯 Detection Use Cases

All detections are mapped to the [MITRE ATT&CK Framework](https://attack.mitre.org/).

| # | Detection | Event Source | MITRE Technique | Severity |
|---|---|---|---|---|
| 1 | [Brute Force / Password Spray](#uc1) | EventID 4625 | T1110 | 🔴 High |
| 2 | [Account Lockout Spike](#uc2) | EventID 4740 | T1110.003 | 🔴 High |
| 3 | [Unauthorized Admin Account Creation](#uc3) | EventID 4720 + 4732 | T1136 + T1098 | 🔴 Critical |
| 4 | [Scheduled Task Persistence](#uc4) | EventID 4698, Sysmon EID 1 | T1053.005 | 🟠 High |

---

## 📂 Repository Structure

```
splunk-siem-lab/
│
├── README.md                          ← This file
│
├── detections/                        ← SPL detection queries (one per use case)
│   ├── UC1_brute_force.spl
│   ├── UC2_account_lockout_spike.spl
│   ├── UC3_new_admin_account.spl
│   └── UC4_scheduled_task_persistence.spl
│
├── attack-simulations/                ← Safe PowerShell simulation scripts
│   ├── sim_brute_force.ps1
│   ├── sim_account_lockout.ps1
│   ├── sim_create_admin_account.ps1
│   └── sim_scheduled_task.ps1
│
├── configs/                           ← Splunk forwarder configuration files
│   ├── inputs.conf
│   └── outputs.conf
│
├── dashboards/                        ← Splunk dashboard XML
│   └── soc_overview_dashboard.xml
│
└── docs/                              ← Documentation and screenshots
    ├── lab-setup-guide.md
    ├── mitre-attack-mapping.md
    └── screenshots/
        ├── uc1_brute_force/
        ├── uc2_lockout_spike/
        ├── uc3_admin_creation/
        └── uc4_scheduled_task/
```

---

<a name="uc1"></a>
## 🔍 Detection Use Case 1 — Brute Force / Password Spray

**Objective:** Detect repeated authentication failures indicating automated credential attacks.

**Security Relevance:** Brute force and password spraying are among the top initial access techniques used by threat actors. Early detection prevents account compromise.

**Event Source:** Windows Security Log — EventID 4625 (Failed Logon)

**Attack Simulation:**
```powershell
for ($i = 1; $i -le 10; $i++) {
    net use \\127.0.0.1\IPC$ /user:Administrator WrongPass$i 2>$null
}
```

**SPL Detection Query:**
```spl
index=* EventCode=4625
| stats count by Account_Name, Source_Network_Address
| sort - count
```

**MITRE ATT&CK:** [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)

**Investigation Findings:**
- Multiple EventID 4625 entries from same source IP
- High-frequency failures against Administrator account
- Short time window between attempts — indicates automation

---

<a name="uc2"></a>
## 🔍 Detection Use Case 2 — Account Lockout Spike

**Objective:** Detect abnormal spikes in account lockout activity caused by automated credential attacks.

**Security Relevance:** Account lockouts triggered in rapid succession across multiple accounts strongly indicate a password spray campaign in progress.

**Event Source:** Windows Security Log — EventID 4740 (Account Locked Out)

**Attack Simulation:**
```powershell
# Trigger multiple lockouts by exceeding threshold
for ($i = 1; $i -le 6; $i++) {
    net use \\127.0.0.1\IPC$ /user:testuser BadPassword 2>$null
}
```

**SPL Detection Query:**
```spl
index=* EventCode=4740
| stats count by Target_Account
| sort - count
```

**MITRE ATT&CK:** [T1110.003 — Password Spraying](https://attack.mitre.org/techniques/T1110/003/)

**Investigation Findings:**
- Multiple accounts locked within condensed timeframe
- High-frequency lockout events correlated with 4625 activity
- Evidence consistent with automated password spraying

---

<a name="uc3"></a>
## 🔍 Detection Use Case 3 — Unauthorized Local Administrator Account Creation

**Objective:** Detect creation of privileged local accounts indicating persistence or privilege escalation.

**Security Relevance:** Creating a backdoor admin account is a standard post-exploitation persistence technique. Detecting the 4720+4732 event sequence in close succession is a near-certain indicator of malicious intent.

**Event Source:** Windows Security Log  
- EventID 4720 — User Account Created  
- EventID 4732 — User Added to Local Group

**Attack Simulation:**
```powershell
net user backdoor P@ssw0rd123! /add
net localgroup Administrators backdoor /add
```

**SPL Detection Query:**
```spl
index=* (EventCode=4720 OR EventCode=4732)
| eval event_type=case(EventCode=4720,"account_created",EventCode=4732,"added_to_group")
| stats values(event_type) AS events, min(_time) AS first, max(_time) AS last BY Account_Name
| where mvcount(events) >= 2 AND (last - first) <= 300
| eval severity="CRITICAL", mitre="T1136.001 + T1098"
```

**MITRE ATT&CK:**  
- [T1136 — Create Account](https://attack.mitre.org/techniques/T1136/)  
- [T1098 — Account Manipulation](https://attack.mitre.org/techniques/T1098/)

**Investigation Findings:**
- New account provisioned and immediately added to Administrators group
- Time correlation between 4720 and 4732 confirmed deliberate escalation sequence
- Username did not match any legitimate IT provisioning pattern

---

<a name="uc4"></a>
## 🔍 Detection Use Case 4 — Scheduled Task Persistence

**Objective:** Detect scheduled task creation used as a persistence mechanism after initial compromise.

**Security Relevance:** Scheduled tasks are one of the most abused persistence mechanisms. Detecting `schtasks.exe` with suspicious parameters — especially `/onstart`, `/SYSTEM`, or payloads pointing to temp paths — is a strong post-exploitation indicator.

**Event Source:**  
- Windows Security Log — EventID 4698 (Scheduled Task Created)  
- Sysmon EventID 1 (Process Creation — schtasks.exe)

**Attack Simulation:**
```powershell
schtasks /create /tn "WindowsUpdateHelper" /tr "C:\Windows\System32\cmd.exe /c whoami > C:\temp\out.txt" /sc onstart /ru SYSTEM
```

**SPL Detection Query:**
```spl
index=* schtasks
```
```spl
index=* EventCode=4698
```

**MITRE ATT&CK:** [T1053.005 — Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)

**Investigation Findings:**
- `schtasks.exe` process creation captured in Sysmon EID 1
- Task named `WindowsUpdateHelper` — deliberate masquerading
- Task configured to run as SYSTEM on startup — high-privilege persistence
- EventID 4698 confirmed task registration in Windows Security log

---

## ⚙️ Configuration Files

### inputs.conf (Universal Forwarder — Windows VM)
```ini
[WinEventLog://Security]
index = windows_logs
disabled = false

[WinEventLog://System]
index = windows_logs
disabled = false

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
index = windows_logs
disabled = false
renderXml = true
```

### outputs.conf (Universal Forwarder — Windows VM)
```ini
[tcpout]
defaultGroup = splunk_indexer

[tcpout:splunk_indexer]
server = <SPLUNK_LINUX_IP>:9997
```

---

## 🛠️ Technical Skills Demonstrated

**SIEM & Detection Engineering**
- Splunk Enterprise administration and index management
- SPL query development for threat detection
- Correlation search logic and alert engineering
- Log normalization and field extraction

**Windows Security Monitoring**
- Windows Event Log analysis (Security, System channels)
- Sysmon telemetry configuration and investigation
- Authentication event monitoring (4624, 4625, 4740)
- Administrative activity analysis (4720, 4732, 4698)

**SOC Operations**
- Security event triage and investigation
- MITRE ATT&CK framework mapping
- Attack simulation and detection validation
- Incident investigation workflow documentation

---

## 🔗 References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [Splunk SPL Documentation](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference)
- [Windows Security Event IDs Reference](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)

---

## 👤 Author

**Harish Goud**  
Cybersecurity Enthusiast — SOC Operations | SIEM Monitoring | Threat Detection | Blue Team

[![GitHub](https://img.shields.io/badge/GitHub-harishgoud1410--cpu-181717?style=flat&logo=github)](https://github.com/harishgoud1410-cpu)

---

> ⚠️ **Disclaimer:** This project was developed in a controlled lab environment for educational and cybersecurity training purposes only. All attack simulations were performed on isolated virtual machines with no connection to production systems.
