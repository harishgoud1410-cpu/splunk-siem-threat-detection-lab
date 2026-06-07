# Lab Setup Guide

Step-by-step instructions to replicate this SIEM lab environment from scratch.

## Prerequisites

| Item | Requirement |
|---|---|
| Host machine RAM | 16 GB minimum (8 GB for VMs) |
| Virtualization | VirtualBox or VMware |
| Linux VM | Ubuntu 22.04 LTS |
| Windows VM | Windows 10 |
| Splunk Enterprise | Free trial (splunk.com) |
| Sysmon | Microsoft Sysinternals |

---

## Step 1 — Install Splunk Enterprise on Linux

```bash
# Download from splunk.com (free 60-day trial, 500MB/day limit)
wget -O splunk.deb 'https://download.splunk.com/products/splunk/releases/9.x.x/linux/splunk-9.x.x-linux-2.6-amd64.deb'

sudo dpkg -i splunk.deb
sudo /opt/splunk/bin/splunk start --accept-license
sudo /opt/splunk/bin/splunk enable boot-start

# Access Splunk Web UI at: http://<linux-ip>:8000
```

**In Splunk Web UI:**
1. Settings → Indexes → Create New Index → Name: `windows_logs`
2. Settings → Data Inputs → TCP → Add New → Port: `9997`

---

## Step 2 — Install Sysmon on Windows VM

```powershell
# Download Sysmon from Microsoft Sysinternals
# Download SwiftOnSecurity config
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "C:\sysmonconfig.xml"

# Install with config
.\Sysmon64.exe -accepteula -i C:\sysmonconfig.xml

# Verify
Get-Service Sysmon64
```

---

## Step 3 — Install Universal Forwarder on Windows VM

1. Download from splunk.com → Products → Universal Forwarder (Windows 64-bit)
2. Run installer, set admin credentials
3. Copy `configs/inputs.conf` to: `C:\Program Files\SplunkUniversalForwarder\etc\system\local\`
4. Copy `configs/outputs.conf` to the same directory, replacing `<SPLUNK_LINUX_IP>` with your Linux IP
5. Restart forwarder:

```powershell
& "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe" restart
```

---

## Step 4 — Verify Data Flow

In Splunk Search & Reporting, run:

```spl
index=windows_logs | stats count by sourcetype
```

You should see these sourcetypes:
- `WinEventLog:Security`
- `WinEventLog:System`
- `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

---

## Step 5 — Run Attack Simulations

On the Windows VM, open PowerShell as Administrator and run:

```powershell
.\attack-simulations\lab_attack_simulations.ps1
```

Follow the on-screen menu to trigger each detection use case.

---

## Step 6 — Load Detection Queries

Copy each `.spl` file from the `detections/` folder into Splunk Search & Reporting, run, and save as alerts.
