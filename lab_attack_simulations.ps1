# =============================================================
# SPLUNK SIEM LAB - Attack Simulation Scripts
# Author: Harish Goud
# Purpose: Safe, non-destructive attack simulations for home lab
# Environment: Windows 10 VM (ISOLATED - no production use)
# =============================================================

# ⚠️ WARNING: Run ONLY on isolated lab VMs
# ⚠️ Never run on production or corporate systems

Write-Host "=== SPLUNK SIEM LAB - Attack Simulation Menu ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "[1] Simulate Brute Force Attack (EventID 4625)"
Write-Host "[2] Simulate Account Lockout Spike (EventID 4740)"
Write-Host "[3] Simulate New Admin Account Creation (EventID 4720 + 4732)"
Write-Host "[4] Simulate Scheduled Task Persistence (EventID 4698 + Sysmon EID 1)"
Write-Host "[5] Run ALL simulations"
Write-Host "[C] Cleanup - Remove all test artifacts"
Write-Host ""

# =============================================================
# SIMULATION 1 - Brute Force / Password Spray
# Generates: EventID 4625 (Failed Logon)
# MITRE: T1110
# =============================================================
function Invoke-BruteForceSimulation {
    Write-Host "`n[*] Starting Brute Force Simulation..." -ForegroundColor Yellow
    Write-Host "[*] Target: Local Administrator account"
    Write-Host "[*] This generates EventID 4625 entries in Security log`n"

    for ($i = 1; $i -le 10; $i++) {
        net use \\127.0.0.1\IPC$ /user:Administrator "WrongPassword$i" 2>$null
        Write-Host "[+] Attempt $i/10 sent - failed login logged" -ForegroundColor Green
        Start-Sleep -Milliseconds 500
    }

    Write-Host "`n[✓] Brute force simulation complete" -ForegroundColor Cyan
    Write-Host "[!] Check Splunk: index=* EventCode=4625"
    Write-Host "[!] Verify in Event Viewer: Windows Logs > Security > Filter 4625`n"
}

# =============================================================
# SIMULATION 2 - Account Lockout Spike  
# Generates: EventID 4740 (Account Locked Out)
# MITRE: T1110.003
# =============================================================
function Invoke-AccountLockoutSimulation {
    Write-Host "`n[*] Starting Account Lockout Simulation..." -ForegroundColor Yellow
    Write-Host "[*] First creating test user accounts..."

    # Create test accounts for simulation
    $testUsers = @("labtest_user1", "labtest_user2", "labtest_user3")
    
    foreach ($user in $testUsers) {
        net user $user "InitialPass123!" /add 2>$null
        Write-Host "[+] Created test user: $user"
    }

    # Set low lockout threshold for demo
    net accounts /lockoutthreshold:5 /lockoutduration:1 2>$null
    Write-Host "[*] Set lockout threshold to 5 attempts"

    Write-Host "`n[*] Now triggering lockouts with bad passwords..."
    foreach ($user in $testUsers) {
        for ($i = 1; $i -le 6; $i++) {
            net use \\127.0.0.1\IPC$ /user:$user "BadPassword$i" 2>$null
        }
        Write-Host "[+] Lockout triggered for: $user" -ForegroundColor Green
        Start-Sleep -Milliseconds 300
    }

    Write-Host "`n[✓] Account lockout simulation complete" -ForegroundColor Cyan
    Write-Host "[!] Check Splunk: index=* EventCode=4740"
    Write-Host "[!] Verify in Event Viewer: Windows Logs > Security > Filter 4740`n"
}

# =============================================================
# SIMULATION 3 - Unauthorized Admin Account Creation
# Generates: EventID 4720 (Account Created) + 4732 (Added to Group)
# MITRE: T1136 + T1098
# =============================================================
function Invoke-AdminAccountSimulation {
    Write-Host "`n[*] Starting Admin Account Creation Simulation..." -ForegroundColor Yellow
    Write-Host "[*] Creating backdoor account and adding to Administrators..."
    Write-Host "[*] This mimics post-exploitation persistence technique`n"

    # Create the backdoor account
    net user backdoor_lab "P@ssw0rd123!" /add 2>$null
    Write-Host "[+] EventID 4720 generated - new account: backdoor_lab" -ForegroundColor Green
    Start-Sleep -Seconds 1

    # Add to Administrators group
    net localgroup Administrators backdoor_lab /add 2>$null
    Write-Host "[+] EventID 4732 generated - added to Administrators group" -ForegroundColor Green

    Write-Host "`n[✓] Admin account simulation complete" -ForegroundColor Cyan
    Write-Host "[!] Check Splunk: index=* (EventCode=4720 OR EventCode=4732)"
    Write-Host "[!] Verify in Event Viewer: Windows Logs > Security > Filter 4720 and 4732"
    Write-Host "[!] NOTE: Run cleanup function after testing`n"
}

# =============================================================
# SIMULATION 4 - Scheduled Task Persistence
# Generates: EventID 4698 (Task Created) + Sysmon EID 1 (schtasks.exe)
# MITRE: T1053.005
# =============================================================
function Invoke-ScheduledTaskSimulation {
    Write-Host "`n[*] Starting Scheduled Task Persistence Simulation..." -ForegroundColor Yellow
    Write-Host "[*] Creating a task named 'WindowsUpdateHelper' to mimic attacker masquerading"
    Write-Host "[*] Payload: harmless 'whoami' command redirected to C:\temp`n"

    # Create temp directory
    if (-not (Test-Path "C:\temp")) {
        New-Item -ItemType Directory -Path "C:\temp" | Out-Null
        Write-Host "[+] Created C:\temp directory"
    }

    # Create the scheduled task (non-destructive)
    schtasks /create /tn "WindowsUpdateHelper" `
             /tr "C:\Windows\System32\cmd.exe /c whoami > C:\temp\siem_lab_output.txt" `
             /sc onstart `
             /ru SYSTEM `
             /f 2>$null

    Write-Host "[+] Sysmon EID 1 generated - schtasks.exe process creation captured" -ForegroundColor Green
    Write-Host "[+] EventID 4698 generated - scheduled task registered" -ForegroundColor Green

    # Verify it was created
    $taskCheck = schtasks /query /tn "WindowsUpdateHelper" 2>$null
    if ($taskCheck) {
        Write-Host "[✓] Task 'WindowsUpdateHelper' confirmed in task scheduler" -ForegroundColor Cyan
    }

    Write-Host "`n[✓] Scheduled task simulation complete" -ForegroundColor Cyan
    Write-Host "[!] Check Splunk: index=* schtasks"
    Write-Host "[!] Check Splunk: index=* EventCode=4698"
    Write-Host "[!] Check Sysmon: Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 5"
    Write-Host "[!] NOTE: Run cleanup function after testing`n"
}

# =============================================================
# CLEANUP - Remove all test artifacts
# =============================================================
function Invoke-LabCleanup {
    Write-Host "`n[*] Starting lab cleanup..." -ForegroundColor Yellow

    # Remove test users
    $usersToRemove = @("labtest_user1", "labtest_user2", "labtest_user3", "backdoor_lab")
    foreach ($user in $usersToRemove) {
        net user $user /delete 2>$null
        Write-Host "[+] Removed user: $user"
    }

    # Remove scheduled task
    schtasks /delete /tn "WindowsUpdateHelper" /f 2>$null
    Write-Host "[+] Removed scheduled task: WindowsUpdateHelper"

    # Remove temp output file
    if (Test-Path "C:\temp\siem_lab_output.txt") {
        Remove-Item "C:\temp\siem_lab_output.txt" -Force
        Write-Host "[+] Removed C:\temp\siem_lab_output.txt"
    }

    # Reset lockout policy to default
    net accounts /lockoutthreshold:0 2>$null
    Write-Host "[+] Reset lockout threshold to default"

    Write-Host "`n[✓] Lab cleanup complete - all test artifacts removed`n" -ForegroundColor Cyan
}

# =============================================================
# MENU EXECUTION
# =============================================================
$choice = Read-Host "Enter your choice"

switch ($choice) {
    "1" { Invoke-BruteForceSimulation }
    "2" { Invoke-AccountLockoutSimulation }
    "3" { Invoke-AdminAccountSimulation }
    "4" { Invoke-ScheduledTaskSimulation }
    "5" {
        Invoke-BruteForceSimulation
        Start-Sleep -Seconds 2
        Invoke-AccountLockoutSimulation
        Start-Sleep -Seconds 2
        Invoke-AdminAccountSimulation
        Start-Sleep -Seconds 2
        Invoke-ScheduledTaskSimulation
        Write-Host "`n[✓] All simulations complete! Check Splunk for detections." -ForegroundColor Cyan
        Write-Host "[!] Remember to run cleanup: Press C and enter" -ForegroundColor Yellow
    }
    "C" { Invoke-LabCleanup }
    default { Write-Host "Invalid choice. Run script again." -ForegroundColor Red }
}
