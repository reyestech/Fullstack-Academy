# 🛠️ Win‑Troubleshoot PowerShell Toolkit

Modern cyber‑defence is equal parts **speed**, **visibility**, and **automation**. This repository delivers ready‑to‑run PowerShell utilities that give any Security Operations Center (SOC) or Windows administrator instant leverage: collect evidence in seconds, surface anomalies on‑demand, and kick‑off trusted remediation workflows — all without installing a single third‑party dependency.

Whether you’re a **junior analyst** looking to practise blue‑team fundamentals, or a **seasoned responder** who needs lightweight tools during an incident bridge call, these scripts have you covered. Each file is heavily commented, parameter‑driven, and production‑safe so you can copy‑paste with confidence.

---

## 🗂️ Table of Contents

1. [Quick Start Guide](#-quick-start-guide)
2. [Script Catalogue](#-script-catalogue)

   * [Collect‑EventLogs.ps1](#1️⃣-collect-eventlogsps1)
   * [Run‑SFCandDISM.ps1](#2️⃣-run-sfcanddismps1)
   * [Get‑ActiveConnections.ps1](#3️⃣-get-activeconnectionsps1)
   * [Get‑SystemHealthSnapshot.ps1](#4️⃣-get-systemhealthsnapshotps1)
   * [Detect‑BruteForceLogons.ps1](#5️⃣-detect-bruteforcelogonsps1)
   * [Get‑ListeningPorts.ps1](#6️⃣-get-listeningportsps1)
   * [Audit‑LocalAdminMembers.ps1](#7️⃣-audit-localadminmembersps1)
   * [Invoke‑WindowsDefenderScan.ps1](#8️⃣-invoke-windowsdefenderscanps1)
   * [Test‑NetworkConnectivity.ps1](#9️⃣-test-networkconnectivityps1)
   * [Export‑WindowsFirewallRules.ps1](#🔟-export-windowsfirewallrulesps1)
3. [Conclusion](#-conclusion)

---

## 🚀 Quick‑Start Guide

1. **Clone the repository** – Fetches the toolkit to your workstation so you can inspect or modify the scripts locally.

   ```powershell
   git clone https://github.com/<you>/win‑troubleshoot‑powershell.git
   cd win‑troubleshoot‑powershell\Scripts
   ```
2. **Unblock local execution** – Windows protects you from running unsigned code. Setting the policy **only for your user** keeps the OS secure while allowing these scripts to run:

   ```powershell
   Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
   ```
3. **Run any helper** – Each script is self‑contained. For example, export the last 12 hours of System & Security logs to `D:\Logs`:

   ```powershell
   ./Collect-EventLogs.ps1 -HoursBack 12 -Logs 'System','Security' -OutputDir 'D:\Logs'
   ```
4. **Review the output** – Most scripts write either a table to screen or an artefact (CSV / JSON / TXT) you can attach to a ticket or drop into a SIEM pipeline.

> *Tip:* All parameters have sensible defaults; launch a script with `-Help` to see them.

---

## 📜 Script Catalogue

### 1️⃣ Collect‑EventLogs

**Purpose (detailed)**  ► When incidents strike, the first question is *“What happened, and when?”* This script automates forensic evidence collection by exporting Windows Event Logs for any time window you specify. Instead of clicking through Event Viewer and manually saving EVTX files, you receive tidy CSVs that slide straight into Excel, Log Parser, or your SIEM for timeline analysis.

**How it works**

* Accepts **`HoursBack`**, **`Logs`** (array of log names), and **`OutputDir`**.
* Creates the destination folder if it doesn’t exist.
* Uses **`Get‑WinEvent`** with a hashtable filter for efficiency (no slow `Where‑Object`).
* Selects the most actionable fields (timestamp, event ID, severity, message).
* Exports each log type to its own CSV for clean segregation.

**Usage Example**

```powershell
./Collect-EventLogs.ps1 -HoursBack 24 -Logs 'System','Application' -OutputDir 'C:\IR\Logs'
```

### Code

```powershell
param(
    [int]      $HoursBack = 24,
    [string[]] $Logs      = @('System','Application','Security'),
    [string]   $OutputDir = (Join-Path $PWD 'EventLogs')
)
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}
$start = (Get-Date).AddHours(-$HoursBack)

foreach ($log in $Logs) {
    Get-WinEvent -FilterHashtable @{ LogName = $log; StartTime = $start } |
        Select TimeCreated, Id, LevelDisplayName, Message |
        Export-Csv -NoTypeInformation -Path (Join-Path $OutputDir "$log.csv")
}
Write-Host "✔ Logs exported to $OutputDir"
```

---

### 2️⃣ Run‑SFCandDISM

**Purpose (detailed)**  ► System file corruption is a silent reliability killer. This script chains Microsoft’s two native repair tools — **System File Checker (SFC)** and **Deployment Image Servicing and Management (DISM)** — capturing their combined output into a timestamped log. Ideal for post‑compromise integrity checks or troubleshooting unexplained OS errors.

**How it works**

* Builds a log directory on‑the‑fly to preserve historical runs.
* Executes `sfc /scannow` to repair active system files.
* Follows up with `DISM /RestoreHealth` to patch the underlying Windows image.
* Pipes all console output through **`Tee‑Object`** so you see progress live *and* keep a text record.

**Usage Example**

```powershell
./Run-SFCandDISM.ps1 -LogDir 'D:\HealthChecks'
```


### Code

```powershell
param([string]$LogDir = (Join-Path $PWD 'HealthChecks'))
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir | Out-Null
}
$log = Join-Path $LogDir ("HealthCheck_{0:yyyyMMdd_HHmm}.txt" -f (Get-Date))

"=== SFC ==="  | Tee-Object $log
sfc /scannow   | Tee-Object $log -Append
"=== DISM ===" | Tee-Object $log -Append
DISM /Online /Cleanup-Image /RestoreHealth | Tee-Object $log -Append

Write-Host "✔ Repair complete – see $log"
```

---

### 3️⃣ Get‑ActiveConnections

**Purpose (detailed)**  ► Malware loves to hide in plain sight by piggy‑backing on legitimate processes. This script surfaces every established outbound TCP session — tagging each with process name and the user that launched it — so analysts can swiftly spot unauthorised beacons or data exfiltration channels.

**How it works**

* Queries `Get‑NetTCPConnection` for **`State = Established`**.
* Resolves Process ID to friendly names using `Get‑Process`.
* Retrieves the owning username via CIM’s `Win32_Process.GetOwner()`.
* Outputs an alphabetised table ready for copy‑paste into a report or pasted into Grid View.

**Usage Example**

```powershell
./Get-ActiveConnections.ps1 | Out-GridView
```


### Code

```powershell
Get-NetTCPConnection -State Established | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    $user = (Get-CimInstance Win32_Process -Filter "ProcessId=$($_.OwningProcess)").GetOwner().User
    [pscustomobject]@{
        Local   = "$($_.LocalAddress):$($_.LocalPort)"
        Remote  = "$($_.RemoteAddress):$($_.RemotePort)"
        State   = $_.State
        Process = $proc.ProcessName
        User    = $user
    }
} | Sort Remote | Format-Table -AutoSize
```

---

### 4️⃣ Get‑SystemHealthSnapshot

**Purpose (detailed)**  ► Before you troubleshoot, you need a baseline. This script captures **real‑time CPU load**, **memory usage**, **free disk space**, and **pending Windows Update count** — all in one shot. Run it at ticket open and close to prove your remediation impact.

**How it works**

* Samples CPU with `Get‑Counter '\Processor(_Total)\% Processor Time'` (three 1‑second polls averaged).
* Pulls memory stats from `Win32_OperatingSystem`, converting KB to GB for human readability.
* Enumerates drives via `Get‑PSDrive -PSProvider FileSystem`, rounding free space.
* If the **PSWindowsUpdate** module exists, `Get‑WindowsUpdate` counts pending patches; otherwise, it skips silently.
* Outputs everything as a tidy formatted list — perfect for screenshots or copy‑paste into an incident timeline.

**Usage Example**

```powershell
./Get-SystemHealthSnapshot.ps1 | Tee-Object '.\health-before.txt'
```

*(Run it again after fixes and `Compare-Object` the two logs to quantify improvement.)*

---

### Code

```powershell
$cpu = (Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 1 -MaxSamples 3).CounterSamples.CookedValue |
        Measure-Object -Average | Select-Object -ExpandProperty Average
$mem = Get-CimInstance Win32_OperatingSystem
$disk = Get-PSDrive -PSProvider FileSystem | Select Name,@{n='Free(GB)';e={[math]::Round($_.Free/1GB,1)}}

[pscustomobject]@{
    Timestamp       = Get-Date
    CPU_Load_Percent= [math]::Round($cpu,1)
    RAM_Used_GB     = [math]::Round(($mem.TotalVisibleMemorySize-$mem.FreePhysicalMemory)/1MB,2)
    Pending_Updates = (Get-WindowsUpdate -MicrosoftUpdate -IgnoreReboot -ErrorAction SilentlyContinue).Count
    Disk_Free       = ($disk | Out-String).Trim()
} | Format-List
```
---

### 5️⃣ Detect‑BruteForceLogons

**Purpose (detailed)**  ► A burst of failed logon attempts is a classic pre‑attack signal. This script scans Security Event ID 4625 for the last *N* hours, aggregates by **Source IP & Account**, and flags any entity exceeding a threshold you define. Perfect for feeding an alert into Sentinel, Splunk, or emailing your blue‑team.

**How it works**

* Queries the Security log via `Get‑WinEvent` using a precise hashtable filter (fast!).
* Pulls **Source Network Address** and **Account Name** via lightweight regex.
* Groups results and filters where attempts ≥ `Threshold`.
* Exports a CSV so you can pivot or join against threat‑intel feeds.

**Usage Example**

```powershell
./Detect-BruteForceLogons.ps1 -HoursBack 12 -Threshold 15 -Report '.\bruteforce.csv'
```
### Code

```powershell
param(
  [int]$HoursBack = 24,
  [int]$Threshold = 10,
  [string]$Report = (Join-Path $PWD 'BruteForceReport.csv')
)
$start = (Get-Date).AddHours(-$HoursBack)
$events = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4625; StartTime=$start }

$patternIP      = '(?<=Source Network Address:\s+)(\d{1,3}(?:\.\d{1,3}){3})'
$patternAccount = '(?<=Account Name:\s+)(\S+)'

$data = $events | ForEach-Object {
    $ip  = [regex]::Match($_.Message, $patternIP).Value
    $acc = [regex]::Match($_.Message, $patternAccount).Value
    if ($ip) { [pscustomobject]@{ IP=$ip; Account=$acc } }
} | Group-Object IP,Account | Where-Object Count -ge $Threshold |
    Select-Object @{n='IP';       e={$_.Name.Split(',')[0]}},
                  @{n='Account';  e={$_.Name.Split(',')[1]}},
                  @{n='Attempts'; e={$_.Count}}

$data | Export-Csv -NoTypeInformation -Path $Report
Write-Host "✔ Report written to $Report"
```

---

### 6️⃣ Get‑ListeningPorts

**Purpose (detailed)**  ► Knowing what’s *listening* is as important as knowing what’s *talking*. This utility enumerates every TCP & UDP port in LISTEN state, maps each to its owning process, and prints the executable path — a rapid way to spot shadow IT or malware‑spawned services.

**How it works**

* Combines `Get‑NetTCPConnection -State Listen` and `Get‑NetUDPEndpoint` results.
* Resolves `OwningProcess` to process name & binary path via `Get‑Process`.
* Outputs a sortable table you can ship to CSV or Grid View.

**Usage Example**

```powershell
./Get-ListeningPorts.ps1 | Export-Csv '.\listening.csv' -NoTypeInformation
```
### Code

```powershell
$tcp = Get-NetTCPConnection -State Listen
$udp = Get-NetUDPEndpoint
($tcp + $udp) | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    [pscustomobject]@{
        Protocol = $_.GetType().Name -replace 'Net','' -replace 'Endpoint',''
        Local    = "$($_.LocalAddress):$($_.LocalPort)"
        PID      = $_.OwningProcess
        Process  = $proc.ProcessName
        Path     = $proc.Path
    }
} | Sort-Object Local | Format-Table -AutoSize
```

---

### 7️⃣ Audit‑LocalAdminMembers.ps1

**Purpose (detailed)**  ► Local admin sprawl is a lateral‑movement dream. This script enumerates the local **Administrators** group, tags default versus non‑default accounts, and highlights any surprises so you can tighten privilege boundaries before attackers exploit them.

**How it works**

* Calls `Get‑LocalGroupMember -Group 'Administrators'` (Windows 10/11 & Server 2016+).
* Compares against a hard‑coded safe list (`Administrator`, `Domain Admins`, etc.).
* Prints a flag (⚠ Review) next to unknown members.

**Usage Example**

```powershell
./Audit-LocalAdminMembers.ps1 | Out-File '.\admin-audit.txt'
```

### Code

```powershell
$default = 'Administrator','Domain Admins','SYSTEM','Administrators'
Get-LocalGroupMember -Group 'Administrators' | ForEach-Object {
    [pscustomobject]@{
        Member = $_.Name
        Type   = $_.ObjectClass
        Note   = if ($default -contains $_.Name) { 'Default' } else { '⚠ Review' }
    }
} | Format-Table -AutoSize
```

---

### 8️⃣ Invoke‑WindowsDefenderScan.ps1

**Purpose (detailed)**  ► During incident response you often need an immediate antivirus sweep without clicking through the GUI. This wrapper launches a **Quick** or **Full** Microsoft Defender scan, waits for completion, and echoes any findings so you can escalate or close out confidently.

**How it works**

* Starts the scan with `Start‑MpScan`.
* Polls `Get‑MpComputerStatus` until scan flags clear.
* Pulls threat objects from `Get‑MpThreat` and prints a table if any are found.

**Usage Example**

```powershell
./Invoke-WindowsDefenderScan.ps1 -ScanType Full
```

### Code

```powershell
param([ValidateSet('Quick','Full')][string]$ScanType='Quick')
Start-MpScan -ScanType $ScanType
Write-Host "Scanning ($ScanType)…"
while ((Get-MpComputerStatus).PerformingQuickScan -or (Get-MpComputerStatus).PerformingFullScan) {
    Start-Sleep 5
}
$threats = Get-MpThreat
if ($threats) {
    $threats | Format-Table
} else {
    Write-Host "✔ No threats detected."
}
```

---

### 9️⃣ Test‑NetworkConnectivity

**Purpose (detailed)**  ► Is it the host? The network? Or the destination? This script parallel‑tests reachability to critical hosts (gateway, DNS, SaaS endpoints) by combining **ping latency** and **traceroute hop‑count** — giving you at‑a‑glance health before you escalate to NetOps.

**How it works**

* Reads targets from `-Targets` parameter or `targets.txt` if present.
* Uses `Test‑Connection` for fast latency sampling.
* Falls back to `Test‑NetConnection -TraceRoute` when ping fails, capturing hop length.
* Outputs a mini‑dashboard table (Reachable ✔ / ✖, Avg RTT, Hops).

**Usage Example**

```powershell
./Test-NetworkConnectivity.ps1 -Targets '8.8.8.8','1.1.1.1','microsoft.com'
```
### Code

```powershell
param([string[]]$Targets = (Test-Path './targets.txt') ? (Get-Content './targets.txt') : @('8.8.8.8'))
$results = foreach ($t in $Targets) {
    if (Test-Connection -Quiet -Count 4 -ComputerName $t) {
        $avg = (Test-Connection -Count 4 $t | Measure-Object -Property ResponseTime -Average).Average
        [pscustomobject]@{ Target=$t; Reachable=$true; AvgRTT_ms=[math]::Round($avg,1); Hops='—' }
    } else {
        $hops = (Test-NetConnection $t -TraceRoute).TraceRoute.Length
        [pscustomobject]@{ Target=$t; Reachable=$false; AvgRTT_ms='—'; Hops=$hops }
    }
}
$results | Format-Table -AutoSize
```

---

### 🔟 Export‑WindowsFirewallRules.ps1

**Purpose (detailed)**  ► Firewalls drift over time. This exporter converts every Windows Firewall rule to structured JSON, making it easy to diff between baselines, ingest into Git, or share with auditors. Use it before and after policy changes to prove least‑privilege adherence.

**How it works**

* Loops through `Get‑NetFirewallRule`, enriching with port filters via `Get‑NetFirewallPortFilter`.
* Builds a PSCustomObject with key rule properties (Name, Direction, Action, Profile, Program, Ports).
* Serialises the array to prettified JSON (UTF‑8) for cross‑platform parsing.

**Usage Example**

```powershell
./Export-WindowsFirewallRules.ps1 -OutFile '.\firewall-backup.json'
```
### Code

```powershell
param([string]$OutFile = (Join-Path $PWD 'FirewallRules.json'))

$rules = Get-NetFirewallRule | ForEach-Object {
    $port = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $_ -ErrorAction SilentlyContinue
    [pscustomobject]@{
        Name      = $_.Name
        Direction = $_.Direction
        Action    = $_.Action
        Profile   = $_.Profile
        Enabled   = $_.Enabled
        Program   = $_.ApplicationName
        Service   = $_.ServiceName
        Protocol  = $port.Protocol
        LocalPort = $port.LocalPort
        RemotePort= $port.RemotePort
    }
}

$rules | ConvertTo-Json -Depth 4 | Out-File -FilePath $OutFile -Encoding utf8
Write-Host "✔ Firewall rules exported to $OutFile"
```

---

## 🔚 Conclusion

This toolkit is designed to showcase **practical PowerShell expertise** — the same skills you’ll leverage when integrating with enterprise SIEMs like Microsoft Sentinel or Splunk. Recruiters: each script is deliberately lightweight, heavily documented, and demonstrates **automation mindset** — a core competency for modern Cybersecurity Analysts. Engineers: clone, fork, or open a PR; security is a team sport!

> **Next Steps:** Star ⭐ the repo if you find it useful, or raise an issue if you’d like new features. Happy hunting — and automate *all* the things! 

> **Next Steps:** Star ⭐ the repo if you find it useful, or raise an issue if you’d like new features. Happy hunting — and automate *all* the things! 🔍

Happy hunting 🔍 — feel free to open an issue or request with new scripts!

<img src="https://i.imgur.com/1C8iiWB.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

