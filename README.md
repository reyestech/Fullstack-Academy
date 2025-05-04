# 🛠️ Win‑Troubleshoot PowerShell Toolkit

Modern cyber‑defence is equal parts **speed**, **visibility**, and **automation**. This repository delivers ready‑to‑run PowerShell utilities that give any Security Operations Center (SOC) or Windows administrator instant leverage: collect evidence in seconds, surface anomalies on‑demand, and kick‑off trusted remediation workflows — all without installing a single third‑party dependency.

Whether you’re a **junior analyst** looking to practise blue‑team fundamentals, or a **seasoned responder** who needs lightweight tools during an incident bridge call, these scripts have you covered. Each file is heavily commented, parameter‑driven, and production‑safe so you can copy‑paste with confidence.

---

<details>
  <summary>🗂️ <strong>Table of Contents</strong></summary>

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

</details>

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

### 1️⃣ Collect‑EventLogs.ps1

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

---

### 2️⃣ Run‑SFCandDISM.ps1

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

---

### 3️⃣ Get‑ActiveConnections.ps1

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

---

### 4️⃣ Get‑SystemHealthSnapshot.ps1

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

### 5️⃣ Detect‑BruteForceLogons.ps1 Detect‑BruteForceLogons.ps1

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

---

### 6️⃣ Get‑ListeningPorts.ps1

**Purpose (detailed)**  ► Knowing what’s *listening* is as important as knowing what’s *talking*. This utility enumerates every TCP & UDP port in LISTEN state, maps each to its owning process, and prints the executable path — a rapid way to spot shadow IT or malware‑spawned services.

**How it works**

* Combines `Get‑NetTCPConnection -State Listen` and `Get‑NetUDPEndpoint` results.
* Resolves `OwningProcess` to process name & binary path via `Get‑Process`.
* Outputs a sortable table you can ship to CSV or Grid View.

**Usage Example**

```powershell
./Get-ListeningPorts.ps1 | Export-Csv '.\listening.csv' -NoTypeInformation
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

---

### 9️⃣ Test‑NetworkConnectivity.ps1

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

---

## 🔚 Conclusion

This toolkit is designed to showcase **practical PowerShell expertise** — the same skills you’ll leverage when integrating with enterprise SIEMs like Microsoft Sentinel or Splunk. Recruiters: each script is deliberately lightweight, heavily documented, and demonstrates **automation mindset** — a core competency for modern Cybersecurity Analysts. Engineers: clone, fork, or open a PR; security is a team sport!

> **Next Steps:** Star ⭐ the repo if you find it useful, or raise an issue if you’d like new features. Happy hunting — and automate *all* the things! 🔍 Conclusion
> This toolkit is designed to showcase **practical PowerShell expertise** — the same skills you’ll leverage when integrating with enterprise SIEMs like Microsoft Sentinel or Splunk. Recruiters: each script is deliberately lightweight, heavily documented, and demonstrates **automation mindset** — a core competency for modern Cybersecurity Analysts. Engineers: clone, fork, or open a PR; security is a team sport!

> **Next Steps:** Star ⭐ the repo if you find it useful, or raise an issue if you’d like new features. Happy hunting — and automate *all* the things! 🔍











<img src="https://i.imgur.com/1C8iiWB.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

