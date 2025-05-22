
----

----


----
1
----

# Azure‑Sentinel‑KQL‑Hunting‑&‑Detection‑Toolkit

![Sentinel Banner](https://raw.githubusercontent.com/reyestech/assets/main/sentinel_kql_toolkit_banner.png)

## Overview

Proactive cloud defence hinges on **fast analytics**, **threat visibility**, and **reusable detection logic**. This repository curates a **suite of 12 production‑ready Kusto Query Language (KQL) searches** designed for **Microsoft Sentinel** and **Azure Monitor Logs**. With these queries you can:

* 🔍 **Surface critical security events** in seconds across petabytes of log data.
* 🛡️ **Detect sophisticated attacker tradecraft** and anomalous behaviour before impact.
* ⚡ **Accelerate hunt-to-automation workflows**, transforming ad‑hoc insight into always‑on analytics rules.

Whether you’re a SOC analyst building your first hunt workbook, a Cloud Security Engineer codifying blue‑team knowledge, or a recruiter scanning GitHub for real‑world Sentinel skills, this toolkit showcases **production‑safe KQL craftsmanship**.

> Use the copy icon next to each fenced KQL block (`📋`) to paste directly into Log Analytics or the Sentinel rule wizard.

---

<details>
<summary><strong>📚 Table of Contents — click to expand</strong></summary>

* [Quick‑Start](#quick‑start)
* [Query‑Catalogue](#query‑catalogue)

  1. [Failed Sign‑In Surge](#1️⃣-failed-sign‑in-surge)
  2. [Impossible Travel](#2️⃣-impossible-travel)
  3. [Privilege Escalation Alert](#3️⃣-privilege-escalation-alert)
  4. [New External App Registration](#4️⃣-new-external-app-registration)
  5. [Rare Process Creation on Server](#5️⃣-rare-process-creation-on-server)
  6. [High‑Volume Data Exfil](#6️⃣-high‑volume-data-exfil)
  7. [DNS Tunnelling Detection](#7️⃣-dns-tunnelling-detection)
  8. [Suspicious PowerShell Usage](#8️⃣-suspicious-powershell-usage)
  9. [Azure Resource Deletion Spike](#9️⃣-azure-resource-deletion-spike)
  10. [Multiple MFA Denials](#🔟-multiple-mfa-denials)
  11. [Rare Service‑Principal Usage](#1️⃣1️⃣-rare-service‑principal-usage)
  12. [Unusual VM Guest Login Geo](#1️⃣2️⃣-unusual-vm-guest-login-geo)
* [Conclusion](#conclusion)

</details>

---

## Quick‑Start

Deploying the toolkit is trivial: clone or fork the repo, open any `.kql` file in the **Log Analytics Query** blade or **Sentinel Analytics Rule Wizard**, tweak parameters such as `TimeRange` or `Whitelist` tables, then save as a **Scheduled Query Rule** or **Hunting query**. Each query is fully commented, parameter‑driven, and safe to run read‑only—no data mutation commands are used.

---

## Query‑Catalogue

### 1️⃣ Failed Sign‑In Surge

A sudden uptick in authentication failures is often a prelude to brute‑force or credential‑stuffing attacks. This KQL query baselines sign‑in error rates per user and tenant, then flags any hour where failures exceed the previous week’s maximum by a configurable factor. Analysts receive a concise list of usernames, IPs, and client apps driving the spike, enabling rapid blocking or conditional access enforcement.

By converting the logic into an analytics rule, you transform a one‑off investigation into a perpetual guardrail—ensuring future surges trigger automated playbooks such as token revocation or SOC paging.

#### How it works

* Pulls `SigninLogs` for the last 24 h and the prior 7 d baseline.
* Aggregates `resultType != 0` counts per hour.
* Uses `make_series` and `series_fir()` to derive dynamic thresholds.
* Emits rows where the latest count > baseline × `SurgeFactor` (default 3).

```kql
// Failed Sign‑In Surge
let SurgeFactor = 3;
let LookbackHours = 24;
let BaselineDays = 7;
let endTime = now();
let startTime = endTime - datetime_diff('hour', LookbackHours, 0);
let baselineStart = endTime - BaselineDays * 1d;
// Baseline series
let baseline = SigninLogs
  | where TimeGenerated between (baselineStart .. endTime)
  | where ResultType !in (0, "0")
  | summarize count() by bin(TimeGenerated, 1h)
  | summarize Baseline=max(count);
// Current window
SigninLogs
  | where TimeGenerated between (startTime .. endTime) and ResultType !in (0, "0")
  | summarize Failures=count() by bin(TimeGenerated, 1h), UserPrincipalName, IPAddress
  | join kind=inner (baseline) on $left.Failures > Baseline * SurgeFactor
  | project TimeGenerated, UserPrincipalName, IPAddress, Failures, Baseline, SurgeFactor
  | order by Failures desc
```

---

### 2️⃣ Impossible Travel

Attackers who harvest credentials often log in from geographically distant locations within impossibly short intervals. This query detects sequential sign‑ins for the same user where the calculated travel speed between source IP geolocations exceeds a safe human threshold (default 500 mph / 800 kmh). Results highlight the first and second sign‑in, plus estimated speed, so responders can confirm compromise and enforce MFA resets.

Deploying as a continuous rule dramatically reduces dwell time for account takeovers, especially in hybrid workforces accessing resources from mixed IP ranges.

#### How it works

* Uses `SigninLogs` fields `Location` → `Latitude`, `Longitude`.
* Calculates haversine distance between consecutive sign‑ins per user.
* Divides by time delta to derive mph / kmh.
* Flags if speed > `TravelThreshold`.

#### Usage Example (KQL)

```kql
// Impossible Travel Detection
let TravelThresholdKmh = 800; // ≈ 500 mph
let lookback = 1d;
SigninLogs
| where TimeGenerated > ago(lookback)
| project TimeGenerated, UserPrincipalName, IPAddress, Country = tostring(LocationDetails.countryOrRegion), Latitude, Longitude
| sort by UserPrincipalName, TimeGenerated asc
| serialize rank= row_number()
| extend PrevTime = prev(TimeGenerated), PrevLat = prev(Latitude), PrevLon = prev(Longitude), PrevCountry = prev(Country), UserPrev = prev(UserPrincipalName)
| where UserPrev == UserPrincipalName // consecutive for same user
| extend DistKm = geo_distance_2points(Latitude, Longitude, PrevLat, PrevLon)/1000.0, Hours = datetime_diff('second', TimeGenerated, PrevTime)/3600.0
| extend SpeedKmh = iff(Hours==0, 0, DistKm/Hours)
| where SpeedKmh > TravelThresholdKmh
| project UserPrincipalName, PrevCountry, Country, PrevTime, TimeGenerated, DistKm, SpeedKmh
| order by SpeedKmh desc
```

### 3️⃣ Privilege Escalation Alert

Elevations from low‑privileged roles to high‑impact ones (e.g., `Owner`, `Global Administrator`) can rapidly expand an attacker’s blast radius. This query scans `AuditLogs` for role‑assignment operations, enriches with actor IP and device details, and filters against an optional change‑window whitelist. Any escalations outside approved maintenance windows merit immediate review and, if necessary, access revocation.

Automating the logic as an hourly analytics rule produces a tamper‑proof ledger of privilege changes, lightening compliance workloads and reducing mean time to detect insider threats.

#### How it works

* Queries `AuditLogs` for `Add member to role` and `Update role assignment`.
* Joins `IdentityInfo` to map department / job title.
* `leftanti` joins against a `ChangeWindow_AllowList` table.
* Outputs timestamp, actor, target role, and source IP.

#### Usage Example (KQL)

```kql
// Privilege Escalation Alert
let ChangeWindow_AllowList = materialize(externaldata(WindowStart:datetime, WindowEnd:datetime)["https://raw.githubusercontent.com/reyestech/assets/main/change_window.csv"] with(format="csv"));
AuditLogs
| where OperationName in ("Add member to role", "Update role assignment")
| extend TargetRole = tostring(parse_json(TargetResources)[0].displayName)
| extend Actor = tostring(parse_json(InitiatedBy).user.userPrincipalName), IP = tostring(InitiatedBy.user.ipAddress)
| project TimeGenerated, Actor, IP, TargetRole, ActivityDisplayName
| join kind=leftanti (ChangeWindow_AllowList) on $left.TimeGenerated between (WindowStart .. WindowEnd)
| order by TimeGenerated desc
```

### 4️⃣ New External App Registration

Malicious OAuth consent grants and rogue multi‑tenant apps are increasingly leveraged for stealthy persistence. This query spots newly registered Azure AD applications whose `PublisherDomain` **does not** match your tenant’s verified domain, exposing risky third‑party or attacker‑controlled integrations. Each hit lists the permissions requested and the creating principal so the SOC can quickly revoke consent.

When transformed into a scheduled rule, you gain a constant watchtower against supply‑chain incursions via OAuth.

#### How it works

* Reads `AADServicePrincipalCreationLogs` for the past 24 h.
* Extracts `PublisherDomain`, `AppDisplayName`, and `RequiredResourceAccess` scopes.
* Compares domain to `TenantDomain` parameter.
* Emits non‑matching entries.

#### Usage Example (KQL)

```kql
// External App Registration Detection
let TenantDomain = "contoso.com";
AADServicePrincipalCreationLogs
| where TimeGenerated > ago(1d)
| extend PublisherDomain = tostring(ApplicationPublisherDomain)
| where PublisherDomain != TenantDomain
| mv-expand scope = RequiredResourceAccess
| project TimeGenerated, AppDisplayName, PublisherDomain, CreatedBy = tostring(CreatedBy.userPrincipalName), Permission = scope
| order by TimeGenerated desc
```

### 5️⃣ Rare Process Creation on Server

Unexpected executables running on production servers often herald post‑exploitation activity. This query baselines process launches over the last 30 days and isolates today’s executions whose frequency falls below the 1st percentile—surfacing suspicious binaries regardless of hash or signature evasion. Contextual fields such as command line, parent process, and user help analysts decide whether to quarantine or whitelist.

This behaviour‑first lens complements signature‑based defences, catching renamed or LOLBin misuse that traditional AV misses.

#### How it works

* Baselines `EventID==4688` (`Sysmon EventID==1`) by `Computer`, `ProcessName` for 30 d.
* Computes launch frequency percentile.
* Flags today’s processes below `RareThreshold` (default 1%).

#### Usage Example (KQL)

```kql
// Rare Process Creation
let RareThreshold = 1; // percentile
let baselineDays = 30d;
let todayStart = startofday(now());
let baseline = SecurityEvent
  | where TimeGenerated between (ago(baselineDays) .. todayStart)
  | where EventID == 4688
  | summarize Launches=count() by Computer, ProcessName
  | summarize pct=percentile(Launches, RareThreshold);
let today = SecurityEvent
  | where TimeGenerated > todayStart and EventID == 4688
  | project TimeGenerated, Computer, ProcessName, CommandLine, ParentProcessName, Account
  | join kind=inner (baseline) on Computer
  | where Launches < pct
  | order by TimeGenerated desc
;
today
```

### 6️⃣ High‑Volume Data Exfil

Massive outbound transfers to unfamiliar destinations can indicate data theft or misconfigured backups. This query analyses NSG flow logs (`AzureNetworkAnalytics_CL`) or firewall logs to identify public IPs receiving volumes 5× above the median for the same VM over the previous week. Outputs include byte counts, destination, and protocol—arming responders to cut egress or throttle bandwidth.

Paired with automated ticketing, the alert helps enforce data‑loss‑prevention controls across hybrid infrastructures.

#### How it works

* Summarises `BytesSent` per `PublicIP` for last 6 h.
* Retrieves 7‑day median per VM.
* Calculates delta and triggers at 500%.

#### Usage Example (KQL)

```kql
// High Volume Data Exfiltration
let LookbackHours = 6h;
let BaselineDays = 7d;
let Multiplier = 5.0;
let recent = AzureNetworkAnalytics_CL
  | where TimeGenerated > ago(LookbackHours)
  | summarize BytesSent=sum(SentBytes) by VM=VirtualMachineId_s, DestIP=RemoteIP_s;
let baseline = AzureNetworkAnalytics_CL
  | where TimeGenerated between (ago(BaselineDays) .. ago(LookbackHours))
  | summarize MedianBytes=percentile(sum(SentBytes), 50) by VM=VirtualMachineId_s;
recent
| join kind=inner baseline on VM
| extend Delta = BytesSent / MedianBytes
| where Delta > Multiplier
| project VM, DestIP, BytesSent, MedianBytes, Delta
| order by Delta desc
```

### 7️⃣ DNS Tunnelling Detection

Malware and insiders alike abuse DNS to hide command‑and‑control or exfiltration traffic. This query scrutinises DNS events for excessively long sub‑domains, high entropy (indicating encoded payloads), and large NXDOMAIN ratios—three hallmarks of tunnelling techniques. Analysts receive a prioritised list of suspect domains, supporting swift sinkholing or firewall blocks.

When converted to an analytic rule, this detection raises early flags before full compromise unfolds.

#### How it works

* Calculates length and Shannon entropy of `QueryName`.
* Counts NXDOMAIN responses per `QueryName`.
* Flags entries meeting all three heuristic thresholds.

#### Usage Example (KQL)

```kql
// DNS Tunnelling Hunt
let LengthThreshold = 50;
let EntropyThreshold = 4.0;
let NXDomainThreshold = 0.5; // 50%
DnsEvents
| where TimeGenerated > ago(6h)
| extend NameLen = strlen(QueryName), Entropy = entropy(QueryName)
| summarize TotalQueries=count(), NX=countif(ResponseCode==3) by QueryName, ClientIP
| extend NXRate = todouble(NX)/TotalQueries
| where NameLen > LengthThreshold and Entropy > EntropyThreshold and NXRate > NXDomainThreshold
| order by Entropy desc
```

### 8️⃣ Suspicious PowerShell Usage

PowerShell remains a preferred attacker toolkit due to its native reach and stealth. This query targets command‑lines containing obfuscation flags, downloaders, or AMSI bypass keywords, while excluding signed Microsoft scripts. Hits include device, user, truncated command line, and script hash, enabling containment of compromised endpoints.

Automated response can isolate or offboard hosts before payload deployment, slashing attacker dwell time.

#### How it works

* Pattern‑matches `ProcessCommandLine` for risky substrings.
* Filters out trusted signers.
* Deduplicates by hash to reduce alert noise.

#### Usage Example (KQL)

```kql
// Suspicious PowerShell Execution
let Dangerous = dynamic(["-enc", "Invoke-WebRequest", "IEX", "Bypass", "DownloadString"]);
DeviceProcessEvents
| where Timestamp > ago(12h)
| where ProcessName =~ "powershell.exe"
| where array_length(array_intersect(Dangerous, split(tolower(ProcessCommandLine),' '))) > 0
| where Signer != "Microsoft Windows"
| project Timestamp, DeviceName, AccountName, ShortCmd = substring(ProcessCommandLine, 0, 120), SHA256, FileName
| order by Timestamp desc
```

### 9️⃣ Azure Resource Deletion Spike

Mass deletions of cloud resources can stem from misfired automation or a malicious actor with stolen credentials. This query monitors `AzureActivity` for successful `Delete` operations and compares the hourly count against the highest hourly volume seen in the last 90 days. Surpassing that watermark triggers an alert, prompting teams to halt destructive scripts or initiate recovery.

Tying the alert to a Logic App can automatically lock the subscription or notify on‑call engineers via Teams, shortening reaction windows.

#### How it works

* Filters for `OperationNameValue` ending `/delete`.
* Summarises per hour by caller and resource type.
* Compares to 90‑day high; triggers on exceedance.

#### Usage Example (KQL)

```kql
// Resource Deletion Spike
let lookback = 90d;
let HourlyDeletes = AzureActivity
  | where OperationNameValue has "/delete" and ActivityStatus == "Succeeded"
  | summarize Deletes=count() by Caller, bin(TimeGenerated, 1h);
let historicalMax = HourlyDeletes
  | where TimeGenerated between (ago(lookback) .. ago(2h))
  | summarize MaxDeletes=max(Deletes);
HourlyDeletes
| where TimeGenerated > ago(2h)
| where Deletes > historicalMax
| project TimeGenerated, Caller, Deletes, historicalMax
| order by Deletes desc
```

### 🔟 Multiple MFA Denials

An influx of MFA denials within minutes usually signals password‑spray or user confusion exploited by phishing. This query tallies denial responses (result code `500121`) over a 30‑minute sliding window, grouping by user and IP. Entities exceeding five denials surface in the results, equipping identity teams to reset credentials or educate users.

Automated containment via Conditional Access policies can immediately block suspicious IPs, curbing brute‑force persistence.

#### How it works

* Looks back 30 minutes in `SigninLogs`.
* Filters for MFA required + denial code.
* Summarises denials ≥ 5 per user/IP.

#### Usage Example (KQL)

```kql
// MFA Denial Burst
let Window = 30m;
SigninLogs
| where TimeGenerated > ago(Window)
| where ResultType == 500121 and AuthenticationRequirement == "multiFactorAuthentication"
| summarize Denials=count() by UserPrincipalName, IPAddress
| where Denials >= 5
| order by Denials desc
```

### 1️⃣1️⃣ Rare Service‑Principal Usage

Service principals normally follow predictable schedules. Deviations—either sudden spikes or first‑time sign‑ins—can indicate credential leakage or automation gone awry. This query baselines 30 days of non‑interactive sign‑ins per SP and flags any that exceed the 95th percentile today. Metadata such as resource and IP enable swift investigation and scope containment.

Visualising the metric in a Workbook keeps cloud‑to‑cloud trust relationships transparent and accountable.

#### How it works

* Baselines daily sign‑ins via `AADNonInteractiveUserSignInLogs`.
* Calculates per‑SP P95 over 30 days.
* Compares today’s count to baseline.

#### Usage Example (KQL)

```kql
// Rare Service Principal Activity
let baselineDays = 30d;
let todayStart = startofday(now());
let baseline = AADNonInteractiveUserSignInLogs
  | where TimeGenerated between (ago(baselineDays) .. todayStart)
  | summarize Daily=count() by ServicePrincipalId, bin(TimeGenerated, 1d)
  | summarize P95=percentile(Daily, 95) by ServicePrincipalId;
AADNonInteractiveUserSignInLogs
| where TimeGenerated > todayStart
| summarize TodayCnt=count() by ServicePrincipalId, AppDisplayName, ResourceDisplayName
| join baseline on ServicePrincipalId
| where TodayCnt > P95
| project TimeGenerated=todayStart, AppDisplayName, ResourceDisplayName, TodayCnt, P95
| order by TodayCnt desc
```

### 1️⃣2️⃣ Unusual VM Guest Login Geo

Hands‑on‑keyboard intrusions often start with interactive logons from unexpected countries. By correlating Windows `SecurityEvent` ID 4624 and Linux `sshd` successes with GeoIP lookups, this query identifies the first time a given VM sees a login from a new country within the past 24 hours. Output includes user, IP, geo, and host, giving defenders a clear signal to investigate or geo‑lock access.

Scheduling the detection ensures any anomalous geolocation triggers near‑real‑time response, especially important for regulated environments with strict data residency requirements.

#### How it works

* Normalises login events across Windows (`4624`) and Linux (`sshd`).
* Uses `ip_to_country()` function (or custom reference table).
* Maintains historical country set per host via `make_set()`.
* Emits new country logins in the last day.

#### Usage Example (KQL)

```kql
// Unusual Geo Login to VM
let lookback = 1d;
let historicWindow = 90d;
let logins = (union
  SecurityEvent
    | where TimeGenerated > ago(historicWindow) and EventID == 4624 and LogonType == 10
    | project TimeGenerated, Computer, User = Account, IP = tostring(parse_xml(EventData).Data[18]), 
  Syslog
    | where TimeGenerated > ago(historicWindow) and ProcessName == "sshd" and SyslogMessage has "Accepted password"
    | extend parts = split(SyslogMessage, " ")
    | project TimeGenerated, Computer=HostName, User=parts[10], IP=parts[8]
);
let withGeo = logins | extend Country = ip_to_country(IP);
let historic = withGeo | summarize Countries=make_set(Country) by Computer;
let recent = withGeo | where TimeGenerated > ago(lookback);
recent
| join kind=inner historic on Computer
| where Country !in (Countries)
| project TimeGenerated, Computer, User, IP, Country
| order by TimeGenerated desc
```

Unexpected interactive logins to Windows or Linux IaaS VMs from foreign geolocations can presage hands‑on‑keyboard activity. By correlating `SecurityEvent` (Windows) and `Syslog` (Linux) logins with `GeoInfo` on source IP, this query detects first‑seen countries per VM in the last 90 days. Output includes username, country, city, and timestamp.

SOC teams can instantly quarantine VMs or enable JIT access only to sanctioned locations.

#### How it works

* Normalises login events (`EventID == 4624`, `sshd` success).
* Enriches IP with `ip_to_country()` user function or GeoLite table.
* Stores historical `make_set()` of countries per host.
* Emits new country entries within last 24 h.

---

## Conclusion

The **Azure‑Sentinel‑KQL‑Hunting‑&‑Detection‑Toolkit** distils field‑tested detection logic into reusable building blocks, bridging the gap between isolated investigations and codified security posture. By embracing KQL’s expressive analytics and wrapping each query with operational context, the toolkit accelerates your journey from raw logs to automated response.

Fork, star ⭐, and contribute additional hunts—together we can sharpen cloud defences and raise the collective bar for threat detection in Microsoft Sentinel. 🔍 **Happy hunting—and automate *all* the detections!**



----

----


----
2
----


----

----



----
3
----


----

----



----
4
----


----

----



----
5
----




<img src="https://i.imgur.com/1C8iiWB.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

