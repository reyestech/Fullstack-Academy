
----

----


----
1
----



# 🛡️ Azure Honeynet & Sentinel Hardening

Modern cybersecurity hinges on three pillars—**visibility, speed, and automation**. This project brings them together by deploying a production‑style Azure honeynet, capturing live attacker traffic, and then **hardening** the cloud environment with Microsoft Sentinel analytics and NIST controls. The walkthrough is written for:

* **SOC Analysts / Incident Responders** who want to see real logs, queries, and playbooks.
* **Network & Cloud Administrators** evaluating Azure security posture tools.
* **Hiring managers & non‑technical recruiters** seeking clear evidence of hands‑on Azure security skills.

---

## 📉 Initial Posture

The environment launched with a default and permissive configuration, common in real-world cloud missteps. This included open ports, limited segmentation, and no access controls on sensitive assets. The goal was to simulate a high-risk Azure footprint and collect telemetry from live attacker traffic.

This posture exposed several weaknesses, such as unrestricted inbound rules in NSGs and public-facing access to critical resources like SQL and Key Vault. These vulnerabilities were leveraged by automated scans and brute-force attempts, offering visibility into attack behaviors and trends.

## 🔍 Initial Attack Surface – Microsoft Defender for Cloud

Initial analysis from Microsoft Defender for Cloud showed a **low Secure Score**. Most issues are related to identity protection, endpoint configuration, and a lack of resource-level segmentation.

* **Security Score:** The Azure environment initially scored 34%, with critical Defender recommendations for enabling MFA, reducing exposed endpoints, and applying OS-level patches.
* **NIST SP 800-53 R5 Access Control (AC) Findings:** The setup lacked enforced role-based access, secure defaults, and audit logging—violating core NIST controls under the Access Control (AC) family.

## 🌐 Sentinel Maps – Monitoring Active Cyber Threats

Microsoft Sentinel's built-in geospatial map feature revealed rapid inbound scanning activity. Within 24 hours, the environment had attracted thousands of connection attempts, primarily from Brazil, China, and Russia, highlighting how quickly attackers target new Azure resources with open ports.

## 🐧 Linux SSH Attacks – Authentication Failures

SSH services on Ubuntu servers faced persistent brute-force login attempts. Sentinel flagged multiple password failures from a small set of rotating global IPs.

* **Phase 1:** Detection began with hundreds of "Failed password" messages in the Syslog stream.
* **Phase 2:** Analysts used automation to isolate attacker IPs and block them at the NSG level. These attacks slowed significantly post-hardening.

<details>
  <summary><strong> 📋 Click to View Query: SSH Attacks </strong></summary>

```kql
Syslog
| where Facility == "auth" and SyslogMessage contains "Failed password"
```

</details>

## 🪟 Windows RDP Attacks – SMB/RDP Authentication Failures

Attackers repeatedly targeted exposed Windows VMs through port 3389 using common usernames and password variations. These brute-force attempts triggered Sentinel rules after reaching detection thresholds.

* **Phase 1:** Failed logons were seen in `SecurityEvent` logs, marked with EventID 4625 and logonType 10 (RDP).
* **Phase 2:** Accounts were protected by enabling lockouts and narrowing NSG rules.

<details>
  <summary><strong> ⚙ How RDP Traffic Query Works: Click to View </strong></summary>

Analyzes failed RDP login attempts through SecurityEvent logs. Flags brute-force indicators like logonType 10 and repeated account failures.

</details>

<details>
  <summary><strong> 📋 Click to View Query: RDP Brute Force </strong></summary>

```kql
SecurityEvent
| where EventID == 4625 and AccountType == "User" and LogonType == 10
```

</details>

## 🗄 SQL Server Attacks – Authentication Failures

SQL Server faced login brute-force attempts through unauthenticated probes aimed at default accounts like sa. Sentinel registered spikes in failed logins and clustered alerts from similar IP ranges.

Phase 1: SQL logs highlighted repeated login failures often spaced in short intervals.
Phase 2: Sentinel playbooks were deployed to quarantine source IPs and notify security teams.

<details>
  <summary><strong> ⚙ How SQL Login Query Works: Click to View </strong></summary>

Captures authentication failures from SQL audit logs, filtered by login type and failure status.

</details>

<details>
  <summary><strong> 📋 Click to View Query: SQL Brute Force </strong></summary>

```kql
SqlAuditLogs
| where action_name_s == "FAILED_LOGIN"
```

</details>

## 🧠 Analysis & Incident Assessment

Sentinel correlated alerts from different services into Incident ID 329. This involved login failures from Windows, Linux, and SQL services tied to malicious IP 74.249.102.160.

* This level of correlation highlighted Sentinel’s ability to track multi-vector campaigns in real time.
* Each alert showed distinct phases of an attempted breach—probing, persistence, and escalation.

### 📊 Analyzing the Traffic

Visualizations helped SOC analysts identify temporal spikes in activity. IP mapping and flow logs pointed to lateral movement attempts across subnets, allowing rapid containment.

### 🔎 Azure Investigation Graph

Microsoft Sentinel’s Investigation Graph stitched all elements—hosts, alerts, IPs, and user actions—into a single navigable chain. This visualization helped responders understand event sequences and attribution.

### 🛡 Application and NSG Hardening

All traffic through NSGs was re-scoped to trusted IP ranges. Public-facing endpoints were moved to private networks, and Just-In-Time access was enabled where needed. The hardening phase demonstrated measurable reduction in attack surface.

## 🔐 Post-Hardening Attack Surface

The environment underwent multiple changes post-assessment:

* NSGs applied deny-by-default policies.
* Firewall policies restricted lateral movement.
* Defender for Cloud validated all NIST-mapped controls.

After hardening, the attack frequency dropped by over 90% across all services, confirming the success of remediation steps.

## 🌐 VLAN and Subnet Configuration

Network segmentation separated workload tiers—web, app, and database—across individual subnets. This constrained lateral movement and improved visibility during investigations.

### Azure Topology

A diagram representing each tier’s NSG, UDR, and peered network connections shows the isolation strategy across services.

## 🧰 Azure NIST Overview

NIST SP-800-53 served as the compliance blueprint. Each Defender recommendation was mapped to a control, guiding the prioritization of remediation actions.

* Security coverage increased through layered IAM policies, network controls, and endpoint hardening.
* Logs were continuously reviewed to ensure policy enforcement aligned with SC-7 and AC series controls.

<details>
  <summary><strong>📋 Copy Markdown — Azure NIST Overview</strong></summary>

```markdown
### 🧰 Azure NIST Overview

| Stage         | Key Actions                                                                                        |
| ------------- | -------------------------------------------------------------------------------------------------- |
| **Build**     | Develop security framework using the NIST SP 800‑53 workbook as a foundational guide.              |
| **Assess**    | Conduct assessments using Microsoft Sentinel and Defender to identify misconfigurations and risks. |
| **Remediate** | Implement Azure DDoS Protection, restrict NSGs, and enforce access controls.                       |
| **Monitor**   | Continuously oversee security controls and telemetry within Defender and Sentinel.                 |
| **Respond**   | Use automated playbooks to notify governance teams and log all critical incidents.                 |

> Navigate to: **Azure Home → Defender for Cloud → Regulatory Compliance → NIST SP‑800‑53‑R5**

NIST SP‑800‑53 is a comprehensive guideline for security and privacy controls in federal systems. It underpins compliance programs such as FedRAMP, CSF, and Azure Security Benchmark. This approach promotes continuous risk management across the security lifecycle and enhances cloud resilience.
```

</details>



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

