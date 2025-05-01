<img src="https://i.imgur.com/1C8iiWB.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>


<p align="center">
  <img src="https://github.com/user-attachments/assets/544ac8c3-8ffc-44c3-b9fd-347a20dfe786"
       alt="Project banner animation" width="600">
</p>

<h1 align="center">Azure Sentinel Honeynet &amp; Network Hardening</h1>

<p align="center">
  <strong>Hector M. Reyes | SOC Analyst</strong> ·
  <a href="https://docs.google.com/document/d/1TbSMzlBtGITVFOTaBGqKXjKY0mPG14p5ZWra-Tj8WNk/pub">
    Full Technical Write-Up ↗
  </a>
</p>

---

<details open>
<summary>Table of Contents</summary>

- [Overview](#overview)
- [Architecture](#architecture)
- [Methodology](#methodology)
- [Metrics &amp; Results](#metrics--results)
- [Key KQL Queries](#key-kql-queries)
- [Screenshots](#screenshots)
- [xxx](#xxx)
</details>



<details open>
<summary>Table of Contents</summary>

- [Introduction](#Introduction)
- [Architecture](#architecture)
- [Objective:](Objective:)
- [Metrics &amp; Results](#metrics--results)
- [Key KQL Queries](#key-kql-queries)
- [Screenshots](#screenshots)
- [Conclusion](#conclusion)
</details>



## Introduction
We will establish a honeynet within our Microsoft Azure Security Information and Event Management (SIEM) system to attract malicious actors worldwide and provoke live attacks on our cloud environment. Our Security Operations Center (SOC) will log, monitor, and analyze the malicious traffic generated, enabling us to conduct incident response effectively. Subsequently, we will implement stringent hardening controls, ensure compliance with regulatory standards such as NIST 800-53, and adhere to Microsoft Defender for Cloud recommendations to fortify the security of our cloud infrastructure.


![image](https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/9859c84f-cf7b-4ccb-8ad7-4bf2dd5a35cb)

## Objective:
Over 24 hours, we observed attacks from various locations globally targeting our cloud environment, encompassing Windows Virtual Machines, SQL Servers, and Ubuntu Linux VMs. Log Analytics was employed to ingest logs from diverse sources, empowering Microsoft Sentinel to construct attack maps, trigger alerts, and initiate incident responses. Microsoft Defender for Cloud served as a crucial data source for the Log Analytics Workspace (LAW) and aided in evaluating the configuration of virtual machines in alignment with regulatory frameworks and security controls. I configured log collection within the vulnerable environment, established security metrics, and monitored the environment continuously for 24 hours. Following an investigation into the incidents flagged by Microsoft Sentinel during this timeframe, security controls were implemented to mitigate the identified threats and bolster the environment based on Microsoft Defender's recommendations. After another 24-hour monitoring phase, new metrics were gathered post-remediation, followed by the adoption of NIST 800-53 standards as a foundational framework to enhance the security posture of our cloud environment.

## xxx
 Sentinel to construct attack maps, trigger alerts, and initiate incident responses. Microsoft Defender for Cloud served as a crucial data source for the Log Analytics Workspace (LAW) and aided in evaluating the configuration of virtual machines in alignment with regulatory frameworks and security controls. I configured log collection within the vulnerable environment, established security metrics, and monitored the en

## Overview

This project demonstrates how to deploy a **live honeynet** in Microsoft Azure, capture real-world attacks, and then **harden** the environment using **Microsoft Sentinel**, **Defender for Cloud**, and **NIST SP 800-53** controls.  
Over two 24-hour windows (before and after hardening) I:

* Collected multi-platform logs (Windows, Linux, SQL, NSG flows) in a **Log Analytics Workspace**  
* Visualized attacks with Sentinel maps and custom KQL dashboards  
* Implemented layered controls (NSGs, private endpoints, hardening baselines)  
* Measured the resulting drop in malicious activity (**&gt; 99 % reduction**)  

---

## Architecture

| Stage | Diagram | Description |
|-------|---------|-------------|
| **Before Hardening** | <img src="https://i.imgur.com/iSlfeYX.jpg" alt="Pre-hardening architecture" width="350"> | Public-facing VMs &amp; services intentionally exposed to attract attackers. |
| **After Hardening**  | <img src="https://i.imgur.com/ShquQ5C.jpg" alt="Post-hardening architecture" width="350"> | NSGs tightened, firewalls tuned, public endpoints replaced by private endpoints, controls aligned to NIST SC-7(3). |

---

## Methodology

| Phase | Key Actions |
|-------|-------------|
| **1  Environment Build** | Deployed 2 Windows VMs, 1 Ubuntu VM, SQL Server, Storage Account &amp; Key Vault with permissive NSGs. |
| **2  Log Collection**   | Enabled diagnostic settings → Log Analytics; onboarded Defender for Cloud &amp; Sentinel. |
| **3  Baseline (24 h)**  | Captured attacks, created Sentinel alerts/incidents, stored metrics for comparison. |
| **4  Hardening**        | Applied Microsoft &amp; NIST recommendations (NSGs, firewalls, private endpoints, IAM). |
| **5  Post-Remediation (24 h)** | Re-monitored metrics; validated 0 incidents and 0 malicious flows. |

---

## Metrics &amp; Results

### ⏱️ Before vs After (24 h)

| Metric | Before | After | Δ % |
|--------|-------:|------:|----:|
| **Security Events** (Windows) | 221 542 | 84 | **-99.96** |
| **Syslog** (Linux)            | 2 310   | 2  | **-99.91** |
| **Security Alerts**           | 4       | 0  | **-100.00** |
| **Sentinel Incidents**        | 662     | 0  | **-100.00** |
| **Malicious NSG Flows**       | 1 742   | 0  | **-100.00** |

> 🔍 These figures confirm a complete elimination of detected attacks after hardening.

---

## Key KQL Queries

<details>
<summary>Expand to view queries</summary>




