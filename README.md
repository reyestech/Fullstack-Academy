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
- [Conclusion](#conclusion)
</details>

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




