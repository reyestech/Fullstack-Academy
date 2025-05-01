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

## 📊 Post-Hardening Analysis

> All map queries returned no results due to zero malicious activity during the 24 hours following hardening.

<p align="center">
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/727edb36-b4e2-448d-aed0-60b5484ae91e" alt="No incidents after hardening" width="500"/>
</p>

---

### 🔐 VLAN and Subnet Configuration

<p align="center">
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/67ba9152-de43-4345-82fd-92b2da05b9f2" alt="Subnet config 1" width="350"/>
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/fa608462-bba8-4dea-975a-5c9fc9905081" alt="Subnet config 2" width="350"/>
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/49cb6ca9-e3d9-4bd5-bea5-44e0a19cc78a" alt="Subnet config 3" width="350"/>
</p>

---

### 🧰 Azure NIST Overview

NIST SP 800-53 is a comprehensive guideline for security and privacy controls in federal information systems. It serves as the foundation for compliance frameworks like FedRAMP, CSF, and Azure Security Benchmark.

<p align="center">
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/ef0a32ee-daa3-4dd3-a6a2-c3e8d3ba5f66" alt="NIST overview chart" width="500"/>
</p>

To view NIST SP-800-53-R5 compliance:
- Go to **Azure Home > Microsoft Defender for Cloud > Regulatory compliance > NIST SP-800-53-R5**

<p align="center">
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/00b13f92-53cb-4cec-a630-d168dcec4542" alt="Defender compliance 1" width="350"/>
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/430f4980-c604-44d7-bc29-f468c3d18f01" alt="Defender compliance 2" width="350"/>
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/821b1360-c5c8-4606-bd1b-f274761594a3" alt="Defender compliance 3" width="350"/>
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




