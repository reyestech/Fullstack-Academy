



---

## 📚 Table of Contents

- [🔐 Introduction](#%F0%9F%94%90-introduction)
- [🎯 Objective](#-objective)
- [🛠️ Methodology Overview](#-methodology-overview)
- [📌 Key Skills](#key-skills)
- [🔓 Before Hardening: Insecure Cloud Architecture](#before-hardening-insecure-cloud-architecture)
- [🔐 After Hardening: Secure & Compliant Architecture](#after-hardening-secure--compliant-architecture)
- [📉 Attack Surface Before Hardening](#attack-surface-before-hardening)
- [🌍 Attack Maps Before Hardening](#attack-maps-before-hardening)
  - [🌐 NSG – Malicious Inbound Flows](#1-network-security-group-nsg--malicious-inbound-flows)
  - [🐧 Linux SSH Attacks](#2-linux-ssh-attacks--authentication-failures)
  - [🪟 Windows RDP Attacks](#3-windows-rdp-attacks--smbrdp-authentication-failures)
  - [🛢️ SQL Server Attacks](#4-sql-server-attacks--authentication-failures)
- [🧠 Analysis & Incident Assessment](#analysis--incident-assessment)
- [📊 Post-Hardening](#post-hardening)
- [🌐 VLAN and Subnet Configuration](#-vlan-and-subnet-configuration)
- [🧰 Azure NIST Overview](#-azure-nist-overview)
- [🏗️ Azure Hardening Analysis](#azure-hardening-analysis)
  - [🔧 Architecture](#architecture)
  - [🔍 Methodology](#methodology)
  - [📈 Metrics & Results](#metrics--results)
- [🔎 KQL & Automation Queries](#kusto-query-language-kql--python-sdk-automation-queries)
- [✅ Conclusion](#conclusion)

---

---


---
---


<p align="center">
  <img src="https://github.com/user-attachments/assets/544ac8c3-8ffc-44c3-b9fd-347a20dfe786" alt="ezgif-7650866c6a50db" width="900"/>
</p>

# Azure: Sentinel Honeynet and Network Hardening
 **Hector M. Reyes | SOC Analyst** |  [Google Docs Version](https://docs.google.com/document/d/1TbSMzlBtGITVFOTaBGqKXjKY0mPG14p5ZWra-Tj8WNk/pub)

---

<h2 align="center">🔐 Introduction</h2>

In this project, I designed and deployed a Security Operations Center (SOC) environment using Microsoft Azure, using Microsoft Sentinel as the central Security Information and Event Management (SIEM) solution. To investigate emerging cyberattack behavior, I set up a honeynet by deploying intentionally vulnerable virtual machines running Windows, Linux, and SQL Servers, all of which were exposed to the internet. This configuration was designed to attract malicious actors from around the globe, enabling the collection and analysis of real-time attack data and current threat vectors.

The SOC was designed to log, monitor, and analyze malicious traffic, which facilitated effective incident response. After the initial observations, I implemented stringent hardening controls that aligned with regulatory standards, such as NIST SP 800-53. I followed recommendations from Microsoft Defender for Cloud to enhance the security posture of the cloud infrastructure.

<p align="center">
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/9859c84f-cf7b-4ccb-8ad7-4bf2dd5a35cb" width="800">
</p>


## 🎯 **Objective**  
This project aimed to evaluate and enhance the security posture of a cloud environment by simulating real-world cyberattacks and establishing a structured incident response process. A honeynet, consisting of virtual machines (VMs) running Windows, Linux, and SQL Server, was deployed over 24 hours to attract global cyber threats. Logs collected via Azure Log Analytics facilitated the detection of malicious activities, the generation of alerts, and the initiation of automated incident responses utilizing Microsoft Sentinel.

Microsoft Defender for Cloud was used to assess the VMs' configurations against established compliance benchmarks, identifying existing security vulnerabilities. Following the implementation of hardening measures, an additional assessment was conducted over a 24-hour period to validate the effectiveness of these remediation efforts. The NIST SP 800-53 framework was adopted as the foundational standard to ensure long-term compliance and to strengthen the cloud environment's defenses against potential threats.

## **Methodology Overview**
This project adopted a structured six-phase approach to attract, detect, simulate, monitor, and defend against real-world cyber threats within a live cloud environment. The primary aim was to entice malicious activity, contain it within a controlled sandbox setting, and extract insights to enhance threat detection and response mechanisms.

1. **Environment Setup and Initial Assessment:**
Intentionally vulnerable virtual machines, including Windows, Linux, and SQL Server, were deployed in Azure to replicate an insecure production environment. This configuration effectively functioned as a honeynet designed to attract live cyber threats and simulate adversarial behavior within a controlled environment.
2. **Log Data Configuration and Collection:**
Azure resources were configured to forward system, network, and security logs to a centralized Log Analytics workspace. This arrangement ensured comprehensive visibility and facilitated the correlation of suspicious activities throughout the cloud environment.
3. **Monitoring and Benchmarking:**
A 24-hour monitoring period was implemented to capture critical security events and performance metrics. This initiative provided a benchmark for identifying abnormal behavior and assessing the effectiveness of future remediation efforts.
4. **Incident Detection and Response:**
Remedial actions were undertaken based on Azure best practices, aligning with NIST SP 800-53 controls and NIST SP 800-61 incident handling guidance. These measures enhanced the overall security posture of the environment and ensured compliance with applicable industry standards.
5. **Security Enhancement Implementation:**
Remedial actions were undertaken based on Azure best practices, aligning with NIST SP 800-53 controls and NIST SP 800-61 incident handling guidance. These measures enhanced the overall security posture of the environment and ensured compliance with applicable industry standards.
6. **Post-Remediation Assessment and Evaluation:**
A subsequent 24-hour monitoring period was conducted to evaluate the effectiveness of the security enhancements. Data from both assessment phases were analyzed and compared to quantify improvements and verify a reduced vulnerability to contemporary threat actors.

<h3 align="center">📂 Secured Storage Access via Private Endpoint </h3>

<p align="center">
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/70416dd1-70eb-4933-a0c7-f0a341276abb" width="800">
</p>

### **Key Skills**  
> 1. **Azure Security Architecture:** Designed and implemented a secure cloud infrastructure within Microsoft Azure.
> 2. **SIEM Log Analytics:** Utilized Microsoft Sentinel for real-time monitoring and analysis of security events.
> 3. **Kusto Query Language (KQL):** Developed and executed queries for effective threat hunting and data analysis.
> 4. **Threat Detection & Response:** Identified and responded to security incidents, enhancing the environment's resilience.
> 5. **Vulnerability Management:** Assessed and mitigated vulnerabilities within the cloud infrastructure.
> 6. **Compliance Governance:** Ensured adherence to regulatory standards and best practices.
> 7. **Cloud Networking:** Configured and managed network security groups and virtual networks.
> 8. **Automation:** Implemented automated responses to security incidents, streamlining operations.

---

## 🔓 **Before Hardening: Insecure Cloud Architecture**
The initial cloud architecture was intentionally misconfigured to simulate a high-risk production-like environment, resembling those typically found in real-world security incidents. This insecure setup was designed to attract live cyber threats, gather telemetry data, and identify common attack vectors. Azure resources were purposefully exposed with minimal access restrictions, creating a controlled environment for observing adversary behavior.
1. **Public Exposure of Critical Resources:** The deployment included Windows and Linux virtual machines (VMs), an SQL Server, a storage account, and a key vault with public-facing endpoints and open network security groups (NSGs) designed to mirror prevalent misconfigurations
2. **Permissive Network Security Groups (NSGs):** Default and loosely configured NSG rules allowed unrestricted inbound traffic, making the environment vulnerable to scanning, brute-force attacks, and lateral movement.
3. **Initial Monitoring via Microsoft Sentinel:** Logs from all resources were systematically collected through Azure Log Analytics and monitored using Microsoft Sentinel to detect real-time alerts, failed authentication attempts, and reconnaissance activities.

![68747470733a2f2f692e696d6775722e636f6d2f69536c666559582e6a7067](https://github.com/user-attachments/assets/f5ec8a80-09b3-42a4-ac2b-8f6cfb5d2918)


## 🔐**After Hardening: Secure & Compliant Architecture**
After the initial detection and analysis of threats, the environment was restructured to incorporate secure architecture principles in line with NIST SP 800-53 controls, specifically SC-7(3): Access Restrictions for External Connections. The key enhancements focused on minimizing external exposure, strengthening infrastructure, and ensuring compliance with relevant standards. 

This transformation highlights the critical role of Security Operations Center (SOC) analysts, who use platforms like Microsoft Sentinel. Their responsibilities include continuous monitoring, log correlation, and incident triage. Additionally, it emphasizes the need for dedicated analysts to detect and neutralize threats before they escalate proactively.
1. **Restricted Access via Hardened NSGs:** Ingress traffic was rigorously controlled by permitting access exclusively from specific, trusted public IP addresses while blocking all other external traffic.
2. **Replacement of Public Endpoints with Private Endpoints:** Azure Private Endpoints were integrated for critical resources (e.g., storage, key vault), ensuring that access is restricted to trusted virtual networks and eliminating public exposure.
3. **Enforced Firewall and Policy Controls:** Azure-native firewalls and Defender for Cloud policies were applied to implement platform-level protection and maintain compliance with SC-7(3): Access Restrictions for External Connections.

![68747470733a2f2f692e696d6775722e636f6d2f536871755135432e6a7067](https://github.com/user-attachments/assets/a8eeaf5e-f941-4db5-9a1c-dfd87f05b160)


---


# 📉 Attack Surface Before Hardening

## 🛡️Microsoft Defender for Cloud – Initial Posture

Overview: Initial assessment revealed a low security posture and a lack of compliance with access control standards.
  - Security Score:

<p align="left">
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/343d9f0f-4a53-49c6-b540-0ae7bf918b2e" width="400">
</p>


  - NIST SP 800-53 R5 – Access Control (AC) Findings:
> AC. Access Control: In access control, we can see what is missing to meet NIST standards.

<p align="left">
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/1a89ae0f-1d81-47b7-852d-b66cdafb0748" width="800">
</p>


<p align="left">
  <img src="https://github.com/user-attachments/assets/b79fc23a-764b-4b23-afe5-2962621f2e6b" width="800">
</p>


# 🌍 Attack Maps Before Hardening

## 🌐 1. Network Security Group (NSG) – Malicious Inbound Flows
> Description: NSGs allowed inbound traffic from untrusted IPs.
 <details>
   <summary><strong> 🔹KQL Query: NSGs traffic  </strong></summary>
     
NSG traffic
```kql
AzureNetworkAnalytics_CL
| where FlowType_s == "MaliciousFlow" and AllowedInFlows_d >= 1
| project TimeGenerated, IpAddress = SrcIP_s, DestinationIpAddress = DestIP_s
```

![image](https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/04e1dffa-958e-4d1c-b326-dc75a3ca91df)

</details>

<p align="left">
  <img src="https://github.com/user-attachments/assets/73cc9fbe-f8b9-4593-b40f-f4a485c9150b" width="800">
</p>


## 🐧2. Linux SSH Attacks – Authentication Failures
> Description: Detected failed SSH login attempts targeting Ubuntu VM.
 <details>
   <summary><strong> 🔹KQL Query: SSH Attacks </strong></summary>
   
SSH Authentication Fails
```kql
Syslog
| where Facility == "auth" and SyslogMessage contains "Failed password"
```

![image](https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/067e7d93-2757-4375-8d27-4b3472a9900c)

</details>

<p align="left">
  <img src="https://github.com/user-attachments/assets/f722c441-841d-4044-9181-3f2cea84a558" width="800">
</p>



## 🪟 3. Windows RDP Attacks – SMB/RDP Authentication Failures
> Description: Observed brute-force attempts via RDP/SMB protocols on Windows VMs.
 <details>
   <summary><strong> 🔹KQL Query: SMB/RDP Attacks </strong></summary>
   
RDP Authentication Fails
```kql
SecurityEvent
| where EventID == 4625
| where LogonType == 10
```

![image](https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/13021670-248a-4aa0-8266-deb373dfd6a7)

</details>

<p align="left">
  <img src="https://github.com/user-attachments/assets/97d93c53-713c-4857-9643-a3149a2317f0" width="800">
</p>


## 🛢️ 4. SQL Server Attacks – Authentication Failures
> - Description: Repeated failed login attempts targeting exposed SQL Server.
<details>
  <summary><strong> 🔹KQL Query: SQL Server Attacks </strong></summary>

SQL Server Authentication Fails
```kql
// Failed SQL logins
SqlSecurityAuditEvents
| where action_name == "FAILED_LOGIN"
```
  
  ![image](https://github.com/user-attachments/assets/06872696-6720-4d20-8d54-68233c7ab16d)

</details>

<p align="left">
  <img src="https://github.com/user-attachments/assets/a687ffa2-0469-4f4a-a54b-8758583b7985" width="800">
</p>



---

# Analysis & Incident Assessment 

This section highlights how Microsoft Sentinel was used to investigate and respond to coordinated brute-force attacks across Windows, SQL Server, and Linux systems within a 24-hour monitoring period.
**Incident ID: 329** Wass linked to malicious IP 74.249.102.160, which triggered multiple alerts.
> 1. **Alert 205:** Brute Force Attempt – Windows
> 2. **Alert 214:** Brute Force Attempt – MS SQL Server
> 3. **Alert 329:** Brute Force Success – Linux Syslog

<img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/2fa96acc-9a23-44a0-87a3-e1d74ac72856" width="350"/> 


### **Analyzing the Traffic** 
Sentinel analytics helped correlate these events, enabling detailed examination of attacker behavior, IP reputation, and sequence of actions. I analyzed both successful and failed attempts, filtering out false positives and tracking escalation patterns.

📊 **The included visuals show:**
> 1.	Sharp spikes in brute-force login attempts during the vulnerable phase
> 2.	NSG flow logs mapping inbound malicious traffic
> 3.	Timelines that illustrate how these threats stopped once hardening controls were applied

<img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/9d31a24c-d5b6-41b5-9089-7675844cf60d" width="700"/> 

✅ **Result:** Sentinel detections and NSG rule adjustments significantly reduced the attack surface and prevented further compromise. 


### **Azure Investigation Graph**
The Investigation Graph automatically visualizes the complete attack chain.
> Connecting alerts, affected hosts, and user accounts in a unified timeline. This enables analysts to swiftly transition from one indicator to corresponding evidence, enhancing the speed of triage and root-cause analysis.

![image](https://github.com/user-attachments/assets/0b4fd94a-d8f0-46ab-b832-5fdfe0c2858c)


### **Application and NSG hardening**
Remediated by associating and resetting the passwords for the compromised users and locking down NSGs
> Impact: The account was local to the Linux machine and non-admin, so it had a low impact. However, NSG hardening will remediate the attacks that have resulted in many other incidents.

  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/23a192c8-65d3-4dc7-8112-d57e522eefac" width="800"/>
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/ea612103-e77f-4529-be2a-c867c3c3f7aa" width="800"/>

---

# 📊 Post-Hardening

All map queries returned no results because there was zero malicious activity during the 24 hours following hardening.
After implementing hardening measures, we detected no malicious activity. All queries on the Sentinel map returned zero results, confirming the effectiveness of tightening our Network Security Groups (NSGs), utilizing private endpoints, and adhering to compliance requirements. By following Microsoft-recommended hardening steps alongside NIST SP 800-53 controls, we successfully reduced malicious traffic and incidents to zero within 24 hours.
<p align="left">
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/727edb36-b4e2-448d-aed0-60b5484ae91e" alt="No incidents after hardening" width="700"/>
</p>


### 🔐 VLAN and Subnet Configuration

These visuals demonstrate how the lab's single virtual network was divided into **three purpose-built subnets**. These subnets act as isolation zones, restricting traffic and limiting the blast radius if an attacker compromises a single host.

> **Azure Topology:** The Azure topology view displays all virtual machines (VMs), databases, and gateways on a single subnet within a virtual network. These subnets are separate rooms within the same building, each with doors (network security groups) that can be locked individually. The resource list in the right-hand pane is filtered by subnet, confirming that web, SQL, and management workloads reside in their segments.

<p align="left">
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/67ba9152-de43-4345-82fd-92b2da05b9f2" alt="Subnet config 1" width="330"/>
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/fa608462-bba8-4dea-975a-5c9fc9905081" alt="Subnet config 2" width="340"/>
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/49cb6ca9-e3d9-4bd5-bea5-44e0a19cc78a" alt="Subnet config 3" width="330"/>
</p>

---

### 🧰 Azure NIST Overview
NIST SP-800-53 is a comprehensive guideline for security and privacy controls in federal information systems. It serves as the foundation for compliance frameworks like FedRAMP, CSF, and Azure Security Benchmark.
To check NIST SP-800-53-R5 compliance:
> Navigate to: **Azure Home > Microsoft Defender for Cloud > Regulatory compliance > NIST SP-800-53-R5**
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/00b13f92-53cb-4cec-a630-d168dcec4542" alt="Defender compliance 1" width="700"/>


**NIST Protection:** 
A high-level use case for implementing NIST controls involves thoroughly examining the security lifecycle. This process includes the following stages:
> 1. **Build:** Develop security frameworks using the NIST workbook as a foundational guide. 
> 2. **Assess:** Conduct assessments with tools like Sentinel to identify vulnerabilities and gaps within the security infrastructure.
> 3. **Remediate:** Implement Azure DDoS protection to address identified threats.
> 4. **Monitor:** Continuously oversee and evaluate security measures to ensure their effectiveness.
> 5. **Respond:** Utilize an automated playbook designed to notify the governance team of any security incidents.

This systematic approach promotes effective management of security controls throughout their lifecycle, ensuring organizational resilience against potential threats.

![image](https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/821b1360-c5c8-4606-bd1b-f274761594a3)

---

# Azure Hardening Analysis 

## Architecture

> 🧱 This side-by-side comparison shows how exposed infrastructure was transformed into a secure environment by integrating best practices, including private endpoints and network security group (NSG) restrictions.

| Stage | Diagram | Description |
|-------|---------|-------------|
| **Before Hardening** | <img src="https://i.imgur.com/iSlfeYX.jpg" alt="Pre-hardening architecture" width="350"> | Public-facing VMs & services intentionally exposed to attract attackers. |
| **After Hardening**  | <img src="https://i.imgur.com/ShquQ5C.jpg" alt="Post-hardening architecture" width="350"> | NSGs tightened, firewalls tuned, public endpoints replaced by private endpoints, controls aligned to NIST SC-7(3). |



---

## Methodology

> 🔍 Each phase followed a logical progression from open exposure to complete remediation. Sentinel, Defender, and NIST guidelines were used together to identify threats and harden the environment based on real-world telemetry.

| Phase | Key Actions |
|-------|-------------|
| **1  Environment Build** | Deployed 2 Windows VMs, 1 Ubuntu VM, SQL Server, Storage Account & Key Vault with permissive NSGs. |
| **2  Log Collection**   | Enabled diagnostic settings → Log Analytics; onboarded Defender for Cloud & Sentinel. |
| **3  Baseline (24 h)**  | Captured attacks, created Sentinel alerts/incidents, stored metrics for comparison. |
| **4  Hardening**        | Applied Microsoft & NIST recommendations (NSGs, firewalls, private endpoints, IAM). |
| **5  Post-Remediation (24 h)** | Re-monitored metrics; validated 0 incidents and 0 malicious flows. |

---

## Metrics & Results

> 📉 The dramatic drop in alerts, flows, and incidents demonstrates how quickly and effectively the environment improved after targeted hardening strategies were implemented.

### ⏱️ Before vs After (24 h)

| Metric | Before | After | Δ % |
|--------|-------:|------:|----:|
| **Security Events** (Windows) | 221 542 | 84 | **-99.96** |
| **Syslog** (Linux)            | 2 310   | 2  | **-99.91** |
| **Security Alerts**           | 4       | 0  | **-100.00** |
| **Sentinel Incidents**        | 662     | 0  | **-100.00** |
| **Malicious NSG Flows**       | 1 742   | 0  | **-100.00** |

> 🔍 These figures confirm a complete elimination of detected attacks after hardening.

## Kusto Query Language (KQL) & Python SDK Automation Queries

<details>
<summary>KQL Queries Used</summary>
  
### Start & Stop Time
```
range x from 1 to 1 step 1
| project StartTime = ago(24h), StopTime = now()
```
### Security Events (Windows VMs)
```
SecurityEvent
| where TimeGenerated >= ago(24h)
| count
```
### Syslog (Ubuntu Linux VMs)  
```
Syslog
| where TimeGenerated >= ago(24h)
| count
```
### Security Alert (Microsoft Defender for Cloud)
```
SecurityAlert
| where DisplayName !startswith "CUSTOM" and DisplayName !startswith "TEST"
| where TimeGenerated >= ago(24h)
| count
```
### Security Incidents (Sentinel Incidents)
```
SecurityIncident
| where TimeGenerated >= ago(24h)
| count
```
### Azure NSG Inbound Malicious Flows Allowed
```
AzureNetworkAnalytics_CL 
| where FlowType_s == "MaliciousFlow" and AllowedInFlows_d > 0
| where TimeGenerated >= ago(24h)
| count
```
### Azure NSG Inbound Malicious Flows Allowed
```
AzureNetworkAnalytics_CL 
| where FlowType_s == "MaliciousFlow" and DeniedInFlows_d > 0
| where TimeGenerated >= ago(24h)
| count
```
</details>

---

## Conclusion

As part of this project, a honeynet was strategically deployed within the Microsoft Azure environment to emulate a high-risk, production-like setting that is susceptible to contemporary cyberattacks. Intentionally misconfigured virtual machines operating on Windows, Linux, and SQL Server were exposed to the internet to attract real-time threat activity. Logging was centralized through Azure Log Analytics, integrating telemetry from system, network, and security sources. Microsoft Sentinel served as the Security Information and Event Management (SIEM) platform, facilitating the creation of custom analytics rules, triggering real-time alerts, and visualizing threat activity through interactive workbooks and geolocation-based attack maps. Each alert was correlated with specific incidents, allowing for structured triage workflows that mirrored the operations of an actual Security Operations Center (SOC).

After performing a baseline analysis of threat activity and authentication failures, the environment was fortified using Azure-native security controls and compliance standards aligned with NIST SP 800-53. Critical measures implemented included Network Security Group (NSG) lockdowns, enforcing firewall rules, and migrating to private endpoints. Microsoft Defender for Cloud was also utilized to assess misconfigurations and guide remediation efforts. Following the implementation of these security controls, a subsequent monitoring phase revealed a marked reduction in unauthorized access attempts and brute-force attacks. These findings highlight the importance of layered security, continuous monitoring, and standards-based governance in enhancing cloud environments, resulting in measurable improvements in detection, prevention, and overall security posture from the perspective of a SOC analyst.


![Synapse-Animation_Embargoed](https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/6f463eb3-2e28-4023-94c2-9c85e56b23e9)




---
---

<img src="https://i.imgur.com/1C8iiWB.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

