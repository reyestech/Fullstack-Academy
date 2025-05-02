

## 🔓 Before Hardening: Insecure Cloud Architecture
The initial cloud architecture was intentionally misconfigured to simulate a high-risk production-like environment, resembling those typically found in real-world security incidents. This insecure setup was designed to attract live cyber threats, gather telemetry data, and identify common attack vectors. Azure resources were purposefully exposed with minimal access restrictions, creating a controlled environment for observing adversary behavior.
- Public Exposure of Critical Resources: The deployment included Windows and Linux virtual machines (VMs), an SQL Server, a storage account, and a key vault with public-facing endpoints and open network security groups (NSGs) designed to mirror prevalent misconfigurations
- Permissive Network Security Groups (NSGs): Default and loosely configured NSG rules allowed unrestricted inbound traffic, making the environment vulnerable to scanning, brute-force attacks, and lateral movement.
- Initial Monitoring via Microsoft Sentinel: Logs from all resources were systematically collected through Azure Log Analytics and monitored using Microsoft Sentinel to detect real-time alerts, failed authentication attempts, and reconnaissance activities.

![68747470733a2f2f692e696d6775722e636f6d2f69536c666559582e6a7067](https://github.com/user-attachments/assets/f5ec8a80-09b3-42a4-ac2b-8f6cfb5d2918)


## 🔐After Hardening: Secure & Compliant Architecture
After the initial detection and analysis of threats, the environment was restructured to incorporate secure architecture principles in line with NIST SP 800-53 controls, specifically SC-7(3): Access Restrictions for External Connections. The key enhancements focused on minimizing external exposure, strengthening infrastructure, and ensuring compliance with relevant standards. 

This transformation highlights the critical role of Security Operations Center (SOC) analysts, who use platforms like Microsoft Sentinel. Their responsibilities include continuous monitoring, log correlation, and incident triage. Additionally, it emphasizes the need for dedicated analysts to detect and neutralize threats before they escalate proactively.

- Restricted Access via Hardened NSGs: Ingress traffic was rigorously controlled by permitting access exclusively from specific, trusted public IP addresses while blocking all other external traffic.
- Replacement of Public Endpoints with Private Endpoints: Azure Private Endpoints were integrated for critical resources (e.g., storage, key vault), ensuring that access is restricted to trusted virtual networks and eliminating public exposure.
- Enforced Firewall and Policy Controls: Azure-native firewalls and Defender for Cloud policies were applied to implement platform-level protection and maintain compliance with SC-7(3): Access Restrictions for External Connections.

![68747470733a2f2f692e696d6775722e636f6d2f536871755135432e6a7067](https://github.com/user-attachments/assets/a8eeaf5e-f941-4db5-9a1c-dfd87f05b160)




---



---
---



---
---


---
---



---
---



---
---



---
---

<img src="https://i.imgur.com/1C8iiWB.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

