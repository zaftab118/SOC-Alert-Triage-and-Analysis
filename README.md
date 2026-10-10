# SOC-Alert-Triage-and-Analysis
A threat intelligence and alert classification project analyzing real-world Snort Rule IDs (SIDs) and Common Vulnerabilities and Exposures (CVEs) across distinct enterprise environments (Windows vs. Linux) to assess exploitability, reduce alert fatigue, and triage True Positives vs. False Positives.

---

## Project Overview
Alert fatigue is a primary operational bottleneck in modern Security Operations Centers (SOCs). Tier-1 analysts must rapidly evaluate telemetry against asset context, software versions, and network topology to determine whether an exploit payload represents an active threat:
- **Threat Intelligence & Vulnerability Research:** Mapped Snort Rule IDs to CVE designations, CVSS base scores, exploit mechanisms, and targeted software stacks.
- **Cross-Environment Triage Evaluation:** Classified 10 distinct security events against two enterprise environments: a corporate **Windows Domain** (Windows 10, Windows Server 2016, HP LaserJet fleet, Grandstream VoIP) and an **Enterprise Linux Environment** (Linux DNS/Web/Mail servers, Linux endpoints, Cisco IP Telephony, Epson fleet).
- **Analytical Decision-Making:** Categorized events into **True Positive (TP)**, **False Positive (FP)**, or **Requires Further Investigation**, citing exact technical criteria such as architecture mismatch, vulnerable binary presence, and protocol relevance.

---

## Security Frameworks & Triage Criteria
- **Vulnerability Databases:** MITRE CVE, NIST National Vulnerability Database (NVD)
- **Signature Intelligence:** Snort NIDS Signature Database, VirusTotal
- **Scoring System:** Common Vulnerability Scoring System (CVSS v3.x)
- **Classification Taxonomy:**
  - **True Positive (TP):** The alert accurately reflects malicious activity or exploitation targeting a known vulnerable service present in the environment.
  - **False Positive (FP):** The alert signature matched network traffic, but the underlying host/architecture is not vulnerable (e.g., Linux-specific exploit sent to a Windows Server).
  - **Requires Further Investigation:** The signature matches an attack vector that could succeed depending on unconfirmed software revisions, libraries, or external BYOD assets.

---

## Comprehensive Alert & Vulnerability Intelligence Matrix

| Alert / Snort ID | CVE Reference | CVSS Score | Vulnerability / Threat Profile | Impacted Architecture & Vector |
| :--- | :--- | :--- | :--- | :--- |
| **SID 1-54630** | CVE-2020-8617 | 7.5 (High) | BIND 9 Denial of Service | Buffer assertion failure crashes BIND DNS servers |
| **N/A** | CVE-2021-3438 | 7.8 (High) | HP/Samsung Printer Driver EoP | Buffer overflow in `ssport.sys` driver allows local privilege escalation |
| **N/A** | CVE-2020-5723 | 9.8 (Critical) | Grandstream UCM6200 SQL Cleartext | Hardcoded SQLite DB exposure allows unauthenticated password dump |
| **SID 1-46597** | CVE-2018-8165 | 7.8 (High) | Windows DirectX Graphics Kernel EoP | Improper memory object handling in `dxgkrnl.sys` allows privilege elevation |
| **N/A** | CVE-2020-28374 | 8.1 (High) | Linux LIO iSCSI Target Auth Bypass | LUN unauthorized access allows data manipulation and file compromise |
| **SID 1-31814** | *No CVE (C2)* | N/A (Malware) | CnC Malware Beaconing | Host beaconing to known command-and-control infrastructure |
| **SID 1-50089** | CVE-2019-0885 | 7.8 (High) | Windows OLE Remote Code Execution | Improper user input validation during OLE object execution |
| **SID 1-50190** | CVE-2019-3462 | 8.1 (High) | APT HTTP Transport Redirect RCE | Unsanitized 302 redirect allows in-flight package injection / MiTM |
| **SID 1-49188** | *No CVE (Trojan)*| N/A (Malware) | Linux SpeakUp Trojan / Backdoor | Multi-vendor flagged C2 backdoor deployed via Linux SpeakUp |
| **SID 1-46991** | CVE-2018-4243 | 7.8 (High) | Apple XNU Kernel `getvolattrlist` Buffer Overflow | Heap buffer overflow in `getvolattrlist` allows kernel-level code execution |

---

## Environment Comparative Analysis

### Environment A: Corporate Windows Infrastructure
*Assets: Windows 10 Workstations, Windows Server 2016, HP LaserJet Printers, Grandstream UCM6200 IP Telephony.*

| Identifier | Classification | Technical Rationale & Action Plan |
| :--- | :--- | :--- |
| **SID 1-54630** | **False Positive** | Target infrastructure does not deploy Linux/BIND DNS; DNS services are handled natively via Windows Active Directory DNS. |
| **CVE-2021-3438** | **True Positive** | HP LaserJet network printers are active; the vulnerable print driver is deployed across workstations. Escalate for immediate vendor patch deployment. |
| **CVE-2020-5723** | **True Positive** | Active Grandstream UCM6200 VoIP system in use. Critical (9.8) database dump threat; isolate VoIP admin portal and upgrade firmware. |
| **SID 1-46597** | **True Positive** | Directly impacts Windows 10 and Server 2016 DirectX Kernel drivers. High threat of local escalation; audit endpoint patch levels. |
| **CVE-2020-28374** | **False Positive** | Linux LIO iSCSI storage vulnerability does not apply to native Windows iSCSI initiator/target implementations. |
| **SID 1-31814** | **True Positive** | Active command-and-control beaconing from an internal Windows client. Isolate host immediately from subnet and initiate memory triage. |
| **SID 1-50089** | **Need More Info** | Windows OLE execution is present, but vulnerability exploitability relies on specific patch rollouts (KB updates) and Office suite versions. |
| **SID 1-50190** | **True Positive** | Exploits Debian/Ubuntu `apt` transport. In an enterprise environment, unvetted Linux subsystems (WSL) or third-party build containers may be impacted. |
| **SID 1-49188** | **False Positive** | Linux-specific SpeakUp Trojan payload cannot execute natively on standard Windows PE environments. |
| **SID 1-46991** | **Need More Info** | Apple macOS/iOS kernel vulnerability. While enterprise endpoints are Windows, investigation is required to determine whether executive BYOD or remote macOS clients access the subnet. |

---

### Environment B: Enterprise Linux Infrastructure
*Assets: Linux Servers (BIND DNS, Nginx Web, Postfix Mail), Linux Workstations, Cisco IP Phones, Epson Printers.*

| Identifier | Classification | Technical Rationale & Action Plan |
| :--- | :--- | :--- |
| **SID 1-54630** | **True Positive** | Enterprise hosts authoritative BIND 9 DNS servers. Exploit payload poses immediate service crash/DoS threat. Patch to secured BIND release. |
| **CVE-2021-3438** | **False Positive** | Environment uses an Epson printer fleet and Linux printing architecture (CUPS); vulnerable HP/Samsung Windows drivers are absent. |
| **CVE-2020-5723** | **Need More Info** | Environment uses Cisco IP phones instead of Grandstream; investigate if rogue or legacy Grandstream hardware exists in peripheral subnets. |
| **SID 1-46597** | **False Positive** | Windows DirectX graphics driver exploit is incompatible with Linux display servers (X11 / Wayland). |
| **CVE-2020-28374** | **True Positive** | Targets Linux kernel LIO iSCSI target framework directly. Threat actor could bypass authentication to alter storage backstores. |
| **SID 1-31814** | **False Positive** | Known Windows-specific C2 binary signature. Network traffic represents non-viable execution attempts on Linux endpoints. |
| **SID 1-50089** | **False Positive** | Windows OLE protocol execution vulnerability is not viable against native Linux desktop/server environments. |
| **SID 1-50190** | **True Positive** | Linux workstations/servers running Debian/Ubuntu utilize `apt`. Critical in-flight redirect RCE vector; verify `apt` versions are post-1.4.8. |
| **SID 1-49188** | **True Positive** | Trojan explicitly engineered to target Linux systems. Immediate containment: isolate infected host, dump process memory, and hunt for persistence. |
| **SID 1-46991** | **False Positive** | Apple XNU Kernel buffer overflow payload is structurally ineffective against Linux kernel architectures. |

---

## Key Takeaways & SOC Engineering Insights
- **Context Over Content:** A high-severity signature (e.g., CVSS 9.8) does not constitute a critical incident if the targeted service or operating system does not exist in the subnet. Asset inventory context turns raw alert volume into high-fidelity intelligence.
- **Signature Tuning & Rule Suppression:** SIDs regularly triggering on non-applicable operating systems (e.g., Windows OLE exploits directed at Linux web nodes) should be tuned at the sensor level or suppressed by subnet to reduce analyst cognitive load.
- **BYOD & Perimeter Blindspots:** Ambiguous classifications ("Need More Info") highlight the necessity for Network Access Control (NAC) and MDM solutions to detect unmanaged assets (such as Apple or rogue IoT hardware) on corporate segments.
