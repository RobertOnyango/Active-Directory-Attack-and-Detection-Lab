# LLMNR Poisoning Attack

## 📝 Full Write-up
[Medium Article - Active Directory Attack Simulation and AI-Assisted Threat Detection with Popular SIEM Tools - Part 3](https://medium.com/@robertmark94/active-directory-attack-simulation-and-ai-assisted-threat-detection-with-popular-siem-tools-part-3-9e96e033fc59)

## 📌 Overview
Linked-Local Multicast Name Resolution; LLMNR (UDP 5355) and NetBIOS Name Service (NBT-NS, UDP 137) are fallback prtocols used in Windows networks when DNS resolution fails. Poisoning allows an attacker to respond to local name-resolution requests and coerce a target to authenticate to the attacker, often exposing NTLM hashes or enabling SMB/NTLM relay. This lab demonstrates the attack, how to capture artifacts, and detection steps for rapid triage, containment and remediation.

This lab simulates an **LLMNR poisoning attack** using Responder from a Kali attacker machine against two Windows clients and a Domain Controller, while monitoring the activity with:
- **Security Onion (Suricata IDS)**
- **Splunk (Windows Event Logs & Sysmon)**
- **Wireshark (packet analysis)**


## 📂 Detection Artifacts (Repository Structure)
- `/splunk-queries/` → SPL queries for investigation i.e. detecting LLMNR activity in network logs and failed NTLM authentications in Windows logs and incident reponse i.e. setting up alerts
- `/suricata-rules/` → Custom detection rules for LLMNR traffic
- `/sigma-rules/` → Custom sigma rules for coorelation and attack flow:
    - LLMNR traffic
    - SMB connections
    - SMB connections post LLMNR traffic for same source IP
- `/pcap-examples/` → Screenshots of captured LLMNR traffic with sanitization notes
- `/detection-notes` → Considerations made during detection engineering

## 🔎 Lab Playbook (What I did)
**Step 1: Setup**
- Domain Controller + 2 Windows 10 clients
- Kali Linux attacker with Responder
- Security Onion for network monitoring
- Splunk + Sysmon on DC for log analysis

**Step 2: Attack Simulation**
- Triggered name resolution from victim (`ping the attacker's IP address`)
- Captured malicious responses + NTLM challenge/response via Responder
- Cracked the password via Hashcat

**Step 3: Evidence Collection**
- Collected PCAPs with Wireshark & tcpdump  
- Logged Windows Event IDs (4625, 4648) via Splunk  
- Correlated LLMNR queries with authentication attempts  

**Step 4: Detection and Response**
- Suricata IDS alert for 224.0.0.252 UDP 5355 traffic
- Suricata IDS alert for SMB authentication to unauthorized server
- Sigma alert for LLMNR packets followed by SMB authentication request for the same source IP i.e. Cross-correlation between network events & logon attempts
- Splunk queries detecting failed NTLM authentications, outbound SMB connections and the correalation.

**Step 5: Enterprise Recommendations**
- Disable LLMNR via GPO (`Computer Config > DNS Client > Turn off multicast name resolution`)  
- Disable NTLM where possible, enforce Kerberos  
- Monitor for abnormal NTLM authentications in SIEM 

---

## Next Steps
This repo will grow with other AD attack techniques (SMB Relay, Pass-the-Hash, Kerberoasting, Lateral Movement) following the same structure.