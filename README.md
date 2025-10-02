# Active Directory Attack & Detection Lab

## 📝 Full Write-up
[Medium Article - Active Directory Attack Simulation and AI-Assisted Threat Detection with Popular SIEM Tools](https://medium.com/@robertmark94/active-directory-attack-simulation-and-ai-assisted-threat-detection-with-popular-siem-tools-part-1-37dc1a71be7f)

## 📌 Overview
This lab simulates an enterprise Active Directory environment with Windows Server + clients.  
I executed common AD attacks and developed detections in Splunk & Security Onion.
The lab also suggests ways in which I, as a Security Analyst, can use AI and LLMs during security operations for enterprises.

## ⚙️ Tools & Tech
- Windows Server 2019 (Domain Controller)
- Windows 10 clients (Domain members)
- Splunk (Sysmon & Event Log ingestion)
- Security Onion (Suricata + Zeek)
- Kali Linux (attacker machine)

## 🛡️ Attacks Simulated
- LLMNR Poisoning (Responder) @ `/LLMNR-Poisoning-Attack`/
<!--
- Pass-the-Hash
- Kerberoasting
- Lateral Movement (SMB, RDP)
-->
