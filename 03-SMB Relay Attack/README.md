# SMB Relay (NTLM Relay) Attack

## 📝 Full Write-up

[Medium Article – Active Directory Attack Simulation and AI-Assisted Threat Detection with Popular SIEM Tools – Part 4](https://robertmark94.medium.com/active-directory-attack-simulation-and-ai-assisted-threat-detection-with-popular-siem-tools-part-4-01a8a12f7feb)

## 📌 Overview
SMB relay (NTLM relay) is a post-credential-coercion attack that abuses the NTLM authentication protocol by forwarding captured authentication challenges from a victim to another service without cracking credentials. When SMB signing is not enforced, an attacker can relay NTLM authentication to authenticate as the victim and access network resources or execute actions on remote systems.

This lab demonstrates **NTLM relay over SMB** following LLMNR poisoning, highlights how the attack appears at the network protocol level, and explores realistic detection strategies using network telemetry and limited endpoint logging.

The attack was simulated in an Active Directory environment and monitored with:
- **Security Onion (Suricata IDS)**
- **Splunk (Windows Event Logs & Sysmon)**
- **Wireshark (packet analysis)**

## 📂 Detection Artifacts (Repository Structure)
- `/splunk-queries/` → SPL queries detecting anomalous NTLM network logons (Event ID 4624, Logon Type 3)
- `/pcap-examples/` → SMB negotiation and NTLM authentication packet captures (screenshots)
- `/detection-notes/` → Detection logic, limitations, and tuning considerations

## 🔎 Step-by-Step Lab (What I did)
**Step 1: Attack Simulation**
- Captured NTLM authentication via prior LLMNR poisoning
- Relayed NTLM authentication to a second Windows host over SMB
- Successfully authenticated without cracking credentials
- Established SMB session and accessed IPC$ share

**Step 2: Evidence Collection**
- Captured SMB2 traffic showing:
    - NTLMSSP NEGOTIATE
    - NTLMSSP CHALLENGE
    - NTLMSSP AUTH
- Identified identical NTLM authentication blobs reused across separate SMB sessions
- Observed Tree Connect requests to \\<target>\IPC$

**Step 3: Detection and Analysis**
- Suricata alert triggered for SMB connection to rogue server
- Wireshark confirmed NTLM relay by comparing NTLM security blobs
- Splunk detected NTLM-based network logons (Event ID 4624, Logon Type 3) from unexpected source IPs

**Step 4: Enterprise Recommendations**
- Enforce SMB signing on all servers
- Restrict or disable NTLM where possible
- Monitor NTLM authentication usage in Kerberos environments
- Prioritize network-based detection for credential relay attacks

---

## Next Steps
This repository is part of a growing Active Directory attack & detection series, including:
- LLMNR Poisoning
- SMB Relay (this repo)
- Pass-the-Hash
- Kerberoasting
- Lateral Movement

Each attack follows the same structure for repeatable detection engineering and SOC workflows.