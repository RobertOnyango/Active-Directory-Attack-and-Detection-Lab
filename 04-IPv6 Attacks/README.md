# IPv6 Attacks

## 📝 Full Write-up

[Medium Article – Active Directory Attack Simulation and AI-Assisted Threat Detection with Popular SIEM Tools – Part 4]()

## 📌 Overview
IPv4 networks can and are compromised via IPv6, for example the Man-in-The-Middle attack that abuses the default IPv6 configuration in Windows networks to spoof DNS replies by acting as a malicious DNS server and redirecting traffic to an attacker specified endpoint. The second phase of this attack exploits the Windows Proxy Auto Discovery (WPAD) feature in order to relay credentials and authenticate to various services within the network.

This lab illustrates the use of the **mitm6 tool** that spoofs an IPv6 DNS server for the specified domain by sending rogue router advertisements via ICMPv6 such that all the Windows clients in the environment request IPv6 configuration via DHCPv6 from the attacker. The rogue server replies in kind to these DHCPv6 requests, assigning the victims IPv6 addresses within its link-local range and its IPv6 address as the victims default DNS server. This leads to any attempts by the victims to access the internet to go through the attacker, who is the MiTM, which results in NTLM credentials leak and capture by **Responder**, information discloure and privilege escalation.

The lab will also demonstrate the incident response procedure i.e. the cues to lookout for in a SIEM and at network protocol level then finally explore realistic detection strategies.

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
- mitm6 tool is positioned as the default IPv6 DNS server for the domain after sending ICMPv6 router advertisements.
- Client action is abused via WPAD over IPv6, taking advantage of the new default DNS server.
- Responder captures and relays NTLM credentials successfully.
- Information disclosure after unauthorized access.
- Privilege escalation to gaining domain control and persistence.

**Step 2: Evidence Collection**
- 

**Step 3: Detection and Analysis**
- 

**Step 4: Enterprise Recommendations**
- 

## Next Steps
This repository is part of a growing Active Directory attack & detection series, including:
- LLMNR Poisoning
- SMB Relay
- IPv6 Attacks (this repo)
- Pass-the-Hash
- Kerberoasting
- Lateral Movement

Each attack follows the same structure for repeatable detection engineering and SOC workflows.