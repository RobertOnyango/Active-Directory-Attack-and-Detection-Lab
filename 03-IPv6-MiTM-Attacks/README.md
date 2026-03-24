# IPv6 MiTM Attacks

## 📝 Full Write-up

[Medium Article – Active Directory Attack Simulation and AI-Assisted Threat Detection with Popular SIEM Tools – Part 4](https://robertmark94.medium.com/active-directory-attack-simulation-and-ai-assisted-threat-detection-with-popular-siem-tools-part5-ab502c7d281f)

## 📌 Overview
IPv6 introduces an often-overlooked attack surface in Windows environments where IPv4 may appear well-secured. When IPv6 is enabled by default, attackers can abuse rogue router advertisements and DNS spoofing to position themselves as a man-in-the-middle without requiring direct network compromise. This attack path enables credential interception and relay by exploiting Windows Proxy Auto Discocery (WPAD) even in networks that rely primarily on IPv4.

This lab demonstrates an IPv6 man-in-the-middle attack using the **mitm6 tool**. This tool spoofs an IPv6 DNS server for the specified domain and begins sending rogue router advertisements via ICMPv6. The result is the Windows clients in the environment request IPv6 configuration via DHCPv6 from the attacker. The rogue server replies in kind to these DHCPv6 requests by assigning the victims IPv6 addresses within its link-local range and configuring its IPv6 address as the victims default DNS server. This results in any attempts by the victims to access the internet going through the attacker, a classic MiTM scenario successfully achieved. NTLM credentials are leaked to the attacker using **Responder**. This results in credential exposure, unauthorized authentication, and privilege escalation via relay.

The final part of the lab is to illustrate the incident response procedure for such an attack in an enterprise deployment. This repo summmarises the queries used to investigate how this malicious activity manifests at both the network protocol level and within endpoint and authentication logs, enabling realistic detection strategies.

The attack was simulated in an Active Directory environment and monitored with:
- **Security Onion (Suricata IDS)**
- **Splunk (Windows Event Logs & Sysmon)**
- **Wireshark (packet analysis)**

## 📂 Detection Artifacts (Repository Structure)
- `/splunk-queries/` → SPL queries detecting anomalous NTLM network logons (Event ID 4624, Logon Type 3)
- `/pcap-examples/` → SMB negotiation and NTLM authentication packet captures (screenshots)
- `/detection-notes/` → Detection logic, limitations, and tuning considerations

---

## ⚔️ Attack Simulation

1. **Rogue IPv6 Network Injection**  
   The attacker uses `mitm6` to send malicious IPv6 Router Advertisements (RA), causing victims to automatically configure the attacker as their IPv6 DNS server.

2. **WPAD Spoofing**  
   The victim queries for `wpad` to discover proxy settings.  
   The attacker responds with a malicious WPAD (PAC) file, configuring the attacker’s machine as the system proxy.

3. **Traffic Interception via Proxy**  
   The victim routes web traffic through the attacker-controlled proxy as defined in the PAC file.

4. **Forced NTLM Authentication**  
   The attacker responds with a `407 Proxy Authentication Required` message, triggering the victim to automatically send NTLM authentication credentials.

5. **NTLM Relay to Target Service**  
   Captured NTLM authentication is relayed in real time to a target service (e.g., LDAPS on the Domain Controller) using `ntlmrelayx`.

6. **Authenticated Action Execution**  
   Depending on permissions, the attacker performs actions such as:
   - Creating a machine account (via Machine Account Quota)
   - Configuring Resource-Based Constrained Delegation (RBCD)
   - Enumerating domain information

7. **Optional Privilege Escalation**  
   If higher-privileged credentials are relayed, the attacker may:
   - Create user accounts  
   - Modify directory objects  
   - Gain elevated access within the domain

8. **Cleanup and Evasion**  
   The attacker can restore modified Active Directory attributes using generated restore files, reducing visible indicators of compromise.

---

**Step 2: Evidence Collection**
- Captured ICMPv6 Router Advertisement traffic
- Observed DHCPv6 requests and rogue DNS responses
- Identified NTLM authentication over the network using:
    - NTLMSSP NEGOTIATE
    - NTLMSSP CHALLENGE
    - NTLMSSP AUTH
- Correlated authentication activity with unexpected IPv6 source addresses
- Validated protocol-level behavior using Wireshark

**Step 3: Detection and Analysis**
- Suricata generated alerts for suspicious IPv6 and SMB activity
- Splunk identified NTLM-based network logons (Event ID 4624, Logon Type 3)
- Detected authentication from unexpected IP addresses and mismatched workstation identities
- Correlated NTLM activity with preceding IPv6 infrastructure manipulation
- Confirmed non-interactive, impersonation-based authentication indicative of relay behavior

**Step 4: Enterprise Recommendations**
- Disable IPv6 where it is not required
- Block rogue IPv6 router advertisements at the network layer
- Disable or restrict WPAD usage
- Enforce SMB signing across all systems
- Limit or phase out NTLM in Kerberos-based environments
- Monitor for NTLM authentication over the network as a high-risk signal

## Next Steps
This repository is part of a growing Active Directory attack & detection series, including:
- LLMNR Poisoning
- SMB Relay
- IPv6 Attacks (this repo)
- Pass-the-Hash
- Kerberoasting
- Lateral Movement

Each lab follows a consistent structure focused on **attack simulation, evidence collection, detection engineering, and SOC-ready analysis**.
