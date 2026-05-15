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

The objective of the lab is to demonstrate:
- How IPv6 infrastructure abuse occurs in modern networks
- How NTLM relay attacks leverage trusted protocol behavior
- The telemetry generated during the attack lifecycle
- Detection opportunities across network and endpoint telemetry
- Challenges of detecting protocol abuse in enterprise environments

---

## 📂 Repository Structure

This repository is organized to reflect the lifecycle of a security investigation.

| Folder | Purpose |
|------|------|
| attack-simulation | Steps used to perform the IPv6 MitM attack |
| telemetry-analysis | Network and endpoint artifacts generated during the attack |
| threat-hunting-and-investigation | Investigation steps and analysis queries |
| detection-engineering | Detection rules for identifying attack behavior |
| threat-mapping | MITRE ATT&CK mapping |

---

## ⚔️ Attack Simulation

The attack was performed from a Kali Linux attacker machine using:
- `mitm6`
- `ntlmrelayx`

### Steps

1. Attacker joins the internal network and introduces itself as a rogue IPv6 DNS server using ICMPv6 Router Advertisements.
2. Victim systems automatically configure IPv6 settings through SLAAC and begin trusting the attacker-controlled host for DNS resolution.
3. Victim systems request the location of the `wpad.dat` file from the rogue DNS server.
4. Attacker responds with a malicious WPAD configuration pointing victims to an attacker-controlled proxy.
5. Victim systems attempt web access through the rogue proxy.
6. Attacker responds with `HTTP 407 Proxy Authentication Required`.
7. Windows automatically sends NTLM authentication over the network.
8. Captured NTLM authentication is relayed to the Domain Controller over LDAPS using `ntlmrelayx`.
9. Successful authentication is used to:
   - Create unauthorized computer objects
   - Create unauthorized user accounts
   - Abuse delegated Active Directory permissions

---

## 📡 Telemetry Artifacts

The attack generated observable artifacts across both network and endpoint telemetry.

Examples include:

- ICMPv6 Router Advertisements from unauthorized systems
- DHCPv6 Solicit and Request traffic
- WPAD (`wpad.dat`) discovery requests
- DNS queries sent to unauthorized DNS infrastructure
- Increased LLMNR and mDNS traffic caused by DNS instability
- NTLM-authenticated network logons (Event ID 4624 – Logon Type 3)
- New computer object creation (Event ID 4741)
- New user account creation (Event ID 4720)
- Password reset activity (Event ID 4724)

Artifacts were analyzed using:
- Suricata IDS alerts
- Splunk SIEM queries
- Wireshark packet captures

Screenshots and analysis are available in the **telemetry-analysis/** directory.

---

## 🔎 Investigation & Threat Hunting

Investigation was performed through correlation of:
- IPv6 network telemetry
- Authentication activity
- Active Directory audit logs
- Packet captures

Examples include:

- Identification of rogue IPv6 Router Advertisements
- Analysis of DHCPv6 negotiation activity
- Investigation of WPAD requests and HTTP proxy abuse
- Detection of NTLM-only authentication patterns
- Correlation of NTLM logons with Active Directory object creation
- Identification of authentication originating from unexpected source systems
- Wireshark analysis of IPv6 infrastructure abuse and DNS manipulation

Investigation queries and analysis steps are documented in the **threat-hunting-and-investigation/** directory.

---

## 🚨 Detection Engineering

Detection rules were developed to identify suspicious IPv6 infrastructure abuse and NTLM relay activity.

These are:

### Suricata Detection Rules

- Detection of ICMPv6 Router Advertisements
- Detection of DHCPv6 traffic
- Detection of WPAD discovery requests
- Detection of DNS queries to unauthorized DNS servers
- Detection of LLMNR and mDNS traffic anomalies

### Splunk Detection Queries

- NTLM-only authentication detection
- Correlation of NTLM authentication with:
  - Computer object creation
  - User account creation
- Detection of multiple source IPs authenticating to the same host

All detection logic is available in the **detection-engineering/** directory.

---

## 🛡️ Enterprise Mitigations

Recommended mitigations include:

- Disable WPAD where unnecessary
- Restrict or disable NTLM authentication
- Prefer Kerberos authentication within Active Directory
- Enable LDAP signing and channel binding
- Disable IPv6 if not required operationally
- Monitor ICMPv6 Router Advertisements
- Restrict DHCPv6 activity to approved infrastructure
- Implement network segmentation
- Monitor Active Directory object creation events
- Harden delegated permissions and ACLs

---

## 🧑‍💻 Why This Matters

IPv6 MitM attacks abuse legitimate protocol behavior rather than software vulnerabilities.

Attackers leverage:
- Automatic IPv6 configuration
- Trusted network discovery mechanisms
- Legacy NTLM authentication behavior

As a result:
- The attack can occur silently
- Traditional IPv4 monitoring may miss critical activity
- Detection requires telemetry correlation across multiple layers

rather than relying solely on traditional signature-based detections.

---

## 💻 Lab Takeaways

This lab demonstrates several real-world detection challenges:

- IPv6 introduces an often-unmonitored attack surface within enterprise environments.
- Windows systems prioritize IPv6 by default even in primarily IPv4 environments.
- NTLM relay attacks may generate minimal failed authentication activity.
- Multiple low-severity alerts can combine into a high-confidence compromise.
- Correlating network telemetry with Active Directory logs is essential for accurate investigation.

---

## Next Steps
This repository is part of a growing Active Directory attack & detection series, including:
- LLMNR Poisoning
- SMB Relay
- IPv6 Attacks (this repo)
- Post Enumeration Exploitation
- Pass-the-Hash
- Kerberoasting
- Lateral Movement

---
