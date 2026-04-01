# Detection Notes – IPv6 MitM (mitm6 + NTLM Relay)

## Overview

This document outlines the detection strategy for the IPv6 Man-in-the-Middle (mitm6) and NTLM relay attack chain. The attack leverages IPv6 auto-configuration, WPAD abuse, and NTLM authentication to perform unauthorized Active Directory operations.

Detection is structured across three layers:
- Network telemetry (Suricata, Wireshark)
- Authentication telemetry (Splunk)
- Active Directory activity (Splunk)

---

## Detection Approach

This attack cannot be reliably detected using a single alert. Instead, it requires correlating multiple weak signals across different layers of the environment.

Key principle:

> Detection should focus on behavioral anomalies and sequence of events rather than individual indicators.

---

## Attack Chain Mapping to Detection

| Stage | Technique | Detection Signal |
|------|----------|------------------|
| Initial Access | Rogue host joins network | DHCP hostname anomaly (Suricata) |
| Positioning | IPv6 Router Advertisement | ICMPv6 RA detection |
| Configuration | DHCPv6 interaction | DHCPv6 Solicit/Request |
| Manipulation | DNS influence | DNS queries to non-approved servers |
| Degradation | DNS failure fallback | LLMNR / mDNS traffic |
| Coercion | WPAD abuse | HTTP request for `wpad.dat` on proxy |
| Credential Access | NTLM authentication | NTLM-only authentication detection |
| Exploitation | AD object creation | Event IDs 4741, 4720 |
| Impact | Privileged activity | NTLM → AD modification correlation |

---

## Key Detection Strategies

### 1. IPv6 Control Plane Visibility

- Detect ICMPv6 Router Advertisements
- Detect DHCPv6 activity following RA

#### Insight:
IPv6 introduces a hidden control plane that can override network configuration without user interaction.

---

### 2. DNS Behavior Monitoring

- Detect DNS queries to non-approved servers
- Detect increase in multicast name resolution (LLMNR, mDNS)

#### Insight:
DNS manipulation and degradation are critical precursors to WPAD abuse.

---

### 3. WPAD and Proxy Abuse

- Detect `wpad.dat` requests
- Correlate with DNS anomalies

#### Insight:
WPAD is used as an authentication coercion mechanism rather than a payload delivery vector.

---

### 4. NTLM Authentication Analysis

- Detect NTLM-only authentication patterns
- Identify absence of Kerberos usage

#### Insight:
In Active Directory environments, Kerberos should dominate authentication. NTLM-only behavior is a strong anomaly.

---

### 5. Identity and Source Mismatch

- Compare `Source_Network_Address` with expected host
- Identify authentication originating from unexpected systems

#### Insight:
NTLM relay causes authentication to appear from the attacker’s host rather than the victim system.

---

### 6. Privileged Activity Correlation

- Detect:
  - Computer object creation (4741)
  - User account creation (4720)

- Correlate with preceding NTLM authentication

#### Insight:
Immediate privileged actions following authentication are a strong indicator of relay-based exploitation.

---

### 7. Multi-Source Authentication Patterns

- Detect multiple source IPs authenticating to a single host

#### Insight:
May indicate credential reuse, relay activity, or lateral movement.

---

## Detection Limitations

- NTLM authentication is not inherently malicious
- IPv6 traffic is often not monitored in enterprise environments
- Some detections are environment-specific (e.g., DNS server configuration)
- Legitimate administrative activity may resemble attack behavior

---

## Correlation is Critical

High-confidence detection requires combining:

- Network signals:
  - RA, DHCPv6, WPAD
- Authentication signals:
  - NTLM logons
- Directory activity:
  - Object creation events

---

## Detection Model

### Weak Signals (Individually Low Confidence)

- WPAD request
- NTLM authentication
- LLMNR traffic

---

### Strong Signals (When Correlated)

- NTLM authentication from unexpected source  
- Followed by AD object creation  
- Within a short time window  

---

## High-Confidence Indicator

> NTLM network authentication followed immediately by Active Directory modification from the same source

This pattern has:
- Low false positives
- High relevance to credential relay attacks

---

## Key Takeaways

- IPv6 introduces attack paths that bypass traditional IPv4 monitoring  
- NTLM relay attacks rely on protocol behavior rather than exploitation  
- Detection should focus on:
  - Authentication anomalies  
  - Identity mismatches  
  - Behavioral sequences  

---

## Conclusion

The IPv6 MitM attack demonstrates how multiple low-severity signals can combine into a high-impact compromise.

Effective detection requires:
- Cross-layer visibility  
- Protocol-level understanding  
- Correlation of network and host-based telemetry  

This approach aligns with real-world SOC operations, where attackers evade single-point detections but expose themselves through behavioral patterns.