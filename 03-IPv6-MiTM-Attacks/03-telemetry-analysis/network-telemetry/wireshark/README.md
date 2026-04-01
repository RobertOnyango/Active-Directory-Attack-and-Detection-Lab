# Network Telemetry – Wireshark (Packet Analysis)

## Overview

Wireshark provides deep packet-level visibility, enabling analysis of protocol behavior and detection of network manipulation techniques.

In this lab, Wireshark was used to:
- Identify IPv6-based attack mechanisms
- Analyze DNS and name resolution behavior
- Validate WPAD abuse and network positioning

---

## Key Observations

### 1. Rogue IPv6 Router Advertisements

- ICMPv6 Router Advertisements observed
- Sent to multicast address: `ff02::1`

#### Insight:
- Confirms rogue host acting as IPv6 router
- Enables automatic client configuration
- Foundation for MITM positioning

---

### 2. DHCPv6 Activity

- Clients request and accept IPv6 configuration

#### Insight:
- Confirms attacker-controlled network configuration
- Indicates successful IPv6 takeover

---

### 3. DNS Manipulation

- Rogue host (`192.168.4.11`) performs DNS queries
- Communicates with external server

#### Insight:
- Host acting as DNS intermediary
- Indicates influence over name resolution

---

### 4. Multicast Name Resolution

- Presence of:
  - LLMNR
  - mDNS

#### Insight:
- Triggered by DNS resolution failure
- Enables attacker to respond to name queries
- Facilitates credential interception

---

### 5. WPAD Discovery

- HTTP request for `wpad.dat` observed

#### Insight:
- Triggered by name resolution instability
- Used to:
  - Redirect traffic
  - Coerce NTLM authentication

---

## Correlation with Host-Based Evidence

- Network activity explains:
  - How credentials were exposed
- Splunk confirms:
  - Successful authentication and exploitation

---

## Detection Value

Wireshark provides:
- Visibility into:
  - IPv6 control-plane manipulation
  - Protocol-level behavior
- Ability to:
  - Identify root cause of attack

---

## Limitations

- Does not directly confirm:
  - Authentication success
  - Directory changes

- Requires:
  - SIEM correlation (Splunk)

---

## SOC Relevance

- IPv6 is often unmonitored but critical  
- Rogue Router Advertisements are high-risk indicators  
- DNS anomalies and fallback protocols signal attack conditions  
- Packet analysis is essential for uncovering hidden attack paths  

---
