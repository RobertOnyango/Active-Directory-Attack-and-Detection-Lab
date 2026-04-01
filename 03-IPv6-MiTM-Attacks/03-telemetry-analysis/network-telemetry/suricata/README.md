# Network Telemetry – Suricata

## Overview

Suricata provides network-based detection by analyzing packet flows and generating alerts based on known signatures and protocol anomalies.

In this lab, Suricata (via Security Onion) was used to detect suspicious activity related to:
- Unauthorized host presence
- WPAD abuse
- Potential proxy-based credential coercion

---

## Key Observations

### 1. Suspicious DHCP Hostname

- Alert: **Possible Kali Linux hostname in DHCP request packet**
- Source: `192.168.4.11`
- Protocol: DHCP (UDP 68 → 67)

#### Insight:
- Detection based on hostname pattern ("kali")
- Indicates presence of attacker-controlled system on internal network

---

### 2. WPAD Discovery Activity

- Alert: **WinHttp AutoProxy Request wpad.dat Possible BadTunnel**

#### Observed Behavior:
- HTTP request for `wpad.dat`
- Response from non-standard host

#### Insight:
- WPAD triggered due to name resolution instability
- Indicates proxy auto-configuration attempt
- Potential precursor to NTLM credential coercion

---

### 3. Protocol Correlation

Observed traffic sequence:
- HTTP → WPAD request  
- SMB → authentication attempts  
- ICMP → network communication  

#### Insight:
- Multi-protocol activity aligns with credential relay attack patterns
- WPAD used as an authentication trigger

---

## Detection Value

Suricata provides:
- Early detection of attacker presence (DHCP anomaly)
- Visibility into proxy abuse (WPAD)
- Signature-based alerts for known behaviors

---

## Limitations

- Limited visibility into:
  - IPv6 control-plane abuse (RA spoofing)
  - Credential relay mechanics (NTLM relay)
- Requires correlation with:
  - Endpoint telemetry (Splunk)
  - Packet analysis (Wireshark)

---

## 🔐 SOC Relevance

- High-value alerts may appear benign without context
- Low-severity alerts (e.g., WPAD) can be critical in attack chains
- Effective use requires:
  - Alert correlation
  - Protocol-level understanding

---