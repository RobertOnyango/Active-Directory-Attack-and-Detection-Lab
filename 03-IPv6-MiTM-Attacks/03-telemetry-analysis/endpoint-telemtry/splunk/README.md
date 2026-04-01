# Endpoint Telemetry – Splunk (Windows Security Logs)

## Overview

Splunk provides visibility into host-based activity through Windows Security Logs, enabling detection of authentication events and Active Directory modifications.

In this lab, Splunk was used to:
- Confirm authentication activity
- Identify NTLM abuse
- Detect unauthorized directory changes

---

## Key Observations

### 1. NTLM Authentication from Suspicious Host

- Source IP: `192.168.4.11`
- Target: `DESKTOP-1`
- Event ID: **4624 (Successful Logon)**
- Authentication Package: **NTLM**
- Logon Type: **3 (Network)**

#### Insight:
- NTLM used from unexpected host
- No corresponding Kerberos activity
- Consistent with relay-based authentication

---

### 2. Computer Object Creation

- Event ID: **4741**
- Object: `JFGZCWKA$`

#### Insight:
- Indicates unauthorized domain join
- Likely abuse of Machine Account Quota
- Strong indicator of post-authentication exploitation

---

### 3. Password Reset Activity

- Event ID: **4724**
- Initiated by: `DESKTOP-1$`

#### Insight:
- Workstation accounts should not perform password resets
- Suggests:
  - Delegated permission abuse
  - Relayed privileged context

---

### 4. User Account Creation

- Event ID: **4720**

#### Insight:
- Indicates privilege escalation
- Confirms compromise of privileged credentials

---

## Timeline Correlation

Observed sequence:
1. NTLM authentication (4624)  
2. Computer object creation (4741)  
3. Password reset (4724)  
4. User account creation (4720)  

#### Insight:
- Rapid sequence indicates automated attack execution
- Strongly aligned with NTLM relay behavior

---

## Detection Value

Splunk provides:
- High-fidelity detection of:
  - Authentication anomalies
  - Privileged operations
- Visibility into:
  - Active Directory changes
  - Identity misuse

---

## Limitations

- Cannot directly observe:
  - Credential interception (network-level)
  - WPAD or proxy abuse

- Requires correlation with:
  - Network telemetry (Suricata, Wireshark)

---

## SOC Relevance

- NTLM authentication from unexpected sources is high risk  
- Workstation accounts performing privileged actions is a strong anomaly  
- Rapid authentication → AD modification sequence is a key detection pattern

---
