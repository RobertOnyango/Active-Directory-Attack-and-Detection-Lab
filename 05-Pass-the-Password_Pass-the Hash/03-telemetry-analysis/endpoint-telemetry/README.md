# Splunk Endpoint Telemetry Analysis

## Overview

The Splunk investigation provided the strongest evidence of credential abuse and lateral movement during the Pass the Password / Pass the Hash attack simulation. While Security Onion identified the rogue host entering the network, Windows Event Logs collected by Splunk Enterprise allowed investigators to reconstruct the attack timeline, identify the compromised account, correlate authentication activity, and investigate post-authentication behavior across multiple hosts.

---

## Alert Summary

The NTLM-only authentication detection rule generated multiple alerts during the attack window.

### Alert Details

| Field | Value |
|---------|---------|
| Alert Type | NTLM-Only Authentication |
| Source IP | 192.168.4.11 |
| Authentication Method | NTLM |
| Event ID | 4624 |
| Investigation Result | True Positive |
| Attack Phase | Credential Abuse / Lateral Movement |

### Investigation Findings

- A single source IP generated all alerts.
- The source host was identified as `192.168.4.11`.
- Security Onion previously identified the same host as a Kali Linux system.
- The host successfully authenticated to multiple systems within the domain.

### Assessment

The alert accurately identified unauthorized NTLM authentication activity originating from the attacker's workstation.

---

## Authentication Telemetry Analysis

### Event ID 4624 - Successful Logon

Event ID 4624 records successful authentication events.

#### Observed Activity

| Field | Observation |
|---------|---------|
| Authentication Package | NTLM |
| Logon Type | 3 (Network) |
| Source IP | 192.168.4.11 |
| User Account | ronyango |
| Systems Accessed | Domain Controller, Desktop-1, Desktop-2 |

#### Security Relevance

The compromised user account successfully authenticated to multiple systems from a single source host.

#### Assessment

This behavior is consistent with:

- Pass the Password attacks
- Pass the Hash attacks
- Credential replay attacks
- Lateral movement activity

---

### Event ID 4768 - Kerberos Authentication

Event ID 4768 records requests for Kerberos Ticket Granting Tickets (TGTs).

#### Observed Activity

- Kerberos activity originated from expected hosts.
- No suspicious source IP addresses were identified.
- No Kerberos activity was associated with the attacker IP.

#### Assessment

The attacker primarily relied on NTLM authentication rather than Kerberos.

This finding strengthens the conclusion that the observed activity involved credential reuse rather than normal user authentication behavior.

---

## Credential Access Telemetry

### Event ID 5379 - Credential Manager Credentials Read

Event ID 5379 indicates that stored credentials were accessed within Windows Credential Manager.

#### Observed Activity

![alt text](<Figure 27.png>)

| Field | Value |
|---------|---------|
| Event ID | 5379 |
| Operation | Enumerate Credentials |
| Account | ronyango |

#### Investigation Findings

Credential Manager access events were observed during the attack window.

#### Assessment

Credential enumeration activity may indicate attempts to identify additional credentials available on the system.

However, no direct correlation was identified between Credential Manager access and the attacker's authenticated NTLM sessions.

---

## Process Telemetry Analysis

### Event ID 4688 - Process Creation

Event ID 4688 records newly created processes.

#### Investigation Findings

Process creation events were correlated with:

- Event ID 4624
- Event ID 5379

The objective was to identify offensive tooling or suspicious processes executed shortly after authentication.

#### Observed Activity

- Standard Windows background processes.
- No offensive tooling identified.
- No suspicious parent-child process relationships observed.

#### Assessment

The available telemetry did not reveal evidence of malicious process execution associated with credential access activity.

---

## Object Access Telemetry

### Event ID 4656 - Handle to an Object Requested

Event ID 4656 records requests for access to protected Windows objects.

#### Observed Activity

![alt text](<Figure 33.png>)

| Field | Observation |
|---------|---------|
| Dominant Access Requested | DELETE |
| Dominant Process | lsass.exe |
| Object Types | SAM_SERVER, SAM_DOMAIN |
| Accounts Observed | Desktop-1$, Desktop-2$, ronyango |

#### Investigation Findings

Most object access requests originated from:

- lsass.exe
- taskhostw.exe
- MsMpEng.exe

These are expected Windows processes.

The majority of activity was associated with machine accounts and the SYSTEM Logon ID (`0x3E7`).

#### Assessment

Most observed activity is consistent with normal Windows authentication and security operations.

Further investigation was required to determine whether any object access requests occurred within attacker-controlled authentication sessions.

---

## Session Correlation Analysis

### Correlation of Event IDs 4624 and 5379

The investigation attempted to determine whether Credential Manager access occurred within the same authenticated NTLM session.

#### Findings

- No shared Logon IDs identified.
- No evidence that credentials were read during the attacker's authenticated sessions.

#### Assessment

Credential access activity cannot be directly attributed to the attacker based on the available telemetry.

---

### Correlation of Event IDs 4624 and 4656

The final stage of the investigation correlated successful NTLM authentication events with object access requests.

#### Findings

![alt text](<Figure 41-1.png>)

| Observation | Result |
|-------------|---------|
| Shared Logon IDs | Yes |
| User Account | ronyango |
| Authentication Type | NTLM |
| Object Access | SAM |
| Process | lsass.exe |
| Access Requested | DELETE |

Two events were identified:

- Desktop-1
- Desktop-2

Both occurred within authenticated NTLM sessions established by the compromised account.

#### Assessment

The telemetry demonstrates:

- Successful NTLM authentication.
- Subsequent interaction with Security Account Manager (SAM) objects.
- Activity occurring under the security context of the compromised account.

Although direct credential dumping cannot be confirmed, the telemetry strongly supports credential abuse and lateral movement activity.

---

## Key Indicators of Compromise

| Indicator | Value |
|------------|---------|
| Malicious Host | 192.168.4.11 |
| Compromised Account | ronyango |
| Authentication Method | NTLM |
| Event ID | 4624 |
| Credential Access Event | 5379 |
| Object Access Event | 4656 |
| Sensitive Object | SAM |
| Process | lsass.exe |

---

## Detection Opportunities

The investigation highlights several valuable detection opportunities.

### Authentication Monitoring

- NTLM-only authentication.
- Multiple hosts accessed from a single source IP.
- Workstation-to-workstation authentication.

### Credential Access Monitoring

- Event ID 5379.
- Credential enumeration activity.
- Abnormal Credential Manager access.

### Object Access Monitoring

- Event ID 4656.
- Access requests involving SAM objects.
- Correlation of authentication and object access events.

### Lateral Movement Detection

- Authentication to multiple hosts.
- Repeated NTLM network logons.
- Cross-host credential usage.

---

## SOC Assessment

The endpoint telemetry collected through Splunk Enterprise provided strong evidence of credential abuse and lateral movement originating from the attacker-controlled host at `192.168.4.11`. Correlation of successful NTLM authentication events, account activity, and Security Account Manager (SAM) object access requests demonstrated that the compromised account was used to access multiple systems within the Active Directory environment.

While the available telemetry did not conclusively demonstrate credential dumping activity, the combined evidence supports a finding of unauthorized access, credential misuse, and lateral movement across multiple hosts within the domain.