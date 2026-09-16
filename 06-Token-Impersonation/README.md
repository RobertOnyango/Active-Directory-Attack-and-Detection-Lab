# Token Impersonation

## 📝 Full Write-up

[Medium Article – Active Directory Attack Simulation and AI-Assisted Threat Detection with Popular SIEM Tools – Token Impersonation]

## 📌 Overview

Token Impersonation is a Windows post-exploitation technique that allows an attacker to use an existing access token belonging to another user or security context.

Rather than obtaining the user's plaintext password or password hash, the attacker abuses an existing Windows security context to perform actions with the privileges associated with that token.

This lab demonstrates how access tokens are used within Windows security architecture, how an attacker can impersonate a privileged token, and how the surrounding authentication, privilege, service, and process activity can be investigated from a defensive perspective.

The attack was simulated in an Active Directory environment and monitored with:

- **Security Onion (Sysmon / endpoint telemetry)**
- **Splunk (Windows Event Logs and Sysmon)**
- **Metasploit / Meterpreter (attack execution)**

The objective of the lab is to demonstrate:

- How Windows access tokens represent a user's security context
- How Token Impersonation can be performed during post-exploitation
- How privileged tokens can provide access without directly obtaining passwords
- The telemetry generated around token abuse
- How analysts investigate authentication and privileged activity
- Detection opportunities for SOC environments
- The limitations of Windows and Sysmon telemetry when direct token-manipulation events are not available

---

## 📂 Repository Structure

This repository is organized to reflect the lifecycle of a security investigation.

| Folder | Purpose |
|------|------|
| attack-simulation | Steps used to obtain and impersonate an existing Windows access token |
| telemetry-analysis | Windows Event Logs and Sysmon artifacts generated during the investigation |
| threat-hunting-and-investigation | Investigative queries used to reconstruct the attack sequence |
| detection-engineering | Splunk detection rules developed from the available telemetry |
| threat-mapping | MITRE ATT&CK mapping |

---

## ⚔️ Attack Simulation

The attack was performed from a Kali Linux attacker machine against a Windows workstation in the Active Directory lab environment.

The attacker first established a Meterpreter session using Metasploit's PsExec module. The PsExec-style execution technique created a temporary Windows service that executed the payload under the `NT AUTHORITY\SYSTEM` security context.

The investigation then focused on Windows access tokens and the ability to use an existing privileged security context.

### Steps

1. Attacker establishes remote execution against the Windows workstation using the Metasploit PsExec module.

2. A temporary Windows service is created through the Windows Service Control Manager.

3. The service executes the Meterpreter payload under the `NT AUTHORITY\SYSTEM` security context.

4. The attacker obtains an interactive Meterpreter session on the victim system.

5. The attacker enumerates available security contexts and access tokens.

6. The attacker identifies a privileged user token that can be used for impersonation.

7. The attacker performs Token Impersonation to operate under the selected security context.

8. Windows and Sysmon telemetry are investigated to identify authentication, privilege, service, and process activity surrounding the attack.

The lab demonstrates that Token Impersonation is fundamentally an abuse of an existing Windows security context rather than direct theft of the user's password.

---

## 📡 Telemetry Artifacts

The investigation generated observable artifacts across Windows Security Event Logs and Sysmon telemetry.

Examples include:

- Successful network logons (Event ID 4624).

- Special privileges assigned to new logon sessions (Event ID 4672).

- Credential Manager access events (Event ID 5379).

- Explicit credential usage (Event ID 4648).

- Windows service creation events (Event ID 7045).

- Sysmon process creation events (Event ID 1).

- Sysmon process termination events (Event ID 5).

- SYSTEM processes launched by `services.exe`.

- Randomly named executable files associated with temporary service execution.

- Parent-child process relationships involving `services.exe`.

- `rundll32.exe` execution associated with service-launched processes.

Artifacts were analyzed using:

- Splunk SIEM investigations.

- Windows Security Event Logs.

- Sysmon process telemetry.

- Process tree analysis.

- Event correlation and timeline analysis.

Screenshots and analysis are available in the **telemetry-analysis/** directory.

---

## 🔎 Investigation & Threat Hunting

Investigation was performed through correlation of:

- Authentication telemetry

- Privileged logon events

- Windows service creation events

- Sysmon process creation events

- Process parent-child relationships

- User security contexts

- Logon IDs

Examples include:

- Identification of successful NTLM authentication activity.

- Correlation of Event ID 4624 with Event ID 4672.

- Investigation of privileged user activity on the victim workstation.

- Identification of temporary Windows services created during the attack.

- Correlation of Event ID 7045 with Sysmon Event ID 1.

- Identification of random executable names launched by `services.exe`.

- Identification of SYSTEM-level process execution.

- Analysis of process parent-child relationships.

- Investigation of privileged-user process activity surrounding service creation.

- Timeline analysis of authentication, service creation, and process execution.

Investigation queries and analysis steps are documented in the **threat-hunting-and-investigation/** directory.

---

## 🚨 Detection Engineering

Detection rules were developed to identify the authentication, privilege, service, and process activity surrounding potential Token Impersonation.

### Splunk Detection Queries

The investigation produced three primary detection rules:

- **Detection of NTLM Logon Followed by Special Privileges**

  Identifies successful NTLM authentication followed by Event ID 4672 within a defined time window.

- **Detection of Windows Service Creation Followed by SYSTEM Process Execution**

  Correlates Event ID 7045 service creation with subsequent SYSTEM process execution through `services.exe`.

- **Detection of Suspicious Service Execution During Privileged User Activity**

  Correlates Windows service creation with privileged-user process activity occurring on the same host.

These detections are designed to identify suspicious conditions and execution sequences surrounding potential token abuse.

They should not be interpreted individually as definitive proof of Token Impersonation.

The available Windows and Sysmon telemetry did not expose a direct event representing the token transition itself. Therefore, the detection strategy focuses on correlating the surrounding security-context and process activity.

All detection logic is available in the **detection-engineering/** directory.

---

## 🛡️ Enterprise Mitigations

Recommended mitigations include:

- Apply least privilege principles to administrative accounts.

- Limit the number of users with highly privileged access.

- Implement Privileged Access Management (PAM).

- Use separate administrative accounts for privileged operations.

- Apply administrative account tiering.

- Prevent privileged accounts from logging into lower-trust workstations where possible.

- Restrict local administrator privileges.

- Monitor privileged logons and special privilege assignments.

- Monitor Windows service creation and execution.

- Monitor suspicious SYSTEM-level process creation.

- Enable appropriate Windows and Sysmon process telemetry.

- Correlate privileged-user activity with unusual service execution.

- Restrict remote administration to authorized management systems.

- Investigate unexpected processes operating under privileged security contexts.

---

## 🧑‍💻 Why This Matters

Token Impersonation demonstrates an important distinction between authentication and authorization in Windows.

An attacker does not always need to obtain a user's password to operate under that user's security context.

Once a privileged access token becomes available to an attacker, the token can potentially provide access to resources and operations according to the privileges and group memberships represented by that security context.

This makes token abuse particularly important for post-exploitation detection.

Effective detection therefore requires visibility across:

- Authentication events

- Privileged logons

- Access token security contexts

- Windows service activity

- Process creation

- Process parent-child relationships

- User and system identities

rather than relying on a single authentication event.

---

## 💻 Lab Takeaways

This lab demonstrates several real-world detection challenges:

- Windows access tokens are central to authorization decisions.

- Token Impersonation does not require the attacker to know the impersonated user's password.

- A privileged logon creates an access token containing the user's security context.

- Event ID 4672 indicates that a logon session received special privileges, but does not prove that the token was subsequently impersonated.

- Event ID 5379 indicates Credential Manager access but does not by itself demonstrate Token Impersonation.

- Windows service creation can provide a strong execution artifact when correlated with subsequent SYSTEM process creation.

- Sysmon process telemetry provides valuable visibility into process security contexts and parent-child relationships.

- Temporal proximity between privileged activity and suspicious execution provides investigative context but does not independently prove token impersonation.

- The configured Windows and Sysmon telemetry did not expose a direct event representing the token transition.

- Effective detection therefore required correlation of authentication, privilege, service, identity, and process telemetry.

---

## 🔗 MITRE ATT&CK

The investigation maps primarily to:

| Tactic | Technique | ID |
|------|------|------|
| Privilege Escalation / Defense Evasion | Access Token Manipulation: Token Impersonation/Theft | T1134.001 |
| Execution | System Services: Service Execution | T1569.002 |
| Privilege Escalation / Persistence | Create or Modify System Process: Windows Service | T1543.003 |

The detailed mapping is available in the **threat-mapping/** directory.

---

## Next Steps

This repository is part of a growing Active Directory attack & detection series, including:

- LLMNR Poisoning

- SMB Relay

- IPv6 MiTM Attacks

- Post-Compromise Enumeration

- Pass the Password / Pass the Hash

- Token Impersonation (this repo)

- Kerberoasting

- Lateral Movement

- Privilege Escalation

---