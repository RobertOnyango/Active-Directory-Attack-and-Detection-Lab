# Detection Engineering

## Overview

The investigation revealed several indicators of compromise associated with credential abuse and lateral movement within the Active Directory environment. While Security Onion generated the initial alert, Windows Event Logs collected by Splunk Enterprise provided the strongest evidence of NTLM authentication abuse, cross-host access, and interaction with sensitive Windows security objects.

The following detection rules were developed from the investigation findings to identify similar Pass the Password, Pass the Hash, and credential-based lateral movement attacks.

---

## Alert on Source IPs Authenticating to Multiple Hosts Using NTLM

This rule identifies source IP addresses that successfully authenticate to multiple hosts using NTLM network logons (Event ID 4624, Logon Type 3).

In most environments, legitimate users only access a small number of systems during a short time period. Attackers performing Pass the Password or Pass the Hash attacks often reuse stolen credentials across multiple hosts in rapid succession.

### Detection Rule

```spl
index="windowseventlogs" EventCode=4624 Authentication_Package=NTLM Logon_Type=3
| stats values(Account_Name) as Credentials_Used values(ComputerName) as Devices_Accessed dc(ComputerName) as Host_Count by Source_Network_Address
| where Source_Network_Address!="-" AND Host_Count > 1
| sort - Host_Count
```

### Detects

- Pass the Password attacks
- Pass the Hash attacks
- Credential replay attacks
- NTLM-based lateral movement

### Investigation Value

- Identifies a single host authenticating to multiple systems.
- Highlights credential reuse activity.
- Helps investigators identify the initial source of lateral movement.

---

## Alert on Authentication Activity from Non-Management Hosts

This rule identifies systems performing authentication activity against multiple hosts when they are not expected to function as management systems.

In well-segmented environments, administrative activity typically originates from management workstations, jump servers, or Domain Controllers. Workstations and user devices rarely authenticate to multiple systems within a short timeframe.

For this lab, the Domain Controller (`192.168.4.10`) is treated as the designated management host and is excluded from the detection logic.

### Detection Rule

```spl
index="windowseventlogs" (EventCode=4624 OR EventCode=4625)
| stats values(EventCode) as Auth_Events values(Account_Name) as Credentials_Used values(ComputerName) as Devices_Probed dc(ComputerName) as Host_Count by Source_Network_Address
| where Source_Network_Address!="-" AND Source_Network_Address!="192.168.4.10" AND Host_Count > 1
```

### Detects

- Unauthorized lateral movement
- Workstation-to-workstation authentication
- Credential abuse activity
- Internal reconnaissance

### Investigation Value

- Identifies non-management systems authenticating across the environment.
- Highlights unusual authentication patterns.
- Assists with lateral movement investigations.

---

## Alert on Object Access Requests During NTLM-Authenticated Sessions

This rule correlates successful NTLM-authenticated logons with sensitive object access requests using the Windows Logon ID.

The objective is to determine whether sensitive object interactions occurred within the same authenticated session established by a potentially compromised account.

### Detection Rule

```spl
index="windowseventlogs" Account_Name=ronyango (EventCode=4656 OR (EventCode=4624 Authentication_Package=NTLM Logon_Type=3))
| stats values(EventCode) as EventCodes values(ComputerName) as Hosts values(Account_Name) as Account values(Source_Network_Address) as SourceIP values(Object_Name) as Objects values(Process_Name) as Processes values(Accesses) as AccessRights min(_time) as FirstSeen max(_time) as LastSeen by Logon_ID
| where mvcount(EventCodes)>1
```

### Detects

- Post-authentication object access
- Access to sensitive Windows security objects
- Potential credential access activity
- Suspicious NTLM-authenticated sessions

### Investigation Value

- Correlates Event ID 4624 and Event ID 4656 activity.
- Identifies sensitive object requests following authentication.
- Provides additional context during credential abuse investigations.
- Assists analysts in identifying potential post-compromise activity.

---

# Summary

These detection rules focus on three key attack behaviors observed during the investigation:

1. NTLM-authenticated access to multiple systems.
2. Authentication activity originating from non-management hosts.
3. Sensitive object access occurring within authenticated NTLM sessions.

Together, these detections provide visibility into credential abuse, Pass the Password attacks, Pass the Hash attacks, and lateral movement activity within Active Directory environments.