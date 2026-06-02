# Splunk Alerts and Investigations

## Splunk Alerts

One of the most valuable outcomes of the previous Detection Engineering exercises was the creation of a rule designed to identify hosts performing NTLM-only authentication. This detection was originally developed during the IPv6 Man-in-the-Middle Attacks lab and has now proven its effectiveness by generating multiple alerts during the attack simulation.

![alt text](<Figure 14.png>)

The alerts were triggered repeatedly within a relatively short period of approximately 40 minutes. An important question immediately emerges:

> Is the same host identified by Security Onion as a suspected Kali Linux system also responsible for the NTLM-only authentication activity?


### Findings

| Source IP Address | Observation |
|------------------|-------------|
| 192.168.4.11 | Responsible for all NTLM-only authentication alerts |

![alt text](<Figure 15.png>)

---

## Splunk Investigations

The triggered alerts point to a single suspect:

```text
192.168.4.11
```

Correlating these alerts with the network telemetry observed in Security Onion confirms that the host previously identified as a Kali Linux attack machine is also responsible for the NTLM-only authentication activity observed throughout the domain environment.

The search query in the screenshot above groups computer names and account names by source IP address, allowing investigators to identify authentication patterns associated with a specific host.

### Findings

- The attacker successfully authenticated to multiple systems using NTLM authentication.
- Multiple domain systems were accessed from the same source IP address.
- Authentication attempts were observed against both workstations and the Domain Controller.

This activity is highly indicative of credential abuse and lateral movement.

> **Note:** The observed `ANONYMOUS_LOGON` and null (`-`) account name entries are commonly generated during SMB negotiation, NTLM authentication setup, and network enumeration activity associated with tools such as CrackMapExec and Impacket.

---

## Investigate All Successful Logons

The previous investigation revealed successful authentication activity by the compromised user account `ronyango` against all three domain systems.

The next step is to establish whether any additional user or computer accounts successfully authenticated during the same timeframe.

```spl
index="windowseventlogs" EventCode=4624 Authentication_Package=NTLM Logon_Type=3
```

### Findings

![alt text](<Figure 21.png>)

The following account names were identified:

- DC$
- Desktop-1$
- Desktop-2$
- jrogan
- ronyango

The machine accounts were investigated first.

The results revealed expected behavior for all three systems:

- Authentication Package: Kerberos
- Logon Type: 3 (Network)
- Source Network Address: Expected internal IP addresses
- No activity originating from 192.168.4.11

These findings indicate normal machine-to-machine communications.

---

## Investigate the Compromised User's Successful Logons

The Splunk alerts specifically highlighted the user account **ronyango**. We begin by filtering oput all the successful logons associated using the query:

```
index="windowseventlogs" Account_Name="ronyango" EventCode=4624 Logon_Type=3
```

The results to the query reveals both Kerberos and NTLM authentication activity.

The Kerberos logons were reviewed first using the query:

```spl
index="windowseventlogs" Account_Name="ronyango" EventCode=4768
```

### Findings

- Kerberos authentication activity appears normal.
- No suspicious source IP addresses observed.
- Authentication patterns align with expected user activity.

Attention then shifted to NTLM-authenticated logons.

```spl
index="windowseventlogs" Account_Name="ronyango" Authentication_Package=NTLM EventCode=4624
```

### Findings

- The user successfully authenticated to all domain systems.
- All logons occurred using Logon Type 3 (Network).
- The source IP address for every NTLM-authenticated session was:

```text
192.168.4.11
```

- The user is not expected to authenticate to multiple systems in this manner.

### Conclusion

At this stage of the investigation, we can confirm that the malicious actor successfully gained unauthorized access to multiple systems using the compromised credentials belonging to `ronyango`.

---

## Investigate the Malicious Actor's Activity

The next step is to investigate the activities performed by the compromised account following successful authentication.

```spl
index="windowseventlogs" Account_Name="ronyango"
```

![alt text](<Figure 25.png>)

Reviewing the EventCode field reveals the following Windows Security Events.

| Event ID | Description |
|-----------|------------|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4634 | Logoff |
| 4656 | Handle to an object requested |
| 4688 | Process creation |
| 4689 | Process termination |
| 4768 | Kerberos TGT requested |
| 5379 | Credential Manager credentials read |

---

## Investigate Credential Access Activity

Event ID 5379 indicates that stored credentials within Windows Credential Manager were accessed.

```spl
index="windowseventlogs" Account_Name="ronyango" EventCode=5379
```

### Findings

![alt text](<Figure 27.png>)

- Read Operation: Enumerate Credentials
- Credential Manager access observed during the attack window.

This suggests that stored credentials were accessed during the investigation timeframe.

---

## Correlate Process Creation and Credential Access

To determine whether malicious tooling was responsible for reading credentials, Event ID 4688 (Process Creation) was correlated with Event ID 5379 (Credential Access).

```spl
index="windowseventlogs" Account_Name="ronyango" (EventCode=4688 OR EventCode=5379)
```

### Findings

![alt text](<Figure 28.png>)

- No suspicious processes were identified.
- Only normal Windows background processes were observed.
- No offensive tooling was visible in the process creation telemetry.

---

## Correlate NTLM Logons, Process Creation, and Credential Enumeration

Attempt to identify process execution following successful NTLM authentication.

```spl
index="windowseventlogs" Account_Name="ronyango" ((EventCode=4624 Authentication_Package=NTLM Logon_Type=3) OR (EventCode=5379 OR EventCode=4688))
| eval event_type=case(EventCode=4624, "NTLM Network Logon", EventCode=4688, "Process Created", EventCode=5379, "Credentials Enumerated")
| transaction ComputerName Account_Name maxspan=5m
| where event_type="NTLM Network Logon" and event_type="Process Created"
| table _time ComputerName Account_Name Source_Network_Address event_type New_Process_Name Creator_Process_Name
```

### Findings

![alt text](<Figure 29.png>)

- No suspicious process activity was observed.
- No offensive tooling was identified.
- The process list consisted entirely of legitimate Windows processes.

---

## Investigate Whether Credentials Were Read During the Same NTLM Session

To determine whether credential access occurred within the same authenticated session established by the attacker, Event ID 4624 was correlated with Event ID 5379 using the Windows Logon ID.

```spl
index="windowseventlogs" ((Account_Name="ronyango" EventCode=4624 Authentication_Package=NTLM Logon_Type=3) OR EventCode=5379)
| stats values(EventCode) as EventCodes values(Account_Name) as Accounts values(ComputerName) as Hosts values(Source_Network_Address) as SourceIPs min(_time) as FirstSeen max(_time) as LastSeen by Logon_ID
```

### Findings

![alt text](<Figure 30.png>)

No shared Logon IDs were identified.

### Conclusion

Correlation of Event ID 4624 and Event ID 5379 did not reveal any NTLM-authenticated sessions in which Credential Manager access also occurred. While NTLM-only authentication activity was observed from the malicious host, the available telemetry does not demonstrate credential access occurring within the same authenticated session.

---

## Pivot to Object Access Requests

During the investigation, a noticeable increase in Event ID 4656 activity was observed.

Event ID 4656 indicates that a handle to an object was requested.

```spl
index="windowseventlogs" EventCode=4656
```

### Findings

![alt text](<Figure 33.png>)

- The dominant permission requested was `DELETE`.
- Account names included:
  - Desktop-1$
  - Desktop-2$
  - ronyango
- The dominant Logon ID was:

```text
0x3E7
```

- Object Types included:
  - SAM_SERVER
  - SAM_DOMAIN

### Process Analysis

The majority of requests originated from:

- lsass.exe
- taskhostw.exe
- MsMpEng.exe

LSASS accounted for over 80% of the observed activity.

### Conclusion

The findings reveal multiple requests against Security Account Manager (SAM) objects, including `SAM_SERVER` and `SAM_DOMAIN` object types. Most of the observed activity originated from legitimate Windows processes and machine accounts. At this stage, the evidence is insufficient to directly attribute the activity to the attacker or the compromised account.

The next step is therefore to determine whether any of the observed SAM object requests occurred within authenticated NTLM sessions established by the compromised account.

---

## Investigate the Compromised User's Object Requests

The majority of Event ID 4656 activity was associated with machine accounts and the SYSTEM Logon ID (`0x3E7`).

Attention was therefore shifted to the two events associated with the compromised account:

```text
ronyango
```

### Findings

![alt text](<Figure 40.png>)

- Two Event ID 4656 events identified.
- One event occurred on Desktop-1.
- One event occurred on Desktop-2.
- Object Name: SAM
- Process Name: lsass.exe
- Access Requested: DELETE

Event ID 4656 only records the request for access and does not confirm that the requested operation was ultimately performed.

### Conclusion

Although the observed activity is consistent with normal Windows authentication behavior, the requests occurred within the security context of the compromised account and therefore warrant additional investigation.

---

## Correlate the SAM Object Access Request and NTLM-Only Logon Session

First, identify shared Logon IDs between Event ID 4624 and Event ID 4656.

```spl
index="windowseventlogs" EventCode=4656 OR EventCode=4624
| stats values(EventCode) as EventCodes values(Account_Name) as Accounts by Logon_ID
```

Count the number of events where a Logon ID was used more than once between Event IDs 4624 and 4656.

```spl
index="windowseventlogs" Account_Name=ronyango (EventCode=4656 OR (EventCode=4624 Authentication_Package=NTLM Logon_Type=3))
| stats count values(EventCode) as EventCodes values(ComputerName) as Hosts values(Object_Name) as Objects values(Process_Name) as Processes values(Accesses) as AccessRights min(_time) as FirstSeen max(_time) as LastSeen by Logon_ID
| where count>1
```

Count the distinct Event IDs associated with each Logon ID. 
```
index="windowseventlogs" Account_Name=ronyango (EventCode=4656 OR (EventCode=4624 Authentication_Package=NTLM Logon_Type=3))
| stats values(EventCode) as EventCodes values(ComputerName) as Hosts values(Account_Name) as Account values(Source_Network_Address) as SourceIP values(Object_Name) as Objects values(Process_Name) as Processes values(Accesses) as AccessRights min(_time) as FirstSeen max(_time) as LastSeen by Logon_ID
| where mvcount(EventCodes)>1
```

### Findings

![alt text](<Figure 41.png>)

The results show that:

- DELETE access was requested against SAM objects.
- The requests occurred under the security context of `ronyango`.
- The requests were performed by `lsass.exe`.
- The activity occurred on both Desktop-1 and Desktop-2.
- The requests occurred within authenticated NTLM logon sessions.

### Investigation Conclusion

While the available telemetry does not confirm direct access to the underlying SAM registry hive or credential dumping activity, it does demonstrate interaction with the Security Account Manager subsystem following successful NTLM authentication.

When combined with the earlier NTLM logon evidence and successful authentication across multiple systems, these findings provide strong evidence of credential abuse and lateral movement by the malicious actor throughout the Active Directory environment.