# Detection Notes – Pass the Password / Pass the Hash

## Attack Summary

The attacker leveraged previously compromised domain credentials to authenticate to multiple systems within the Active Directory environment using NTLM authentication. Following successful authentication, the attacker attempted to enumerate accessible systems, extract credential material, and move laterally across the network using SMB-based administrative services.

Some aspects of the activities in detail included:

- NTLM-only network authentication
- Credential reuse across multiple hosts
- SMB-based lateral movement attempts
- Security Account Manager (SAM) object access requests
- Credential enumeration activity
- Attempts to dump local credential material using SecretsDump
- Pass the Password and Pass the Hash authentication attempts

The investigation relied heavily on correlating:

- Security Onion alerts
- Wireshark packet captures
- Windows Event Logs
- Splunk detections
- Authentication telemetry
- Object access telemetry

---

## Key Findings

| Artifact | Observation |
|---|---|
| Rogue Host | Kali Linux attacker host identified at `192.168.4.11` |
| Authentication Activity | NTLM-only network logons (Event ID 4624, Logon Type 3) |
| Credential Abuse | Successful authentication using the compromised account `ronyango` |
| Lateral Movement | Authentication observed across Desktop-1, Desktop-2, and the Domain Controller |
| Credential Access | Credential Manager enumeration activity (Event ID 5379) |
| Object Access | Security Account Manager (SAM) object access requests (Event ID 4656) |
| Process Activity | `lsass.exe` responsible for SAM object requests |
| Network Activity | Repeated SMB connection attempts targeting TCP port 445 |
| Packet Analysis | TCP SYN packets and retransmissions from the attacker host |

---

## Detection Opportunities

### NTLM Authentication to Multiple Hosts

Detect source IP addresses authenticating to multiple systems using NTLM network logons.

```spl
index="windowseventlogs" EventCode=4624 Authentication_Package=NTLM Logon_Type=3
| stats values(Account_Name) as Credentials_Used values(ComputerName) as Devices_Accessed dc(ComputerName) as Host_Count by Source_Network_Address
| where Source_Network_Address!="-" AND Host_Count > 1
| sort - Host_Count
```

---

### Authentication Activity from Non-Management Hosts

Detect systems that are not designated management hosts authenticating to multiple devices.

```spl
index="windowseventlogs" (EventCode=4624 OR EventCode=4625)
| stats values(EventCode) as Auth_Events values(Account_Name) as Credentials_Used values(ComputerName) as Devices_Probed dc(ComputerName) as Host_Count by Source_Network_Address
| where Source_Network_Address!="-" AND Source_Network_Address!="192.168.4.10" AND Host_Count > 1
```

---

### Sensitive Object Access Following NTLM Authentication

Detect sensitive object access requests occurring within authenticated NTLM sessions.

```spl
index="windowseventlogs" Account_Name=ronyango (EventCode=4656 OR (EventCode=4624 Authentication_Package=NTLM Logon_Type=3))
| stats values(EventCode) as EventCodes values(ComputerName) as Hosts values(Account_Name) as Account values(Source_Network_Address) as SourceIP values(Object_Name) as Objects values(Process_Name) as Processes values(Accesses) as AccessRights min(_time) as FirstSeen max(_time) as LastSeen by Logon_ID
| where mvcount(EventCodes)>1
```

---

## Mitigation Recommendations

- Disable NTLM authentication where operationally feasible and enforce Kerberos authentication.
- Implement Microsoft LAPS or Windows LAPS to prevent local administrator password reuse.
- Restrict local administrator privileges using least privilege principles.
- Limit SMB administrative access to approved management systems.
- Segment administrative systems from user workstations.
- Monitor NTLM authentication activity across the environment.
- Audit access requests against Security Account Manager (SAM) objects.
- Enable advanced Windows auditing for object access and credential access events.
- Restrict and monitor the use of remote administration protocols.
- Implement Privileged Access Management (PAM) solutions for sensitive accounts.

---

## Lessons Learned

- NTLM-only authentication remains a valuable indicator of credential abuse and lateral movement.
- Successful authentication to multiple hosts from a single source system can provide early evidence of Pass the Password and Pass the Hash attacks.
- Correlation of authentication events and object access telemetry significantly improves investigation accuracy.
- Security Onion provided the initial indicator of compromise, while Splunk Enterprise supplied the strongest evidence of credential abuse and lateral movement.
- Packet captures alone did not provide sufficient evidence of credential dumping activity, highlighting the importance of host-based telemetry during post-compromise investigations.
- Monitoring sensitive object access requests can provide additional context when investigating credential-based attacks within Active Directory environments.