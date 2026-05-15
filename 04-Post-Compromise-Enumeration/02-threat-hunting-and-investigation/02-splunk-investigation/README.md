## Splunk Investigation

The Splunk investigation focused on correlating suspicious authentication activity, remote PowerShell execution, and host-based enumeration artifacts associated with the attacker-controlled IP address `192.168.4.11`.

The investigation began from a custom alert designed to identify hosts authenticating via NTLM without associated Kerberos authentication. This behavior can indicate fallback authentication, credential abuse, or remote management activity originating from unauthorized systems.

---

### Rule Optimization

The original authentication detection rule was refined by adding the `ComputerName` field to improve visibility into the destination systems being accessed.

```spl
index="windowsevenetlogs" EventCode=4624 Logon_type=3
| stats values(Authentication_Package) as auth_methods by Source_Network_Address, Account_Name, ComputerName
| where match(auth_methods, "NTLM") AND NOT match(auth_methods, "Kerberos")
```

This refinement revealed:
- The attacker-controlled IP `192.168.4.11`
- The client machine *DESKTOP-1* - `192.168.4.16`
- Multiple NTLM-authenticated network logons
- Events associated with `NT AUTHORITY\ANONYMOUS LOGON`

![alt text](<Figure 47.png>)

---

### Investigating the Client Machine Authentication Activity

Filter all successful authentication events originating from the client machine `192.168.4.16`.

```spl
index="windowseventlogs" EventCode=4624 Source_Network_Address="192.168.4.16"
```

This query was used to investigate:
- Account names involved in authentication
- Authentication packages used
- Destination systems accessed

![alt text](<Figure 48.png>)

---

### Filtering NTLM Authentication Events

The query was refined further to isolate NTLM-authenticated network logons.

```spl
index="windowseventlogs EventCode=4624 Source_Network_Address="192.168.4.16" Authentication_Package=NTLM
```

The investigation showed:
- Multiple NTLM-authenticated events
- `Account_Domain=NT AUTHORITY`
- `Account_Name=ANONYMOUS LOGON`

This behavior suggested incomplete or fallback authentication activity likely related to domain communication or enumeration attempts.

![alt text](<Figure 50.png>)

---

### Investigating the Attacker IP

Filter all logs associated with the attacker-controlled system `192.168.4.11`.

```spl
index="windowseventlogs" Source_Network_Address="192.168.4.11"
```

The results showed:
- Successful and failed authentication attempts
- Logon Type 3 (Network) activity
- Authentication events targeting Desktop-1
- NTLM authentication without associated Kerberos activity

![alt text](<Figure 52.png>)

---

### Host-Based Investigation on Desktop-1

Filter all Windows Event Logs generated on Desktop-1 during the investigation period.

```spl
index-"windowseventlogs" host="Desktop-1"
```

The investigation timeline revealed:
- Successful NTLM-authenticated network logons
- Creation of `wsmprovhost.exe`
- Subsequent execution of reconnaissance commands

![alt text](<Figure 60.png>)

---

### Investigating WinRM Activity

Filter all process creation events associated with `wsmprovhost.exe` and sort them chronologically.

```spl
index="windowseventlogs" host="Desktop-1" Creator_Process_Name="C:\\Windows\\System32\\wsmprovhost.exe"
| sort + _time
```

This investigation revealed remote execution of:
- `whoami.exe`
- `hostname.exe`
- `systeminfo.exe`
- `ipconfig.exe`
- `net.exe`

The parent-child process relationships strongly indicated remote PowerShell execution over WinRM.

![alt text](<Figure 61.png>)

---

### Sysmon Investigation

Pivot into Sysmon telemetry to gain deeper visibility into host-based activity associated with WinRM.

```spl
index="sysmon" host="Desktop-1" "C:\\Windows\\System32\\wsmprovhost.exe"
| sort + _time
```

Sysmon telemetry revealed:
- PowerShell execution
- Script execution policy bypass attempts
- File creation artifacts
- Additional process creation telemetry

![alt text](<Figure 68.png>)

---

### Investigating PowerView and SharpHound Artifacts

Search both Windows Event Logs and Sysmon telemetry for evidence of PowerView and SharpHound activity.

```spl
(index="windowseventlogs" OR index="sysmon") host="DESKTOP-1" ("*powerview*" OR "*sharphound*")
```

The investigation identified:
- Upload/file creation artifacts for `PowerView.ps1`
- Upload/file creation artifacts for `SharpHound`
- Sysmon Event ID 11 (File Creation) telemetry

However, the investigation did not conclusively confirm successful execution of the tools. This highlighted an important visibility limitation in default Windows logging, particularly for in-memory PowerShell-based tooling and failed LDAP enumeration attempts.

![alt text](<Figure 71.png>)

---
