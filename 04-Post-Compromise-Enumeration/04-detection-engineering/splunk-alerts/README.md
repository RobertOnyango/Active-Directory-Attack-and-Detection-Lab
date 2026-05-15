## Detection Engineering

The investigation demonstrated that host-based telemetry provided the strongest visibility into the attacker’s post-compromise actions. While network telemetry successfully identified reconnaissance activity, endpoint telemetry collected in Splunk revealed the remote execution chain, PowerShell activity, and offensive tooling artifacts associated with the attack.

The following detections were developed based on the observed attacker behavior.

---

### Alert on Suspicious WinRM Sessions

The investigation revealed that remote PowerShell activity initiated through WinRM resulted in the creation of the `wsmprovhost.exe` process, followed by execution of multiple reconnaissance commands.

The following detection identifies the process spawned for the WinRM session to start:

```spl
index="windowseventlogs" EventCode=4688 Creator_Process_Name="*wsmprovhost.exe"
| stats count by ComputerName, New_Process_Name, Creator_Process_Name, Account_Name
```

This detection helps identify:
- Remote PowerShell execution
- Suspicious administrative activity
- Host enumeration commands executed remotely
- Potential lateral movement through WinRM

---

### Alert on NTLM-Only Authentication Followed by WinRM Activity

The investigation showed that the attacker system authenticated via NTLM network logons before initiating WinRM activity on the victim host.

The following correlation rule detects NTLM-authenticated network logons followed shortly afterward by WinRM-related process creation events:

```spl
index="windowseventlogs"
(
    (EventCode=4624 Logon_Type=3 Authentication_Package=NTLM)
    OR
    (EventCode=4688 Creator_Process_Name="*wsmprovhost.exe")
)
| eval event_type=case(EventCode=4624, "NTLM-Only Network Logon", EventCode=4688, "WinRM Session")
| transaction ComputerName Account_Name maxspan=5m
| where event_type="NTLM-Only Network Logon" and event_type="WinRM Session"
| table _time ComputerName Account_Name Source_Network_Address event_type New_Process_Name Creator_Process_Name
```

This behavioral detection improves visibility into:
- Unauthorized remote management activity
- NTLM fallback authentication
- Potential lateral movement
- Remote command execution chains

The rule demonstrates the value of correlating authentication telemetry with process creation events instead of relying solely on single-event detections.

---

### Alert on Offensive Tool Uploads

Sysmon telemetry identified file creation artifacts associated with PowerView and SharpHound uploads onto the victim host.

The following detection identifies creation or upload of common Active Directory enumeration tooling:

```spl
index="sysmon" EventCode=11 (TargetFilename="*PowerView*" OR TargetFilename="*SharpHound*")
```

This detection helps identify:
- Upload of offensive tooling
- Potential Active Directory enumeration preparation
- Suspicious PowerShell-based attack tooling
- Early indicators of post-compromise activity

The investigation did not conclusively confirm successful execution of the tools. However, the upload artifacts, combined with the surrounding WinRM and PowerShell telemetry, strongly suggested attempted deployment of Active Directory enumeration tooling within the environment.