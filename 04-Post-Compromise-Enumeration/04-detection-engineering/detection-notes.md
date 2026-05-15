# Detection Notes – Post-Compromise Enumeration

## Attack Summary

The attacker leveraged previously compromised domain credentials to remotely access an internal workstation using Windows Remote Management (WinRM). After establishing a remote PowerShell session, the attacker executed several low-noise reconnaissance commands to enumerate the host and surrounding Active Directory environment.

Some aspects of the activities in detail included:
- Nmap reconnaissance against remote administration services
- NTLM-authenticated network logons
- Remote PowerShell execution through `wsmprovhost.exe`
- Execution of native enumeration commands
- Upload of PowerView and SharpHound tooling

The investigation relied heavily on correlating:
- Security Onion alerts
- Wireshark packet captures
- Windows Event Logs
- Sysmon telemetry
- Splunk detections

---

# Key Findings

| Artifact | Observation |
|---|---|
| Network Reconnaissance | Nmap scans targeting RDP (`3389`) and WinRM (`5985/5986`) |
| Authentication Activity | NTLM-only network logons (Event ID 4624, Logon Type 3) |
| Remote Execution | Creation of `wsmprovhost.exe` |
| Enumeration Commands | `whoami`, `hostname`, `systeminfo`, `ipconfig`, `net.exe` |
| PowerShell Activity | Execution policy bypass activity |
| Offensive Tooling | File creation artifacts for `PowerView.ps1` and `SharpHound` |
| Packet Analysis | SYN scanning, reverse DNS lookups, incomplete WinRM/RDP connections |

---

# Detection Opportunities

## Suspicious WinRM Sessions

Detect remote PowerShell activity spawned through WinRM.

```spl
index="windowseventlogs" EventCode=4688 Creator_Process_Name="*wsmprovhost.exe"
| stats count by ComputerName, New_Process_Name, Creator_Process_Name, Account_Name
```

---

## NTLM-Only Authentication Followed by WinRM Activity

Detect NTLM-authenticated network logons followed by WinRM process creation.

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

---

## Offensive Tool Upload Detection

Detect upload or creation of common Active Directory enumeration tools.

```spl
index="sysmon" EventCode=11 (TargetFilename="*PowerView*" OR TargetFilename="*SharpHound*")
```

---

# Mitigation Recommendations

- Restrict WinRM access to approved administrative hosts.
- Disable NTLM where possible and enforce Kerberos authentication.
- Enable PowerShell Script Block Logging and Module Logging.
- Deploy Sysmon to improve process and file creation visibility.
- Monitor creation and execution of `wsmprovhost.exe`.
- Restrict outbound internet access from internal endpoints.
- Enable LDAP query logging for improved Active Directory visibility.
- Monitor upload and execution of offensive tooling.
- Apply least privilege principles across administrative accounts.

---

# Lessons Learned

- Host telemetry provided significantly deeper visibility than network telemetry during post-compromise activity.
- Packet captures alone were insufficient to reconstruct the full attack chain.
- Correlating authentication logs, process creation telemetry, Sysmon events, and IDS alerts was essential to understanding attacker behavior.
- In-memory PowerShell tooling and incomplete LDAP execution created visibility gaps within default Windows logging configurations.