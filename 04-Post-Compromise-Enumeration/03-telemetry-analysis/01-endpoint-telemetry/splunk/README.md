## Endpoint Telemetry Analysis (Splunk)

Endpoint telemetry collected and analyzed in Splunk Enterprise provided the deepest visibility into the post-compromise enumeration activity performed during the lab. While network telemetry identified reconnaissance and scanning behavior, host-based telemetry revealed the actual execution chain associated with remote access and enumeration.

The investigation identified the following key attack artifacts:

- NTLM-authenticated network logons originating from the attacker-controlled host `192.168.4.11`.
- Logon Type 3 (Network) authentication events targeting Desktop-1.

![alt text](<Figure 47.png>)

- Creation of `wsmprovhost.exe`, indicating the establishment of a WinRM remote PowerShell session.

![alt text](<Figure 60.png>)

- Parent-child process relationships showing remote execution of:
  - `whoami.exe`
  - `hostname.exe`
  - `systeminfo.exe`
  - `ipconfig.exe`
  - `net.exe`
- PowerShell execution policy bypass attempts.

![alt text](<Figure 67.png>)

- File creation artifacts associated with `PowerView.ps1` and `SharpHound`.

The investigation timeline reconstructed from Windows Event Logs and Sysmon telemetry showed the following attack progression:

```text
NTLM Network Logon
        ↓
wsmprovhost.exe Created
        ↓
Remote PowerShell Session Established
        ↓
Reconnaissance Commands Executed
        ↓
PowerShell Activity
        ↓
PowerView / SharpHound Artifacts Observed
```

One of the most significant findings during the investigation was the visibility gap between process execution and in-memory tooling. While Sysmon successfully captured file creation artifacts associated with PowerView and SharpHound, the investigation could not conclusively confirm successful execution of the tools through Windows Event Logs alone. This highlighted an important operational limitation in default Windows logging configurations, particularly for in-memory PowerShell-based tooling and failed LDAP enumeration attempts.

The investigation also demonstrated the value of correlating:
- Authentication telemetry
- Process creation logs
- Parent-child process relationships
- Sysmon file creation events
- PowerShell activity

to reconstruct attacker behavior on compromised systems.

Overall, endpoint telemetry proved significantly more valuable than network telemetry for understanding the attacker’s post-compromise actions within the Active Directory environment.