# Spluk Queries - SMB Relay Attack

These are some of the important Splunk queries used for investigation and subsequent alerts to detect malicious activities related to or signalling SMB relay attacks.

### Filter out all the commands run on command line and PowerShell

***index="sysmon" ComputerName="DESKTOP-2.mydomain.com" (CommandLine="*cmd.exe*" OR CommandLine=*powershell.exe*)**

## Alerts

### Suspicious successfull network logons from non-domain devices

index="windowseventlogs" EventCode=4624 Logon_Type=3 Authentication_Package=NTLM AND (Source_Network_Address!="192.168.4.0/24" OR Source_Network_Address!="127.0.0.1")
| stats count(Source_Network_Address) as Exploit_Count by ComputerName, Source_Network_Address

