Alert in Splunk that fired: Host authentication with NTLM-auth only, no Kerberos involved <defense 3>

Filter the Source Ip and confirm the succcessful logons on NTLM-only authentication on the domain machine desktop-1. <defense 4>

Important to observe the timestamps of the events: (These will come ion handy later) <defense 5>
- 9:55 - 9:59AM
- 11:45AM
- 3:15PM - 3:16PM

**First artifact**: Malicious IP Address 192.168.4.11 authenticating to domain host using NTLM-auth only.

Proceed to add Desktop-1 to the search filer and examine the extracted fields. Too many events returned, proceed t use the timestamps. <defense 6>

The alert gave us a clue: Account name that was used to logon to Desktop-1. Proceed to add it to the search and examine the EventCodes. <defense 7>

We see the following EventCodes:

| Code | Description |
|-----|-----|
| 4688 | A new process has been created |
| 4689 | A process has exited/terminated |
| 5379 | Credentials stored in the Windows Credential Manager are read |
| 4624 | A successful account logon |
| 4634 | User account logon session was terminated and no longer exists |

Proceed  to confirm whether the EventCode 5379 was recorded during the insecure NTLM authenticated session. We see that each Credential Manager read had a different Logon_ID while the logons themselves i.e. EventCode 4624 share the LogonId 0x57EA0. <defense 8>

Move to the next phase of the investigation where filter for the LogonId identified for the insecure logons above in the Sysmon Logs. <defense 9>

We see the following findings:
- One common user, ronyango, as expected for all the logs filtered out. <defense 10>

- The commands used to start the processes during this session in the CommandLine field. <defense 11>

- "whoami" is a common enumeration command. Filter it out to see the ParentImage, **cmd.exe**. <defense 12>


