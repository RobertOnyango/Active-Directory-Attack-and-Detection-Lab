# Endpoint Investigation

## Overview

The page below documents the steps taken in sequence during the investigation of the Token Impersonation Attack.

---

### Alert Overview

No alert was triggered in Splunk, which raised an alarm. Investigation led to the *IPv6 MiTM Source IPs with only NTLM-auth logons (No Kerberos detected)* detection rule. Adding the rule in the search query showed the following results <defense 3>

We can see the rule should trigger based on the results above, however, it does not. This highlights the importance of testing your detection rules after writing them. An improvement to the **rule trigger conditions** was required as below <defense 4>

The alert should be triggered per each result however, to reduce alert fatigue, the throttle condtions that the alerts should be suppressed when resultant log has a unique combination of the pairing Source_Network_Address, Account_Name and ComputerName are observed within a span of 1 hour. 

In simpler terms:
- New device using a known account will give a new alert possibly signalling lateral movement.
- New account on known IP+host pair will give a new alert possibly signalling credential harvestting or privilege escalation.
- All while adhering the spirit of the rule that only Source IPs that have no Kerberos authentication are alerted as **CRITICAL** alerts.

**First artifact**: Malicious IP Address 192.168.4.11 authenticating to domain host using NTLM-auth only.

### Investigation steps

Proceed with the investigation, narrowing down on the malicious IP address, add it to the search query as below and search for the logs.

```spl
index="windowseventlogs" Source_Network_Address="192.168.4.14"
```

We see 3 events, all successful logons (EventCode=4624, Authentication_Package=NTLM). 

The next step is to know what happened before and during the logon sessions. We do this using the Timestamps as highlighted below. <defense 5>

Filter out all the Events that happened on the attacked machine, Desktop-1, between 9:42AM and 10:00AM, 08/24/2026 (Estimated time of compromise)

```spl
index="windowseventlogs" ComputerName="DESKTOP-1.mydomain.local"
``` 
<defense 6>

<defense 7>

1001 and events returned, we have to fine-tune the results to best build an attack chain. We know that 3 events, (NTLM-authenticated logons) led us here, let's further ammend our search query to know extract eavents recoreded 30 seconds after each login.

We need to determine the Events that occured during the NTLM-successful logons during this duration. We use the query below to filter the successful NTLM-authenticated logons and extract the Logon_IDs. 

```spl
index="windowseventlogs" ComputerName="DESKTOP-1.mydomain.local" EventCode=4624 Authentication_Package=NTLM
```

<defense 8>

Proceed to filter all the events that have the extracted logon ID using the query below:

```spl
index="windowseventlogs" ComputerName="DESKTOP-1.mydomain.local" (Logon_ID=0x44AC101 OR Logon_ID=0x44135A0 OR Logon_ID=0x44BB499)
| table _time Logon_ID Account_Name ComputerName EventCode Authentication_Package
| sort -_time
```

<defense 9>

Observe the following Event Codes:

| Code | Description |
|-----|-----|
| 4624 | A successful account logon |
| 4634 | User account logon session was terminated and no longer exists |
| 4672 | An account has successfully logged on and is assigned special, administrator-equivalent privileges |

**Second Artifact** The presense of Event ID 4672 and Event ID 4624 that is via NTLM authentication, *in the same timestamp*, raises so much concern. High-privileged successful logon autenticated via the insecure NTLM is a clear sign of compromise i.e. Privilege Escalation.

See the list of Privileges assigned during the insecure logon session.

<defense 10>

Proceeding with the ivestigations, we use the highlighted Logon_IDs to find the internal processes that run during the sessions from Sysmon logs, using the query below.

```spl
index="sysmon" (LogonId=0x44AC101 OR LogonId=0x44135A0 OR LogonId=0x44BB499)
```

<defense 11>

We get no results here. 

Pivot back to the timestamps that we observed from the Windows Event Logs, where we had an idea of the duration of the attack and filter all the system events in this time slot using the SPL query below.

**NOTE:** The query removes all instances of the Splunk Forwarder.

```spl
index="sysmon" ComputerName="DESKTOP-1.mydomain.local" Image!="*SplunkUniversalForwarder*"
| table _time User LogonId Image ParentImage CommandLine ProcessId
```

We observe what looks like a randomly generated executable file name that is being launched directly by the Service Control Manager and with the elevated context of NT AUTHORITY\SYSTEM which is basically the highest-ranking privileged account on Windows OS.

<defense 12>

The process appears to crash but boot back up after a very short period. 

There is also another process with more or less the same characteristics.

<defense 13>

**Third Artifact**: Unauthrorized files, located directly ubder *C:\Windows* with randomly generated names launched directly by the SCM, *services.exe* and are running as *SYSTEM*, using the OS privileges (Highest privilege in Windows). These file names are:
- fioLUfBp.exe
- eBfTlBzd.exe

**Current HYPOTHESIS**

The attempt to load an executable was unsuccessful as it ended up crashing, however the second attempt was successful as the Windows binary executed. We need to find out if the two executables are related or different versions of the same attack.

We investigate the above hypothesis by adding the hashes field in the table to filter out any instances of the processes we've highlighted. We see the processes are different and not necessarily related based on their hashes. 

```spl
index="sysmon" ComputerName="DESKTOP-1.mydomain.local" (Image="*fioLUfBp.exe*" OR ParentImage="*fioLUfBp.exe*")  OR (Image="*eBfTlBzd.exe*" OR ParentImage"*eBfTlBzd.exe*")
| table _time User LogonId Image ParentImage CommandLine ParentCommandLine ProcessId Hashes
| sort _time
```

<defense 14>

The parent-child relationship also catches my eye. Normal Windows activity is:  `services.exe -> fioLUfBp.exe`
But here we have: `services.exe -> eBfTlBzd.exe -> rundll32.exe` (Running as SYSTEM).

**services.exe investigation**

The relationship tree above shows that *services.exe* launched the two executables which we can assume were two services' configured executables. (Two because as we've seen above the hashes are different).

We need to figure out what security events are associated with these 'services' are by searching in Windows Event Logs using the following query:

```spl
index="windowseventlogs" ("*fioLUfBp.exe*" OR "*eBfTlBzd.exe*")
```

<defense 15>

We see the following Event Codes:

| Code | Description |
|-----|-----|
| 7045 | A new service was installed by the user indicated in the subject which often identifies local system (SYSTEM) |
| 1000 | Generic Windows Error Reporting log entry indicating that an application or service has stopped unexpectedly |
| 1001 | Windows Error Reporting (WER) informational or error log indicating that Windows recorded a system crash, bugcheck (Blue Screen of Death / BSOD), or a kernel-level component/driver issue |

Proceed to filter Event Code 7045 using the query below:

```spl
index="windowseventlogs" EventCode=7045
| table _time ComputerName Service_File_Name Service_Name Service_Start_Type Service_Account
| sort _time
```

Here we again find services with randomized names, running under %SYSTEMROOT% and two of them line up with the suspicious processes that we are investigating. The service names are:
- GFCoruhGsrYHYnaK
- qkrYMCKsLKfWEFCc
- VFzXKOBuQoQPpICb

<defense 16>

**Fourth Artifact** Services that triggered *services.exe* to run the executables also have randomized file names which are: 
- GFCoruhGsrYHYnaK
- qkrYMCKsLKfWEFCc
- VFzXKOBuQoQPpICb

We need to confirm the timing of the chain between service installation, services.exe running the executable of the service and in the last case, default Windows binaries being executed by the suspicious executables.

Run the search filter below:

```spl
(index="windowseventlogs" EventCode=7045) OR (index="sysmon" ComputerName="DESKTOP-1.mydomain.local" (Image="*fioLUfBp.exe*" OR ParentImage="*fioLUfBp.exe*")  OR (Image="*eBfTlBzd.exe*" OR ParentImage"*eBfTlBzd.exe*"))
| table _time EventCode ComputerName Service_Name Service_File_Name ParentImage Image
| sort _time
```

We see that the chain occurs within a matter of milliseconds indicating possible tool use or automated execution.

<defense 17>

**Fifth Artifact** The temporal proximity between the service creation and the executables running strongly supports the hypothesis that the service installation and process creation were part of the same execution sequence. 

We observe the behaviour, relationships and lifecycle of the suspicious executables in the victim host as follows:
- It's parent service names (also random). 
- Windows process `services.exe` executing them.
- Executables calling and executing Windows internal binaries e.g. `WerFault.exe` and `rundll32.exe`.

In addition to the above finding, correlation with the NTLM-authenticated sessions, we see temporal proximity that indicates what may have happened on the domain. 

```spl
(index="windowseventlogs" EventCode=7045 OR (EventCode=4624 Authentication_Package=NTLM)) OR (index="sysmon" ComputerName="DESKTOP-1.mydomain.local" (Image="*fioLUfBp.exe*" OR ParentImage="*fioLUfBp.exe*")  OR (Image="*eBfTlBzd.exe*" OR ParentImage"*eBfTlBzd.exe*"))
| table _time EventCode Account_Name Elevated_Token User Service_Name Service_File_Name ParentImage Image
| sort _time
```

<defense 19>

**LOLBIN INVESTIGATION**

The second suspicious executable runs *rundll32.exe*, a legitimate Windows process that can be abused by an attacker and is a well known **living-off-the-land-binary (LOLBIN)**. 

We need to find out whether the attacker attempted to execute malicious code while masking it as the legitimate system process `rundll32.exe`.

The command line as shown in the screenshot is `rundll32.exe` without any arguments. This is also suspicious because the binary needs to be given some argunments to run.

<defense 18>

There's no alarming event from `rundll32.exe`.

We proceed with the investigation by looking at the processes that executed immediately after the new services and LOLBIN above were spawned.

<defense 20>

A key observation is the User again changes from SYSTEM to the Domain Administartor's context.

<defense 21>

Proceed to investigate the events generated on the Host machine by the Domain Admin account. Focus on the Event codes using the following query:

```spl
(index="sysmon" host="DESKTOP-1" Image!="*SplunkUniversalForwarder*") OR (index="windowseventlogs" host="DESKTOP-1") *a-onyangor* (EventCode=4624 OR EventCode=5379 OR EventCode=4672)
| table _time EventCode Account_Name
| sort - _time
```

Wee see the same relation: successful privileged logon (4624 + 4672), then Crendentials are read from Windows Credential Manager (5379).

<defense 22>


**Unlikely path analysis**

Suspected that the most recent rule, where one source IP successfully logs on to multiple hosts via NTLM authentication, but it did not.<defense 2a>

```spl
index="windowseventlogs" EventCode=4624 Authentication_Package=NTLM Logon_Type=3
| stats values(Account_Name) as Credentials_Used values(ComputerName) as Devices_Accessed dc(ComputerName) as Host_Count by Source_Network_Address
| where Source_Network_Address!="-" AND Host_Count > 1
| sort - Host_Count
```

Adjusting the rule to fire on one or more host as below, did indeed show the suspicious IP in question. <defense 2b>

```spl
index="windowseventlogs" EventCode=4624 Authentication_Package=NTLM Logon_Type=3
| stats values(Account_Name) as Credentials_Used values(ComputerName) as Devices_Accessed dc(ComputerName) as Host_Count by Source_Network_Address
| where Source_Network_Address!="-" AND Host_Count >= 1
| sort - Host_Count
```

**Conclusion**

A detection rule must reflect the threat scenario you actually intend to detect, not the scenario you assume the data will produce

The above rule should ideally trigger on successful credential dumping instances in the enterprise network. Applying the Software Engineering principle KISS is useful in such cases.



