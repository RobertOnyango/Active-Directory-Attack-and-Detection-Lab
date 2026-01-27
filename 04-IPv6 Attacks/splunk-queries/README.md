# Splunk Queries for IPv6 MiTM Attack

These are some of the important Splunk queries used for investigation and subsequent alerts to detect malicious activities related to IPv6 MiTM attacks and **Credentials abuse**.

## Investigations

Event ID 4776: The domain controller attempted to validate the credentials for an account via NTLM.

Event ID 4768: A Kerberos authentication ticket (TGT) was requested.

```
index="windowseventlogs" (EventCode=4768 OR EventCode=4776)
```

## Alerts

#### 1. Successful logons from non-domain devices

```
source="WinEventLog:Security" EventCode=4624 Logon=3 Authentication_Package="NTLM" NOT (Source_Network_Address IN ("192.168.4.0/24", "127.0.0.1"))
```

#### 2. Workstation computer account resets another account’s password (Event 4724)

Computer accounts do not reset other user accounts unless delegation / ACLs are abused.

```
index=windows*
source="WinEventLog:Security"
EventCode=4724
| eval is_computer_account=if(match(Subject_Account_Name, "\$$"), "true", "false")
| where is_computer_account="true"
| where Subject_Account_Name != Target_Account_Name
| table _time ComputerName Subject_Account_Name Subject_Account_Domain Target_Account_Name Target_Account_Domain
| sort -_time
```

#### 3. Privileged account creates a new user (Event 4720)

Broad rule that should be used in context while correlating rules.

```
index=windows*
source="WinEventLog:Security"
EventCode=4720
| where Subject_Account_Name IN ("Administrator", "Domain Admins")
| table _time ComputerName Subject_Account_Name Target_Account_Name Target_SID
| sort -_time
```


#### 4. User creation → network logon milliseconds later (NTLM relay / credential abuse)

```
index=windows*
source="WinEventLog:Security"
(EventCode=4720 OR EventCode=4624)
| eval event_type=case(
    EventCode=4720, "user_created",
    EventCode=4624, "logon"
)
| transaction Target_Account_Name maxspan=2s
| search event_type="user_created" event_type="logon"
| where LogonType=3 AND AuthenticationPackage="NTLM"
| table _time ComputerName Subject_Account_Name Target_Account_Name IpAddress WorkstationName LogonType AuthenticationPackage ImpersonationLevel
| sort -_time
```

##### What is the 'Impersonation Level' in Windows?

It defines how much authority a service or process has to act on behalf of a user, most commonly found for EventID 4624. It indicates security context, ranging from Anonymous to Delegate, and is critical for monitoring privilege escalation, with "Impersonate" being the recommended level for WMI. Key Impersonation Levels

- **Anonymous (%%1832)**: The server cannot identify the client or impersonate them. The identity remains hidden.
- **Identification (%%1833)**: The default level for many logons. The server can see the client's identity and perform access control checks (ACL) but cannot perform actions as the client.
- **Impersonation (%%1834)**: The server can act as the client on its local system but cannot access remote network resources using the client’s credentials. This is the standard recommendation for WMI-related activities to ensure the service has enough permission to execute.
- **Delegation (%%1835)**: The most powerful level. The server can act as the client on both local and remote systems, passing credentials across multiple computers in a domain.
