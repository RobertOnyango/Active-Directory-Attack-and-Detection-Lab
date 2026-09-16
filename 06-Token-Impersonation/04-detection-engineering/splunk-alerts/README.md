# Detecion Engineering

## Overview

The following detection rules were developed from the Windows and Sysmon telemetry observed during the Token Impersonation investigation. Rather than relying on a single event to identify token abuse, the detections correlate authentication, privilege, service, and process activity to identify the security conditions and execution patterns surrounding the attack.

The rules are designed for Splunk Enterprise and reflect the telemetry available in this lab environment. Each detection includes the relevant event sources, correlation logic, and considerations for interpreting the results. The detections should be treated as investigation and correlation mechanisms rather than definitive proof of Token Impersonation unless direct token-manipulation telemetry is available.

---

## 1. Detect NTLM logon with special privileges

```spl
index="windowseventlogs"
(EventCode=4624 OR EventCode=4672)
| eval event_time=_time
| eval logon_id=coalesce(Logon_ID, LogonId)
| eval account=coalesce(Account_Name, Target_User_Name)
| stats
    min(eval(if(EventCode=4624,event_time,null()))) as logon_time
    max(eval(if(EventCode=4672,event_time,null()))) as privilege_time
    values(Authentication_Package) as auth_package
    values(Logon_Type) as logon_type
    values(Elevated_Token) as elevated_token
    values(Privileges) as privileges
    by ComputerName account logon_id
| where isnotnull(logon_time)
    AND isnotnull(privilege_time)
    AND privilege_time >= logon_time
    AND privilege_time <= logon_time + 300
    AND mvfind(auth_package,"NTLM") >= 0
```

### Detection Logic

The detection correlates two Windows Security events:

* **Event ID 4624** — records a successful logon and the creation of a logon session.
* **Event ID 4672** — records the assignment of sensitive privileges to a new logon session.

Windows provides the **Logon ID** field in both events to allow the events to be correlated to the same logon session.

The query begins by collecting both event types:

```spl
(EventCode=4624 OR EventCode=4672)
```

It then creates a normalized event timestamp and normalizes the Logon ID and account fields using `coalesce`. This allows the query to work with the corresponding fields regardless of which event populated them:

```spl
| eval event_time=_time
| eval logon_id=coalesce(Logon_ID, LogonId)
| eval account=coalesce(Account_Name, Target_User_Name)
```

The events are then grouped using `stats` by `ComputerName`, account, and Logon ID. For each group, the query identifies the earliest 4624 event as `logon_time` and the latest 4672 event as `privilege_time`.

```spl
| stats
    min(eval(if(EventCode=4624,event_time,null()))) as logon_time
    max(eval(if(EventCode=4672,event_time,null()))) as privilege_time
    values(Authentication_Package) as auth_package
    values(Logon_Type) as logon_type
    values(Elevated_Token) as elevated_token
    values(Privileges) as privileges
    by ComputerName account logon_id
```

The final conditions require both events to exist, require the privilege event to occur after the successful logon, and restrict the correlation window to five minutes:

```spl
| where isnotnull(logon_time)
    AND isnotnull(privilege_time)
    AND privilege_time >= logon_time
    AND privilege_time <= logon_time + 300
```

The final condition:

```spl
AND mvfind(auth_package,"NTLM") >= 0
```

restricts the detection to logon sessions associated with NTLM authentication. Windows identifies NTLM as an authentication package and distinguishes it from Kerberos and Negotiate in Event 4624.

### Detection Pattern

The rule is designed to identify the following sequence:

```text
Windows Security
Event ID 4624
Successful Logon
        │
        │ Logon ID
        ▼
Authentication Package = NTLM
        │
        ▼
Windows Security
Event ID 4672
Special Privileges Assigned
        │
        ├── SeImpersonatePrivilege
        ├── SeDebugPrivilege
        ├── SeAssignPrimaryTokenPrivilege
        └── Other sensitive privileges
```

The important relationship is the shared **Logon ID**. The 4624 event establishes the successful logon session, while 4672 indicates that sensitive privileges were assigned to that session. Microsoft documents privileges including `SeImpersonatePrivilege`, `SeDebugPrivilege`, and `SeAssignPrimaryTokenPrivilege` as sensitive privileges that can cause Event 4672 to be generated.

### Detection Considerations

This rule should not be interpreted as a direct Token Impersonation detector. Event 4672 indicates that sensitive privileges were **assigned to a logon session**, not that those privileges were actually exercised. For example, the presence of `SeImpersonatePrivilege` does not demonstrate that `ImpersonateLoggedOnUser`, token duplication, or another token-manipulation operation subsequently occurred.

The rule is also expected to generate legitimate results in environments where administrative accounts, service accounts, or privileged system components authenticate using NTLM. Microsoft recommends monitoring 4624 events involving high-value accounts and specifically notes that NTLM authentication can be monitored when NTLM usage is not expected or should be restricted.

For this reason, the detection becomes more valuable when additional context is applied. Useful enrichment includes the account involved, Logon Type, source network address, elevated-token status, assigned privileges, workstation, and subsequent process or service activity. A privileged NTLM logon followed by suspicious service creation or SYSTEM-level process execution would warrant significantly more investigation than an isolated 4624/4672 pair.

### Detection Engineering Lesson

The main lesson from this rule is that **capability is not the same as execution**. The 4624 and 4672 events allow the analyst to identify a successful authenticated session and determine whether that session received sensitive privileges. They do not, by themselves, demonstrate that the privileges were subsequently abused.

This makes the rule most useful as an **early-stage correlation and enrichment detection**. It establishes the authentication and privilege context that can later be combined with process creation, service execution, token manipulation, or other endpoint telemetry to determine whether the privileged security context was actually used in suspicious activity.

---

## 2. Detect Windows service creation followed by SYSTEM process execution**

```spl
| multisearch
    [ search index="windowseventlogs" EventCode=7045
      | eval event_type="service_install"
      | rename Service_Name as service_name, Service_File_Name as service_path 
    ]
    [ search index="sysmon" EventCode=1
      | eval event_type="system_process"
      | rename Image as process_image, ParentImage as parent_image, User as process_user
      | where process_user="NT AUTHORITY\SYSTEM" AND match(parent_image, "(?i)services\.exe$") 
    ]
| fields _time ComputerName event_type service_name service_path process_image parent_image process_user ProcessId
| sort 0 ComputerName -_time
| transaction ComputerName maxspan=10s startswith=eval(event_type="service_install") endswith=eval(event_type="system_process")
| where eventcount>=2
| table _time ComputerName event_type service_name service_path process_image parent_image process_user ProcessId duration
```

### Detection Logic

The detection combines two telemetry sources:

* **Windows Security Event ID 7045** — indicates that a new Windows service was installed.
* **Sysmon Event ID 1** — records process creation, including the executable image, parent process, user, and process ID.

The two searches are combined using `multisearch`. Each event is assigned an `event_type`:

```text
service_install
system_process
```

The Sysmon branch is restricted to processes running as `NT AUTHORITY\SYSTEM` where the parent process matches `services.exe`. This reduces the result set to process executions that are consistent with the Service Control Manager launching a SYSTEM service.

The resulting events are then sorted using:

```spl
| sort 0 -_time
```

The `-` before `_time` specifies descending order. This is important because Splunk's `transaction` command requires incoming events to be in descending chronological order, particularly when using `maxspan`.

The transaction is then constructed using the affected `ComputerName`:

```spl
| transaction ComputerName
    maxspan=10s
    startswith=eval(event_type="service_install")
    endswith=eval(event_type="system_process")
```

The `maxspan=10s` condition limits the transaction to events occurring within a 10-second period. The `startswith` condition requires the sequence to begin with a service installation, while `endswith` requires the sequence to terminate with the SYSTEM process event. Splunk's `transaction` command provides the resulting `duration` and `eventcount` fields, which can then be used to validate and investigate the correlated activity.

The final filter:

```spl
| where eventcount>=2
```

ensures that the transaction contains at least the two expected event types. I use `>=2` rather than `=2` because the detection is intended to identify the required sequence without assuming that only two events can occur during the transaction.

### Detection Pattern

The rule is designed to identify the following behavioral sequence:

```text
Windows Security
Event ID 7045
        │
        │ New service installed
        ▼
Service Control Manager
services.exe
        │
        │ launches service
        ▼
Sysmon
Event ID 1
        │
        ├── Process: suspicious/unusual executable
        ├── Parent: services.exe
        └── User: NT AUTHORITY\SYSTEM
```

This sequence is significant because service-based execution can provide an attacker with SYSTEM-level execution when the created service is configured to run under the LocalSystem account.

### Detection Considerations

The rule should not be interpreted as a definitive PsExec detector. Windows services are legitimate and are routinely created or modified by software installers, management agents, security products, and system administration tools. Therefore, the correlated sequence should be treated as a **high-value investigation signal**, with additional context used to determine whether the activity is malicious.

Useful enrichment includes the service name, service executable path, file hash, signer information, account associated with the service creation, command line, network connections, and whether the executable is normally present on the host.

The randomized service names observed during the lab were useful investigative indicators, but they should not be used as the primary detection condition. An attacker can change the service name easily, whereas the behavioral relationship between service creation, `services.exe`, and SYSTEM execution is more fundamental.

### Detection Engineering Lesson

The main lesson from this rule is that a useful detection does not necessarily come from a single suspicious event. Event ID 7045 alone tells us that a service was created. Sysmon Event ID 1 alone tells us that a process was created. Correlating the two events within a short time window provides considerably more context and allows the detection to represent an **attack sequence rather than an isolated event**.

---

## 3. Detect suspicious Service Execution while a Privileged Account is Logged on the same host

```spl
| multisearch
    [ search index="windowseventlogs" EventCode=7045
      | eval event_type="service_install"
      | rename Service_Name as service_name, Service_File_Name as service_path 
    ]
    [ search index="sysmon" EventCode=1
      | eval event_type="admin_process"
      | rename User as admin_user, LogonId as admin_logon_id
      | rename Image as process_image, ParentImage as parent_image
      | where match(admin_user,"(?i)(admin|administrator|domain admins|a-onyangor)")
    ]
| fields _time ComputerName event_type service_name service_path admin_user admin_logon_id process_image parent_image ProcessId CommandLine
| sort 0 ComputerName -_time
| transaction ComputerName maxspan=8h startswith=eval(event_type="service_install") endswith=eval(event_type="admin_process")
| where eventcount>=2
| table _time ComputerName admin_user admin_logon_id service_name service_path process_image parent_image ProcessId CommandLine duration
```

### Detection Logic

The detection correlates two telemetry sources:

* **Windows Security Event ID 7045** — records the installation of a new Windows service.
* **Sysmon Event ID 1** — records process creation and provides information about the process image, parent process, command line, and user context.

The Windows Security event is assigned the event type:

```text
service_install
```

The Sysmon process-creation events are assigned:

```text
admin_process
```

after filtering for the specified privileged account.

The two event streams are combined using `multisearch` and reduced to the fields required for correlation and investigation:

```spl
| fields _time ComputerName event_type service_name service_path admin_user admin_logon_id process_image parent_image ProcessId CommandLine
```

The events are then sorted by host and descending time:

```spl
| sort 0 ComputerName -_time
```

The descending time order is required because Splunk's `transaction` command expects incoming events to be in descending chronological order. The `sort` command uses the minus sign before `_time` to specify descending order.

The transaction is constructed using `ComputerName`:

```spl
| transaction ComputerName
    maxspan=8h
    startswith=eval(event_type="service_install")
    endswith=eval(event_type="admin_process")
```

This requires the correlated events to occur on the same host and limits the transaction to an eight-hour span. The `startswith` and `endswith` conditions define the required event types within the transaction. Splunk documents `maxspan` as the maximum time span covered by events in a transaction, while `startswith` and `endswith` allow specific events to define the transaction boundaries.

Because the events are processed in descending chronological order, the transaction begins with the more recent service-installation event and works backwards to the earlier privileged-user process event. This is why the `startswith` condition is `service_install` even though, chronologically, the privileged-user process activity occurred first.

The final condition:

```spl
| where eventcount>=2
```

ensures that the transaction contains at least the two required event types.

### Detection Pattern

The rule is designed to identify the following sequence on the same host:

```text
Sysmon Event ID 1
Privileged-user process
        │
        │
        │ within 8 hours
        ▼
Windows Security
Event ID 7045
New service installed
```

The resulting transaction provides the analyst with both the privileged-user context and the service-creation context in a single result.

### Detection Considerations

The detection should not be interpreted as a direct Token Impersonation detector. A Sysmon Event ID 1 showing a process running under a privileged account establishes that process activity occurred under that user context, but it does not demonstrate that another process obtained or impersonated the user's access token.

The eight-hour `maxspan` is also a correlation window rather than proof that the privileged account remained continuously logged on for the entire period. The purpose of the window is to associate related activity occurring on the same host and provide a useful investigation starting point.

The privileged-account filter is currently based on the known account used in the lab. In a production environment, the account-selection logic would need to reflect the organization's privileged-account inventory rather than relying on a fixed account name.

### Detection Engineering Lesson

The main lesson from this rule is the value of combining **execution telemetry with identity context**. A service installation is more informative when the analyst can also see that privileged-user process activity was occurring on the same host during the surrounding period. Sysmon Event ID 1 provides the process and user context required to establish this relationship, while Event ID 7045 provides the service-installation evidence.

The resulting detection should therefore be treated as a **high-value correlation for investigation**, rather than as proof that token impersonation occurred. The actual determination of token abuse requires additional evidence showing that a process or thread acquired or used the privileged security context.

---