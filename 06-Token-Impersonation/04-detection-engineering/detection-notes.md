# Detection Notes -- Token Impersonation

## Attack Summary

The investigation focused on Token Impersonation as a post-exploitation
technique in which an attacker obtains and uses an existing access token
to operate under another user's security context. The lab investigation
demonstrated the surrounding conditions that can enable token abuse,
including privileged logon sessions, sensitive token privileges, and
SYSTEM-level execution through Windows services.

The detection engineering work therefore focused on identifying the
observable behaviors supported by the available Windows and Sysmon
telemetry rather than claiming direct visibility into the
token-impersonation operation itself.

Some aspects of the activities in detail included:

-   Successful NTLM authentication followed by assignment of sensitive
    privileges
-   Windows service creation
-   SYSTEM-level process execution through the Service Control Manager
-   Process activity associated with a privileged account on the same
    host
-   Correlation of authentication, service, and process telemetry
-   Investigation of privileged security-context activity surrounding
    service-based execution

The investigation relied heavily on correlating:

-   Windows Event Logs
-   Sysmon process-creation telemetry
-   Splunk detections
-   Process parent-child relationships
-   User and Logon ID information
-   Service creation telemetry
-   Authentication and privilege information

------------------------------------------------------------------------

## Key Findings

  -----------------------------------------------------------------------
  Artifact                            Observation
  ----------------------------------- -----------------------------------
  Authentication                      Successful NTLM logon followed by
                                      Event ID 4672

  Privileged Session                  Sensitive privileges were assigned
                                      to the authenticated logon session

  Service Creation                    Event ID 7045 identified newly
                                      installed Windows services

  Service Execution                   Temporary service executables were
                                      launched through `services.exe`

  Security Context                    Service processes executed as
                                      `NT AUTHORITY\SYSTEM`

  Privileged User Activity            Sysmon Event ID 1 showed process
                                      activity associated with
                                      `MYDOMAIN\a-onyangor` on the victim
                                      host

  Process Correlation                 Privileged-user process activity
                                      and service installation were
                                      correlated on the same host

  Token Impersonation Evidence        Available telemetry established
                                      conditions and capability relevant
                                      to token abuse, but did not
                                      directly prove a
                                      token-impersonation transition
  -----------------------------------------------------------------------

------------------------------------------------------------------------

## Detection Opportunities

### NTLM Logon Followed by Special Privileges

Detect successful NTLM authentication followed by assignment of
sensitive privileges to the same logon session.

``` spl
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

This detection establishes the authentication and privilege context of
the logon session. It does not establish that the assigned privileges
were subsequently abused for token impersonation.

------------------------------------------------------------------------

### Windows Service Creation Followed by SYSTEM Process Execution

Detect a newly installed Windows service followed by a SYSTEM process
whose parent is `services.exe`.

``` spl
| multisearch
    [ search index="windowseventlogs" EventCode=7045
      | eval event_type="service_install"
      | rename Service_Name as service_name, Service_File_Name as service_path ]

    [ search index="sysmon" EventCode=1
      | eval event_type="system_process"
      | rename Image as process_image, ParentImage as parent_image, User as process_user
      | where process_user="NT AUTHORITY\SYSTEM"
          AND match(parent_image, "(?i)services\.exe$") ]

| fields _time ComputerName event_type service_name service_path process_image parent_image process_user ProcessId

| sort 0 -_time

| transaction ComputerName
    maxspan=10s
    startswith=eval(event_type="service_install")
    endswith=eval(event_type="system_process")

| where eventcount>=2

| table _time ComputerName event_type service_name service_path process_image parent_image process_user ProcessId duration
```

This detection focuses on the behavioral sequence of service
installation followed by SYSTEM-level execution through the Service
Control Manager. It does not by itself identify a specific tool such as
PsExec.

------------------------------------------------------------------------

### Suspicious Service Execution During Privileged User Activity

Detect service installation occurring on a host where process activity
associated with a privileged account was observed.

``` spl
| multisearch
    [ search index="windowseventlogs" EventCode=7045
      | eval event_type="service_install"
      | rename Service_Name as service_name, Service_File_Name as service_path ]

    [ search index="sysmon" EventCode=1
      | eval event_type="admin_process"
      | rename User as admin_user, LogonId as admin_logon_id
      | rename Image as process_image, ParentImage as parent_image
      | where match(admin_user,"(?i)(admin|administrator|domain admins|a-onyangor)") ]

| fields _time ComputerName event_type service_name service_path admin_user admin_logon_id process_image parent_image ProcessId CommandLine

| sort 0 ComputerName -_time

| transaction ComputerName
    maxspan=8h
    startswith=eval(event_type="service_install")
    endswith=eval(event_type="admin_process")

| where eventcount>=2

| table _time ComputerName admin_user admin_logon_id service_name service_path process_image parent_image ProcessId CommandLine duration
```

This detection provides contextual evidence that privileged-user process
activity was present on the same host during the period surrounding
service installation. It does not establish that the privileged user's
token was impersonated.

------------------------------------------------------------------------

## Detection Considerations

The three detections were intentionally limited to behaviors directly
supported by the telemetry collected during the investigation.

The first rule identifies the authentication and privilege context of a
session. The second identifies the service-based execution chain
observed during the attack. The third adds privileged-user process
activity on the same host as additional context.

These detections should therefore be interpreted as correlated
indicators rather than as a direct detector for Token Impersonation. A
privileged account being active on a host does not prove that its token
was stolen or impersonated, and the assignment of sensitive privileges
does not prove that those privileges were exercised.

The available Sysmon telemetry was particularly valuable for
establishing process context. Sysmon Event ID 1 records process creation
and provides information such as the process image, command line, parent
process, and user context, allowing process activity to be correlated
with service and identity-related events.

------------------------------------------------------------------------

## Mitigation Recommendations

-   Restrict privileged account use on standard user workstations.
-   Apply least privilege to administrative accounts.
-   Implement account tiering to reduce exposure of privileged security
    contexts.
-   Use separate privileged accounts for administrative activities.
-   Restrict unnecessary NTLM authentication where operationally
    feasible.
-   Monitor Windows service creation and service execution.
-   Monitor privileged-user process activity on workstations.
-   Enable and centralize Windows and Sysmon telemetry for correlation.
-   Review sensitive privileges assigned to logon sessions.
-   Implement Privileged Access Management (PAM) controls for high-value
    administrative accounts.

------------------------------------------------------------------------

## Lessons Learned

-   Token Impersonation is primarily an authorization and
    security-context abuse technique; the attacker does not necessarily
    need to obtain the user's password.
-   A privileged logon and sensitive token privileges establish
    capability or opportunity, but do not prove token impersonation.
-   Windows service creation followed by SYSTEM execution provided the
    strongest behavioral evidence in the available telemetry.
-   Sysmon process-creation data provided important user and
    process-context information that was not available from the
    service-creation event alone.
-   Correlating authentication, privilege, service, and process
    telemetry provides stronger investigative context than analyzing
    individual events in isolation.
-   The available telemetry did not directly expose the
    token-manipulation API operations required to conclusively
    demonstrate Token Impersonation.
-   Detection engineering should therefore distinguish between evidence
    of privileged security context, evidence of execution, and evidence
    of actual token manipulation.
