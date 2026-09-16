# MITRE ATT&CK Mapping

The following table maps the observed attacker behaviors during the Token Impersonation lab to the MITRE ATT&CK framework.

| Tactic | Technique | ID | Observed Activity | SOC Relevance |
|---|---|---|---|---|
| Privilege Escalation / Persistence | Create or Modify System Process: Windows Service | T1543.003 | The attacker leveraged PsExec-style remote service execution through the Metasploit PsExec module to create temporary Windows services that executed payloads on the remote victim computer. The services were configured to execute under SYSTEM privileges. | Detect anomalous service creation by correlating Event ID 7045 with unusual service names, executable paths, service accounts, and subsequent process creation. Detect service execution under SYSTEM with unsigned or anomalous binary paths. |
| Execution | System Services: Service Execution | T1569.002 | The attacker leveraged the Metasploit PsExec module to abuse the Windows Service Control Manager (`services.exe`) to execute the payload through the newly created temporary service. | Detect Windows Service Creation and Service Execution as related techniques occurring in sequence: a temporary Windows service is created and its non-standard executable is subsequently launched by `services.exe`. |
| Privilege Escalation / Defense Evasion | Access Token Manipulation: Token Impersonation/Theft | T1134.001 | The attacker duplicated and impersonated an existing access token belonging to another user in order to operate under that user's security context. Token impersonation allows an attacker to use an existing privileged security context without directly obtaining the user's password. | Detect or investigate suspicious processes and command execution associated with token manipulation. Where endpoint telemetry is available, monitor token-access and API-level behavior associated with token duplication and impersonation. Correlate suspicious token operations with changes in process or thread security context, privileged logons, and subsequent activity performed under the impersonated identity. |

## T1543.003 – Windows Service

The attacker leveraged **PsExec-style remote service execution through the Metasploit PsExec module** to create a temporary Windows service on the remote victim computer. The service was configured to execute the payload under the `NT AUTHORITY\SYSTEM` security context.

The attack generated Windows Service creation telemetry, including Event ID 7045, followed by process creation associated with the newly created service.

### SOC Relevance

- Detect anomalous Windows service creation by correlating Event ID 7045 with unusual service names, executable paths, service accounts, and subsequent process creation.
- Detect service execution under SYSTEM where the executable path, binary, or service configuration is unusual for the environment.
- Correlate service creation with Sysmon process-creation telemetry to identify the process launched by `services.exe`.
- Investigate temporary or randomly named services that execute shortly after installation.

## T1569.002 – Service Execution

The attacker leveraged the **Metasploit PsExec module** to abuse the Windows Service Control Manager (`services.exe`) to execute the payload through the newly created temporary service.

### SOC Relevance

- Detect **Windows Service Creation** and **Service Execution** as related techniques occurring in sequence.
- Correlate Event ID 7045 with Sysmon Event ID 1 process creation.
- Identify processes launched by `services.exe` that execute under `NT AUTHORITY\SYSTEM`.
- Investigate non-standard service executables and temporary services.
- Use process lineage, executable path, service configuration, and execution timing to distinguish suspicious service execution from legitimate Windows service activity.

## T1134.001 – Token Impersonation/Theft

The attacker duplicated and impersonated an existing access token belonging to another user in order to operate under that user's security context. Token impersonation allows an attacker to use an existing privileged security context without directly obtaining the user's password.

The technique can involve assigning an existing token to a process or thread, or using a duplicated token to create a new process under the impersonated security context. Relevant Windows mechanisms can include `DuplicateToken`, `DuplicateTokenEx`, `ImpersonateLoggedOnUser`, `SetThreadToken`, `CreateProcessWithTokenW`, and `CreateProcessAsUserW`.

### SOC Relevance

- Detect or investigate suspicious processes and command execution associated with token manipulation.
- Where endpoint telemetry is available, monitor token-access and API-level behavior associated with token duplication and impersonation.
- Correlate suspicious token operations with changes in process or thread security context.
- Correlate token-related activity with privileged logons and subsequent activity performed under the impersonated identity.
- Investigate sequences involving token handle duplication, token assignment or impersonation, followed by a process operating under a different security context.

## Detection Engineering Relationship

The three techniques observed during the investigation represent related stages of the attack chain:

| Stage | MITRE ATT&CK Technique | ID | Detection Focus |
|---|---|---|---|
| 1 | Create or Modify System Process: Windows Service | T1543.003 | Detect Event ID 7045 service creation and anomalous service characteristics. |
| 2 | System Services: Service Execution | T1569.002 | Correlate service creation with subsequent SYSTEM process execution through `services.exe`. |
| 3 | Access Token Manipulation: Token Impersonation/Theft | T1134.001 | Investigate privileged security-context activity and, where available, direct token manipulation telemetry. |

The three primary detections developed during the investigation were:

1. **NTLM Logon Followed by Special Privileges**
2. **Windows Service Creation Followed by SYSTEM Process Execution**
3. **Suspicious Service Execution During Privileged User Activity**

These detections provide observable evidence surrounding the attack chain while maintaining a distinction between privileged security-context availability and confirmed token manipulation.
