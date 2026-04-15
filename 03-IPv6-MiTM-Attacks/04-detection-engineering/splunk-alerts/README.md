# Splunk Alert Rules

Investigation of the observed activity in the domain and the artifacts subsequently collected resulted in the following alerts being added to the detection library.

---

## 1. Detect IPs associated with NTLM authentication only and not Kerberos

While NTLM is considered less secure than Kerberos, it remains widely used in enterprise environments due to legacy systems, compatibility requirements, and fallback authentication scenarios. As a result, alerting on all NTLM traffic would generate significant noise and reduce detection effectiveness.

Instead, this detection focuses on identifying hosts that exclusively use NTLM without any corresponding Kerberos authentication. In a properly functioning Active Directory environment, Kerberos is the preferred protocol, and most legitimate systems will exhibit both Kerberos and NTLM activity over time. Systems that rely solely on NTLM may indicate abnormal behavior, such as credential relay attacks or misconfigured authentication flows, making this a higher-fidelity detection signal.

```
index="windowseventlogs" EventCode=4624 Logon_Type=3
| stats values(Authentication_Package) as auth_methods by Source_Network_Address, Account_Name
| where match(auth_methods, "NTLM") AND NOT match(auth_methods, "Kerberos")
```

## 2. Detect the creation of a new computer object after successful authentication by the same sourceIP

This detection correlates NTLM-based network authentication (Event ID 4624) with subsequent computer account creation (Event ID 4741). In NTLM relay attacks, an attacker forwards authentication to a Domain Controller and immediately performs privileged actions such as creating a new computer object. By identifying this sequence of events within a short time window, this rule provides a high-confidence indicator of credential relay and unauthorized Active Directory modification.

```
index="windowseventlogs" (EventCode=4741 OR EventCode=4624)
| eval is_ntlm_success=if(EventCode==4624 AND Authentication_Package=="NTLM" AND Logon_Type==3,1,0)
| eval is_computerobj_created=if(EventCode==4741,1,0)
| bin _time span=5s
| stats max(is_ntlm_success) as ntlm_seen max(is_computerobj_created) as computer_created values(Account_Name) as Accounts values(Source_Network_Address) as SourceIp by _time
| where ntlm_seen=1 AND computer_created=1
```


## 3. Detect suspicious user creation after NTLM

This rule identifies user account creation events (Event ID 4720) that occur shortly after NTLM-based network authentication (Event ID 4624). In secure Active Directory environments, administrative actions are typically performed using Kerberos and from trusted systems. When privileged actions such as user creation are executed over NTLM from an unexpected source, it may indicate credential relay, privilege abuse, or Active Directory compromise.

```
index="windowseventlogs" (EventCode=4624 OR EventCode=4720)
| eval is_ntlm_success=if(EventCode==4624 AND Authentication_Package=="NTLM" AND Logon_Type==3,1,0)
| eval is_user_created=if(EventCode==4720,1,0)
| bin _time span=5s
| stats max(is_ntlm_success) as ntlm_seen max(is_user_created) as user_created values(Account_Name) as Accounts values(Source_Network_Address) as SourceIp by _time
| where ntlm_seen=1 AND user_created=1
```

## 4. Multiple Source IPs Authenticating Same Host

This rule detects scenarios where a single host receives network logons (Event ID 4624, Logon Type 3) from multiple distinct source IP addresses. While some administrative or remote access scenarios may produce similar patterns, this behavior can also indicate credential relay, lateral movement, or unauthorized access using shared credentials. In the context of NTLM-based attacks, this may reflect an attacker relaying authentication from one system while legitimate access occurs from another, making it a valuable correlation signal when combined with other detections.

```
index=windowseventlogs EventCode=4624 Logon_Type=3 Workstation_Name!="-"
| stats dc(Source_Network_Address) as unique_ips_count values(Source_Network_Address) as SourceIPs by Workstation_Name
| where unique_ips_count > 1
```

#### NOTE: What is the 'Impersonation Level' in Windows?

It defines how much authority a service or process has to act on behalf of a user, most commonly found for EventID 4624. It indicates security context, ranging from Anonymous to Delegate, and is critical for monitoring privilege escalation, with "Impersonate" being the recommended level for WMI. Key Impersonation Levels

- **Anonymous (%%1832)**: The server cannot identify the client or impersonate them. The identity remains hidden.
- **Identification (%%1833)**: The default level for many logons. The server can see the client's identity and perform access control checks (ACL) but cannot perform actions as the client.
- **Impersonation (%%1834)**: The server can act as the client on its local system but cannot access remote network resources using the client’s credentials. This is the standard recommendation for WMI-related activities to ensure the service has enough permission to execute.
- **Delegation (%%1835)**: The most powerful level. The server can act as the client on both local and remote systems, passing credentials across multiple computers in a domain.
