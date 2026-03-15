# Splunk Endpoint Telemetry – SMB Relay Authentication

This section summarizes the **endpoint telemetry observed in Splunk** that confirms the SMB relay attack at the host level. The investigation focused on **Windows Security Event Logs** to determine whether the relayed NTLM authentication resulted in a successful logon and share access on the target system.

---

## NTLM Authentication Confirmation

Initial analysis confirmed that the rogue IP **192.168.1.11** successfully authenticated to **Desktop-2 (192.168.4.12)** using NTLM.

Key log attributes include:

- **EventCode = 4624** → Indicates a successful authentication event.
- **Logon_Type = 3** → Confirms the logon occurred through a **remote network connection**.
- **Authentication Package = NTLM**
- **Logon Process = NTLMSSP**
- **Impersonation_Level = Impersonation**

The impersonation level indicates that the server can act on behalf of the authenticated user locally and potentially across network resources.

---

## Network Share Access Verification

To confirm post-authentication activity, the investigation filtered for **Event ID 5140**, which records when a **network share object is accessed**.

This allowed confirmation of access attempts involving the following SMB shares:

- `\\192.168.1.11\IPC$`
- `\\192.168.4.12\ADMIN$`

Both accesses were associated with the rogue IP **192.168.1.11**, indicating that the attacker successfully relayed the victim's authentication and accessed administrative SMB resources.

---

## Identity Correlation

Additional fields help correlate the authentication events:

- **Security ID (SID)** → Identifies the security principal whose credentials were used.
- **Account Name** → The compromised user account.
- **Logon ID** → Enables correlation between authentication and subsequent activity.

Using the **Logon ID**, investigators can trace the full activity chain following the successful authentication event.

One of the most significant indicators in the logs is the **Source Address**, which identifies where the authentication originated. In this case, the authentication originated from **192.168.1.11**, confirming that the login attempt came from the rogue host rather than the legitimate user workstation.

The **Share Name** field further confirms which SMB resources were accessed during the session.

---

## Key Windows Event IDs Observed

| Event ID | Description |
|---------|-------------|
| 4624 | Successful logon |
| 4625 | Failed logon attempt |
| 4672 | Special privileges assigned to new logon |
| 5140 | Network share accessed |

Event **4624** was particularly significant because it confirmed a **successful NTLM authentication originating from the rogue IP address**, validating that the NTLM relay attack succeeded.