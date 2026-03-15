# Splunk Investigation – SMB Relay Attack

After identifying suspicious SMB activity in Security Onion, the next step in the investigation was to analyze **host-based logs in Splunk**. While Security Onion revealed the **network-level relay chain**, Splunk allows us to validate whether the relayed authentication resulted in **successful host authentication and post-exploitation activity**.

The objective of this investigation was to determine:

- Whether the relayed NTLM authentication succeeded
- Which host accepted the authentication
- Whether any post-authentication activity occurred

---

## Investigation Context

From the Security Onion analysis, the following systems were involved in the relay chain:

| Host | Role |
|-----|------|
| 192.168.4.16 | Victim system |
| 192.168.1.11 | Attacker machine |
| 192.168.4.12 | Target system (Desktop-2) |

Security Onion logs indicated that the attacker captured NTLM authentication from **192.168.4.16** and relayed it to **192.168.4.12**.

To confirm this activity at the host level, Splunk was used to search **Windows Security Event Logs** for authentication events originating from the attacker machine.

---

## Splunk Threat Hunting Query

To identify authentication attempts originating from the rogue system, the attacker IP address was added to the ***Source_Network_Address*** field in the Splunk search.

```
index=wineventlog sourcetype="WinEventLog:Security"
Source_Network_Address=192.168.1.11
```
This search filters Windows Security logs for authentication events originating from the attacker machine.

---

## Authentication Evidence

![alt text](<Figure 22.png>)

The Splunk results revealed Windows authentication events indicating that the rogue IP address 192.168.1.11 successfully authenticated to Desktop-2 using NTLM.

Relevant log details included:

| Field | Value |
|-----|------|
| Authentication Package | NTLM |
| Source Network Address | 192.168.1.11 |
| Destination Host | Desktop-2 |
| Logon Type | Network Logon (Type 3) |

This confirms that the authentication captured from the victim system was successfully **relayed by the attacker to the target host**.

Because the authentication originated from the attacker machine rather than the legitimate user system, this strongly indicates NTLM relay activity rather than legitimate authentication.

---

## Indicators of Post-Exploitation Activity

Once authentication was confirmed, additional logs were examined to identify potential post-authentication behavior.

Indicators that may appear in Splunk during NTLM relay attacks include:

- Access to administrative shares (ADMIN$)
- Remote service creation
- Remote registry access
- Privileged logons
- Network share access events

These activities typically follow successful relay authentication and may indicate **lateral movement or credential dumping attempts**.

---

## Investigation Summary

The combined investigation across Security Onion and Splunk revealed the full NTLM relay attack sequence.
1. The victim machine attempted SMB authentication after a poisoned name resolution response.
2. The attacker machine captured the NTLM authentication.
3. The authentication was relayed to Desktop-2.
4. Splunk logs confirmed that the attacker machine authenticated successfully to Desktop-2 using NTLM.
5. Host-based logs provided additional context for potential post-exploitation activity.

By correlating **network telemetry (Security Onion)** with **host logs (Splunk)**, the investigation successfully confirmed the SMB relay attack and its resulting authentication activity on the target system.

---