# Security Onion Investigations - SMB Relay

This section documents the investigation performed in **Security Onion** after an alert indicating suspicious **SMB activity** was triggered during the SMB Relay attack simulation.

The analysis focuses on understanding how the captured NTLM authentication was relayed from the victim system to a secondary target host.

---

## Alert Overview

![alt text](<Figure 16.png>)

During the attack, Security Onion generated an alert associated with suspicious SMB traffic. Investigation of the SMB logs revealed a sequence of connections that clearly illustrates the **NTLM relay attack chain**.

![alt text](<Figure 17.png>)

The logs showed SMB authentication activity involving the following hosts:

| Host | Role |
|-----|------|
| 192.168.4.16 | Victim machine |
| 192.168.1.11 | Attacker machine |
| 192.168.4.12 | Target machine |

---

## SMB Path Analysis

![alt text](<Figure 20.png>)

During the attack, SMB logs clearly revealed the transition from **credential capture to credential relay** through the observed `smb_path` activity.

The initial connection originated from the legitimate host **192.168.4.16**, which attempted to authenticate to the attacker machine **192.168.1.11** using the SMB path:

```\\192.168.1.11\IPC$```

The **IPC$ share** is commonly used during SMB authentication negotiations and inter-process communication, making it a typical endpoint during the NTLM authentication handshake. 

In this case, the connection was triggered after the attacker responded to a **poisoned name resolution request**, causing the victim to attempt authentication against the rogue SMB service. 

Immediately afterward, the logs show the attacker machine **192.168.1.11** initiating a new SMB session with another legitimate host **192.168.4.12**, this time targeting the administrative share: 

``` \\192.168.4.12\ADMIN$ ``` 

Unlike IPC$, the **ADMIN$ share maps to the Windows directory (`C:\Windows`) and requires administrative privileges.** 

This transition from **IPC$ to ADMIN$** strongly indicates that the attacker successfully **relayed the captured NTLM authentication from 192.168.4.16 to 192.168.4.12**, allowing the attacker to authenticate as the victim **without knowing the password**. 

Additionally, the accessing of **ADMIN$** file share indicates that the credentials belonged to a priviledge administrator. This grants the attacker with **elevated priviledges**, at least for 192.168.4.12, possibly other hosts in the network.

--- 

## NTLM Relay Chain 

The observed SMB path sequence illustrates the full relay chain: 

``` 
Victim Authentication:
192.168.4.16 → 192.168.1.11 (\\IPC$) 

Credential Relay:
192.168.1.11 → 192.168.4.12 (\\ADMIN$) 

Administrative Access:
Post-Exploitation Activity 
``` 

This behavior is characteristic of **SMB Relay attacks**, where an attacker intercepts and forwards NTLM authentication to another system to gain unauthorized access. 

--- 

## Post-Authentication Activity 

Further network analysis showed **DCE/RPC traffic** between the attacker and the target host. 

DCE/RPC traffic after authentication typically indicates **post-exploitation activity**, such as: 
- Remote registry access
- Service creation 
- Remote command execution 
- Credential dumping 

The presence of this traffic strongly suggests **lateral movement enabled by the relayed NTLM authentication**, which can be better investigated in the host logs.

--- 

## Conclusion 

The Security Onion logs provide clear evidence of the NTLM relay attack chain: 

1. The victim machine **192.168.4.16** attempted SMB authentication to the attacker machine. 
2. The attacker captured the NTLM authentication challenge. 
3. The attacker relayed the authentication to **192.168.4.12**. 
4. Administrative access was obtained through the **ADMIN$ share**. 
5. **DCE/RPC traffic** indicated post-authentication activity consistent with lateral movement. 

This investigation demonstrates how **SMB telemetry in Security Onion can reveal the full lifecycle of an NTLM relay attack**, from credential capture to lateral movement. 

--- 
