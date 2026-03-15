# Suricata Telemetry – SMB Relay Artifacts

This section lists the key **network artifacts observed in Suricata telemetry** during the SMB relay attack. These logs provide visibility into SMB sessions, authentication attempts, and administrative share access related to the relay activity.

---

![alt text](<Figure 20.png>)

## Observed Hosts

| Host | Role |
|-----|------|
| 192.168.4.16 | Victim machine |
| 192.168.1.11 | Attacker machine |
| 192.168.4.12 | Relay target |

---

## SMB Authentication Traffic

Suricata logs show the victim machine **192.168.4.16** initiating an SMB session to the attacker machine **192.168.1.11** over **TCP port 445**.

Key artifact:

- `smb_path: IPC$`

The **IPC$ share** commonly appears during SMB authentication negotiations and inter-process communication.

---

## SMB Relay Activity

Shortly after the victim authentication attempt, Suricata logs show a new SMB session originating from the attacker machine **192.168.1.11** to the target **192.168.4.12**.

Key artifact:

- `smb_path: ADMIN$`

The **ADMIN$ share** maps to the Windows system directory and requires administrative privileges.

The transition from **IPC$ to ADMIN$** is a strong indicator of SMB relay activity.

---

## Key Network Artifacts

| Artifact | Description |
|--------|-------------|
| TCP Port 445 | SMB communication |
| IPC$ share access | SMB authentication attempt |
| ADMIN$ share access | Administrative SMB access |
| Sequential SMB sessions | Victim → Attacker → Target relay pattern |

---

## Summary

Suricata telemetry captured the following artifacts during the attack:

- SMB authentication attempt from the victim to the attacker
- IPC$ share access during the NTLM authentication process
- New SMB session from the attacker to the relay target
- Administrative share access (ADMIN$)

These artifacts provide network-level evidence of SMB relay behavior within the monitored environment.