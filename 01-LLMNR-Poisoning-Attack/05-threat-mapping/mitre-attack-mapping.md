# MITRE ATT&CK Mapping

| Tactic | Technique | ID | Description |
|------|------|------|------|
| Credential Access | Adversary-in-the-Middle | T1557 | Intercepting authentication traffic |
| Credential Access | LLMNR/NBT-NS Poisoning | T1557.001 | Spoofing name resolution responses |
| Credential Access | Forced Authentication | T1187 | Forcing a system to authenticate to an attacker |

---

## Attack Flow

The attack observed in this lab follows the sequence below:

Victim attempts hostname resolution
↓
DNS resolution fails
↓
Victim sends LLMNR multicast query (UDP 5355)
↓
Attacker responds pretending to be the requested host
↓
Victim initiates SMB authentication to attacker
↓
NTLM challenge-response captured

---

## Detection Perspective

The techniques above generate observable artifacts across both network and endpoint telemetry.

Key signals include:

- LLMNR multicast traffic on **UDP port 5355**
- SMB authentication attempts following LLMNR responses
- NTLM authentication events in Windows logs
- Network connections to unexpected hosts on **port 445**

These artifacts are analyzed and operationalized into detection rules in the **telemetry**, **threat-hunting**, and **detection-engineering** sections of this repository.