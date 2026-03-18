# Wireshark Telemetry – SMB Relay Traffic

This section highlights key packet-level evidence observed in **Wireshark** during the SMB relay attack. Packet inspection confirms the sequence of events identified in Security Onion and Splunk, including credential leakage, authentication relay, and successful SMB authentication.

---

## Network Reconnaissance

The packet capture first reveals reconnaissance activity from the rogue host.

![alt text](<1. nmap_scanning_logs.png>)

The logs show scanning activity consistent with **network enumeration**, where the attacker identifies hosts and services available on the network prior to launching the relay attack.

---

## NTLM Credential Leakage

The victim machine **192.168.4.16** initiates an SMB connection to the rogue server **192.168.1.11**.

![NTLM Credentials Leak](<2. ntlm_credentials_leak.png>)

During the SMB authentication process, the NTLM challenge-response exchange occurs.  
Packet **53** contains the **NTLMSSP_AUTH** message, confirming that the victim sent its NTLM authentication response to the attacker-controlled SMB server i.e. the **credential leak stage** of the attack.

---

## NTLM Credential Relay

Immediately after capturing the authentication blob, the attacker initiates a new SMB session toward the relay target **192.168.4.12**.

![NTLM Credentials Relay](<3. ntlm_credentials_relay.png>)

The attacker forwards the just captured NTLM authentication response to the new authentication session, effectively relaying the victim's credentials to the target system.

This step demonstrates the **NTLM relay process**, where the attacker reuses the authentication blob without needing to decrypt it.

---

## Successful Authentication

The final stage of the attack shows the attacker successfully authenticates to the relay target using the stolen credentials.

![Successful Malicious Authentication](<4. successful_malicious_authentication.png>)

SMB **Tree Connect** requests confirm that the attacker was able to access SMB resources on the target machine. The authentication succeeded because the target system trusted the NTLM authentication response.

---