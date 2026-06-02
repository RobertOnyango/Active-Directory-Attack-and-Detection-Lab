# Wireshark Investigations

## Overview

Security Onion investigations identified a rogue Kali Linux host (`192.168.4.11`) on the network. Splunk Enterprise investigations later confirmed that the same host was responsible for NTLM-authenticated access and lateral movement across multiple systems.

Since tools such as SecretsDump, CrackMapExec, and PsExec commonly use SMB (TCP/445), the next step is to examine SMB traffic associated with the attacker host.

---

## Investigate SMB Traffic

Filter for SMB-related traffic involving the attacker host.

```wireshark
(tcp.port == 445 || udp.port == 445) && ip.addr == 192.168.4.11
```

### Findings

- Repeated TCP SYN packets from `192.168.4.11`.
- Multiple TCP retransmissions.
- No successful SMB sessions observed.
- No SMB2 negotiations observed.
- No NTLM authentication exchanges observed.

---

## Investigation Conclusion

The packet capture did not reveal any successful SMB sessions, SMB2 negotiations, file-sharing activity, or NTLM authentication exchanges between the attacker host and the target systems.

Instead, the traffic consisted primarily of TCP SYN packets and retransmissions targeting TCP port `445`, indicating unsuccessful SMB connection attempts.

While these findings may indicate network reconnaissance or SMB service discovery, they do not provide sufficient evidence to confirm credential dumping or other SMB-based post-compromise activity. The strongest evidence of compromise remains the authentication and endpoint telemetry collected through Splunk Enterprise and Security Onion, which successfully confirmed credential abuse and lateral movement within the Active Directory environment.