# MITRE ATT&CK Mapping

The SMB Relay attack abuses **NTLM authentication** to relay captured credentials to another service, allowing attackers to authenticate as the victim without cracking the password.

| MITRE Tactic | Technique | ID | Description |
|---------------|------------|----|-------------|
| Credential Access | Adversary-in-the-Middle | T1557 | The attacker intercepts authentication traffic (LLMNR/NBT-NS poisoning) and relays NTLM authentication to another service. |
| Credential Access | Forced Authentication | T1187 | The attacker forces a system to authenticate to the attacker-controlled machine. |
| Lateral Movement | Remote Services (SMB/Windows Admin Shares) | T1021.002 | Relayed NTLM authentication is used to access SMB shares or execute commands on remote machines. |
| Persistence / Privilege Escalation | Valid Accounts | T1078 | The attacker uses relayed legitimate credentials to gain unauthorized access. |