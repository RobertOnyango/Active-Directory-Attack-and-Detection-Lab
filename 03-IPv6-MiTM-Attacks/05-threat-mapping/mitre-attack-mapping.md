# MITRE ATT&CK Mapping

The IPv6 Man-in-the-Middle (MitM) attack abuses **default IPv6 behavior and WPAD auto-discovery** to position the attacker as a trusted network entity, enabling traffic interception and credential coercion via NTLM authentication.

| MITRE Tactic | Technique | ID | Description |
|--------------|------------|----|-------------|
| Credential Access | Adversary-in-the-Middle | T1557 | The attacker injects rogue IPv6 Router Advertisements to position themselves as the victim’s DNS server and network gateway. |
| Credential Access | Forced Authentication | T1187 | The attacker forces the victim to authenticate by responding to web requests with `407 Proxy Authentication Required`. |
| Lateral Movement | Remote Services (SMB/Windows Admin Shares) | T1021.002 | Relayed authentication can be used to access SMB, LDAP, or other internal services. |
| Privilege Escalation | Valid Accounts | T1078 | The attacker leverages relayed legitimate credentials to access systems or escalate privileges. |