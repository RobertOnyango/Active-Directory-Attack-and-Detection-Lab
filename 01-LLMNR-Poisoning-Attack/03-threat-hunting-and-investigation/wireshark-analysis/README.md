# Wireshark Analysis — LLMNR Poisoning Investigation

## Overview

Packet captures were analyzed using Wireshark to investigate network activity generated during the LLMNR poisoning attack.

The analysis focused on identifying:

- LLMNR name resolution traffic
- SMB authentication attempts
- NTLM authentication exchanges

These artifacts provide network-level evidence of the attack.

---

## Investigation Filters

### NTLM Authentication Traffic
```
ip.addr == 192.168.1.11
```

#### Purpose

The filter above builds on the results of the Splunk investigation where the unknown IP address 192.168.1.11 was recovered as an artifact.

#### Outcome

The packet capture revealed the following NTLM authentication sequence:
- NTLMSSP_NEGOTIATE - SMB2 Session setup from client -> server
- NTLMSSP_CHALLENGE - SMB2 Session Setup Response from server -> client
- NTLMSSP_AUTHENTICATE - SMB2 Session Setup Request from client -> server

**NOTE:** *ntlmssp* filter did not yield any results since the NTLM data is embedded deeply within SMB2 packets (encapsulated) as "security blob" that hasn't been explicitly identified by Wireshark's top-level dissector for that specific filter name.

However, paired with the *messagetype* flag and *Follow -> TCP Stream*  it can yield the desired results.

![alt text](<Figure 26.png>)

##### Futher analysis of the NTLMSSP_AUTH packet

We find that the client sent the artificat server its NTLM security blob, **NTProofStr**, which confirm that the client sent its password to the unauthorized server. 

Despite the password not being in cleartext, it can still be cracked by tools such as hashcat, John the Ripper etc.

![alt text](<Figure 27.png>)