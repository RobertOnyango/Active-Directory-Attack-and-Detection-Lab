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
`search string here`

### Purpose

This filter isolates packets containing NTLM authentication messages.

NTLM authentication exchanges occur when a system attempts to authenticate using NTLM challenge-response mechanisms.

### Investigation Outcome

The packet capture revealed the following NTLM authentication sequence:
- NTLMSSP_NEGOTIATE
- NTLMSSP_CHALLENGE
- NTLMSSP_AUTHENTICATE

[image]