# Endpoint Telemetry — Authentication Events (Splunk)

## Overview

Windows authentication and network connection events generated during the attack were analyzed using Splunk.

These events provide endpoint-level evidence of the victim system attempting authentication to the attacker-controlled host.

---

## Event ID 4648 — Explicit Credential Logon

![event ID 4648 image](<Figure 24.png>)

Event ID **4648** indicates that explicit credentials were used during an authentication attempt.

During LLMNR poisoning attacks, this event may occur when the victim system attempts authentication to the attacker-controlled host after receiving a spoofed name resolution response.

## Sysmon Event ID 3 — Network Connection

Sysmon Event ID **3** confirms that a network connection was initiated to the attacker system on **port 445 (SMB)**.

This aligns with the NTLM authentication attempt observed in network packet captures.