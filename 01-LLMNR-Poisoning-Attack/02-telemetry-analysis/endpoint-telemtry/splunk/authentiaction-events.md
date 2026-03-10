# Endpoint Telemetry — Authentication Events (Splunk)

## Overview

Windows authentication and network connection events generated during the attack were analyzed using Splunk.

These events provide endpoint-level evidence of the victim system attempting authentication to the attacker-controlled host.

---

## Event ID 4648 — Explicit Credential Logon

![event ID 4648 image](<Figure 24.png>)

Event ID **4648** indicates that explicit credentials were used during an authentication attempt.

During LLMNR poisoning attacks, this event may occur when the victim system attempts authentication to the attacker-controlled host after receiving a spoofed name resolution response.

The screenshot above shows the **artifact IP address 192.168.1.11**.