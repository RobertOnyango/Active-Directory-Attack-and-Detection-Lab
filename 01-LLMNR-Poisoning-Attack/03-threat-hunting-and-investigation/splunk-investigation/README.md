# Splunk Investigation — LLMNR Poisoning

## Overview

This section documents the investigative queries used to identify artifacts generated during the LLMNR poisoning attack.

Because the lab environment initially contained no detection rules for LLMNR poisoning, investigation was performed through manual searches in Splunk.

These searches were used to:

- Identify suspicious authentication attempts
- Confirm network connections to unauthorized hosts
- Correlate authentication events with network activity

The results of these investigations helped identify the telemetry artifacts used to build detection rules.

---

## Investigation Queries

## Detect Explicit Credential Usage
`query here`


### Purpose
Event ID **4648** indicates explicit credential usage during authentication.

In the context of this attack, the event may appear when the victim system attempts to authenticate to an attacker-controlled host after responding to a spoofed name resolution response.

### Investigation Outcome
This query revealed authentication attempts associated with the attack activity.

[screenshot]