# Splunk Investigation — LLMNR Poisoning

## Overview

This section documents a sample of the investigative queries used to identify artifacts generated during the LLMNR poisoning attack.

Because the lab environment initially contained no detection rules for LLMNR poisoning, investigation was performed through manual searches in Splunk.

These searches were used to:

- Identify suspicious authentication attempts
- Confirm network connections to unauthorized hosts
- Correlate authentication events with network activity

The results of these investigations helped identify the telemetry artifacts used to build detection rules.

---

## Investigation Queries

### Where was NTLM used as the authentication method?

```
index="windowseventlogs" Authentication_Package=NTLM
```

#### Purpose

Kerberos is the authentication method used in Windows Domain environments by default. 

The presence of NTLM in our logs posses the risk of credential theft due to the challenge-response nature of the authentication method.

However, there are some instances where NTLM is allowed and enabled e.g. authentication for Windows systems configured as members of a workgroup and local logon authentication on DCs.

#### Outcome

The query showed that the DC was the only host that used NTLM on only one instance.  

![alt text](<Figure 21.png>)

---

### Confirm if there's a spike in failed logons on the hosts

```
index="windowseventlogs" EventCode=4625 Logon_Type=3
| stats count by Source_Network_Address
```

#### Purpose

Event ID **4625** indicates every time a single account fails to log on to a Windows system.

Failed logons, where the access is via the network **logon_type=3** may indicate attempted remote access, by malicious actors, of the hosts in the domain.

#### Outcome

The only addresses that showed up to have generated the logs are the expected IPs in the network. 

The total counts and time intervals don't seem strange to warrant any further investigations down this path.

![alt text](<Figure 22.png>)

---

### Detect Explicit Credential Usage

```
index="windowseventlogs" EventCode=4625
```

#### Purpose

Event ID **4648** indicates explicit credential usage during authentication.

In the context of this attack, the event may appear when the victim system attempts to authenticate to an attacker-controlled host after responding to a spoofed name resolution response.

#### Investigation Outcome

This query revealed authentication attempts associated with the attack activity, with the IP address 192.168.1.11 confirmed as a artifact that warrants further investigation.

![alt text](<Figure 24.png>)

---