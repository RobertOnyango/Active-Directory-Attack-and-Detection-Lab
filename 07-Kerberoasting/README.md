# Kerberoasting

## 📝 Full Write-up

[Medium Article – Active Directory Attack Simulation and AI-Assisted Threat Detection with Popular SIEM Tools – Kerberoasting](https://robertmark94.medium.com/active-directory-attack-simulation-and-ai-assisted-threat-detection-with-popular-siem-tools-part9-1a24aa57b9ef)

---

## 📌 Overview

Kerberoasting is an Active Directory credential-access technique in which an attacker requests Kerberos service tickets for accounts associated with Service Principal Names (SPNs).

The resulting service-ticket material can be extracted and subjected to offline password analysis without directly interacting with the target service account.

This lab demonstrates how Kerberos authentication and service-ticket requests operate within an Active Directory environment, how an attacker can request a service ticket for an SPN-associated account, and how the resulting activity can be investigated from network and endpoint telemetry.

The attack was simulated in an Active Directory environment and monitored with:

- **Security Onion / Suricata**
- **Splunk**
- **Wireshark**
- **Windows Security Event Logs**
- **Kali Linux / Impacket**

The objective of the lab is to demonstrate:

- How Kerberos authentication operates in an Active Directory environment
- How SPNs identify Kerberos services
- How service tickets are requested for SPN-associated accounts
- How Kerberoasting can produce extractable ticket material
- How Kerberos encryption types affect ticket requests and analysis
- How network and endpoint telemetry can be correlated during an attack
- How Kerberoasting activity can be detected
- The limitations of individual telemetry sources when investigating
  Kerberos-based attacks

---

## Windows Authentication Mental Model

USER
 │
 │ username + password
 ▼
WINLOGON
 │
 │ coordinates interactive logon
 ▼
LSASS
 │
 │ authentication packages
 ▼
NEGOTIATE
 │
 ├───────────────────────┐
 │                       │
 ▼                       ▼
KERBEROS                NTLM
 │                       │
 │                       │
 ▼                       ▼
KDC/DC                  DC
 │                       │
 │                       │
 ▼                       ▼
TGT                  Challenge/
 │                   Response
 │                       │
 │                       ▼
 │                    Validation
 │                       │
 └──────────┬────────────┘
            │
            ▼
      Authentication
         succeeds
            │
            ▼
      Logon Session
            │
            ▼
       Access Token
            │
            ▼
       Authorization

---

## 📂 Repository Structure

This repository is organized to reflect the lifecycle of the security investigation.

| Folder | Purpose |
|------|------|
| attack-simulation | Steps used to authenticate to the domain and request a Kerberos service ticket |
| telemetry-analysis | Splunk, Security Onion, and Wireshark artifacts generated during the investigation |
| threat-hunting-and-investigation | Investigative queries and analysis used to reconstruct the attack |
| detection-engineering | Splunk detection rule developed from the observed telemetry |
| threat-mapping | MITRE ATT&CK mapping for Kerberoasting |

---

## ⚔️ Attack Simulation

The attack was performed from a Kali Linux attacker machine against a Windows Active Directory environment.

The attacker first established access using the compromised domain account `fernandesb`.

The investigation then focused on Kerberos service-ticket acquisition for the `sql_service` account.

The target account was associated with the following SPN:

```text
DOMAINCONTROLLER/sql_service.mydomain.local:60111
```

The `sql_service` account was also configured as a member of Domain Admins in the lab environment, increasing the potential impact if its credentials were successfully recovered.

### Steps
1. Attacker uses the `fernandesb` domain account to authenticate to the Active Directory environment.
2. The attacker obtains a Kerberos Ticket Granting Ticket (TGT).
3. The attacker identifies an SPN-associated service account.
4. The attacker requests a Kerberos service ticket for `sql_service`.
5. The resulting service-ticket material is extracted for offline analysis.
6. The extracted ticket is represented as a Kerberos TGS hash beginning with:

```text
$krb5tgs$18$
```

7. The ticket encryption type is identified as AES256 (etype 18 / 0x12).
8. Windows, network, and packet-level telemetry are investigated to reconstruct the Kerberos exchange.

The lab demonstrates that Kerberoasting targets Kerberos service-ticket material rather than requiring direct access to the service account's password.

---

## 📡 Telemetry Artifacts

The investigation generated observable artifacts across Windows Security Event Logs, Security Onion/Suricata, and packet captures.

### Windows Security Events

Relevant events included:
- 4624 — Successful network logon
- 4625 — Failed network logon
- 4768 — Kerberos TGT issuance
- 4769 — Kerberos service-ticket request
- 4776 — NTLM credential validation
- 4634 — Logoff
- 4672 — Special privileges assigned to a new logon
- 4648 — Explicit credential usage
- 4662 — Active Directory object access
- 4770 — Kerberos service-ticket renewal
- 5061 — Cryptographic operation

The most important Kerberos events for the attack were:

```text
4624 → 4768 → 4769
```

The observed service-ticket event identified:

```text
Service_Name = sql_service
Ticket_Encryption_Type = 0x12
```

0x12 corresponds to Kerberos **etype 18 / AES256-CTS-HMAC-SHA1-96**.

## Security Onion / Suricata

Network investigation identified communication from:

```text
Attacker: 192.168.1.10
Domain Controller: 192.168.4.10
```

Observed traffic included:
- LDAP — TCP 389
- Kerberos — TCP 88
- LDAPS — TCP 636

Custom LLMNR and mDNS Suricata rules generated alerts during the broader investigation.

The stock/default Suricata detection library did not independently identify the Kerberoasting activity.

## Wireshark

Packet-level analysis confirmed:
- LDAP authentication using NTLMSSP
- Kerberos AS-REQ / AS-REP exchanges
- Kerberos TGT acquisition
- Kerberos TGS-REP activity
- AES256 Kerberos encryption
- Service-ticket activity associated with sql_service

The relevant PCAP analysis is documented in the
telemetry-analysis/ directory.

---

## 🔎 Investigation & Threat Hunting

The investigation was performed by correlating network, endpoint, and packet-level telemetry.

### Security Onion

Security Onion was used to identify suspicious communication involving the Domain Controller.

Filtering identified traffic from the attacker:

```text
192.168.1.10 → 192.168.4.10
```

The investigation identified 59 relevant events after filtering multicast traffic.

Observed protocols included:
- LDAP
- Kerberos
- LDAPS

These network observations provided the initial pivot into endpoint investigation.

### Splunk

Splunk was used to reconstruct authentication and Kerberos ticket activity.

The investigation identified:
- Successful NTLM authentication using fernandesb
- Network Logon Type 3
- Source address 192.168.1.10
- Kerberos TGT issuance
- Kerberos service-ticket request
- sql_service as the targeted service account
- AES256 ticket encryption (0x12)

The observed Kerberos sequence included:

```text
4776
  ↓
4624
  ↓
4768
  ↓
4769
  ↓
4634
```

The final authentication/ticketing sequence relevant to detection engineering was:

```text
4624 → 4768 → 4769
```

The 4768 and 4769 events occurred approximately 67 milliseconds apart.

### Wireshark

Wireshark was used to validate the underlying packet-level activity.

The observed Kerberos exchange included:

```text
AS-REQ
   ↓
KRB5KDC_ERR_PREAUTH_REQUIRED
   ↓
AS-REQ
   ↓
AS-REP / TGT
   ↓
TGS-REP / Service Ticket
```

The corresponding TGS-REQ packet was not captured in the PCAP.

Therefore, the presence of the TGS-REP and the surrounding Kerberos exchange supports the normal Kerberos workflow, but the capture does not directly prove which TGT was presented in the missing TGS-REQ.

Investigation queries and analysis steps are documented in the threat-hunting-and-investigation/ directory.

---

## 🚨 Detection Engineering

The investigation produced one additional host-based detection.

### NTLM Authentication → Kerberos TGT → Service Ticket

The detection identifies a rapid authentication and ticketing sequence involving the same normalized user and source IP.

The detection correlates:

```text
4624 - Successful NTLM Network Logon
              ↓
4768 - Kerberos TGT Issuance
              ↓
4769 - Kerberos Service Ticket Request
```

The three events must occur within a 5-second transaction window.

The detection normalizes:
- IPv4-mapped IPv6 addresses such as `::ffff:192.168.1.10`
- UPN-formatted usernames such as `fernandesb@mydomain.local`
- Username capitalization differences

This allows the three events to be correlated as:

```text
User      = fernandesb
Source IP = 192.168.1.10
```

The detection successfully reproduced the observed attack sequence:

```text
4624 → 4768 → 4769
```

with a transaction duration of: **0.099 seconds**

The detection does not independently prove Kerberoasting. It identifies the suspicious NTLM-to-Kerberos ticketing sequence and provides an investigative pivot into the targeted service account, SPN, ticket encryption type, and
other supporting evidence.

The detection logic is available in the
**detection-engineering/** directory.

---

## 🛡️ Enterprise Mitigations

Recommended mitigations include:
- Use strong, unique passwords for service accounts.
- Prefer Group Managed Service Accounts (gMSAs) where appropriate.
- Minimize privileges assigned to service accounts.
- Avoid unnecessary membership of service accounts in privileged groups.
- Review and remove unnecessary SPNs.
- Prefer AES Kerberos encryption over legacy RC4 where operationally feasible.
- Monitor Event ID 4769 for unusual service-ticket activity.
- Monitor unusual service-ticket requests from unexpected hosts.
- Monitor Kerberos encryption types and investigate unexpected legacy
  encryption.
- Centralize Windows Security Event Logs for correlation.
- Apply least privilege to service accounts.
- Implement Privileged Access Management for high-value administrative
  accounts.
- Regularly review service-account ownership, purpose, SPNs, and privileges.

---

## 🧑‍💻 Why This Matters

Kerberoasting demonstrates an important characteristic of Active Directory authentication: an attacker does not necessarily need direct access to a service account's password database to obtain material that can be subjected to offline password analysis.

The attack leverages legitimate Kerberos functionality:

```text
SPN
 ↓
Service Ticket Request
 ↓
Encrypted Ticket Material
 ↓
Offline Password Analysis
```

This makes detection challenging because the initial service-ticket request can appear to be normal Kerberos activity.

Effective detection therefore requires correlation across:
- User identity
- Source host
- Authentication protocol
- Kerberos ticket activity
- SPN-associated service accounts
- Ticket encryption type
- Network telemetry
- Endpoint telemetry

The investigation also demonstrates why no single telemetry source provided the complete picture.

Security Onion identified suspicious network communication, Splunk exposed the authentication and ticketing sequence, and Wireshark provided packet-level validation of the Kerberos exchange.

---

## 💻 Lab Takeaways

This lab demonstrates several important Kerberos and detection-engineering concepts:
- Kerberos service tickets can be requested remotely across network boundaries; the attacker does not need to be on the same subnet as the Domain Controller.
- SPNs identify services and provide the target for Kerberos service-ticket requests.
- Event ID 4769 provides important visibility into Kerberos service-ticket activity.
- A successful TGT request does not imply that the subsequent service ticket uses the same encryption type.
- The observed service ticket used AES256 (`etype 18 / 0x12`).
- RC4 availability on an account does not mean that the observed service ticket used RC4.
- The extracted $krb5tgs$18$ material corresponds to an AES256 Kerberos service ticket.
- `KDC_ERR_ETYPE_NOSUPP` during the initial attack demonstrated the importance of Kerberos encryption-type compatibility.
- LDAP authentication and Kerberos ticketing can be observed as separate layers of the same investigation.
- Security Onion provides useful network-level investigation and detection pivots, but network traffic alone does not prove Kerberoasting.
- Wireshark can validate the underlying Kerberos protocol exchange but may not capture every packet required to reconstruct the complete transaction.
- Correlating authentication and ticketing events provides stronger detection context than monitoring individual events in isolation.
- The host-based correlation rule successfully identified the observed `4624 → 4768 → 4769` sequence within 99 milliseconds.
- Successful password cracking of the extracted service-ticket material was not established by this investigation.

---

## 🔗 MITRE ATT&CK

The investigation maps primarily to:

| Tactic | Technique | ID |
|-----|-----|-----|
| Credential Access | Steal or Forge Kerberos Tickets: Kerberoasting | T1558.003 

The detailed mapping is available in the **threat-mapping/** directory.

---

## Next Steps

This repository is part of a growing Active Directory attack & detection
series, including:
- LLMNR Poisoning
- SMB Relay
- IPv6 MiTM Attacks
- Post-Compromise Enumeration
- Pass the Password / Pass the Hash
- Token Impersonation
- Kerberoasting (this repo)

---

