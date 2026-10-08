# MITRE ATT&CK Mapping -- Kerberoasting

## Technique Overview

| Field | Mapping |
|---|---|
| Tactic | Credential Access |
| Technique | T1558 - Steal or Forge Kerberos Tickets |
| Sub-technique | T1558.003 - Kerberoasting |
| Platform | Windows |

Kerberoasting is a Credential Access technique in which an adversary requests Kerberos service tickets for accounts associated with Service Principal Names (SPNs) and obtains ticket material that may be subjected to offline password cracking. MITRE ATT&CK identifies Kerberoasting as T1558.003.

---

## Attack Mapping

### T1558.003 -- Kerberoasting

The lab investigation demonstrated the following activity consistent with
Kerberoasting:

1. The attacker authenticated to the domain using the compromised
   `fernandesb` account.
2. A Kerberos TGT was obtained from the Domain Controller.
3. A Kerberos service ticket was requested for the `sql_service` account.
4. The target account was associated with an SPN:
   `DOMAINCONTROLLER/sql_service.mydomain.local:60111`.
5. The resulting service-ticket material was extracted for offline analysis.
6. The extracted ticket was represented as a Kerberos TGS hash beginning with
   `$krb5tgs$18$`, corresponding to AES256 Kerberos encryption (etype 18).

These observations map the attack to **T1558.003 - Kerberoasting**.

---

## Evidence

| Evidence | Observation | ATT&CK Relevance |
|---|---|---|
| Active Directory | `sql_service` had an SPN registered | Identifies a Kerberos service account that can be targeted |
| Event ID 4768 | TGT issued to `fernandesb` | Provides Kerberos authentication context |
| Event ID 4769 | Service ticket requested for `sql_service` | Directly relevant to service-ticket acquisition |
| Ticket Encryption Type | `0x12` / AES256 | Identifies the encryption type of the observed service ticket |
| Extracted ticket | `$krb5tgs$18$` | Confirms the extracted material represents an AES256 Kerberos TGS hash |
| Wireshark | Kerberos AS-REQ/AS-REP and TGS-REP observed | Packet-level validation of the Kerberos exchange |
| Splunk | 4624 → 4768 → 4769 within 0.099 seconds | Correlated authentication and ticketing behavior |

---

## Detection Mapping

The investigation produced one additional host-based detection:

### NTLM → TGT → Service Ticket Correlation

The detection correlates:

```text
4624 - Successful NTLM Network Logon
              ↓
4768 - Kerberos TGT Issuance
              ↓
4769 - Kerberos Service Ticket Request

---