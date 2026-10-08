# Detection Notes -- Kerberoasting

## Attack Summary

The detection engineering investigation focused on identifying the authentication
and Kerberos ticketing sequence observed during the Kerberoasting attack.

The available telemetry showed:

- Successful NTLM network authentication (Event ID 4624)
- Kerberos TGT issuance (Event ID 4768)
- Kerberos service-ticket request (Event ID 4769)
- Matching user and source IP across the three events

The investigation resulted in one additional host-based correlation detection.

---

## Detection Opportunity

### NTLM Authentication Followed by Kerberos TGT and Service Ticket

Detect a successful NTLM network logon followed by Kerberos TGT issuance and
service-ticket request for the same normalized user and source IP within
5 seconds.

```spl
index=windowseventlogs (EventCode=4624 Authentication_Package=NTLM Logon_Type=3) OR EventCode=4768 OR EventCode=4769
| eval Source_IP=replace(coalesce(Source_Network_Address, Client_Address), "^::ffff:", "")
| eval RawAccount=coalesce(Account_Name, Target_User_Name)
| eval RawAccount=mvfilter(RawAccount!="-" AND RawAccount!="")
| eval User=lower(mvindex(split(mvindex(RawAccount,0),"@"),0))
| sort 0 _time User Source_IP
| transaction User Source_IP maxspan=5s
| eval distinct_codes=mvcount(mvdedup(EventCode)), sequence=mvjoin(EventCode,">")
| where distinct_codes=3 AND match(sequence,"4624.*4768.*4769")
| table _time User Source_IP sequence duration
```

---

## Detection Logic

The rule correlates:

```
4624 NTLM Network Logon
        ↓
4768 Kerberos TGT Issuance
        ↓
4769 Kerberos Service Ticket Request
```

The correlation uses:
- User as the account pivot
- Source IP as the host pivot
- 5 seconds as the maximum transaction window

The source IP is normalized to account for IPv4-mapped IPv6 addresses, while the username is normalized to account for UPN formatting and case differences.

---

## Validation

The detection was validated against the Kerberoasting attack telemetry.

Observed sequence:

**4624 → 4768 → 4769**

```
User:       fernandesb
Source IP:  192.168.1.10
Duration:   0.099 seconds
```

The detection successfully correlated the three events into a single transaction.

---

## Detection COnsiderations

This detection identifies a suspicious NTLM-to-Kerberos ticketing sequence. It
does not independently prove Kerberoasting.
The Kerberoasting assessment requires additional context, including the targeted
service account, SPN, service-ticket details, encryption type, and other
network and endpoint evidence collected during the investigation.
The rule should therefore be treated as a behavioral detection and
investigative pivot rather than a standalone proof of compromise.

---
