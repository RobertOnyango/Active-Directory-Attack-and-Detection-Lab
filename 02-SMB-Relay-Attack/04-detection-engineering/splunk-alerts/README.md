# Splunk Alert Rules

Investigation of the observed activity in the domain and the artifacts subsequently collected resulted in the following two alerts being added to the detection library.

## Malicious SMB Relay Authentication Success

```
index="windowseventlogs" EventCode=4624 Logon_Type=3 Authentication_Package=NTLM
| where NOT cidrmatch("192.168.4.0/24", Source_Network_Address) AND Source_Network_Address!="127.0.0.1" AND Source_Network_Address!="-"
| stats count by ComputerName, Source_Network_Address
```

---

## NTLM Authentication from Multiple Hosts (Relay Indicator)

```
index="windowseventlogs" EventCode=4624 Logon_Type=3 Authentication_Package=NTLM
| stats dc(ComputerName) as TargetHosts by Source_Network_Address
| where TargetHosts > 1
```

