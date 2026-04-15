# Splunk Alert Rules

Investigation of the observed activity in the domain and the artifacts subsequently collected resulted in the following two alerts being added to the detection library.

## Alert on successful NTLM authentication to non-domain hostsho

Alert whenever a host, whose IP address is not from the internal IP address pool, sucessfully authenticates using NTLM. Whitelist the loopback address since NTLM is enabled for some internal processes in Windows.

```
index="windowseventlogs" EventCode=4624 Logon_Type=3 Authentication_Package=NTLM
| where NOT cidrmatch("192.168.4.0/24", Source_Network_Address) AND Source_Network_Address!="127.0.0.1" AND Source_Network_Address!="-"
| stats count by ComputerName, Source_Network_Address
| where count > 1
```

---

## Alert on successful NTLM authentication by one Source IP on multiple hosts (Relay Indicator)

Alert on the observed artifact of one host (indicated by Source IP) successfully authenticates to more than one machine in the deployment.

```
index="windowseventlogs" EventCode=4624 Logon_Type=3 Authentication_Package=NTLM
| stats dc(ComputerName) as TargetHosts by Source_Network_Address
| where TargetHosts > 1
```

