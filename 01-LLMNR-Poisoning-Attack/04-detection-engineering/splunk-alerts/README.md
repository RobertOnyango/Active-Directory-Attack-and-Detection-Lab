# Splunk Alert Rules

Investigation of the observed activity in the domain and the artifacts subsequently collected resulted in the following two alerts being added to the detection library.

---

## 1. Detect authentication to unauthorized servers using explicit credentials

During normal LLMNR attacks, the victim does not explicitly supply credentials to the rogue server, rather, Windows auto-uses the current logon session. However, in this instance, Event ID 4648 is generated on Desktop-1. The Network Address field (the destination) contains an IP that matches neither the expected loopback addresses (127.0.0.1 or ::1) nor the management server/Domain Controller (192.168.4.10).

This indicates the the victim manually entered their credentials, an edge case that we must account for. Event ID 4648 is triggered on the source machine that is supplying the credentials (indicated in the ComputerName field), while the 'Account whose credentials were used' section captures the specific identity provided. 

In this scenario, the Network Address represents the rogue server the victim attempted to access. The core premise of this detection rule is to determine: **Should our client machines be supplying explicit credentials to this specific network address?**

```
index="windowseventlogs" EventCode=4648 Network_Address != "127.0.0.1" Network_Address != "-" Network_Address != "192.168.4.10"
| stats count by ComputerName, Account_Name, Network_Address
| search count >= 1
```

---

## 2. Alert on numerous outbound sysmon SMB Connections from one host from a specific source IP

For each 10-minute window and each source IP, tell me how many unique destinations were contacted and what those destinations were. SMB connections need to be consistent with the role-assigned to the user identity. In the lab, if the destination of an SMB connection is a workstation, this indicates abnormal activity. 

```
index="sysmon" EventCode=3 DestinationPort=445 DestinationIp!="192.168.4.10"
| bin _time span=10m
| stats dc(DestinationIp) as unique_destinations, values(DestinationIp) as DestinationIps by _time, SourceIp
| where unique_destinations >=2
| table _time, SourceIp, unique_destinations, DestinationIps
```

---
