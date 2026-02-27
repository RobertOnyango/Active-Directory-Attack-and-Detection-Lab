# Splunk Queries - LLMNR Poisoning

This file contains an exerpt of the important Splunk queries that I used to investigate the LLMNR attack and eventually create alerts that would detect LLMNR poisoning

## Investigations

#### Confirm NTLM handshakes

```index='windowseventlogs' Authentication_Package=NTLM```

#### Confirm successful NTLM authentication (Event ID 4624)

```index='windowseventlogs' Logon_Type=3 EventCode=4624 | stats count by Source_Network_Address```

#### Confirm if there was a spike in unsuccessful NTLM authentications

```index='windowseventlogs' Logon_Type=3 EventCode=4625 | stats count by ComputerName```

#### Confirm if any logons were attempted using explicit credentials (Even ID 4648)

```index='windowseventlogs' EventCode=4648```

#### Investigate suspicious IP activity

```index='windowseventlogs' EventCode=4648 Network_Address="192.168.1.11"```

## Alerts

Investigation of the observed activity resulted in the following three alerts being added to the detection library:

#### 1. Detect malicious authentication

During normal LLMNR attacks, the victim does not explicitly supply credentials to the rogue server, rather, Windows auto-uses the current logon session. However, we do see that the event ID 4648 is generated on Desktop-1, by an IP address that's neither the expected loopback addresses IPv4 127.0.0.1 and IPv6 ::1 nor the management server, the Domain Controller 192.168.4.10. This indicates the the victim user entered his/her credentials, an edge case that we must account and prepare for.

Event ID 4648 is triggered on the machine that is supplying the credentials i.e. ComputerName field. These details are also captured in the 'Account whose credentials were used' section. 

The Network_Address and the Subject section, where the Account_Name field is located, is the UID of the host whose process requested the credentials. In our case, this the rogue server the victim is trying to connect to.

The premise of this rule is to answer the question: Should our cleint machines be supplying credentials to the network address?

```
index="windowseventlogs" EventCode=4648 Network_Address != "127.0.0.1" Network_Address != "-" Network_Address != "192.168.4.10"
| stats count by ComputerName, Account_Name, Network_Address
| search count >= 1
```

#### 2. Outbound sysmon SMB Connections

For each 10-minute window and each source IP, tell me how many unique destinations were contacted and what those destinations were. SMB connections need to be consistent with the role-assigned to the user identity. In the lab, if the destination of an SMB connection is a workstation, this indicates abnormal activity. 

```
index="sysmon" EventCode=3 DestinationPort=445 DestinationIp!="192.168.4.10"
| bin _time span=10m
| stats dc(DestinationIp) as unique_destinations, values(DestinationIp) as DestinationIps by _time, SourceIp
| where unique_destinations >=2
| table _time, SourceIp, unique_destinations, DestinationIps
```
