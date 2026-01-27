# Splunk Queries - LLMNR Poisoning

This file contains an exerpt of the important Splunk queries that I used to investigate the LLMNR attack and eventually create alerts that would detect LLMNR poisoning

## Investigations

### Confirm NTLM handshakes

index='windowseventlog' Authentication_Package=NTLM

### Confirm successfull NTLM authentication (Event ID 4624)

index='windowseventlog' Logon_Type=3 EventCode=4624
| stats count by Source_Network_Address

### Confirm if there was a spike in unsuccessful NTLM authentications

index='windowseventlog' Logon_Type=3 EventCode=4625
| stats count by ComputerName

### Confirm if any logons were attempted using explicit credentials (Even ID 4648)

index='windowseventlog' EventCode=4648

### Investigate suspicious IP activity

index='windowseventlog' EventCode=4648 Network_Address="
192.168.1.11"

## Alerts

### LLMNR - Detect malicious authentication

The rule will alert on authentication attempts that trigger Event ID 4648 whereby the target machine receiving the credentials is not the domain controller or processes within the host. 

```
index="windowseventlog" EventCode=4648 NOT (Network_Address IN ("127.0.0.1", "192.168.4.10"))

| bin _time span=30m
| stats dc(ComputerName) as value_count by _time

| search value_count >= 2
```

### Outbound sysmon SMB Connections

Within 10 minutes, detect 2 or more SMB connections from the same SourceIp + Image to non-DC IPs over port 445. 

```
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 DestinationPort=445 NOT DestinationIp="192.168.4.10"

| bin _time span=10m
| stats dc(DestinationIp) as value_count by _time

| search value_count >= 2
```

#### Improved alert in Splunk
```
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=3
DestinationPort=445
NOT DestinationIp="192.168.4.10"

| bin _time span=10m
| stats count as smb_connection_count 
        by _time SourceIp DestinationIp Image
| where smb_connection_count >= 2
| table _time SourceIp DestinationIp Image smb_connection_count
| sort - smb_connection_count
```

### LLMNR -> SMB correlation
Filter out any LLMNR traffic and all SMB traffic not sent to the Domain Controller within a span of 5m

```
index="windowseventlogs" EventCode=4648 OR index=Sysmon EventCode=3 DestinationPort=445
| eval stage=case(EventCode=4648,"auth", EventCode=3,"smb")

index="windowseventlogs" index="sysmon" (DestinationIp="224.0.0.252 AND DestinationPort=5355) AND (DestiantionPort=445 AND DestinationIp!="192.168.4.10")
| bin _time span=5m
| stats dc(event_type) as event_type_count by _time

| search event_type_count >= 2
```