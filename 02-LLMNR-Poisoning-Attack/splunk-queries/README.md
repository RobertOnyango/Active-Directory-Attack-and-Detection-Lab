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

### LLMNR - Detect authentication attempts

The rule will alert on authentication attempts that trigger Event ID 4648 whereby the target machine receiving the credentials is not the domain controller or processes within the host. 

index="windowseventlog" EventCode=4648 AND (Network_Address!="127.0.0.1" AND Network_Address!="-" AND Network_Address!="192.168.4.10")
| stats values(Account_Name) as username, values(ComputerName) as target count by ComputerName


### Outbound sysmon SMB Connections

This query will alert on any SMB connections not sent to the domain controller 

index="sysmon" EventCode=3 DestinationPort=445
| stats count by SourceIp, DestinationIp, Image
| where DestinationIp != "192.168.4.10"

### LLMNR -> SMB correlation

index=WindowsEventLogs EventCode=4648 OR index=Sysmon EventCode=3 DestinationPort=445
| eval stage=case(EventCode=4648,"auth", EventCode=3,"smb")