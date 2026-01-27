# SPLUNK

##

Event ID 4776: The domain controller attempted to validate the credentials for an account via NTLM.

Event ID 4768: A Kerberos authentication ticket (TGT) was requested.

***index="windowseventlogs" (EventCode=4768 OR EventCode=4776)***

## Alerts
```
source="WinEventLog:Security" EventCode=4624 Logon=3 Authentication_Package="NTLM" NOT (Source_Network_Address IN ("192.168.4.0/24", "127.0.0.1"))
```