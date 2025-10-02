# PCAP Evidence (Screenshots)

This folder contains screenshots from Wireshark captures of LLMNR traffic.  
Full PCAPs are not shared to avoid exposing sensitive data.  

## Sanitization Learning
I am learning how to sanitize PCAPs using tools like TraceWrangler and `tcprewrite`.  
The idea is to:
- Replace private IPs with dummy ranges
- Strip payloads but keep headers for detection testing
- Validate that LLMNR queries/responses remain intact

For now, I include screenshots to demonstrate what was captured.  