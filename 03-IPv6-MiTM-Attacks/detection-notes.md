# Detection Notes – IPv6 NTLM Relay Attack

## Detection Objective
Identify NTLM authentication abuse resulting from IPv6-based man-in-the-middle activity, focusing on credential relay and unauthorized network authentication.

## Data Sources
- Windows Security Event Logs (4624, 4720, 4724)
- Sysmon (Event ID 3 – Network connections)
- Network IDS (Suricata)
- PCAPs (Wireshark validation)

## Detection Logic Summary
This detection focuses on correlating:
- IPv6 infrastructure manipulation (rogue router advertisements, DNS changes)
- NTLM authentication over the network (Logon Type 3)
- Authentication from unexpected IP addresses or mismatched workstation identities
- Non-interactive authentication using impersonation tokens

## Key Indicators
- NTLM network logons in Kerberos-dominant environments
- Authentication over IPv6 from unauthorized hosts
- Mismatch between source IP and workstation name
- Authentication occurring shortly after infrastructure changes

## False Positives & Expected Noise
- Legitimate NTLM usage for legacy systems
- Network devices performing name resolution
- Administrative testing or misconfigured clients

These detections should be tuned with:
- Known infrastructure IP allowlists
- Approved service and administrative accounts
- Change management windows

## Detection Gaps & Limitations
- Encrypted SMB traffic limits payload inspection
- NTLM relay without authentication success may not generate logon events
- IPv6 traffic visibility depends on network telemetry coverage

## Analyst Triage Guidance
When this alert fires:
1. Confirm whether IPv6 is required in the environment
2. Identify the source IPv6 address and associated host
3. Review recent authentication and directory service events
4. Validate whether SMB signing or NTLM restrictions are enforced

## Recommended Response Actions
- Isolate affected hosts
- Disable NTLM where possible
- Enforce SMB signing
- Review AD delegation and ACLs
- Reset potentially exposed credentials

## Related Techniques
- MITRE ATT&CK: T1557 (Adversary-in-the-Middle)
- MITRE ATT&CK: T1021 (Lateral Movement)

## Related Detections
- LLMNR Poisoning Detection
- SMB Relay Detection
- NTLM Network Logon Monitoring
