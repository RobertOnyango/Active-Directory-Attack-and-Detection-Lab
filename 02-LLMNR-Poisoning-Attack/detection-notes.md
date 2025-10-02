# Detection Notes — LLMNR Poisoning

## Detection Approach
- **Network Layer:**  
  - IDS/IPS (Suricata) rules flag UDP traffic on ports 5355 (LLMNR) 
  - Look for unexpected hosts answering queries  

- **Host Layer (Windows Event Logs + Sysmon):**  
  - Event ID **4625** (failed logon)  
  <!-- - Event ID **4776** (NTLM authentication attempt) -->
  - Event ID **4648** (explicit credentials)  
  - Sysmon **Event ID 3** (NetworkConnect) to attacker host  

- **Correlation Logic:**  
  - LLMNR query → NTLM auth attempt within 10–15 minutes  
  - If SMB session established, escalate severity  

---

## False Positives & Tuning
- Some IoT devices or printers use multicast name resolution legitimately.  
- Whitelist known devices to reduce noise i.e. Domain Controller
- Raise priority only if combined with NTLM authentication events.  

---

## Remediation
- Disable LLMNR & NetBIOS over TCP/IP where not needed  
- Move toward Kerberos-only authentication  
- Educate users: avoid clicking on “unknown shares” or non-existent paths  

---

## Why This Matters
This attack is **widely used in real-world environments** to gain initial credentials.  
Being able to simulate and detect it demonstrates ability to:
- Think like an attacker  
- Collect & analyze multi-source evidence  
- Build detection logic for SIEM/SOC operations