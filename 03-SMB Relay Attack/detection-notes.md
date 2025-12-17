# Detection Notes — SMB Relay (NTLM Relay)

## Detection Approach
- **Network Layer (Primary Detection by Suricata & Zeek):**
    - Detect SMB sessions to unauthorized or non-standard servers
    - Flag Tree Connect requests to IPC$
    - Identify repeated NTLM authentication attempts across different SMB sessions

- **Wireshark:**
    - Extract and compare NTLMSSP security blobs
    - Confirm authentication replay (relay) by matching NTLM AUTH messages

- **Host Layer (Supporting Evidence)**
    - Windows Security Logs
    - Event ID 4624
    - Logon Type 3 (Network Logon)
    - Authentication Package NTLM

#### Note: SMB relay itself does not generate a unique Windows event. Detection relies on authentication context anomalies, not explicit exploit logs.

---

- **Correlation Logic**
    - LLMNR poisoning → NTLM credential capture (previous stage)
    - NTLM authentication observed over SMB to second host
    - Network logon (4624 / Type 3) from unexpected source IP
    - SMB Tree Connect to IPC$ confirms relay success

---

- **False Positives & Tuning**
    - Legitimate NTLM usage may exist for:
        - Legacy systems
        - File servers
        - Backup software

- **Tuning recommendations:**
    - Baseline expected NTLM usage
    - Whitelist known SMB servers
    - Escalate severity when NTLM authentication follows name-resolution poisoning or targets multiple hosts

--- 

- **Remediation**
    - Enforce SMB signing (RequireSecuritySignature = Enabled)
    - Disable NTLM where operationally possible
    - Limit administrative SMB access
    - Monitor for NTLM authentication in Kerberos-preferred environments

- **Why This Matters**
- SMB relay attacks:
    - Do not require password cracking
    - Often bypass endpoint-based detection
    - Are best identified through network protocol analysis and authentication context

- This lab demonstrates:
    - Realistic detection constraints
    - Multi-layer telemetry correlation
    - Practical detection engineering trade-offs in SOC environments