## Wireshark Investigation

The Wireshark investigation focused on validating the network activity associated with the attacker-controlled host `192.168.4.11` following the alerts and host-based findings observed in Splunk Enterprise.

The objective of the packet analysis was to:
- Confirm reconnaissance activity targeting remote administration services.
- Identify potential WinRM or RDP session establishment.
- Investigate whether Active Directory enumeration generated observable network traffic.
- Correlate network telemetry with the host-based events identified during the Splunk investigation.

---

### Investigating RDP and WinRM Probing Activity

Filter all traffic originating from the attacker-controlled IP `192.168.4.11` targeting the common remote administration ports:
- RDP (`3389`)
- WinRM HTTP (`5985`)
- WinRM HTTPS (`5986`)

```wireshark
ip.addr == 192.168.4.11 && (tcp.port == 3389 || tcp.port == 5985 || tcp.port == 5986)
```

The packet analysis revealed:
- Multiple TCP SYN packets
- Incomplete TCP 3-way handshakes
- Traffic targeting remote administration service ports
- Reconnaissance activity consistent with service discovery and port scanning

The observed connections remained in the `incomplete SYN` state, indicating that the attacker system attempted to probe the services but did not successfully establish full sessions within the captured traffic.

This behavior aligned with:
- The Nmap scanning activity detected by Security Onion.
- Earlier connectivity and WinRM session establishment issues observed during the attack simulation.

---

### Investigating Additional WinRM Activity

Filter all traffic associated with WinRM ports to identify additional remote management activity within the packet capture.

```wireshark
(tcp.port == 5985 || tcp.port == 5986)
```

The analysis identified no LDAP enumeration traffic was observed in the packet capture.

---

### Reverse DNS Lookup Activity

The packet analysis also identified multiple reverse DNS lookup requests (`PTR` queries) originating from the attacker-controlled host.

These requests attempted to resolve internal IP addresses to hostnames within the Active Directory environment, suggesting:
- Host discovery activity
- Internal subnet mapping
- Enumeration of network assets

This activity supported the broader reconnaissance narrative established during the investigation.

---

### Correlation with Host Telemetry

While Wireshark successfully captured reconnaissance-related network activity, it did not provide direct visibility into:
- PowerShell command execution
- PowerView activity
- SharpHound execution
- Host-based enumeration commands

These activities were instead observed through:
- Windows Event Logs
- Sysmon telemetry
- Splunk investigations

This highlights an important operational reality in enterprise investigations:

> Network telemetry alone may not provide complete visibility into post-compromise activity, particularly when attacker actions transition from network reconnaissance to host-based execution and in-memory tooling.

Effective investigations therefore require correlation between:
- Packet captures
- IDS alerts
- Authentication telemetry
- Process creation logs
- Endpoint instrumentation