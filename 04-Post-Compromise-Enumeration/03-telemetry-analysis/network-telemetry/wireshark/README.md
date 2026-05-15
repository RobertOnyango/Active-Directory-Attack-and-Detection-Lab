## Packet Capture Telemetry Analysis (Wireshark)

Packet-level telemetry collected and analyzed using Wireshark provided visibility into the reconnaissance and network discovery phase of the attack.

The packet captures identified the following key network artifacts originating from the attacker-controlled host `192.168.4.11`:

- TCP SYN scanning activity targeting:
  - RDP (`3389`)
  - WinRM HTTP (`5985`)
  - WinRM HTTPS (`5986`)
- Incomplete TCP 3-way handshakes (`incomplete SYN`)
- Reverse DNS lookup (`PTR`) requests
- DNS-based host discovery activity
- Internal subnet reconnaissance behavior


The packet analysis confirmed that the attacker system attempted to identify exposed remote administration services and discover internal hosts within the Active Directory environment.

The following Wireshark filter was used to isolate remote administration probing activity:

```wireshark
ip.addr == 192.168.4.11 && (tcp.port == 3389 || tcp.port == 5985 || tcp.port == 5986)
```

![alt text](<Figure 72.png>)

The analysis showed incomplete connection attempts without successful TCP session establishment, indicating reconnaissance and service probing behavior rather than confirmed remote access within the captured traffic.

Additional WinRM-related traffic was investigated using:

```wireshark
(tcp.port == 5985 || tcp.port == 5986)
```

![alt text](<Figure 74.png>)

The packet captures did not reveal:
- Successful LDAP enumeration traffic
- Fully established WinRM sessions
- Observable PowerView or SharpHound network execution

This highlighted an important investigative limitation:

> Packet captures provide visibility into network communication, but not direct visibility into host-based process execution or in-memory tooling.

The investigation therefore relied heavily on correlating packet-level telemetry with:
- IDS alerts from Security Onion
- Windows Event Logs
- Sysmon telemetry
- Splunk investigations

to reconstruct the complete attack timeline.