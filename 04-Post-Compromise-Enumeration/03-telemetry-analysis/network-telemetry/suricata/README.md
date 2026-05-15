## Network Telemetry Analysis (Security Onion / Suricata)

Network telemetry collected through Security Onion provided visibility into the reconnaissance phase of the attack.

![alt text](<Figure 42.png>)

The investigation identified the following network-based artifacts:

- Nmap scan alerts originating from the attacker-controlled host `192.168.4.11`
- Probing activity targeting:
  - RDP (`3389`)
  - WinRM HTTP (`5985`)
  - WinRM HTTPS (`5986`)

The alerts indicated that the attacker system performed service discovery and attempted to identify exposed remote administration services within the Active Directory environment.

![alt text](<Figure 41.png>)

> Network telemetry provided strong visibility into reconnaissance activity, but limited visibility into post-compromise host execution and in-memory tooling.