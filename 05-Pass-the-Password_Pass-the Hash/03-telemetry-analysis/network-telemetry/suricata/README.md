## Security Onion Telemetry Analysis

### Alert Summary

Security Onion generated an alert identifying a host suspected of running Kali Linux within the Active Directory environment.

| Field | Value |
|---------|---------|
| Alert Name | Possible Kali Linux hostname in DHCP Request Packet |
| Severity | High |
| Source IP | 192.168.4.11 |
| Investigation Status | True Positive |
| Attack Phase | Initial Access / Credential Abuse |

The alert served as the initial indicator of compromise (IOC) and guided subsequent investigations across endpoint and authentication telemetry sources.

---

## Network Telemetry Analysis

### Host Identification

The alert identified the endpoint:

```text
192.168.4.11
```

as the source of the suspicious DHCP activity.

Further investigation confirmed that this system corresponds to the Kali Linux attacker machine used throughout the attack simulation.

---

### Port Activity Analysis

Reviewing Security Onion dashboards revealed the following network activity associated with the source host.

| Port | Protocol | Observation |
|---------|---------|---------|
| 443 | HTTPS | Normal web browsing activity |
| 53 | DNS | DNS requests sent to the network gateway |
| 67 | DHCP | DHCP requests sent to obtain network configuration |

---

### HTTPS Traffic

HTTPS traffic was observed between the host and external resources.

#### Assessment

- Expected network activity.
- Consistent with normal web browsing behavior.
- No immediate indicators of malicious activity.

---

### DNS Traffic

DNS traffic was observed between the source host and the gateway:

```text
192.168.4.1
```

#### Assessment

- Expected behavior for a newly connected device.
- Required for hostname resolution and network communications.
- No suspicious DNS patterns observed during the investigation period.

---

### DHCP Traffic

DHCP traffic was observed from the attacker host to the gateway.

#### Observed Activity

| Source IP | Destination IP | Destination Port |
|------------|------------|------------|
| 192.168.4.11 | 192.168.4.1 | 67 |

The observed traffic is consistent with DHCP lease negotiation messages such as:

- DHCP Discover
- DHCP Request

#### Assessment

This activity indicates that the host was actively requesting network configuration information and attempting to gain access to network resources.

Because the DHCP request contained a hostname commonly associated with Kali Linux, Security Onion generated the corresponding alert.

---

## Investigation Findings

The investigation produced the following findings:

| Finding | Result |
|-----------|-----------|
| Rogue Host Identified | Yes |
| Kali Linux Host Detected | Yes |
| DHCP Activity Observed | Yes |
| DNS Activity Observed | Yes |
| HTTPS Activity Observed | Yes |
| Additional Security Onion Alerts | No |

The evidence confirms that the attacker-controlled host successfully joined the network and generated sufficient telemetry for Security Onion to identify its presence.

---

## Detection Opportunities

Security Onion successfully identified the attacker host before lateral movement activities were investigated through endpoint telemetry.

Potential detection opportunities include:

- DHCP requests containing known penetration testing hostnames.
- Unauthorized operating systems appearing on enterprise networks.
- Rogue devices requesting network configuration information.
- New hosts communicating with internal infrastructure.
- Unapproved systems generating DNS and authentication traffic.

---

## SOC Assessment

The Security Onion investigation successfully identified an unauthorized host operating within the Active Directory environment. Although the DHCP, DNS, and HTTPS activity observed during this phase was not inherently malicious, the presence of a Kali Linux system on the network represented a significant security concern and justified further investigation.

The alert provided an effective starting point for the incident response process and enabled investigators to pivot into authentication, credential abuse, and lateral movement telemetry collected from Windows Event Logs and Splunk Enterprise.

---