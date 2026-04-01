# Suricata Detection Rules

This file contains the suircata rules that will raise alerts when the symptoms of IPv6 MiTM are detected.

We appreciate the two alerts that were raised when signatures matching the default Suricata rules were detected in the network, however, we need to build a strong narrative in our SOC for IPv6 MiTM based on our investigations, escpecially from the evidence gathered from Wireshark.

---

## Alert when ICMPv6 rogue RAs are detected in the network

Detects ICMPv6 Router Advertisements (RA), which are used by IPv6 routers to provide network configuration. In environments where IPv6 is not explicitly configured, the presence of RA messages may indicate a rogue device attempting to introduce itself as a network router, enabling man-in-the-middle positioning.

```
alert icmpv6 any any -> ff02::1 any (
    msg:"IPv6 Router Advertisement Detected";
    icmpv6_type:134;
    flowbits:set;ipv6_ra_seen;
    sid:300001;
    priority:1;
    rev:1;
)
```

---

## Alert when DHCPv6 traffic is detected in the network

Detects ICMPv6 Router Advertisements (RA), which are used by IPv6 routers to provide network configuration. In environments where IPv6 is not explicitly configured, the presence of RA messages may indicate a rogue device attempting to introduce itself as a network router, enabling man-in-the-middle positioning.

```
alert udp any 546 -> ff02::1:2 547 (
    msg:"DHCPv6 solicitation traffic detected";
    content:"|01|";offset:0;depth:1;
    sid: 300002;
    priority:2;
    rev:1;
)
```

---

### Correlation rule that alerts when specific hosts initiate DHCPv6 configs after IPv6 RAs are detected

This sequence strongly indicates that a system has accepted rogue IPv6 network settings, a key step in IPv6-based man-in-the-middle attacks.

```
alert udp any 546 -> ff02::1:2 547 (
    msg:"IPv6 RA followed by DHCPv6 (Possible Rogue configuration)";
    content:"|01|";offset:0;depth:1;
    flowbits:isset,ipv6_ra_seen;
    sid: 300003;
    priority:1;
    rev:1;
)
```


## Alert there DNS resolution failure 

Investigations revelead that there were two indicators of DNS tampering and the presence of a rogue system influencing name resolution or acting as a malicious intermediary: 

---

1. The presence of fallback name resolution protocols, mDNS/LLMNR, in the network that take up when DNS fails due to tampering or manipulation.

```
alert udp any 5353 -> any 5353 (
    msg:"mDNS traffic detected (DNS failure);
    sid: 300004;
    priority:2;
    rev:1;
)
```

---

2. When internal clients send DNS queries to the unauthorized hosts that are neither the gateway (192.168.4.1) nor the designatied Domain Controller (192.168.4.10).

*NOTE*: This rule is specific to the lab controlled environment whereby all the clients are configured to use a central DNS server. **This rule must be tuned based on legitimate DNS infrastructure (e.g., forwarders, external resolvers)**

```
alert udp 192.168.4.0/24 any -> ![192.168.4.10,192.168.4.1] 53 (
    msg:"DNS Query to Non-Approved DNS Server";
    sid:300005;
    priority:2
    rev:2;
) 
```

---

We can correlate the baseline rule above to detect DNS queries to unauthorized servers following the observation of IPv6 Router Advertisements, indicating a high probability of a rogue MiTM after IPv6 tampering.

```
alert udp 192.168.4.0/24 any -> ![192.168.4.10,192.168.4.1] 53 (
    msg:"DNS Query to Non-Approved DNS Server";
    flowbits:isset,ipv6_ra_seen;
    sid:300006;
    priority:1
    rev:2;
) 
```

---

**NOTE**: SID 30000* - IPv6 MiTM detections

---

## Detection Takeaways

- IPv6 attacks are detectable through behavioral sequences, not single events
- Multicast protocols (RA, DHCPv6, LLMNR) are high-signal in managed networks
- DNS deviations are often the first observable anomaly
- Chaining detections (flowbits) increases confidence and reduces noise