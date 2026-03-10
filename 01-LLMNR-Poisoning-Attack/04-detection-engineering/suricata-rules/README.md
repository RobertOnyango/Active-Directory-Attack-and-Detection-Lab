# Suricata Detection Rules

This file contains the suircata rules that will raise alerts when the symptoms of LLMNR poisoning are detected.

## Baseline rule that will alert if LLMNR multicast traffic is detected in the network

The rule will be very loud in enterprise environments. For this lab scenario, it works for illustration purposes.

```
alert udp any any -> 224.0.0.252 5355 (
    msg:"LLMNR multicast query detected";
    sid:100001;
    priority:2;
    rev:1;
)
```

## 'Silent' Rule that sets a flowbit maker for correlation, SMB traffic observed within a short period after LLMNR traffic

LLMNR traffic is not necessarily bad in your environment, escpecially if LLMNR is not explicitly disabled. The rule wil detect the traffic and set the flowbit 'llmnr_observed' but will not raise an alert.

```
alert udp any any -> 224.0.0.252 5355 (
    msg:"LLMNR multicast query detected";
    flowbits:set,llmnr_observed;
    flowbits:noalert;
    sid:100002;
    rev:1;
)
```

**NOTE**: LLMNR multicast addrress = 224.0.0.252, UDP port 5355

## Chained detection rule that will alert when there is an SMB handshake occurence with a unauthorized server.

This rule follows the above rule and will alert when LLMNR traffic is observed, then SMB traffic observed shortly aftwerwards. 

The rule specifies that we are keen on the packets that are  sent towards the server in the TCP session (i.e. the server that typically replies with a SYN-ACK packet). This server is not the DC, hence !192.168.4.10. Also, we need an established connection, meaning the TCP 3-way handshake bewtween the client and this server completed successfully.

**NOTE**: The IP address 192.168.4.10 belongs to the Domain Controller. SMB uses the TCP port 445.

The rule will generate one alert per host (by_src) within a period of 30 seconds if matching pattern is detected.

```
alert tcp any any -> !192.168.4.10 445 (
    msg:"Possible SMB connection to non-domain host server after LLMNR detected"; flowbits:isset,llmnr_observed;
    flow:to_server,established;
    threshold:type both, track by_src, count 1, seconds 30;
    sid:100003;
    priority:1;
    rev:1;
)
```

## Rule that will alert on SMB traffic to servers whose IP is not within the internal IP address space

We alert on SMB traffic to IPs not within the internal range. This could be to external IPs that signals network scanning, 

```
alert tcp any any -> !192.168.4.0/24 445 (
    msg:"SMB traffic to unknown server not in internal network";
    flow:to_server,established;
    sid:200001;
    priority:2;
    rev:1;
)
```

**NOTE**: SID:10000* - LLMNR detection track and SID:20000* - Outbound SMB detection track.