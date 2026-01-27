## Suricata Rules - LLMNR Poisoning

This file contains the suircata rules used to detect LLMNR poisoning in this lab

#### Baseline rule that will alert if LLMNR multicast traffic is detected in the network

```
alert udp any any -> 224.0.0.252 5355 (msg:"LLMNR multicast query detected"; sid:100001; rev:1; classtype:policy-violation;)
```

**NOTE**: LLMNR multicast addrress = 224.0.0.252, UDP port 5355

#### Rule that will alert when there is an SMB handshake occurence with a rogue/unauthorized server.

```
alert tcp any any -> !192.168.4.10 445 (msg:"Possible SMB connection to rogue server"; flow:established; sid:100002; rev:1;)
```

**NOTE**: The IP address 192.168.4.10 belongs to the Domain Controller. SMB uses the TCP port 445.
