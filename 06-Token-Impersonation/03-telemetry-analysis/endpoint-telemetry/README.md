# Splunk Endpoint Telemetry Analysis

## Overview

This section documents the host and security telemetry generated during the Token Impersonation investigation. The analysis focuses on correlating Windows Event Logs and Sysmon data to reconstruct the attack sequence and identify the security context, service execution, and process activity surrounding the attack.

The objective is to demonstrate how individual telemetry sources can be combined in Splunk to build an evidence-based attack timeline and identify detection opportunities.

---

**First artifact**: Malicious IP Address 192.168.4.11 authenticating to domain host using NTLM-auth only.

<defense 3>

---

**Second Artifact** The presense of Event ID 4672 and Event ID 4624 that is via NTLM authentication, *in the same timestamp*, raises so much concern. High-privileged successful logon autenticated via the insecure NTLM is a clear sign of compromise i.e. Insecure Privilege Escalation.

<defense 9>

---

**Third Artifact**: Unauthrorized files, located directly under *C:\Windows* with randomly generated names launched directly by the SCM, *services.exe* and are running as *SYSTEM*, using the OS privileges (Highest privilege in Windows). These file names are:
- fioLUfBp.exe
- eBfTlBzd.exe

<defense 13>

---

**Fourth Artifact** Services that triggered `services.exe` to run the executables (via the normal function of *services.exe* looking up the service file name executable using the service name as an identifier) also have randomized file names which are: 
- GFCoruhGsrYHYnaK
- qkrYMCKsLKfWEFCc
- VFzXKOBuQoQPpICb

<defense 16>

---

**Fifth Artifact** The temporal proximity between the service creation and the executables running strongly supports the hypothesis that the service installation and process creation were part of the same execution sequence. 

We observe the bahviour, relationships and lifecycle of the suspicious executables in the victim host as follows:
- It's parent service names (also random). 
- Windows process `services.exe` executing them.
- Executables calling and executing Windows internal binaries e.g. `WerFault.exe` and `rundll32.exe`.

<defense 17>

---

**Sixth Artifact** The full attack chain from the insecure logon, specifically highlighting privileges assigned during the session the to the binary execution by the randomly named executable. We get this by combining Artifact Two and Artifact Five.

<defense 10> <defense 19>

- The compromised session possessed the capability to perform token manipulation.

---

**Artifact Assessment**
- Insecure logon (Event ID 4624, Authentication NTLM, Logon_Type 3) by the non-admin user `fernandesb`.
- Evidence that the logon has high privileges with the presence of Event ID 4672 in the same timestamp of the successful logon by the same Account_Name on the same victim host.
- During this logon session:
    - Randomly named services with were created on the victim host. (Event ID 7045)
    - The executables of the files indicated that they were stored in `%SYSTEMROOT%` (`C:\Windows`) with different random names.
    - The services were executed by `services.exe` under the high priviledge **SYSTEM** authorization context.
    - This execution led the suspicious services to call Windows internal binaries `WerFault.exe` and `rundll32.exe`.

***Notes***

- A non-admin domain account obtained an elevated security context possessing privileges associated with token manipulation, followed by SYSTEM-level execution on the victim.
- The `fernandesb` logon session was assigned an elevated access token containing `SeImpersonatePrivilege` and other powerful privileges. The subsequent `SYSTEM-level` execution demonstrates a transition to a higher-privileged security context; however, the available telemetry does not independently prove that this transition occurred through token impersonation.
- The presence of `SeImpersonatePrivilege` establishes that the compromised session had the capability to perform token-impersonation techniques. The subsequent `SYSTEM` execution makes token abuse a viable hypothesis, but additional telemetry would be required to prove that a `SYSTEM` or another user's token was actually impersonated.

---

**Detection Opportunities**

 - Starting of a highly priviledged logon that is NTLM authenticated.
 - Not common for services to be stored directly in %SYSTEMROOT%.
 - Creation of services after insecure NTLM-authenticated logon.