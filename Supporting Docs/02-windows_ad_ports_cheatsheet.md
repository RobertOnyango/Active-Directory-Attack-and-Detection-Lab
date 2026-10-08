# Windows / Active Directory Service Ports — Cheatsheet

> **Scope:** Ports shown in the Active Directory exploitation series screenshots, plus the common Windows/AD services they represent.
>
> **Important:** A port being open does **not** automatically mean the host is a Domain Controller or that the corresponding service is required for AD. Some ports are optional Windows services, application services, or remote-administration services.

---

## 1. Active Directory / Domain Controller Ports

| Port | Protocol | Service / Protocol | Primary purpose | AD / Windows relevance |
|---|---|---|---|---|
| **53** | TCP/UDP | DNS | Resolves hostnames ↔ IP addresses; supports DNS queries and zone transfers/updates | **Critical to AD.** AD clients locate Domain Controllers and AD services through DNS records |
| **88** | TCP/UDP | Kerberos | Authentication using tickets | **Core AD authentication protocol.** Used for Kerberos authentication between clients, users, services and DCs |
| **135** | TCP | MS RPC Endpoint Mapper | Initial RPC connection setup; tells clients which dynamic RPC port a service is listening on | **Core Windows management/AD infrastructure.** Used by many RPC-based services |
| **139** | TCP | NetBIOS Session Service | Session-oriented NetBIOS communication | Legacy Windows file/printer sharing and some older Windows/AD communication |
| **389** | TCP/UDP | LDAP | Directory queries and directory operations | **Core AD directory access.** Used to query users, groups, computers, OUs, etc. |
| **445** | TCP | SMB | File/printer sharing and Windows networking | **Extremely important in AD environments.** Used for SYSVOL/NETLOGON, administration, file shares and many Windows protocols |
| **464** | TCP/UDP | Kerberos Password Change (kpasswd5) | Kerberos-assisted password change/set operations | Used when changing/resetting domain passwords |
| **593** | TCP | RPC over HTTP (ncacn_http) | RPC communication encapsulated over HTTP | Used by certain Windows/RPC applications; not normally a primary AD authentication port |
| **636** | TCP | LDAPS | LDAP over TLS | Encrypted LDAP directory communication |
| **3268** | TCP | Global Catalog (GC over ldap) | LDAP access to the Global Catalog | Used to search/query forest-wide directory information |
| **3269** | TCP | Global Catalog over SSL/TLS | Encrypted Global Catalog access | Secure Global Catalog queries |
| **9389** | TCP | Active Directory Web Services (ADWS) | Web-service interface used by AD administrative tools | Important for PowerShell/AD Administrative Center operations; **not shown in your screenshots but commonly associated with modern AD** |
| **49152–65535** | TCP | Dynamic RPC ports | Dynamically allocated RPC server endpoints | **Important for modern Windows Server.** AD replication and many Windows management operations may use dynamic RPC ports |

---

# 2. General Windows / Application Services in the Screenshots

| Port | Protocol | Service / Protocol | Primary purpose | Typical Windows use |
|---|---|---|---|---|
| **21** | TCP | FTP | FTP control connection | IIS FTP Server / third-party FTP servers |
| **22** | TCP | SSH | Secure remote shell and file transfer (SFTP/SCP) | OpenSSH Server on modern Windows; not an AD-specific service |
| **80** | TCP | HTTP | Unencrypted web traffic | IIS and other HTTP applications |
| **443** | TCP | HTTPS | HTTP over TLS | IIS, web APIs, management interfaces and other secure web applications |
| **1433** | TCP | Microsoft SQL Server | SQL Server database connectivity | Microsoft SQL Server default TCP listener |
| **3389** | TCP/UDP | RDP | Remote Desktop Protocol | Remote interactive Windows administration / user sessions |
| **5357** | TCP | WSDAPI / Web Services for Devices | Web Services for Devices communication | Windows device discovery/management; can appear as an HTTPAPI service |
| **5985** | TCP | WinRM over HTTP | Windows Remote Management | PowerShell Remoting / WS-Man remote administration |
| **5986** | TCP | WinRM over HTTPS | Encrypted Windows Remote Management | Secure PowerShell Remoting / WS-Man |

---

# 3. Port-by-Port Notes

## 53 — DNS

**Protocol:** UDP/TCP

### Purpose
DNS translates names such as:

```text
dc01.mydomain.local
        ↓
192.168.10.10
```

It also allows clients to discover AD services through DNS records.

### Why AD cares
Active Directory is heavily dependent on DNS.

A domain-joined computer uses DNS to locate Domain Controllers and services such as:

```text
_ldap._tcp.dc._msdcs.<domain>
_kerberos._tcp.<domain>
```

### Security relevance

Common areas to investigate:

- DNS misconfiguration
- Unauthorized DNS servers
- DNS zone transfer exposure
- Dynamic DNS abuse
- DNS tunneling
- Malicious DNS records

**Remember:**

> DNS does not authenticate the user. It helps the client **find the services required for authentication**.

---

# 4. 88 — Kerberos

**Protocol:** TCP/UDP

### Purpose
Kerberos provides ticket-based authentication.

Simplified flow:

```text
User
  |
  | Authentication
  v
KDC on Domain Controller
  |
  +--> TGT
  |
  +--> Service Ticket
          |
          v
       Target Service
```

The Domain Controller provides the **KDC (Key Distribution Center)** functionality.

### Security relevance

Important AD attacks/concepts:

- Kerberoasting
- AS-REP Roasting
- Pass-the-Ticket
- Golden Ticket
- Silver Ticket
- Overpass-the-Hash

### Key idea

```text
88 = Kerberos authentication
```

---

# 5. 135 — RPC Endpoint Mapper

**Protocol:** TCP

### Purpose
RPC allows Windows systems/services to communicate remotely.

Port **135** is the RPC Endpoint Mapper.

The basic concept:

```text
Client
  |
  | TCP 135
  v
RPC Endpoint Mapper
  |
  | "Service X is listening on dynamic port Y"
  v
Dynamic RPC Port
```

For modern Windows Server environments, dynamic RPC ports commonly fall within:

```text
49152–65535/TCP
```

### Security relevance

RPC is involved in many Windows administrative and AD operations.

It is associated with:

- Remote administration
- WMI/DCOM
- Service management
- AD replication
- SAM/LSA/Netlogon RPC
- Group Policy operations
- Other Windows management functions

### Key idea

> **135 finds the RPC service; the actual RPC conversation may then move to a dynamic high port.**

---

# 6. 139 — NetBIOS Session Service

**Protocol:** TCP

### Purpose
Provides session-oriented NetBIOS communication.

Historically used heavily for:

- Windows file sharing
- Printer sharing
- Computer-name based networking

Modern Windows environments generally prefer:

```text
SMB → TCP 445
```

rather than:

```text
SMB → NetBIOS → TCP 139
```

### Security relevance

Port 139 is often considered a **legacy Windows networking port**.

It may still appear in scans of older systems or environments where NetBIOS is enabled.

---

# 7. 389 — LDAP

**Protocol:** TCP/UDP

### Purpose
LDAP provides access to directory information.

In Active Directory, LDAP can be used to query objects such as:

```text
Users
Groups
Computers
Organizational Units
Contacts
Service Accounts
Group Policy-related objects
```

Example conceptual query:

```text
"Find all users in this OU"
             |
             v
           LDAP
             |
             v
     Active Directory
```

### Security relevance

LDAP is extremely important for AD enumeration.

Attackers may query:

- Users
- Groups
- Domain computers
- SPNs
- OUs
- Group memberships
- Domain configuration

Tools that interact with AD commonly make LDAP queries.

### Key idea

```text
389 = LDAP directory access
```

---

# 8. 445 — SMB

**Protocol:** TCP

### Purpose
SMB provides Windows network file and resource sharing.

It is used for:

- File shares
- Printer sharing
- IPC$
- SYSVOL
- NETLOGON
- Remote administration mechanisms
- Named pipes
- Various Windows RPC-based operations

### AD importance

Domain Controllers expose important shares such as:

```text
\\DC01\SYSVOL
\\DC01\NETLOGON
```

### Security relevance

SMB is one of the most important ports to understand for Windows security.

Common attack concepts include:

- SMB relay
- NTLM relay
- Pass-the-Hash
- SMB enumeration
- Anonymous/unauthenticated access where misconfigured
- Malicious file/share access
- Lateral movement

### Key idea

```text
445 = SMB
```

If you are studying AD attacks, **445 should be one of the first ports you recognize.**

---

# 9. 464 — Kerberos Password Change

**Protocol:** TCP/UDP

### Purpose
Supports Kerberos password change operations.

This is associated with changing or setting passwords in an AD/Kerberos environment.

### Remember

```text
88  → Kerberos authentication
464 → Kerberos password change
```

---

# 10. 593 — RPC over HTTP

**Protocol:** TCP

### Purpose
Carries certain RPC traffic over HTTP.

This can allow RPC-based applications to communicate through HTTP infrastructure.

### Important distinction

Do not confuse:

```text
135 → RPC Endpoint Mapper
593 → RPC over HTTP
```

They are related to RPC but serve different purposes.

---

# 11. 636 — LDAPS

**Protocol:** TCP

### Purpose
LDAP protected using TLS.

Conceptually:

```text
LDAP
389
 |
 | TLS
 v
LDAPS
636
```

### Security relevance

LDAPS protects directory traffic in transit.

Compare:

| Port | Function |
|---|---|
| 389 | LDAP |
| 636 | LDAP over TLS |

---

# 12. 3268 — Global Catalog

**Protocol:** TCP

### Purpose
Provides LDAP access to the **Global Catalog (GC)**.

The Global Catalog contains a searchable representation of objects across the Active Directory forest.

Conceptually:

```text
              AD Forest
                  |
        +---------+---------+
        |                   |
     Domain A            Domain B
        |                   |
        +---------+---------+
                  |
             Global Catalog
                  |
               TCP 3268
```

### Why it matters

The GC is useful when applications need to search for objects across domains in a forest.

---

# 13. 3269 — Global Catalog over TLS

**Protocol:** TCP

Same basic purpose as TCP 3268, but encrypted using TLS.

```text
3268 → Global Catalog
3269 → Global Catalog + TLS
```

---

# 14. 21 — FTP

**Protocol:** TCP

### Purpose
FTP provides file transfer.

TCP 21 is normally the **FTP control connection**.

FTP data transfer may involve additional ports depending on active/passive mode.

### Windows relevance

Can be provided by:

- IIS FTP Server
- Third-party FTP software

### AD relevance

Not an AD core service.

If an AD server exposes FTP, treat it as an **additional application/service**, not as an inherent requirement for AD.

---

# 15. 22 — SSH

**Protocol:** TCP

### Purpose
Secure remote command-line access.

Common related protocols:

```text
SSH
SCP
SFTP
```

### Windows relevance

Modern Windows can run **OpenSSH Server**.

However:

> SSH is not a fundamental Active Directory protocol.

In a Windows/AD environment you are more likely to encounter:

```text
RDP     → 3389
WinRM   → 5985/5986
SMB     → 445
```

for Windows administration.

---

# 16. 80 — HTTP

**Protocol:** TCP

### Purpose
Unencrypted HTTP web traffic.

Common Windows implementation:

```text
IIS (Internet Information Services)
```

Example:

```text
http://server/
```

### Security relevance

Potentially exposes:

- Web applications
- APIs
- Management interfaces
- IIS applications
- Web services

Port 80 itself does not mean IIS is running; other applications can bind to it.

---

# 17. 443 — HTTPS

**Protocol:** TCP

### Purpose
HTTP protected by TLS.

Common uses:

- IIS websites
- APIs
- Web applications
- Secure management interfaces

Conceptually:

```text
HTTP       → 80
HTTPS      → 443
```

---

# 18. 1433 — Microsoft SQL Server

**Protocol:** TCP

### Purpose
Default TCP port for Microsoft SQL Server database connections.

Example:

```text
Application
     |
     | TCP 1433
     v
Microsoft SQL Server
```

### AD relevance

SQL Server is **not an AD service**, but SQL Server may exist in an enterprise/AD environment.

Potential security concerns include:

- Weak SQL credentials
- Excessive database permissions
- SQL authentication exposure
- Integrated Windows authentication
- Service account privileges
- SQL Server-to-AD relationships

---

# 19. 3389 — Remote Desktop Protocol (RDP)

**Protocol:** TCP/UDP

### Purpose
Remote graphical Windows sessions.

```text
RDP Client
    |
    | 3389
    v
Windows Server / Workstation
```

### Security relevance

RDP is heavily used for remote administration and therefore is important for:

- Brute-force/password attacks
- Credential theft
- Lateral movement
- Remote interactive logons
- Post-compromise administration

Useful Windows telemetry includes:

```text
Event ID 4624
Logon Type 10 = RemoteInteractive
```

---

# 20. 5357 — Web Services for Devices

**Protocol:** TCP

### Purpose
Windows Web Services for Devices (WSD) functionality.

WSD uses HTTP-based communication and may be implemented through Windows HTTP.sys / HTTPAPI.

It is associated with device discovery and communication, including devices such as printers.

### Important correction

A scanner may report something similar to:

```text
Microsoft HTTPAPI httpd 2.0
```

This identifies the HTTP server implementation (`HTTP.sys`/HTTP API), not necessarily a conventional IIS website.

**5357 is commonly associated with WSD (Web Services for Devices).**

Do not automatically interpret:

```text
5357 = IIS
```

---

# 21. 5985 — WinRM over HTTP

**Protocol:** TCP

### Purpose
Windows Remote Management using HTTP.

WinRM implements the WS-Management protocol.

Common uses:

```text
PowerShell Remoting
Remote Windows administration
Remote command execution
```

Example:

```powershell
Enter-PSSession -ComputerName SERVER01
```

### Security relevance

WinRM is particularly important in Windows administration and lateral-movement investigations.

A connection to:

```text
5985
```

can indicate WinRM/PowerShell remoting activity, although the port alone does not prove malicious activity.

---

# 22. 5986 — WinRM over HTTPS

**Protocol:** TCP

Same general purpose as 5985, but protected with HTTPS/TLS.

```text
5985 → WinRM / HTTP
5986 → WinRM / HTTPS
```

---

# 23. The Windows RPC Dynamic Port Range

Modern Windows Server systems commonly use:

```text
49152–65535/TCP
```

for dynamically allocated RPC endpoints.

This is important because seeing:

```text
TCP 135
```

does **not** mean all RPC traffic stays on 135.

Instead:

```text
Client
  |
  | TCP 135
  v
RPC Endpoint Mapper
  |
  | "Use port 496xx"
  v
TCP 496xx
  |
  v
RPC Service
```

### Why this matters for AD

Several AD/Windows operations depend on RPC.

Examples include:

- AD replication
- LSA RPC
- SAM RPC
- Netlogon
- Group Policy-related operations
- WMI/DCOM
- Windows remote administration

Therefore, enterprise firewalls often need to account for both:

```text
TCP 135
+
TCP 49152–65535
```

unless the environment has deliberately restricted RPC to specific ports.

---

# 24. The Core AD Port Mental Model

Instead of memorizing ports independently, group them by **what AD is doing**.

## Name resolution

```text
53
DNS
```

> "Where is the Domain Controller?"

---

## Authentication

```text
88
Kerberos
```

> "Prove who I am."

```text
464
Kerberos password change
```

> "Change my password."

---

## Directory access

```text
389
LDAP
```

> "Give me information from Active Directory."

```text
636
LDAPS
```

> "Give me directory information over TLS."

---

## Forest-wide directory search

```text
3268
Global Catalog
```

> "Search directory information across the forest."

```text
3269
Global Catalog over TLS
```

---

## Windows networking / file sharing

```text
445
SMB
```

> "Access Windows shares, named pipes and other SMB-based services."

```text
139
NetBIOS Session Service
```

> Legacy Windows networking associated with SMB.

---

## Remote procedure calls

```text
135
RPC Endpoint Mapper
```

> "Where is the RPC service?"

```text
49152–65535
Dynamic RPC
```

> "Now communicate with that RPC service."

---

# 25. Quick AD Enumeration Cheat Sheet

When an Nmap scan shows:

```text
53
88
135
139
389
445
464
636
3268
3269
```

you should immediately think:

```text
                DOMAIN CONTROLLER
                       |
       +---------------+---------------+
       |               |               |
      DNS         Kerberos           LDAP
       |               |               |
      53              88           389/636
                                       |
                                       v
                              Global Catalog
                                  3268/3269
                                       |
                                       v
                                      SMB
                                      445
                                       |
                                       v
                                      RPC
                                   135 + high ports
```

This combination is much more characteristic of an AD Domain Controller than any single port by itself.

---

# 26. Port Relationships Worth Memorizing

| Remember this | Meaning |
|---|---|
| **53 → DNS** | Find services and hosts |
| **88 → Kerberos** | Authentication |
| **135 → RPC Mapper** | Find RPC endpoints |
| **139 → NetBIOS** | Legacy Windows networking |
| **389 → LDAP** | Directory queries |
| **445 → SMB** | Windows file/network services |
| **464 → Kerberos password change** | Password operations |
| **593 → RPC over HTTP** | RPC via HTTP |
| **636 → LDAPS** | LDAP + TLS |
| **3268 → Global Catalog** | Forest-wide directory search |
| **3269 → GC over TLS** | Secure Global Catalog |
| **3389 → RDP** | Remote graphical Windows session |
| **5357 → WSD** | Web Services for Devices |
| **5985 → WinRM HTTP** | PowerShell/remote management |
| **5986 → WinRM HTTPS** | Secure PowerShell/remote management |
| **21 → FTP** | File transfer |
| **22 → SSH** | Secure shell |
| **80 → HTTP** | Web |
| **443 → HTTPS** | Secure web |
| **1433 → SQL Server** | Database connectivity |

---

# 27. High-Value Ports for Your AD Attack & Detection Lab

For an AD attack/detection engineer, pay particular attention to:

### Tier 1 — Core AD

```text
53     DNS
88     Kerberos
389    LDAP
445    SMB
464    Kerberos password change
636    LDAPS
3268   Global Catalog
3269   Global Catalog over TLS
```

### Tier 2 — Windows infrastructure

```text
135    RPC Endpoint Mapper
139    NetBIOS
49152–65535   Dynamic RPC
5985   WinRM
5986   WinRM HTTPS
3389   RDP
```

### Tier 3 — Common additional applications/services

```text
21     FTP
22     SSH
80     HTTP
443    HTTPS
1433   SQL Server
5357   WSD
593    RPC over HTTP
```

---

# 28. Security Investigation Mapping

| Port | Useful investigation question |
|---|---|
| 53 | Is the host providing DNS? Are unusual DNS queries/updates occurring? |
| 88 | Is Kerberos authentication behaving normally? |
| 135 | Is remote RPC activity occurring? |
| 139 | Is legacy NetBIOS/SMB communication still enabled? |
| 389 | Who/what is querying AD via LDAP? |
| 445 | Is SMB being used for lateral movement, relay or share access? |
| 464 | Are password-change operations expected? |
| 593 | Is RPC-over-HTTP expected in this environment? |
| 636 | Is encrypted LDAP being used correctly? |
| 3268/3269 | What systems are querying the Global Catalog? |
| 3389 | Who is establishing RDP sessions? |
| 5357 | What device/WSD service is listening? |
| 5985/5986 | Who is using WinRM/PowerShell remoting? |
| 1433 | Which applications/users are connecting to SQL Server? |

---

# 29. Important Caveats

### Port ≠ Service

A port number is only a listening/network endpoint.

For example:

```text
443 → usually HTTPS
```

does **not** prove that IIS is running.

Likewise:

```text
5357 → WSD/HTTPAPI
```

does not mean "IIS."

Always correlate a scan with:

```text
Service detection
Process
Windows service
Configuration
Authentication activity
Event logs
```

---

### AD has more ports than this cheat sheet

The ports above are the ports shown in the training material plus the commonly relevant ADWS port and dynamic RPC range.

Real Windows/AD environments can expose additional ports depending on:

- DFS/DFSR
- Certificate Services
- SQL Server
- IIS
- Exchange
- WSUS
- Hyper-V
- Failover Clustering
- Windows deployment services
- Third-party security/management software
- Custom applications

---

# 30. The One-Minute Memorization Version

```text
AD CORE

53      DNS
88      Kerberos
389     LDAP
445     SMB
464     Kerberos Password Change
636     LDAPS
3268    Global Catalog
3269    Global Catalog over TLS

WINDOWS REMOTE MANAGEMENT

135     RPC Endpoint Mapper
139     NetBIOS Session
3389    RDP
5985    WinRM HTTP
5986    WinRM HTTPS
49152-65535  Dynamic RPC

GENERAL WINDOWS / APPLICATION SERVICES

21      FTP
22      SSH
80      HTTP
443     HTTPS
1433    Microsoft SQL Server
5357    Web Services for Devices
593     RPC over HTTP
```

---

# 31. Mental Model for Your Active Directory Series

When you perform reconnaissance against a Windows host, don't just ask:

> "What ports are open?"

Ask:

> **"What Windows capability does each port expose, and what role does that capability play in authentication, directory access, administration, lateral movement, or application delivery?"**

A useful mental chain is:

```text
                 DNS
                 53
                  |
                  v
        Find Domain Controller
                  |
                  v
              Kerberos
                 88
                  |
                  v
           Authenticate
                  |
        +---------+---------+
        |                   |
        v                   v
      LDAP                 SMB
    389/636                445
        |                   |
        v                   v
  Query AD objects     SYSVOL/NETLOGON
        |                   |
        +---------+---------+
                  |
                  v
              RPC
          135 + dynamic
                  |
        +---------+---------+
        |                   |
        v                   v
      WinRM                RDP
   5985/5986               3389
        |                   |
        v                   v
 Remote administration / lateral movement
```

This is the relationship between the ports that is most useful to retain for Active Directory attack simulation, detection engineering, and SOC investigations.

---

## Primary Microsoft references

- Microsoft Learn — **Service overview and network port requirements for Windows**
- Microsoft Learn — **Configure firewall for AD domains and trusts**
- Microsoft Learn — **TCP/IP port exhaustion troubleshooting / dynamic port range**
- Microsoft Learn — **RPC dynamic port allocation with firewalls**

**Source note:** Port assignments and AD-specific requirements should be checked against the Windows Server version and the actual services enabled in the environment. Modern Windows Server normally uses TCP dynamic ports **49152–65535** for RPC; older Windows versions used different ranges.
