# Wireshark Investigation – SMB Relay Attack

After validating the relay activity using **Security Onion (network alerts)** and **Splunk (host authentication logs)**, packet-level analysis was performed in Wireshark to confirm the exact sequence of events during the SMB relay attack.

Wireshark allows us to observe the **raw protocol interactions** that occur during NTLM authentication, SMB negotiation, and the credential relay process. By inspecting these packets, we can reconstruct how the attacker captured and reused the victim's authentication without knowing the password.

---

## Initial Network Activity

The packet capture begins with **ICMP packets originating from the router**, which were sent to various hosts on the network. These packets are typical in local network environments and indicate general network activity prior to the attack sequence.

Shortly afterward, we observe an **interrupted TCP three-way handshake initiated by the rogue device**.

The sequence appears as:

```SYN → SYN/ACK → RST```

This pattern indicates that the rogue host attempted to initiate a connection but immediately reset the session after the target responded. This is evidence of **network reconnaissance**.

---

![alt text](<Figure 24.png>)

---

## Victim Authentication to the Rogue SMB Server

The actual relay sequence begins when the victim machine **192.168.4.16** initiates a TCP connection over **port 445 (SMB)**.

The **TCP three-way handshake completes successfully** in the following packets:

| Packet Numbers | Description |
|----------------|-------------|
| 37–39 | TCP three-way handshake between 192.168.4.16 and 192.168.1.11 |

Once the connection is established, SMB negotiation begins.

| Packet Numbers | Description |
|----------------|-------------|
| 40–43 | SMB negotiation request and response between the victim and rogue server |

This negotiation establishes the SMB protocol parameters required for authentication.

---

## NTLM Authentication Leak

Following SMB negotiation, the NTLM authentication handshake occurs.

| Packet Numbers | Description |
|----------------|-------------|
| 50–53 | NTLM challenge-response authentication sequence |

At **packet 53**, Wireshark shows the **NTLMSSP_AUTH message**, which contains the authentication response from the victim system.

This packet confirms that the victim machine **192.168.4.16 sent its NTLM authentication data to the attacker machine 192.168.1.11**.

At this point, it is safe to assume, the attacker has successfully captured the victim's authentication material.

---

## Relay to the Target System

Immediately after obtaining the NTLM authentication blob, the attacker, **192.168.1.11**, initiates a **new SMB session toward the target machine 192.168.4.12**,  just as it did with the victim machine **192.168.4.16**. See packets **56-60**.

Packet **65** shows that the first SMB session was terminated after the host's credentials were captured.

| Packet Numbers | Description |
|----------------|-------------|
| 66–67 | NTLM negotiation between attacker and victim |

The packets above indicate that the attacker is preparing the SMB session required to relay the stolen credentials.

---

![alt text](<Figure 25.png>)

---

## NTLM Relay Execution

The actual credential relay occurs during the following packets:

| Packet Numbers | Description |
|----------------|-------------|
| 68–69 | NTLM challenge-response negotiation between attacker and target |

![alt text](<Figure 26.png>)

A closer inspection of **packet 72** reveals where the relay occurs.

In this packet, the user **ronyango** on the attacker machine **192.168.1.11** sends a **security blob** to the target system **192.168.4.12**.

This security blob corresponds to the **NTLM authentication response previously captured from 192.168.4.16**.

The authentication chain can therefore be reconstructed as:

```192.168.4.16 → 192.168.1.11 → 192.168.4.12```

The attacker reused the captured NTLM authentication **without decrypting or cracking it**, successfully authenticating to the target system.

---

## SMB Tree Connect Evidence

Further confirmation of the attack appears later in the packet capture.

Packet **85** shows that the victim machine **192.168.4.16** sends a **Tree Connect request** to the rogue SMB server **192.168.1.11**.

This indicates that the victim machine considered the attacker system to be a legitimate SMB server, meaning the NTLM authentication succeeded.

Immediately afterward, **packet 87** shows the attacker relaying the authenticated SMB session to the target machine **192.168.4.12**.

The attacker forwards the **same IPC$ Tree Connect request**, demonstrating that the SMB session was relayed directly without needing to decrypt the NTLM authentication data.

---

## Investigation Summary

Wireshark packet analysis confirms the complete SMB relay sequence:

1. The victim machine initiated an SMB connection to the attacker.
2. SMB negotiation established the authentication session.
3. The NTLM authentication handshake leaked the victim's credentials.
4. The attacker captured the NTLM authentication blob.
5. The attacker initiated a new SMB session with the relay target.
6. The captured authentication blob was relayed to the target host.
7. The attacker successfully authenticated to the target system.

This packet-level evidence validates the findings previously observed in **Security Onion and Splunk**, providing a full reconstruction of the NTLM relay attack from the network perspective.