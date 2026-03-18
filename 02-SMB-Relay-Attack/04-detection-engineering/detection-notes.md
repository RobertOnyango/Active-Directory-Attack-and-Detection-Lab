# Detection Notes — SMB Relay (NTLM Relay)

## Detection Approach

### Network Layer (Primary Detection)

Primary indicators were observed through **Suricata and Zeek network telemetry**:

- SMB sessions to unauthorized or non-standard server **192.168.1.11**.
- SMB **Tree Connect** requests to `IPC$`.
- Multiple NTLM authentication attempts across separate SMB sessions by the rogue host **192.168.1.11**.
- Sequential SMB connections from one host to another within a short time window.

These behaviors suggest authentication capture followed by relay activity.

---

### Host Layer (Windows Event Logs)

Endpoint telemetry provides supporting evidence that the relayed authentication succeeded.

Relevant Windows Security Logs include:

- **Event ID 4624** – Successful logon
- **Logon Type 3** – Network logon
- **Authentication Package** – NTLM

A key indicator is when the **Source Address** in the authentication event corresponds to a device that should not normally authenticate to the target host.

---

### Packet Analysis (Wireshark)

Wireshark can be used to confirm the relay behavior at the packet level by examining NTLM authentication traffic.

Key validation steps:

- Extract NTLMSSP authentication messages.
- Compare **NTLM security blobs** between sessions.
- Confirm that the **NTLMSSP_AUTH message is replayed** from one session with one host, to another session with a separate host.

Matching authentication blobs across two SMB sessions strongly indicates **NTLM relay activity**.

---

## Correlation Logic

SMB relay itself does not generate a unique Windows event. Detection relies on identifying anomalies in authentication context rather than explicit exploit logs.

A typical detection chain may include the following sequence:

1. **LLMNR or NBT-NS poisoning activity** detected on the network.
2. NTLM authentication captured by an attacker-controlled host.
3. New SMB authentication attempt observed from the attacker to another host.
4. **Event ID 4624 (Logon Type 3)** recorded on the target system.
5. Throughout steps 1-4, SMB **Tree Connect** request to `IPC$` or `ADMIN$` is observed as a key IoC, that indicates **priviledge escalation**.

---

## False Positives & Tuning

NTLM authentication may legitimately occur in some environments, particularly where legacy systems are still in use.

Common legitimate use cases include access to or by:

- File servers
- Legacy authentication mechanisms
- Backup or management software

### Tuning Recommendations

- Establish a **baseline for NTLM authentication activity**.
- Whitelist known SMB servers and management hosts.
- Escalate alerts when NTLM authentication:
  - originates from unusual hosts
  - occurs shortly after name resolution poisoning
  - targets multiple hosts in rapid succession

--- 