# Detection Engineering 

## Overview


# NTLM Logon Followed by Kerberos TGT and Service Ticket (Same User / Source IP)

A Splunk SPL detection that finds a user authenticating over the network with **NTLM**, followed within **30 seconds** by a **Kerberos TGT request** and a **Kerberos service-ticket request**, all from the same source IP.

## Events used

| EventCode | Meaning | Filter applied |
|-----------|---------|----------------|
| 4624 | Successful logon | `Authentication_Package=NTLM` and `Logon_Type=3` (network logon) |
| 4768 | Kerberos TGT requested | none |
| 4769 | Kerberos service ticket requested | none |

## The rule

```spl
index=windowseventlogs (EventCode=4624 Authentication_Package=NTLM Logon_Type=3) OR EventCode=4768 OR EventCode=4769
| eval Source_IP=replace(coalesce(Source_Network_Address, Client_Address), "^::ffff:", "")
| eval RawAccount=coalesce(Account_Name, Target_User_Name)
| eval RawAccount=mvfilter(RawAccount!="-" AND RawAccount!="")
| eval User=lower(mvindex(split(mvindex(RawAccount,0),"@"),0))
| sort 0 -_time User Source_IP
| transaction User Source_IP maxspan=5s
| eval distinct_codes=mvcount(mvdedup(EventCode)), sequence=mvjoin(EventCode,">")
| where distinct_codes=3 AND match(sequence,"4624.*4768.*4769")
| table _time User Source_IP sequence duration
```

## How it works, line by line

### 1. Base search

```spl
index=windowseventlogs (EventCode=4624 Authentication_Package=NTLM Logon_Type=3) OR EventCode=4768 OR EventCode=4769
```

Pulls only the three event types needed. The 4624 is restricted to NTLM network logons (`Logon_Type=3`) so interactive and Kerberos logons never enter the pipeline. Filtering in the base search keeps the expensive `transaction` step small.

### 2. Normalize the source IP

```spl
| eval Source_IP=replace(coalesce(Source_Network_Address, Client_Address), "^::ffff:", "")
```

- The 4624 stores the client address in `Source_Network_Address`; the 4768/4769 store it in `Client_Address`. `coalesce` puts both in one field.
- Kerberos events often log IPv4 addresses in IPv4-mapped IPv6 form (`::ffff:192.168.1.10`), while the NTLM 4624 logs plain `192.168.1.10`. Without stripping the `::ffff:` prefix, the same host appears as two different sources and the events never group.

### 3. Normalize the account name

```spl
| eval RawAccount=coalesce(Account_Name, Target_User_Name)
| eval RawAccount=mvfilter(RawAccount!="-" AND RawAccount!="")
| eval User=lower(mvindex(split(mvindex(RawAccount,0),"@"),0))
```

Three separate quirks are handled here:

1. **Multivalue account on 4624.** A 4624 contains two account name fields: the *Subject* (usually `-` for a network logon) and the *New Logon* account. Depending on field extraction, `Account_Name` can hold both. `mvfilter` drops the `-` placeholder so only the real account remains.
2. **UPN suffix on 4769.** The 4769 logs the account as `user@domain.local`, while the 4768 and 4624 log just `user`. `split(...,"@")` and `mvindex(...,0)` keep only the part before the `@`, so all three events share one key.
3. **Case differences.** `lower()` ensures `Administrator` and `administrator` are treated as the same user.

Without this normalization the three events carry three different `User` values and never correlate.

### 4. Sort

```spl
| sort 0 _time User Source_IP
```

`transaction` needs events in a consistent time order. The `0` removes `sort`'s default 10,000-result limit, which would otherwise silently drop events on a busy domain controller.

### 5. Correlate

```spl
| transaction User Source_IP maxspan=30s
```

Groups events that share the same `User` and `Source_IP` and fall within 5 seconds of each other. Each resulting row is one candidate sequence. Adjust `maxspan` to widen or narrow the correlation window.

### 6. Validate the group

```spl
| eval distinct_codes=mvcount(mvdedup(EventCode)), sequence=mvjoin(EventCode,">")
| where distinct_codes=3 AND match(sequence,"4624.*4768.*4769")
```

- **Why not `eventcount=3`?** `eventcount` counts *all raw events* in the group, duplicates included. A real sequence often contains repeats (for example, two 4624 events from one authentication), so a valid group can have four or more events, while a meaningless group of three identical events would pass. Counting **distinct** `EventCode` values with `mvdedup` checks what actually matters: all three event types are present.
- **The `sequence` check.** `mvjoin` builds a string of the codes, and `match` tests that they appear in the order 4624, 4768, 4769. See [Known limitation: ordering](#known-limitation-ordering) before relying on this as an ordering guarantee.

### 7. Output

```spl
| table _time User Source_IP sequence duration
```

Keeps the result readable: when it started, who, from where, which codes were seen, and how long the sequence took in seconds.

## Known limitation: ordering

By default, `transaction` returns multivalue fields as a **deduplicated set sorted alphabetically**, not in arrival order. As written, `sequence` therefore always reads `4624>4768>4769` whenever all three codes are present, so the regex check cannot reject an out-of-order group. In practice `distinct_codes=3` is doing the real filtering.

If strict ordering matters, keep arrival order by changing the `transaction` line to:

```spl
| transaction User Source_IP maxspan=30s mvlist=EventCode
```

Then verify on a known sequence that `sequence` reads in chronological order (for example `4624>4624>4768>4769`). If it comes out reversed on your deployment, flip the regex to `4769.*4768.*4624`.

## Assumptions

- Windows Security logs are in `index=windowseventlogs`.
- Field names match your Splunk Add-on for Windows extraction: `Authentication_Package`, `Logon_Type`, `Source_Network_Address`, `Client_Address`, `Account_Name`, `Target_User_Name`. Some TAs call the package field `Authentication_Package_Name`. If the rule returns nothing, check the names against your data (`| fieldsummary`).
- Domain controller auditing is enabled for Kerberos Authentication Service and Kerberos Service Ticket Operations, and logon auditing is enabled for the systems receiving NTLM logons.

## False positives

The rule is intentionally simple, and it does not exclude:

- **Machine accounts** (usernames ending in `$`), which generate routine Kerberos traffic
- **Loopback and local sources** (`::1`, `127.0.0.1`)
- **Anonymous logons**
- Legitimate clients that fall back between NTLM and Kerberos (for example, accessing a resource by IP address rather than hostname)

Review results against your own environment before alerting on them, then add exclusions for known-good accounts, hosts, or subnets.

## Running it as an alert

- **Schedule:** every 5 minutes over the last 10 minutes. The search window must be longer than `maxspan` plus the schedule interval, or a sequence that straddles two runs will be missed.
- **Throttle:** suppress by `User` and `Source_IP` (for example, for one hour). Overlapping windows would otherwise fire twice for the same sequence.
- **Trigger:** once per result, so each user/IP pair becomes its own alert.
- **Performance:** `transaction` runs on the search head and is memory intensive. For wide historical hunts, expect it to be slow; for scheduled alerts, keep the window short.

## Possible improvements

Deliberately left out to keep the rule readable:

- Exclude machine accounts, loopback addresses, and anonymous logons before the `transaction`
- Capture `Ticket_Encryption_Type` from the 4769 to flag RC4 (`0x17`) service tickets
- Include `Service_Name` and the workstation or host name for faster triage
- Rewrite with `stats` and per-event-code timestamps (`min(eval(if(EventCode=4624,_time,null())))`) for true ordering checks and better scalability on very busy domain controllers

## Testing

The rule was validated against a known NTLM, TGT, service-ticket sequence in test data. To validate in your environment, generate a network logon with NTLM (for example, access a share by IP address) followed by Kerberos activity for the same account from the same host, then confirm the sequence appears as a single row.

---