# PsExec Hunt: Lateral Movement Investigation (CyberDefenders)

![Platform](https://img.shields.io/badge/Platform-CyberDefenders-blue) ![Difficulty](https://img.shields.io/badge/Difficulty-Easy-green) ![Category](https://img.shields.io/badge/Category-Network%20Forensics-orange)

## Scenario

An IDS alert flagged suspicious lateral movement involving PsExec. As a SOC analyst, I investigated the provided PCAP in Wireshark to find the attacker's entry point, the machines targeted, the credentials used, and how far the breach went.

| | |
|---|---|
| **Tools** | Wireshark |
| **Protocols** | SMB2 over TCP/445, NTLM authentication |
| **Difficulty** | Easy |
| **Time** | ~30 minutes |
| **Skills shown** | PCAP analysis, SMB and NTLM inspection, lateral movement detection, MITRE mapping |

## Background

PsExec is a legitimate Microsoft admin tool. Attackers abuse it to run commands on remote Windows machines. It works in three steps:

1. Authenticate to the target over SMB.
2. Copy its service binary (`PSEXESVC.exe`) into the hidden `ADMIN$` share.
3. Start that service and talk to it through the `IPC$` share.

Each step leaves a trace in the packets.

## Investigation

### 1. Find the source of the activity
Opened **Statistics → Protocol Hierarchy**. SMB2 over NetBIOS session service stood out. Filtering on `smb2` showed an SMB Negotiate Request from **10.0.0.130** to **10.0.0.133** on port 445. **10.0.0.130** is the machine the attacker operated from.

### 2. Identify the first pivot target
Followed the TCP stream and opened the NTLM Challenge response. It exposes the target's NetBIOS and DNS computer names. The first pivot target (10.0.0.133) is **SALES-PC**.

### 3. Find the account used
In the **SMB2 Session Setup Request**, the NTLMSSP authentication section shows the account name: **ssales**. This account was used to authenticate, so it should be treated as compromised.

### 4. Find the service executable
An **SMB2 Create Request** later in the stream writes a file named **PSEXESVC.exe** on the target. This is the PsExec service component.

### 5. Find the install share
The Create Request's tree points to `\\10.0.0.133\ADMIN$`. **ADMIN$** is the hidden share mapped to `C:\Windows`, and PsExec uses it to drop its service binary.

### 6. Find the communication share
An earlier **Tree Connect Request** targets `\\10.0.0.133\IPC$`. **IPC$** carries the RPC traffic PsExec uses to control the remote service.

### 7. Find the second target
The attacker also sent an SMB Negotiate from 10.0.0.130 to **10.0.0.131**. The NTLM Challenge revealed the hostname **MARKETING-PC**. The session setup returned **STATUS_LOGON_FAILURE**, so this pivot attempt failed.

## Attack timeline

```
10.0.0.130 -> 10.0.0.133 (SALES-PC)
  SMB negotiate -> NTLM auth as ssales -> Tree connect IPC$
  -> Create PSEXESVC.exe on ADMIN$ -> remote execution

10.0.0.130 -> 10.0.0.131 (MARKETING-PC)
  SMB negotiate -> NTLM auth -> STATUS_LOGON_FAILURE (blocked)
```

## IOC summary

| Type | Value | Meaning | Action |
|---|---|---|---|
| IP | `10.0.0.130` | Source of lateral movement | Isolate, investigate |
| IP / host | `10.0.0.133` / SALES-PC | Compromised target | Isolate, forensic review |
| IP / host | `10.0.0.131` / MARKETING-PC | Failed target | Monitor, check for other attempts |
| Account | `ssales` | Credentials used | Reset password, review activity |
| File | `PSEXESVC.exe` | PsExec service binary | Search all hosts, check `C:\Windows` |
| Share | `ADMIN$` | Service install path | Alert on remote writes |
| Share | `IPC$` | Control channel | Baseline normal use |

## MITRE ATT&CK mapping

| ID | Technique | Evidence |
|---|---|---|
| T1021.002 | Remote Services: SMB/Windows Admin Shares | SMB sessions to ADMIN$ and IPC$ |
| T1570 | Lateral Tool Transfer | PSEXESVC.exe copied to the target |
| T1569.002 | System Services: Service Execution | PsExec runs through a remote service |
| T1078 | Valid Accounts | Authentication with the ssales account |

## Verdict

**True positive.** An attacker used valid credentials (`ssales`) to move from 10.0.0.130 to SALES-PC with PsExec. A second move to MARKETING-PC failed.

### Recommended response
1. Isolate 10.0.0.130 and 10.0.0.133.
2. Reset the `ssales` password and review its recent logons.
3. Search all endpoints for `PSEXESVC.exe` and Event ID 7045 (service install).
4. Restrict remote admin share access and use host firewalls to limit SMB between workstations.
5. Check other hosts for logon failures from 10.0.0.130.

## Detection ideas

**Wireshark filters used:**
```
smb2
smb2.cmd == 1                          # Session Setup
smb2.cmd == 3                          # Tree Connect
smb2.cmd == 5                          # Create (file open)
smb2.filename contains "PSEXESVC"
smb2.nt_status == 0xc000006d           # STATUS_LOGON_FAILURE
ntlmssp                                # NTLM authentication messages
```

**Splunk (Windows logs):**
```
index=* EventCode=7045 Service_File_Name="*PSEXESVC*"
index=* EventCode=5145 Share_Name="\\\\*\\ADMIN$" | stats count by Source_Address, Account_Name
index=* EventCode=4625 | stats count by src_ip, user
```

## What I learned

- PsExec leaves a clear trail: SMB auth, ADMIN$ write, IPC$ connection, service start.
- The NTLM Challenge message leaks the target's hostname, which helps identify machines from a PCAP alone.
- A failed pivot (STATUS_LOGON_FAILURE) is still evidence of attacker intent.
- Limiting workstation-to-workstation SMB would have cut this attack's reach.

## References

- [CyberDefenders: PsExec Hunt lab](https://cyberdefenders.org/blueteam-ctf-challenges/psexec-hunt/)
- [MITRE ATT&CK T1021.002](https://attack.mitre.org/techniques/T1021/002/)
- [MITRE ATT&CK T1569.002](https://attack.mitre.org/techniques/T1569/002/)
