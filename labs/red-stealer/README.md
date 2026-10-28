# Red Stealer: Threat Intel Investigation (CyberDefenders)

![Platform](https://img.shields.io/badge/Platform-CyberDefenders-blue) ![Difficulty](https://img.shields.io/badge/Difficulty-Easy-green) ![Category](https://img.shields.io/badge/Category-Threat%20Intel-orange)

## Scenario

As a SOC threat intelligence analyst, I was given a suspicious executable suspected of communicating with a command-and-control (C2) server. The goal: identify the malware, collect IOCs, map its behavior to MITRE ATT&CK, and give the SOC and Incident Response teams actionable data.

| | |
|---|---|
| **Tools** | VirusTotal, MalwareBazaar, Malpedia, MITRE ATT&CK |
| **Difficulty** | Easy |
| **Time** | ~30 minutes |
| **Skills shown** | Malware triage, IOC extraction, MITRE mapping, detection coverage |

## Investigation

### 1. Classify the sample
Looked up the SHA-256 on VirusTotal. Microsoft classifies it as a **Trojan**. The category speeds up understanding of the malware's behavior and attack vector.

### 2. Name the file
The file name is **Wextract** (extension excluded). A clear name keeps SOC communication consistent.

### 3. Check when it first appeared
First submitted to VirusTotal on **2023-10-06 04:41 UTC**. Newer samples may need faster containment, while older ones are usually better documented.

### 4. Map behavior to MITRE ATT&CK
The malware collects data before exfiltration: **T1005, Data from Local System**.

### 5. Find the connectivity check
After execution, it resolves **facebook.com** before contacting C2. This tests internet access. The domain is legitimate, so it must **not** be blocked. It is a behavioral indicator only.

### 6. Identify the C2
The malware communicates with **77.91.124.55 on port 19071**. This is the main network IOC to block.

### 7. Find detection coverage
On MalwareBazaar, the YARA rule by "Varp0s" is **detect_Redline_Stealer**, tying the sample to the RedLine stealer family.

### 8. Check family aliases
Malpedia lists the alias **RECORDSTEALER** for the family linked to the malicious IP.

### 9. Check imports
The DLL used for privilege escalation is **ADVAPI32.dll**. Defenders can monitor for unusual loading of it.

## IOC summary

| Type | Value (defanged) | Action |
|---|---|---|
| SHA-256 | `248fcc901aff4e4b4c48c91e4d78a939bf681c9a1bc24addc3551b32768f907b` | Block, hunt on endpoints |
| IP:port | `77[.]91[.]124[.]55:19071` | Block, search proxy and firewall logs |
| File name | `Wextract` | Hunting hint |
| Domain | `facebook[.]com` | Behavioral only, do not block |
| DLL | `ADVAPI32.dll` | Monitor for unusual loading |
| YARA | `detect_Redline_Stealer` | Deploy in scanners |

## MITRE ATT&CK mapping

| ID | Technique | Evidence |
|---|---|---|
| T1005 | Data from Local System | Collects local data before exfiltration |

## Verdict

**True positive.** The sample is a Trojan with infostealer behavior (RedLine / RecordStealer family) that collects local data and contacts a hardcoded C2.

### Recommended response
1. Isolate the affected host.
2. Block the hash on EDR and the C2 IP at the firewall.
3. Search logs for the C2 IP and hash across the environment.
4. Reset credentials used on the host, since stealers target saved logins and cookies.
5. Deploy the YARA rule.

### Hunting query (Splunk)
```
index=* dest_ip=77.91.124.55 dest_port=19071 | stats count by src_ip, host
```

## What I learned

- One hash can give the category, timeline, C2, techniques and family using free tools.
- IOCs are what you block. TTPs describe how the attacker behaves. Keep them separate.
- A legitimate domain (facebook.com) can appear in malware behavior. Context decides whether to block it.

## References

- [CyberDefenders: Red Stealer lab](https://cyberdefenders.org/blueteam-ctf-challenges/red-stealer/)
- [VirusTotal](https://www.virustotal.com)
- [MalwareBazaar](https://bazaar.abuse.ch)
- [MITRE ATT&CK T1005](https://attack.mitre.org/techniques/T1005/)
