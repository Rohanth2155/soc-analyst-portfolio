# Oski: Threat Intel Investigation (CyberDefenders)

> **Platform:** CyberDefenders | **Difficulty:** Easy | **Category:** Threat Intel

## 🎯 Scenario

As a SOC analyst, I was given an Any.Run sandbox report for a suspicious sample believed to be an information stealer (belonging to the **Stealc** malware family). The goal: identify its behavior, extract the config and network indicators, and map its tactics to MITRE ATT&CK so the SOC can block and hunt it.

- **Tools:** Any.Run sandbox report, VirusTotal, MITRE ATT&CK
- **Difficulty:** Easy
- **Time:** ~30 minutes
- **Skills shown:** Sandbox report analysis, IOC extraction, config review, MITRE mapping

---

## 🔍 Investigation

### 1. Identify the sample
Pulled the SHA-256 from the sandbox report header:
```text
a040a0af8697e30506218103074c7d6ea77a84ba3ac1ee5efae20f15530a19bb
```

### 2. Check when it was created
The sample's creation time is **2022-09-28 17:40:46 UTC**. Timing helps decide how well documented the threat is and how urgent containment is.

### 3. Read the network tab
The malware sends an HTTP **POST** to:
```text
hxxp://171[.]22[.]28[.]221/5c06c05b7b34e8e6[.]php
```
A POST to a hardcoded external IP is a typical sign of stolen data leaving the host.

### 4. Find the supporting library
The sandbox shows the malware using **sqlite3.dll**. Browsers store saved logins in SQLite databases, so stealers need this library to read them.

### 5. Check the staging location
The malware works from `C:\ProgramData\`. This folder is writable by most users and often overlooked, which makes it a common malware staging spot.

### 6. Review the config
The sample uses an **RC4 key** to decrypt its strings:
```text
5329514621441247975720749009
```

### 7. Measure the execution time
Time taken: **5 seconds**. Stealers work fast: they collect, package and send data within seconds, so detection depends on blocking early and on network visibility.

### 8. Map behavior to MITRE ATT&CK
The credential harvesting maps to **T1555, Credentials from Password Stores**. If the sandbox lists the sub-technique, **T1555.003 (Credentials from Web Browsers)** is the more precise label.

---

## ⛓️ Behavior Chain

```text
Execute -> contact C2 -> fetch sqlite3.dll into C:\ProgramData
-> read browser credential databases -> decrypt strings (RC4)
-> POST stolen data to /5c06c05b7b34e8e6.php
```

---

## 📋 IOC Summary

| Type | Value (defanged) | Action |
| :--- | :--- | :--- |
| **SHA-256** | `a040a0af8697e30506218103074c7d6ea77a84ba3ac1ee5efae20f15530a19bb` | Block, hunt on endpoints |
| **IP** | `171[.]22[.]28[.]221` | Firewall block |
| **URL** | `hxxp://171[.]22[.]28[.]221/5c06c05b7b34e8e6[.]php` | Block, search proxy logs |
| **File** | `sqlite3.dll` | Alert on creation outside normal software paths |
| **Path** | `C:\ProgramData\` | Monitor new DLLs and EXEs |
| **RC4 key** | `5329514621441247975720749009` | Add to detection notes |

---

## 🗺️ MITRE ATT&CK Mapping

| ID | Technique | Evidence |
| :--- | :--- | :--- |
| **T1555** | Credentials from Password Stores | Reads stored browser credentials through `sqlite3.dll` |

---

## ⚖️ Verdict

**True positive.** The sample is an information stealer (**Stealc** family) that fetches supporting libraries, harvests browser credentials and exfiltrates them over HTTP POST to a hardcoded C2.

### Recommended Response
1. Isolate the affected host.
2. Block the hash, C2 IP and URL path.
3. Reset all credentials stored in browsers on that host.
4. Search endpoints for `sqlite3.dll` created in `C:\ProgramData`.
5. Review proxy logs for the POST path.

### Hunting Queries (Splunk)
```splunk
index=* "171.22.28.221"
index=* "5c06c05b7b34e8e6.php"
index=* sha256="a040a0af8697e30506218103074c7d6ea77a84ba3ac1ee5efae20f15530a19bb"
index=* EventCode=11 TargetFilename="C:\\ProgramData\\*.dll" | stats count by Image, TargetFilename
```
*(Note: The last query assumes Sysmon file-create logs (Event ID 11).)*

---

## 💡 What I Learned

- A sandbox report answers most triage questions: process tree, network, files and MITRE in one place.
- Stealers are fast, so network blocking and early alerts matter more than slow investigation.
- Common staging folders like `C:\ProgramData` are worth monitoring.
- Always give the full IOC: IP, port and URL path, not just the IP.

---

## 🔗 References

- [CyberDefenders: Oski lab](https://cyberdefenders.org/blueteam-ctf-challenges/oski/)
- [Any.Run](https://any.run)
- [MITRE ATT&CK T1555](https://attack.mitre.org/techniques/T1555/)