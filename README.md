# SOC Analyst Portfolio

Hands-on write-ups from my journey toward an entry-level SOC analyst role. Each lab follows the same structure: scenario, investigation steps, findings, IOCs (defanged), MITRE ATT&CK mapping, verdict, recommended response and the commands used.

## Labs

| Lab | Type | Skills shown |
|---|---|---|
| [Red Stealer](labs/red-stealer) | Threat intelligence | Malware triage, IOC extraction, MITRE mapping, detection coverage |
| [Oski](labs/oski) | Sandbox analysis | Reading a sandbox report, stealer behavior, C2 and config indicators |
| [PsExec Hunt](labs/psexec-hunt) | Network forensics | Wireshark, SMB and NTLM analysis, lateral movement detection |
| [Phishing Sample 1](labs/phishing-sample-1) | Email analysis | Header analysis, SPF/DKIM/DMARC, origin IP investigation, link analysis |
| [Phishing Sample 2](labs/phishing-sample-2) | Email analysis | Reply-based phishing, spoofed brand, mailto lures, filter-evasion tricks |
| [Snow Trail (TryHackMe AoC 2026)](labs/thm-aoc-2026-snow-trail) | DFIR / incident response | Log triage, data recovery, evidence handling, quishing recognition, IoT containment |

## Cheat sheets

| Sheet | Contents |
|---|---|
| [Phishing analysis commands](cheatsheets/phishing-analysis-commands.md) | Header, IP, domain, link and attachment commands, defanging, MITRE map |
| [Splunk SPL commands](cheatsheets/splunk-spl-commands.md) | Core SPL commands, brute-force detection, IOC hunting queries |

## Tools used

Wireshark, VirusTotal, MalwareBazaar, Malpedia, Any.Run, AbuseIPDB, urlscan.io, whois/dig, Splunk (SPL), Wazuh, MITRE ATT&CK

## Conventions

- All indicators are defanged (`hxxp://`, `[.]`).
- No malware was executed and no suspicious links were opened.
- Lookup results are dated, because reputation and registration data change.

## Contact

GitHub: [Rohanth2155](https://github.com/Rohanth2155)
