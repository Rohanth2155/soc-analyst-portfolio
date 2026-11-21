# SOC Analyst Portfolio

Hands-on write-ups from my journey toward an entry-level SOC analyst role. Each lab follows the same structure: scenario, investigation steps, findings, IOCs (defanged), MITRE ATT&CK mapping, verdict and recommended response.

## Labs

| Lab | Type | Skills shown |
|---|---|---|
| [Red Stealer](labs/red-stealer) | Threat intelligence | Malware triage, IOC extraction, MITRE mapping, detection coverage |
| [Oski](labs/oski) | Sandbox analysis | Reading a sandbox report, stealer behavior, C2 and config indicators |
| [PsExec Hunt](labs/psexec-hunt) | Network forensics | Wireshark, SMB and NTLM analysis, lateral movement detection |
| [Phishing Sample 1](labs/phishing-sample-1) | Email analysis | Header analysis, SPF/DKIM/DMARC, origin IP investigation, link analysis |

## Tools used

Wireshark, VirusTotal, MalwareBazaar, Malpedia, Any.Run, AbuseIPDB, urlscan.io, whois/dig, Splunk (SPL), Wazuh, MITRE ATT&CK

## Conventions

- All indicators are defanged (`hxxp://`, `[.]`).
- No malware was executed and no suspicious links were opened.
- Lookup results are dated, because reputation and registration data change.

## Contact

GitHub: [Rohanth2155](https://github.com/Rohanth2155)
