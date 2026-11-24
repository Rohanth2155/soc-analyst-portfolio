# Phishing Analysis: Bradesco / Livelo Reward Lure (Sample 1)

![Type](https://img.shields.io/badge/Type-Phishing%20Analysis-red) ![Verdict](https://img.shields.io/badge/Verdict-Phishing-critical) ![Confidence](https://img.shields.io/badge/Confidence-High-orange)

## Summary

An email impersonating **Bradesco / Livelo** claims the recipient's card has **92,990 points expiring today** and pushes them to click a link. Header, routing and link analysis show it is **phishing**: the sender is spoofed, the mail came from a default-named cloud VPS as `root`, no authentication passed, and the link goes to an unrelated domain.

| | |
|---|---|
| **Case ID** | PH-001 |
| **Email date (UTC)** | 2023-09-19 18:35:49 |
| **Analyzed** | 2026-11-21 |
| **Verdict** | Phishing (high confidence) |
| **Tools** | Text editor / Python `email` module, whois, dig, VirusTotal, AbuseIPDB |
| **Safety** | Nothing clicked or opened. Analysis done on a Kali VM. All IOCs defanged. |

## 1. Email details

| Field | Value |
|---|---|
| Subject | CLIENTE PRIME - BRADESCO LIVELO: Seu cartão tem 92.990 pontos LIVELO expirando hoje! |
| From | "BANCO DO BRADESCO LIVELO" `<banco.bradesco@atendimento[.]com[.]br>` |
| Return-Path | `root@ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06` |
| Reply-To | None seen |
| Message-ID | `<20230919183549.39DEA3F725@ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06>` |
| Body | `text/html`, no attachments |

## 2. Authentication

| Check | Result |
|---|---|
| SPF | temperror |
| DKIM | none |
| DMARC | temperror |

`temperror` means the receiver could not evaluate the check (temporary error). It is not a "fail". The message is **unauthenticated**: nothing proves Bradesco sent it.

## 3. Routing (Received chain, read bottom to top)

| Hop | What it shows |
|---|---|
| 1 | Created by Postfix on `ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06`, **userid 0 (root)** |
| 2 | Microsoft Exchange Online Protection recorded the connection from **137[.]184[.]34[.]4** |
| 3-4 | Microsoft internal routing to the mailbox |

Hop 2 was written by Microsoft, a trusted server, so **137[.]184[.]34[.]4** is the origin IP. The hostname in hop 1 matches the Message-ID hostname.

## 4. Origin IP investigation

| Check | Result |
|---|---|
| Owner | DigitalOcean, LLC (AS14061), US |
| Network | DIGITALOCEAN-137-184-0-0 |
| Reverse DNS (PTR) | `1627707[.]cloudwaysapps[.]com` (managed hosting) |
| Hostname pattern | Default cloud droplet naming (Ubuntu, 1 vCPU, 1 GB, SFO3) |
| VirusTotal IP | 1 suspicious vendor, about 55 clean, rest unrated |
| VirusTotal URL scan of the IP | 0 flagged, redirects to a Cloudways default error page (benign) |
| AbuseIPDB | 13 reports from 9 reporters, first 2024-12-14, last 2026-05-14 |

**Caveat:** the abuse reports start about 15 months after this email, and cloud IPs are reassigned between customers. Current reputation may not describe the 2023 sender. The verdict rests on the header evidence, not on IP reputation.

## 5. Content and link analysis

| Item | Finding |
|---|---|
| Lure | Reward points expiring today (reward plus urgency), written in Portuguese for Brazilian customers |
| Buttons | "Clique aqui" and "Resgatar Agora" |
| Destination | Both go to `hxxps://blog1seguimentmydomaine2bra[.]me/` |
| Domain | Unrelated to Bradesco or Livelo, long machine-like name, `.me` TLD |
| Whois (2026-11-21) | `Domain not found`, so it is no longer registered |
| Benign URLs | Google Fonts (`fonts.googleapis.com`, `fonts.gstatic.com`), excluded from IOCs |

A dead domain does not weaken the verdict. Phishing infrastructure is often short-lived, and logs from 2023 may still contain hits.

**Limitation:** because the domain is no longer registered, its creation date, registrar and name servers could not be recovered from live whois.

## 6. Indicators of compromise (defanged)

| Type | Value | Action |
|---|---|---|
| URL | `hxxps://blog1seguimentmydomaine2bra[.]me/` | Block at proxy and DNS |
| Domain | `blog1seguimentmydomaine2bra[.]me` | Block, hunt logs |
| IP | `137[.]184[.]34[.]4` | Watch or block short-term |
| Sender | `banco.bradesco@atendimento[.]com[.]br` | Block |
| Hostname | `ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06` | Mail-log hunting |
| Return-Path | `root@ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06` | Gateway rule |

Do **not** block `137.184.0.0/16` or `/17`. It is a large shared hosting range.

## 7. MITRE ATT&CK

| ID | Technique |
|---|---|
| T1566.002 | Phishing: Spearphishing Link |
| T1204.001 | User Execution: Malicious Link |

## 8. Findings

1. Brand impersonation: the `From` domain is not the bank's.
2. `Return-Path` is `root@` on a default-named VPS.
3. Sent as root by a script, with no authentication passed.
4. Link destination is unrelated to the brand.
5. Reward plus urgency social engineering.
6. Link domain is no longer registered (short-lived infrastructure).

## 9. Verdict

**Phishing, high confidence.**

## 10. Recommended response

1. Block the sender address, URL and domain at the email gateway, proxy and DNS.
2. Search proxy and DNS logs for the domain. A hit means someone clicked.
3. Purge the message from all mailboxes by sender, subject and Message-ID.
4. If a click is found: reset credentials, check card and banking activity, notify the user.
5. Report the IP to `abuse@digitalocean[.]com` with the headers and UTC time.
6. Report the domain or URL to PhishTank, OpenPhish or Google Safe Browsing if still live.

## Hunting queries (Splunk)

```
index=* "blog1seguimentmydomaine2bra.me"
index=* "137.184.34.4" | stats count by src_ip, dest_ip, host
index=* subject="*LIVELO*" | stats count by sender, recipient
```

## Commands used

```bash
# Header fields
grep -iE "^(From|Return-Path|Reply-To|Message-ID|Subject|Date|X-Mailer):" sample-1.eml
grep -i "^Received:" sample-1.eml                      # hops, read bottom to top
grep -iE "Authentication-Results|Received-SPF" sample-1.eml

# Attachments
grep -iE "content-type|filename" sample-1.eml

# Origin IP
whois 137.184.34.4 | grep -iE "orgname|netname|country|descr|abuse"
dig -x 137.184.34.4 +short                             # PTR (reverse DNS)

# Link extraction (anchor text -> href, no clicking)
python3 - <<'PY'
import email, re
from email import policy
with open('sample-1.eml', 'rb') as f:
    m = email.message_from_binary_file(f, policy=policy.default)
body = m.get_body(preferencelist=('html', 'plain'))
t = body.get_content() if body else ''
for href, text in re.findall(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', t, re.I | re.S):
    print(re.sub(r'<[^>]+>', '', text).strip()[:60], '->', href)
PY

# Domain registration check
whois blog1seguimentmydomaine2bra.me | head -40        # "Domain not found" = not registered

# Defang before sharing
echo "http://evil.example.com" | sed 's/\./[.]/g; s/http/hxxp/g'
```

## Method (reusable checklist)

```
1. Sender: From vs Return-Path vs Reply-To
2. SPF / DKIM / DMARC results
3. Received chain, bottom to top, trust only hops you control
4. Origin IP: whois, PTR, VirusTotal, AbuseIPDB (note the date)
5. Message-ID and X-Mailer clues
6. Links: real domain, domain age, reputation, urlscan.io (never click)
7. Attachments: type, hash, sandbox
8. Verdict, IOCs (defanged), MITRE, actions
```

## What I learned

- Read the `Received` chain bottom to top and trust only hops added by servers you control.
- `temperror` is not `fail`. Report auth results exactly.
- A default VPS hostname in the Message-ID can expose the real sending infrastructure.
- Current IP reputation may not describe the past, so check dates before drawing conclusions.
- Exclude benign URLs (fonts, CDNs) from IOC lists.
- A dead domain is still evidence. Hunt old logs.

## Tools

whois, dig, VirusTotal, AbuseIPDB, urlscan.io, crt.sh, Python `email` module
