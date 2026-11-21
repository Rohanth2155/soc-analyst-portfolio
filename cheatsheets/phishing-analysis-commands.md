# Phishing Analysis: Command Cheat Sheet

Work on a VM, never open samples in a mail client, never click links, and defang IOCs.

## 1. Headers

```bash
grep -iE "^(From|Return-Path|Reply-To|Message-ID|Subject|Date|X-Mailer):" sample.eml
grep -i "^Received:" sample.eml                         # read bottom to top
grep -iE "Authentication-Results|Received-SPF|dkim|dmarc" sample.eml
grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" sample.eml | sort -u   # every IPv4 in the file
```

| Check | Reading |
|---|---|
| From vs Return-Path vs Reply-To | Mismatches signal spoofing |
| Received chain | Bottom is the first hop. Trust only hops added by servers you control. |
| spf / dkim / dmarc | pass, fail, softfail, none, temperror, permerror. Report exactly. |
| Message-ID domain | Often exposes the real sending system |

## 2. IP investigation

```bash
whois <ip> | grep -iE "orgname|netname|country|descr|abuse|inetnum|org-name"
dig -x <ip> +short                                      # PTR record
```
Then check VirusTotal (`/gui/ip-address/<ip>`) and AbuseIPDB (`/check/<ip>`). Record the date, because reputation changes and cloud IPs are reassigned.

## 3. Domains and URLs

```bash
whois <domain> | head -40                               # "not found" = not registered now
whois <domain> | grep -iE "creat|registrar|expir|status"
dig +short <domain>
dig +short NS <domain>
```
Browser tools: VirusTotal (URL tab), urlscan.io (private scan), crt.sh (certificate history). Never visit the live URL.

## 4. Body, links and attachments

```bash
grep -iE "content-type|filename" sample.eml             # multipart/mixed or a filename = attachment

python3 - <<'PY'
import email, re
from email import policy
with open('sample.eml', 'rb') as f:
    m = email.message_from_binary_file(f, policy=policy.default)
body = m.get_body(preferencelist=('html', 'plain'))
t = body.get_content() if body else ''
print("== Anchor text -> href ==")
for href, text in re.findall(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', t, re.I | re.S):
    print(re.sub(r'<[^>]+>', '', text).strip()[:60], '->', href)
print("== src / action targets ==")
for u in sorted(set(re.findall(r'(?:src|action)\s*=\s*["\']([^"\']+)', t, re.I))): print(u)
print("== Any http(s) URL ==")
for u in sorted(set(re.findall(r'https?://[^\s"\'<>]+', t))): print(u)
PY
```

Save and check an attachment (never open it):
```bash
python3 - <<'PY'
import email
from email import policy
with open('sample.eml', 'rb') as f:
    m = email.message_from_binary_file(f, policy=policy.default)
for p in m.iter_attachments():
    name = p.get_filename() or 'attachment.bin'
    open(name, 'wb').write(p.get_payload(decode=True)); print("saved", name)
PY
file attachment.bin            # true type, ignore the extension
sha256sum attachment.bin       # then search the hash on VirusTotal
strings -n 8 attachment.bin | head -50
olevba file.docm               # Office macros (pip install oletools)
```

## 5. Defanging

```bash
echo "http://evil.example.com/login" | sed 's/\./[.]/g; s/http/hxxp/g'
```

## 6. MITRE quick map

| Finding | ID |
|---|---|
| Malicious link | T1566.002 |
| Malicious attachment | T1566.001 |
| Phishing for information | T1598 |
| Impersonation | T1656 |
| User opens file / clicks link | T1204.002 / T1204.001 |

## 7. Verdict checklist

```
Sender fields | Authentication | Received chain | Origin IP | Links | Attachments
Verdict -> IOCs (defanged) -> MITRE -> Actions
```
