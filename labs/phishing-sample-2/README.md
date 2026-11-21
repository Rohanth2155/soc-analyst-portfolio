# Phishing Analysis: Fake Microsoft "Unusual Sign-in" Alert (Sample 2)

![Type](https://img.shields.io/badge/Type-Phishing%20Analysis-red) ![Verdict](https://img.shields.io/badge/Verdict-Phishing-critical) ![Confidence](https://img.shields.io/badge/Confidence-High-orange)

## Summary

An email posing as the **Microsoft account team** warns of an "unusual sign-in" from Russia and asks the recipient to "report the user". There is **no web link and no attachment**: every button is a `mailto:` link to one Gmail address, so the goal is to get the victim to **reply to the attacker**. The sender is spoofed, three unrelated domains appear in the sender fields, and nothing authenticated.

| | |
|---|---|
| **Case ID** | PH-002 |
| **Email date (UTC)** | 2023-09-08 05:47:04 |
| **Verdict** | Phishing (high confidence) |
| **Type** | Reply-based phishing with a fake security alert |
| **Tools** | grep, Python `email` module, whois, dig |
| **Safety** | Nothing clicked or opened. Analysis on a Kali VM. IOCs defanged. |

## 1. Sender fields

| Field | Value (defanged) | Finding |
|---|---|---|
| From | "Microsoft account team" `no-reply@access-accsecurity[.]com` | Lookalike domain, not a Microsoft domain |
| Return-Path | `bounce@thcultarfdes[.]co[.]uk` | A second, unrelated domain with a random-looking name |
| Reply-To | `sotrecognizd@gmail[.]com` | Replies go to a free Gmail account |
| Message-ID | Empty | Common for scripted sending |
| Subject | Microsoft account unusual signin activity | Fear lure |

**Three different domains** (`access-accsecurity`, `thcultarfdes`, `gmail`) appear across `From`, `Return-Path` and `Reply-To`. A genuine Microsoft message would not do this.

## 2. Authentication

| Check | Result | Meaning |
|---|---|---|
| SPF | none | The envelope domain publishes no SPF record authorizing the sending IP |
| DKIM | none | Message not signed |
| DMARC | permerror | Policy for `access-accsecurity.com` could not be evaluated (a permanent error). Not a pass and not a fail. |

The message is **unauthenticated**.

## 3. Routing (Received chain, bottom to top)

| Hop | Meaning |
|---|---|
| 1 | Microsoft Exchange Online Protection (EOP) recorded a connection from **89[.]144[.]44[.]2**, which announced itself as `thcultarfdes[.]co[.]uk` |
| 2 | Microsoft's European EOP edge |
| 3-4 | Microsoft internal routing to the mailbox |

Hop 1 was written by Microsoft, a trusted server, so **89[.]144[.]44[.]2** is the origin IP.

## 4. Origin IP and domain checks

| Check | Result |
|---|---|
| Network | `89.144.44.0/24`, NetName MSCODE (MSCode.pl) |
| Country | Poland (PL) |
| PTR | `r2[.]mscode[.]pl` |
| Abuse contact | `abuse@ghostnet[.]de` |
| `thcultarfdes[.]co[.]uk` | whois: "This domain name has not been registered" (checked 2026-11-21) |

"MSCode" is a Polish hosting organization and has nothing to do with Microsoft. I could not tell from whois whether the attacker rented this server or compromised a customer's machine.

**Limitations:** the lookups were run about three years after the email, so current IP reputation may not describe the original sender. Reputation results for the IP and registration data for `access-accsecurity[.]com` were not collected for this report.

## 5. Body analysis

**Visible text (summary):** "We detected something unusual about a recent sign-in" to the account, with sign-in details: Country Russia/Moscow, IP `103.225.77.255`, Windows 10, Firefox. It asks the user to "report the user".

| Observation | Meaning |
|---|---|
| All three anchors are `mailto:sotrecognizd@gmail.com` | **No web link.** The only action is emailing the attacker. |
| `cc` set to the same Gmail address | Replies are copied to the attacker's mailbox |
| Buttons: "Report The User", "click here" (unsubscribe), and the recipient address | Every clickable element leads to the same reply flow |
| Sign-in time `05:46:57`, email date `05:47:04` | Seven seconds apart: the "sign-in event" was generated at send time by a script |
| "sign.in" spelled with a dot in the title | Likely evasion of keyword filters |
| Block of unrelated random words at the bottom | Appears to be keyword padding, commonly used to dilute spam-filter scoring |
| Fake sign-in IP `103.225.77.255` | A lure detail. It is not the sender's infrastructure, so don't treat it as the C2 or block it based on this email alone. |

**Likely intent:** reply phishing starts a conversation that can lead to credential theft or a scam. The email itself doesn't show the final goal, so intent beyond "get a reply" is unconfirmed.

## 6. Indicators of compromise (defanged)

| Type | Value | Action |
|---|---|---|
| Sender | `no-reply@access-accsecurity[.]com` | Block |
| Domain | `access-accsecurity[.]com` | Block |
| Return-Path domain | `thcultarfdes[.]co[.]uk` | Block, hunt logs |
| Reply-To / mailto | `sotrecognizd@gmail[.]com` | Block the address, report to Google. Do not block gmail.com. |
| IP | `89[.]144[.]44[.]2` | Watch or block the single IP. Do not block the /24. |
| Lure artifact | `103[.]225[.]77[.]255` | Context only, not sender infrastructure |

## 7. MITRE ATT&CK

| ID | Technique | Why |
|---|---|---|
| T1566 | Phishing | Email-based initial contact (no link or attachment, so the parent technique fits best) |
| T1598 | Phishing for Information | The lure aims to get the victim to engage and respond |
| T1656 | Impersonation | Poses as the Microsoft account team |

## 8. Findings

1. Microsoft brand sent from a lookalike domain.
2. Three unrelated domains across `From`, `Return-Path` and `Reply-To`.
3. Free Gmail address as `Reply-To` and the target of every button.
4. SPF none, DKIM none, DMARC permerror.
5. Fear lure with fabricated sign-in details generated at send time.
6. No link or attachment, so link scanners and sandboxes would miss it.
7. Filter-evasion tricks: "sign.in" spelling and random word padding.

## 9. Verdict

**Phishing, high confidence.**

## 10. Recommended response

1. Block the sender, both domains and the Gmail address at the email gateway.
2. Search mail logs for those domains and the Gmail address. **Outbound mail to the Gmail address means a user replied.**
3. Purge the message from all mailboxes.
4. If a user replied: ask what they shared, reset the Microsoft password, review sign-ins, revoke sessions and check MFA.
5. Report the Gmail address to Google and the domain to its registrar.
6. Add a gateway rule for the HELO and Return-Path domain mismatch.

## Commands used

```bash
grep -iE "^(From|Return-Path|Reply-To|Message-ID|Subject|Date):" sample-2.eml
grep -i "^Received:" sample-2.eml
grep -iE "Authentication-Results|Received-SPF" sample-2.eml
grep -iE "content-type|filename" sample-2.eml

whois 89.144.44.2 | grep -iE "inetnum|netname|descr|country|org-name|abuse"
dig -x 89.144.44.2 +short
whois thcultarfdes.co.uk | grep -iE "registered|registrar|created|no match"

# Anchors, visible text, phone numbers and emails in the body
python3 - <<'PY'
import email, re
from email import policy
with open('sample-2.eml', 'rb') as f:
    m = email.message_from_binary_file(f, policy=policy.default)
body = m.get_body(preferencelist=('html', 'plain'))
t = body.get_content() if body else ''
for href, text in re.findall(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', t, re.I | re.S):
    print(re.sub(r'<[^>]+>', '', text).strip()[:60], '->', href)
print(re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', ' ', t)).strip()[:800])
print(set(re.findall(r'\+?\d[\d\s().-]{8,}\d', t)), set(re.findall(r'[\w.+-]+@[\w.-]+', t)))
PY
```

## Hunting queries (Splunk)

```
index=* "access-accsecurity.com"
index=* "thcultarfdes.co.uk"
index=* "sotrecognizd@gmail.com" | stats count by sender, recipient, src_user
index=* "89.144.44.2" | stats count by src_ip, dest_ip, host
```

## What I learned

- A phishing email doesn't need a link or an attachment. A `mailto:` button can be the whole attack.
- Three different domains across the sender fields is a strong, easy-to-check spoofing signal.
- `permerror`, `temperror`, `none` and `fail` are different results, so report each one exactly.
- Details inside the lure (the fake sign-in IP) are not the attacker's infrastructure.
- Check timestamps inside the body against the email date to spot generated content.
