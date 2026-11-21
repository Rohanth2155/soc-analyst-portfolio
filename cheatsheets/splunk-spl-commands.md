# Splunk SPL: Command Cheat Sheet

One search is a chain of commands joined by `|`. Filter first, transform later. Field names are case-sensitive.

## Core commands

| Command | Used for | Example |
|---|---|---|
| `search` | Retrieve or filter events | `index=main "Failed password"` |
| `head` / `tail` | First or last N events | `... \| head 10` |
| `table` | Show chosen columns | `... \| table _time src_ip user` |
| `fields` | Keep (`+`) or drop (`-`) fields | `... \| fields - _raw` |
| `rex` | Extract a field with regex | `... \| rex "from (?<src_ip>\S+)"` |
| `eval` | Create or change a field | `... \| eval kb=bytes/1024` |
| `stats` | Aggregate, optionally grouped | `... \| stats count by src_ip` |
| `sort` | Order results (`-` = descending) | `... \| sort -count` |
| `where` | Filter on computed values | `... \| where count > 5` |
| `dedup` | One event per unique value | `... \| dedup src_ip` |
| `top` / `rare` | Most or least common values | `... \| top limit=5 src_ip` |
| `timechart` | Counts over time | `... \| timechart span=1h count` |
| `rename` | Rename a field | `... \| rename src_ip as "Source IP"` |

## Useful `stats` functions

`count`, `dc()` (distinct count), `values()`, `sum()`, `avg()`, `min()`, `max()`, `earliest()`, `latest()`

## Regex pieces for `rex`

| Pattern | Matches |
|---|---|
| `\d+` | Digits |
| `\S+` | Non-space characters |
| `\d+\.\d+\.\d+\.\d+` | IPv4 address |
| `(?<name>...)` | Capture into field `name` |

## SSH brute-force detection

```
index=main "Failed password"
| rex "for (invalid user )?(?<user>\S+) from (?<src_ip>\S+)"
| stats count dc(user) as users_tried by src_ip
| where count > 5
| sort -count
```

## Hunting for phishing IOCs

```
index=* "malicious-domain.example"
index=* "203.0.113.5" | stats count by src_ip, dest_ip, host
index=* subject="*urgent*" | stats count by sender, recipient
```

## Windows logs (Sysmon / Security)

```
index=* EventCode=4625 | stats count by src_ip, user
index=* EventCode=7045 Service_File_Name="*PSEXESVC*"
index=* EventCode=11 TargetFilename="C:\\ProgramData\\*.dll" | stats count by Image, TargetFilename
```
