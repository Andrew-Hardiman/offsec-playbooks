
## Purpose

Identify every open port on every live host before moving to service detection. 

You have a confirmed list of live hosts from [[Step 3. Host Discovery]] in `live_hosts.txt`. If you have a single IP and no `live_hosts.txt`, create one first:

```bash
echo '<target_ip>' > live_hosts.txt
```

---

## Step 1 — Establish privilege level

- Running as root or sudo → use `-sS` (SYN scan — less likely to appear in application-level connection logs, not invisible at network level)
- Running as unprivileged user → use `-sT` (connect scan — only option available, full handshake, more likely to be logged)

---

## Step 2 — Full TCP scan

```bash
sudo nmap -sS -p- -T4 -iL live_hosts.txt -oA tcp_full
```

Unprivileged — replace `-sS` with `-sT`.

```bash
grep "Not shown:" tcp_full.nmap | grep -q "net-unreach" && echo "WARNING: net-unreach detected — routing issue suspected, results may be unreliable. Re-run scan or revisit Step 2. Scope & Reachability." || echo "No net-unreach detected"
```

⚠️ `net-unreach` is a router between you and the target returning ICMP network unreachable — not the target itself. Your results are likely unreliable.

---

## Step 3 — UDP scan

Always run. Covers high-value UDP services TCP will likely not find (SNMP, DNS, TFTP, NTP, NetBIOS).

```bash
sudo nmap -sU --top-ports 20 -iL live_hosts.txt -oA udp_top20
```

⚠️ UDP is slow. `--top-ports 20` is the default scope for this reason. Extending to `--top-ports 100` or `-p-` across multiple hosts can take a very long time — only do this if you have a specific reason.

```bash
grep "Not shown:" udp_top20.nmap | grep -q "net-unreach" && echo "WARNING: net-unreach detected — routing issue suspected, results may be unreliable. Re-run scan or revisit Step 2. Scope & Reachability." || echo "No net-unreach detected"
```

⚠️ `net-unreach` is a router between you and the target returning ICMP network unreachable — not the target itself. Your results are likely unreliable.

---

## Step 4 — Act on scan results

Run all three checks in order. Do not skip any.

---
### Check 1 — Probe individually listed filtered TCP ports

⚠️ This probe covers TCP only. If `udp_top20.gnmap` contains individually listed `filtered` or `closed|filtered` ports, note them but do not probe unless you have a specific reason.

```bash
grep "Ports:" tcp_full.gnmap | grep -oP '\d+/(closed\|)?filtered/tcp' | grep -q . && echo "Filtered ports found" || echo "No individually listed filtered ports"
```

- **No individually listed filtered ports** → move to Check 2
- **Filtered ports found** → run probe:

```bash
while read ip; do
    ports=$(grep "$ip" tcp_full.gnmap | grep -oP '\d+/(closed\|)?filtered/tcp' | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
    if [ -n "$ports" ]; then
        sudo nmap -sS --reason -p "$ports" -T4 "$ip" -oA tcp_filtered_probe_${ip}
    fi
done < live_hosts.txt
```

Move to Check 2.

---

### Check 2 — Note any majority-filtered hosts

```bash
grep "Ignored State: filtered" tcp_full.gnmap | grep -oP 'Host: \K[\d.]+'
```

- **No output** → move to Check 3
- **IPs returned** → for each IP create an artefact:

```bash
while read ip; do
    if grep "Host: $ip" tcp_full.gnmap | grep -q "Ignored State: filtered"; then
        grep -A2 "Nmap scan report for $ip" tcp_full.nmap | grep "Not shown:" > filtered_majority_${ip}.txt
    fi
done < live_hosts.txt
```

Verify:

```bash
for f in filtered_majority_*.txt; do
    [ -f "$f" ] && echo "=== $f ===" && cat "$f"
done
```

Move to Check 3.

---

### Check 3 — Confirm open ports exist

```bash
grep "Ports:" tcp_full.gnmap udp_top20.gnmap | grep -oP '\d+/open(\|filtered)?/(tcp|udp)' | grep -q . && echo "Open ports found" || echo "No open ports found"
```

- **Open ports found** → proceed to Step 5
- **No open ports found** → run targeted high-value scan:

```bash
sudo nmap -sS -p 22,80,443,21,25,3389,8080 -T1 -iL live_hosts.txt -oA tcp_targeted
```

- Something found → proceed to Step 5
- Still nothing → proceed to Step 5 with no open ports and note engagement may be heavily filtered

---

## Step 5 — Collate ports

```bash
# TCP open and open|filtered from full scan
# Filtered TCP ports are handled by the probe — do not extract them here
grep "Ports:" tcp_full.gnmap | while IFS= read -r line; do
    ip=$(echo "$line" | grep -oP '(?<=Host: )[\d.]+')
    [ -z "$ip" ] && continue
    echo "$line" | grep -oP '\d+/open(\|filtered)?/tcp' >> ports_${ip}.txt
done

# UDP all actionable states from UDP scan
grep "Ports:" udp_top20.gnmap | while IFS= read -r line; do
    ip=$(echo "$line" | grep -oP '(?<=Host: )[\d.]+')
    [ -z "$ip" ] && continue
    echo "$line" | grep -oP '\d+/(open(\|filtered)?|(closed\|)?filtered)/udp' >> ports_${ip}.txt
done

# TCP filtered probe — only exists if Check 1 found filtered ports
for f in tcp_filtered_probe_*.gnmap; do
    [ -f "$f" ] || continue
    ip=$(echo "$f" | grep -oP '\d+\.\d+\.\d+\.\d+')
    grep "Ports:" "$f" | grep -oP '\d+/(open(\|filtered)?|(closed\|)?filtered)/tcp' >> ports_${ip}.txt
done

# TCP targeted scan — only exists if Check 3 found no open ports and targeted scan was run
if [ -f "tcp_targeted.gnmap" ]; then
    grep "Ports:" tcp_targeted.gnmap | while IFS= read -r line; do
        ip=$(echo "$line" | grep -oP '(?<=Host: )[\d.]+')
        [ -z "$ip" ] && continue
        echo "$line" | grep -oP '\d+/open(\|filtered)?/tcp' >> ports_${ip}.txt
    done
fi

# Cross-state deduplication — if a port/protocol appears as both open and filtered, open wins
for f in ports_*.txt; do [ -f "$f" ] || continue; awk -F'/' '{ key=$1"/"$3; if($2=="open"){open[key]=$0} else {other[key]=$0} } END{for(k in open)print open[k]; for(k in other) if(!(k in open))print other[k]}' "$f" | sort > "${f}.tmp" && mv "${f}.tmp" "$f"; done

# Deduplicate on full string — 68/open|filtered/udp and 68/open/tcp are distinct records
for f in ports_*.txt; do [ -f "$f" ] || continue; grep '/tcp$' "$f" | sort -t'/' -k1,1n > "${f}.tmp"; grep '/udp$' "$f" | sort -t'/' -k1,1n >> "${f}.tmp"; mv "${f}.tmp" "$f"; done

# Verify
for f in ports_*.txt; do
    [ -f "$f" ] && echo "=== $f ===" && cat "$f"
done
```


---


## Step 6 — Hand off to service detection

Carry all artefacts forward to [[Step 5. Service & Version Detection]]:

- `ports_<ip>.txt` — one file per live host, all actionable ports in `port/state/protocol` format
- `filtered_majority_<ip>.txt` — one file per affected host, majority-filtered reason breakdown — only exists if Check 2 found `Ignored State: filtered`
- `tcp_filtered_probe_<ip>.nmap` — one file per affected host, reason detail for individually listed filtered ports — only exists if Check 1 found filtered ports

⚠️ If Step 5. Service & Version Detection and beyond yield nothing useful — return here and escalate using the Escalation section. Consult `filtered_majority_<ip>.txt` and `tcp_filtered_probe_<ip>.nmap` to determine which escalation technique to reach for.

---

## Escalation

Do not reach for these during a normal engagement. Return here only when default scans yield nothing useful.

---
### Firewall rule mapping

Use when default scans return heavily filtered results. Identifies which ports the firewall is not blocking — does not confirm a service is listening.

Run both and compare:

```bash
sudo nmap -sA -p- -T4 -iL live_hosts.txt -oA ack_scan
sudo nmap -sW -p- -T4 -iL live_hosts.txt -oA window_scan
```

- Ports appearing `unfiltered` in `-sA` → firewall not blocking them
- Same ports appearing `closed` in `-sW` → corroborates firewall not blocking them
- These scans do not confirm open ports — they confirm which ports the firewall is not blocking. Take note of unblocked ports and probe them directly with `-sS` before feeding through Step 5 - Collate ports.

---
### Stateless firewall evasion

Use when `-sS` and `-sT` are both returning heavily filtered results. Exploits stateless firewall misconfigurations where rules match specifically on the SYN flag rather than blocking all traffic to a port. Useless against correctly configured stateless firewalls and stateful firewalls entirely.

```bash
sudo nmap -sN -p- -T4 -iL live_hosts.txt -oA null_scan
sudo nmap -sF -p- -T4 -iL live_hosts.txt -oA fin_scan
sudo nmap -sX -p- -T4 -iL live_hosts.txt -oA xmas_scan
```

`open|filtered` results feed into Step 5 — Collate ports as `open|filtered`. Do not promote to `open`. Service detection in [[Step 5. Service & Version Detection]] will determine if anything is listening.

---
### Stealth options

Append to any scan command when operating on a real engagement where attribution or detection is a concern:

| Option                               | Purpose                                 | Condition                                             |
| ------------------------------------ | --------------------------------------- | ----------------------------------------------------- |
| `-D <IP1>,<IP2>,RND,ME`              | Decoy scan — hides your IP among others | Attribution risk                                      |
| `-f` / `-ff`                         | Fragment packets into 8/16 byte chunks  | Evading traditional IDS/firewall                      |
| `--source-port 53`                   | Spoof source port                       | Firewall allows traffic from trusted ports            |
| `--data-length <num>`                | Pad packets with random data            | Evading IDS signature matching                        |
| `-e <interface> -Pn -S <SPOOFED_IP>` | Full IP spoofing                        | Only if you can monitor network traffic for responses |
| `--spoof-mac <MAC>`                  | Spoof MAC address                       | Same subnet only                                      |

---

### Maximum stealth — idle/zombie scan

Your IP never touches the target. Requires a genuinely idle host with predictable sequential IP ID incrementation. If the zombie is busy — results are useless.

```bash
sudo nmap -sI <ZOMBIE_IP> -p- -T4 <target>
```

---

## Timing reference

| Flag  | Use case                                   |
| ----- | ------------------------------------------ |
| `-T0` | Paranoid - very slow                       |
| `-T1` | Real engagements — stealth priority        |
| `-T3` | Nmap default                               |
| `-T4` | CTFs and practice targets                  |
| `-T5` | Fastest — risks packet loss and inaccuracy |

---