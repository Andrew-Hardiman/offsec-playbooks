
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
grep "Ports:" tcp_full.gnmap | grep -oP '\d+/open(\|filtered)?/tcp' | grep -q . && echo "Open TCP ports found" || echo "No open TCP ports found"
```

- **Open TCP ports found** → proceed to Step 5
- **No open TCP ports found** → run targeted high-value scan:

```bash
sudo nmap -sS -p 22,80,443,21,25,3389,8080 -T1 -iL live_hosts.txt -oA tcp_targeted
```

- proceed to Step 5

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

# TCP targeted scan — only exists if Check 3 found no open TCP ports and targeted scan was run
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

# Decision 
cat ports_*.txt | grep -qP '\d+/(open|open\|filtered)/(tcp|udp)' && echo "Open ports found — proceed to Step 6 Hand off" || echo "No open ports found — go to Escalation"
```

- **Open ports found** → proceed to Step 6 — Hand off to service detection
- **No open ports found** → go to Escalation section. Consult `filtered_majority_<ip>.txt` and `tcp_filtered_probe_<ip>.nmap` to determine which escalation technique to reach for.

---


## Step 6 — Hand off to service detection

Carry the below artefacts forward to [[Step 5. Service & Version Detection]]:

- `live_hosts.txt` — one file
- `ports_<ip>.txt` — one file per live host, all actionable ports in `port/state/protocol` format
- `filtered_majority_<ip>.txt` — one file per affected host, majority-filtered reason breakdown — only exists if Check 2 found `Ignored State: filtered`
- `tcp_filtered_probe_<ip>.nmap` — one file per affected host, reason detail for individually listed filtered ports — only exists if Check 1 found filtered ports (**This file provides the `reason`, which is not detailed in the `live_hosts.txt` files**)

⚠️ If [[Step 5. Service & Version Detection]] and beyond yield nothing useful — return here and escalate using the Escalation section. Consult `filtered_majority_<ip>.txt` and `tcp_filtered_probe_<ip>.nmap` to determine which escalation technique to reach for. **Also, you can create `tcp_targeted` from `Step 4/Check 3`, if not already created.**

---

## Escalation

Do not reach for these during a normal engagement. Return here only when default scans yield nothing useful.

---
### Pick the right escalation

Walk in order, stop at first match:

| #   | Symptom                                               | Section                    |
| --- | ----------------------------------------------------- | -------------------------- |
| 1   | Default scans heavily filtered, cause unclear         | Firewall rule mapping      |
| 2   | `-sA` shows unfiltered, `-sS` shows filtered          | --source-port probe        |
| 3   | Results inconsistent across re-runs                   | Slow timing                |
| 4   | `-sA` confirms stateless firewall doing SYN-filtering | Stateless firewall evasion |
| 5   | Attribution risk (real engagement)                    | Stealth options            |
| 6   | Maximum stealth required                              | Idle/zombie scan           |

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
### --source-port probe

Use when `-sA` shows ports unfiltered but `-sS` shows them filtered — firewall is trusting traffic from specific source ports. Source port and target port are independent — scan all destination ports each time, varying only the claimed source.

```bash
# Probing all ports, claiming source is DNS
sudo nmap -sS --source-port 53 -p- -T4 -iL live_hosts.txt -oA srcport_53
```

```bash
# Probing all ports, claiming source is HTTP
sudo nmap -sS --source-port 80 -p- -T4 -iL live_hosts.txt -oA srcport_80
```

```bash
# Probing all ports, claiming source is HTTPS
sudo nmap -sS --source-port 443 -p- -T4 -iL live_hosts.txt -oA srcport_443
```

- Different results across the three runs → firewall is source-port-trusting. Feed differing results into Step 5 - Collate ports.
- All three identical to default `-sS` → firewall is not source-port-trusting, move to next escalation.

---
### Slow timing

Use when results are inconsistent across re-runs (ports flip open/filtered between scans) — defender may be rate-limiting or dropping after probe-rate threshold. Re-run the full TCP scan slower:

```bash
# Re-scan slower to defeat rate limiting
sudo nmap -sS -p- -T2 -iL live_hosts.txt -oA tcp_full_T2
```

⚠️ Use `-T2` first; only escalate to `-T1` if results still inconsistent.

- Results match original `-T4` scan → rate limiting isn't the issue.
- Results differ → use slower scan's results, feed into Step 5 - Collate ports.

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

Two distinct goals — pick subsections based on which applies.

- **Detection avoidance** — defender does not see the scan happening
- **Attribution avoidance** — defender sees the scan but cannot identify you as the source

All commands assume `-T1` (correct default — real-world rate detection mostly fires on fast scans). If `-T1` is detected, the defender may be alerting on slow/long-duration scans instead — try `-T2` or `-T3`. Timing is empirical. Add `-n` to disable reverse DNS lookups — defender's authoritative DNS will not see lookups for their range.

#### Decoy scan (attribution avoidance)

Target sees scans from multiple sources and cannot distinguish the real attacker. Detection still occurs.

```bash
# Decoys + random fillers + you, scan all ports
sudo nmap -sS -Pn -D <decoy_ip1>,<decoy_ip2>,RND,RND,ME -p- -T1 -iL live_hosts.txt -oA decoy_scan
```

⚠️ Decoys must be reachable IPs. `RND` generates random reachable IPs.

#### Spoof MAC address (attribution avoidance)

Same subnet only — MAC addresses do not traverse routers. Use on internal pentests / post-foothold pivots.

```bash
# Spoof as random MAC
sudo nmap -sS --spoof-mac 0 -p- -T1 -iL live_hosts.txt -oA spoofmac_scan
```

`--spoof-mac 0` randomises. Pass a vendor prefix (`Cisco`, `Apple`) or full MAC for specific impersonation.

#### Pad packet data (detection avoidance)

Defeats signature IDS rules matching on packet length.

```bash
# Append 25 bytes of random data to each probe
sudo nmap -sS -Pn --data-length 25 -p- -T1 -iL live_hosts.txt -oA padded_scan
```

#### Fragment packets (detection avoidance)

⚠️ Largely defeated by modern IDS — Snort/Suricata reassemble fragments before matching. Only useful against legacy or misconfigured inspectors.

```bash
# Fragment into 8-byte chunks
sudo nmap -sS -Pn -f -p- -T1 -iL live_hosts.txt -oA frag_scan
```

`-ff` fragments into 16-byte chunks. Some firewalls drop tiny fragments outright.

#### Full IP spoofing (attribution avoidance)

⚠️ Last-resort, rarely practical. Replies go to the spoofed IP, not you — only useful if you are ARP-positioned or on-path to monitor responses.

```bash
# Spoof source IP, requires response monitoring
sudo nmap -sS -Pn -e <interface> -Pn -S <spoofed_ip> -p- -T1 <target>
```
### Maximum stealth — idle/zombie scan

Your IP never touches the target. Requires a genuinely idle host with predictable sequential IP ID incrementation. If the zombie is busy — results are useless.

```bash
sudo nmap -sI -Pn <zombie_ip> -p- -T1 <target>
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