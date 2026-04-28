
## Inputs from Step 4

There may be multiple `ports_<ip>.txt` files — one per live host discovered in Step 4. The commands in this note loop over all of them automatically. You do not run anything once per file.

| Artefact                       | Always present | Condition                                                          |
| ------------------------------ | -------------- | ------------------------------------------------------------------ |
| `live_hosts.txt`               | ✓              | One file                                                           |
| `ports_<ip>.txt`               | ✓              | One file per live host                                             |
| `filtered_majority_<ip>.txt`   | ✗              | Only if Check 2 in Step 4 found `Ignored State: filtered`          |
| `tcp_filtered_probe_<ip>.nmap` | ✗              | Only if Check 1 in Step 4 found individually listed filtered ports |

`ports_<ip>.txt` format: `port/state/protocol` — one entry per line. Contains both TCP and UDP entries.

⚠️ UDP ports are not probed in this step. `-sV`, and `-O` are TCP operations. All UDP entries carry forward to `services_<ip>.txt` with `-/-`.

---

## Step 1 — Run detection

Loops over every `ports_<ip>.txt` file. Derives the IP from the filename. 

```bash
for f in ports_*.txt; do
    [ -f "$f" ] || continue
    ip=$(echo "$f" | grep -oP '\d+\.\d+\.\d+\.\d+')
    ports=$(grep '/open' "$f" | grep '/tcp$' | cut -d'/' -f1 | paste -sd',')
    if [ -z "$ports" ]; then
        echo "[$ip] No open or open|filtered TCP ports — skipping detection"
    else
        echo "[$ip] Running detection on ports: $ports"
        sudo nmap -sV -O -p "$ports" "$ip" -oA services_$ip
    fi
done
```

---

## Step 2 — Build services artefacts

Reads every line from `ports_<ip>.txt` and writes to `services_<ip>.txt`. 

`-sV` may resolve `open|filtered` to confirmed `open`. If no match is found, the original state is preserved. No port is dropped.

```bash
for f in ports_*.txt; do
    [ -f "$f" ] || continue
    ip=$(echo "$f" | grep -oP '\d+\.\d+\.\d+\.\d+')
    gnmap="services_${ip}.gnmap"
    out="services_${ip}.txt"
    > "$out"
    while IFS='/' read -r port state proto; do
        if [[ ( "$state" == "open" || "$state" == "open|filtered" ) && "$proto" == "tcp" && -f "$gnmap" ]]; then
            match=$(grep "Ports:" "$gnmap" | grep -oP "\b${port}/[^/]+/tcp//[^/]*/[^/]*/[^/]*")
            if [ -n "$match" ]; then
                gnmap_state=$(echo "$match" | cut -d'/' -f2)
                service=$(echo "$match" | cut -d'/' -f5)
                version=$(echo "$match" | cut -d'/' -f7)
                [ -z "$service" ] && service="-"
                [ -z "$version" ] && version="-"
                if [[ "$state" == "open|filtered" && "$gnmap_state" == "open" ]]; then resolved_state="open"; else resolved_state="$state"; fi
                echo "${port}/${resolved_state}/${proto}/${service}/${version}" >> "$out"
            else
                echo "${port}/${state}/${proto}/-/-" >> "$out"
            fi
        else
            echo "${port}/${state}/${proto}/-/-" >> "$out"
        fi
    done < "$f"
    echo "=== $out ===" && cat "$out"
done
```

Expected format:

```
22/open/tcp/ssh/OpenSSH 7.6p1 Ubuntu 4ubuntu0.3
80/open/tcp/http/Apache httpd 2.4.41
8080/open|filtered/tcp/-/-
53/open/udp/-/-
```


## Step 3 — Resolve version gaps

Read each `services_<ip>.txt`. Ignore rows where **both** service and version are `-` (nmap got nothing — no probe target). 

For each remaining row where the version number is missing (product name only, protocol descriptor only), incomplete (major version only, no minor), or where service is `tcpwrapped` (port alive but actively rebuffed nmap), run probes by service:

| Service                                   | Probes                                                                                                                                                                                                                                                                       |
| ----------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `http`, `https`, `http-proxy`, `http-alt` | `curl -sI http://<ip>:<port>` <br><br>then `whatweb -a 3 http://<ip>:<port>` <br><br>If both silent: <br>`nikto -host <ip> -port <port> -Tuning b`                                                                                                                           |
| `netbios-ssn`, `microsoft-ds`             | `sudo nmap --script smb-os-discovery -p <port> <ip>`. <br><br>If output contains a `Host script results:` block with a version → update `services` file. <br><br>If output shows only the port/state/service line and no script block → leave as gap (nothing found).        |
| `ssh`                                     | `nc <ip> 22` <br><br>Banner arrives instantly (format: `SSH-<proto>-<software>`). `Ctrl+C` once you see it — `nc` will hang waiting for `SSH` handshake otherwise. Extract clean software version manually if banner contains junk (e.g. CTF flag that broke nmap's parser). |
| `ftp`                                     | STUB (YOU NEED TO WRITE THIS)                                                                                                                                                                                                                                                |
| `tcpwrapped`                              | `nc -nv <ip> <port>`<br># Ctrl+C after ~5s if silent<br><br>`curl -sI http://<ip>:<port>`<br><br>`curl -skI https://<ip>:<port>`                                                                                                                                             |
| anything else                             | Leave as-is                                                                                                                                                                                                                                                                  |

Manually edit `services_<ip>.txt` with confirmed versions:

```
Before: 80/open/tcp/http/lighttpd
After:  80/open/tcp/http/lighttpd 1.4.55
```

Unresolved gaps stay as-is and fall through to Step 6.

⚠️ UDP version detection is **not** handled here — Step 1 runs TCP-only. Flagged as a future consideration: if UDP version gaps prove valuable in real engagements, extend Step 1's nmap to include `-sU -sV` or add a UDP-specific version step.

## Step 4 — Extract OS detection output 

```bash 
for f in services_*.nmap; do [ -f "$f" ] || continue; ip=$(echo "$f" | grep -oP '\d+\.\d+\.\d+\.\d+'); grep -E "OS details:|Aggressive OS guesses:|Running:|OS CPE:" "$f" > os_${ip}.txt; echo "=== os_${ip}.txt ===" && cat os_${ip}.txt; done
```

## Step 5 — Decision

→ Services and/or versions detected on any host — proceed to [[Step 6. Vulnerability Analysis]] with the appropriate **Carry-forward artefacts**.

→ Nothing detected on any host — return to [[Step 4. Port Scanning]]. **Run and create the `tcp_targeted` files from Check 3 (which may not have been created on the first run)**, also consult `filtered_majority_<ip>.txt` and `tcp_filtered_probe_<ip>.nmap` to determine which escalation technique to reach for. 

---

## Carry-forward artefacts

| Artefact            | Contents                                                               |
| ------------------- | ---------------------------------------------------------------------- |
| `live_hosts.txt`    | One file                                                               |
| `services_<ip>.txt` | `port/state/protocol/service/version` — primary artefact, one per host |
| `os_<ip>.txt`       | OS detection output - one per host                                     |
