
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

## Step 3 — Resolve service-identity gaps

Confirm the true identity of any open TCP service nmap left unconfirmed. Resolve identity here, before version resolution.

### Step 3.1 — Detect uncertain-identity rows

Lists every open TCP service whose identity nmap did not confirm: service field ends in `?` (no/low-confidence match), is `unknown`, or is blank (`-`). UDP, `filtered`, and `tcpwrapped` rows are excluded by design (`tcpwrapped` is handled in Step 4).

```bash
for f in services_*.txt; do [ -f "$f" ] || continue; ip=$(echo "$f" | grep -oP '\d+\.\d+\.\d+\.\d+'); echo "=== $ip ==="; awk -F/ '$3=="tcp" && ($2=="open" || $2=="open|filtered") && ($4 ~ /\?$/ || $4=="unknown" || $4=="-")' "$f"; done
```

- No rows returned → Step 4.
- Rows returned → resolve each one below (`<ip>` / `<port>` from the row).

### Step 3.2 — Decode the captured fingerprint (do this first)

nmap already captured the service's raw probe responses in `services_<ip>.nmap`. Decode them into readable form with suggested field values:

```bash
~/scripts/nmap_fp_decode.py services_<ip>.nmap <port>
```

Script unavailable (unsynced box): `sed -n '/^SF-Port<port>-TCP:/,/");[[:space:]]*$/p' services_<ip>.nmap` prints the raw block to read by eye.

Route on the trailing `FIELD 4 (service):` line:

- `<service>` (not `UNKNOWN`) → identity resolved. Step 3.4 with the printed field 4 (and field 5 if not `-`).
- `UNKNOWN` → read the decoded probe responses printed above. The identifying response is the one carrying an `HTTP/` status line or a protocol banner, not nmap's `400 Bad Request` rejection probes. Identify by eye → Step 3.4; can't → Step 3.3.
- `NO_FINGERPRINT: ...` → no fingerprint was captured → Step 3.3.

### Step 3.3 — Active probe (only when 3.2 was absent or inconclusive)

```bash
curl -sI http://<ip>:<port>        # HTTP response headers returned → http
curl -skI https://<ip>:<port>      # if plaintext returned nothing → https
nc -nv <ip> <port>                 # Ctrl+C after ~5s; capture any banner for a non-HTTP service
```

- A response identifies the service → Step 3.4.
- No response / still unidentifiable → leave the row unchanged; it falls through to [[Step 6. Vulnerability Analysis]] as-is. Next row.

### Step 3.4 — Record identity

Manually edit the row in `services_<ip>.txt`: set field 4 (service) to the confirmed nmap service name. If 3.2/3.3 also revealed a product or version, set field 5 too; otherwise leave `-` for Step 4 to resolve.

```
Before: 3001/open/tcp/nessus?/-
After:  3001/open/tcp/http/Next.js
```

Edited rows enter Step 4 (Resolve version gaps) keyed on the service you just set.
## Step 4 — Resolve version gaps

Read each `services_<ip>.txt`. Ignore rows where **both** service and version are `-` (nmap got nothing — no probe target). 

For each remaining row where the version number is missing (product name only, protocol descriptor only), incomplete (major version only, no minor), or where service is `tcpwrapped` (port alive but actively rebuffed nmap), run probes by service:

| Service                                                  | Probes                                                                                                                                                                                                                                                                       |
| -------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `http`, `https`, `http-proxy`, `http-alt`                | `curl -sI http://<ip>:<port>` <br><br>then `whatweb -a 3 http://<ip>:<port>` <br><br>If both silent: <br>`nikto -host <ip> -port <port> -Tuning b`                                                                                                                           |
| `ssh`                                                    | `nc <ip> 22` <br><br>Banner arrives instantly (format: `SSH-<proto>-<software>`). `Ctrl+C` once you see it — `nc` will hang waiting for `SSH` handshake otherwise. Extract clean software version manually if banner contains junk (e.g. CTF flag that broke nmap's parser). |
| `irc`                                                    | `printf 'NICK probe\r\nUSER probe 0 * :probe\r\nQUIT\r\n' \| nc -w 10 <ip> <port>` <br><br>Version appears in numerics `002` (`Your host is <server>, running version <version>`) and `004` (`<server> <version> <umodes> <chanmodes>`). Extract the version string.         |
| `ftp`                                                    | STUB (YOU NEED TO WRITE THIS)                                                                                                                                                                                                                                                |
| `tcpwrapped`                                             | `nc -nv <ip> <port>`<br># Ctrl+C after ~5s if silent<br><br>`curl -sI http://<ip>:<port>`<br><br>`curl -skI https://<ip>:<port>`                                                                                                                                             |
| `netbios-ssn` `microsoft-ds` `msrpc` <br>`ms-wbt-server` | Leave as-is — OS-keyed, routes via Lookup C and Pass 3 per-service workflow                                                                                                                                                                                                  |
| anything else                                            | Leave as-is                                                                                                                                                                                                                                                                  |


Manually edit `services_<ip>.txt` with confirmed versions:

```
Before: 80/open/tcp/http/lighttpd
After:  80/open/tcp/http/lighttpd 1.4.55
```

Unresolved gaps stay as-is and fall through to [[Step 6. Vulnerability Analysis]].

⚠️ UDP version detection is **not** handled here — Step 1 runs TCP-only. Flagged as a future consideration: if UDP version gaps prove valuable in real engagements, extend Step 1's nmap to include `-sU -sV` or add a UDP-specific version step.

## Step 5 — Extract OS detection output 

```bash 
for f in services_*.nmap; do [ -f "$f" ] || continue; ip=$(echo "$f" | grep -oP '\d+\.\d+\.\d+\.\d+'); grep -E "OS details:|Aggressive OS guesses:|Running:|OS CPE:" "$f" > os_${ip}.txt; echo "=== os_${ip}.txt ===" && cat os_${ip}.txt; done
```
## Step 6 — Decision

→ Services and/or versions detected on any host — proceed to [[Step 6. Vulnerability Analysis]] with the appropriate **Carry-forward artefacts**.

→ Nothing detected on any host — return to [[Step 4. Port Scanning]]. **Run and create the `tcp_targeted` files from Check 3 (which may not have been created on the first run)**, also consult `filtered_majority_<ip>.txt` and `tcp_filtered_probe_<ip>.nmap` to determine which escalation technique to reach for. 

---

## Carry-forward artefacts

| Artefact            | Contents                                                               |
| ------------------- | ---------------------------------------------------------------------- |
| `live_hosts.txt`    | One file                                                               |
| `services_<ip>.txt` | `port/state/protocol/service/version` — primary artefact, one per host |
| `os_<ip>.txt`       | OS detection output - one per host                                     |
