
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

**`-sV` — service and version detection**

- `service` field = port-number name lookup — unverified
- `version` field = Nmap connected and read the banner — verified
- Never treat both fields with equal confidence

**`-O` — OS detection**

- Needs at least one open and one closed port for a reliable guess
- Scepticism rules — apply in order:
    1. Treat OS guess as a lead, not a confirmed fact
    2. Kernel version — additional scepticism regardless of target type
    3. Virtualised target — treat the entire `-O` output with scepticism, not just the kernel version

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
            match=$(grep "Ports:" "$gnmap" | grep -oP "\b${port}/(?:open(?:\|filtered)?)/tcp//[^/]*/[^/]*/[^/]*")
            if [ -n "$match" ]; then
                resolved_state=$(echo "$match" | cut -d'/' -f2)
                service=$(echo "$match" | cut -d'/' -f5)
                version=$(echo "$match" | cut -d'/' -f7)
                [ -z "$service" ] && service="-"
                [ -z "$version" ] && version="-"
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

## Step 3 — Extract OS detection output 

```bash 
for f in services_*.nmap; do [ -f "$f" ] || continue; ip=$(echo "$f" | grep -oP '\d+\.\d+\.\d+\.\d+'); grep -E "OS details:|Aggressive OS guesses:|Running:|OS CPE:" "$f" > os_${ip}.txt; echo "=== os_${ip}.txt ===" && cat os_${ip}.txt; done
```

## Step 4 — Decision

→ Services and/or versions detected on any host — proceed to [[Step 6. Vulnerability Analysis]] with the appropriate **Carry-forward artefacts**.

→ Nothing detected on any host — return to [[Step 4. Port Scanning]]. **Run and create the `tcp_targeted` files from Check 3 (which may not have been created on the first run)**, also consult `filtered_majority_<ip>.txt` and `tcp_filtered_probe_<ip>.nmap` to determine which escalation technique to reach for. 

---

## Carry-forward artefacts

| Artefact            | Contents                                                               |
| ------------------- | ---------------------------------------------------------------------- |
| `live_hosts.txt`    | One file                                                               |
| `services_<ip>.txt` | `port/state/protocol/service/version` — primary artefact, one per host |
| `os_<ip>.txt`       | OS detection output - one per host                                     |
