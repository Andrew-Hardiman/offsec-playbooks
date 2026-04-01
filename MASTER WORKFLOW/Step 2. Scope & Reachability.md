### Purpose

Confirm what scope you have been given and verify reachability before scanning.

---

### Step 1 — What scope were you given?

- **Single IP** → continue below
- **Range, subnet, or multiple targets** → go to [[Step 3. Host Discovery]]

---

### Step 2 — Create working directory
```bash
mkdir -p ~/<engagements>/<target_name>
cd ~/<engagements>/<target_name>
```

---

### Step 3 — Confirm reachability
```bash
ping -c 4 <target_ip>
```

- **If response** → proceed to [[Step 4. Port Scanning]]
- **If no response** → ICMP may be blocked, do not assume host is down, continue below
```bash
sudo nmap -Pn -p21,22,23,25,80,443,445,3306,3389,8080,8443 <target_ip> -oA reachability_probe
```

- **If any ports show open** → proceed to [[Step 4. Port Scanning]]
- **If nothing responds** → host may be down or heavily filtered.


