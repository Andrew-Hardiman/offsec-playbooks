
### Purpose

You have one or more IP addresses, ranges, or subnets in scope.

Find every live host before port scanning. No single method guarantees complete coverage — run all methods, save all output, deduplicate at the end.

If you have a **single IP scope**, you are in the wrong step — go to [[Step 2. Scope & Reachability]].

---

### Step 1 — Create working directory and define scope

```bash
mkdir -p ~/<engagements>/<target_name>/host_discovery

cd ~/<engagements>/<target_name>/host_discovery
```

Define scope — one entry per line. Example:
```bash
cat > scope.txt << 'EOF'
10.10.10.0/24
10.10.20.0/24
EOF
```

Confirm exactly what Nmap will scan before sending any packets:
```bash
nmap -sL -n -iL scope.txt
```

Review output. If anything looks wrong, fix `scope.txt` before proceeding.

---

### Step 2 — Run all discovery methods

Run every method below regardless of what previous methods return.

A host may block ICMP but respond to TCP. A host may block TCP but respond to UDP.

Individual hosts may apply their own filters independently of network-level filtering.

Missing a host here means missing it for the entire engagement.

#### ARP (same subnet only)
⚠️ ARP only works if your machine is on the same subnet as the targets. 

If your IP is in the same subnet as `scope.txt` — proceed. If not — skip ARP entirely and start at 'ICMP Echo'.
```bash
sudo nmap -PR -sn -iL scope.txt -oA arp_scan

sudo arp-scan -I eth0 --file scope.txt | tee arp_scan_tool.txt
```

#### Useful flags (append to any command below)
`-n` — skip reverse-DNS lookup, faster and quieter
`-R` — force reverse-DNS lookup even for hosts that appear offline
#### ICMP Echo
```bash
sudo nmap -PE -sn -iL scope.txt -oA icmp_echo
```

#### ICMP Timestamp
```bash
sudo nmap -PP -sn -iL scope.txt -oA icmp_timestamp
```

#### ICMP Address Mask
```bash
sudo nmap -PM -sn -iL scope.txt -oA icmp_addrmask
```

#### TCP SYN Ping
```bash
sudo nmap -PS22,23,25,80,443,3389,8080,8443 -sn -iL scope.txt -oA tcp_syn_ping
```

#### TCP ACK Ping (must run as root)
```bash
sudo nmap -PA22,23,25,80,443,3389,8080,8443 -sn -iL scope.txt -oA tcp_ack_ping
```

#### UDP Ping
```bash
sudo nmap -PU53,67,68,161,162 -sn -iL scope.txt -oA udp_ping
```

---

### Step 3 — Aggregate and deduplicate live hosts

Extract all live IPs from every grepable output file and deduplicate into a single list:
```bash
grep "Up" *.gnmap | awk '{print $2}' | sort -u > live_hosts.txt
```

Filtered host detection — some hosts block all discovery traffic but still expose ports. Probe directly against full scope to catch hosts invisible to discovery methods: 
```bash 
sudo nmap -Pn -p22,80,443,3389,8080,8443 -iL scope.txt -oA pn_probe 
```

Merge any newly found hosts into `live_hosts.txt` and deduplicate: 
```bash 
grep "open" pn_probe.gnmap | awk '{print $2}' | sort -u >> live_hosts.txt 

sort -u live_hosts.txt -o live_hosts.txt 
```

Verify the list:
```bash
cat live_hosts.txt
```

---

### Step 4 — Hand off to port scanning

Live hosts confirmed. Proceed to [[Step 4. Port Scanning]]:
```bash
sudo nmap -p- -T4 -iL live_hosts.txt -oA port_scan_all
```