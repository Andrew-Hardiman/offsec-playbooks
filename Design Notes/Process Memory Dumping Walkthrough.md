## Purpose and status

Design specification for the `[[Process Memory Dumping]]` walkthrough — LPEC Step 4 Credential Harvesting bullet 5. Ptrace-mediated dump of same-UID process address space for credentials that landed in a process's memory during its lifetime and never made it into `[[History Files]]`, `[[Config Files]]`, `[[SSH Keys]]`, or `[[Process cmdline & environ]]`. Preserves the deliberated design from the 2026-08-05 session where Item 1 was investigated as an Arm-2 unassigned walkthrough stub. The walkthrough itself is deferred to first real-target encounter — no walkthrough file exists at time of writing; LPEC bullet 5 wiki-links to `[[Process Memory Dumping]]` with an explicit pointer to this design note.

**Status: build-when-encountered.** The technique applies narrowly. Most cred-holding daemons (`sshd`, `gdm`, `lightdm`, `mysqld`, `postgres`, `apache2`/`nginx` workers) are NON-dumpable by default because they transitioned UIDs from root via `setuid()`, which clears the process dumpable flag. This means a same-UID non-root foothold CANNOT ptrace-attach to them (see kernel access check chain in Verified facts below). Realistic viable-from-non-root-foothold cases:

1. Interactive user foothold + active desktop session → `gnome-keyring-daemon` running as same UID (dumpable, populated with user creds/tokens).
2. Interactive user foothold + user's own long-running processes (`bash`, editor, browser, `ssh-agent` with password-protected keys unlocked in memory).
3. Rare: daemons that explicitly re-enable dumpability via `prctl(PR_SET_DUMPABLE, 1)` after dropping privileges (e.g. `ceph`).

Post-root, the technique broadens substantially (CAP_SYS_PTRACE bypasses same-UID + dumpable checks) — but that is credential extraction for lateral movement, not PrivEsc, and is out of LPEC scope. Covered by the eventual `[[Linux Credential Extraction Checksheet]]`.

**When to consult this note and build:** at the first encounter with a target where foothold has same UID as a viable candidate process (i.e. `test -r /proc/<pid>/mem` succeeds) AND ptrace_scope permits attach.

**Related in-vault artefacts (applied this session — do not re-apply):**

- LPEC Step 4 new bullet 5: `[[Process Memory Dumping]]` wiki-link + stub-and-defer language pointing to this design note.

**Not yet applied — this build's deliverables:**

- `[[Process Memory Dumping]]` walkthrough per specification below.
- Real-target validation on a target where a same-UID dumpable process holds credential material.

---

## Motivation — what LPEC Step 4 bullet 5 catches, what walkthrough handles

LPEC Step 4 covers Credential Harvesting via read-only enum: history files, config files, SSH keys, process cmdline+environ. Bullet 5 covers the remaining substrate — **credentials a process has brought into its memory at runtime and not overwritten**, that never appeared in argv/envp at exec time and never got written to disk.

Walkthrough scope:

- Preflight kill-switch checks (`ptrace_scope`, EUID sanity).
- Enumerate candidate PIDs (same UID as foothold, in cred-holding-daemon allowlist).
- Filter to dumpable candidates via `test -r /proc/<pid>/mem` (viability predicate).
- Attach + dump target regions using `gdb`.
- Extract credential candidates from dump via `strings` + regex.
- Route each candidate into existing Checksheet handlers.
- Detach + cleanup.

Bullet 5 is materially different substrate from bullet 4 (`[[Process cmdline & environ]]`). Bullet 4 reads `/proc/<pid>/cmdline` and `/proc/<pid>/environ` — a fixed initial-state slice bounded by `mm_struct` pointers (`arg_start`/`arg_end`, `env_start`/`env_end`), set at `execve()` and frozen thereafter. No LSM check, DAC-only, `cmdline` world-readable. Bullet 5 reads `/proc/<pid>/mem` — the full virtual address space (heap, stack, mmap'd anon regions) — requiring ptrace attach and the full ptrace access check chain.

---

## Verified facts — primary sources

Verified during 2026-08-05 design session.

### Kernel ptrace access check chain

Per ptrace(2). Every operation requiring `PTRACE_MODE_ATTACH` (which includes `PTRACE_ATTACH`, `process_vm_readv`, and opening `/proc/<pid>/mem`) runs a check chain:

1. If caller and target are in the same thread group → allowed.
2. Deny if target's real/effective/saved UIDs and GIDs don't all match caller's, AND caller lacks `CAP_SYS_PTRACE` in target's user namespace.
3. Deny if target's "dumpable" attribute is not `1` (SUID_DUMP_USER), AND caller lacks `CAP_SYS_PTRACE`.
4. Invoke LSM `security_ptrace_access_check()` — Yama, SELinux, AppArmor, Smack, commoncap can all deny here. Yama specifically: mode `0` no restriction; mode `1` bypassable by `CAP_SYS_PTRACE`; mode `2` requires `CAP_SYS_PTRACE`; mode `3` no bypass (sticky).

**`CAP_SYS_PTRACE` as the master override.** The capability bypasses steps 2, 3, AND 4 (Yama modes 0/1/2 only — mode 3 remains sticky). A foothold holding `CAP_SYS_PTRACE` in the target's user namespace has ptrace-attack scope equivalent to root for ptrace purposes: cross-UID targets, non-dumpable targets (including `sshd`, `mysqld`, `gdm-password`, `nginx`/`apache2` workers), all attackable.

Two operator modes to distinguish upfront during preflight:

- **`CAP_SYS_PTRACE` held**: full-scope attack across UID and dumpability boundaries. mimipenguin-shape target list applicable. Yield distribution shifts substantially toward direct-root and bulk credential extraction. Only Yama mode 3 remains a kill-switch.
- **`CAP_SYS_PTRACE` not held**: attach only to same-UID + dumpable + Yama-permitted targets. Constrained yield distribution.

Non-root foothold routes to holding `CAP_SYS_PTRACE` without being uid=0 (verified as existence, not exhaustive):

- Container with `--cap-add=SYS_PTRACE` at startup (common in dev/debug containers, some CI runners).
- File capability set on a binary in the foothold's exec path (`getcap -r / 2>/dev/null` reveals).
- Ambient/inheritable capabilities set on the process by a privileged parent.
- User namespace where foothold is root within the namespace.

Consequence: a non-root foothold's ptrace reach depends on the intersection of same-UID + dumpable + Yama for the `NO_CAP` case, or on Yama-mode-3 alone for the `PTRACE_CAP` case. Any of these gates failing means attach fails.

### The dumpable flag

Per prctl(2). Every process has a "dumpable" attribute controlling ptrace-attach permission and core-dump generation. Default value is `1` (dumpable). It is automatically reset to the value in `/proc/sys/fs/suid_dumpable` (default `0` — not dumpable) in the following circumstances:

- The process's effective UID or GID is changed (e.g. via `setuid()`).
- The process's filesystem UID or GID is changed.
- The process executes (`execve()`) a set-user-ID/set-group-ID binary, or a binary with file capabilities.

Critical PrivEsc consequence: **daemons that start as root and drop privileges via `setuid()` are non-dumpable by default.** This is nearly all production daemons — `sshd` (privilege-separated worker), `nginx`/`apache2` workers, `mysqld`, `postgres`, `gdm-password`, `lightdm`, etc. Foothold as their service account CANNOT ptrace-attach without `CAP_SYS_PTRACE`.

Some daemons explicitly re-enable dumpability post-drop via `prctl(PR_SET_DUMPABLE, 1)` — motivated by wanting coredumps for crash debugging. `ceph` is a verified case (PRs #11582, #13845). These are per-daemon exceptions; verify at candidate-viability check time.

Additional consequence: when dumpable is `0`, the ownership of `/proc/<pid>/*` files is set to root (not the process's EUID). Even a same-UID reader cannot open `/proc/<pid>/mem` (mode 0600 owned by root). Hence `test -r /proc/<pid>/mem` is the definitive viability check — it collapses the dumpable + same-UID + Yama triad into one predicate the operator can run without attempting attach.

### Yama LSM `ptrace_scope`

Per kernel `Documentation/admin-guide/LSM/Yama.rst`. Yama is a Linux Security Module in mainline since kernel 3.4 (`CONFIG_SECURITY_YAMA`). Restricts `PTRACE_MODE_ATTACH` beyond the base kernel checks. Sysctl at `/proc/sys/kernel/yama/ptrace_scope`, writable only with `CAP_SYS_PTRACE`. Values:

- `0` — classic ptrace permissions: same-UID + dumpable (base kernel behavior).
- `1` — restricted ptrace: caller must be an ancestor of the target OR the target explicitly declared the caller via `prctl(PR_SET_PTRACER, <caller_pid>, ...)`. Same-UID + dumpable still required. **Kernel default per ptrace(2) man page.**
- `2` — admin-only: only `CAP_SYS_PTRACE` may attach.
- `3` — no attach at all. Sticky — cannot be reduced without reboot.

### Per-distro `ptrace_scope` defaults

Verified from distro sysctl.d overrides and Fedora/RHEL wiki/STIG sources:

| Distro | Default | Source |
| --- | --- | --- |
| Ubuntu | `1` | procps ships `/etc/sysctl.d/10-ptrace.conf` |
| Debian | `0` | `elfutils-default-yama-scope` override |
| Fedora | `0` | `elfutils-default-yama-scope` override |
| RHEL 8/9 | `1` | kernel default; STIG-required (V-230546) |
| Arch, openSUSE | `1` | kernel default; no override shipped |
| Kali | Assume `0` — VERIFY | inferred (Debian-derived + debugging tools) |

Do not assume defaults — always read the sysctl on the target.

### procfs `hidepid` mount option

Per proc(5). Controls per-user visibility of `/proc/[pid]/` directories. Available since Linux 3.3. Values:

- `0` (default) — everyone can access all `/proc/[pid]/` directories.
- `1` — users may not access files/subdirs inside other users' `/proc/[pid]/`, but the directories themselves remain visible. `ps` still lists own-UID PIDs.
- `2` — as `1` plus other users' `/proc/[pid]/` directories are entirely invisible.

Orthogonal to the ptrace access check chain — `hidepid` blocks discovery, the ptrace chain blocks attack even if discovery succeeded via other means (e.g. `kill -0 <pid>`). Verify at candidate-enumeration time. For same-UID enumeration `ps` still works regardless of `hidepid` value.

### IOC profile

Every ptrace-attach fires the following forensic signals:

- **`/proc/<pid>/status` `TracerPid` field** — non-zero while attached, shows PID of the ptracer. Trivial detection primitive; well-known anti-debug marker used by commercial software.
- **`auditd`** — the `ptrace` syscall is auditable via a `SYS_ptrace` audit rule; ubiquitous on production/regulated hosts.
- **EDR ptrace hooks** — Elastic Security, CrowdStrike, SentinelOne all ship production rules matching `gdb` / `truffleproc` / `mimipenguin`-style behavior against sensitive PIDs (e.g. Elastic "Linux init (PID 1) Secret Dump via GDB").
- **Target stall** — `PTRACE_ATTACH` sends SIGSTOP to the target; the target stops until detached. Users of an interactive session or clients hitting a stopped daemon may notice.

Compare with Step 4 bullets 1-4 (History, Config, SSH Keys, cmdline/environ) which are stealth-positive (only bash history of read commands as IOC). Item 1 is materially louder — the walkthrough should be understood as an engagement-context-sensitive vector, not a stealth-context vector.

### What lives in process memory

Content class depends on the process's runtime behavior. Practical categories:

| Target class | Example `comm` | Content class in memory |
| --- | --- | --- |
| Keyring/agent (user session) | `gnome-keyring-d`, `kwalletd`, `gpg-agent`, `ssh-agent` | User's stored passwords, SSH passphrases, unlocked private keys, browser saved-password decryption keys |
| User's own long-lived processes | `bash`, `vim`, `emacs`, browsers | Session cookies, tokens the user pasted, unsaved buffers, temp secrets |
| Login/auth daemon | `sshd` worker, `gdm-password`, `lightdm`, `login`, `su`, `sudo` | Briefly-held plaintext during PAM auth; PAM buffer leaks (`_pammodutil_getpwnam_*` structures persist post-auth). Typically non-dumpable from non-root foothold. |
| Web daemon (worker) | `nginx` worker, `apache2` worker, `php-fpm` | Backend DB conn strings, `proxy_pass` upstream creds, in-flight HTTP Basic Auth, TLS session material. Typically non-dumpable from non-root foothold. |
| DB daemon | `mysqld`, `postgres` | Replication creds, plugin creds. Typically non-dumpable from non-root foothold. |
| Long-running app | Java/Python app servers | Config secrets loaded from env/vault at startup, cached tokens. Dumpability varies. |

For non-root foothold, rows 1 and 2 are typically dumpable; rows 3-5 typically not. `test -r /proc/<pid>/mem` per candidate is authoritative.

### Tools — mimipenguin, truffleproc, gdb

**mimipenguin** (`huntergregal/mimipenguin`) — canned scanner. Target list hardcoded in source: `gdm-password`, `gnome-keyring-daemon`, `lightdm`, `vsftpd` (if `/etc/vsftpd.conf` exists), `sshd` (if `/etc/ssh/sshd_config` exists), `apache2` (if `/etc/apache2/apache2.conf` exists). Uses process-specific "needles" to locate password material (verified needles: `^_pammodutil_getpwnam_root_1$`, `^gkr_system_authtok$`, `^_pammodutil_getspnam_`). **Requires root** — source raises `RuntimeError('mimipenguin should be ran as root')`. Not suitable for non-root foothold cases; useful post-root as bulk extraction, and hence lives in the future `[[Linux Credential Extraction Checksheet]]`, not this walkthrough.

**truffleproc** (`controlplaneio/truffleproc`) — mashup: `gdb dump memory` produces raw dumps, then `TruffleHog` scans strings for known secret patterns. Requires `gdb` on target AND Docker to run the TruffleHog container. Practical use: dump on target, exfil, analyze off-box. Detected by production EDR rules.

**gdb** — the primitive. Manual workflow:

- Attach: `gdb -p <pid>` (interactive) or `gdb -batch -p <pid> -ex '<cmd>'` (scripted).
- View regions: `(gdb) info proc mappings` OR read `/proc/<pid>/maps` directly.
- Dump: `(gdb) dump memory <outfile> <start_hex> <end_hex>` — dumps the byte range `[<start_hex>, <end_hex>)` from the process's address space.
- Detach: `(gdb) detach` OR `(gdb) quit` in `-batch` mode.

Regions of interest in `/proc/<pid>/maps`:

- `[heap]` — process heap; most malloc'd credential material lands here. Often several MB.
- `[stack]` — main thread stack; auth-time password buffers, local variables holding secrets. Small (~136 kB typical for `bash`).
- Anonymous `rw-p` with no path (device/inode `00:00 0` with no name) — thread stacks, malloc arenas, mmap'd anon regions.
- File-backed `r-xp` — code; uninteresting for cred harvest.

### Reference sources

- Linux kernel `Documentation/admin-guide/LSM/Yama.rst` — canonical Yama LSM semantics: `https://docs.kernel.org/admin-guide/LSM/Yama.html`
- ptrace(2) man page — access check chain: `https://man7.org/linux/man-pages/man2/ptrace.2.html`
- prctl(2) man page — dumpable flag semantics and clearing conditions.
- proc(5) / proc_pid_status(5) man page — hidepid mount option, `/proc/[pid]/status` fields including `TracerPid`.
- `huntergregal/mimipenguin` source — verified target daemon list and needles: `https://github.com/huntergregal/mimipenguin`
- `controlplaneio/truffleproc` source — gdb + TruffleHog workflow: `https://github.com/controlplaneio/truffleproc`
- Elastic Security rule "Linux init (PID 1) Secret Dump via GDB" — production EDR detection precedent for this technique class.
- Ubuntu procps `/etc/sysctl.d/10-ptrace.conf` — Ubuntu default `ptrace_scope=1` source.
- Fedora Wiki `Changes/Restrict_ptrace_by_default` — Fedora/Debian ship `elfutils-default-yama-scope` with `ptrace_scope=0` override.
- Ceph PRs #11582, #13845 — production daemon example of re-enabling dumpability via `prctl(PR_SET_DUMPABLE, 1)` after setuid.
- RHEL 8 STIG V-230546 — RHEL `ptrace_scope=1` requirement.

---

## Design decisions — rationale-preserving

### Why a dedicated walkthrough, not extension of existing

**Considered:** merge Item 1 into `[[Process cmdline & environ]]` as extended scope (all-of-procfs).

**Rejected.** cmdline/environ is a fixed initial-state slice bounded by `mm_struct` pointers, DAC-only (`cmdline` world-readable, `environ` owner-only), no LSM check. Ptrace-mediated memory dump is a completely different substrate: full address space, ptrace access check chain (four gates), dumpable required, LSM-gated, IOC-generating. Different substrate, different access requirements, different IOC profile, different tools. Split per V_S propagating-fork rule.

**Also considered:** unify under a hypothetical `[[Process Memory]]` umbrella walkthrough covering both.

**Rejected.** cmdline/environ is stealth-positive; memory dumping is IOC-generating. Under stealth-required engagement rules they must be run at different sensitivity gates. Umbrella walkthrough would obscure that separation.

### LPEC-side gate vs walkthrough-side preflight — walkthrough wins

**Initially considered:** put the `ptrace_scope` kill-switch inline in LPEC bullet 5, following the Step 3 Local account database pattern.

**Rejected.** Step 3's checks aren't kill-switches, they're multi-way routing (readable→one walkthrough, writable→another). Bullet 5's `ptrace_scope` is a single-vector kill-switch. Vault convention for single-vector kill-switches is "Hard preconditions" at the top of the walkthrough (see `[[Cron File Permissions]]`, `[[Docker Socket Abuse]]`, `[[MySQL UDF]]`, `[[Dirty COW]]`). LPEC bullet 5 stays a pure `[[wiki-link]]` parallel to bullets 1-4; preflight lives in the walkthrough.

### No dedicated enumeration script — inline in walkthrough

**Considered:** dedicated `~/scripts/proc_mem_enum.sh` parallel to `~/scripts/proc_argenv_enum.sh` (bullet 4's script).

**Rejected.** The enumeration for bullet 5 is: read `ptrace_scope` → filter `ps` to same-UID → intersect with cred-holding-daemon allowlist → per-PID viability check via `test -r /proc/<pid>/mem`. That's four inline commands with obvious correctness on read — no shell-semantics traps, no multi-file parsing, no complex regex. The escalation trigger doesn't fire. Complex correctness lives in the per-target-class dump handlers, which are walkthrough-body content, not enum content.

Contrast: `proc_argenv_enum.sh` (bullet 4) IS script-shaped because NUL-separated pseudo-file parsing + credential regex is non-obvious on read.

### Realistic yield framing — mixed direct-and-lateral, distribution depends on `CAP_SYS_PTRACE`

**Rationale-preserving position:** the mimipenguin/truffleproc marketing framing is "dump memory, extract root password". Reality is more constrained but not lateral-only, and shifts significantly based on `CAP_SYS_PTRACE` availability.

**`NO_CAP` branch (constrained non-root foothold):**

- The daemons that hold root's plaintext password briefly during PAM auth (`sshd`, `login`, `su`, `sudo`) are typically non-dumpable (they started as root, dropped/kept privileges via setuid, dumpable flag cleared).
- The daemons that ARE dumpable from foothold are typically user-session (`gnome-keyring-daemon`, `ssh-agent`, `gpg-agent`, user shell, editor) — hold what THIS USER stored or brought into memory.

Yield distribution parallels bullets 1-4: direct-to-root when the recovered credential is root's password or authorized-for-root SSH material; lateral when the credential is another user's; non-local (chain via `[[MySQL UDF]]`, `[[SSH Keys]]`) when the credential is service-scoped. Direct-to-root paths available from non-root foothold under `NO_CAP`:

- `gnome-keyring-daemon` holds root's password (user previously SSH'd/su'd as root; sysadmin stored root creds in keyring for own workflow) → `su root`.
- `ssh-agent` holds unlocked private key authorized for `root@<host>` → `ssh root@<host>`.
- `gpg-agent` holds passphrase for passphrase-protected root-authorized SSH key → unlock private key → SSH as root.
- User's `vim`/`emacs`/shell heap holds root's password in a live buffer → `su root`.

Distribution is lateral-tilted vs History Files because keyring content is user-scoped by design (holds what THIS USER stored), whereas bash history structurally accumulates root-credential-bearing commands like `mysql -uroot -p<pw>`. Tilt is quantitative, not categorical.

**`PTRACE_CAP` branch (foothold with `CAP_SYS_PTRACE` but not uid=0):**

Yield expands to mimipenguin-shape target list. All root-owned cred-holding daemons become attackable:

- `sshd` (post-auth PAM buffer leakage via `_pammodutil_getpwnam_*` needles) → briefly-held plaintext of authenticating users, including root.
- `gdm-password`, `lightdm` → login form buffer contents → user passwords including root if root SSH'd/logged in.
- `sudo`, `su` recent invocations → password of whoever invoked them.
- `mysqld`, `postgres` → replication creds, plugin creds.

This branch resembles mimipenguin's post-root use case but from a non-root foothold that happens to hold the capability. Direct-to-root yield probability is substantially higher than the `NO_CAP` branch. IOC profile is also substantially louder — dumping root-owned daemons is EDR-obvious.

### Target class taxonomy — dumpable-viability-based, not category-based

**Considered:** organize walkthrough by daemon category (auth / web / DB / keyring), following mimipenguin's shape.

**Rejected.** Category is the wrong axis for a non-root foothold — most categories fail the dumpable check regardless of what they hold. The right axis is: what's actually attackable from THIS foothold. Enum step produces the viable-candidates list via `test -r /proc/<pid>/mem`; per-candidate handler dispatches by `comm` for known-good dump strategies (mimipenguin-style needles for known daemons, generic heap grep for unknown).

### Verification — chain into existing Checksheet handlers per V_S

Recovered credentials from a dump are routed via the same handler machinery `[[Config Files]]` Step 2 uses:

- `<user>:<pw>` for local Linux account → `su <user>` verification (mirrors `[[History Files]]` Step 2).
- URL-embedded creds → `[[Config Files]]` URL-embedded handler.
- PEM private key blocks → `[[Config Files]]` PEM handler (or `[[SSH Keys]]` plain private-key handler).
- Service tokens (GitHub PAT, Slack tokens, AWS keys) → log for post-root use.

No duplication of routing logic. Walkthrough exits at "candidate found → route into `<handler>`", not at "run script X against candidate".

---

## Proposed walkthrough structure

Save the built walkthrough to `Linux PrivEsc/Techniques/Process Memory Dumping.md`. Standard shape (hard preconditions header, numbered steps with paste-ready single-line commands, verify with `id`, cleanup, Decision, Validation) matching precedents in `[[History Files]]`, `[[Config Files]]`.

### Header — Hard preconditions

Prose bullets stating hard preconditions:

- Foothold is non-root (walkthrough is scoped to PrivEsc; if already root, redirect to `[[Linux Credential Extraction Checksheet]]` — out of scope for LPEC).
- `gdb` present on target OR foothold has ability to transfer a static `gdb` binary via `[[Attacker Toolchain]]`.
- Ptrace not fully disabled (Yama `ptrace_scope` ≠ `3`, no blanket LSM deny) — checked in Step 1.
- At least one attackable candidate process exists — checked in Step 3:
    - `NO_CAP` branch: same-UID AND dumpable.
    - `PTRACE_CAP` branch: any process in the cred-holding allowlist (same-UID and dumpable gates both bypassed by `CAP_SYS_PTRACE`).

### Step 1 — Preflight kill-switches

Four checks in order. Any HARD-TERMINATE returns to `[[Linux Privilege Escalation Checksheet]]` `Credential Harvesting`. Check C outcome (`PTRACE_CAP` vs `NO_CAP`) determines the branching in Step 2 and Step 3.

**Check A — EUID.** On **target:**

`id -u`

- `0` → foothold is root; this walkthrough is PrivEsc-scoped. Redirect to `[[Linux Credential Extraction Checksheet]]` (deferred; post-root activity, out of LPEC scope).
- Non-zero → proceed to Check B.

**Check B — `gdb` availability.** On **target:**

`command -v gdb`

- Path returned → proceed to Check C.
- Empty output → transfer static `gdb` via `[[Attacker Toolchain]]`, then re-verify. Transfer not feasible → HARD-TERMINATE.

**Check C — `CAP_SYS_PTRACE` in effective capability set.** On **target:**

`v=$(awk '/^CapEff/ {print $2}' /proc/self/status); [ $(( 0x$v & 0x80000 )) -ne 0 ] && echo "PTRACE_CAP" || echo "NO_CAP"`

Bit `0x80000` is CAP_SYS_PTRACE (capability number 19).

- `PTRACE_CAP` → foothold has ptrace capability. Steps 2-3 same-UID + dumpable filters are BYPASSED. Full mimipenguin-shape target list applicable in Step 4. Proceed to Check D with this branch.
- `NO_CAP` → constrained non-root foothold. Standard same-UID + dumpable flow. Proceed to Check D with this branch.

**Check D — Yama `ptrace_scope`.** On **target:**

`cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo "0"`

Route based on Check C outcome AND Check D output:

- Check C = `PTRACE_CAP`:
    - `0`, `1`, or `2` → `CAP_SYS_PTRACE` bypasses. Proceed to Step 2 with `PTRACE_CAP` branch.
    - `3` → HARD-TERMINATE. No capability bypasses mode 3.
- Check C = `NO_CAP`:
    - `0` — classic ptrace: same-UID + dumpable targets attackable. Proceed to Step 2 with `NO_CAP` branch.
    - `1` — restricted: only descendants of the foothold shell (or `prctl(PR_SET_PTRACER)`-declared) attackable. Fresh foothold shell has no relevant descendants for cred harvest. INAPPLICABLE for the general case. Exception: operator has explicitly spawned an attackable child holding credentials, or knows of a specific `PR_SET_PTRACER` declaration.
    - `2` — admin-only: requires `CAP_SYS_PTRACE` which foothold lacks (per Check C). HARD-TERMINATE.
    - `3` — no attach permitted, sticky. HARD-TERMINATE.
- No output from Check D at all → paste did not execute (terminal issue, syntax mangling, or connection drop). Retry.

### Step 2 — Candidate PID enumeration

Branch on Check C outcome from Step 1.

**`NO_CAP` branch — same-UID filter.** On **target:**

`ps -eo pid,uid,comm | awk -v u=$(id -u) '$2==u {print $1"\t"$3}'`

Emits `<pid>\t<comm>` for each same-UID process.

**`PTRACE_CAP` branch — no UID filter (full target space).** On **target:**

`ps -eo pid,uid,comm`

Emits full process table.

Cross-reference candidates against the cred-holding allowlist:

- Keyring/agent: `gnome-keyring-d`, `gnome-keyring-daemon`, `kwalletd`, `kwalletd5`, `gpg-agent`, `ssh-agent`.
- User's own long-lived: `bash`, `zsh`, `vim`, `emacs`, `firefox`, `chrome`, `chromium`, `slack`, `discord`, `code`.
- Auth/web/DB (attackable under `PTRACE_CAP`; usually non-dumpable so unattackable under `NO_CAP`): `sshd`, `gdm-password`, `lightdm`, `mysqld`, `postgres`, `nginx`, `apache2`, `httpd`, `php-fpm`, `vsftpd`, `proftpd`.

Extend during real engagements when unknown targets appear.

Empty candidate list → INAPPLICABLE. Return to `[[Linux Privilege Escalation Checksheet]]` `Credential Harvesting`.

Otherwise proceed with candidate `<pid>` list to Step 3.

### Step 3 — Per-candidate dumpability check

Branch on Check C outcome from Step 1.

**`PTRACE_CAP` branch — SKIP.** `CAP_SYS_PTRACE` bypasses the dumpable check (step 3 of the ptrace access check chain). Every allowlist candidate from Step 2 is viable. Proceed to Step 4 with all candidates.

**`NO_CAP` branch — per-candidate viability.** For each `<pid>` from Step 2:

`test -r /proc/<pid>/mem && echo "VIABLE: <pid>" || echo "NON-DUMPABLE: <pid>"`

Emits `VIABLE: <pid>` for candidates where ptrace-attach will succeed. `NON-DUMPABLE: <pid>` for candidates where target's dumpable flag is cleared (most root-dropped daemons).

- All candidates `NON-DUMPABLE` → INAPPLICABLE. Return to `[[Linux Privilege Escalation Checksheet]]` `Credential Harvesting`.

Otherwise proceed with `VIABLE: <pid>` list to Step 4.

### Step 4 — Dump viable candidates

For each `VIABLE: <pid>` from Step 3, dispatch by class (Class A first — highest yield):

**Class A — Keyring/agent, user's own processes.** Highest yield from non-root foothold.

Enumerate rw-p regions of interest for `<pid>`:

`grep -E '\[heap\]|rw-p' /proc/<pid>/maps`

For each region line reading `<start_hex>-<end_hex> rw-p ...`, dump that range:

```
gdb -batch -p <pid> \
  -ex 'dump memory /tmp/dump_<pid>_<start_hex>.bin 0x<start_hex> 0x<end_hex>' \
  -ex 'quit'
```

Combine dumps:

`cat /tmp/dump_<pid>_*.bin > /tmp/dump_<pid>.bin`

**Class B — Auth/web/DB daemons (only if VIABLE — normally non-dumpable).** If `VIABLE: <pid>` fired for one of these, the target has explicitly re-enabled dumpability (rare). Same dump procedure as Class A. For auth daemons, dumping during active auth flow catches plaintext; passive dump post-auth relies on PAM buffer leakage.

### Step 5 — Extract credential candidates from dump

For each `/tmp/dump_<pid>.bin`:

`strings /tmp/dump_<pid>.bin | grep -aiE 'password|passwd|pwd|secret|token|bearer|api[_-]?key|access[_-]?key|BEGIN [A-Z ]+PRIVATE KEY|://[^/]+:[^/]+@|_pammodutil_'`

For PEM block extraction specifically:

`strings -n 20 /tmp/dump_<pid>.bin | awk '/BEGIN.*PRIVATE KEY/,/END.*PRIVATE KEY/'`

Route output lines by pattern class:

- `<user>:<pw>` context (surrounding lines identify local Linux account) → treat as History Files Step 2 candidate.
- `<scheme>://<user>:<pw>@<host>` URL-embedded → treat as Config Files URL-embedded handler input.
- `-----BEGIN [A-Z ]+PRIVATE KEY-----` block → treat as SSH Keys or Config Files PEM handler input.
- Service tokens (`ghp_`, `xox[bpas]-`, `sk_live_`, `Bearer <hex>`) → log for post-root use. Not a PrivEsc primitive.
- `_pammodutil_getpwnam_*` / `_pammodutil_getspnam_*` needles → mimipenguin-style PAM buffer leak; password value typically at fixed offset relative to needle. Manual inspection of surrounding bytes with `strings -n 6 <dump>` context needed.

### Step 6 — Route candidates

For each recovered credential candidate, route into existing Checksheet handlers:

- Local Linux `<user>:<pw>` → `su <user>` → check `id`:
    - `uid=0(root)` → root achieved. Proceed to Decision.
    - Non-root `<user>` → lateral foothold. Re-enter `[[Linux Privilege Escalation Checksheet]]` from `<user>`'s context.
    - Authentication failure → next candidate.
- URL-embedded creds → `[[Config Files]]` Step 2 URL-embedded handler → onward chain (`[[MySQL UDF]]` if MySQL-as-root).
- PEM key → `[[SSH Keys]]` plain private-key handler or `[[Config Files]]` PEM handler.
- All candidates exhausted with no root yield → Return to `[[Linux Privilege Escalation Checksheet]]` `Credential Harvesting`.

### Step 7 — Detach and cleanup

Gdb's `-batch` mode detaches automatically after `quit`. Verify no lingering ptrace attachment on any `<pid>` from Step 4:

`for p in <pid_list>; do awk '/TracerPid/ {print $2}' /proc/$p/status; done`

- All zero → clean.
- Non-zero for any `<pid>` → gdb detach failed; force-detach by killing any dangling gdb: `pkill -u $(id -u) gdb`.

Cleanup dump files (IOC hygiene):

`shred -u /tmp/dump_*.bin 2>/dev/null; rm -f /tmp/dump_*.bin`

Note: file modification times and any auditd/EDR logs remain visible. Full evidence-scrubbing is out of scope — cleanup restores workspace state, not chain-of-custody state.

### Decision

Root shell achieved → common destinations: `[[Linux Credential Extraction Checksheet]]`, `[[Linux Persistence Checksheet]]`, `[[Linux Lateral Movement Checksheet]]`.

### Validation

No THM room targets this vector cleanly (target hardening variants make Item 1 rarely exercised in lab). Real-target validation on:

- User-session foothold with `gnome-keyring-daemon` running and populated → dump → confirm stored password extraction.
- Foothold where a daemon has explicitly re-enabled dumpability → dump → confirm cred extraction.

---

## Rejected alternatives

1. **Bulk-dump ALL same-UID processes.** Rejected: high volume, low signal, high IOC. Filter to allowlist first.
2. **Use `mimipenguin` as the primary tool.** Rejected: requires root, doesn't fit LPEC's PrivEsc scope. Belongs in `[[Linux Credential Extraction Checksheet]]` post-root.
3. **Use `truffleproc` as the primary tool.** Rejected: Docker dependency for TruffleHog means it's an off-box analysis tool, not a live foothold tool. Overhead > yield for foothold context.
4. **Read `/proc/<pid>/mem` directly without gdb (raw seek + read).** Rejected: same ptrace access check chain applies; would need to know which regions are readable and handle the seek/read manually. Adds no capability over `gdb dump memory` and requires custom code on target.
5. **Use `gcore` to full-coredump the target.** Rejected: full coredump can be gigabytes; heap + anon `rw-p` is typically tens of MB. Volume ≠ yield.
6. **Attack across UID boundaries assuming `hidepid=0` and `ptrace_scope=0`, without `CAP_SYS_PTRACE`.** Rejected: same-UID is a HARD kernel gate (step 2 of the ptrace access check chain), separate from Yama or hidepid. Only bypassable via `CAP_SYS_PTRACE`. The `PTRACE_CAP` branch of the walkthrough handles the case where foothold DOES hold the capability without being uid=0; the `NO_CAP` branch stays same-UID-restricted.
7. **Split walkthrough into per-daemon-class sub-walkthroughs.** Rejected: dumpable-viability is the dominant axis, not daemon class. Same enum + dump primitive works for all classes; per-class variation is at the strings-grep pattern level only.

---

## Session provenance

**Design session date:** 2026-08-05.

**Primary sources verified during design session:**

- Linux kernel `Documentation/admin-guide/LSM/Yama.rst`.
- Linux man pages: ptrace(2), prctl(2), proc(5), proc_pid_status(5).
- `huntergregal/mimipenguin` source — target daemon list and needles.
- `controlplaneio/truffleproc` source — gdb + TruffleHog workflow.
- Ubuntu procps `/etc/sysctl.d/10-ptrace.conf` (default `ptrace_scope=1`).
- Fedora Wiki `Changes/Restrict_ptrace_by_default` (Fedora/Debian `elfutils-default-yama-scope` override).
- RHEL 8 STIG V-230546 (`ptrace_scope=1` requirement).
- Elastic Security detection rule "Linux init (PID 1) Secret Dump via GDB".
- Ceph PRs #11582, #13845 (documented case of `prctl(PR_SET_DUMPABLE, 1)` post-setuid re-enablement).

**Sandbox verification scope during design session:**

- `cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo "0"` — verified across Yama-present (returns value) and Yama-absent (returns `0`) cases in shell sandbox.
- `CAP_SYS_PTRACE` bit check `v=$(awk '/^CapEff/ {print $2}' /proc/self/status); [ $(( 0x$v & 0x80000 )) -ne 0 ] && echo "PTRACE_CAP" || echo "NO_CAP"` — verified against synthetic capability sets (empty, only-CAP_SYS_PTRACE, full lower caps) and against the sandbox's own live CapEff. All cases route correctly. POSIX shell arithmetic with `0x`-prefix hex literals — portable across `bash`, `dash`, `zsh`.
- Sandbox lacks Yama LSM — no per-target verification of `ptrace_scope` runtime behavior. Flag for real-box verification on first encounter.
- No live target with a viable dumpable same-UID cred-holding process available in sandbox for end-to-end `gdb dump memory` verification.
- `test -r /proc/<pid>/mem` viability predicate NOT sandbox-verified for the non-dumpable case (requires a setuid-transitioned daemon running in the sandbox, not available). Flag for real-box verification on first encounter.
- `gdb -batch -p <pid> -ex 'dump memory ...'` invocation syntax verified from gdb reference; behavior against a live target not sandbox-verified.

**Correction history preserved for regression prevention:**

- Initial framing had `ptrace_scope` as the dominant constraint. Corrected during primary source pass: the base kernel `dumpable` check (per ptrace(2) access check chain step 3) is dominant. Yama LSM is an additional gate on top of the base kernel check, not a replacement for it. Most cred-holding daemons fail the `dumpable` check independently of `ptrace_scope`.
- Initial per-distro `ptrace_scope` defaults claimed "Debian/Ubuntu = 1, RHEL/Kali = 0" from memory. Corrected during primary source pass: Debian actually ships `0` (via `elfutils-default-yama-scope`), Fedora ships `0`, Ubuntu ships `1`, RHEL uses kernel default `1`. Kali is Debian-derived and likely `0` but should be verified per-target.
- Initial framing treated `mimipenguin` as a viable foothold tool. Corrected during primary source pass: mimipenguin source requires root (`if not running_as_root(): raise`), making it a post-root credential extraction tool, not a PrivEsc primitive. Reframed accordingly.
- Initial framing floated LPEC-side `ptrace_scope` gate as design decision. Retracted mid-session — Step 3 was the wrong precedent (multi-way routing, not kill-switch). Single-vector kill-switches belong at the top of the walkthrough as Hard preconditions, per established vault convention.
- Initial framing treated Yama `ptrace_scope` as the dominant kill-switch and `CAP_SYS_PTRACE` as an edge case implicitly excluded by "non-root foothold". Corrected: `CAP_SYS_PTRACE` is the master override across steps 2, 3, and 4 of the ptrace access check chain (bypasses same-UID, dumpable, AND Yama modes 0/1/2). Non-root footholds can hold `CAP_SYS_PTRACE` via container `--cap-add`, file capabilities, ambient/inheritable caps, or user-namespace root. Walkthrough restructured to branch on `PTRACE_CAP` vs `NO_CAP` at Step 1 Check C, with Steps 2-3 taking different shapes per branch. Rejected alternative #6 reworded to reflect that the CAP_SYS_PTRACE case is now explicitly in-scope, not excluded by assumption.
- Initial framing of "Realistic yield" section labelled the technique a "lateral credential harvester" with only occasional direct-to-root yield. Corrected: direct-to-root paths are structurally identical to `[[History Files]]` — recovered credential is used against `su root` / `ssh root@<host>` / `[[MySQL UDF]]`-shape chains. Direct-to-root vs lateral is a yield-distribution property (Item 1 is lateral-tilted vs bullets 1-4 because keyring content is user-scoped by design), not a categorical exclusion. Section reframed as "mixed direct-and-lateral, distribution depends on `CAP_SYS_PTRACE`".

**Not yet applied — this build's deliverables:**

- `[[Process Memory Dumping]]` walkthrough per specification above.
- Real-target validation with a viable candidate.

**V_S convention grounding:**

- Walkthrough split-vs-unify rule (propagating fork — substrate, access-check chain, IOC profile, tools all differ from `[[Process cmdline & environ]]` → distinct walkthrough warranted).
- Marker naming convention (`<pid>`, `<comm>`, `<start_hex>`, `<end_hex>` name the value's kind, consistent with SSH Keys / Logrotate precedents).
- Verification commands are explicit (`id` output-keyed branch per V_S convention).
- Payload-driven, algorithmic, binary-decision commands (each Step's action pasteable single-line or top-level fenced multi-line).
- Build-when-encountered convention.
- Design Notes top-level directory convention (established Root-owned Services session; applied here as fourth design note per this convention).
- Design note formatting discipline: no nested code fences with H2/H3 headers inside; no single-backtick multi-line commands. Multi-line commands use top-level triple-backtick fences; single-line commands use inline single backticks. All angle-bracket placeholders in backticks in prose.
