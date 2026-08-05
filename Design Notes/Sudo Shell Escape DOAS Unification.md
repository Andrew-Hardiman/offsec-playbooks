
## Purpose and status

Design specification for extending [[Sudo Shell Escape]] with a **doas enumeration branch** at the top of the walkthrough, per V_S "Walkthrough split-vs-unify rule." Preserves the deliberated design from the session where the DOAS narrow-applicability vector was investigated as part of Cluster G Step 16 work. The refactor itself is deferred to first real-target encounter — [[Sudo Shell Escape]] is unchanged at time of writing; LPEC Step 16's DOAS sub-block routes here for the unification specification when the sub-block's trivial permit-nopass quick-win misses.

**Status: build-when-encountered.** The DOAS vector applies only when doas is installed on target (opendoas on Linux, native doas on OpenBSD/BSD-derived). Hit rate is near-zero on typical modern Linux targets; non-zero on OpenBSD, hardened/minimalist Linux configs, and CTF/exam boxes deliberately configured to test doas exploitation. LPEC Step 16 sub-block performs a fast presence check + trivial permit-nopass quick-win across common shells; this Design Note specifies how [[Sudo Shell Escape]] should be extended when the quick-win misses and full enumeration is required.

**When to consult this note and build:** at the first encounter with a target where the LPEC Step 16 DOAS sub-block emitted `DOAS_SHELL_SCANNED` without a preceding `DOAS_NOPASS_SHELL` marker (i.e., doas is installed but no trivial-shell permit-nopass rule fired), and full doas entitlement enumeration is needed to find exploitable rules on non-shell binaries or on non-standard shells not in the Step 16 quick-win list.

**Related in-vault artefacts (applied this session — do not re-apply):**

- LPEC Step 16 new sub-block "DOAS entitlements": presence check (`command -v doas && test -f /etc/doas.conf`) → trivial permit-nopass quick-win across common shells (`/bin/sh`, `/bin/bash`, `/bin/ksh`, `/bin/dash`, `/bin/zsh`, `/bin/ash`) via `doas -C /etc/doas.conf <shell>` iteration → route to this design note on non-trivial cases.

**Not yet applied — this build's deliverables:**

- [[Sudo Shell Escape]] restructure: top-of-walkthrough enumeration branch (sudo path vs doas path) per V_S bounded-fork unification. Paste-ready specification in this note.
- [[GTFOBins Cross-Reference]] extension: `doas` as a new primitive (maps to Sudo tab, uses `doas` invocation prefix). Paste-ready specification in this note.
- Real-target validation on a doas-configured box.
- Optional `~/scripts/doas_enum.sh` if inline doas.conf parse complexity warrants escalation per V_S "correctness on read" rule.

---

## Motivation — what LPEC Step 16 quick-win misses

LPEC Step 16 DOAS sub-block catches trivial doas permit-nopass rules on common shells. Concrete misses:

1. **Non-shell binaries with permit-nopass + GTFOBins escape.** Example: `permit nopass alice cmd /usr/bin/vim`. Step 16 quick-win doesn't iterate non-shell binaries; walkthrough must run GTFOBins Cross-Reference against the full candidate list.
2. **Permit-with-password rules where foothold has harvested credentials.** Example: `permit alice cmd /bin/bash` (no `nopass`) — foothold has alice's password from Step 4 harvest. Step 16 quick-win filters on `permit nopass` output only.
3. **Rules keyed by group membership.** Example: `permit nopass :wheel cmd /usr/bin/apt`. Step 16 quick-win does not filter by current user's group set; a rule for `:wheel` matches foothold user if they're in wheel, but the current sub-block doesn't examine group semantics.
4. **Shell binaries at non-standard paths.** Example: `/usr/local/bin/bash` on some BSDs, or busybox-symlinked shells at unusual paths.

Coverage gap: an operator on a target where doas allows exploitable non-shell binaries has no LPEC-driven route to reach root via doas without this refactor. The vector is real but off-path.

---

## Verified facts — primary sources

Verified during 2026-08-05 design session.

### Origin and packaging

- **Origin:** OpenBSD 5.8 (2015). Author: Ted Unangst.
- **Linux port:** opendoas (github.com/Duncaen/OpenDoas).
- **Package names:** Debian/Ubuntu `opendoas`; Arch `doas`; Gentoo `app-admin/doas`; Alpine `doas`.
- **Config file:** `/etc/doas.conf` — canonical path across OpenBSD, Debian, Arch, Gentoo (verified against all four manpage sources).

### Config syntax (doas.conf(5))

`permit|deny [options] identity [as target] [cmd command [args ...]]`

- **Options:** `nopass` (no password required), `nolog` (no syslog entry), `persist` (credential caching), `keepenv` (retain caller env), `setenv {VAR VAR=val ...}` (env modification).
- **Identity:** username, `:groupname` (colon prefix marks group), or numeric ID.
- **Target:** `as <user>` — defaults to root if omitted.
- **Command:** `cmd <binary> [args <arg1> <arg2> ...]` — restricts rule to specific binary + optional argument match. Rules without `cmd` clause are unrestricted (permit any command).
- **Rule precedence:** last matching rule wins (bottom-to-top precedence for conflicts). This differs from sudo (first-match).

### Default state

- **doas.conf does not exist by default** on fresh installs. Doas installed but no config file → deny all by default (no rules → no permits).
- **Step 16 sub-block's `test -f /etc/doas.conf` filter correctly INAPPLICABLE-fires** on this case.

### doas(1) CLI flags — canonical from OpenBSD manpage

- **`-C config` [`command`]:** parses config file; if command is supplied, prints `permit` / `permit nopass` / `deny` for match. No command executed. Non-invasive entitlement check.
- **`-n`:** non-interactive mode; fails if matching rule doesn't have `nopass`. No password prompt.
- **`-s`:** execute shell from `$SHELL` env var or `/etc/passwd`.
- **`-u <user>`:** execute as `<user>` (default root).
- **`-L`:** clear persisted authentications.
- **`-a <style>`:** authentication style (login.conf(5) auth-doas entry).

**No `-l` equivalent to `sudo -l`.** Doas has no "list all my entitlements" flag. Enumeration must proceed via one of:

- Direct read of `/etc/doas.conf` (if readable).
- Iterative `doas -C /etc/doas.conf <candidate>` probes against a candidate binary list.

### GTFOBins compatibility

**GTFOBins has no dedicated DOAS tab.** Convention across security community references (morgan-bin-bash's Linux Privilege Escalation GitBook, InternalAllTheThings, ArchWiki DOAS entry, Debian Wiki DOAS entry) is to use Sudo-tab payloads with `doas` prefix substituted for `sudo`.

Rationale: doas's execution model matches sudo's — setuid-root process spawns command as target user, subject to per-user config file entitlements. GTFOBins payloads describe how a specific binary escapes to shell when invoked with elevated privileges. Mechanism is identical regardless of whether elevation was via `sudo` or `doas`.

---

## V_S split-vs-unify rule application

Sub-step mapping vs the existing Sudo Shell Escape walkthrough:

|Sub-step|doas branch|sudo branch (existing)|
|---|---|---|
|Enumeration mechanism|`cat /etc/doas.conf` (if readable) OR iterative `doas -C` probes|`sudo -l`|
|Candidate binary list construction|Parse permit rules matching current user (`id -un`) or their groups (`id -Gn`); extract `cmd <binary>`|Parse `sudo -l` output|
|GTFOBins Cross-Reference invocation|Same (with primitive=`doas`)|Same (with primitive=`sudo`)|
|Per-binary payload execution|`doas <binary> <payload>`|`sudo <binary> <payload>`|
|Verification with `id`|Same|Same|

**One materially divergent step: enumeration mechanism.** Invocation prefix is a per-binary parameter within the shared GTFOBins call, not a top-level step.

V_S rule: "**Bounded fork** (one step diverges, ~90% content shared) → unify with a top-of-walkthrough branch at the deploy step."

**Conclusion: bounded fork → unify [[Sudo Shell Escape]] with a top-of-walkthrough branch at Step 1 (enumeration).**

---

## Design decisions — rationale-preserving

### Why unify, not split into peer walkthrough

**Considered:** separate `[[DOAS Shell Escape]]` walkthrough as a peer to `[[Sudo Shell Escape]]`.

**Rejected under V_S split-vs-unify:** exploit chain diverges in only one materially-different step (enumeration). Splitting would ~90%-duplicate Sudo Shell Escape's content. Duplication creates drift risk between the two walkthroughs (updates to GTFOBins invocation, verification pattern, etc. must be applied twice), adds navigation cost under pressure, and violates V_S DRY discipline. Bounded fork classification → unify.

### Why branch at enumeration step, not at invocation step

**Considered:** unify at invocation step. Have Sudo Shell Escape's Step 1 (`sudo -l`) enumerate for sudo, and add a small "if doas is present, also parse `/etc/doas.conf`" branch adjacent to the sudo enumeration.

**Rejected:** enumeration mechanism is materially different (config-file-parse vs `sudo -l`). Shoehorning doas's enumeration into a sudo-first structure would obscure the trigger-routing (V_S line 197 — algorithm walks by trigger). Cleaner to branch explicitly at Step 1 based on which mechanism is applicable, then converge at the shared GTFOBins call at Step 2.

### GTFOBins Cross-Reference extension — Option A (new primitive) over Option B (prefix parameter)

**Considered:**

- **Option A:** New primitive `doas` in GTFOBins Cross-Reference. Maps to Sudo GTFOBins tab (payloads identical), uses `doas` invocation prefix. Extension shape: add row to primitive→tab table; add invocation rule.
- **Option B:** GTFOBins Cross-Reference accepts an optional invocation-prefix parameter. Callers pass `primitive=sudo, prefix=doas` for doas cases. Otherwise unchanged.

**Position: Option A.** Semantically cleaner — `doas` is a real primitive on doas-configured boxes, not a variant of sudo. Under trigger-routing (V_S line 197), the primitive name should map to the operator's mental model. "Doas is its own thing" is truer than "doas is sudo with a different prefix."

Option A extension is trivial:

- Add row to primitive → tab table in GTFOBins Cross-Reference: `doas → Sudo tab`.
- Add invocation rule: primitive `doas` → prefix `doas` for the payload execution shape.

### Concurrent sudo AND doas — try both

**Consideration:** what if the target has both sudo and doas installed?

**Position:** rare but possible. When both present, try sudo path first (higher fire rate; most boxes have sudo), then doas path if sudo yields no elevation. Independent enumeration paths, both may produce candidate binary lists.

Refactored Step 1 structure handles this by making each path a separate sub-step; operator runs whichever apply and proceeds through GTFOBins Cross-Reference with each candidate list.

### Enumeration fallback when doas.conf unreadable

Two-tier fallback preserved:

1. **`/etc/doas.conf` readable:** grep for permit rules matching current user or their groups; extract `cmd <binary>` clauses; build candidate binary list from matches.
2. **`/etc/doas.conf` unreadable:** iterate `doas -C /etc/doas.conf <candidate>` probes against a fixed candidate list drawn from GTFOBins Sudo-tab common escape binaries. Slower (one exec per candidate) but doesn't require config read.

Fallback is degraded coverage — doesn't catch permit rules on unusual binaries not in the candidate list. Documented as known limitation.

### Optional `doas_enum.sh` script escalation

If inline doas.conf parsing (Section 2 below) becomes complex enough that correctness on read is not obvious, escalate to `~/scripts/doas_enum.sh` per V_S "correctness on read" rule. Emitted markers analogous to `sched_enum.sh` / `config_enum.sh`:

- `DOAS_RULE: <options> <cmd_binary_or_unrestricted>` — one line per matching rule for current user.
- `DOAS_CONF_DENIED` — config unreadable; consumer falls back to `-C` iteration.
- `DOAS_SCANNED` — completion marker.

Decision deferred to build time. If real-target doas.conf files are consistently simple (few rules, straightforward permit syntax), inline `grep` + `awk` parse suffices. If real targets show complex rules (multiple identity clauses, quoted args, escape sequences), escalate.

---

## Proposed refactor structure (paste-ready when built)

[[Sudo Shell Escape]] restructure with top-of-walkthrough enumeration branch. Existing content mostly preserved; sudo path stays as-is; doas path added; GTFOBins invocation extended.

### Section 1 — Hard preconditions (revised)

```markdown
⚠️ Hard preconditions:

- Current user has entitlement to at least one binary via `sudo` OR `doas`, for which a GTFOBins entry exists with a Shell function AND the Shell function has a populated Sudo tab.
- Authentication available. Either NOPASSWD (sudo) / nopass (doas) on the chosen binary, or the current user's password (foothold creds usually suffice).
- Non-destructive. No filesystem modification; root shell spawned in-process. IOCs: `auth.log` entry for the `sudo` invocation, or syslog entry for the `doas` invocation.

No external lookup needed beyond GTFOBins for the specific payload — preconditions checked below.
```

### Section 2 — Enumerate entitlements (branch by mechanism)

```

## Enumerate entitlements

If both sudo AND doas are installed, run sudo path first (higher fire rate); fall through to doas path if sudo yields no elevation.

### Step 1a — Sudo path (if `command -v sudo`)

[Existing Section 1 content preserved verbatim — `sudo -l`, per-binary bullets, env_keep parallel route, TTY upgrade route. Primitive for GTFOBins invocation: `sudo`.]

### Step 1b — Doas path (if `command -v doas` AND `test -f /etc/doas.conf`)

Try to read the config directly:

`cat /etc/doas.conf 2>/dev/null`

Rules relevant to current user match on identity being the current user OR a group the current user is a member of. Determine current user and groups:

`id -un && id -Gn`

For each `permit` rule in output, evaluate:

- `permit nopass <user_or_:group> [as root] cmd <binary>` where `<user_or_:group>` matches current user or any of their groups → note the binary; primitive = `doas`; no password required.
- `permit nopass <user_or_:group> [as root]` (no `cmd` clause) where identity matches → unrestricted; note `/bin/sh` (or preferred shell) as target binary; primitive = `doas`; no password required. Any binary is permitted; shell-spawn is the direct route.
- `permit <user_or_:group> [as root] cmd <binary>` (no `nopass`) where identity matches → note the binary; primitive = `doas`; password required at execution.
- `permit <user_or_:group> as <non-root-user>` where identity matches → walkthrough doesn't apply for root elevation. May apply for lateral pivot to `<non-root-user>` (out of scope for this walkthrough — record and return to [[Linux Privilege Escalation Checksheet]]).
- `deny <user_or_:group>` where identity matches → skip; rule precedence is last-match, so a subsequent `permit` for the same identity may override.

Remember rule precedence: **last matching rule wins** (bottom-to-top). If enumeration surfaces a permit rule at line 3 and a deny rule at line 7 both matching the current user, the deny is authoritative.

If `/etc/doas.conf` is unreadable:

Fall back to iterative `-C` probes against GTFOBins Sudo-tab common escape binaries. Candidate list at time of writing (may extend as GTFOBins evolves): `find awk vim less more sed nano python python3 perl ruby lua tar zip cp mv chmod chown dd bash sh ksh dash zsh systemctl mysql`.

`for c in find awk vim less more sed nano python python3 perl ruby lua tar zip cp mv chmod chown dd bash sh ksh dash zsh systemctl mysql; do r=$(doas -C /etc/doas.conf "$c" 2>/dev/null); [ -n "$r" ] && [ "$r" != "deny" ] && echo "DOAS_CAND: $c: $r"; done`

- `DOAS_CAND: <binary>: permit nopass` → note the binary; primitive = `doas`; no password required.
- `DOAS_CAND: <binary>: permit` → note the binary; primitive = `doas`; password required at execution.

If iterative probing yields no candidates, doas walkthrough doesn't apply → return to [[Linux Privilege Escalation Checksheet]].

### Step 2 — Exploit via GTFOBins

Pass the noted binaries as the list to [[GTFOBins Cross-Reference]]. For each candidate, provide `(binary, primitive)` where primitive is `sudo` (from Step 1a) or `doas` (from Step 1b). GTFOBins Cross-Reference loops the list, stops at the first that elevates, returns one verdict.

- Returns **root** → proceed to Decision.
- Returns **none elevated** → walkthrough doesn't apply → return to [[Linux Privilege Escalation Checksheet]].
```

### Section 3 — Decision, Validation (unchanged)

Existing Decision and Validation sections preserved verbatim.

---

## Supporting work — GTFOBins Cross-Reference extension

Small extension to [[GTFOBins Cross-Reference]]:

### Section 1 changes (primitive → tab mapping)

Add row to primitive-to-tab table:

```
Primitive → GTFOBins tab:

- **sudo** (binary in `sudo -l`) → **Sudo** tab
- **doas** (binary permitted in `/etc/doas.conf` for current user or their groups) → **Sudo** tab
- **SUID** (setuid bit) → **SUID** tab
- **SGID** (setgid bit) → **SUID** tab (no SGID tab — see SGID caveat)
```

### Section 2 changes (invocation rule)

Add doas to the invocation-per-primitive rules. Current:

```
1. **Invocation depends on primitive.**
    - **sudo** — prefix line 1 with `sudo`. GTFOBins assumes `sudo` is implicit on the Sudo tab. Operator types `sudo <line-1>` at the shell prompt.
    - **SUID / SGID** — run the binary directly, no prefix (already set-id). ...
```

Extended:

```
1. **Invocation depends on primitive.**
    - **sudo** — prefix line 1 with `sudo`. GTFOBins assumes `sudo` is implicit on the Sudo tab. Operator types `sudo <line-1>` at the shell prompt.
    - **doas** — prefix line 1 with `doas`. GTFOBins Sudo-tab payloads apply because doas's execution model matches sudo's; substitute `doas` for `sudo` in the invocation. Operator types `doas <line-1>` at the shell prompt.
    - **SUID / SGID** — run the binary directly, no prefix (already set-id). ...
```

### Otherwise unchanged

Step 1 GTFOBins page cross-reference, Step 2 payload execution rules 2-3 (subsequent-lines-inside-program, shell-escape-characters), Per-binary gotchas appendix — all unchanged; apply identically to doas invocations.

---

## Alternative approaches considered and rejected

Preserved so future build does not re-litigate.

1. **Separate `[[DOAS Shell Escape]]` walkthrough as peer to [[Sudo Shell Escape]].** Rejected: V_S split-vs-unify bounded-fork classification → unify preferred. Duplicates ~90% of Sudo Shell Escape's content; drift risk between two walkthroughs.
2. **DOAS inline in LPEC Step 16 (skip walkthrough entirely).** Rejected: Step 16 sub-block is appropriately-sized for trivial quick-win (shell permit-nopass check). Full enumeration + GTFOBins iteration + per-binary payload execution is walkthrough-shape territory. Doesn't fit sub-block shape.
3. **DOAS as Shared Concept (like [[GTFOBins Cross-Reference]]).** Rejected: doas exploitation has one committed caller today (this walkthrough via LPEC Step 16). Multi-caller reuse infrastructure not earned per V_S build-when-encountered. If doas exploitation ever becomes reusable across multiple LPEC entry points, revisit.
4. **GTFOBins Cross-Reference invocation-prefix parameter (rejected in favor of new-primitive Option A).** Rejected: primitive extension (Option A) is semantically cleaner. Doas is its own primitive, not a sudo variant.
5. **Handler cross-referencing existing Sudo Shell Escape Section 1 for doas parsing.** Rejected: intra-walkthrough cross-reference between sections would be spaghetti. Correct form is a clean branch at Step 1 with independent enumeration paths converging at Step 2.
6. **Check only `/bin/sh` in the Step 16 quick-win.** Rejected during design session: OSCP-framing analysis showed common-shell iteration is worth the modest complexity to catch specific-shell permit-nopass rules for `/bin/bash`, `/bin/ksh`, etc.

---

## Session provenance

**Design session date:** 2026-08-05.

**Primary sources verified during design session:**

- OpenBSD doas(1) manpage — https://man.openbsd.org/doas
- OpenBSD doas.conf(5) manpage — https://man.openbsd.org/doas.conf
- Debian opendoas manpages (bullseye, bookworm, testing, unstable).
- Arch Linux doas manpage — https://man.archlinux.org/man/doas.conf.5.en
- Debian Wiki DoAS entry — https://wiki.debian.org/Doas
- OpenBSD Handbook Security chapter — https://www.openbsdhandbook.com/system_management/privileges/
- Community DOAS PrivEsc references (morgan-bin-bash Linux PrivEsc GitBook, InternalAllTheThings).

**Sandbox verification scope during design session:**

- For-loop logic for LPEC Step 16 sub-block's trivial permit-nopass check verified via mock (see LPEC Step 16 build log — mock returned expected `DOAS_NOPASS_SHELL: /bin/bash` and `DOAS_SHELL_SCANNED` markers for match and non-match cases, and correctly skipped non-existent shell paths).
- `doas -C` actual output format on live doas install NOT verified — sandbox lacks doas. Assumption: opendoas Linux port matches OpenBSD manpage semantics for `-C` command output (`permit`, `permit nopass`, `deny`). Flag for real-box verification on first encounter.
- doas.conf real-target parse (for Section 2 doas path enumeration) NOT verified — sandbox lacks live doas config. Parse specification is based on doas.conf(5) grammar; real-target parse may surface edge cases (quoted args, escape sequences, multi-line rules) not covered by the inline `grep` + `awk` approach. Flag for real-box verification.

**Correction history preserved for regression prevention:**

- **Initial consideration was separate `[[DOAS Shell Escape]]` walkthrough as peer to Sudo Shell Escape.** Corrected via V_S split-vs-unify rule application: bounded fork (one materially divergent step) → unify.
- **Initial Step 16 quick-win was `doas -C /etc/doas.conf /bin/sh` only (single shell).** Corrected via OSCP-framing analysis: multiple common shells checked to catch specific-shell permit-nopass rules for `/bin/bash` (Linux default), `/bin/ksh` (OpenBSD default), and other common shells.
- **Initial consideration was Option B (invocation prefix parameter) for GTFOBins Cross-Reference extension.** Corrected: Option A (new primitive) is semantically cleaner. Primitive names should map to operator mental model, not implementation detail.

**F&R contents applied this session (verbatim):**

The following F&R was applied to `Linux PrivEsc/Linux Privilege Escalation Checksheet.md`:

**F&R — Insert DOAS sub-block into Step 16:**

Find:

```
- `BIG_UID_SCANNED` with no preceding `BIG_UID` → INAPPLICABLE, proceed to next narrow-vector check.
- No output at all → paste did not execute (terminal issue, syntax mangling, or connection drop). Retry.

---

## Step 17 — Kernel exploits
```

Replace:

```
- `BIG_UID_SCANNED` with no preceding `BIG_UID` → INAPPLICABLE, proceed to next narrow-vector check.
- No output at all → paste did not execute (terminal issue, syntax mangling, or connection drop). Retry.

### DOAS entitlements:

On **target:**

`command -v doas >/dev/null 2>&1 && test -f /etc/doas.conf && echo "DOAS_INSTALLED"; echo "DOAS_SCANNED"`

Route on output markers:

- `DOAS_INSTALLED` → run trivial permit-nopass check across common shell paths:

    `for s in /bin/sh /bin/bash /bin/ksh /bin/dash /bin/zsh /bin/ash; do [ -x "$s" ] && [ "$(doas -C /etc/doas.conf "$s" 2>/dev/null)" = "permit nopass" ] && echo "DOAS_NOPASS_SHELL: $s" && break; done; echo "DOAS_SHELL_SCANNED"`

    - `DOAS_NOPASS_SHELL: <shell>` → run `doas <shell>` → interactive root shell → verify root by running `id` → `uid=0(...)` → root authority achieved. Done.
    - `DOAS_SHELL_SCANNED` with no preceding `DOAS_NOPASS_SHELL` → no trivial shell catch; route to [[Sudo Shell Escape]] (doas branch — see [[Sudo Shell Escape DOAS Unification]]; refactor deferred to build-when-encountered).
- `DOAS_SCANNED` with no preceding `DOAS_INSTALLED` → INAPPLICABLE, proceed to next narrow-vector check.
- No output at all → paste did not execute (terminal issue, syntax mangling, or connection drop). Retry.

---

## Step 17 — Kernel exploits
```

**Deferred to build-when-encountered:**

- [[Sudo Shell Escape]] restructure per Section "Proposed refactor structure" above.
- [[GTFOBins Cross-Reference]] extension per Section "Supporting work — GTFOBins Cross-Reference extension" above.
- Optional `~/scripts/doas_enum.sh` if inline parse complexity warrants escalation.
- Real-target validation on a doas-configured box.

**V_S convention grounding:**

- Walkthrough split-vs-unify rule (bounded fork → unify with top-of-walkthrough branch).
- GTFOBins routing convention (Shell function required; Sudo tab for sudo-family primitives).
- Trigger-routing (algorithm walks by trigger, not by grouping — separate enumeration paths at Step 1 based on trigger mechanism).
- Build-when-encountered convention.
- Design Notes top-level directory convention (established Root-owned Services session; applied here).
- Verification commands are explicit (`id` with `uid=0(...)` output-keyed branch).