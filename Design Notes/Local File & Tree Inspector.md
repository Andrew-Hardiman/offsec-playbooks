
> **STATUS: DESIGN (deferred build)** — captured 2026-10-05. Not built. This note preserves the first-principles design so a future build needs no archaeology. Build trigger below.


A single deferred attacker-side script that, **given a local file or a local directory tree, emits creds / secrets / endpoints found within**. One job: inspect local content → findings markers. It does NOT fetch (callers hand it already-local files) and it is the shared core several WAC consumers currently duplicate or lack.

## Why this exists / why deferred

Four WAC consumers want the same thing — "given a file, find creds/secrets/endpoints":

- **7.1(d)** config-shape file inspection (`.env`, `.htaccess`, `web.config`, `phpinfo`, `.log`)
- **7.1(e)** source-shape file inspection (`.js`, `.json`, `.bak`, `.old`, `.orig`, `.swp`, `~`) — also extracts `ENDPOINT_REF`
- **7.3** archive members — each file inside a retrieved+extracted archive (`[[archive_enum]]` discovers/lists; it does NOT extract or inspect)
- **7.1(g)** the `.git`-dump recovered tree ("grep recovered tree for creds/endpoints")

Four real, in-tree consumers clears the no-premature-DRY bar (V_S: extract only on 3+ audited consumers or demonstrated drift). It is **deferred, not built**, because (d)/(e) are parked behind their 4th-amendment STOP tripwires and 7.3 inspection was scoped out — building the shared core now would un-park deferred work. Build it when the **first** consumer actually needs it (the 4th amendment to (d)/(e), or the first time a 7.3 `ARCHIVE_FOUND` must be mined), and route the others onto it then — do not duplicate the inspector per consumer.

## Shape — one job: inspect

The inspector does ONE job: take a local file or a local directory tree, walk it, and emit findings markers. Per file: text-like → grep creds/secrets/endpoints; binary → magic-classify, then archive → extract, media (image/font/audio/video) → skip, any other binary (executable/object/.pyc/firmware/…) → `strings`-extract then grep the same regex. It does not fetch, and it does not unpack.

Two adjacent concerns are NOT part of the inspector — they are caller prep (or separate tiny helpers), decided at build time, never folded into the inspector's identity:

- **Retrieval** (URL → local file) — the caller downloads before calling. `[[archive_enum]]` (7.3) discovers/lists; the operator/caller retrieves a confirmed archive.
- **Extraction** (archive → local tree, recursively for nested archives) — unpack to a sandboxed dir, then hand the resulting tree to the inspector. Archive-format-specific; carries the safety axes below.

The archive path is therefore a three-step caller pipeline — retrieve → extract → inspect — with the inspector as the pure final stage, reused unchanged by (d)/(e)/(g), which hand it single files or an already-local tree.

## I/O contract

- **In:** a local file path or directory path (+ optional depth cap, size cap).
- **Out (stdout markers):** `FILE_CRED: <path>: <match>` / `SECRET: <path>: <type>:<value>` / `ENDPOINT_REF: <path>: <ref>`. Plus an always-emitted completion summary (per the scan-completion convention).
- **Loot vs surface:** the file/archive itself is loot (already retrieved). **Endpoints mined from inside** (`ENDPOINT_REF`) ARE surface → the caller appends them to `unauth_paths_<host>.txt` to re-fire at the next Step boundary. This is the exact mechanism (e) already has for `ENDPOINT_REF`, now sourced from inside archives too.

## Verdict-tree logic (carried from the (d)/(e) build-spec — supersedes the inline summaries in those tripwires)

- Manual-review is a leaf on **every fetch-success branch** (cred-hit, endpoint-hit, both, no-match) — a file is high-value by **selection** (its extension/name got it inspected), not by match; the regexes highlight, they do not exhaust.
- **Fetch/read failure is its own outcome** (404/403/5xx/empty/timeout for a retrieved file; unreadable/corrupt for a local one) — never folded into "no-match", which would falsely advise review of a file that isn't there.
- Preserve every current (d)/(e)/(g) marker and route verbatim on migration — this is an escalation of existing logic, not a redesign.

## Cred/secret regex — lessons locked this session (build the pattern right)

- Keyword-anchored cred grep must allow the rest of the identifier **and** an optional closing quote before the delimiter: `(password|passwd|secret|api[_-]?key|token|bearer)[A-Za-z0-9._-]*["']?\s*[:=]`. Without the bridge, `SECRET_KEY=`, `secret_key_base=`, `AWS_SECRET_ACCESS_KEY=` and JSON `"password":` are all **missed** (the keyword must be the last token before `[:=]`, which they aren't). Sandbox-proven.
- Grep is case-insensitive (`-oiE`) — keep that.
- Shell-escaping trap: a literal `'` inside a single-quoted grep arg must be written `["'"'"']?`, not `["']?` (the raw form terminates the string and hangs the shell). This is itself the reason (d)/(e) escalate to a script — the quoting is not confirmable-correct on read.
- Secret classification by **re-fire action**, not ontology: `{password → spray users; bearer/token → auth header; jwt → Session Cookie Attacks}`; unclassifiable → log, don't invent a type. (Standalone-secret handling was itself deferred YAGNI — fold in here only if a build needs it.)

## Extractor — failure/safety axes to close before "done" (front-loaded)

- **Zip bomb** — decompression-ratio + absolute-size cap (mandatory; a malicious `backup.zip` fills Kali disk otherwise).
- **Zip-slip** — member paths like `../../etc/x`; confine extraction to the sandbox dir (target-provided content, real risk).
- **Nesting depth** — cap archive-in-archive recursion.
- **Binary routing** — never grep raw bytes (useless); but don't blanket-skip either. Media → skip; executables/objects/`.pyc`/firmware → `strings`-extract then grep (hardcoded creds/keys/endpoints in compiled artifacts are a real yield class); archives → extract. Size-cap the `strings` pass to bound noise.
- **Format coverage + tooling** — `zip`/`tar`/`gz`/`bz2`/`xz` are Python stdlib (`zipfile`/`tarfile`); `7z`/`rar` need external binaries — availability is a toolchain axis to flag, not assume.

## Build

Typed Python (`mypy --strict`) + `test_<name>.py`, attacker-side per V_S `## Language selection`. Mirror the sibling web scripts' structure (pure testable core split from any thin shell). On build, migrate 7.1(d)/(e)/(g) and 7.3 onto it and retire their inline/manual inspection.

## Consumers / wiring

- [[Web Attack Checksheet]] 7.1(d), 7.1(e), 7.1(g) — STOP tripwires point here.
- [[Web Attack Checksheet]] 7.3 (archive members) — `[[archive_enum]]` lists; this inspects what the operator retrieves.
