
> **STATUS: INSPECTOR BUILT (2026-10-06) · EXTRACTOR DEFERRED.** The inspector is built and live-validated — `~/scripts/local_file_inspector.py` + `test_local_file_inspector.py`, documented in `Scripts_Index.md`. **That script, its docstring, and its test suite are the source of truth for inspector behaviour — do NOT re-document or re-derive it here.** This note is retained for its inbound `[[Local File & Tree Inspector]]` links and for the one still-unbuilt stage: the **archive extractor**, below.

A single attacker-side inspector that, **given a local file or directory tree, emits creds / secrets / endpoints / CTF flags found within**. Read-only: does NOT fetch (callers retrieve first) and does NOT unpack archives (a nested archive is a leaf → `ARCHIVE_NESTED`; the caller extracts and re-inspects).

## Built: the inspector (pointer — source of truth is the script, not this note)

`~/scripts/local_file_inspector.py <file|dir>` → markers `FILE_CRED` / `SECRET` / `ENDPOINT_REF` / `FLAG` / `ARCHIVE_NESTED` / `READ_FAIL` / `MANUAL_REVIEW` / `SCAN COMPLETE`. Per-file by content class: text → regex-grep; other binary → `strings` + grep; media → skip; archive → `ARCHIVE_NESTED` leaf; unreadable/over-cap → `READ_FAIL`.

Full marker contract, detectors, and the locked decisions — broad endpoint openers with the accepted `/g` regex-flag FP; `MANUAL_REVIEW` loot-triggered (cred/secret/flag) **not** endpoint-triggered; FILE_CRED vs SECRET split; URI-userinfo connection-string creds — live in the `Scripts_Index.md` entry and the script docstring. **Not duplicated here** (duplication is drift).

Consumers call the script directly: WAC **7.1(d)** (the merged (d)+(e)) and WAC **7.3** (archive members, after extraction); the deferred **7.2 endpoint-harvest** will too. The WAC **7.1(f)** `.git`-dump recovered tree is a natural consumer but is **not yet wired** — it still greps by hand ("out of Step 7 scope"); wiring it onto the inspector is a candidate, not done.

## Deferred: the archive extractor (build on first ARCHIVE_FOUND worth mining)

The archive path is a three-step caller pipeline — **retrieve → extract → inspect**. Retrieve (operator / `curl`) and inspect (the built script) exist; **extract does not**. The extractor unpacks a confirmed archive (surfaced by `archive_enum.py`, WAC 7.3) to a sandboxed dir — recursively for nested archives — then hands the resulting tree to the inspector.

**Build trigger:** the first time a 7.3 `ARCHIVE_FOUND` must actually be mined. Until then the operator extracts by hand and points the inspector at the result.

**Failure / safety axes to close before "done" (front-loaded):**
- **Zip bomb** — decompression-ratio + absolute-size cap (mandatory; a malicious `backup.zip` fills Kali disk otherwise).
- **Zip-slip** — member paths like `../../etc/x`; confine extraction to the sandbox dir (target-provided content, real risk).
- **Nesting depth** — cap archive-in-archive recursion.
- **Binary routing** — the extractor unpacks and sandboxes only; it hands every extracted file to the inspector, which already does media-skip / `strings` / nested-archive-leaf classification. Do not re-implement inspection in the extractor.
- **Format coverage + tooling** — `zip`/`tar`/`gz`/`bz2`/`xz` are Python stdlib (`zipfile`/`tarfile`); `7z`/`rar` need external binaries — availability is a toolchain axis to flag, not assume.

Typed Python (`mypy --strict`) + `test_<name>.py`, attacker-side per `Vault_Strategy.md` `## Language selection`; mirror the sibling web scripts' structure. On build, wire it into the WAC 7.3 `ARCHIVE_FOUND` route between retrieve and the inspector call.

## Loot vs surface

The retrieved file / archive itself is **loot** — do NOT add it to `unauth_paths_<host>.txt`. Endpoints mined from *inside* it on inspection (`ENDPOINT_REF`) ARE **surface** → the caller appends them to `unauth_paths_<host>.txt` to re-fire at the next Step boundary.
