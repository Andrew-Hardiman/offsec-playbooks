
> **STATUS: STUB** — design agreed 2026-09-28, not built. Trigger, scope, model, table shape and wiring are settled below; no verified component rows yet. Build the relevant row the first time a component-with-no-version blocks a Lookup D match in the wild. Not CANONICAL.

Web-layer version-gap resolver. Turns a web-stack **component with no version** into a version number, so the Version-discovery route can re-fire and Lookup D can match a CVE.

## Trigger

Reached from [[Web Attack Checksheet]] when a web-stack component is identified but no version number is known.

Binary the operator can always answer: **component token in hand + no version number → come here.** No runtime-vs-framework-vs-library classification required.

## Scope

Keyed on **any web-stack component whose version unlocks a Lookup D / Web Stack Exploit Index CVE match** — not frameworks only:

- Runtime: Node, PHP, Python (CPython)
- Framework: Django, Next.js, Express, Laravel
- Library: jQuery, Log4j-class dependencies

Deliberately mirrors the key and vocabulary of Lookup D and the Web Stack Exploit Index — this note feeds them.

## Model

**One note, one row per component**, accreting a row at a time as boxes are walked — same shape as [[Step 5. Service & Version Detection]]'s "Resolve version gaps" table (service-keyed) and the Web Stack Exploit Index. Not one-note-per-component. Build the Django row when Django blocks a lookup; add Express when Express does; etc.

## Probe table

| Component | Version-discovery probe |
|---|---|
| _(build per box — see build notes)_ | |

Recovered version → write into `services_<ip>.txt` field 5 → hand back to the **Version-discovery route** (re-fires cleanly now a version is present) → Lookup D.

**Fall-through:** version unrecoverable → mark component version-unknown; still check Lookup D by component name — some walkthroughs attempt version-blind (e.g. the [[Next.js Middleware Auth Bypass (CVE-2025-29927)]] one does).

## Build notes (fold into the row when built)

- **Django** — the technical-500 debug page leaks `Django Version: X.Y.Z` when `DEBUG=True` (verified against Django source 3.2.4 → 5.1). The technical-404 debug page does NOT carry it. `DEBUG=True` and the exact 500 trigger are box-dependent — confirm the trigger live before locking the row's payload (verify-before-paste).
- Generic component tells to evaluate: `/admin/` (or app console) login styling + static-asset paths/hashes (version-linked), static file path fingerprints, error-page wording/format changes across versions.
