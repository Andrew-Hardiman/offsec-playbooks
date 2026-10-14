

**Type:** Design Notes (deferred-build design capture). Not a playbook — no STATUS tier.
**Owns:** the derivation behind [[Web Attack Checksheet]] 7.2, and the closed tripwire that preceded it.
**Surfaced:** 2026-09-22, THM "Modern Web Stacks" (MERN box) — walk of WAC 6.2 against a Next.js/Express app on :3000.

---

## The finding (one line)

Blind path brute-force — feroxbuster/gobuster + a wordlist, recursion included — **categorically cannot** discover a deep, custom, sparsely-routed API endpoint. This is a property of the technique, not a tool bug or a tuning gap. No wordlist size, method flag, or filter setting changes it.

Worked example (the two endpoints the room hands you, never showing how to find them): `/api/user/update` (POST) and `/api/admin/flag` (GET). WAC 6.2 found neither; only `/` (`found: 1`).

---

## feroxbuster mechanics — pinned so this is never re-derived

*(These correct a prior WAC error that read "Feroxbuster default surfaces 200/204/301/302/307/308/401/403/405 and excludes 404." That was wrong — it described a status allowlist feroxbuster does not use. Lesson: verify a tool's DEFAULT behaviour, not just flag syntax.)*

**Status handling — shows everything, filters by signature.**
- Default `--status-codes` = **All Status Codes** (Kali man page; printed as `Status Codes │ All Status Codes!` in the run banner). There is no built-in allowlist — a `500`, `422`, `429` all surface.
- The not-found wall is suppressed by a **signature-based wildcard auto-filter**: the `Auto-filtering found 404-like response and created new filter` lines. It is keyed on the not-found response's **signature — lines/words/chars** (the `10l 15w` columns), one filter **per method**, not on the status code.
- Consequence: a response that **deviates** from the signature — any non-404, *or a 404 of a different size* — is shown. Only signature-matching responses are hidden. `--dont-filter` disables this and returns the entire 404 wall (noise, not signal).

**Two subsystems — do not conflate them** (this was the flip-flop trap):
1. **Output filter — per response, governs *display*.** A `GET /x` returning 404 does **not** suppress a `POST /x` returning 200. Filtering is per (method, path) response.
2. **Recursion engine — path-level, governs *descent*.** feroxbuster recurses only into **non-filtered ("found")** paths. A 404 path is filtered → never descended into.

A 404 therefore has *no* effect on displaying other responses to the same path, but *does* gate whether feroxbuster descends into it. Both statements are true; they are about different subsystems.

**Recursion trigger (verified — feroxbuster docs):**
- Default: a redirect (300–399) whose `Location` = URL + trailing slash, **or** a `200–299`/`403` on a URL that ends in `/`.
- `--force-recursion` relaxes the *looks-like-a-directory* requirement — it recurses into **any** found endpoint. It does **not** relax the *must-not-be-filtered* requirement. A 404 is never recursed into, in either mode.

---

## Why blind brute misses the endpoints

feroxbuster only ever requests a path two ways: **(a)** `base + literal wordlist entry`, or **(b)** `discovered-directory + entry` via recursion. It appends **one word per level** — it does **not** try wordlist words in combination.

For `/api/user/update`:
- **(a)** fails — `api/user/update` is not a literal entry in `api-endpoints.txt` (verified absent; `api/admin/flag` and even the bare word `flag` are also absent).
- **(b)** fails — recursion needs each rung to be non-404: descend into `/api/` (needs `/api` non-404) → then `/api/user/` (needs `/api/user` non-404) → then try `update`. A REST backend routes only the **leaf**; `/api`, `/api/user`, `/api/admin` all 404. The ladder never starts, so the leaf is never assembled.

**Right words ≠ assembled path.** A custom wordlist containing `api admin flag user update` **plus** `--force-recursion` still fails: at the root it requests `/api /admin /flag /user /update`, all 404, nothing to recurse into — it never constructs `/api/admin/flag`. Verified by sandbox reproduction (parents 404 → recursion finds nothing; only the five single-word requests are made). gobuster is strictly worse here — no recursion at all, so literal entries only.

---

## What *does* reach multi-segment paths — positional (combinatorial) fuzz

> **PRESCRIPTION SUPERSEDED 2026-10-12** — the mechanics here are correct and are retained as 7.2(f) segment-swap (single fuzz position, off an already-discovered endpoint). Multi-position clusterbomb as the *primary* discovery sweep is dropped; 7.2(e) runs a curated full-path list instead — observed-route corpora were examined and ruled out. See *Session addendum — 2026-10-12*.

Put a fuzz point in **every** path position and request the combinations directly:

`ffuf -u "http://<host>:<port>/api/FUZZONE/FUZZTWO" -w <list>:FUZZONE -w <list>:FUZZTWO -mode clusterbomb -mc 200`

This builds the full path and requests it outright — **no recursion, no non-404 parents needed.** Verified: finds `/api/user/update` (and `/api/admin/flag` when the segment is in the list) where recursion could not.

**Why it is NOT a blind default — its limits:**
- **Depth-locked:** `/api/FUZZONE/FUZZTWO` only finds 3-segment paths. Each depth needs its own template.
- **Prefix assumption:** the leading `api` is fixed; to not assume it you must fuzz that position too (`/FUZZZERO/FUZZONE/FUZZTWO`).
- **Combinatorial explosion:** N fuzzed positions from a wordlist of size W = **W^N** requests. SecLists `objects.txt` (thousands of nouns) × `actions.txt` (hundreds of verbs) at depth 3 with the prefix fixed ≈ hundreds of thousands of requests; fuzz the prefix and cover several depths → tens of millions. Infeasible and loud.

So positional fuzz is a **targeted** technique: practical only once the API's shape is **constrained** — known prefix, known depth, small targeted lists per position. On a small lab box with the prefix pinned you can brute one depth; it does not generalise.

**Tools (all allowed, all on Kali):** `ffuf` (multi-`FUZZ` clusterbomb — the tool for this), `wfuzz` (multi-keyword), `gobuster fuzz` (single position). Wordlists: `objects.txt` × `actions.txt`.

---

## Where paths outside the wordlist come from (stack-agnostic)

A path the wordlist can't reach has to be learned from a source other than blind guessing. Two mechanisms, first-principles:

**1. The application discloses it.** Source classes, none stack-specific:
- **Machine-readable API description** — OpenAPI/Swagger, GraphQL introspection, WSDL/WADL → WAC 6.2 `(c)`/`(d)` already consume these.
- **The client's shipped code** — whatever the client ships names the endpoints it calls. For a web target that's the JS/HTML the page loads (path literals, `fetch`/XHR calls); for a thick/mobile client it's the decompiled app. JS is the common web instance, not the category.
- **Observed traffic** — proxy/crawl the app while using it and it fires the real requests itself (Step 1 HAR crawl, Burp history).
- **Server-side disclosure** — source leaks (`.git`, backups — some caught by 6.1), error/stack traces naming routes, exposed config, docs.
- **Authenticated view** — once a session/creds exist, the authed UI and its responses expose endpoints invisible unauth.

**2. You infer it off an already-discovered endpoint.** Given one real endpoint from *any* source above — or from *any other enumeration step* that happens to surface e.g. `/api` — positional fuzz enumerates its siblings by pattern.

**Ordering:** not a fixed pipeline. An endpoint (or a prefix like `/api`) can surface at any point — a spec parse, the crawl, an error message, an unrelated brute hit — and the operator reaches for positional fuzz *then*, off whatever structure was just learned. Positional fuzz is a multiplier on discovered structure, not a stage that runs after `(c)`/`(d)`.

**Principle:** paths outside the wordlist come from the app disclosing them, or from inferring off a known endpoint. Blind brute is the backstop, not the primary method.

**Playbook gap this exposed — CLOSED 2026-10-12 by 7.2(d).** At the time of writing, WAC had no first-class step to *harvest* endpoints from what the app discloses — the client's shipped code and observed traffic (for a web target, predominantly the JS/HTML it ships). 6.1 `(e)` greped only source-shape files feroxbuster happened to surface, and feroxbuster's link-extraction scans them but is unreliable (misses dynamically-built routes like `` fetch(`/api/${x}/update`) ``, and on the box that surfaced this returned only root). 7.2(d) client-code harvest now owns this.

---

## Decision — deferred, with tripwire

> **SUPERSEDED 2026-10-12** — the tripwire fired twice and is now **CLOSED (actioned)**. The deferral decision and the prescribed fix below are historical. Live spec: [[Web Attack Checksheet]] 7.2. See *Session addendum — 2026-10-12*.

**Do NOT build now.** Rationale (career-strategy-aligned; OSCP+ is the immediate gate):
- **Fire rate is near-zero on the OSCP+ exam** — classic web (SQLi, LFI/RFI, upload, auth bypass, known-CVE) dominates; deep custom sparse-routed API endpoints are atypical of the exam.
- **Current 6.2 is sufficient for the gate** — common paths + spec-parse `(c)` + GraphQL `(d)` + auth-gated `(e)` + JSON-API `(f)` cover the common cases.
- **Rejected alternatives:** a custom Rust/Go discovery tool (ffuf already does it; months of yak-shave; zero OSCP advancement); materialising the combinatorial wordlist to a file and feeding feroxbuster (that *is* positional fuzz, W^N-exploded onto disk — strictly worse than ffuf).

**Tripwire (do not ignore a second time):**
- **First** engagement where a known/suspected API endpoint exists but brute + recursion cannot surface it → log `DEFERRED: api-discovery-blindspot: <detail>` in `route_<ip>.txt`, use the manual workaround, move on.
- **Second** occurrence → build the solution. Do not re-deliberate.

**The fix, when built, uses existing tools — never a custom tool:**
- (a) an **endpoint-harvest** sub-block — pull endpoint strings from what the app discloses: the client's shipped code (for a web target, the JS/HTML the page loads — grep path literals + `fetch`/XHR patterns; tools like `katana` / `LinkFinder`), observed traffic (the Step 1 crawl / proxy history), and server-side disclosure (source leaks, error traces); and/or
- (b) an **ffuf positional-fuzz** sub-block — the inference multiplier: once any source yields a prefix/structure, clusterbomb the known positions (`objects.txt` × `actions.txt`, known prefix + depth).

**Manual workaround for right now:** if you have or can guess the structure, `ffuf` clusterbomb the known prefix; and always check the client JS bundle + the Step 1 HAR crawl for endpoint strings.

---

## Evidence / sources

- feroxbuster — Kali man page (`--status-codes` default: All Status Codes; `-m/--methods` default GET; `-d/--depth` default 4): https://www.kali.org/tools/feroxbuster/
- feroxbuster recursion / forced-recursion rules: https://epi052.github.io/feroxbuster-docs/ (Forced Recursion), https://github.com/epi052/feroxbuster
- SecLists `Discovery/Web-Content/api/` — full directory composition confirmed on Kali 2026-10-12; see *Session addendum — 2026-10-12* → *SecLists `api/` composition*: https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content/api
- API-discovery method reference: OWASP WSTG API Reconnaissance; https://zerodayhacker.com/discover-api-endpoints-with-feroxbuster/
- Sandbox-verified this session: recursion-ladder failure (parents 404 → recursion assembles nothing); positional-fuzz success (same wordlist, clusterbomb reaches the leaf); status/content-type classification.

---

## Session addendum — 2026-10-06 (tripwire fired → build triggered)

**Additive only** — everything above is unchanged. This records the second tripwire occurrence that triggers the build, plus design points raised while scoping it that the original derivation does not cover. Where a point sharpens an existing section, it names that section rather than restating it.

### Status: the build is now triggered

> **CLOSED 2026-10-12** — built. See *Session addendum — 2026-10-12*.

Second occurrence (the tripwire's "do not ignore a second time"): THM **Web Server Attacks - I**, the API app on **:8000**. Brute (7.2) returned only `/`; the room's own writeup shows `/api/users`, `/api/routes`, `/api/debug/env` exist — exactly the blind spot in _Why blind brute misses the endpoints_. → Build the fix.

### Numbering (the body above predates the WAC restructure)

`6.2 API endpoint enumeration` throughout the body = current **7.2**. `6.1 (e)` (source-shape grep) = the former 7.1(e), now **merged into 7.1(d)** and routed through the shared inspector (below). Read the body's step numbers accordingly.

### Yield ordering — where discovery actually comes from (recalibration)

`unauth_paths_<host>` is fed by many WAC steps. Ranked by yield for _this_ blind spot, to keep the build centred correctly:

1. **One-hit-full-surface disclosures** — the existing spec/GraphQL parse (7.2 c/d) **and** a route-disclosing / debug-endpoint probe (new, below). One hit returns the whole route table.
2. **Client-side code harvest (the harvest's primary source)** — grep the app's **shipped client code** — the SPA / front-end JS bundle loaded via the Step 1 HAR — for endpoint literals + `fetch`/XHR/axios targets. **High-yield for SPA / thick-client apps**: the bundle names essentially every endpoint the UI calls. N/A only for API-only or purely server-rendered targets. Runs through the inspector's `ENDPOINT_REF`.
3. **Positional-fuzz** (the _What does reach multi-segment paths_ section above) — the systematic sweep once structure is known; finds endpoints the UI does **not** call (hidden admin/internal/debug routes the bundle never names), so it complements (2) rather than duplicating it.
4. **Stray-file harvest** — the inspector over config / txt / source files surfaced elsewhere (7.1(d), 7.3 archive members). A **low-yield backstop** (occasional path-shapes). Distinct from (2) — do not conflate "inspector over the JS bundle" (primary) with "inspector over a txt file" (backstop).

### New: route-disclosing / debug-endpoint probe (highest yield, cheap)

Before any blind fuzz, probe a small curated set of endpoints that **dump their own surface**: `/api/routes`, `/api/_routes`, `/api/debug/*`, `/actuator/mappings` (Spring Boot), `/__routes`, and framework siblings. A hit returns the full route list — the same "one hit, full surface" payoff the spec parse already gives. Belongs in the harvest sub-block, **ahead of** fuzz.

### New: request-shape is a second, compounding axis

The finding above is _path-assembly_ (you never request the path). Independent of it: a correctly-assembled path still false-negatives if the probe sends the wrong **request shape** — a browser `GET` against a content-negotiated API that only answers `Accept: application/json`, or a `GET` against a POST-only route (`/api/user/update` in the body is POST). So **every validation probe and ffuf matcher in both sub-blocks must vary `Accept: application/json` and the method (GET/POST), with matchers set accordingly** — per the V_S _GET/POST default-header asymmetry_ decision for browser-faithful headers. A path-assembly fix that still sends plain GETs re-introduces the miss at the validation step.

### Harvest = acquisition (extraction is built); placement

The "grep client code → endpoints" extraction half of harvest (the `katana`/`LinkFinder` role named in the body) is now the shared general-purpose **`local_file_inspector`** — a reusable vault tool (not just an API-discovery component), built + validated 2026-10-06; see [[Local File & Tree Inspector]]. It is the endpoint-extraction engine for the **file / client-code** sources specifically (JS bundle, stray config/source files), emitting `ENDPOINT_REF`; the structured sources (spec/GraphQL via c/d, the route-dumper probe) yield endpoints directly, not through it. So the harvest sub-block only needs its **acquisition** half: gather the disclosure sources — **the full set in _Where paths outside the wordlist come from_ above** (spec/GraphQL via c/d; **client JS bundle via the Step 1 HAR — the primary source, distinct from Step 1's fired-traffic+hrefs and from old 7.1(e)'s brute-surfaced-only files**; observed traffic; server-side disclosure incl. the route-dumper probe + error traces; authenticated view) — and hand them to the inspector, whose `ENDPOINT_REF` flows to `unauth_paths`. The three-item shorthand elsewhere in this addendum is illustrative, not the whole list.

**Placement:** harvest is a **7.2** sub-block that runs **late** — its input is maximal only after the Step 1 HAR and 7.1 brute exist — and feeds the positional-fuzz. Derived from that data-flow, not placement convenience (passed the V_S force-fit check).

### Positional-fuzz — the curated per-position lists (completes the body's "small targeted lists per position")

> **SUPERSEDED 2026-10-12** — the per-position lists and per-depth clusterbomb templates were not built, and neither was a curated vocabulary file. 7.2(f) builds its segment vocabulary at runtime from distro-packaged SecLists instead. See *Session addendum — 2026-10-12*.

The body establishes the principle — positional fuzz is practical only with "known prefix, known depth, small targeted lists per position" — but leaves the lists as generic `objects.txt × actions.txt`, which it also flags as exploding (thousands of nouns × hundreds of verbs). The completion: **each position gets its own small, curated, API-meaningful set**, not a generic SecLists dump. This keeps depth-3+ feasible (small lists bound W^N) _and_ high-signal (real API vocabulary, not dictionary words):

- **Prefix / structural position** — usually _pinned_ from discovered structure rather than fuzzed: `api`, `v1`, `v2`, `v3`, `rest`, `graphql`, `internal`, `admin`.
- **Resource / noun positions**: `users`, `user`, `accounts`, `products`, `orders`, `items`, `routes`, `admin`, `auth`, `sessions`, `tokens`, `files`, `uploads`, `config`, `settings`, `debug`, `health`, `status`, `logs`, `reports`.
- **Action / verb + common-sub positions**: `list`, `get`, `all`, `search`, `create`, `new`, `add`, `update`, `edit`, `delete`, `remove`, `me`, `self`, `export`, `import`, `status`.

Mechanics (extends the body): pin the prefix from discovered structure; provide a template **per depth** — **depth 2 (`/<prefix>/FUZZ`) and depth 3 (`/<prefix>/FUZZ/FUZZ`) at least** (explicit operator requirement — real APIs nest past two segments), extensible to depth 4 — each its own `ffuf` clusterbomb invocation, feeding the matching curated list into each position (resource-vocab into noun positions, verb-vocab into action positions) and the request-shape headers/method above. Build-time: derive/trim these lists against the SecLists `Discovery/Web-Content/api/` wordlists, keeping each small enough that depth-3 stays feasible and quiet.

### Minor: dynamic-route stubs as segment-swap templates (written as "fuzz seeds")

The inspector emits template-literal routes as static stubs (`/api/${id}/update`). Route these as **positional-fuzz seeds** (known prefix + known trailing segment), not literal `unauth_paths` probes. Low-yield; noted for completeness.

## Session addendum — 2026-10-12 (build actioned → tripwire closed; prescription superseded)

**The finding and the feroxbuster mechanics above are unchanged and remain correct.** What is superseded is the **prescribed fix** — the two-sub-block "endpoint-harvest + ffuf positional-fuzz" design, and the per-position curated-list / per-depth-clusterbomb mechanics in the 2026-10-06 addendum. Those were derived from "what tools do I already have", not from "what does the field actually do". Re-derived this session against primary sources; the answer differs.

### Tripwire: CLOSED

Fired twice (2026-09-22 MERN box :3000; 2026-10-06 THM _Web Server Attacks - I_ :8000). Actioned 2026-10-12. The build is the rewritten [[Web Attack Checksheet]] **7.2**, which is now the live spec. This note is historical derivation from here on — it no longer prescribes a build.

### What the re-derivation changed

**1. Observed-route corpora beat cartesian products.** The body's rejection of "materialise the combinatorial wordlist to a file" is still correct _as written_ — a W^N product on disk is strictly worse than generating it in ffuf. But it left a third option unexamined: a wordlist of **complete observed routes**, mined from real-world API specs, is not a materialised cartesian product. It is a different artefact. It carries only paths that real APIs actually serve, so it is small, dense, and has no depth ceiling and no prefix assumption — the exact three limits the body lists against positional fuzz. Entries are full paths, so recursion is disabled (`-d 1`) and the non-404-parent problem never arises. This is what the field uses; a self-generated cartesian product is not.

**But no usable corpus exists at a feasible size, so 7.2(e) does not use one.** Both candidates failed on inspection: Assetnote's `swagger-wordlist.txt` is 958,872 entries — the same order as the `httparchive_apiroutes` list rejected on size minutes earlier, so ~1.9M requests at `-m GET,POST`, not exam-viable; and SecLists `api-seen-in-wild.txt` (7,615) holds API **function names**, not routes — its first entries are `!`, `!=`, `&&`, `=`, `==`. 7.2(e) therefore runs SecLists `api-endpoints.txt`: 269 curated full paths, distro-packaged, zero custody. **Do not reach for a corpus again without reading its first lines** — both failures came from inferring content from a filename.

**2. Multi-position clusterbomb is a multiplier, not a sweep.** Retained in 7.2(f) as a **single-position segment swap** off an already-discovered endpoint — which is the body's own "you infer it off an already-discovered endpoint" mechanism, and the only form in which wildcard calibration is well-defined. Multi-position clusterbomb as the primary discovery sweep is dropped.

**3. Vector order corrected — brute is last.** OWASP WSTG `12-API_Testing/01-API_Reconnaissance` and PortSwigger _API testing_ both sequence discovery as: spec/docs → passive → observed traffic → client-side code → **active brute last**. The 2026-10-06 addendum had harvest running _late_ (after the 7.1 brute) on a data-flow argument. That argument was about harvest's _inputs_ being maximal; it does not justify running the low-yield blind sweep first. 7.2 now runs: (a) spec/docs → (b) route-dumper → (c) GraphQL → (d) client-code harvest → (e) curated-route brute → (f) segment-swap → (g) classifiers.

**4. kiterunner exists, and it has the mechanism this design lacked.** `kr` — replays **complete spec-derived requests** (method + path + headers + body) from a corpus compiled from internet-scanned Swagger paths, GitHub, and APIs.guru; baselines the not-found response **per host at a configurable directory depth**, and quarantines a host whose routing is wildcard. Depth-aware per-host baselining + wildcard quarantine is the missing piece — every design in this note before today baselined not-found globally or not at all. Exam-legal and unlimited. **Not used.** Briefly carried in 7.2(e) as a flagged overlay, then dropped: owning its corpus does not fix the chain, because `kr` itself is unpackaged, lightly maintained and flag-unverified — one owned link in a three-link dependency. The mechanism it demonstrates is the value recorded here; the tool is not.

**Source honesty:** only OWASP WSTG names kiterunner. PortSwigger does **not** mention it and teaches Burp Intruder segment-swapping instead. One authoritative source, not two converging — recorded because an earlier draft of this reasoning overstated it.

**5. Still standing from 2026-10-06:** _request-shape is a second, compounding axis_ — unchanged and honoured (7.2(e) runs `-m GET,POST`; every probe in (a)–(c) sets `Accept: application/json` or a JSON body; (f) re-runs with the POST shape). _Yield ordering_ — unchanged in rank 1 (one-hit-full-surface) and rank 2 (client-code harvest); rank 3 is now the curated-route brute, with segment-swap as the multiplier and stray-file harvest the backstop. _Dynamic-route stubs_ — unchanged in substance; terminology is now **template** not **seed** (a seed is what you plant into the hole, so the hole-bearing path is the template). The retained per-position vocabulary was **not** built as a file — 7.2(f) builds its segment list at runtime from SecLists `objects.txt` (alphabetic-leading kept in both cases, pure-numeric stripped — numeric segments belong to [[IDOR]]) ∪ `actions.txt`, plus `flag`, `routes`, `route`, the three tokens SecLists lacks.

### SecLists `api/` composition — confirmed on Kali 2026-10-12

Settles both wordlist choices. The directory is the upstream `chrislockard/api_wordlist` repo plus SecLists additions; its README states the intent is **Burp Intruder cluster-bomb** (payload set 1 = `actions.txt`, set 2 = `objects.txt`), so most files are single tokens by design, not paths.

- `api-endpoints.txt` — **269 full paths**, no leading slash (`api/ads`, `api/announcements`). Absent from the README; a SecLists addition, and the only general-purpose path-shaped list in the directory. → 7.2(e).
- `objects.txt` (3,132) — nouns, but carries a numeric block (`0`, `00`, `01`, …) plus Capitalised variants. → 7.2(f), filtered to alphabetic-leading. PascalCase compounds (`UserAccount`) are **kept**: ASP.NET routes are commonly PascalCase and paths are case-sensitive.
- `actions.txt` (224) — verbs, lowercase and Capitalised interleaved (112 + 112). → 7.2(f).
- `api-seen-in-wild.txt` (7,615) — function **names**, not routes. Unusable as a path list.
- `api-endpoints-res.txt` (12,334) — README: "combination of all of the files above". Single words.
- `actions-lowercase`/`-uppercase`, `objects-lowercase`/`-uppercase` — small case-variant subsets.
- `ispsystem_billmanager_api.txt` (988), `salesforce-aura-objects.txt` (1,285) — vendor-scoped, format unexamined; irrelevant to a general backstop whatever their format.

`flag`, `routes` and `route` are absent from both `objects.txt` and `actions.txt` — hence the three inline supplements in 7.2(f)'s build command. `flag` is the token that reaches `/api/admin/flag`, this note's own worked example.

### What was built and discarded

`api_positional_fuzz.py` — ~700 lines, typed, injectable runner, 60 tests, `mypy --strict` clean, every ffuf flag Kali-confirmed. Generated prefix-jobs and curated-set clusterbomb jobs across depths 2–3, plus stub templates. **Discarded for the 7.2 brute role** — it generates cartesian products (point 1) and has no depth-aware baselining (point 4).

First live run against a THM box emitted **237,386 `API_ENDPOINT_FOUND` lines, all 404**. The sandbox tests had not caught it because the mock's 404 was constant-size. The on-box root cause was **deliberately not established** — diagnosing it would have meant reading that box's not-found shape and tuning to it, and a tool tuned against the box that tests it is not built from first principles. The research instead supplies the likely mechanism: no per-host, depth-aware not-found baseline, so the not-found wall was never characterised and `-fc 404` is a patch on a mis-diagnosed cause.

Kept on disk, not in the vault, as the starting point for the deferred own-tool project.

### Deferred — own kiterunner-class tool (post-OSCP)

Build a maintained observed-route scanner with depth-aware per-host baselining and wildcard quarantine. Rationale: kiterunner is stale, the corpus is the moat, and the mechanism is now understood. **Not now** — zero OSCP+ advancement, and it is a public-artefact / differentiator project, not an exam one. No tripwire; this is a scheduled career item, not a reactive one.

### Discipline lessons (two, both generalisations of existing V_S rules)

- **Ask "what does a world-class operator do" against primary sources _before_ designing, not after a design fails.** The whole positional-fuzz design was a correct derivation inside an under-searched solution space. The body's own _Evidence / sources_ section cites OWASP WSTG API Reconnaissance — and the design still did not follow its ordering. Citing a source is not reading it.
- **A passing test suite over a self-written mock proves the procedure runs; it does not prove the procedure is right.** V_S already holds this. This is its second instance, and the most expensive: 60 green tests over a mock with a constant-size 404, against a 237k-line false-positive flood on first contact. When the mock models the adversarial surface, model its _variability_, not one instance of it.