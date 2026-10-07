

**Type:** Design Notes (deferred-build design capture). Not a playbook — no STATUS tier.
**Owns:** the reasoning behind the ⚠️ tripwire in [[Web Attack Checksheet]] `6.2 API endpoint enumeration`.
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

**Current playbook gap this exposes:** WAC has no first-class step to *harvest* endpoints from what the app discloses — the client's shipped code and observed traffic (for a web target, predominantly the JS/HTML it ships). 6.1 `(e)` greps only source-shape files feroxbuster happens to surface, and feroxbuster's link-extraction scans them but is unreliable (misses dynamically-built routes like `` fetch(`/api/${x}/update`) ``, and on the box that surfaced this returned only root).

---

## Decision — deferred, with tripwire

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
- SecLists `Discovery/Web-Content/api/` README (`objects.txt` = nouns, `actions.txt` = verbs; `api-endpoints.txt` = 371 curated full paths incl. spec/doc/graphql): https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content/api
- API-discovery method reference: OWASP WSTG API Reconnaissance; https://zerodayhacker.com/discover-api-endpoints-with-feroxbuster/
- Sandbox-verified this session: recursion-ladder failure (parents 404 → recursion assembles nothing); positional-fuzz success (same wordlist, clusterbomb reaches the leaf); status/content-type classification.

---

## Session addendum — 2026-10-06 (tripwire fired → build triggered)

**Additive only** — everything above is unchanged. This records the second tripwire occurrence that triggers the build, plus design points raised while scoping it that the original derivation does not cover. Where a point sharpens an existing section, it names that section rather than restating it.

### Status: the build is now triggered

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

The body establishes the principle — positional fuzz is practical only with "known prefix, known depth, small targeted lists per position" — but leaves the lists as generic `objects.txt × actions.txt`, which it also flags as exploding (thousands of nouns × hundreds of verbs). The completion: **each position gets its own small, curated, API-meaningful set**, not a generic SecLists dump. This keeps depth-3+ feasible (small lists bound W^N) _and_ high-signal (real API vocabulary, not dictionary words):

- **Prefix / structural position** — usually _pinned_ from discovered structure rather than fuzzed: `api`, `v1`, `v2`, `v3`, `rest`, `graphql`, `internal`, `admin`.
- **Resource / noun positions**: `users`, `user`, `accounts`, `products`, `orders`, `items`, `routes`, `admin`, `auth`, `sessions`, `tokens`, `files`, `uploads`, `config`, `settings`, `debug`, `health`, `status`, `logs`, `reports`.
- **Action / verb + common-sub positions**: `list`, `get`, `all`, `search`, `create`, `new`, `add`, `update`, `edit`, `delete`, `remove`, `me`, `self`, `export`, `import`, `status`.

Mechanics (extends the body): pin the prefix from discovered structure; provide a template **per depth** — **depth 2 (`/<prefix>/FUZZ`) and depth 3 (`/<prefix>/FUZZ/FUZZ`) at least** (explicit operator requirement — real APIs nest past two segments), extensible to depth 4 — each its own `ffuf` clusterbomb invocation, feeding the matching curated list into each position (resource-vocab into noun positions, verb-vocab into action positions) and the request-shape headers/method above. Build-time: derive/trim these lists against the SecLists `Discovery/Web-Content/api/` wordlists, keeping each small enough that depth-3 stays feasible and quiet.

### Minor: dynamic-route stubs as fuzz seeds

The inspector emits template-literal routes as static stubs (`/api/${id}/update`). Route these as **positional-fuzz seeds** (known prefix + known trailing segment), not literal `unauth_paths` probes. Low-yield; noted for completeness.