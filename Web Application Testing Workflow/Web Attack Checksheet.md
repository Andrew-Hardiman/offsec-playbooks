
> **STATUS: FORMAT-ONLY** — three-set structural restructure applied 2026-09-19; Step 7 (Active content discovery) fully first-principles + primary-source audited (7.1 2026-09-19, 7.2 2026-09-22); remaining sub-blocks structurally reshaped from pre-audit state, per-sub-block first-principles derivation INCOMPLETE. Live-validation pending. Not CANONICAL.

Routes HTTP/HTTPS service to web attack technique walkthroughs. Pure router — attack content lives in per-technique files.

Ordering: P(yield)/time-cost, OSCP+-tuned. Surface enumeration first (Step 1); root-only fingerprinting (Step 2); passive per-path recon (Step 3); input-surface enumeration + injection routing (Step 4); auth-form processing (Step 5); well-known files (Step 6); active scanning (Step 7); subdomain enum only if domain-based (Step 8); deferred low-EV last (Step 9). Off-target OSINT footer-only — near-zero P(yield) on lab boxes.

---

## Setup

Per HTTP/HTTPS service on target (multiple ports = multiple walks).

`<host>` = target hostname or IP for the HTTP service. `<port>` = the HTTP/HTTPS port. `<ip>` = target IP (matches existing MW `route_<ip>.txt`). `<domain>` = target's DNS-resolvable domain (Step 8 only; skip Step 8 if target is IP-only).

Initialise decision log — append to existing `route_<ip>.txt`:

```bash
printf '\nWEB_ROUTES_TRIED (<host>:<port>):\n[<technique>] <disposition>\n' >> route_<ip>.txt
```

`<disposition>` ∈ `{APPLIED: <outcome>, INAPPLICABLE: <reason>, DEFERRED: <reason>}`

---

## Version-discovery route

Fires any time a product or version token is observed during the walk. Sub-blocks 2.1–2.4 are the dedicated probes; the route also fires opportunistically on version signals surfaced by later sub-blocks (headers on gobuster hits, meta generators on inspected pages, framework hints in error responses, etc.).

1. Grep `services_<ip>.txt` for this service: `grep '^<port>/open' services_<ip>.txt`
2. Field 5 already contains `<product>` AND `<version>` tokens → next sub-block (Pass 1 has covered this).
3. Product/component token known, no version → [[Web Stack Version Discovery]] (recover the version → write to `services_<ip>.txt` field 5 → re-apply this route from step 1).
4. Either token new → run [[MASTER WORKFLOW/Step 6. Vulnerability Analysis#Pass 1 re-fire]].

---

## Accumulator conventions

Three per-host accumulator files hold intel harvested during the walk. Each is drained by a sub-routine in [[#Accumulator re-fire check]] at every Step boundary that has one. All appends followed by periodic dedup: `sort -u <file> -o <file>`.

### `users_<host>.txt`

Any sub-block that enumerates or verifies a valid target username appends:

`echo '<username>' >> users_<host>.txt`

### `creds_<host>.txt`

Used by [[Authenticated Walk]].

Any sub-block that recovers or creates a working credential pair appends:

`echo '<username>:<password>' >> creds_<host>.txt`

Format: `<username>:<password>` per line.

### `unauth_paths_<host>.txt`

Master path list of the unauthenticated attack surface. 

Any sub-block that discovers an in-target path appends:

`echo '<path>' >> unauth_paths_<host>.txt`

Format: absolute path (starts with `/`), one per line.

---

## Accumulator re-fire check

Fires at end of each Step that has a boundary check and at end of [[Authenticated Walk]] per-cred iteration. Runs each accumulator's sub-routine with unwalked entries. Every action fires against every unwalked entry; entry marked walked after all applicable actions complete.

### `users_<host>.txt` sub-routine

Runs when `users_<host>.txt` has entries not present in `users_<host>.txt.walked`:

`comm -23 <(sort -u users_<host>.txt) <(sort -u users_<host>.txt.walked 2>/dev/null)`

Actions (each fires against every unwalked entry; preconditions checked per action):

1. [[Credential Attacks]] §5 (enum-fed credential attack). Precondition: a login form was discovered anywhere in the walk. Treat entry as username; convert to `<entry>@<known_domain>` if login form uses email format.
2. [[Password Reset Attacks]] against unauth forgot-password form. Precondition: a forgot-password form was discovered anywhere in the walk. Treat entry as identifier; convert to email format if forgot form expects email.

Mark entry walked after all applicable actions run:

`echo '<entry>' >> users_<host>.txt.walked`

Any working credentials yielded → `echo '<user>:<pass>' >> creds_<host>.txt`. Handled by `creds_<host>.txt` sub-routine below.

### `creds_<host>.txt` sub-routine

Runs when `creds_<host>.txt` has entries not present in `creds_<host>.txt.walked`:

`comm -23 <(sort -u creds_<host>.txt) <(sort -u creds_<host>.txt.walked 2>/dev/null)`

Action:

- [[Authenticated Walk]]

Mark **all** newly-walked entries after Auth Walk returns:

`echo '<entry>' >> creds_<host>.txt.walked`

### `unauth_paths_<host>.txt` sub-routine

Runs when `unauth_paths_<host>.txt` has entries not present in `unauth_paths_<host>.txt.walked`:

`comm -23 <(sort -u unauth_paths_<host>.txt) <(sort -u unauth_paths_<host>.txt.walked 2>/dev/null)`

For each unwalked path `<p>`:

1. Apply Passive Recon set actions (Step 3 — each with its scope filter; skip actions whose filter excludes `<p>`).
2. Input Surface Enumeration (Step 4) — run both scripts against `<p>`, then route per 4.2 / defer per 4.3.
3. If `<p>` matches auth-shape filter → additionally dispatch Auth-form Per-path processing:
   - Matches `(login|signin|portal)` → 5.1 Per-path processing
   - Matches `(register|signup)` → 5.2 Per-path processing
   - Matches `(forgot|reset|recover)` → 5.3 Per-path processing

Mark path walked after all applicable actions run:

`echo '<p>' >> unauth_paths_<host>.txt.walked`

---

## Step 1 — Unauthenticated surface enumeration

Produces a master path list (`unauth_paths_<host>.txt`) of the unauthenticated attack surface.

Firefox DevTools → Network tab (persist logs on) captures all requests. Click through every navigation element visible without authentication: main nav, dropdowns, hero CTAs, sidebar items, footer links, breadcrumbs on each landing, pagination controls. Every click loads a real page.

When exploration complete: right-click on a request row within the Network tab → Save All As HAR → `unauth_crawl_<host>.har`.

Curl-sweep HAR-captured target-host HTMLpages for embedded hrefs (catches paths advertised but not clicked; MIME-filter reduces waste on binary responses):

`jq -r --arg h "<host>" --arg p "<port>" '.log.entries[] | select(.request.url | test("^https?://" + $h + "(:" + $p + ")?/")) | select(.response.content.mimeType // "" | startswith("text/html")) | .request.url' unauth_crawl_<host>.har | sed -E "s|^https?://<host>(:<port>)?||" | grep -E '^/([^/]|$)' | sort -u | while read fetch_p; do curl -s --max-time 5 "http://<host>:<port>${fetch_p}" | grep -oiE 'href=["'"'"'][^"'"'"']+'; done | sort -u > unauth_hrefs_<host>.txt`

Combine target-host URLs from HAR with extracted hrefs, filtering to target-host paths only (rejects third-party CDN URLs, protocol-relative URLs, mailto/tel/javascript/fragment hrefs):

`{ jq -r --arg h "<host>" --arg p "<port>" '.log.entries[] | select(.request.url | test("^https?://" + $h + "(:" + $p + ")?/")) | .request.url' unauth_crawl_<host>.har 2>/dev/null; sed -E 's|^href=["'"'"']||' unauth_hrefs_<host>.txt; } | sed -E "s|^https?://<host>(:<port>)?||" | grep -E '^/([^/]|$)' | sort -u > unauth_paths_<host>.txt`

Route:

- `unauth_paths_<host>.txt` non-empty → seed walked file (below), continue to Step 2.
- `unauth_paths_<host>.txt` empty → seed with root only: `echo '/' > unauth_paths_<host>.txt`. Seed walked file (below), continue to Step 2.

Seed walked file — marks all Step-1-discovered paths as already-covered by Passive Recon (Step 3) initial iteration; end-of-Step-5-onward re-fires drain only paths discovered post-Step-1:

`cp unauth_paths_<host>.txt unauth_paths_<host>.txt.walked`

---

## Step 2 — Root-only fingerprinting

Homepage-only sub-blocks; scope is `/` (or `/favicon.ico` for 2.2). These signals are server-config or template-level and near-always identical across paths on a single-app target; per-path iteration is not required.

### 2.1 HTTP response headers

`curl -s -D - -o /dev/null "http://<host>:<port>/" | grep -iE '^(Server|X-Powered-By):' || echo "NO_VERSION_HEADERS"`

Route on output:

- `Server: <product>/<version>` line present → apply Version-discovery route (above)
- `X-Powered-By: <product>/<version>` line present → apply Version-discovery route (above)
- `NO_VERSION_HEADERS` → 2.2

### 2.2 Favicon fingerprint

`curl -sfL http://<host>:<port>/favicon.ico | md5sum || echo "FAVICON_ABSENT"`

Compare hash against [OWASP favicon database](https://wiki.owasp.org/index.php/OWASP_favicon_database) ([[Useful Websites (Web App Pen Testing)]]) - **NB: Search the database using `Ctrl+f` on the webpage; using the search input box searches the entire website, not the database (page)**

Route on output:

- Hash matches framework+version entry in DB (label contains product name and version, e.g. `WordPress 5.4`) → apply **Version-discovery route**
- Hash matches non-framework entry (e.g. `Zero byte favicon d41d8cd98f00b204e9800998ecf8427e`, generic server default icon) → 2.3
- Hash has no DB match → 2.3
- `FAVICON_ABSENT` → 2.3

### 2.3 Wappalyzer extension

In **browser** (Wappalyzer extension installed), navigate to `http://<host>:<port>/`. Read extension panel.

Route on panel content:

- Server-side product identified with version (web server, language runtime, backend framework, CMS) → apply **Version-discovery route** (above)
- Client-side library identified with version (jQuery, Bootstrap, React, Vue, Angular, etc.) → log `CLIENT_LIB: <name> <version>` under `WEB_ROUTES_TRIED (<host>:<port>)` in `route_<ip>.txt`
- Framework identified without version → [[Web Stack Version Discovery]]
- Nothing identified → 2.4

### 2.4 HTML source version disclosure

Two sweeps: meta tags and visible text. Both feed **Version-discovery route** (above).

#### Meta tags:

`curl -s http://<host>:<port>/ | grep -oiE '<meta[^>]*(generator|framework)[^>]*>' || echo "NO_META_GEN"`

Route on output:

- Content attribute contains framework + version → apply **Version-discovery route**
- Content attribute contains framework only → [[Web Stack Version Discovery]]
- `NO_META_GEN` → visible-text sweep

#### Visible text:

`{ curl -s http://<host>:<port>/ | perl -0777 -pe 's#<(style|script)\b[^>]*>.*?</\1>##gs; s#<[^>]*># #g' | grep -oiE '[a-zA-Z][a-zA-Z0-9._-]* v?[0-9]+(\.[0-9]+)+' || echo "NO_VISIBLE_VERSION"; } | sort -u`

Route on output:

- Match contains framework + version (e.g. `RecruitX v2.4`, `WordPress 5.4`) → apply **Version-discovery route**
- `NO_VISIBLE_VERSION` → 2.5

### 2.5 Cookies (unauth, root)

`curl -s -D - -o /dev/null "http://<host>:<port>/" | grep -i '^Set-Cookie:' || echo "NO_COOKIES"`

Route on output:

- One or more `Set-Cookie` values present → [[Session Cookie Attacks]]
- `NO_COOKIES` → continue to Step 3.

---

## Step 3 — Passive Reconnaissance

Per-path passive reads (comments, admin-link discovery, flag hunt). Initial run: apply each sub-block's action to all paths in `unauth_paths_<host>.txt` (each applies its own scope filter). Subsequent invocations via the `unauth_paths_<host>.txt` sub-routine in [[#Accumulator re-fire check]] at end-of-Step boundaries — walked-tracked.

Any sub-block that discovers a new path appends to `unauth_paths_<host>.txt`; re-fire drains at next boundary.

### 3.1 HTML comments sweep

Scope: HTML-eligible paths in `unauth_paths_<host>.txt`.

`grep -vE '\.(png|jpg|jpeg|gif|css|js|woff2?|ico|svg|mp4|webm|pdf|zip|tar|gz|json)$' unauth_paths_<host>.txt | while read p; do echo "=== $p ==="; out=$(curl -s "http://<host>:<port>${p}" | grep -Pzo '(?s)<!--.*?-->' | tr -d '\0'); [ -n "$out" ] && printf '%s\n' "$out" || echo "NO_COMMENTS"; done`

Route per path on inspection (per finding, may fire multiple):

- Framework name + version → apply **Version-discovery route**
- Framework name only, no version → [[Web Stack Version Discovery]]
- Username(s) → `echo '<username>' >> users_<host>.txt`
- Credentials (user:pass, key=value) → `echo '<user>:<pass>' >> creds_<host>.txt`
- Endpoint / path → `echo '<endpoint>' >> unauth_paths_<host>.txt` (re-fire drains at next step boundary)
- Nothing exploitable → no action

### 3.2 Visible admin/dashboard links (unauth)

Scope: HTML-eligible paths in `unauth_paths_<host>.txt`.

`grep -vE '\.(png|jpg|jpeg|gif|css|js|woff2?|ico|svg|mp4|webm|pdf|zip|tar|gz|json)$' unauth_paths_<host>.txt | while read p; do echo "=== $p ==="; curl -s "http://<host>:<port>${p}" | grep -oiE 'href=["'"'"'][^"'"'"']*(admin|dashboard|settings|manage|console)[^"'"'"']*' | sort -u || echo "NO_ADMIN_LINK"; done`

For each admin-shape href hit, extract the path portion. Test unauth access:

`curl -s -o /dev/null -w "%{http_code}\n" http://<host>:<port>/<extracted_path>`

Route on status code:

- 200 / 302 (no auth challenge) → `echo '/<extracted_path>' >> unauth_paths_<host>.txt` (re-fire drains at next Step boundary — auth-shape filter dispatches Auth-form Per-path processing if matches).
- 401 / 403 / redirect to login → note the admin path for later credential re-use; if creds recovered anywhere later → try against this path.
- `NO_ADMIN_LINK` for a path → no action.

---

### 3.3 Flag hunt (CTF-only overlay)

⚠️ **CTF/lab only** — skip on real engagements. 

Scope: HTML-eligible paths in `unauth_paths_<host>.txt`.

`grep -vE '\.(png|jpg|jpeg|gif|css|js|woff2?|ico|svg|mp4|webm|pdf|zip|tar|gz|json)$' unauth_paths_<host>.txt | while read p; do echo "=== $p ==="; out=$(curl -s "http://<host>:<port>${p}" | grep -oE '(THM|HTB|flag|FLAG|CTF)\{[^}]*\}'); [ -n "$out" ] && printf '%s\n' "$out" || echo "NO_FLAG"; done`

Route per path on output:

- Flag hit → capture value; enter into room's answer field if THM/HTB task; log to `route_<ip>.txt` as `FLAG_FOUND: <path>: <value>`
- `NO_FLAG` → no action for this path

## Step 4 — Input Surface Enumeration

Enumerate every input the app exposes — URL query parameters and HTML form controls — across all discovered paths, then route each to its highest-EV technique. Two scripts surface the two input containers (URL query strings; form fields including hidden inputs, POST bodies, textareas); one routing table consumes both.

### 4.1 Enumerate inputs

Batch both scripts over the master path list:

`~/scripts/url_params_enum.py --base http://$host:$port --paths unauth_paths_$host.txt --verbose >> url_params_$host.txt`

`~/scripts/form_enum.py --base http://$host:$port --paths unauth_paths_$host.txt --verbose >> form_enum_$host.txt`

⚠️ **JS-tripwire:** `form_enum.py` flags pages whose forms may be JS-built (they won't appear in its output). If a form visible in the browser is missing from the output, capture it from HAR/Burp and route it manually.

### 4.2 Route candidates (highest-EV first)

Collect all `ROUTE_CANDIDATE` / `UPLOAD_CANDIDATE` lines from both scripts. Route each by param name, then by value shape (URL params carry `[url/<shape>]`; form fields route by name / control type). 

Marker formats:

- `url_params_enum.py` → `ROUTE_CANDIDATE: GET <endpoint> <param> [url/<shape>]` — `<shape>` ∈ `{EMPTY, URLISH, NUMERIC, HEXHASH, PATHISH, OPAQUE}`
- `form_enum.py` → `ROUTE_CANDIDATE: <method> <action> <param> [<control>]` and `UPLOAD_CANDIDATE: <action> <param>`, grouped under `FORM #<n>` headers — `<control>` ∈ `{input/<type>, textarea, select}`

Walk in this order:

1. `UPLOAD_CANDIDATE: <action> <param>` → [[File Upload]]
2. name ∈ {`file`, `page`, `include`, `template`, `lang`, `doc`} OR shape `PATHISH` → [[Local File Inclusion]], then [[Remote File Inclusion]], then [[Path Traversal]]
3. name ∈ {`url`, `server`, `redirect`, `fetch`, `dst`, `endpoint`, `src`, `next`, `return`, `returnUrl`, `continue`} OR shape `URLISH` → [[SSRF]]
4. name ∈ {`id`, `uid`, `pid`} OR shape ∈ {`NUMERIC`, `HEXHASH`} → [[IDOR]]
5. Any other user-controlled param → [[Injection]] (top-level stub routes into sub-technique per input context)

Name/shape is a priority hint, not proof — a param confirmed user-controllable by testing is injectable regardless of its name; the hint only picks which technique to try first. A param unmatched by 1–4 still gets [[Injection]] (bucket 5).

No candidates emitted for a path → no action for that path.

### 4.3 Defer reflected / stored / state surfaces (Step 9 sweep)

Client-side and state-abuse surfaces are lower-EV for foothold — logged now, walked in the Step 9 sweep, not here. Seed from script output (text / textarea / search controls) plus browse. For each, log DEFERRED — do NOT walk the technique now:

- Search / filter / error / page param that echoes into the response → `printf '[step9-sweep] DEFERRED: REFLECTED_CANDIDATE: <location>\n' >> route_<ip>.txt`
- Textarea / comment / review / bio / message field (content persists) → `printf '[step9-sweep] DEFERRED: STORED_SURFACE: <location>\n' >> route_<ip>.txt`
- State-mutating submit (register, redeem, transfer, one-time claim) → `printf '[step9-sweep] DEFERRED: STATE_ENDPOINT: <location>\n' >> route_<ip>.txt`

Nothing observed for a path → no action.

## Step 5 — Auth-form processing

### 5.1 Login form

Discover login form via:

`~/scripts/web_auth_probe.sh <host> <port> --mode=login`

Optional flags:

- `--scheme=https` for TLS services (default: http)
- `--verbose` to show DEAD (404) markers when summary reports 0 FOUND / 0 CANDIDATE

Route on markers:

- `LOGIN_FORM_FOUND: [<orig> → ]<final>` → login form discovered; `<login_path>` = final path (after `→` if present, else the path shown).

  **Capture form metadata** (required before technique walk):

  `curl -sL http://<host>:<port>/<login_path> | grep -oiE '<(form|input)[^>]*>'`

  From output, set the variables consumed by all downstream techniques:

  - `<login_username_field>` = `name=` of the text or email input
  - `<login_password_field>` = `name=` of the `type=password` input
  - `<login_form_action>` = `action=` of the `<form>` tag (if absent, use `<login_path>`)

  **Probe statefulness** (required before technique walk):

  `~/scripts/statefulness_probe.sh --host=<host> --port=<port> --path=<login_path>`

    Optional flags:

  - `--scheme=https` for TLS services (default: http)
  - `--delay=<ms>` milliseconds between the two GETs (default: 0)

  Route on `ROUTE:` marker:

  - `ROUTE: shell` → set `<login_static_cookies>` = `STATIC_COOKIES:` value, `<login_static_hidden_fields>` = `STATIC_HIDDEN_FIELDS:` value; walk techniques via shell tools with these vars in POSTs.
  - `ROUTE: burp` → in Burp, build the base target request with `STATIC_COOKIES:` value in the Cookie header and `STATIC_HIDDEN_FIELDS:` value in the POST body; set up state-refresh macro per [[Automating Fresh State in Burp]] using `ROTATING_*` + `NEW_*_GET2` marker names as the "Update only the following parameters and headers" list; walk techniques via Burp Intruder.
  - `BAIL: <reason>` → probe could not classify; try [[Automating Fresh State in Burp]] manually, or log INAPPLICABLE if login path itself broken.
  - `RATE_LIMITED: <detail>` → re-run with higher `--delay=<ms>` (start 500; double until throttling clears).

  **Walk techniques in order:**

  1. [[Credential Attacks]] Sections 1-4 (default creds, credential stuffing, hit-and-hope brute force, password spray) — Section 5 defers to `users_<host>.txt` re-fire sub-routine.
  2. [[Login Bypass Techniques]] (all sections — HTML comments, injection, tampering, direct access, header bypass, case-sensitivity, HTTP Basic Auth)
  3. [[Username Enumeration]] Section 1.1 (login-form differential signal detection — appends to `users_<host>.txt`)
  4. [[Session Cookie Attacks]] if Set-Cookie observed on any request during walk (per sub-block 2.5 detection)
  5. [[MFA Bypass]] if multi-step verification observed after successful first-factor auth
- `LOGIN_CANDIDATE: [<orig> → ]<final> (<detail>)` (no FOUND for this path) → open final path in browser; if login form confirmed, `<login_path>` = final path, follow LOGIN_FORM_FOUND branch above (capture metadata + walk techniques); if not confirmed, log INAPPLICABLE
- `AUTH_CHALLENGE: [<orig> → ]<final> (code=401 scheme=Basic)` → walk [[Login Bypass Techniques]] "HTTP Basic Auth" section against that path
- `AUTH_CHALLENGE` with scheme other than Basic (Bearer / Digest / etc.) → log informational, note as auth surface for later
- Other markers (`RESTRICTED` / `METHOD_MISMATCH` / `SERVER_ERROR` / `NO_FORM` / `DEAD` / `UNREACHABLE`) → informational, no action in this sub-block
- No `LOGIN_FORM_FOUND` AND no `LOGIN_CANDIDATE` AND no actionable `AUTH_CHALLENGE` → continue

### 5.2 Register form

Discover register / sign-up form via:

`~/scripts/web_auth_probe.sh <host> <port> --mode=register`

Optional flags:

- `--scheme=https` for TLS services (default: http)
- `--verbose` to show DEAD (404) markers when summary reports 0 FOUND / 0 CANDIDATE

Route on markers:

- `REGISTER_FORM_FOUND: [<orig> → ]<final>` → register form discovered; `<register_path>` = final path (after `→` if present, else the path shown).

  **Capture form metadata** (required before technique walk):

  `curl -sL http://<host>:<port>/<register_path> | grep -oiE '<(form|input)[^>]*>'`

  From output, set the variables consumed by all downstream techniques:

  - `<register_username_field>` = `name=` of the text input whose `name=` matches username (e.g. `username`, `user`, `uname`); empty string if form has no username input
  - `<register_email_field>` = `name=` of the `type=email` input, or text input whose `name=` matches email (e.g. `email`, `mail`, `e_mail`); empty string if form has no email input
  - `<register_password_field>` = `name=` of the first `type=password` input
  - `<register_confirm_password_field>` = `name=` of the second `type=password` input; empty string if only one password input present
  - `<register_form_action>` = `action=` of the `<form>` tag (if absent, use `<register_path>`)

  **Probe statefulness** (required before technique walk):

  `~/scripts/statefulness_probe.sh --host=<host> --port=<port> --path=<register_path>`

  Optional flags:

  - `--scheme=https` for TLS services (default: http)
  - `--delay=<ms>` milliseconds between the two GETs (default: 0)

  Route on `ROUTE:` marker:

  - `ROUTE: shell` → set `<register_static_cookies>` = `STATIC_COOKIES:` value, `<register_static_hidden_fields>` = `STATIC_HIDDEN_FIELDS:` value; walk techniques via shell tools with these vars in POSTs.
  - `ROUTE: burp` → in Burp, build the base target request with `STATIC_COOKIES:` value in the Cookie header and `STATIC_HIDDEN_FIELDS:` value in the POST body; set up state-refresh macro per [[Automating Fresh State in Burp]] using `ROTATING_*` + `NEW_*_GET2` marker names as the "Update only the following parameters and headers" list; walk techniques via Burp Intruder.
  - `BAIL: <reason>` → probe could not classify; try [[Automating Fresh State in Burp]] manually, or log INAPPLICABLE if register path itself broken.
  - `RATE_LIMITED: <detail>` → re-run with higher `--delay=<ms>` (start 500; double until throttling clears).

  **Walk techniques in order:**

  1. [[Registration Attacks]] (all sections — privileged usernames, username variants, parameter tampering, weak password policy, race conditions, post-registration surface enumeration)
  2. [[Username Enumeration]] Section 1.2 (register-form signal detection — appends to `users_<host>.txt`)
- `REGISTER_CANDIDATE: [<orig> → ]<final> (<detail>)` (no FOUND for this path) → open final path in browser; if register form confirmed, `<register_path>` = final path, follow REGISTER_FORM_FOUND branch above (capture metadata + walk techniques); if not confirmed, log INAPPLICABLE
- Other markers (`AUTH_CHALLENGE` / `RESTRICTED` / `METHOD_MISMATCH` / `SERVER_ERROR` / `NO_FORM` / `DEAD` / `UNREACHABLE`) → informational, no action in this sub-block
- No `REGISTER_FORM_FOUND` AND no `REGISTER_CANDIDATE` → Continue

### 5.3 Forgot-password form

Discover forgot-password / reset form via:

`~/scripts/web_auth_probe.sh <host> <port> --mode=forgot`

Optional flags:

- `--scheme=https` for TLS services (default: http)
- `--verbose` to show DEAD (404) markers when summary reports 0 FOUND / 0 CANDIDATE

Route on markers:

- `FORGOT_FORM_FOUND: [<orig> → ]<final>` → forgot-password form discovered; `<forgot_path>` = final path (after `→` if present, else the path shown).

  **Capture form metadata** (required before technique walk):

  `curl -sL http://<host>:<port>/<forgot_path> | grep -oiE '<(form|input)[^>]*>'`

  From output, set the variables consumed by all downstream techniques:

  - `<forgot_identifier_field>` = `name=` of the input where the user provides their account identifier (`type=email` input, or text input whose `name=` matches `email`, `mail`, `username`, `user`, `login`, `identifier`)
  - `<forgot_form_action>` = `action=` of the `<form>` tag (if absent, use `<forgot_path>`)

  **Probe statefulness** (required before technique walk):

  `~/scripts/statefulness_probe.sh --host=<host> --port=<port> --path=<forgot_path>`

  Optional flags:

  - `--scheme=https` for TLS services (default: http)
  - `--delay=<ms>` milliseconds between the two GETs (default: 0)

  Route on `ROUTE:` marker:

  - `ROUTE: shell` → set `<forgot_static_cookies>` = `STATIC_COOKIES:` value, `<forgot_static_hidden_fields>` = `STATIC_HIDDEN_FIELDS:` value; walk techniques via shell tools with these vars in POSTs.
  - `ROUTE: burp` → in Burp, build the base target request with `STATIC_COOKIES:` value in the Cookie header and `STATIC_HIDDEN_FIELDS:` value in the POST body; set up state-refresh macro per [[Automating Fresh State in Burp]] using `ROTATING_*` + `NEW_*_GET2` marker names as the "Update only the following parameters and headers" list; walk techniques via Burp Intruder.
  - `BAIL: <reason>` → probe could not classify; try [[Automating Fresh State in Burp]] manually, or log INAPPLICABLE if forgot path itself broken.
  - `RATE_LIMITED: <detail>` → re-run with higher `--delay=<ms>` (start 500; double until throttling clears).

  **Walk techniques in order:**

  1. [[Password Reset Attacks]] (all sections — token attacks, URL manipulation, poisoning, logic flaws, security questions)
  2. [[Username Enumeration]] Section 1.3 (forgot-password signal detection — appends to `users_<host>.txt`)
- `FORGOT_CANDIDATE: [<orig> → ]<final> (<detail>)` (no FOUND for this path) → open final path in browser; if forgot-password form confirmed, `<forgot_path>` = final path, follow FORGOT_FORM_FOUND branch above (capture metadata + walk techniques); if not confirmed, log INAPPLICABLE
- Other markers (`AUTH_CHALLENGE` / `RESTRICTED` / `METHOD_MISMATCH` / `SERVER_ERROR` / `NO_FORM` / `DEAD` / `UNREACHABLE`) → informational, no action in this sub-block
- No `FORGOT_FORM_FOUND` AND no `FORGOT_CANDIDATE` → Continue

---
## — Boundary — end of Step 5

→ [[#Accumulator re-fire check]]
→ Step 6

---

## Step 6 — Well-known files

### 6.1 robots.txt

`curl -s http://<host>:<port>/robots.txt || echo "ROBOTS_ABSENT"`

Route on output:

- Entries under `Disallow:` → for each, `echo '<path>' >> unauth_paths_<host>.txt` (re-fire drains at Step boundary)
- `ROBOTS_ABSENT` → 6.2

### 6.2 sitemap.xml

`{ curl -sfL "http://<host>:<port>/sitemap.xml" || curl -sfL "http://<host>:<port>/sitemap_index.xml"; } || echo "SITEMAP_ABSENT"`

Route on output:

- `<loc>` entries present → for each not already in `unauth_paths_<host>.txt`, extract path (strip scheme+host) → `echo '<path>' >> unauth_paths_<host>.txt`
- `SITEMAP_ABSENT` → continue

### 6.3 Apache diagnostic endpoints (`/server-status`, `/server-info`)

⚠️ Apache-stack only. mod_status` / `mod_info` default to `Require local`, but a `Require all granted` in any vhost silently overrides it.

##### Server Status

`code=$(curl -s -o /dev/null -w '%{http_code}' "http://<host>:<port>/server-status"); echo "SERVER_STATUS: HTTP $code"`

Route on `$code`:

- `200` — exposed. Mine:
  - Version: `curl -s "http://<host>:<port>/server-status" | grep -oiE 'Server Version: *[^<]+'` → **Version-discovery route** on the `Apache/<version>` token and any other product/version tokens in the line (OpenSSL, mod_perl, PHP, …). 
  - In-flight request paths (present only under `ExtendedStatus On`): `curl -s "http://<host>:<port>/server-status" | grep -oiE '(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)[[:space:]]+/[^[:space:]]*[[:space:]]+HTTP/[0-9.]+' | awk '{print $2}' | grep -vE '^/server-(status|info)\b'`. **Add relevant paths to `unauth_paths_<host>.txt`** No matches → `ExtendedStatus` off; version only.
- `403` — module loaded, `Require local` effective. `echo 'RESTRICTED: /server-status' >> route_<ip>.txt`; re-attempt via any localhost-origin primitive (e.g. SSRF) found later.
- `404` — `mod_status` off/absent. No action.

##### Server Info

`code=$(curl -s -o /dev/null -w '%{http_code}' "http://<host>:<port>/server-info"); echo "SERVER_INFO: HTTP $code"`

Route on `$code`:

- `200` — exposed. Leaks loaded modules + full config (module presence → attack surface, e.g. `mod_cgi`; config may disclose `DocumentRoot`, aliases, paths).
  - Version: `curl -s "http://<host>:<port>/server-info" | grep -oiE 'Server Version: *[^<]+'` → **Version-discovery route**.
  - `echo 'CONFIG_LEAK: /server-info' >> route_<ip>.txt`, read manually: `curl -s "http://<host>:<port>/server-info" | less`; any path/alias disclosed → `echo '<path>' >> unauth_paths_<host>.txt`.
- `403` — loaded, restricted. `echo 'RESTRICTED: /server-info' >> route_<ip>.txt`.
- `404` — `mod_info` off/absent. No action.

---

## — Boundary — end of Step 6

→ [[#Accumulator re-fire check]]
→ Step 7

---

## Step 7 — Active content discovery

> **STATUS (this step): AUDITED** — first-principles + primary-source derivation. 7.1: OWASP WSTG-INFO-04/06, PortSwigger Content Discovery, HackTricks Directory Brute Force, PayloadsAllTheThings, feroxbuster/gobuster/SecLists docs. 7.2: OWASP WSTG API Reconnaissance, SecLists api-endpoints.txt, GraphQL introspection. Sandbox-verified mechanics — 7.1: autoindex/credential/endpoint/href/output parsing; 7.2: jq spec-parse (OpenAPI-3 servers + Swagger-2 basePath prefixing, HTML-UI rejection), GraphQL introspection detection, content-type JSON classification. Tool-flag correctness (feroxbuster/gobuster/jq/curl) verification-pending until first live run; live-validation on ≥1 real target pending. Not yet CANONICAL.

Actively enumerate paths the app didn't advertise. Two mechanisms: recursive wordlist enumeration (7.1) and API endpoint enumeration (7.2). All hits append to `unauth_paths_<host>.txt` — re-fire at Step 7 boundary dispatches Passive Recon (Step 3) and Auth-form Per-path processing (Step 5).

### 7.1 Recursive wordlist enumeration

**Tool: feroxbuster.** Native recursion (default-enabled). Kali 2020.4+ default install. Fallback below.

Select extension set per server-side stack identified in Step 2 (Version-discovery route). If stack unknown, use wide-net.

#### **Choose one — feroxbuster invocation:**

- **PHP stack**:
  `feroxbuster -u "http://<host>:<port>" -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,phtml,php3,php4,php5,inc,html,txt,js,json,bak,log,conf,env,old,orig -d 4 --auto-tune -o feroxbuster_<ip>_<port>.txt`

- **ASP.NET stack**:
  `feroxbuster -u "http://<host>:<port>" -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x aspx,asp,ashx,asmx,config,html,txt,js,json,bak,log,old -d 4 --auto-tune -o feroxbuster_<ip>_<port>.txt`

- **Java/JSP stack**:
  `feroxbuster -u "http://<host>:<port>" -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x jsp,jspx,do,action,xml,html,txt,js,json,bak,log,conf,old -d 4 --auto-tune -o feroxbuster_<ip>_<port>.txt`

- **Node.js / Python stack**:
  `feroxbuster -u "http://$host:$port" -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x js,json,txt,bak,log,env,conf,old,py -d 4 --auto-tune -o feroxbuster_${host}_$port.txt`

- **Stack unknown** (wide-net fallback):
  `feroxbuster -u "http://$host:$port" -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,aspx,jsp,html,txt,js,json,bak,log,conf,inc,env,old,orig,py -d 4 --auto-tune -o feroxbuster_${host}_$port.txt`

`-d 4` caps recursion depth. Feroxbuster shows all status codes; it suppresses the not-found wall by auto-building a wildcard filter from that response's signature (lines/words/chars) — the `… created new filter` lines are this calibration, not findings. Any response deviating from the signature (a non-404, or a 404 of a different size) is shown.

**Overlays:**
- ⚠️ Rate-limit (real engagement, WAF suspected): append `-t 5 --rate-limit 10` (5 threads, 10 req/sec) ⚠️.
- Same-length noise (server returns 200 for missing paths): feroxbuster's automatic wildcard filter handles most (see body); manual `-C <length>` filters a specific response length.

#### **Gobuster fallback** — if feroxbuster unavailable:

`gobuster dir -u "http://<host>:<port>" -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x <extensions_per_stack> -o gobuster_<ip>_<port>.txt`

⚠️ Gobuster does NOT recurse. `-r` follows redirects only. For every 200/301/302 hit on a directory-shape path, manually re-invoke:
`gobuster dir -u "http://<host>:<port>/<discovered_dir>/" -w <wordlist> -x <extensions> -o gobuster_<ip>_<port>_<slug>.txt`

#### **Error gate** — run before per-hit processing:

Feroxbuster run only — skip if gobuster fallback was used.

Read `errors:<errors>` and the request total from feroxbuster's overall completion line (`<total>/<total> … found:… errors:<errors>`), then:

`awk -v e=<errors> -v t=<total> 'BEGIN{r=e/t*100; printf "%.3f%% errored — %s\n", r, (r>0.5?"RERUN":"PROCEED")}'`

Route on verdict:

- `PROCEED` → continue to per-hit processing.
- `RERUN` → rerun this leg once with `-t 10`, then continue to per-hit processing.

#### **Per-hit processing** — five small single-purpose commands:

##### (a) Extract hit URLs to a working file:

`awk '/^[0-9]{3}[[:space:]]/ {print $NF}' feroxbuster_${host}_$port.txt | sort -u > hits_${host}_$port.txt`

##### (b) Add every hit path to `unauth_paths_<host>.txt`:

`sed -E "s|^https?://<host>(:<port>)?||" hits_<ip>_<port>.txt >> unauth_paths_<host>.txt && sort -u unauth_paths_<host>.txt -o unauth_paths_<host>.txt`

##### (c) Autoindex detection loop — extract directory listings:

`grep 'directory listing' feroxbuster_<ip>_<port>.txt | sed -E 's|^.*directory listing: |AUTOINDEX: |'`

For each `AUTOINDEX: <url>` line, record to `route_<ip>.txt`.
##### (d) High-value file inspection

Create the local inspection dir:

`mkdir -p inspect_${host}_$port`

Download every hit (**relies on `(a) Extract hit URLs....`, above, having been successfully run**) except HTML pages and media:

`grep -vE '\.(html?|png|jpe?g|gif|svg|ico|webp|bmp|tiff?|avif|css|woff2?|ttf|otf|eot|mp[34]|m4[av]|webm|wav|ogg|oga|flac|aac|avi|mov|mkv|wmv|flv)$|/$' hits_${host}_$port.txt | while read -r url; do curl -s -L -O --output-dir inspect_${host}_$port "$url"; done`

Inspect the tree:

`~/scripts/local_file_inspector.py inspect_${host}_$port`

Route per marker:

- `FILE_CRED: <path>: <match>` — verify (may be a placeholder like `changeme` / `<PASSWORD>`); real credential → `echo '<user>:<pass>' >> creds_<host>.txt`; log `echo 'FILE_CRED: <path>: <match>' >> route_<ip>.txt`.
- `SECRET: <path>: <type>:<value>` — route by `<type>`: `jwt` → [[Session Cookie Attacks]] (JWT branch); `bearer` / `token` → reuse as an `Authorization` header on auth-gated requests; `aws_akid` / `api_key` / `google_api_key` / `slack_token` / `pem_private_key` / `secret` → note for the matching service, reuse when that service surfaces. Log to `route_<ip>.txt`.
- `ENDPOINT_REF: <path>: <ref>` — new attack surface → `echo '<ref>' >> unauth_paths_<host>.txt` (re-fire drains at the Step 7 boundary). A `${...}` / `:param` stub is a 7.2 positional-fuzz seed, not a literal probe.
- `ARCHIVE_NESTED: <path>` — the retrieved file is itself an archive → 7.3 loot: extract to a sandbox dir, then re-run the inspector over the extracted tree.
- `MANUAL_REVIEW: <path>` — file read OK; eyeball the local copy at `inspect_<ip>_<port>/…` for what the regexes do not catch (stack traces, framework hints, usernames, source disclosure in `.bak` / `.old` / `.orig` / `~`).
- `FLAG: <path>: <value>` — CTF flag.
- `READ_FAIL: <path>: <reason>` — retrieval or read failed; NOT a no-match. Re-fetch manually if the hit looked live.
- `SCAN COMPLETE: …` — positive completion; a clean no-finding run is explicit, never a silent return.

##### (e) 403 handling — surface for later credential re-use:

`out=$(awk '/^403[[:space:]]/ {print $NF}' feroxbuster_<ip>_<port>.txt); if [ -n "$out" ]; then echo "$out" | while read u; do path=$(echo "$u" | sed -E "s|^https?://<host>(:<port>)?||"); echo "RESTRICTED: $path"; done; else echo "NO_403_HITS"; fi`

Route per marker:

- `RESTRICTED: <path>` — 403 path exists but forbidden:
  - Log for audit trail: `echo 'RESTRICTED: <path>' >> route_<ip>.txt`
  - When creds recovered downstream, re-attempt via authed request
- `NO_403_HITS` — feroxbuster found no 403s on this target.

##### (f) `.git` metadata — surface for git-dumper (out of Step 7 scope):

`out=$(grep -E '/\.git/(HEAD|config|index)$' hits_<ip>_<port>.txt); if [ -n "$out" ]; then echo "$out" | while read u; do echo "GIT_LEAK: $u — run 'git-dumper <base_git_url> ./gitdump-<ip>' (out of Step 7)"; done; else echo "NO_GIT_LEAK"; fi`

Route per marker:

- `GIT_LEAK: <url>` — `.git` metadata exposed:
  - Log for audit trail: `echo 'GIT_LEAK: <url>' >> route_<ip>.txt`
  - Run `git-dumper <base_git_url> ./gitdump-<ip>` — recover source tree
  - Grep recovered tree for creds/endpoints/framework hints (out of Step 7 scope)
- `NO_GIT_LEAK` — no `.git` metadata exposed. No action.

Then → 7.2.

### 7.2 API endpoint enumeration

> ⚠️ **Brute has a categorical blind spot: deep, custom, sparsely-routed endpoints.** A path that isn't a literal wordlist entry and whose parents 404 (recursion can't reach it — `--force-recursion` included) is never requested — a property of the technique, not a tuning gap. Recover such paths from what the app discloses (spec/GraphQL `(c)`/`(d)`, client code, observed traffic, source/error leaks, authed view) or via `ffuf` positional fuzz off a known prefix.
> **Tripwire:** first time a known/suspected endpoint won't surface → log `DEFERRED: api-discovery-blindspot: <detail>` in `route_<ip>.txt`, work around it, move on. Second occurrence → build the fix; do not ignore it again.
> Full derivation + deferred-build decision: [[API Endpoint Discovery - Brute-Force Limits]]

#### feroxbuster invocation:

`feroxbuster -u "http://<host>:<port>" -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -d 4 --auto-tune -o feroxbuster_api_<ip>_<port>.txt`

`-d 4` caps recursion depth. Feroxbuster shows all status codes; it suppresses the not-found wall by auto-building a wildcard filter from that response's signature (lines/words/chars) — the `… created new filter` lines are this calibration, not findings. Any response deviating from the signature (a non-404, or a 404 of a different size) is shown.

**Overlays:**
- ⚠️ Rate-limit (real engagement, WAF suspected): append `-t 5 --rate-limit 10` (5 threads, 10 req/sec).
- Same-length noise (server returns 200 for missing paths): feroxbuster's automatic wildcard filter handles most (see body); manual `-C <length>` filters a specific response length.

⚠️ **Stack-conditional doc paths** — only if Step 2 fingerprinted the stack. Probe the matching stack's path(s); any 200 → append the URL to `hits_api_<ip>_<port>.txt` and run (c) against it.

- Java/Spring → `/v2/api-docs`, `/v3/api-docs`
- .NET → `/swagger/v1/swagger.json`

#### Gobuster fallback — if feroxbuster unavailable:

`gobuster dir -u "http://<host>:<port>" -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -o gobuster_api_<ip>_<port>.txt`

Gobuster does NOT recurse. For every 200/301/302 hit on a directory-shape path (`/api`, `/api/v1`, …), manually re-invoke against it:
`gobuster dir -u "http://<host>:<port>/<discovered_dir>/" -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -o gobuster_api_<ip>_<port>_<slug>.txt`

#### Error gate — run before per-hit processing:

Feroxbuster run only — skip if gobuster fallback was used.

Read `errors:<errors>` and the request total from feroxbuster's overall completion line (`<total>/<total> … found:… errors:<errors>`), then:

`awk -v e=<errors> -v t=<total> 'BEGIN{r=e/t*100; printf "%.3f%% errored — %s\n", r, (r>0.5?"RERUN":"PROCEED")}'`

Route on verdict:

- `PROCEED` → continue to per-hit processing.
- `RERUN` → rerun this leg once with `-t 10`, then continue to per-hit processing.

#### Per-hit processing:

##### (a) Extract hit URLs to a working file:

`awk '/^[0-9]{3}[[:space:]]/ {print $NF}' feroxbuster_api_<ip>_<port>.txt | sort -u > hits_api_<ip>_<port>.txt`

##### (b) Add every hit path to `unauth_paths_<host>.txt`:

`sed -E "s|^https?://<host>(:<port>)?||" hits_api_<ip>_<port>.txt >> unauth_paths_<host>.txt && sort -u unauth_paths_<host>.txt -o unauth_paths_<host>.txt`

##### (c) Spec-doc parse — pull the full documented API surface from any OpenAPI/Swagger spec in one hit:

`grep -iE '/(swagger|openapi|api-docs|v[23]/api-docs)' hits_api_<ip>_<port>.txt | sort -u | while read u; do spec=$(curl -s -H 'Accept: application/json' "$u"); if echo "$spec" | jq -e 'has("openapi") or has("swagger")' >/dev/null 2>&1; then echo "SPEC_FOUND: $u"; echo "$spec" | jq -r '((.servers[0].url // "") | sub("^https?://[^/]+";"")) as $s | (if $s != "" then $s else (.basePath // "") end) as $b | .paths | keys[] | $b + .' 2>/dev/null >> unauth_paths_<host>.txt; ver=$(echo "$spec" | jq -r '.info.version // empty' 2>/dev/null); [ -n "$ver" ] && echo "SPEC_VERSION: $u: $ver"; else case "$u" in *.yaml|*.yml) echo "SPEC_YAML_MANUAL: $u";; *) echo "NOT_SPEC: $u";; esac; fi; done`

Route per marker:

- `SPEC_FOUND: <url>` → every documented endpoint (server/basePath-prefixed) appended to `unauth_paths_<host>.txt`; re-fire at the Step 7 boundary dispatches Passive Recon (Step 3) + Auth-form processing (Step 5) over each. Highest yield in 7.2 — one hit, full surface.
- `SPEC_VERSION: <url>: <version>` → apply **Version-discovery route**.
- `SPEC_YAML_MANUAL: <url>` → jq parses JSON only; read the YAML spec by eye and append its `paths:` entries to `unauth_paths_<host>.txt` manually.
- `NOT_SPEC: <url>` → 200 but not a real spec document (usually the Swagger-UI HTML shell, not its backing JSON) → no action; the UI's spec is a separate hit.

##### (d) GraphQL detection → route:

`grep -iE '/(graphql|graphiql|playground)' hits_api_<ip>_<port>.txt | sort -u | while read u; do tn=$(curl -s -H 'Content-Type: application/json' -d '{"query":"{__typename}"}' "$u" | jq -r '.data.__typename // empty' 2>/dev/null); [ -z "$tn" ] && continue; curl -s -H 'Content-Type: application/json' -d '{"query":"{__schema{queryType{name}}}"}' "$u" | jq -e '.data.__schema' >/dev/null 2>&1 && intro=on || intro=off; p=$(echo "$u" | sed -E "s|^https?://<host>(:<port>)?||"); echo "GRAPHQL: $p (introspection=$intro)"; done`

Route per marker:

- `GRAPHQL: <path> (introspection=on)` → schema is fully dumpable → [[GraphQL Attacks]] (introspection dump + query/mutation abuse).
- `GRAPHQL: <path> (introspection=off)` → confirmed GraphQL, introspection disabled → [[GraphQL Attacks]] (field-suggestion / clairvoyance path).

##### (e) Auth-gated endpoint detection → route:

`awk '/^(401|403)[[:space:]]/ {print $NF}' feroxbuster_api_<ip>_<port>.txt | sort -u | while read u; do hint=$(curl -s -D - -o /dev/null "$u" | grep -oiE '(Bearer|JWT|OAuth|API-?Key)' | sort -u | head -1); p=$(echo "$u" | sed -E "s|^https?://<host>(:<port>)?||"); echo "AUTH_GATED_API: $p (auth=${hint:-none})"; done`

Route per marker:

- `AUTH_GATED_API: <path> (auth=Bearer|JWT)` → token-based auth → [[Session Cookie Attacks]] (JWT branch).
- `AUTH_GATED_API: <path> (auth=OAuth|API-Key|none)` → note the path for credential re-use once creds are recovered downstream.

##### (f) JSON API detection → route:

`grep -vE '/(swagger|openapi|api-docs|graphql|graphiql|playground)' hits_api_<ip>_<port>.txt | sort -u | while read u; do meta=$(curl -s -o /dev/null -w '%{http_code} %{content_type}' -H 'Accept: application/json' "$u"); code=${meta%% *}; case "$code" in 2*) ;; *) continue;; esac; echo "$meta" | grep -qi json || continue; p=$(echo "$u" | sed -E "s|^https?://<host>(:<port>)?||"); ids=$(curl -s -H 'Accept: application/json' "$u" | grep -oiE '"[a-z_]*(id|uuid|guid)"[[:space:]]*:[[:space:]]*"?[0-9a-fA-F-]+"?' | head -3 | tr '\n' ' '); echo "JSON_API: $p${ids:+ | ids: $ids}"; done`

Route per marker:

- `JSON_API: <path>` → live JSON endpoint. Fuzz its query/body parameters → [[Injection]]; enumerate accepted methods (`curl -s -i -X OPTIONS "http://<host>:<port><path>" | grep -i '^allow:'`) and exercise any write method returned (POST/PUT/PATCH/DELETE).
- `JSON_API: <path> | ids: ...` → sequential-integer or UUID identifiers in the body → [[IDOR]] (increment integers; enumerate/swap UUIDs), and test path-segment IDs directly: `/…/<n>` → `/…/<n±1>`.

---

### 7.3 Archive / backup / dump discovery

> **STATUS: AUDITED** — `archive_enum.py` first-principles derived; `mypy --strict` clean; 68/68 `test_archive_enum.py`; probe→classify→render mechanism sandbox-validated (magic / SQL-sniff / 403 / soft-404-suppression legs all exercised). Live-validation on a real box pending → promote to CANONICAL after THM `Web Server Attacks - I`.

Surfaces archive / backup / dump **loot** (`backup.zip`, `<host>.tar.gz`, `db.sql`, `www.tar.gz`, …) that recursive wordlist brute (7.1) and API enum (7.2) do not target. Discovery only: confirms file identity (magic bytes / Content-Type) and **lists** — it does NOT download bodies, extract, or inspect contents.

Run **after 7.1** so `--paths` consumes the directories 7.1 discovered.

#### Invocation

⚠️ Script can take a minute to run. 

```
~/scripts/archive_enum.py <host> <port> [--scheme https] [--paths unauth_paths_<host>.txt] [--stack <php|aspnet|java|node>] [| tee archive_enum_<ip>_<port>.txt]
```

- `--paths unauth_paths_<host>.txt` — probe directories are every discovered path's ancestor dirs (`/local/archives/x.sql` → `/`, `/local/`, `/local/archives/`). Omit → webroot `/` only.
- `--scheme https` — TLS services (default `http`).
- `--stack <stack>` — from Step 2 fingerprint; `java` adds `war,jar,ear` to the extension set. Others stacks (`php`/`aspnet`/`node`) not built yet.

⚠️ The boxed preamble echoes the actual run config and the probe-count side effect (`issues up to N HTTP requests`). If N is too loud for the engagement, trim the `_COMMON_STEMS` / `_CORE_EXTS` constants in the script.

#### Route per marker

- `ARCHIVE_FOUND: <url> [<kind>] <size> (basis=…)` — confirmed archive = **loot**.
    - Log: `echo 'ARCHIVE_FOUND: <url>' >> route_<ip>.txt`
    - Retrieve, extract to a sandbox dir, and inspect: `~/scripts/local_file_inspector.py <dir>` → route its `FILE_CRED` / `SECRET` / `ENDPOINT_REF` / `FLAG` markers. The **extractor** (archive→tree unpack) is the one deferred stage — until built, extract by hand; full design: [[Local File & Tree Inspector]].
    - **Loot, not surface:** do NOT add `<url>` to `unauth_paths_<host>.txt` (its re-fire consumers — Step 3 reads, Step 4 input enum, Step 5 auth forms — all no-op on an archive). Paths/endpoints found _inside_ the archive on inspection ARE surface → those go to `unauth_paths_<host>.txt` and re-fire at the next Step boundary.
- `ARCHIVE_RESTRICTED: <url> (HTTP 401/403 …)` — exists but forbidden. Log `RESTRICTED: <url>` to `route_<ip>.txt`; re-attempt with any credentials recovered downstream.
- `ARCHIVE_UNCONFIRMED: <url> (200, …)` — 200 but identity not confirmable (generic `octet-stream`, or no magic / not HTML / not SQL). Eyeball manually: `curl -s -r 0-63 "<url>" | xxd | head`. Real archive → treat as `ARCHIVE_FOUND`; otherwise drop.
- `NO_ARCHIVES_CONFIRMED: <target>` 
- `SCAN COMPLETE: <N> probed, <c> confirmed, <u> unconfirmed, <r> restricted, <s> soft-404 suppressed, <m> not-found` (+ `, <e> errored` when any probe got no response) — positive scan-completion confirmation. A clean no-hit run is explicit, never a silent prompt-return.

## — Boundary — end of Step 7

→ [[#Accumulator re-fire check]]
→ Step 8

---

## Step 8 — Subdomain enumeration

⚠️ Skip Step 8 entirely if target is IP-only (no domain). Set `<domain>` = target's DNS-resolvable domain (e.g. `example.thm`).

### 8.1 crt.sh

Browser: `https://crt.sh` — run six searches (replace TLDs to match target):

- `%.<domain>.co.uk`
- `%.<domain>.com`
- `<domain>.co.uk`
- `<domain>.com`
- `"<domain>.co.uk"`
- `"<domain>.com"`

Route on results:

- Subdomain in CN/SAN not previously known → add to subdomain list for 8.5
- No new subdomains → 8.2

### 8.2 DNSDumpster

Browser: `https://dnsdumpster.com` → input `<domain>`.

Route on results:

- New subdomain not previously known → add to subdomain list for 8.5
- Additional infrastructure host (fqdn + ip, out of foothold scope) → log for lateral movement, 8.3
- No results → 8.3

### 8.3 Gobuster dns

`gobuster dns -d <domain> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -o gobuster_dns_<domain>.txt`

Route on output (`grep '^Found:' gobuster_dns_<domain>.txt`):

- Subdomain in `Found:` line → add to subdomain list for 8.5
- No `Found:` lines → 8.4

### 8.4 Gobuster vhost

`gobuster vhost -u http://<host> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain --domain <domain> -o gobuster_vhost_<host>.txt`

If flooded by same-length responses, append `--exclude-length <n>` where `<n>` = the flood length observed.

Route on output (`grep 'Found:' gobuster_vhost_<host>.txt`):

- Vhost in `Found:` line → add to vhost list for 8.5
- No `Found:` lines → skip 8.5 and continue

### 8.5 Validate and recurse

For each subdomain / vhost collected from 8.1–8.4:

1. If not resolvable, add to `/etc/hosts`:

    `echo "<target_ip> <subdomain>" | sudo tee -a /etc/hosts`

2. Verify HTTP alive:

    `curl -s -o /dev/null -w "%{http_code}\n" http://<subdomain>/`

3. HTTP 200/301/302 → recurse: **run this Checksheet from Step 1 against `<subdomain>`** as `<host>`. Note: `users_<host>.txt`, `creds_<host>.txt`, and `unauth_paths_<host>.txt` are per-host — subdomain recursion uses its own accumulator files.

4. Non-alive → log INAPPLICABLE, next subdomain.

---

## — Boundary — end of Step 8

→ [[#Accumulator re-fire check]]
→ Step 9

---

## Step 9 — Deferred low-EV route sweep

Walks routes deferred by Steps 3-8 sub-blocks that logged DEFERRED entries.

`grep 'DEFERRED' route_<ip>.txt`

For each DEFERRED entry:

- `REFLECTED_CANDIDATE: <location>` → [[XSS]] (Reflected branch)
- `STORED_SURFACE: <location>` → [[XSS]] (Stored branch)
- `STATE_ENDPOINT: <location>` → [[Race Conditions]]

XSS foothold typically via session hijack — captured cookie feeds back to [[Session Cookie Attacks]] or direct impersonation. Race Conditions typically eval/proof only — log finding, continue.

No DEFERRED entries → Boundary check.

---

## — Boundary — end of Step 9

End of unauth walk. Fires once, in sequence:

1. → [[#Accumulator re-fire check]]
2. Session-establishment opportunity present (`creds_<host>.txt` non-empty OR register form discovered anywhere during Steps 1-9) → [[Authenticated Walk]]
3. No session-establishment opportunity OR Auth Walk complete → Exhaustion

---

## Exhaustion

Steps 1-9 walked without foothold → return to [[MASTER WORKFLOW/Step 6. Vulnerability Analysis]] Pass 3, next priority service.

---

## Real-engagement OSINT (footer reference — not a walking step)

Off-target OSINT sources — near-zero P(yield) on OSCP+/CTF/lab boxes (synthetic targets have no public infrastructure). Walk only when engagement scope explicitly includes real production infrastructure:

- Google dorking (`site:`, `inurl:`, `filetype:`, `intitle:`)
- Wayback machine — historical paths still live
- GitHub search — public repos, leaked credentials
- S3 buckets — common suffix probing (`.s3.amazonaws.com`)
- Shodan — additional ports, flagged CVEs

Any hit here: extract path, `echo '<path>' >> unauth_paths_<host>.txt` -> [[#Accumulator re-fire check]]
