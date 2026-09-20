> **STATUS: FORMAT-ONLY** — three-set structural restructure applied 2026-09-19; Step 6 (Active content discovery) fully first-principles + primary-source audited 2026-09-19; remaining sub-blocks structurally reshaped from pre-audit state, per-sub-block first-principles derivation INCOMPLETE. Live-validation pending. Not CANONICAL.

Routes HTTP/HTTPS service to web attack technique walkthroughs. Pure router — attack content lives in per-technique files.

Ordering: P(yield)/time-cost, OSCP+-tuned. Surface enumeration first (Step 1); root-only fingerprinting (Step 2); basic per-path recon (Step 3); auth-form processing (Step 4); well-known files (Step 5); active scanning (Step 6); subdomain enum only if domain-based (Step 7); deferred low-EV last (Step 8). Off-target OSINT footer-only — near-zero P(yield) on lab boxes.

---

## Setup

Per HTTP/HTTPS service on target (multiple ports = multiple walks).

`<host>` = target hostname or IP for the HTTP service. `<port>` = the HTTP/HTTPS port. `<ip>` = target IP (matches existing MW `route_<ip>.txt`). `<domain>` = target's DNS-resolvable domain (Step 7 only; skip Step 7 if target is IP-only).

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
3. Either token new → run [[MASTER WORKFLOW/Step 6. Vulnerability Analysis#Pass 1 re-fire]].

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

**Path scope filters** (applied by consuming sub-blocks):

- **HTML-eligible**: does not match extension heuristic `\.(png|jpg|jpeg|gif|css|js|woff2?|ico|svg|mp4|webm|pdf|zip|tar|gz|json)$`. Filter: `grep -vE '\.(png|jpg|jpeg|gif|css|js|woff2?|ico|svg|mp4|webm|pdf|zip|tar|gz|json)$'`. Sub-blocks that grep HTML body content apply this to their input.
- **Auth-shape**: matches `(login|signin|admin|auth|register|signup|forgot|reset|recover|portal)`. Filter: `grep -E '(login|signin|admin|auth|register|signup|forgot|reset|recover|portal)'`. Auth-form processing (Step 4) applies this filter.

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

1. Apply Basic Recon set actions (Step 3 — each with its scope filter; skip actions whose filter excludes `<p>`).
2. If `<p>` matches auth-shape filter → additionally dispatch Auth-form Per-path processing:
   - Matches `(login|signin|portal)` → 4.1 Per-path processing
   - Matches `(register|signup)` → 4.2 Per-path processing
   - Matches `(forgot|reset|recover)` → 4.3 Per-path processing

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

Seed walked file — marks all Step-1-discovered paths as already-covered by Basic Recon (Step 3) initial iteration; end-of-Step-4-onward re-fires drain only paths discovered post-Step-1:

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
- Hash matches non-framework entry (e.g. `Zero byte favicon`, generic server default icon) → 2.3
- Hash has no DB match → 2.3
- `FAVICON_ABSENT` → 2.3

### 2.3 Wappalyzer extension

In **browser** (Wappalyzer extension installed), navigate to `http://<host>:<port>/`. Read extension panel.

Route on panel content:

- Server-side product identified with version (web server, language runtime, backend framework, CMS) → apply **Version-discovery route** (above)
- Client-side library identified with version (jQuery, Bootstrap, React, Vue, Angular, etc.) → log `CLIENT_LIB: <name> <version>` under `WEB_ROUTES_TRIED (<host>:<port>)` in `route_<ip>.txt`
- Framework identified without version → note framework hint, 2.4
- Nothing identified → 2.4

### 2.4 HTML source version disclosure

Two sweeps: meta tags and visible text. Both feed **Version-discovery route** (above).

#### Meta tags:

`curl -s http://<host>:<port>/ | grep -oiE '<meta[^>]*(generator|framework)[^>]*>' || echo "NO_META_GEN"`

Route on output:

- Content attribute contains framework + version → apply **Version-discovery route**
- Content attribute contains framework only → note framework hint
- `NO_META_GEN` → visible-text sweep

#### Visible text:

`{ curl -s http://<host>:<port>/ | perl -0777 -pe 's#<(style|script)\b[^>]*>.*?</\1>##gs; s#<[^>]*># #g' | grep -oiE '[a-zA-Z][a-zA-Z0-9._-]* v?[0-9]+(\.[0-9]+)+' || echo "NO_VISIBLE_VERSION"; } | sort -u`

Route on output:

- Match contains framework + version (e.g. `RecruitX v2.4`, `WordPress 5.4`) → apply **Version-discovery route**
- `NO_VISIBLE_VERSION` → 2.5

### 2.5 Cookies (unauth, root)

`curl -s -D - -o /dev/null "http://<host>:<port>/" | grep -i '^Set-Cookie:' || echo "NO_COOKIES"`

For each `Set-Cookie` value, assess format.

Route on assessment:

- Value is plain (e.g. `admin=false`, `user_id=1`), base64 (e.g. `eyJ...`, decodes with `base64 -d`), or hex hash (32/40/64 chars) → [[Session Cookie Attacks]]
- Value is opaque (long random-looking, no discernible format) → log informational
- `NO_COOKIES` → continue to Step 3

---

## Step 3 — Basic Reconnaissance

Per-path passive/basic checks. Initial run: apply each sub-block's action to all paths in `unauth_paths_<host>.txt` (each sub-block applies its own scope filter). Subsequent invocations via `unauth_paths_<host>.txt` sub-routine in [[#Accumulator re-fire check]] dispatched at end-of-Step boundaries — walked-tracked.

Any sub-block that discovers a new path appends to `unauth_paths_<host>.txt`; re-fire drains at next boundary.

### 3.1 HTML comments sweep

Scope: HTML-eligible paths in `unauth_paths_<host>.txt`.

`grep -vE '\.(png|jpg|jpeg|gif|css|js|woff2?|ico|svg|mp4|webm|pdf|zip|tar|gz|json)$' unauth_paths_<host>.txt | while read p; do echo "=== $p ==="; out=$(curl -s "http://<host>:<port>${p}" | grep -Pzo '(?s)<!--.*?-->' | tr -d '\0'); [ -n "$out" ] && printf '%s\n' "$out" || echo "NO_COMMENTS"; done`

Route per path on inspection (per finding, may fire multiple):

- Framework name + version → apply **Version-discovery route**
- Framework name only, no version → note framework hint
- Username(s) → `echo '<username>' >> users_<host>.txt`
- Credentials (user:pass, key=value) → `echo '<user>:<pass>' >> creds_<host>.txt`
- Endpoint / path → `echo '<endpoint>' >> unauth_paths_<host>.txt` (re-fire drains at next step boundary)
- Nothing exploitable → no action

### 3.2 Upload surface (unauth)

Scope: HTML-eligible paths in `unauth_paths_<host>.txt`.

`grep -vE '\.(png|jpg|jpeg|gif|css|js|woff2?|ico|svg|mp4|webm|pdf|zip|tar|gz|json)$' unauth_paths_<host>.txt | while read p; do echo "=== $p ==="; curl -s "http://<host>:<port>${p}" | grep -oiE '<input[^>]*type=["'"'"']?file' || echo "NO_FILE_INPUT"; done`

Route per path on output + browse observation:

- File input present (grep hit OR observed on discoverable page) → [[File Upload]] against `<p>`
- `NO_FILE_INPUT` → no action

### 3.3 URL parameters

Scope: HTML-eligible paths in `unauth_paths_<host>.txt`.

> ⚠️ **3.3 command revision history: 4 iterations Sep 2026** (original per-path sort → global sort with path-self extraction → sed-prefixed tuple format → attackable-URL format). If you find yourself modifying this command a FIFTH time, STOP — it has exceeded the "obvious on read" threshold for inline. Escalate to `~/scripts/url_params_enum.sh` with regression test suite (`.tests.sh`) per V_S script convention. Do not iterate inline further.

`grep -vE '\.(png|jpg|jpeg|gif|css|js|woff2?|ico|svg|mp4|webm|pdf|zip|tar|gz|json)$' unauth_paths_<host>.txt | while read p; do echo "$p" | grep -E '\?'; curl -s "http://<host>:<port>${p}" | grep -oiE '(href|action)=["'"'"'][^"'"'"']*\?[^"'"'"']*' | sed -E 's/^(href|action)=["'"'"']//'; done | sort -u`

Also inspect Burp Proxy history for XHR/fetch requests with parameters.

Route per parameter observed (classify by name / value shape):

- Parameter name in {`file`, `page`, `include`, `template`, `lang`, `doc`} → [[Local File Inclusion]], then [[Remote File Inclusion]], then [[Path Traversal]]
- Parameter name in {`url`, `server`, `redirect`, `fetch`, `dst`, `endpoint`, `src`} → [[SSRF]]
- Parameter name in {`id`, `uid`, `pid`} OR value numeric-sequential / base64 / predictable-hash → [[IDOR]]
- Any other user-controlled parameter → [[Injection]] (top-level stub routes into sub-technique per input context)
- No parameters observed for a path → no action

### 3.4 Low-EV input surfaces

Scope: HTML-eligible paths in `unauth_paths_<host>.txt`.

Browse each in scope; note mutable-input candidates. For each, log to `WEB_ROUTES_TRIED` as DEFERRED for Step 8 sweep — do NOT walk technique now:

```bash
printf '[step8-sweep] DEFERRED: <marker>: <location>\n' >> route_<ip>.txt
```

`<marker>` values (Step 8 greps these literally):

- `REFLECTED_CANDIDATE` — search boxes, error banners, filter fields, page params that echo back
- `STORED_SURFACE` — comment forms, review forms, profile bio fields, ticket bodies, chat messages
- `STATE_ENDPOINT` — buttons/actions that mutate state (register, redeem, transfer, one-time claim)

Nothing observed for a given path → no action.

### 3.5 Visible admin/dashboard links (unauth)

Scope: HTML-eligible paths in `unauth_paths_<host>.txt`.

`grep -vE '\.(png|jpg|jpeg|gif|css|js|woff2?|ico|svg|mp4|webm|pdf|zip|tar|gz|json)$' unauth_paths_<host>.txt | while read p; do echo "=== $p ==="; curl -s "http://<host>:<port>${p}" | grep -oiE 'href=["'"'"'][^"'"'"']*(admin|dashboard|settings|manage|console)[^"'"'"']*' | sort -u || echo "NO_ADMIN_LINK"; done`

For each admin-shape href hit, extract the path portion. Test unauth access:

`curl -s -o /dev/null -w "%{http_code}\n" http://<host>:<port>/<extracted_path>`

Route on status code:

- 200 / 302 (no auth challenge) → `echo '/<extracted_path>' >> unauth_paths_<host>.txt` (re-fire drains at next Step boundary — auth-shape filter dispatches Auth-form Per-path processing if matches).
- 401 / 403 / redirect to login → note the admin path for later credential re-use; if creds recovered anywhere later → try against this path.
- `NO_ADMIN_LINK` for a path → no action.

---

### 3.6 Flag hunt (CTF-only overlay)

⚠️ **CTF/lab only** — skip on real engagements. 

Scope: HTML-eligible paths in `unauth_paths_<host>.txt`.

`grep -vE '\.(png|jpg|jpeg|gif|css|js|woff2?|ico|svg|mp4|webm|pdf|zip|tar|gz|json)$' unauth_paths_<host>.txt | while read p; do echo "=== $p ==="; out=$(curl -s "http://<host>:<port>${p}" | grep -oE '(THM|HTB|flag|FLAG|CTF)\{[^}]*\}'); [ -n "$out" ] && printf '%s\n' "$out" || echo "NO_FLAG"; done`

Route per path on output:

- Flag hit → capture value; enter into room's answer field if THM/HTB task; log to `route_<ip>.txt` as `FLAG_FOUND: <path>: <value>`
- `NO_FLAG` → no action for this path

## Step 4 — Auth-form processing

### 4.1 Login form

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

### 4.2 Register form

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

### 4.3 Forgot-password form

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
## — Boundary — end of Step 4

→ [[#Accumulator re-fire check]]
→ Step 5

---

## Step 5 — Well-known files

### 5.1 robots.txt

`curl -s http://<host>:<port>/robots.txt || echo "ROBOTS_ABSENT"`

Route on output:

- Entries under `Disallow:` → for each, `echo '<path>' >> unauth_paths_<host>.txt` (re-fire drains at Step boundary)
- `ROBOTS_ABSENT` → 5.2

### 5.2 sitemap.xml

`{ curl -sfL "http://<host>:<port>/sitemap.xml" || curl -sfL "http://<host>:<port>/sitemap_index.xml"; } || echo "SITEMAP_ABSENT"`

Route on output:

- `<loc>` entries present → for each not already in `unauth_paths_<host>.txt`, extract path (strip scheme+host) → `echo '<path>' >> unauth_paths_<host>.txt`
- `SITEMAP_ABSENT` → continue

---

## — Boundary — end of Step 5

→ [[#Accumulator re-fire check]]
→ Step 6

---

## Step 6 — Active content discovery

> **STATUS (this step): AUDITED** — first-principles + primary-source derivation (OWASP WSTG-INFO-04/06, PortSwigger Content Discovery, HackTricks Directory Brute Force, PayloadsAllTheThings, feroxbuster/gobuster/SecLists docs); sandbox-verified inspection mechanics (autoindex detection, credential grep, endpoint grep, href extraction, output-format parsing); tool-flag correctness verification-pending until first live run; live-validation on ≥1 real target pending. Not yet CANONICAL.

Actively enumerate paths the app didn't advertise. Two mechanisms: recursive wordlist enumeration (6.1) and API endpoint enumeration (6.2). All hits append to `unauth_paths_<host>.txt` — re-fire at Step 6 boundary dispatches Basic Recon (Step 3) and Auth-form Per-path processing (Step 4).

### 6.1 Recursive wordlist enumeration

**Tool: feroxbuster.** Native recursion (default-enabled). Kali 2020.4+ default install. Fallback below.

Select extension set per server-side stack identified in Step 2 (Version-discovery route). If stack unknown, use wide-net.

#### **Choose one — feroxbuster invocation:**

- **PHP stack**:
  `feroxbuster -u "http://<host>:<port>" -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,phtml,php3,php4,php5,inc,html,txt,js,json,bak,log,conf,env,old,orig -d 4 -o feroxbuster_<ip>_<port>.txt`

- **ASP.NET stack**:
  `feroxbuster -u "http://<host>:<port>" -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x aspx,asp,ashx,asmx,config,html,txt,js,json,bak,log,old -d 4 -o feroxbuster_<ip>_<port>.txt`

- **Java/JSP stack**:
  `feroxbuster -u "http://<host>:<port>" -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x jsp,jspx,do,action,xml,html,txt,js,json,bak,log,conf,old -d 4 -o feroxbuster_<ip>_<port>.txt`

- **Node.js / Python stack**:
  `feroxbuster -u "http://<host>:<port>" -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x js,json,txt,bak,log,env,conf,old,py -d 4 -o feroxbuster_<ip>_<port>.txt`

- **Stack unknown** (wide-net fallback):
  `feroxbuster -u "http://<host>:<port>" -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,aspx,jsp,html,txt,js,json,bak,log,conf,inc,env,old,orig,py -d 4 -o feroxbuster_<ip>_<port>.txt`

`-d 4` caps recursion depth. Feroxbuster default surfaces 200/204/301/302/307/308/401/403/405 and excludes 404.

**Overlays:**
- ⚠️ Rate-limit (real engagement, WAF suspected): append `-t 5 --rate-limit 10` (5 threads, 10 req/sec) ⚠️.
- Same-length noise (server returns 200 for missing paths): feroxbuster's `--auto-tune` / `--auto-bail` handles most; manual `-C <length>` filters a specific length.

#### **Gobuster fallback** — if feroxbuster unavailable:

`gobuster dir -u "http://<host>:<port>" -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x <extensions_per_stack> -o gobuster_<ip>_<port>.txt`

⚠️ Gobuster does NOT recurse. `-r` follows redirects only. For every 200/301/302 hit on a directory-shape path, manually re-invoke:
`gobuster dir -u "http://<host>:<port>/<discovered_dir>/" -w <wordlist> -x <extensions> -o gobuster_<ip>_<port>_<slug>.txt`

#### **Per-hit processing** — five small single-purpose commands:

##### (a) Extract hit URLs to a working file:

`awk '/^[0-9]{3}[[:space:]]/ {print $NF}' feroxbuster_<ip>_<port>.txt | sort -u > hits_<ip>_<port>.txt`

##### (b) Add every hit path to `unauth_paths_<host>.txt`:

`sed -E "s|^https?://<host>(:<port>)?||" hits_<ip>_<port>.txt >> unauth_paths_<host>.txt && sort -u unauth_paths_<host>.txt -o unauth_paths_<host>.txt`

##### (c) Autoindex detection loop — extract directory listings:

`grep 'directory listing' feroxbuster_<ip>_<port>.txt | sed -E 's|^.*directory listing: |AUTOINDEX: |'`

For each `AUTOINDEX: <url>` line, record to `route_<ip>.txt`.
##### (d) High-value config-shape file inspection — `.env`, `.htaccess`, `web.config`, `phpinfo`, `.log`:

`grep -E '(\.env|\.htaccess|web\.config|phpinfo|\.log)$|/\.env$|/phpinfo\.php$' hits_<ip>_<port>.txt | while read u; do echo "=== $u ==="; out=$(curl -s -L "$u" | grep -oiE '(password|passwd|secret|api[_-]?key|token|bearer)\s*[:=]\s*["'"'"']?[^"'"'"'[:space:]]+'); if [ -n "$out" ]; then echo "$out" | while read c; do echo "FILE_CRED: $u: $c"; done; else echo "NO_CRED_PATTERN — high-value file, MANUAL REVIEW ADVISED (curl -s -L \"$u\")"; fi; done`

Route per marker:

- `FILE_CRED: <url>: <match>` — cred pattern matched:
  - Verify manually (may be placeholder like `changeme`, `<PASSWORD>`, template-shape value)
  - Real credential → `echo '<user>:<pass>' >> creds_<host>.txt` per accumulator convention
  - Log for audit trail: `echo 'FILE_CRED: <url>: <match>' >> route_<ip>.txt`
- `NO_CRED_PATTERN` — grep found no cred pattern, but file is high-value:
  - Manually review with the ready-to-paste `curl` command shown in the marker output
  - Look for stack traces, paths, framework hints, usernames — none of which the cred grep catches
  - If review yields credentials → `echo '<user>:<pass>' >> creds_<host>.txt`
  - If review yields nothing exploitable → no action; file was inspected, moving on

##### (e) High-value source-shape file inspection — `.js`, `.json`, `.bak`, `.old`, `.orig`, `.swp`, `~`:

`grep -E '\.(js|json|bak|old|orig|swp)$|~$' hits_<ip>_<port>.txt | while read u; do echo "=== $u ==="; body=$(curl -s -L "$u"); creds=$(echo "$body" | grep -oiE '(password|passwd|secret|api[_-]?key|token|bearer)\s*[:=]\s*["'"'"'][^"'"'"']+'); eps=$(echo "$body" | grep -oiE '["'"'"']/(api|v[0-9]|admin|user|auth|login|internal)[^"'"'"']*["'"'"']' | tr -d '"'"'"); if [ -n "$creds" ]; then echo "$creds" | while read c; do echo "SRC_CRED: $u: $c"; done; fi; if [ -n "$eps" ]; then echo "$eps" | while read ep; do echo "ENDPOINT_REF: $u: $ep"; done; fi; if [ -z "$creds" ] && [ -z "$eps" ]; then echo "NO_PATTERN_MATCH — source-shape file, MANUAL REVIEW ADVISED for backup/source-disclosure content (curl -s -L \"$u\" | less)"; fi; done`

Route per marker:

- `SRC_CRED: <url>: <match>` — cred pattern matched:
  - Verify manually — may be dev placeholder rather than real credential
  - Real credential → `echo '<user>:<pass>' >> creds_<host>.txt`
  - Log for audit trail: `echo 'SRC_CRED: <url>: <match>' >> route_<ip>.txt`
- `ENDPOINT_REF: <url>: <ref>` — endpoint reference extracted from source file:
  - Add to accumulator: `echo '<ref>' >> unauth_paths_<host>.txt` (re-fire drains at Step 6 boundary)
- `NO_PATTERN_MATCH` — neither cred nor endpoint pattern matched, but file may still hold value:
  - For `.bak` / `.old` / `.orig` / `~` / `.swp`: high-value source disclosure — manually review
  - For `.js` / `.json`: often minified library or benign config — skim, likely skip
  - Manual review command shown in the marker output

##### (f) 403 handling — surface for later credential re-use:

`out=$(awk '/^403[[:space:]]/ {print $NF}' feroxbuster_<ip>_<port>.txt); if [ -n "$out" ]; then echo "$out" | while read u; do path=$(echo "$u" | sed -E "s|^https?://<host>(:<port>)?||"); echo "RESTRICTED: $path"; done; else echo "NO_403_HITS"; fi`

Route per marker:

- `RESTRICTED: <path>` — 403 path exists but forbidden:
  - Log for audit trail: `echo 'RESTRICTED: <path>' >> route_<ip>.txt`
  - When creds recovered downstream, re-attempt via authed request
- `NO_403_HITS` — feroxbuster found no 403s on this target.

##### (g) `.git` metadata — surface for git-dumper (out of Step 6 scope):

`out=$(grep -E '/\.git/(HEAD|config|index)$' hits_<ip>_<port>.txt); if [ -n "$out" ]; then echo "$out" | while read u; do echo "GIT_LEAK: $u — run 'git-dumper <base_git_url> ./gitdump-<ip>' (out of Step 6)"; done; else echo "NO_GIT_LEAK"; fi`

Route per marker:

- `GIT_LEAK: <url>` — `.git` metadata exposed:
  - Log for audit trail: `echo 'GIT_LEAK: <url>' >> route_<ip>.txt`
  - Run `git-dumper <base_git_url> ./gitdump-<ip>` — recover source tree
  - Grep recovered tree for creds/endpoints/framework hints (out of Step 6 scope)
- `NO_GIT_LEAK` — no `.git` metadata exposed. No action.

Then → 6.2.

### 6.2 API endpoint enumeration

Convention path list including documentation endpoints (high-yield):

`for p in /api /api/users /api/users/admin /api/messages /api/messages/admin /api/chats /api/admin /api/v1 /api/v2 /api/v3 /graphql /graphql/console /graphiql /playground /rest /rest/v1 /rest/v2 /swagger /swagger-ui /swagger-ui/ /swagger.json /swagger.yaml /openapi.json /openapi.yaml /api-docs /docs; do status=$(curl -s -o /dev/null -w "%{http_code}" "http://<host>:<port>${p}"); [ "$status" = "404" ] && continue; ctype=$(curl -sI "http://<host>:<port>${p}" | grep -i '^content-type:' | tr -d '\r'); echo "=== ${p} (status=${status}, ${ctype}) ==="; curl -s "http://<host>:<port>${p}" | head -c 500; echo; echo "$p" >> unauth_paths_<host>.txt; done`

Per-hit follow-up — three small commands:

**(a) JSON API detection:**

`for p in /api /api/users /api/users/admin /api/messages /api/messages/admin /api/chats /api/admin /api/v1 /api/v2 /api/v3 /graphql /rest /rest/v1 /rest/v2; do curl -sI "http://<host>:<port>${p}" | grep -qi '^content-type:.*application/json' && echo "JSON_API: $p" >> route_<ip>.txt; done`

**(b) Swagger / OpenAPI extraction — pulls full API surface in one hit:**

`for p in /swagger.json /swagger.yaml /openapi.json /openapi.yaml /api-docs; do body=$(curl -s "http://<host>:<port>${p}"); echo "$body" | head -c 100 | grep -qE '"(swagger|openapi)"' && { echo "SWAGGER_EXTRACT: $p" >> route_<ip>.txt; echo "$body" | grep -oE '"/[^"]+"' | tr -d '"' | sort -u >> unauth_paths_<host>.txt; }; done`

**(c) Auth-gated API detection:**

`for p in /api /api/v1 /api/v2 /graphql; do status=$(curl -s -o /dev/null -w "%{http_code}" "http://<host>:<port>${p}"); case "$status" in 401|403) auth_hint=$(curl -s "http://<host>:<port>${p}" | grep -oiE '(Bearer|JWT|OAuth|API-Key)' | sort -u | head -1); echo "AUTH_GATED_API: $p (status=$status, auth=$auth_hint)" >> route_<ip>.txt ;; esac; done`

Route per marker:

- `JSON_API: <path>` → real API surface. Path added to `unauth_paths_<host>.txt`; Basic Recon 3.3 URL parameters finds query params via re-fire. JSON body may reveal numeric/UUID IDs → route to [[IDOR]] via re-fire.
- `SWAGGER_EXTRACT: <path>` → all documented endpoints extracted and appended to `unauth_paths_<host>.txt`. Huge yield for one hit.
- `AUTH_GATED_API: <path> (auth=Bearer|JWT|OAuth|API-Key)` → JWT/Bearer visible → route to [[Session Cookie Attacks]] (JWT tampering branch). Otherwise: note for later credential re-use.

---

## — Boundary — end of Step 6

→ [[#Accumulator re-fire check]]
→ Step 7

---

## Step 7 — Subdomain enumeration

⚠️ Skip Step 7 entirely if target is IP-only (no domain). Set `<domain>` = target's DNS-resolvable domain (e.g. `example.thm`).

### 7.1 crt.sh

Browser: `https://crt.sh` — run six searches (replace TLDs to match target):

- `%.<domain>.co.uk`
- `%.<domain>.com`
- `<domain>.co.uk`
- `<domain>.com`
- `"<domain>.co.uk"`
- `"<domain>.com"`

Route on results:

- Subdomain in CN/SAN not previously known → add to subdomain list for 7.5
- No new subdomains → 7.2

### 7.2 DNSDumpster

Browser: `https://dnsdumpster.com` → input `<domain>`.

Route on results:

- New subdomain not previously known → add to subdomain list for 7.5
- Additional infrastructure host (fqdn + ip, out of foothold scope) → log for lateral movement, 7.3
- No results → 7.3

### 7.3 Gobuster dns

`gobuster dns -d <domain> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -o gobuster_dns_<domain>.txt`

Route on output (`grep '^Found:' gobuster_dns_<domain>.txt`):

- Subdomain in `Found:` line → add to subdomain list for 7.5
- No `Found:` lines → 7.4

### 7.4 Gobuster vhost

`gobuster vhost -u http://<host> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain --domain <domain> -o gobuster_vhost_<host>.txt`

If flooded by same-length responses, append `--exclude-length <n>` where `<n>` = the flood length observed.

Route on output (`grep 'Found:' gobuster_vhost_<host>.txt`):

- Vhost in `Found:` line → add to vhost list for 7.5
- No `Found:` lines → skip 7.5 and continue

### 7.5 Validate and recurse

For each subdomain / vhost collected from 7.1–7.4:

1. If not resolvable, add to `/etc/hosts`:

    `echo "<target_ip> <subdomain>" | sudo tee -a /etc/hosts`

2. Verify HTTP alive:

    `curl -s -o /dev/null -w "%{http_code}\n" http://<subdomain>/`

3. HTTP 200/301/302 → recurse: **run this Checksheet from Step 1 against `<subdomain>`** as `<host>`. Note: `users_<host>.txt`, `creds_<host>.txt`, and `unauth_paths_<host>.txt` are per-host — subdomain recursion uses its own accumulator files.

4. Non-alive → log INAPPLICABLE, next subdomain.

---

## — Boundary — end of Step 7

→ [[#Accumulator re-fire check]]
→ Step 8

---

## Step 8 — Deferred low-EV route sweep

Walks routes deferred by Steps 3-7 sub-blocks that logged DEFERRED entries.

`grep 'DEFERRED' route_<ip>.txt`

For each DEFERRED entry:

- `REFLECTED_CANDIDATE: <location>` → [[XSS]] (Reflected branch)
- `STORED_SURFACE: <location>` → [[XSS]] (Stored branch)
- `STATE_ENDPOINT: <location>` → [[Race Conditions]]

XSS foothold typically via session hijack — captured cookie feeds back to [[Session Cookie Attacks]] or direct impersonation. Race Conditions typically eval/proof only — log finding, continue.

No DEFERRED entries → Boundary check.

---

## — Boundary — end of Step 8

End of unauth walk. Fires once, in sequence:

1. → [[#Accumulator re-fire check]]
2. Session-establishment opportunity present (`creds_<host>.txt` non-empty OR register form discovered anywhere during Steps 1-8) → [[Authenticated Walk]]
3. No session-establishment opportunity OR Auth Walk complete → Exhaustion

---

## Exhaustion

Steps 1-8 walked without foothold → return to [[MASTER WORKFLOW/Step 6. Vulnerability Analysis]] Pass 3, next priority service.

---

## Real-engagement OSINT (footer reference — not a walking step)

Off-target OSINT sources — near-zero P(yield) on OSCP+/CTF/lab boxes (synthetic targets have no public infrastructure). Walk only when engagement scope explicitly includes real production infrastructure:

- Google dorking (`site:`, `inurl:`, `filetype:`, `intitle:`)
- Wayback machine — historical paths still live
- GitHub search — public repos, leaked credentials
- S3 buckets — common suffix probing (`.s3.amazonaws.com`)
- Shodan — additional ports, flagged CVEs

Any hit here: extract path, `echo '<path>' >> unauth_paths_<host>.txt` -> [[#Accumulator re-fire check]]
