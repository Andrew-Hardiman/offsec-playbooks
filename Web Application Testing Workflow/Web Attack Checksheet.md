
> **STATUS: FORMAT-ONLY** — three-set structural restructure applied 2026-09-19; Step 7 (Active content discovery) fully first-principles + primary-source audited (7.1 2026-09-19 / reworked 2026-10-14, 7.2 re-derived 2026-10-12); remaining sub-blocks structurally reshaped from pre-audit state, per-sub-block first-principles derivation INCOMPLETE. Live-validation pending. Not CANONICAL.

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

`jq -r --arg h "$host" --arg p "$port" '.log.entries[] | select(.request.url | test("^https?://" + $h + "(:" + $p + ")?/")) | select(.response.content.mimeType // "" | startswith("text/html")) | .request.url' unauth_crawl_$host.har | sed -E "s|^https?://$host(:$port)?||" | grep -E '^/([^/]|$)' | sort -u | while read fetch_p; do curl -s --max-time 5 "http://$host:$port${fetch_p}" | grep -oiE 'href=["'"'"'][^"'"'"']+'; done | sort -u > unauth_hrefs_$host.txt`

Combine target-host URLs from HAR with extracted hrefs, filtering to target-host paths only (rejects third-party CDN URLs, protocol-relative URLs, mailto/tel/javascript/fragment hrefs):

`{ jq -r --arg h "$host" --arg p "$port" '.log.entries[] | select(.request.url | test("^https?://" + $h + "(:" + $p + ")?/")) | .request.url' unauth_crawl_$host.har 2>/dev/null; sed -E 's|^href=["'"'"']||' unauth_hrefs_$host.txt; } | sed -E "s|^https?://$host(:$port)?||" | grep -E '^/([^/]|$)' | sort -u > unauth_paths_$host.txt`

Route:

- `unauth_paths_<host>.txt` non-empty → seed walked file (below), continue to Step 2.
- `unauth_paths_<host>.txt` empty → seed with root only: `echo '/' > unauth_paths_<host>.txt`. Seed walked file (below), continue to Step 2.

Seed walked file — marks all Step-1-discovered paths as already-covered by Passive Recon (Step 3) initial iteration; end-of-Step-5-onward re-fires drain only paths discovered post-Step-1:

`cp unauth_paths_$host.txt unauth_paths_$host.txt.walked`

---

## Step 2 — Root-only fingerprinting

Homepage-only sub-blocks; scope is `/` (or `/favicon.ico` for 2.2). These signals are server-config or template-level and near-always identical across paths on a single-app target; per-path iteration is not required.

### 2.1 Server identity — headers and error page

Run both, before routing. The two emission points **can** disagree; a disagreement is a second component, not a duplicate.

##### Headers (root):

`curl -s -D - -o /dev/null "http://$host:$port/" | grep -iE '^(Server|X-Powered-By):' || echo "NO_VERSION_HEADERS"`

##### Default error page (non-routed path):

`curl -s --max-time 5 "http://$host:$port/zzrandomzz404" | grep -oiE '(apache tomcat|apache-coyote|microsoft-iis|openresty|nginx|apache|lighttpd|jetty|litespeed|caddy|gunicorn|werkzeug)([/ ]v?[0-9]+(\.[0-9]+)*)?' | sort -u | grep . || echo "NO_ERRORPAGE_BANNER"`

Route on output (each line routes independently; a product already seen in the other leg needs no second lookup):

- `Server: <product>/<version>` or `X-Powered-By: <product>/<version>` → apply **Version-discovery route** (above)
- `Server: <product>` or `X-Powered-By: <product>`, no version number → [[Web Stack Version Discovery]]
- `<product>/<version>` from the error page → apply **Version-discovery route** (above)
- `<product>` from the error page, no version number → [[Web Stack Version Discovery]]
- `NO_VERSION_HEADERS` AND `NO_ERRORPAGE_BANNER` → 2.2

### 2.2 Favicon fingerprint

`curl -sfL http://$host:$port/favicon.ico | md5sum || echo "FAVICON_ABSENT"`

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

`curl -s http://$host:$port/ | grep -oiE '<meta[^>]*(generator|framework)[^>]*>' || echo "NO_META_GEN"`

Route on output:

- Content attribute contains framework + version → apply **Version-discovery route**
- Content attribute contains framework only → [[Web Stack Version Discovery]]
- `NO_META_GEN` → visible-text sweep

#### Visible text:

`{ curl -s http://$host:$port/ | perl -0777 -pe 's#<(style|script)\b[^>]*>.*?</\1>##gs; s#<[^>]*># #g' | grep -oiE '[a-zA-Z][a-zA-Z0-9._-]* v?[0-9]+(\.[0-9]+)+' || echo "NO_VISIBLE_VERSION"; } | sort -u`

Route on output:

- Match contains framework + version (e.g. `RecruitX v2.4`, `WordPress 5.4`) → apply **Version-discovery route**
- `NO_VISIBLE_VERSION` → 2.5

### 2.5 Cookies (unauth, root)

`curl -s -D - -o /dev/null "http://$host:$port/" | grep -i '^Set-Cookie:' || echo "NO_COOKIES"`

Route on output:

- One or more `Set-Cookie` values present → [[Session Cookie Attacks]]
- `NO_COOKIES` → continue to Step 3.

---

## Step 3 — Passive Reconnaissance

Per-path passive reads (comments, admin-link discovery, flag hunt). Initial run: apply each sub-block's action to all paths in `unauth_paths_<host>.txt` (each applies its own scope filter). Subsequent invocations via the `unauth_paths_<host>.txt` sub-routine in [[#Accumulator re-fire check]] at end-of-Step boundaries — walked-tracked.

Any sub-block that discovers a new path appends to `unauth_paths_<host>.txt`; re-fire drains at next boundary.

### 3.1 HTML comments sweep

Scope: HTML-eligible paths in `unauth_paths_<host>.txt`.

`grep -vE '\.(png|jpg|jpeg|gif|css|js|woff2?|ico|svg|mp4|webm|pdf|zip|tar|gz|json)$' unauth_paths_$host.txt | while read p; do echo "=== $p ==="; out=$(curl -s "http://$host:$port${p}" | grep -Pzo '(?s)<!--.*?-->' | tr -d '\0'); [ -n "$out" ] && printf '%s\n' "$out" || echo "NO_COMMENTS"; done`

Route per path on inspection (per finding, may fire multiple):

- Framework name + version → apply **Version-discovery route**
- Framework name only, no version → [[Web Stack Version Discovery]]
- Username(s) → `echo '<username>' >> users_<host>.txt`
- Credentials (user:pass, key=value) → `echo '<user>:<pass>' >> creds_<host>.txt`
- Endpoint / path → `echo '<endpoint>' >> unauth_paths_<host>.txt` (re-fire drains at next step boundary)
- Nothing exploitable → no action

### 3.2 Visible admin/dashboard links (unauth)

Scope: HTML-eligible paths in `unauth_paths_<host>.txt`.

`grep -vE '\.(png|jpg|jpeg|gif|css|js|woff2?|ico|svg|mp4|webm|pdf|zip|tar|gz|json)$' unauth_paths_$host.txt | while read p; do echo "=== $p ==="; curl -s "http://$host:$port${p}" | grep -oiE 'href=["'"'"'][^"'"'"']*(admin|dashboard|settings|manage|console)[^"'"'"']*' | sort -u || echo "NO_ADMIN_LINK"; done`

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

`grep -vE '\.(png|jpg|jpeg|gif|css|js|woff2?|ico|svg|mp4|webm|pdf|zip|tar|gz|json)$' unauth_paths_$host.txt | while read p; do echo "=== $p ==="; out=$(curl -s "http://$host:$port${p}" | grep -oE '(THM|HTB|flag|FLAG|CTF)\{[^}]*\}'); [ -n "$out" ] && printf '%s\n' "$out" || echo "NO_FLAG"; done`

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

`~/scripts/web_auth_probe.sh $host $port --mode=login`

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

`~/scripts/web_auth_probe.sh $host $port --mode=register`

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

`~/scripts/web_auth_probe.sh $host $port --mode=forgot`

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

`curl -s http://$host:$port/robots.txt || echo "ROBOTS_ABSENT"`

Route on output:

- Entries under `Disallow:` → for each, `echo '<path>' >> unauth_paths_<host>.txt` (re-fire drains at Step boundary)
- `ROBOTS_ABSENT` → 6.2

### 6.2 sitemap.xml

`{ curl -sfL "http://$host:$port/sitemap.xml" || curl -sfL "http://$host:$port/sitemap_index.xml"; } || echo "SITEMAP_ABSENT"`

Route on output:

- `<loc>` entries present → for each not already in `unauth_paths_<host>.txt`, extract path (strip scheme+host) → `echo '<path>' >> unauth_paths_<host>.txt`
- `SITEMAP_ABSENT` → continue

### 6.3 Server diagnostic endpoints

⚠️ Stack-gated — run the Apache block on an Apache stack, the nginx block on an nginx stack; stack unknown → run both.

⚠️ `mod_status` / `mod_info` default to `Require local`, but a `Require all granted` in any vhost silently overrides it. nginx `stub_status` has no default location and no default access restriction — both are set per `location` block.

##### Apache Server Status

`code=$(curl -s -o /dev/null -w '%{http_code}' "http://$host:$port/server-status"); echo "SERVER_STATUS: HTTP $code"`

Route on `$code`:

- `200` — exposed. Mine:
  - Version: `curl -s "http://<host>:<port>/server-status" | grep -oiE 'Server Version: *[^<]+'` → **Version-discovery route** on the `Apache/<version>` token and any other product/version tokens in the line (OpenSSL, mod_perl, PHP, …). 
  - In-flight request paths (present only under `ExtendedStatus On`): `curl -s "http://<host>:<port>/server-status" | grep -oiE '(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH)[[:space:]]+/[^[:space:]]*[[:space:]]+HTTP/[0-9.]+' | awk '{print $2}' | grep -vE '^/server-(status|info)\b'`. **Add relevant paths to `unauth_paths_<host>.txt`** No matches → `ExtendedStatus` off; version only.
- `403` — module loaded, `Require local` effective. `echo 'RESTRICTED: /server-status' >> route_<ip>.txt`; re-attempt via any localhost-origin primitive (e.g. SSRF) found later.
- `404` — `mod_status` off/absent. No action.

##### Apache Server Info

`code=$(curl -s -o /dev/null -w '%{http_code}' "http://$host:$port/server-info"); echo "SERVER_INFO: HTTP $code"`

Route on `$code`:

- `200` — exposed. Leaks loaded modules + full config (module presence → attack surface, e.g. `mod_cgi`; config may disclose `DocumentRoot`, aliases, paths).
  - Version: `curl -s "http://<host>:<port>/server-info" | grep -oiE 'Server Version: *[^<]+'` → **Version-discovery route**.
  - `echo 'CONFIG_LEAK: /server-info' >> route_<ip>.txt`, read manually: `curl -s "http://<host>:<port>/server-info" | less`; any path/alias disclosed → `echo '<path>' >> unauth_paths_<host>.txt`.
- `403` — loaded, restricted. `echo 'RESTRICTED: /server-info' >> route_<ip>.txt`.
- `404` — `mod_info` off/absent. No action.

##### nginx stub_status

`for sp in nginx_status nginx-status basic_status status stub_status; do code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://$host:$port/$sp"); [ "$code" = "200" ] && curl -s --max-time 5 "http://$host:$port/$sp" | grep -q 'server accepts handled requests' && echo "STUB_STATUS: /$sp (HTTP 200)"; [ "$code" = "403" ] && echo "STUB_STATUS_RESTRICTED: /$sp"; done; echo "STUB_STATUS_PROBE_COMPLETE"`

Route per marker:

- `STUB_STATUS: <path> (HTTP 200)` — exposed. No version, no paths, no config in the body; log only: `echo 'INFO_DISCLOSURE: <path> (nginx stub_status)' >> route_<ip>.txt`. ⚠️ Engagement report finding, not a foothold route.
- `STUB_STATUS_RESTRICTED: <path>` — `echo 'RESTRICTED: <path>' >> route_<ip>.txt`; re-attempt via any localhost-origin primitive (e.g. SSRF) found later.
- `STUB_STATUS_PROBE_COMPLETE` with no other markers — `stub_status` absent or at a non-conventional location. No action.

---

---

## — Boundary — end of Step 6

→ [[#Accumulator re-fire check]]
→ Step 7

---

## Step 7 — Active content discovery

> **STATUS (this step): AUDITED** — 7.1 derived 2026-09-19, reworked 2026-10-14; 7.2 re-derived 2026-10-12, (f) reworked 2026-10-13, (g) re-derived 2026-10-14. Primary sources: OWASP WSTG-INFO-04/06 + API Reconnaissance, PortSwigger Content Discovery + API testing, HackTricks, PayloadsAllTheThings, feroxbuster/ffuf/SecLists docs. Mechanics sandbox-verified; tool flags confirmed on Kali 2026-10-12/13/14. (f) live-run on THM `Modern Web Stacks` + `Web Server Attacks - I`; **(g)'s routing is derived but never run**. Live-validation pending. Not CANONICAL.

Actively enumerate paths the app didn't advertise. Two mechanisms: recursive wordlist enumeration (7.1) and API endpoint enumeration (7.2). All hits reach `unauth_paths_<host>.txt` — 7.1 directly, 7.2 via its own API accumulator — and the re-fire at the Step 7 boundary dispatches Passive Recon (Step 3), Input Surface (Step 4) and Auth-form processing (Step 5).

### 7.1 Recursive wordlist enumeration

#### **Feroxbuster** 

Run both passes. Pass 2 is not conditional on Pass 1's result.

###### Pass 1 — bare words + extensions:

`feroxbuster -u "http://$host:$port" -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,phtml,php3,php4,php5,asp,aspx,ashx,asmx,jsp,jspx,do,action,py,inc,html,xml,txt,js,json,config,conf,env,bak,old,orig,log -d 4 --auto-tune -o feroxbuster_<ip>_$port.txt`

###### Pass 2 — trailing slash, no extensions:

`feroxbuster -u "http://$host:$port" -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -f -d 4 --auto-tune -o feroxbuster_slash_<ip>_$port.txt`

`-d 4` caps recursion depth. 
`-f` appends `/` to each request's URL, replacing the bare form rather than adding a second variant. 

 ⚠️ Feroxbuster shows all status codes; it suppresses the not-found wall by auto-building a wildcard filter from that response's signature (lines/words/chars) — the `… created new filter` lines are this calibration, not findings. Any response deviating from the signature (a non-404, or a 404 of a different size) is shown.

##### ⚠️ Professional Engagement Overlays:
- ⚠️ Rate-limit (real engagement, WAF suspected): append `-t 5 --rate-limit 10` (5 threads, 10 req/sec) ⚠️.
- Same-length noise (server returns 200 for missing paths): feroxbuster's automatic wildcard filter handles most (see body); manual `-C <length>` filters a specific response length.

#### **Gobuster fallback** — if feroxbuster unavailable:

`gobuster dir -u "http://<host>:<port>" -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x <extensions_per_stack> -o gobuster_<ip>_<port>.txt`

⚠️ Gobuster does NOT recurse. `-r` follows redirects only. For every 200/301/302 hit on a directory-shape path, manually re-invoke:
`gobuster dir -u "http://<host>:<port>/<discovered_dir>/" -w <wordlist> -x <extensions> -o gobuster_<ip>_<port>_<slug>.txt`

#### **Error gate** — run before per-hit processing:

Feroxbuster run only — skip if gobuster fallback was used.

Run once per Feroxbuster pass. For each, read `errors:<errors>` and the request total from that pass's own overall completion line (`<total>/<total> … found:… errors:<errors>`), then:

`awk -v e=<errors> -v t=<total> 'BEGIN{r=e/t*100; printf "%.3f%% errored — %s\n", r, (r>0.5?"RERUN":"PROCEED")}'`

Route on verdict:

- `PROCEED` → that pass is clear.
- `RERUN` → rerun that pass's invocation once with `-t 10`, overwriting its own output file.

Per-hit processing starts once both passes are clear.

#### **Per-hit processing** — five small single-purpose commands:

##### (a) Extract hit URLs to a working file:

`awk '/^[0-9]{3}[[:space:]]/ && $NF ~ /^https?:\/\// {print $NF}' feroxbuster_<ip>_$port.txt feroxbuster_slash_<ip>_$port.txt | sort -u > hits_<ip>_$port.txt`

##### (b) Add every hit path to `unauth_paths_<host>.txt`:

`sed -E "s|^https?://$host(:$port)?||" hits_<ip>_$port.txt >> unauth_paths_$host.txt && sort -u unauth_paths_$host.txt -o unauth_paths_$host.txt`

##### (c) Autoindex detection loop — extract directory listings:

`grep 'directory listing' feroxbuster_<ip>_$port.txt feroxbuster_slash_<ip>_$port.txt | sed -E 's|^.*directory listing: |AUTOINDEX: |'`

For each `AUTOINDEX: <url>` line, record to `route_<ip>.txt`.
##### (d) High-value file inspection

Create the local inspection dir:

`mkdir -p inspect_${host}_$port`

Download every hit (**relies on `(a) Extract hit URLs....`, above, having been successfully run**) except HTML pages and media:

`grep -vE '\.(html?|png|jpe?g|gif|svg|ico|webp|bmp|tiff?|avif|css|woff2?|ttf|otf|eot|mp[34]|m4[av]|webm|wav|ogg|oga|flac|aac|avi|mov|mkv|wmv|flv)$|/$' hits_<ip>_$port.txt | while read -r url; do curl -s -L -O --output-dir inspect_${host}_$port "$url"; done`

Inspect the tree:

`~/scripts/local_file_inspector.py inspect_${host}_$port`

Route per marker:

- `FILE_CRED: <path>: <match>` — verify (may be a placeholder like `changeme` / `<PASSWORD>`); real credential → `echo '<user>:<pass>' >> creds_<host>.txt`; log `echo 'FILE_CRED: <path>: <match>' >> route_<ip>.txt`.
- `SECRET: <path>: <type>:<value>` — route by `<type>`: `jwt` → [[Session Cookie Attacks]] (JWT branch); `bearer` / `token` → reuse as an `Authorization` header on auth-gated requests; `aws_akid` / `api_key` / `google_api_key` / `slack_token` / `pem_private_key` / `secret` → note for the matching service, reuse when that service surfaces. Log to `route_<ip>.txt`.
- `ENDPOINT_REF: <path>: <ref>` — new attack surface → `echo '<ref>' >> unauth_paths_<host>.txt` (re-fire drains at the Step 7 boundary). A `${...}` / `:param` stub is a 7.2(f) segment-swap template, not a literal probe.
- `ARCHIVE_NESTED: <path>` — the retrieved file is itself an archive → 7.3 loot: extract to a sandbox dir, then re-run the inspector over the extracted tree.
- `MANUAL_REVIEW: <path>` — file read OK; eyeball the local copy at `inspect_<ip>_<port>/…` for what the regexes do not catch (stack traces, framework hints, usernames, source disclosure in `.bak` / `.old` / `.orig` / `~`).
- `FLAG: <path>: <value>` — CTF flag.
- `READ_FAIL: <path>: <reason>` — retrieval or read failed; NOT a no-match. Re-fetch manually if the hit looked live.
- `SCAN COMPLETE: …` — positive completion; a clean no-finding run is explicit, never a silent return.

##### (e) 403 handling — surface for later credential re-use:

`out=$(awk '/^403[[:space:]]/ {print $NF}' feroxbuster_<ip>_$port.txt feroxbuster_slash_<ip>_$port.txt); if [ -n "$out" ]; then echo "$out" | while read u; do path=$(echo "$u" | sed -E "s|^https?://$host(:$port)?||"); echo "RESTRICTED: $path"; done; else echo "NO_403_HITS"; fi`

Route per marker:

- `RESTRICTED: <path>` — 403 path exists but forbidden:
  - Log for audit trail: `echo 'RESTRICTED: <path>' >> route_<ip>.txt`
  - When creds recovered downstream, re-attempt via authed request
- `NO_403_HITS` — feroxbuster found no 403s on this target.

##### (f) `.git` metadata — surface for git-dumper (out of Step 7 scope):

`out=$(grep -E '/\.git/(HEAD|config|index)$' hits_<ip>_$port.txt); if [ -n "$out" ]; then echo "$out" | while read u; do echo "GIT_LEAK: $u — run 'git-dumper <base_git_url> ./gitdump-<ip>' (out of Step 7)"; done; else echo "NO_GIT_LEAK"; fi`

Route per marker:

- `GIT_LEAK: <url>` — `.git` metadata exposed:
  - Log for audit trail: `echo 'GIT_LEAK: <url>' >> route_<ip>.txt`
  - Run `git-dumper <base_git_url> ./gitdump-<ip>` — recover source tree
  - Grep recovered tree for creds/endpoints/framework hints (out of Step 7 scope)
- `NO_GIT_LEAK` — no `.git` metadata exposed. No action.

Then → 7.2.

### 7.2 API endpoint enumeration

> **STATUS (this sub-step): AUDITED** — re-derived 2026-10-12 from first principles + primary sources re-read this session: OWASP WSTG `12-API_Testing/01-API_Reconnaissance` and PortSwigger _API testing_. Both order discovery as spec/docs → passive → observed traffic → client-side code → **active brute last**; this sub-step follows that order. Supersedes the prior feroxbuster-first 7.2 and the deferred positional-fuzz build. Derivation + what changed: [[API Endpoint Discovery - Brute-Force Limits]].

> ⚠️ **Blind path brute cannot assemble a deep, custom, sparsely-routed endpoint.** A path that is not a literal wordlist entry and whose parents 404 is never requested — recursion needs each rung non-404, and a REST backend routes only the leaf. Property of the technique, not a tuning gap. Consequence for this sub-step: **brute is the backstop, not the primary method** — (a)–(d) below carry the yield; (e)/(f) are the sweep. Full derivation: [[API Endpoint Discovery - Brute-Force Limits]].

All discovered endpoints append to `unauth_api_paths_<host>.txt` — this host's API attack surface. (g) classifies every entry, then merges the file into `unauth_paths_<host>.txt`, where the Step 7 boundary re-fire dispatches Passive Recon (Step 3), Input Surface (Step 4) and Auth-form processing (Step 5) over each.

---

##### (a) Spec / documentation discovery — one hit, full documented surface

###### Probe curated spec paths:

`for sp in api-docs doc docs swagger swagger.json swagger/index.html swagger/v1/swagger.json openapi.json openapi.yaml v2/api-docs v3/api-docs api/swagger.json api/openapi.json .well-known/schema-discovery; do code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://$host:$port/$sp"); [ "$code" = "200" ] && echo "http://$host:$port/$sp"; done > spec_candidates_${host}_$port.txt; printf 'SPEC_CANDIDATES: %s\n' "$(wc -l < spec_candidates_${host}_$port.txt)"`

- `SPEC_CANDIDATES: 0` — no spec exposed → skip the `Parse every candidate` command below → (b).
- `SPEC_CANDIDATES:` non-zero → proceed to `Parse every candidate` command below.

###### Parse every candidate:

`while read -r specurl; do spec=$(curl -s -H 'Accept: application/json' "$specurl"); if echo "$spec" | jq -e 'has("openapi") or has("swagger")' >/dev/null 2>&1; then echo "SPEC_FOUND: $specurl"; echo "$spec" | jq -r '((.servers[0].url // "") | sub("^https?://[^/]+";"")) as $base | (if $base != "" then $base else (.basePath // "") end) as $prefix | .paths | keys[] | $prefix + .' 2>/dev/null >> unauth_api_paths_<host>.txt; ver=$(echo "$spec" | jq -r '.info.version // empty' 2>/dev/null); [ -n "$ver" ] && echo "SPEC_VERSION: $specurl: $ver"; else case "$specurl" in *.yaml|*.yml) echo "SPEC_YAML_MANUAL: $specurl";; *) echo "NOT_SPEC: $specurl";; esac; fi; done < spec_candidates_${host}_$port.txt; echo "SPEC_PARSE_COMPLETE"`

Route per marker:

- `SPEC_FOUND: <url>` — every documented endpoint appended to `unauth_api_paths_<host>.txt`. Highest yield in 7.2. Also probe the spec's **older versions** (`/v1/`, `/v2/` siblings of the found path) — deprecated-but-live endpoints.
- `SPEC_VERSION: <url>: <version>` — apply **Version-discovery route**.
- `SPEC_YAML_MANUAL: <url>` — jq parses JSON only; read the YAML by eye, append its `paths:` keys to `unauth_api_paths_<host>.txt`.
- `NOT_SPEC: <url>` — 200 but not a spec document (usually the Swagger-UI HTML shell, not its backing JSON). Its spec is a separate candidate; no action.

##### (b) Route-dumper / debug-endpoint probe — one hit, full route table

`for rp in api/routes api/_routes api/debug api/debug/routes api/debug/env __routes _routes actuator actuator/mappings actuator/env debug/routes api/v1/routes api/internal/routes; do code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Accept: application/json' --max-time 5 "http://$host:$port/$rp"); [ "$code" = "200" ] && echo "ROUTE_DUMP: /$rp"; done; echo "ROUTE_DUMP_PROBE_COMPLETE"`

Route per marker:

- `ROUTE_DUMP: <path>` — read it (`curl -s -H 'Accept: application/json' "http://$host:$port<path>" | head -200`); extract every route string and append to `unauth_api_paths_$host.txt`. An `env`/`actuator/env` dump is also a **secrets** source — route each recovered value by type:
    - Credential pair / DB connection string (`<user>:<pass>`) → `echo '<user>:<pass>' >> creds_$host.txt`
    - JWT → [[Session Cookie Attacks]] (JWT branch)
    - Bearer / token → reuse as `Authorization: Bearer <value>` on auth-gated requests
    - API key / AWS key / PEM private key / `SECRET_KEY` → log, reuse when the matching service surfaces
    - Log each recovered secret to `route_<ip>.txt`
- `ROUTE_DUMP_PROBE_COMPLETE` with no hits — no self-dumping endpoint → (c).

##### (c) GraphQL detection → route

`for gp in graphql graphiql playground api/graphql v1/graphql; do tn=$(curl -s -H 'Content-Type: application/json' -d '{"query":"{__typename}"}' --max-time 5 "http://$host:$port/$gp" | jq -r '.data.__typename // empty' 2>/dev/null); [ -z "$tn" ] && continue; curl -s -H 'Content-Type: application/json' -d '{"query":"{__schema{queryType{name}}}"}' "http://$host:$port/$gp" | jq -e '.data.__schema' >/dev/null 2>&1 && intro=on || intro=off; echo "GRAPHQL: /$gp (introspection=$intro)"; done; echo "GRAPHQL_PROBE_COMPLETE"`

Route per marker:

- `GRAPHQL: <path> (introspection=on)` — schema fully dumpable → [[GraphQL Attacks]] (introspection dump + query/mutation abuse).
- `GRAPHQL: <path> (introspection=off)` — confirmed GraphQL, introspection disabled → [[GraphQL Attacks]] (field-suggestion / clairvoyance path).
- A GraphQL endpoint is **terminal API surface** — append the path to `unauth_api_paths_<host>.txt`; never feed it to (f) segment-swap (its surface is a schema, not path segments).
- `GRAPHQL_PROBE_COMPLETE` with no hits — no GraphQL endpoint → (d).

##### (d) Client-code harvest — endpoints from the shipped JS

Harvests endpoint strings from the application's shipped client code. High yield on SPA / JS-heavy targets: the shipped bundles expose the endpoints the UI calls, including paths brute cannot reach. ⚠️ **Requires Step 1's HAR**.

###### Collect JS source URLs (HAR ∪ already-discovered pool), dedup:

`{ jq -r --arg h "$host" --arg p "$port" '.log.entries[] | select(.request.url | test("^https?://" + $h + "(:" + $p + ")?/")) | select(((.response.content.mimeType // "") | ascii_downcase | test("javascript|ecmascript")) or ((.request.url | split("?")[0]) | test("\\.(js|mjs|cjs)$"))) | .request.url' unauth_crawl_$host.har 2>/dev/null; grep -iE '\.(js|mjs|cjs)(\?|$)' unauth_paths_$host.txt | sed -E "s#^/#http://$host:$port/#"; } | sort -u > js_urls_${host}_$port.txt; printf 'JS_SOURCES: %s\n' "$(wc -l < js_urls_${host}_$port.txt)"`

- `JS_SOURCES: 0` — no shipped JS surfaced; log `INAPPLICABLE: client-code-harvest: no JS sources` to `route_<ip>.txt` → (e).

###### Retrieve each bundle and its sibling source map, path-preserving:

Create the local harvest dir: 

`mkdir -p harvest_${host}_$port`

`while read -r url; do [ -z "$url" ] && continue; rel=$(printf '%s' "$url" | sed -E "s#^https?://[^/]+/##; s/\?.*$//"); dest="harvest_${host}_$port/$rel"; mkdir -p "$(dirname "$dest")"; curl -s -L --max-time 10 -o "$dest" "$url"; mapcode=$(curl -s -L --max-time 10 -o "${dest}.map" -w '%{http_code}' "${url%%\?*}.map"); [ "$mapcode" = "200" ] || rm -f "${dest}.map"; done < js_urls_${host}_$port.txt`

Inspect the harvested tree:

`~/scripts/local_file_inspector.py harvest_<host>_<port>`

Route per marker (contract as 7.1(d)):

- `ENDPOINT_REF: <path>: <ref>` — split by shape:
    - **Static** ref (no `${...}` / `:param`) → `echo '<ref>' >> unauth_api_paths_<host>.txt`
    - **Dynamic stub** (contains `${...}` or `:param`, e.g. `/api/${id}/update`) → an **(f) segment-swap template**, NOT a literal probe. If the hole is an identifier (`id`/`uuid`/`guid`/`userId`) → [[IDOR]] instead.
    - `/graphql`-shaped → `unauth_api_paths_<host>.txt` + (c) GraphQL routing.
- `SECRET: <path>: <type>:<value>` — hardcoded secret in a bundle (common). Route by `<type>` per 7.1(d).
- `FILE_CRED: <path>: <match>` — verify (may be a placeholder); real → `echo '<user>:<pass>' >> creds_<host>.txt`.
- `FLAG: <path>: <value>` — capture; log `FLAG_FOUND: <path>: <value>` to `route_<ip>.txt`.
- `MANUAL_REVIEW: <path>` — eyeball the bundle; in particular GraphQL operation/field names (`query getAdminFlag {...}`), which are not `/`-paths and will not surface as `ENDPOINT_REF` → [[GraphQL Attacks]].
- `READ_FAIL: <path>: <reason>` — empty/unreadable fetch or over the inspector's size cap → re-fetch manually.

##### (e) Curated-route brute — the backstop sweep

Entries are **full curated routes**, not words to combine — so no recursion and no combinatorial assembly. Multi-method (`-m GET,POST`): a POST-only route is invisible to a GET-only sweep

`feroxbuster -u "http://$host:$port" -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -m GET,POST -d 1 --auto-tune -o feroxbuster_api_<ip>_$port.txt`

`-d 1` disables recursion (entries are already full paths). `--auto-tune` + feroxbuster's per-method signature wildcard filter suppress the not-found wall; the filter is keyed on the response **signature (lines/words/chars)**, one filter per method — it therefore also catches a soft-404 (200/302 not-found) and an SPA wildcard (`200 + index.html`), which a status-only filter cannot.

###### Error gate. Read `errors:<errors>` and the request total from the completion line, then:

`awk -v e=<errors> -v t=<total> 'BEGIN{r=e/t*100; printf "%.3f%% errored — %s\n", r, (r>0.5?"RERUN":"PROCEED")}'`

- `PROCEED` → per-hit processing. 
- `RERUN` → rerun this leg once with `-t 10`, then continue.

###### Per-hit processing — strip hits to paths, append to the API accumulator:

`awk '/^[0-9]{3}[[:space:]]/ {print $NF}' feroxbuster_api_<ip>_$port.txt | sed -E "s|^https?://$host(:$port)?||" | sort -u >> unauth_api_paths_$host.txt`

⚠️ **Implausible hit count (hundreds+) means the not-found wall is leaking, not that the API is enormous** — the target's not-found response is defeating the signature filter. Do NOT route the results. Capture the not-found shape (`curl -s -o /dev/null -w 'status=%{http_code} size=%{size_download}\n' "http://<host>:<port>/<random>"`), then rerun with an explicit `-C <status>` or `--filter-size <n>`.

##### (f) Segment-swap — siblings and children of known endpoints, plus conventional roots

###### Consolidate the API surface:

Pull the API-shaped paths (`/api/`, `/rest/`, `/vN/`) that earlier Steps left in `unauth_paths_$host.txt` into `unauth_api_paths_$host.txt`, so (f) swaps off the complete set:

`grep -E '^/(api|rest|v[0-9]+)/' unauth_paths_$host.txt >> unauth_api_paths_$host.txt; sort -u unauth_api_paths_$host.txt -o unauth_api_paths_$host.txt`

###### Build the API prefix list:

Build the API prefix list — each discovered endpoint **and** its parent, plus conventional defaults (`/api`, `/api/admin`, `/api/user`, `/api/v1`, `/v1`, `/rest`), deduped:

`{ sed -E 's#/[^/]+$##' unauth_api_paths_$host.txt | grep -E '^/.'; grep -E '^/[^/]+/' unauth_api_paths_$host.txt; printf '/api\n/api/admin\n/api/user\n/api/v1\n/v1\n/rest\n'; } | sort -u > api_prefixes_$host.txt`

###### Build the segment vocabulary

Nouns ∪ verbs, both cases, pure-numeric entries excluded (numeric path segments belong to [[IDOR]], not this sub-block):

`{ grep -xE '[A-Za-z][A-Za-z0-9_-]*' /usr/share/seclists/Discovery/Web-Content/api/objects.txt; cat /usr/share/seclists/Discovery/Web-Content/api/actions.txt; printf 'flag\nroutes\nroute\n'; } | sort -u > api_segments.txt; printf 'SEGMENT_VOCAB: %s\n' "$(wc -l < api_segments.txt)"`

###### Sweep every prefix — append one segment (GET + POST):

`while read -r prefix; do ffuf -u "http://$host:$port${prefix}/FUZZSEG" -w api_segments.txt:FUZZSEG -t 20 -of json -o ffuf_scratch.json -s >/dev/null; jq -r '.results[]|"SWAP_HIT: GET \(.status) \(.url)"' ffuf_scratch.json 2>/dev/null; ffuf -u "http://$host:$port${prefix}/FUZZSEG" -w api_segments.txt:FUZZSEG -X POST -H 'Content-Type: application/json' -d '{}' -t 20 -of json -o ffuf_scratch.json -s >/dev/null; jq -r '.results[]|"SWAP_HIT: POST \(.status) \(.url)"' ffuf_scratch.json 2>/dev/null; done < api_prefixes_$host.txt; echo "SWAP_SWEEP_COMPLETE"`

⚠️ **A wall of SWAP_HIT lines (hundreds+) means the target soft-404s, not that you found an API.** ffuf's default matcher only excludes `404`; a target that answers unknown paths with `200` — an SPA wildcard serving `index.html`, or a 200 error page — matches on every segment in the vocabulary. Do **NOT** route the results. Diagnose the prefix that flooded: `curl -s -o /dev/null -w 'status=%{http_code} size=%{size_download}\n' "http://$host:$port<prefix>/zzrandomzz"` — a non-404 status confirms the soft-404. Re-run that prefix alone with `-fs <size>` taken from the probe. If the soft-404 size varies per path (it echoes the path back), size cannot pin it — use `-fw <words>` or `-fl <lines>` instead, which stay constant even when the body length moves.

⚠️ **Known coverage gap (accepted).** This sweep fuzzes the **terminal** segment only — `<prefix>/FUZZSEG`. It does NOT swap an **interior** segment while holding a fixed suffix (`/api/FUZZSEG/get`), so it misses a sibling *resource* that exists only under the same trailing *action* — e.g. `/api/orders/get` inferred from a known `/api/users/get`. Single-position and tractable (one ffuf run), just not expressed by the append-only shape; dropped for simplicity, not cost. **If a real box surfaces a `/<prefix>/<resource>/<action>` where sibling resources under the same `<action>` are plausible, add one mid-swap run:** `ffuf -u "http://$host:$port<prefix>/FUZZSEG/<action>" -w api_segments.txt:FUZZSEG -t 20 -of json -o ffuf_scratch.json -s >/dev/null; jq -r '.results[]|"SWAP_HIT: GET \(.status) \(.url)"' ffuf_scratch.json 2>/dev/null` — add `-X POST -H 'Content-Type: application/json' -d '{}'` when `<action>` is write-shaped.

###### Route per marker:

- `SWAP_HIT: <method> <status> <url>` — sibling endpoint exists (ffuf's default matcher excludes `404`, so every line here is a live response). `<method>` is the pass that surfaced it: `POST` ⇒ a write route — carry POST downstream when probing it. Strip the URL to a path → `echo '<path>' >> unauth_api_paths_<host>.txt`.
- `SWAP_SWEEP_COMPLETE` with no `SWAP_HIT` lines — every prefix swept, no siblings on this vocabulary → (g).
- A dynamic stub from (d) (`/api/${id}/update`) — the hole is a **mid-position** segment, which this append-only sweep does not currently express (see `Known coverage gap (accepted)` warning note, directly above). 

##### (g) Endpoint classifiers — route what (a)–(f) discovered

###### Dedup the API surface, then probe each endpoint once into a 4-field table — `status|content_type|redirect_url|path`:

`sort -u unauth_api_paths_$host.txt -o unauth_api_paths_$host.txt; while read -r apath; do printf '%s|%s\n' "$(curl -s -o /dev/null -w '%{http_code}|%{content_type}|%{redirect_url}' --max-time 5 "http://$host:$port${apath}")" "$apath"; done < unauth_api_paths_$host.txt > api_status_$host.txt; printf 'API_PATHS_PROBED: %s\n' "$(wc -l < api_status_$host.txt)"`
###### Run all three commands below, then route — the Route-per-marker table at the end covers every marker they emit.

Classify:

`awk -F'|' '$1 ~ /^(401|403)$/ || ($1 ~ /^3[0-9][0-9]$/ && $3 ~ /(login|signin|auth|sso)/) {print "AUTH_GATED_API: " $4 " (status=" $1 ")"; next} $1 ~ /^2[0-9][0-9]$/ && $2 ~ /json/ && $4 !~ /\/(swagger|openapi|api-docs|graphql|graphiql|playground)/ {print "JSON_API: " $4; next} $1 ~ /^5[0-9][0-9]$/ {print "API_SERVER_ERROR: " $4 " (status=" $1 ")"}' api_status_$host.txt; echo "API_CLASSIFY_COMPLETE"`

Write-only probe — GET-rejecting paths may still accept a write method:

`awk -F'|' '$1 ~ /^(404|405)$/ {print $4}' api_status_$host.txt | while read -r apath; do pcode=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -X POST -H 'Content-Type: application/json' -d '{}' "http://$host:$port${apath}"); [ "$pcode" = "404" ] && continue; echo "WRITE_ONLY_API: $apath (POST=$pcode)"; done; echo "WRITE_PROBE_COMPLETE"`

Identifier scan on live JSON endpoints:

`awk -F'|' '$1 ~ /^2[0-9][0-9]$/ && $2 ~ /json/ && $4 !~ /\/(swagger|openapi|api-docs|graphql|graphiql|playground)/ {print $4}' api_status_$host.txt | while read -r apath; do ids=$(curl -s --max-time 5 -H 'Accept: application/json' "http://$host:$port${apath}" | grep -oiE '"[a-z_]*(id|uuid|guid)"[[:space:]]*:[[:space:]]*"?[0-9a-fA-F-]+"?' | head -3 | tr '\n' ' '); [ -z "$ids" ] && continue; echo "API_IDS: $apath | $ids"; done; echo "ID_SCAN_COMPLETE"`

###### Route per marker:

- `AUTH_GATED_API: <path> (status=<code>)` — read the challenge: `curl -s -D - -o /dev/null "http://$host:$port<path>" | grep -iE '^(www-authenticate|location|set-cookie):' || echo "NO_CHALLENGE_HEADER"`
    - `Location:` matching `login|signin|auth|sso` → strip to a path → `echo '<location_path>' >> unauth_api_paths_<host>.txt`
    - `WWW-Authenticate: Basic` → [[Login Bypass Techniques]] "HTTP Basic Auth" section
    - `WWW-Authenticate: Bearer` → [[Session Cookie Attacks]] (JWT branch)
    - `WWW-Authenticate:` any other scheme → `echo 'RESTRICTED: <path> (scheme=<scheme>)' >> route_<ip>.txt`
    - `Set-Cookie:` present, no `WWW-Authenticate` → [[Session Cookie Attacks]]
    - `NO_CHALLENGE_HEADER` → `echo 'RESTRICTED: <path>' >> route_<ip>.txt`; re-attempt once creds are recovered downstream
- `JSON_API: <path>` — live JSON endpoint.
    - Auth-wall check: `curl -s --max-time 5 "http://<host>:<port><path>" | grep -qiE '"(error|message|detail|status)"[[:space:]]*:[[:space:]]*"[^"]*(unauthor|forbidden|denied|not authenticated|invalid token)' && echo "SOFT_AUTH_GATE" || echo "NOT SOFT_AUTH_GATE"`. `SOFT_AUTH_GATE` → route as `AUTH_GATED_API` above; stop here for this path.
    - Save the body: `mkdir -p apibodies_${host}_$port; curl -s --max-time 5 -H 'Accept: application/json' "http://$host:$port<path>" -o "apibodies_${host}_$port/$(echo '<path>' | tr '/' '_').json"`
    - Methods: `curl -s -D - -o /dev/null -X OPTIONS "http://<host>:<port><path>" | grep -iE '^(allow|access-control-allow-methods):' || echo "NO_ALLOW_HEADER"`. Any write method listed → probe it per the `WRITE_ONLY_API` branches above.
      **Then, once every `JSON_API` path is saved, as a single run before the merge:**
    - Inspect all saved bodies: `~/scripts/local_file_inspector.py apibodies_<host>_<port>` → route per marker as 7.1(d).
    - Usernames: `grep -ohiE '"(user|username|login|email|mail|account|owner|handle)"[[:space:]]*:[[:space:]]*"[^"]+"' apibodies_<host>_<port>/*.json | sed 's/.*:[[:space:]]*"//; s/"$//' | sort -u | tee -a users_<host>.txt | grep -q . && echo "API_USERS_HARVESTED" || echo "NO_API_USERS"`
- `API_IDS: <path> | <ids>` — identifiers in a live response body → [[IDOR]].
    - Dangling dynamic stubs: `grep -nE '(\$\{[a-zA-Z_]+\}|/:[a-zA-Z_]+|/\{[a-zA-Z_]+\})' unauth_api_paths_<host>.txt || echo "NO_DYNAMIC_STUBS"`. Per stub, substitute one `<ids>` value into the hole and probe: `curl -s -o /dev/null -w '%{http_code}\n' "http://<host>:<port><filled_stub>"`. Non-404 → `echo '<filled_stub>' >> unauth_api_paths_<host>.txt`
    - ⚠️ Real engagement: skip any stub matching `(delete|remove|destroy|purge|reset|send|pay|transfer)`; `printf 'DEFERRED: SCOPE_HOLD: <stub>\n' >> route_<ip>.txt`
- `WRITE_ONLY_API: <path> (POST=<code>)` — write surface.
    - ⚠️ Real engagement: `<path>` matching `(delete|remove|destroy|purge|reset|send|mail|invite|pay|charge|transfer|exec|run|deploy)` → confirm scope before any further request; `printf 'DEFERRED: SCOPE_HOLD: <path>\n' >> route_<ip>.txt`; stop here for this path.
    - POST=400 / 422 → name the body fields: `curl -s -X POST -H 'Content-Type: application/json' -d '{}' "http://<host>:<port><path>" -o apierr_<host>.json; jq . apierr_<host>.json 2>/dev/null || head -40 apierr_<host>.json`. Read the field names from the output → route each per 4.2. No field names → `printf 'DEFERRED: JSON_FIELDS_UNKNOWN: <path>\n' >> route_<ip>.txt`
    - POST=415 → re-probe body formats per [[Request Content-Types by Body Format]]; any non-415 format → re-enter the 400 / 422 branch above
    - POST=2xx → `printf '[step9-sweep] DEFERRED: STATE_ENDPOINT: <path>\n' >> route_<ip>.txt`
    - `<path>` matching `(login|signin|token|session|authenticate)` → [[Credential Attacks]], JSON body, field names as above
    - `<path>` matching `(register|signup)` → [[Registration Attacks]]. Matching `(forgot|reset|recover)` → [[Password Reset Attacks]]
- `API_SERVER_ERROR: <path> (status=<code>)` — unhandled error.
    - Self-inflicted check first: `curl -s -o /dev/null -w '%{http_code}\n' "http://<host>:<port>/" | grep -qE '^(200|30[0-9])$' && echo "HOST_LIVE" || echo "NOT HOST_LIVE"`. `NOT HOST_LIVE` → host degraded by the 7.2(e)/(f) sweeps; `printf 'DEFERRED: API_5XX_SCANNER_INDUCED\n' >> route_<ip>.txt`; discard the whole 5xx set.
    - status=502 / 503 / 504 → upstream, no app body → `printf 'DEFERRED: UPSTREAM_DOWN: <path>\n' >> route_<ip>.txt`
    - status=500 → read the body: `curl -s "http://<host>:<port><path>" | head -60`
        - product / version tokens → **Version-discovery route**
        - SQL text → [[Error-Based SQL Injection]]
        - absolute filesystem paths → target list for [[Local File Inclusion]] and [[Path Traversal]]
        - a named missing parameter → `echo '<path>?<param>=1' >> unauth_api_paths_<host>.txt`
        - none of the above → `printf 'DEFERRED: 500_OPAQUE: <path>\n' >> route_<ip>.txt`
- `API_PATHS_PROBED: 0` — 7.2 discovered nothing → 7.3.

Merge the API surface into the master path list — run last, before the Step 7 boundary:

`cat unauth_api_paths_$host.txt >> unauth_paths_$host.txt && sort -u unauth_paths_$host.txt -o unauth_paths_$host.txt`

Then → 7.3.

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
