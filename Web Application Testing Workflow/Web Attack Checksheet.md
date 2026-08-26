
Routes HTTP/HTTPS service to web attack technique walkthroughs. Pure router — attack content lives in per-technique files.

Ordering: P(yield)/time-cost, OSCP+-tuned. Cheap probes first (Step 1); well-known files (Step 2); active scanning (Step 3); subdomain enum only if domain-based (Step 4); deferred low-EV last (Step 5). Off-target OSINT footer-only — near-zero P(yield) on lab boxes.

---

## Setup

Per HTTP/HTTPS service on target (multiple ports = multiple walks).

`<host>` = target hostname or IP for the HTTP service. `<port>` = the HTTP/HTTPS port. `<ip>` = target IP (matches existing MW `route_<ip>.txt`). `<domain>` = target's DNS-resolvable domain (Step 4 only; skip Step 4 if target is IP-only).

Initialise decision log — append to existing `route_<ip>.txt`:

```bash
printf '\nWEB_ROUTES_TRIED (<host>:<port>):\n[<technique>] <disposition>\n' >> route_<ip>.txt
```

`<disposition>` ∈ `{APPLIED: <outcome>, INAPPLICABLE: <reason>, DEFERRED: <reason>}`

---

## Version-discovery route

Fires any time a product or version token is observed during the walk. Sub-blocks 1.1–1.4 are the dedicated probes; the route also fires opportunistically on version signals surfaced by later sub-blocks (headers on gobuster hits, meta generators on inspected pages, framework hints in error responses, etc.).

1. Grep `services_<ip>.txt` for this service: `grep '^<port>/open' services_<ip>.txt`
2. Field 5 already contains `<product>` AND `<version>` tokens → next sub-block (Pass 1 has covered this).
3. Either token new → run [[MASTER WORKFLOW/Step 6. Vulnerability Analysis#Pass 1 re-fire]].

---

## Username accumulator convention

Used by sub-blocks 1.5, 1.6, 1.7, 1.8, 1.11, and [[IDOR]] via cross-route.

Any sub-block that enumerates or verifies a valid target username appends to `users_<host>.txt`:

`echo '<username>' >> users_<host>.txt`

De-duplicate periodically: `sort -u users_<host>.txt -o users_<host>.txt`. Sub-block 1.14 consumes this file as its precondition input for enum-fed credential attack.

---

## Step 1 — Home-page reconnaissance

### 1.1 HTTP response headers

`curl -s -D - -o /dev/null http://<host>:<port>/ | grep -iE '^(Server|X-Powered-By):' || echo "NO_VERSION_HEADERS"`

Route on output:

- `Server: <product>/<version>` line present → apply Version-discovery route
- `X-Powered-By: <product>/<version>` line present → apply Version-discovery route
- `NO_VERSION_HEADERS` → 1.2

### 1.2 Favicon fingerprint

`curl -sfL http://<host>:<port>/favicon.ico | md5sum || echo "FAVICON_ABSENT"`

Compare hash against [OWASP favicon database](https://wiki.owasp.org/index.php/OWASP_favicon_database) ([[Useful Websites (Web App Pen Testing)]]) - **NB: Search the database using `Ctrl+f` on the webpage; using the search input box searches the entire website, not the database (page)**

Route on output:

- Hash matches framework+version entry in DB (label contains product name and version, e.g. `WordPress 5.4`) → apply **Version-discovery route**
- Hash matches non-framework entry (e.g. `Zero byte favicon`, generic server default icon) → 1.3
- Hash has no DB match → 1.3
- `FAVICON_ABSENT` → 1.3

### 1.3 Wappalyzer extension

In **browser** (Wappalyzer extension installed), navigate to `http://<host>:<port>/`. Read extension panel.

Route on panel content:

- Framework identified with version → apply **Version-discovery route**
- Framework identified without version → note framework hint, 1.4
- Nothing identified → 1.4

### 1.4 HTML source version disclosure

Two sweeps: meta tags and visible text. Both feed Version-discovery route.

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
- `NO_VISIBLE_VERSION` → 1.5

### 1.5 HTML comments sweep

`{ curl -s http://<host>:<port>/ | grep -Pzo '(?s)<!--.*?-->' || echo "NO_COMMENTS"; } | tr -d '\0'`

Route on inspection (per finding, may fire multiple):

- Framework name + version → apply **Version-discovery route**
- Framework name only, no version → note framework hint
- Username(s) → `echo '<username>' >> users_<host>.txt` (per Username accumulator convention)
- Credentials (user:pass, key=value) → try against any known login form (route to sub-block 1.6 with known credentials)
- Endpoint / path → `curl -s http://<host>:<port>/<path>`; new surface → re-apply Step 1 sub-blocks 1.6–1.13 against it
- `NO_COMMENTS` or nothing exploitable → 1.6

### 1.6 Login form

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

  1. [[Credential Attacks]] Sections 1-4 (default creds, credential stuffing, hit-and-hope brute force, password spray) — Section 5 defers to sub-block 1.14
  2. [[Login Bypass Techniques]] (all sections — HTML comments, injection, tampering, direct access, header bypass, case-sensitivity, HTTP Basic Auth)
  3. [[Username Enumeration]] Section 1.1 (login-form differential signal detection — appends to `users_<host>.txt`)
  4. [[Session Cookie Attacks]] if Set-Cookie observed on any request during walk (per sub-block 1.9 detection)
  5. [[MFA Bypass]] if multi-step verification observed after successful first-factor auth
- `LOGIN_CANDIDATE: [<orig> → ]<final> (<detail>)` (no FOUND for this path) → open final path in browser; if login form confirmed, `<login_path>` = final path, follow LOGIN_FORM_FOUND branch above (capture metadata + walk techniques); if not confirmed, log INAPPLICABLE
- `AUTH_CHALLENGE: [<orig> → ]<final> (code=401 scheme=Basic)` → walk [[Login Bypass Techniques]] "HTTP Basic Auth" section against that path
- `AUTH_CHALLENGE` with scheme other than Basic (Bearer / Digest / etc.) → log informational, note as auth surface for later
- Other markers (`RESTRICTED` / `METHOD_MISMATCH` / `SERVER_ERROR` / `NO_FORM` / `DEAD` / `UNREACHABLE`) → informational, no action in this sub-block
- No `LOGIN_FORM_FOUND` AND no `LOGIN_CANDIDATE` AND no actionable `AUTH_CHALLENGE` → 1.7

### 1.7 Register form

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
- No `REGISTER_FORM_FOUND` AND no `REGISTER_CANDIDATE` → 1.8

### 1.8 Forgot-password form

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
- No `FORGOT_FORM_FOUND` AND no `FORGOT_CANDIDATE` → 1.9

### 1.9 Cookies

`curl -s -D - -o /dev/null http://<host>:<port>/ | grep -i '^Set-Cookie:' || echo "NO_COOKIES"`

For each Set-Cookie value, assess format.

Route on assessment:

- Value is plain (e.g. `admin=false`, `user_id=1`), base64 (e.g. `eyJ...`, decodes with `base64 -d`), or hex hash (32/40/64 chars) → [[Session Cookie Attacks]]
- Value is opaque (long random-looking, no discernible format) → log informational, 1.10
- `NO_COOKIES` → 1.10

### 1.10 Upload surface

`curl -s http://<host>:<port>/ | grep -oiE '<input[^>]*type=["'"'"']?file' || echo "NO_FILE_INPUT_HOMEPAGE"`

Also browse for upload features not on home page (profile picture, support ticket attachments, document submission).

Route on output + browse observation:

- File input present (grep hit OR observed on discoverable page) → [[File Upload]]
- `NO_FILE_INPUT_HOMEPAGE` AND no upload surface observed elsewhere → 1.11

### 1.11 URL parameters

`curl -s http://<host>:<port>/ | grep -oiE '(href|action)=["'"'"'][^"'"'"']*\?[^"'"'"']*' | grep -oiE '\?[^"'"'"']*' | sort -u`

Also inspect Burp Proxy history for XHR/fetch requests with parameters.

Route per parameter observed (classify by name / value shape):

- Parameter name in {`file`, `page`, `include`, `template`, `lang`, `doc`} → [[Local File Inclusion]], then [[Remote File Inclusion]], then [[Path Traversal]]
- Parameter name in {`url`, `server`, `redirect`, `fetch`, `dst`, `endpoint`, `src`} → [[SSRF]]
- Parameter name in {`id`, `uid`, `pid`} OR value numeric-sequential / base64 / predictable-hash → [[IDOR]] (may cross-route to [[Username Enumeration]] if enumerating user records — appends to `users_<host>.txt`)
- Any other user-controlled parameter → [[Injection]] (top-level stub routes into sub-technique per input context)
- No parameters observed → 1.12

### 1.12 Low-EV input surfaces

Browse and note candidates. For each, log to `WEB_ROUTES_TRIED` as DEFERRED for Step 5 sweep — do NOT walk technique now:

```bash
printf '[step5-sweep] DEFERRED: <marker>: <location>\n' >> route_<ip>.txt
```

`<marker>` values (Step 5 greps these literally):

- `REFLECTED_CANDIDATE` — search boxes, error banners, filter fields, page params that echo back
- `STORED_SURFACE` — comment forms, review forms, profile bio fields, ticket bodies, chat messages
- `STATE_ENDPOINT` — buttons/actions that mutate state (register, redeem, transfer, one-time claim)

Nothing observed → 1.13.

### 1.13 Visible admin/dashboard links

Browse for visible links to `/admin`, `/dashboard`, `/settings`, `/manage`, `/console`. Also:

`curl -s http://<host>:<port>/ | grep -oiE 'href=["'"'"'][^"'"'"']*(admin|dashboard|settings|manage|console)[^"'"'"']*' | sort -u || echo "NO_ADMIN_LINK"`

For each hit, test unauth access:

`curl -s -o /dev/null -w "%{http_code}\n" http://<host>:<port>/<path>`

Route on status code:

- 200 / 302 (no auth challenge) → new surface reached, re-apply Step 1 sub-blocks 1.6–1.13 against `http://<host>:<port>/<path>/`. If `users_<host>.txt` grew during re-application, re-run 1.14 after.
- 401 / 403 / redirect to login → note the admin path for later credential re-use; if creds recovered anywhere later → try against this path
- `NO_ADMIN_LINK` → 1.14

### 1.14 Credential attack with enumerated usernames

Fires [[Credential Attacks]] Section 5 (enum-fed brute force) against discovered login form using target-enumerated usernames from `users_<host>.txt`.

Preconditions:

- A login form was discovered in 1.6 (or via re-apply from 1.13, 2.1, 2.2, 3.1/3.2, 4.5)
- `users_<host>.txt` is populated

Check preconditions:

`[ -f users_<host>.txt ] && [ -s users_<host>.txt ] && wc -l users_<host>.txt || echo "USERS_ACCUMULATOR_EMPTY"`

Route:

- User count > 0 AND login form was discovered → [[Credential Attacks]] Section 5
- `USERS_ACCUMULATOR_EMPTY` OR no login form discovered anywhere in walk → Step 2

Reference: [[Step 1. Walking An Application]]

---

## Step 2 — Well-known files

### 2.1 robots.txt

`curl -s http://<host>:<port>/robots.txt || echo "ROBOTS_ABSENT"`

Route on output:

- Entries under `Disallow:` → for each, `curl -s -o /dev/null -w "%{http_code}\n" http://<host>:<port>/<path>`; 200/302 → new surface, re-apply Step 1 sub-blocks 1.6–1.13 against it; if `users_<host>.txt` grew, re-run 1.14
- `ROBOTS_ABSENT` → 2.2

### 2.2 sitemap.xml

`{ curl -sfL "http://<host>:<port>/sitemap.xml" || curl -sfL "http://<host>:<port>/sitemap_index.xml"; } || echo "SITEMAP_ABSENT"`

Route on output:

- `<loc>` entries present → visit each; new surface → re-apply Step 1 sub-blocks 1.6–1.13 against each; if `users_<host>.txt` grew, re-run 1.14
- `SITEMAP_ABSENT` → Step 3

Reference: [[Step 2. Content Discovery - Manual]]

---

## Step 3 — Active content discovery

### 3.1 Gobuster dir — directories

`gobuster dir -u "http://<host>:<port>" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -r -o gobuster_dir_<ip>_<port>.txt`

### 3.2 Gobuster dir — extensions

`gobuster dir -u "http://<host>:<port>" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,js,json,bak,log,conf,inc,py -r -o gobuster_ext_<ip>_<port>.txt`

After both 3.1 and 3.2 complete, list non-403/404 hits:

`cat gobuster_dir_<ip>_<port>.txt gobuster_ext_<ip>_<port>.txt | grep -viE 'Status:\s*(403|404)'`

For each hit, verify the real chain (gobuster's `-r` follows redirects and reports only final status):

`curl -s -D - -o /dev/null http://<host>:<port>/<path>`

Route per hit path:

- Path matches `login`, `signin`, `admin`, `auth` → re-apply Step 1 sub-block 1.6 (login form) against `<path>`
- Path matches `register`, `signup`, `create` → re-apply Step 1 sub-block 1.7 (register form) against `<path>`
- Path matches `forgot`, `reset`, `recover` → re-apply Step 1 sub-block 1.8 (forgot-password form) against `<path>`
- Path matches `upload`, `files`, `submit` → re-apply Step 1 sub-block 1.10 (upload surface) against `<path>`
- Path matches `api`, `v1`, `v2`, `graphql`, `rest` → 3.3
- Path matches `.git`, `.env`, `.htaccess`, `backup`, `config`, `phpinfo`, `.bak`, `.old`, `web.config` → `curl -s http://<host>:<port>/<path>`; inspect for creds/config/source; creds recovered → try against any known login form (route to sub-block 1.6 with known credentials); no creds → log, next hit
- Any other 200/301/302 hit → re-apply Step 1 sub-blocks 1.6–1.13 against `<path>`

For any re-application: if `users_<host>.txt` grew during re-application, re-run 1.14 after.

- No non-403/404 hits (empty grep output above) → 3.3

### 3.3 Manual API route guessing

`for p in /api /api/users /api/users/admin /api/messages /api/messages/admin /api/chats /api/admin /api/v1 /api/v2 /graphql; do printf '=== %s ===\n' "$p"; curl -s -w "\n[status: %{http_code}]\n" "http://<host>:<port>$p"; done`

Route per endpoint:

- Status 200 with JSON/data content → re-apply Step 1 sub-block 1.11 (URL parameters) against endpoint; also check for [[SSRF]] if endpoint accepts URL-shape param
- Status 401/403 with informative error (e.g. reveals JWT header expected, Bearer scheme) → note auth mechanism; JWT/Bearer visible → [[Session Cookie Attacks]] (JWT tampering branch)
- Response contains numeric IDs, UUIDs, or ID-shape fields → [[IDOR]] (may append usernames to `users_<host>.txt` via user-record enumeration)
- All endpoints returned 404 or no useful content → Step 4

Reference: [[Step 4. Content Discovery - Automated Discovery (utilising GoBuster)]]

---

## Step 4 — Subdomain enumeration

⚠️ Skip Step 4 entirely if target is IP-only (no domain). Set `<domain>` = target's DNS-resolvable domain (e.g. `example.thm`).

### 4.1 crt.sh

Browser: `https://crt.sh` — run six searches (replace TLDs to match target):

- `%.<domain>.co.uk`
- `%.<domain>.com`
- `<domain>.co.uk`
- `<domain>.com`
- `"<domain>.co.uk"`
- `"<domain>.com"`

Route on results:

- Subdomain in CN/SAN not previously known → add to subdomain list for 4.5
- No new subdomains → 4.2

### 4.2 DNSDumpster

Browser: `https://dnsdumpster.com` → input `<domain>`.

Route on results:

- New subdomain not previously known → add to subdomain list for 4.5
- Additional infrastructure host (fqdn + ip, out of foothold scope) → log for lateral movement, 4.3
- No results → 4.3

### 4.3 Gobuster dns

`gobuster dns -d <domain> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -o gobuster_dns_<domain>.txt`

Route on output (`grep '^Found:' gobuster_dns_<domain>.txt`):

- Subdomain in `Found:` line → add to subdomain list for 4.5
- No `Found:` lines → 4.4

### 4.4 Gobuster vhost

`gobuster vhost -u http://<host> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain --domain <domain> -o gobuster_vhost_<host>.txt`

If flooded by same-length responses, append `--exclude-length <n>` where `<n>` = the flood length observed.

Route on output (`grep 'Found:' gobuster_vhost_<host>.txt`):

- Vhost in `Found:` line → add to vhost list for 4.5
- No `Found:` lines → Step 5

### 4.5 Validate and recurse

For each subdomain / vhost collected from 4.1–4.4:

1. If not resolvable, add to `/etc/hosts`:

    `echo "<target_ip> <subdomain>" | sudo tee -a /etc/hosts`

2. Verify HTTP alive:

    `curl -s -o /dev/null -w "%{http_code}\n" http://<subdomain>/`

3. HTTP 200/301/302 → recurse: **run this Checksheet from Step 1 against `<subdomain>`** as `<host>`. Note: `users_<host>.txt` is per-host — subdomain recursion uses its own accumulator file.

4. Non-alive → log INAPPLICABLE, next subdomain.

Reference: [[Step 5. Subdomain Enumeration - OSINT]], [[Step 6. Subdomain Enumeration - DNS Bruteforce (GoBuster)]]

---

## Step 5 — Deferred low-EV route sweep

Walks routes deferred by Steps 1-4 sub-blocks that logged DEFERRED entries.

`grep 'DEFERRED' route_<ip>.txt`

For each DEFERRED entry:

- `REFLECTED_CANDIDATE: <location>` → [[XSS]] (Reflected branch)
- `STORED_SURFACE: <location>` → [[XSS]] (Stored branch)
- `STATE_ENDPOINT: <location>` → [[Race Conditions]]

XSS foothold typically via session hijack — captured cookie feeds back to [[Session Cookie Attacks]] or direct impersonation. Race Conditions typically eval/proof only — log finding, continue.

No DEFERRED entries → Exhaustion.

---

## Exhaustion

Steps 1-5 walked without foothold → return to [[MASTER WORKFLOW/Step 6. Vulnerability Analysis]] Pass 3, next priority service.

---

## Real-engagement OSINT (footer reference — not a walking step)

Off-target OSINT sources — near-zero P(yield) on OSCP+/CTF/lab boxes (synthetic targets have no public infrastructure). Walk only when engagement scope explicitly includes real production infrastructure:

- Google dorking (`site:`, `inurl:`, `filetype:`, `intitle:`)
- Wayback machine — historical paths still live
- GitHub search — public repos, leaked credentials
- S3 buckets — common suffix probing
- Shodan — additional ports, flagged CVEs

Full reference: [[Step 3. Content Discovery - OSINT]]

Any hit here: route as with any newly-discovered attack surface → re-apply Step 1 sub-blocks.
