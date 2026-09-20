
> **STATUS: PARTIAL AUDIT** — Sub-block 1 (Authenticated surface enumeration) first-principles derived with OWASP WSTG / PortSwigger / bug-bounty consultation; live-validated on THM:Guided Pentest: Web across multiple iterations. Sub-blocks 2, 4, 5, 6, 8, 10 restructured to self-filter design (per Option B) but not full V_S audit — no primary-source review per technique, no sandbox verification, no live-validation. Sub-blocks 3, 7, 9 unaudited (retain original scaffolding shape). Last partial audit: 2026-09-09.

Enumerates and exploits the attack surface exposed only under authentication. Distinct attack techniques and route dispositions from unauth (WAC) Steps 1-6.

## Return contract

After all sub-blocks walked for the current cred → return to Setup. Unwalked creds in `creds_<host>.txt` → next iteration. All walked → return control to WAC (linear walk resumes at Exhaustion).

---

## Setup — establish session

If `creds_<host>.txt` has unwalked entries:

- Pick highest-privilege candidate (lexical priority `root` > `admin` > `administrator` > else next-unwalked)
- Firefox → `http://<host>:<port>/<login_path>` → submit cred
- Firefox DevTools → Storage → Cookies → `http://<host>:<port>` → capture the session cookie (usually longest opaque value; named `PHPSESSID` / `session` / `sessionid` / `connect.sid` / `laravel_session` / app-specific)
- Set `<session_cookie>` = `<name>=<value>`
- Set `<walked_cred_username>` = cred username
- Mark cred as walked: `sed -i 's|^<user>:<pass>$|<user>:<pass> WALKED|' creds_<host>.txt`

Else if register form discovered but no unwalked cred:

- Register a novel account via `<register_path>`
- Log in with the resulting cred
- Capture `<session_cookie>` as above
- Append: `echo '<new_user>:<new_pass> WALKED' >> creds_<host>.txt`

---

## 1. Authenticated surface enumeration

Produces a master path list (`auth_paths_<host>.txt`); sub-blocks 2-10 self-filter this list by their own criteria.

Firefox DevTools → Network tab (persist logs on) captures all requests. Click through every navigation element visible under this session: main nav, dropdowns, dashboard tiles, sidebar items, footer links, "My Account" or profile menu, breadcrumbs on each landing, pagination controls. Every click loads a real page.

When exploration complete: right-click on a request row within the Network tab → Save All As HAR → `auth_crawl_<host>.har`.

Also curl-sweep seed pages for embedded hrefs:

`for p in / /dashboard /profile /settings /account; do curl -s -b '<session_cookie>' "http://<host>:<port>$p" | grep -oiE 'href=["'"'"'][^"'"'"']+' | sort -u; done > auth_hrefs_<host>.txt`

Combine both sources into a deduped path list. Handles HAR URLs (browsers strip default ports — `:80` on http, `:443` on https — but keep non-default ports like `:8080`) and href-prefixed relative paths:

`{ jq -r '.log.entries[].request.url' auth_crawl_<host>.har 2>/dev/null; sed -E 's|^href=["'"'"']||' auth_hrefs_<host>.txt; } | sed -E 's|^https?://[^/]+||' | grep -E '^/' | sort -u > auth_paths_<host>.txt`

### Route 

- `auth_paths_<host>.txt` non-empty → sub-blocks 2-10 self-filter this master list. Continue to sub-block 2. 
- `auth_paths_<host>.txt` empty → walked cred has no authenticated surface beyond anonymous. Skip sub-blocks 2-9; continue to sub-block 10 (privilege escalation — attempt tier lift).

---

## 2. URL parameters (authed)

⚠️ AUDIT PENDING — self-filter design applied, not full V_S audit (no primary-source review per-technique, no sandbox verification, no live-validation).

Filter `auth_paths_<host>.txt` for paths with user-controlled parameters (query string or numeric path segment): 

`grep -E '\?[a-zA-Z_]+=|/[0-9]+' auth_paths_<host>.txt | sort -u` 

For each hit, route by parameter shape: 

- `?id=`, `?uid=`, `?user_id=`, `/user/<n>/`, `/message/<n>/`, `/document/<n>/` → [[IDOR]] 
- `?file=`, `?page=`, `?include=` → [[Local File Inclusion]] → [[Remote File Inclusion]] → [[Path Traversal]] 
- `?url=`, `?redirect=`, `?fetch=` → [[SSRF]] 
- Other user-controlled parameter → [[Injection]]

## 3. Horizontal privilege check

⚠️ AUDIT PENDING

Requires ≥2 walked creds. Submit account A's resource requests (URLs / IDs observed in sub-block 2) using account B's session cookie. Boundary held → note tested-negative. Boundary fell → [[IDOR]] confirmed cross-account access.

## 4. Upload surface (authed)

⚠️ AUDIT PENDING — self-filter design applied, not full V_S audit.

Filter `auth_paths_<host>.txt` for paths with an upload form:

```bash
while read p; do
  curl -s -b '<session_cookie>' "http://<host>:<port>$p" | grep -qiE '<input[^>]*type=["'"'"']?file' && echo "$p"
done < auth_paths_<host>.txt
```

For each hit, walk [[File Upload]] with `<session_cookie>` in scope.

## 5. Profile settings enumeration

⚠️ AUDIT PENDING — self-filter design applied, not full V_S audit.

Filter `auth_paths_<host>.txt` for paths with a form accepting mutation methods (POST / PUT / PATCH / DELETE):

```bash
while read p; do
  curl -s -b '<session_cookie>' "http://<host>:<port>$p" | grep -qiE 'method=["'"'"']?(post|put|delete|patch)' && echo "$p"
done < auth_paths_<host>.txt
```

For each hit, browse the form in Firefox to identify input variety. Route per input type:

- Text input (name, bio, description) → [[Injection]]
- File input (profile pic) → [[File Upload]]
- ID reference field (`user_id`, `owner_id`, `role`) → [[IDOR]]
- URL input (avatar URL, webhook URL) → [[SSRF]]

## 6. Low-EV inputs (authed)

⚠️ AUDIT PENDING — self-filter design applied, not full V_S audit.

Filter `auth_paths_<host>.txt` for paths with text input fields (candidates for stored-input echo — Stored XSS surfaces):

```bash
while read p; do
  curl -s -b '<session_cookie>' "http://<host>:<port>$p" | grep -qiE '<textarea|<input[^>]*type=["'"'"']?text' && echo "$p"
done < auth_paths_<host>.txt
```

For each hit, submit a marker value (`STORED_MARKER_ZZZ`); retrieve the target page in subsequent GET; if marker appears, `STORED_SURFACE` confirmed. Append DEFERRED entries per [[Web Attack Checksheet#2.12 Low-EV input surfaces|WAC 2.12]] pattern.

## 7. Gobuster dir (authed)

⚠️ AUDIT PENDING

Re-run gobuster dir sweep with session cookie for auth-gated directories:

`gobuster dir -u "http://<host>:<port>" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -c '<session_cookie>' -r -o gobuster_auth_dir_<ip>_<port>.txt`

`gobuster dir -u "http://<host>:<port>" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,js,json,bak,log,conf,inc,py -c '<session_cookie>' -r -o gobuster_auth_ext_<ip>_<port>.txt`

## 8. API guessing (authed)

⚠️ AUDIT PENDING — self-filter design applied, not full V_S audit.

Two-part: filter master list for API paths, then probe additional common API endpoints not in the crawl.

Part (a) — filter `auth_paths_<host>.txt` for API paths (URL prefix or JSON content-type):

```bash
while read p; do
  case "$p" in
    /api/*) echo "$p"; continue ;;
  esac
  curl -sI -b '<session_cookie>' "http://<host>:<port>$p" | grep -qi 'content-type: application/json' && echo "$p"
done < auth_paths_<host>.txt
```

Part (b) — probe common API endpoints not in the crawl:

`for p in /api /api/users /api/users/admin /api/messages /api/messages/admin /api/chats /api/admin /api/v1 /api/v2 /graphql; do printf '=== %s ===\n' "$p"; curl -s -b '<session_cookie>' -w "\n[status: %{http_code}]\n" "http://<host>:<port>$p"; done`

For each API endpoint returned, walk API-specific attack techniques (auth bypass on JWT, method sweep, response-based [[IDOR]]).

## 9. Cookies (authed)

⚠️ AUDIT PENDING

Fingerprint the session token, permission claims, CSRF token from post-login Set-Cookie for [[Session Cookie Attacks]] surface:

`curl -s -D - -o /dev/null -b '<session_cookie>' http://<host>:<port>/ | grep -i '^Set-Cookie:'`

## 10. Session fixation & privilege escalation

⚠️ AUDIT PENDING — self-filter design applied, not full V_S audit.

Post-auth-only. Two branches:

Branch 1 — session token attacks. Attempt session token predictability, forced session fixation on the current `<session_cookie>` → [[Session Cookie Attacks]] (session fixation branch).

Branch 2 — vertical privilege escalation. Filter `auth_paths_<host>.txt` for admin-tier paths denied at current session tier:

```bash
while read p; do
  case "$p" in
    /admin*|/manage*|/console*|/dashboard/manage*)
      status=$(curl -s -o /dev/null -w '%{http_code}' -b '<session_cookie>' "http://<host>:<port>$p")
      [ "$status" = "401" ] || [ "$status" = "403" ] && echo "$p"
      ;;
  esac
done < auth_paths_<host>.txt
```

For each hit, attempt tier-lift via known bugs (mass assignment on profile update to set `role=admin`, [[IDOR]] on user role field, JWT payload tampering if session uses JWT).

---

## Routing

- All sub-blocks walked for current cred → [[Web Attack Checksheet#Accumulator re-fire check]]
- Unwalked creds in `creds_<host>.txt` at Setup → next iteration (walks all sub-blocks for the new cred)
- All creds walked → return to caller (WAC linear walk resumes at Exhaustion)
