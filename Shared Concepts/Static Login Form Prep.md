
⚠️ <login_path> = GET path serving the login form. NOT the form's POST target. May differ.

#### Capture form metadata:

`curl -sL http://<host>:<port>/<login_path> | grep -oiE '<(form|input)[^>]*>'`

  From output, set the variables consumed by all downstream techniques:

  - `<login_username_field>` = `name=` of the text or email input
  - `<login_password_field>` = `name=` of the `type=password` input
  - `<login_form_action>` = `action=` of the `<form>` tag (if absent, use `<login_path>`)
  
#### Capture the forwarded static state (state probe):

`~/scripts/statefulness_probe.sh --host=<host> --port=<port> --path=<login_path>`

`ROUTE: burp` (rotating cookies / rotating hidden fields) → you are in the **wrong** playbook, this playbook is specifically **static** login forms only. `ROUTE: shell` → proceed.

- `<login_static_cookies>` = `STATIC_COOKIES` value (e.g. `PHPSESSID=...`)
- `<login_static_hidden_fields>` = `STATIC_HIDDEN_FIELDS` value (raw, pre-encoded `name=value&...`, or empty)
- `<extra_headers>` = operator-supplied, NOT Probe-emitted (the Probe forwards only cookies + hidden fields). Set only if you have manually identified a required request header the Probe cannot see — e.g. a JS-set `X-CSRF-Token: ...` read from the form's JavaScript. Otherwise empty.

#### Hidden fields: 

Wherever `<login_static_hidden_fields_appended>` appears at the end of a POST `-d` body, replace it with `&<login_static_hidden_fields>` if the Probe forwarded any (e.g. `&csrf=abc123`), or with nothing if it didn't.

#### Assemble the always-on request-flag block:

`<req_flags>` = the three always-on header flags, plus a cookie flag only if the Probe forwarded one, plus an extra-header flag only if you set one:

- always: `-H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36' -H 'Referer: http://<host>:<port>/<login_path>' -H 'Origin: http://<host>:<port>'`
- if `<login_static_cookies>` non-empty, append: `-b '<login_static_cookies>'`
- if `<extra_headers>` set, append: `-H '<extra_headers>'`

Resolve these once for the target; the resulting flag string is what you paste for every `<req_flags>` instance.

#### GET-only header block:

`<user_agent_header>` = `-H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36'`

#### Rate limiting profile

Establishes throttling posture. Tunes `<threads>` and `--delay` for `ffuf` commands and the SUCCESS/FAIL oracle probe (next section).

```bash
URL="http://<host>:<port>/<login_form_action>"; for i in $(seq 1 10); do curl -sX POST -o /dev/null -w '[%{http_code}][size:%{size_download}][time:%{time_total}s]\n' <req_flags> -d '<login_username_field>=xyzabc123xxx&<login_password_field>=wrong<login_static_hidden_fields_appended>' "$URL"; done
```

Route on output:

- Any HTTP 429 → hard rate limit. `<threads>` = 1 for all attacks; pass `--delay=<ms>` (500+) to `auth_oracle_probe.sh` in the SUCCESS/FAIL oracle section below.
- Response `time_total` grows across requests → soft throttle. `<threads>` = 1; pass `--delay=<ms>` (a millisecond integer, e.g. `--delay=250`) to `auth_oracle_probe.sh`.
- Response `size` changes at request N → possible lockout at threshold N. Keep any single-username attack under N/2 attempts.
- No changes across all 10 → no lockout observed. `<threads>` = 10 (ffuf) safe. No `--delay` needed on `auth_oracle_probe.sh`.

Save `<threads>` and any `--delay=<ms>` for the SUCCESS/FAIL oracle probe.

#### SUCCESS/FAIL oracle

`~/scripts/auth_oracle_probe.sh --host=<host> --port=<port> --login-path=<login_path> --form-action=<login_form_action> --user-field=<login_username_field> --pass-field=<login_password_field> --cookies='<login_static_cookies>' --hidden-fields='<login_static_hidden_fields>' --extra-headers='<extra_headers>' [--delay=<ms>] [--scheme=<http|https>]`

Set `--delay=<ms>` from rate-limit probe above, if throttling detected. Add `--scheme=https` for TLS targets.

**Route on emitted markers:**

- `CLASS: content|redirect|api` + `ORACLE_SUMMARY: class=<c> confidence=<c>` → shell path OK; capture oracle vars below and proceed.
- `CLASS: basic` + `ROUTE_OUT: Login Bypass Techniques Basic Auth section` → walk [[Login Bypass Techniques#7. HTTP Basic Auth handling]].
- `BAIL: <reason>` (unusual fail status, no stable fail signature, curl failure) → escalate to non-static attack variations. 
- `RATE_LIMITED: sample=<name> <detail>` → target throttled mid-sampling; re-run with higher `--delay`.

**Capture emitted values (substitute textually into the sections below):**

- `<oracle_ffuf>` = value from `ORACLE_FFUF:` line (filter-the-fail matcher/filter block, e.g. `-mc all -fmode and -fc 200 -fr '<marker>'`, or redirect `-mc all -fr 'Location:...'`).
- `<oracle_curl_success_test>` = value from `ORACLE_CURL_SUCCESS_TEST:` line. Wrap it once: `curl_oracle() { <oracle_curl_success_test>; }` — call with `curl_oracle`.
- `<fail_status>` = value from `FAIL_STATUS:` line (e.g. `200`). 
- `<fail_marker>` = string content of the FIRST `FAIL_MARKER_CANDIDATE:` line. Copy the text between the outer double-quotes; the marker itself will typically contain unescaped `"` chars — that's fine, wrap it in single quotes when consuming.

Note the emitted `FAIL_MARKER_CANDIDATE:` lines — ranked alternative markers (form field, error text, etc.) for manual pivot if the primary underperforms. If hits are implausibly few or zero, inspect one real login in Burp before concluding — the oracle is high-recall, not perfect-recall.