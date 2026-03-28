
## Purpose
Determine whether a request can be replayed statically, or whether fresh state must be obtained before each attempt.

## Use this when
- a request may depend on CSRF tokens
- cookies appear to change
- hidden fields look random
- a request works once but may fail when repeated

## Outcome
- Replayable -> automation likely possible
- Not replayable -> handle fresh state first

## Procedure

1. Send the important request (e.g. POSTing the logging form) to Repeater (be sure to drop it from Proxy Intercept).
2. Send it once and record the result (**If there is a redirection, e.g. a 302, you will likely need to follow it because you need to identify if the entire request flow produces a fresh request state before replaying the target request again. For example, it might be the redirect request itself that refreshes request state by fetching the login form again, this time with a fresh CSRF token**). ***NB - Be sure to open a new HTTP tab in repeater and/or copy the request before following a redirect, as the redirect will likely overwrite your original request, with the redirect request.**** 
3. Send the **exact** same **original** request again without changing anything.
4. Compare the two responses.
5. Decide: 
   - If the exact same request works again (exact same response) -> treat it as **replayable**
   - If the exact same request fails or changes significantly -> treat it as **not statically replayable**