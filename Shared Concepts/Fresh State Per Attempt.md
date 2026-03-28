## Purpose
Use this when an HTTP request is not statically replayable and each attempt requires fresh state.

## Goal - to identify the moving parts
Confirm exactly what must be refreshed before each attempt:
- CSRF token
- session cookie
- hidden form field(s)
- all of the above

## Test

1. Send the real target request (e.g. the login POST request) request to Burp Repeater.
2. Send the corresponding state-fetching request (e.g. the login page GET request) to Burp Repeater as well.
3. Send the GET request first, then inspect the response for fresh values such as **CSRF** token, **Set-Cookie**, and **hidden** fields.
4. Compare the fresh values from the GET **response** against the values currently used in the POST **request**.
5. The values that are different between the GET **response** and the POST **request** are the values that must be refreshed in the POST **request** prior to it being sent each time (you can also check which values change in the GET **response** each time).
6. Decide exactly what must be refreshed before each attempt:
   - **CSRF** token only
   - session cookie only
   - **hidden** field(s) only
   - a combination of these

Next: [[Automating Fresh State in Burp]]. Take with you the exact list of values that must be refreshed before each request (i.e. the outcome/decision from step 6 above).