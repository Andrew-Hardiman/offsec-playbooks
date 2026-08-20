Sometimes authentication processes contain logic flaws. A logic flaw is when the typical logical path of an application is either bypassed, circumvented or manipulated by a hacker.

For example, the below mock code checks to see whether the start of the path the client is visiting begins with /admin and if so, then further checks are made to see whether the client is, in fact, an admin. If the page doesn't begin with /admin, the page is shown to the client.

php

if( url.substr(0,6) === '/admin') {
    # Code to check user is an admin
} else {
    # View Page
}
`
Because the above PHP code example uses three equals signs it's looking for an exact match on the string, including the same letter casing. The code presents a logic flaw because an unauthenticated user requesting **/adMin** will not have their privileges checked and have the page displayed to them, totally bypassing the authentication checks.

---

### 1. Logic Flaw in Reset Password Form

Can you find a form asking you for the email address associated with the account on which we wish to perform a password reset. 






If an invalid email is entered, you'll receive the error message "**Account not found from supplied email address**".
