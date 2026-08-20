
### 1. Username Enumeration

If you can find a "Sign-Up" page, you may be able to discover existing usernames, depending on whether or not the application gives you a message along the lines of "Username already taken". (**I.E. it gives you something that let's you know the sign up failed due to the username field being wrong, as opposed to the password field being wrong).**

**YOU COULD ACTUALLY DO THIS FROM A 'SIGN IN' PAGE ALSO, BUT YOU WOULD WANT TO GET AN EXPLICIT 

For example:
1. You find a customer sign up page. It has four fields; username, email address, password, confirm password.
2. You enter `admin` in the username field and click the "Sign Up" button. 
3. The application returns the error message "An account with this username already exists"

**Step three is the really crucial part. If you know what message the application returns when the username is already taken, you can fuzz the sign up form with a wordlist of usernames and record the usernames that return that message. Hence, creating yourself a list of valid application usernames.**

`ffuf -w /usr/share/seclists/Usernames/Names/names.txt -X POST -d "username=FUZZ&email=x&password=x&cpassword=x" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.190.207/customers/signup -mr "username already exists" -o found_usernames.csv -of csv`
  
-w | This the wordlist containing the strings/names that you will be using to FUZZ the form
-X  | HTTP Method (Check this matches the actually method type the form uses)
-d  | The data we will send with the request. Try and match closely with a real form submission, you can always submit the form and look in network at the Request. **Enter `x` as value to most inputs, but enter `FUZZ` as the value of the field you want to FUZZ.**
-H | Content type
-U | Make sure this is the URL the form is sent to, again check Network tab if unsure. Or check the `form` tab in `sources`. 
-mr | The application return message that lets you know you have a match, can be a substring of it.
-o  | Save the output to a file for review. You will then use this 'found' name list with techniques below.

**Finally, once you have your valid output in `csv` format, you can run the following command to simply extract a `txt` file of the found usernames only, effectively removing the rest of the scan output.**

`cut -d ',' -f1 found_usernames.csv | grep -v '^input' > found_usernames.txt`

#### 1.1 Appending domain names to the username list

The above example uses the file `names.txt` for enumeration purposes. Therefore, it is assuming the usernames for the application are simply just names, such as "sally" or "wayne". However, many applications use email address etc. If you are aware that the application uses a format such as "wayne@iprotectu.co.uk", as opposed to just "wayne", then you will need to create a new list from the `names.txt` file, adding the domain to each name in the list. You can do so using the following command:

`sed 's/$/@iprotectu.co.uk/' names.txt > names_iprotectu.txt`

### 2. Brute Force

##### **==Important to Note:==** Before automating login attempts, check [[Testing Replayability in Burp]]. Determine whether the request is **Replayable** or **Not statically replayable**, then return here and follow the correct outcome branch.

Outcome:
- Replayable -> continue below
- Not statically replayable -> follow [[Fresh State Per Attempt]]

#### **Option A — Hydra (command line)**

We can use Hydra to brute force web forms too. You must know which type of request it is making; GET or POST (methods).

`hydra -l <username> -P <wordlist> MACHINE_IP/DOMAIN http-<METHOD>-form "/:username=^USER^&password=^PASS^:F=incorrect" -V`

| Part                                              | Meaning                                                                                        |
| ------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `-l <username>`                                   | Try the username `username` (you can also use `-L` with a file of usernames)                   |
| `-P wordlist.txt`                                 | Use `wordlist.txt` as the list of passwords to try                                             |
| `MACHINE_IP/DOMAIN`                               | Target IP address or Target Domain (note this is domain, note full URL, do not include scheme) |
| `http-post-form`                                  | Tells Hydra you're attacking a form that submits via POST                                      |
| `"/:username=^USER^&password=^PASS^:F=incorrect"` | Format, each section separated by `:`                                                          |

- `/` is the path (`/` in the example) **Be sure to check this, is it actually `/login` or something similar, check the network tab in the browser.**
    
- `username=^USER^&password=^PASS^` are the POST parameters (Hydra replaces ^USER^ and ^PASS^) **Not every form uses `username` and `password` as the field names. You must match the actual names used in the HTML form**
    
- `F=incorrect` tells Hydra what to look for in the response to detect **failure** (e.g., `"Login incorrect"`) **You need to find an actual string in the response that only appears when login fails, and use that for the `F=` part.

#### **Option B — ffuf (command line)**

In order to use this technique you must have built a list of known valid usernames, either through using the technique shown above, `1. Username Enumeration`, or through some other technique.

In our example, we are assuming we have a simple list of valid usernames in the following `txt` file: `found_usernames.txt`.
 
Run this command:

`ffuf -w found_usernames.txt:W1,/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt:W2 -X POST -d "username=W1&password=W2" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.190.207/customers/login -fr "Invalid Password"`

This means:

- FFUF is performing a **POST-based login brute-force attack** using two wordlists (`W1` for usernames, `W2` for passwords).
- `-fr` This is the unique identifier/string, that lets you filter out invalid log in attempts (in other words identify successful attempts). In the example above we are saying that we know all invalid responses contain the string "Invalid Password". Therefore, if we filter out all attempts that return a response containing that string, we know that any attempts that do get printed to the terminal are VALID log in attempt.

**NB: You need to filter out the INVALID login attempts in some way. So submit a deliberately invalid request and take note/use one of the following: 

1. Take note of a string in the response that is unique to invalid login attempts. In this case use `-fr "Noted invalid string found in response body"`
2. Is the response code different in a invalid attempt to a valid login attempt? In this case filter out the responses that contain the response code you know to be invalid `-fc 200`

You can use `-mc` to match codes
You can use `-fc` to filter out codes

Number 2, above, can be tricky. INVALID attempts might return a `200`, with an error message, but VALID attempts might return a `200` also. Likewise, INVALID attempts might return a `302`, i.e. redirect you to the login page, but VALID attempts might return a 302 also, i.e. redirect you to the welcome page.

In case of a `302` you can follow redirects like so, with the `r` option:

`ffuf -w found_usernames.txt:W1,password_list.txt:W2 -X POST -d "username=W1&password=W2" -H "Content-Type: application/x-www-form-urlencoded" -u http://hands.appl/login -r`

However, this likely will not help much, as both INVALID and VALID log in attempts likely follow this pattern:

INVALID REQUEST -> response 302 -> NEW REQUEST -> response 200 (login page)
VALID REQUEST -> response 302 -> NEW REQUEST -> response 200 (Welcome page)

What you can do, however, is look at the "size" of the invalid responses in the terminal output. Then filter out the responses by that size, leaving you with just the VALID responses.

`ffuf -w found_usernames.txt:W1,password_list.txt:W2 -X POST -d "username=W1&password=W2" -H "Content-Type: application/x-www-form-urlencoded" -u http://hands.appl/login -r -fs X`

Where `X` is the size of the invalid response.

### 3. Credential Stuffing  
  
**Purpose:** test known or plausibly leaked username/password pairs against the target login.  
  
Credential stuffing is different from normal brute force.  
  
- **Brute force** = trying many possible passwords against one or more usernames  
- **Credential stuffing** = trying **known username/password pairs** that are already linked together  
  
This attack works because users often reuse the same credentials across multiple platforms.  
  
---  
  
#### Use this when  
- you already have a list of known username/password pairs  
- the username and password values are meant to stay aligned  
- you suspect password reuse across services  
- you want to test leaked or recovered credentials quickly  
  
---  
  
#### Do not use this when  
- you only have usernames and need to guess passwords  
- you need to try every username against every password  
- you are performing a normal login brute-force attack rather than testing known pairs  
  
In those cases:  
- use **Brute Force** if you have valid usernames and want to try many password guesses  
- use **Cluster Bomb** if you need every username/password combination  
  
---  

##### **==Important to Note:==** Before automating login attempts, check [[Testing Replayability in Burp]]. Determine whether the request is **Replayable** or **Not Statically Replayable**, then return here and follow the correct branch below.

---
#### **Replayable branch**

1. Capture a normal login request in Burp Suite and send it to **Intruder**.  
2. Mark the **username** field and **password** field as payload positions.  
3. Select the **Pitchfork** attack type.  
4. Load the username list into payload set 1.  
5. Load the password list into payload set 2.  
6. Start the attack.  
  
**Why Pitchfork?**  
Because Pitchfork keeps both lists aligned row by row:  
  
- row 1 username + row 1 password  
- row 2 username + row 2 password  
- row 3 username + row 3 password  
  
That is exactly what credential stuffing needs.  
  
Example:  
  
- `wayne@company.com` + `Summer2024!`  
- `sally@company.com` + `Password123`  
- `admin@company.com` + `Welcome1`  
  
Pitchfork will test those as pairs.  

#### **Not Statically Replayable branch**

Follow [[Fresh State Per Attempt]]. Return here once Burp can refresh the required values before each attempt, i.e. the appropriate macro(s) and session handling rule(s) are in place.  
  
Then continue with the same **Pitchfork** credential-stuffing workflow as above (Replayable branch).

#### Watch for successful logins  
You still need a way to identify success.  
  
Look for one or more of the following:  
- different response length  
- different status code  
- redirect to a different location  
- absence of the normal login error message  
- presence of logout/dashboard/account content  
- session cookie changes that suggest authentication succeeded  
- different response body [[Comparer]]
  






  




