
## Purpose
Use this after [[Fresh State Per Attempt]] once you know exactly which values must be refreshed before each request.

## Burp mechanism
Use a **macro** to fetch the fresh-state request first, then use a **session handling rule** to extract the required values and update the target request before it is sent.

## Preparation 
1. In Burp, send the state-fetching request to **Repeater** if it is not there already.
2. In Repeater, confirm this is the request you want Burp to run before the target request.
3. Send the target request to **Repeater** if it is not there already.
4. In Repeater, confirm this is the request that must receive the fresh values before being sent.

## Build the macro
1. In Burp, go to **Settings** (cog icon, top right-hand corner).
2. Search for **Sessions**.
3. Open the **Macros** section.
4. Click **Add**.
5. Add the state-fetching request to the macro.
6. Save the macro.
7. Give the macro a clear name that says what it fetches, for example:
   - `Fetch login page`
   - `Fetch fresh CSRF`
   - `Fetch checkout state`

## Create the session handling rule

### Scope
1. In Burp, stay in **Settings**.
2. Search for **Sessions**.
3. Open **Session handling rules**.
4. Click **Add**.
5. Open the **Scope** tab.
6. Under **URL scope**, select **Use custom scope**.
7. Click **Add** and enter the full URL of the **target request**.
   - Build this from: **scheme + Host header + path**
   - Example:
     - `POST /admin/login/ HTTP/1.1`
     - `Host: 10.82.140.31`
     - becomes
     - `http://10.82.140.31/admin/login/`
   - Start with the most specific URL you can. ***This is important and needs to be specific to the target request. If the target request is `POST /admin/login/` and the state-fetching request is `GET /admin/login/`, then a URL scope of `http://10.82.140.31/admin/login/` is going to end up covering both of those requests. This might cause a big problem if the response to the POST request is a GET redirect, because the GET redirect will then trigger the session handling rule too, running the macro again, i.e. requesting the state-fetching request yet again, but not triggering the session handling rule that is only tied to the target request. This will create all sorts of problems and confusion.***
   - **Therefore, you must tick `Restrict to request containing these parameters`, and enter a key/parameter, e.g. `username`, that is unique to the target request only.**
   - Finally, under **Tools scope**, select only the Burp tool where you will sent the target request, for example **Repeater** or **Intruder**.

### Details
9. Open the **Details** tab.
10. Under **Rule actions**, click **Add** and choose **Run a macro**.
11. In the action editor, select (by highlighting) the macro you created for the **state-fetching request**.
12. Enable **Update current request with parameters matched from final macro response**.
13. Select **Update only the following parameters and headers**.
14. Click **Edit**, in the **Update only the following parameters and headers** input.
15. In the list window, click **Add** and enter each parameter name you already identified in [[Fresh State Per Attempt]], for example: `loginToken`
16. Click **Close**.
17. Click **OK** to save the action.
18. Save the rule.


## Test the setup
1. Keep one saved **target request** in Repeater as your base request. Open a new HTTP tab and copy the **target request**, this will be the one you use for testing.
2. Open `logger`, right-click and `Clear Log`.
3. In the request change one dynamic value that should be refreshed each time to an obvious stale marker.
4. Send the request with the session handling rule **off**.
5. In **Logger**, inspect the request that was actually sent and confirm the stale marker is still present.
6. Send the same saved request again with the session handling rule **on**.
7. In **Logger**, inspect the request that was actually sent and confirm Burp replaced the stale marker before sending.
8. If Burp replaces the stale value when the rule is on, the setup is working.
9. If it does not, check:
   - whether the rule scope matches the target request
   - whether the macro runs before the target request
   - whether the correct values are listed for updating
   - whether additional values such as cookies also need refreshing

## Outcome
Working with fresh state -> ready for repeated requests in Burp **using the session handling rule you have created**

Still failing -> return to [[Fresh State Per Attempt]]

