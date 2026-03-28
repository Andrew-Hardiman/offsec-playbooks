IDOR stands for Insecure Direct Object Reference and is a type of access control vulnerability.  

This type of vulnerability can occur when a web server receives user-supplied input to retrieve objects (files, data, documents), too much trust has been placed on the input data, and it is not validated on the server-side to confirm the requested object belongs to the user requesting it.

### 1. **An IDOR Example**

Imagine you've just signed up for an online service, and you want to change your profile information. The link you click on goes to http://online-service.thm/profile?user_id=1305, and you can see your information.

Curiosity gets the better of you, and you try changing the user_id value to 1000 instead (http://online-service.thm/profile?user_id=1000), and to your surprise, you can now see another user's information. You've now discovered an IDOR vulnerability!

### 2. **Finding IDORs in Encoded IDs**

You might find a URL that has a base64 encoded ID, for example:

`https://example.com/profile/MTIzNDU=`

If you decode `MTIzNDU=`

`echo -n MTIzNDU= | "base64" -d`

You might get `12345`

**NB: Some services remove the `=` padding or use URL-safe Base64 (`-` and `_` instead of `+` and `/`) to make it nicer in URLs. THEREFORE, YOU MIGHT NEED TO ADD THE `=` YOURSELF, IN ORDER TO SUCCESSFULLY DECODE THE STRING**

Try changing that ID to something else, say `10000` and encoding it back to base64:

`echo -n 10000 | base64` (which will give you `MTAwMDA=`)

You can now try and access the URL with different IDs, which may give you an exploit, such as accessing another user's data:

`https://example.com/profile/MTAwMDA=`

### 3. **Finding IDORs in Hashed IDs**

You might find a URL that has a hashed ID, for example:

`https://example.com/profile/202cb962ac59075b964b07152d234b70`

1. Can you identify the hash [[Identifying Hashes]]
2. If so, can you crack it [[Cracking Hashes]]

If you manage to identify the hash format, and the crack the hash, you will be able to see the underlying format of the string. For instance, in our example, the hash might represent the user's profile/id number. In which case you can try a different id number, hash it using the identified hash format and potentially exploit the system; gain access to another user's data.

### 4. **Finding IDORs in Unpredictable IDs**

If the Id cannot be detected using the above methods, an excellent method of IDOR detection is to create two accounts and swap the Id numbers between them. If you can view the other users' content using their Id number while still being logged in with a different account (or not logged in at all), you've found a valid IDOR vulnerability.

### 5. **Understand where endpoints live**

IDOR vulnerabilities can appear **anywhere your browser communicates with the server**, not just the visible URL. Key places to check:

1. **Visible URLs**
    
    - Standard query parameters: `/profile?user_id=123`
        
    - Hidden URL segments: `/user/123/edit`
2. **Standard HTTP calls**

	- Open your browser DevTools -> Network tab -> make sure `All` is selected

	- Look at the GET calls, look at the `Request URL` in the `Headers` section. Are there any IDs you can manipulate. E.G. `http://example.com/common/file/images?id=12`
	
	- Look at the POST calls, look at the `Payloads` tab. Are there any IDs you can manipulate here: E.G. `profile_id    12` 

3. **AJAX requests / API calls**
    
    - Open your browser DevTools → **Network tab** → filter by `XHR` or `Fetch`
        
    - Look for calls returning JSON or HTML fragments
        
    - Example: `GET /api/user/details?user_id=123`

	- Make sure to check the `Request URL` in the `Headers` section. There might be IDs in the URL, for example: `https://10-10-219-251/api/v1/customer?id=50`
		**These would  not be visible in the Browsers address bar as they are Ajax calls**
		**CHANGE THE ID, SEND THE REQUEST, SEE WHAT YOU GET BACK, ANOTHER USERS DATA?**

4. **JavaScript files**
    
    - Sometimes parameters or endpoints are hard-coded:
        
        `fetch("/api/user/details?user_id=" + currentUser)`
        
    - Look for endpoints or parameter names that might accept input (`user_id`, `account`, `order`, etc.)
        
5. **HTML source / hidden fields**
    
    - Check `<input type="hidden">` fields, data attributes, or meta tags:
        
        `<input type="hidden" name="user_id" value="123">`
        
    - These may allow you to modify the request to target another user.