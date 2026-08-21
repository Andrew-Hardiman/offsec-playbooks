Examining and editing the cookies set by the web server during your online session can have multiple outcomes, such as unauthenticated access, access to another user's account, or elevated privileges.

### 1. **Plain Text**

Although rare, you might find cookies that are sent in plain text. For example:

| Name      | Value |
| --------- | ----- |
| logged_in | false |
| admin     | false |

If the application in question is simply relying on these values to determine if the user is a) logged in and b) an admin. Then you could simple send a request and change the values to `true`:

`curl -H "Cookie: logged_in=true; admin=false" http://IP_ADDRESS/TARGET_URI`

OR (even worse):

`curl -H "Cookie: logged_in=true; admin=true" http://IP_ADDRESS/TARGET_URI`


### 2. **Hashing**

Sometimes cookie values can look like a long string of random characters; these are called hashes which are an irreversible representation of the original text. Here are some examples that you may come across:

| Original String | Hash Method | Output                                                                                                                           |
| --------------- | ----------- | -------------------------------------------------------------------------------------------------------------------------------- |
| 1               | md5         | c4ca4238a0b923820dcc509a6f75849b                                                                                                 |
| 1               | sha-256     | 6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b                                                                 |
| 1               | sha-512     | 4dff4ea340f0a823f15d3f4f01ab62eae0e5da579ccb851f8db9dfe84c58b2b37b89903a740e1ee172da793a6e79d560e5f7f9bd058a12a280433ed6fa46510a |
| 1               | sha1        | 356a192b7913b04c54574d18c28d46e6395428ab                                                                                         |


### 3. **Encoding**

Encoding is similar to hashing in that it creates what would seem to be a random string of text, but in fact, the encoding is reversible.

Common encoding types are base32 which converts binary data to the characters A-Z and 2-7, and base64 which converts using the characters a-z, A-Z, 0-9,+, / and the equals sign for padding.

Let us say for example you find a cookie that looks like this:

| Name    | Value                          |
| ------- | ------------------------------ |
| session | eyJpZCI6MSwiYWRtaW4iOmZhbHNlfQ |

If you run the following command:

`echo -n 'eyJpZCI6MSwiYWRtaW4iOmZhbHNlfQ' | base64 -d`

You will get the output:

`{"id":1,"admin":false}`

(If you had a base 32 encoded string you would use `echo -n 'BASE32STRING' | base32 -d`)

**We can then simply encode this back to base64 again but this time set the admin value to true, which now gives us admin access.**

1. `touch encode_me`
2. `nano encode_me` and add {"id":1,"admin":true}`
3. `base64 encode_me`

The new cookie value for you to use in your exploit will be printed to the terminal.
