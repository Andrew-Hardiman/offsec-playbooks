## ==Scoping==

### Step One: Go to "Target -> Site Map"

In the left hand window there should be a list of URLs. Right-click and select "Add to Scope".

In the window that pops up click "Yes", this will stop Burp from recording out-of-scope items.

### Step Two: Got to "Target -> Scope"

Here we can check our scope, i.e. check if our action in Step One were successful and what we actually intended them to be.

### Step Three: Go to "Proxy -> Proxy Settings"

Even if we have disabled logging for out-of-scope traffic, the proxy will still intercept everything. To prevent this, we need to go to the "Proxy Settings" sub-tab and select "And URL is in the Target Scope", from the "Request Interception Rules" section.

## ==Proxying HTTPS==

When using HTTPS any Web traffic is encrypted. In order to decrypt the Request the private key is needed. The private key is held only by the receiving server. Therefore, to act as an HTTPS proxy, as opposed to a HTTP proxy, Burp Suite will need its own trusted certificate, in order to decrypt and encrypt the Requests and Responses.

To overcome this issue, we can manually add the PortSwigger CA Certificate to our browser's list of trusted certificate authorities.

### Step One: Download the CA Certificate

With the Burp Proxy activated, navigate to "http://burp/cert" (___for this to work Burp Proxy needs to be active and FoxyProxy needs to be active___). This will download a file called "cacert.der". Save this file somewhere on your local machine.

### Step Two: Access Firefox Certificate Settings

Type "about:preferences" into your Firefox URL bar and press Enter.

Search the page for "certificates" and click on the "View Certificates" button.

### Step Three: Import the CA Certificate

In the Certificate Manager Window, click on the import button. Select the "cacert.der" file that you downloaded in the previous step.

### Step Four: Set Trust for the CA Certificate

In the subsequent window that appears, check the box that says "Trust this CA to identify websites" and click OK.

## ==Header and Body Separation==

HTTP messages can contain headers and an optional body. Therefore, two blank lines ("\r\n") are required in a pretty/raw HTTP Request, in order to delimit the headers from the body. ___Note, even if there is no body, the two lines are still required to delimit the end of the Headers section, otherwise the Request will not be correctly structured and will not work.___

