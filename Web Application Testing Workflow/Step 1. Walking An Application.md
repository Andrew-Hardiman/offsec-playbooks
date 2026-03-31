
More often than not, automated security tools and scripts will miss many potential vulnerabilities and useful information. Therefore, you should execute the following Playbook to manually 'walk' a Web application, before you do anything else.

### 1. View Page Source (NB: This is difference to Element Inspector)

Right-click on the page and select `View Page Source`
#### 1.1 Search Source for Comments

Search for `<!--` , there may be comments left behind by developers that give anyway more information than they should.

#### 1.2 Page Links

You may discover some private area used by the business for storing company/staff/customer information, or a hidden link. Search for `href`. For example:

`<p class="welcome-msg">Our dedicated staff are ready <a href="/secret-page">to</a> assist you with your IT problems.</p>`

Click on the hyperlink to be redirected to the page. You may be able to access information that should not be private.

#### 1.3 Links to External Files

External files such as CSS, JavaScript and Images can be included (`link` tags) using the HTML code. Search for `link`. For example:

`<link rel="stylesheet" href="/assets/bootstrap.min.css">`

and

`<link rel="stylesheet" href="/assets/style.css">`

Here you can see these external files and all stored in the directory `/assets`. 

If you navigate to this directory, what should be displayed is either a blank page or a 403 Forbidden page with an error stating you don't have access to the directory. If the system is not configured correctly, i.e. the directory listing feature has been enabled, it could in fact, list every file in the directory. *Sometimes this isn't an issue, and all the files in the directory are safe to be viewed by the public, but in some instances, backup files, source code or other confidential information could be stored here.*

#### 1.4 Web Application Framework

Viewing the page source can often give us clues into whether a framework is in use and, if so, which framework and even what version. Knowing the framework and version can be a powerful find as there may be public vulnerabilities in the framework, and the website might not be using the most up to date version.

Search for `<!--`. You may find something like this:

`<!--
Page Generated in 0.05235 Seconds using the THM Framework v1.2
-- >`

You can then search the for the Framework and the version number and see if there are any publicly available exploits.

#### 1.5 Form Action Attributes

Search for `<form`. Check the `action` attribute of every form — it defines where the form data is actually sent, which may differ entirely from the page's origin.

```html
<form action="https://third-party.com/endpoint" method="POST">
```

Note any endpoints that:

- Point to third-party domains (sensitive data leaving the app)
- Point to internal endpoints not discoverable any other way
- Could be tampered with via parameter manipulation

### 2. Element Inspector

The page source doesn't always represent what's shown on a webpage; this is because CSS, JavaScript and user interaction can change the content and style of the page, which means we need a way to view what's been displayed in the browser window at this exact time. Element inspector assists us with this by providing us with a live representation of what is currently on the website.

**As well as viewing this live view, we can also edit and interact with the page elements.**

For example, many websites block additional content behind paywalls. If you right-click on the pop-up that appears to inform you of this, you will be able to inspect the elements/HTML that create this message and perform the block.

Many of these blockers are simply HTML classes and applied CSS. For example, you might see HTML like this:

`<div class="premium-customer-blocker">`
    `<h3>This Article Is For Our Premium Customers</h3>`
    `<p>Please talk to a member of staff about upgrading your account today</p>`
	`<a href="/contact" class="btn btn-success">Contact Us</a>`
`</div>`

In this instance, click on the the class `premium-customer-blocker` to view the HTML/CSS/JavaScript that is applied. You might find some applied CSS, for example:

div.premium-customer-blocker {
  display: block;
  position: absolute;
  top: 0;
  left: 0;
  margin-top: 60px;
  width: 100%;
  height: 100%;
  background-color: #FFF;
  border: 2px solid #000;
  text-align: center;

**Try changing `display: block` to `display: none`**

### 3. Sources/Debugger

**In Firefox and Safari, this feature is called Debugger, but in Google Chrome, it's called Sources.**

In both browsers, on the left-hand side, you see a list of all the resources the current webpage is using. Clicking on any of these files, e.g. `.js` files, will display the contents of the file.

**Many times when viewing JavaScript files, you'll notice that everything is on one line, which is because it has been minimised, which means all formatting ( tabs, spacing and newlines ) have been removed to make the file smaller. I.E. it has been obfuscated, which makes it purposely difficult to read, so it can't be copied as easily by other developers.**

*If you load the file, then right-click on the tab that opens, you will be able to select `Print pretty source`, to make it a little more readable (although due to obfuscation, it may still be difficult to comprehend the code).*

**You can add break points in the code, refresh the page and step-debug**

### 4. Network

The network tab on the developer tools can be used to keep track of every external request a webpage makes. If you click on the Network tab and then refresh the page, you'll see all the files the page is requesting.
