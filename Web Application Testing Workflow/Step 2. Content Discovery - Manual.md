
## 1. Robots.txt

The robots.txt file is a document that tells search engines which pages they are and aren't allowed to show on their search engine results or ban specific search engines from crawling the website altogether. It can be common practice to restrict certain website areas so they aren't displayed in search engine results. These pages may be areas such as administration portals or files meant for the website's customers. **This file gives us a great list of locations on the website that the owners don't want us to discover as penetration testers**.

`https://the_web_site/robots.txt`

Pay particularly close attention to the URIs listed in the `Disallow` section. If the company does not want search engines to list the resource, it is likely confidential for some reason. Therefore, can you access it, does it provide private information?

## 2. Favicon

Sometimes when frameworks are used to build a website, a favicon that is part of the installation gets leftover, and if the website developer doesn't replace this with a custom one, this can give us a clue on what framework is in use. 

OWASP host a favicon database [[Useful Websites (Web App Pen Testing)]] (https://wiki.owasp.org/index.php/OWASP_favicon_database) of common framework icons that you can use to check against the targets favicon. Once we know the framework stack, we can use external resources to discover more about it.

i. On the website, open the elements inspector and search for the string `favicon`
ii. Find the `link` tag with the `href` to the `favicon`. For example:
    `<img src="/jira-favicon-scaled.png" alt="Custom Jira icon" data-testid="atlassian-navigation--product-home--icon">`

iii. You can now request the `favicon` file and hash it, to see if it is shown on the OWASP website. If it is, you may be able to find which Framework and Version the site was built with. An example:

`andrew@orange:~$ curl https://iprotectu.atlassian.net/jira-favicon-scaled.png | md5sum`

*Knowing the framework and version can be a powerful find as there may be public vulnerabilities in the framework, and the website might not be using the most up to date version. You can then search the for the Framework and the version number and see if there are any publicly available exploits.*

## 3. Sitemap.xml

Unlike the robots.txt file, which restricts what search engine crawlers can look at, the sitemap.xml file gives a list of every file the website owner wishes to be listed on a search engine. These can sometimes contain areas of the website that are a bit more difficult to navigate to or even list some old webpages that the current site no longer uses but are still working behind the scenes. 

This file might inadvertently leak sensitive information, or paths to private information.

`https://iprotectu.com/sitemap_index.xml`

AND

`https://iprotectu.com/sitemap.xml`

## 4. HTTP Headers

When we make requests to the web server, the server returns various HTTP headers. These headers can sometimes contain useful information such as the webserver software and possibly the programming/scripting language in use. In the below example, we can see the webserver is NGINX version 1.18.0 and runs PHP version 7.4.3. Using this information, we could find vulnerable versions of software being used.

user@machine$ curl http://10.10.200.51 -v 
*   Trying 10.10.200.51:80... 
* TCP_NODELAY set 
* Connected to 10.10.200.51 (10.10.200.51) port 80 (#0) 
* GET / HTTP/1.1 
* Host: 10.10.200.51 
* User-Agent: curl/7.68.0 
* Accept: */* 
* Mark bundle as not supporting multiuse 
 
< HTTP/1.1 200 OK 
< Server: nginx/1.18.0 (Ubuntu) 
< X-Powered-By: PHP/7.4.3 
< Date: Mon, 19 Jul 2021 14:39:09 GMT 
< Content-Type: text/html; charset=UTF-8 
< Transfer-Encoding: chunked < Connection: keep-alive`

Simply use `CURL` to fetch the response:

`andrew@orange:~$ curl https://9w9ui5gs.iprotectu.co.uk -v`

## 5. Framework Stack

*Knowing the framework and version can be a powerful find as there may be public vulnerabilities in the framework, and the website might not be using the most up to date version. You can then search the for the Framework and the version number and see if there are any publicly available exploits.*



