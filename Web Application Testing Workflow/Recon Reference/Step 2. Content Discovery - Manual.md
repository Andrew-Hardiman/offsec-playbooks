
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
## 3. Sitemap.xml

Unlike the robots.txt file, which restricts what search engine crawlers can look at, the sitemap.xml file gives a list of every file the website owner wishes to be listed on a search engine. These can sometimes contain areas of the website that are a bit more difficult to navigate to or even list some old webpages that the current site no longer uses but are still working behind the scenes. 

This file might inadvertently leak sensitive information, or paths to private information.

`https://iprotectu.com/sitemap_index.xml`

AND

`https://iprotectu.com/sitemap.xml`

## 4. HTTP Headers

Response headers often leak webserver software, backend framework, and version — **feeds Lookup A/B version-keyed exploit hunting**.

`curl -s -D - -o /dev/null <url>`

- `-s` silent (no progress meter)
- `-D -` dump response headers to stdout
- `-o /dev/null` discard body

Uses GET, so headers represent a real browse. `curl -sI` (HEAD) is shorter but some frameworks/WAFs return different headers on HEAD than GET, or block HEAD entirely — GET form avoids both traps.

Example output — target advertises `Server: nginx/1.18.0` and `X-Powered-By: PHP/7.4.3`:

```
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
X-Powered-By: PHP/7.4.3
Date: Mon, 19 Jul 2021 14:39:09 GMT
Content-Type: text/html; charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
```




