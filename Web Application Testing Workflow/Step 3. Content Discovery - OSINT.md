
## 1. Google Hacking / Dorking

Google hacking / Dorking utilizes Google's advanced search engine features, which allow you to pick out custom content. You can, for instance, pick out results from a certain domain name using the **site:** filter, for example (site:iprotectu.com) you can then match this up with certain search terms, say, for example, the word admin (site:iprotectu.com admin) this then would only return results from the tryhackme.com website which contain the word admin in its content. You can combine multiple filters as well. Here is an example of more filters you can use:

| Filter              | Example                            | Description                                                                             |
| ------------------- | ---------------------------------- | --------------------------------------------------------------------------------------- |
| `site:`             | `site:tryhackme.com`               | Limits results to pages **only on the specified website/domain**.                       |
| `site: + keyword`   | `site:tryhackme.com admin`         | Limits results to the specified site **and includes the keyword anywhere in the page**. |
| `inurl:`            | `inurl:admin`                      | Returns pages where the **URL contains the specified word** (e.g., “admin” in the URL). |
| `site: + inurl:`    | `site:tryhackme.com inurl:admin`   | Returns pages on the specified site where the **URL contains the given word**.          |
| `filetype:`         | `filetype:pdf`                     | Returns pages that are **of the specified file type** (e.g., PDF documents).            |
| `site: + filetype:` | `site:tryhackme.com filetype:pdf`  | Returns PDF files **only from the specified site**.                                     |
| `intitle:`          | `intitle:admin`                    | Returns pages where the **page title contains the specified word**.                     |
| `site: + intitle:`  | `site:tryhackme.com intitle:admin` | Returns pages on the specified site with the keyword in the page title.                 |

## 2. wappalyzer

https://www.wappalyzer.com/

Find out the technology stack of any website, using `wappalyzer` [[Useful Websites (Web App Pen Testing)]]

Install the free browser extension to see the technologies used on websites you visit.

## 3. Wayback Machine

https://archive.org/web/

The Wayback Machine [[Useful Websites (Web App Pen Testing)]] is a historical archive of websites that dates back to the late 90s. You can search a domain name, and it will show you all the times the service scraped the web page and saved the contents. This service can help uncover old pages that may still be active on the current website.

## 4. GitHub

To understand GitHub, you first need to understand Git. Git is a **version control system** that tracks changes to files in a project. Working in a team is easier because you can see what each team member is editing and what changes they made to files. When users have finished making their changes, they commit them with a message and then push them back to a central location (repository) for the other users to then pull those changes to their local machines. GitHub is a hosted version of Git on the internet. Repositories can either be set to public or private and have various access controls. You can use GitHub's search feature to look for company names or website names to try and locate repositories belonging to your target. Once discovered, you may have access to source code, passwords or other content that you hadn't yet found.

## 5. S3 Buckets

S3 Buckets are a storage service provided by Amazon AWS, allowing people to save files and even static website content in the cloud accessible over HTTP and HTTPS. The owner of the files can set access permissions to either make files public, private and even writable. Sometimes these access permissions are incorrectly set and inadvertently allow access to files that shouldn't be available to the public. The format of the S3 buckets is http(s)://**{name}.**[**s3.amazonaws.com**](http://s3.amazonaws.com/) where {name} is decided by the owner, such as [tryhackme-assets.s3.amazonaws.com](http://tryhackme-assets.s3.amazonaws.com). S3 buckets can be discovered in many ways, such as finding the URLs in the website's page source, GitHub repositories, or even automating the process. One common automation method is by using the company name followed by common terms such as **{name}**-assets, **{name}**-www, **{name}**-public, **{name}**-private, etc.

## 6. Shodan

- Site: [https://shodan.io](https://shodan.io)
- Search: `hostname:<domain>` or `ip:<target_ip>`

Record: 

- Open ports: 
- Service banners: 
- Flagged CVEs: