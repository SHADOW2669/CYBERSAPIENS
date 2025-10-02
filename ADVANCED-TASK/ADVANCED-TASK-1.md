## What is Sensitive Information Disclosure?

Sensitive Information Disclosure, also known as an information leak, is a web application vulnerability where a system unintentionally reveals data that can be used by an attacker. This data can aid in compromising the application, its users, the underlying infrastructure, or the associated business.

The severity of this vulnerability depends on the type of information disclosed. Examples of sensitive information include:

* **User & Customer Data:**
    * Personally Identifiable Information (PII) like names, addresses, phone numbers, social security numbers.
    * Financial information such as credit card numbers and bank account details.
    * Authentication credentials like usernames, passwords, and API keys.

* **Technical Information:**
    * **Error Messages:** Verbose error messages can reveal stack traces, database queries, internal file paths, and framework versions. For example, a database error might leak table or column names.
    * **Server & Software Versions:** Headers like `Server: Apache/2.4.29 (Ubuntu)` can tell an attacker the exact software version you are running, allowing them to search for known exploits (CVEs) for that version.
    * **Source Code:** Comments in HTML/CSS/JavaScript or exposed source code from version control systems (`.git` directory) can reveal business logic, hidden endpoints, or hardcoded credentials.

* **Business Information:**
    * Internal business data, trade secrets, or future plans that might be found in accessible documents or backups.
    * Internal network architecture details, IP addresses, and hostnames.

The root cause is often a lack of proper configuration, insufficient input validation, or developers leaving behind debugging information in a production environment.

---

## What are the techniques & tools to find Sensitive Information Disclosures?

Finding these vulnerabilities involves a combination of manual investigation and automated tooling.

#### **Techniques:**

1.  **Directory & File Brute-forcing (Fuzzing):**
    * This involves using a wordlist of common directory and file names to guess hidden locations on a web server. This can uncover backup files (`config.bak`), temporary files (`data.zip`), administration portals (`/admin`), and exposed version control folders (`/.git/`).

2.  **Analyzing Publicly Available Files:**
    * **`robots.txt`:** This file tells search engines which pages not to crawl. While not a security feature, it often points to sensitive or unlinked directories that the site owner wants to hide.
    * **`sitemap.xml`:** Provides a map of all pages on a site, which can sometimes reveal more than the public-facing navigation does.
    * **Source Code Analysis:** Manually reading HTML comments, JavaScript files, and CSS files can reveal comments left by developers, API endpoints, and sometimes even credentials.

3.  **Google Hacking (Dorking):**
    * Using advanced Google search operators to find sensitive information indexed by search engines. For example:
        * `site:example.com filetype:log` (to find log files)
        * `inurl:admin.php` (to find admin login pages)
        * `intitle:"index of" "backup"` (to find exposed backup directories)

4.  **Inspecting HTTP Headers:**
    * Server response headers can leak technology information. Headers like `Server`, `X-Powered-By`, and `X-AspNet-Version` can give away the webserver, backend language, and framework versions.

5.  **Triggering Error Messages:**
    * Submitting invalid or unexpected input to forms and URL parameters can cause the application to crash and return a detailed error message, revealing stack traces, file paths, or database queries.

6.  **Version Control System Exploitation:**
    * If a developer accidentally leaves the `.git` directory exposed on the web server, attackers can download it to reconstruct the entire source code repository, including past versions and commit history, which may contain removed secrets or passwords.

#### **Tools:**

* **Web Proxies:**
    * **Burp Suite:** An industry-standard tool for intercepting and manipulating web traffic. It's essential for inspecting HTTP requests and responses in detail.
    * **OWASP ZAP:** A free and open-source alternative to Burp Suite with similar functionality.

* **Directory & Content Discovery Tools:**
    * **Gobuster:** A fast command-line tool for brute-forcing URIs (directories and files), DNS subdomains, and virtual host names.
    * **Dirb / Dirbuster:** Classic tools for content discovery.
    * **ffuf (Fuzz Faster U Fool):** A very fast and flexible command-line fuzzer used for finding hidden files and directories.

* **Version Control Tools:**
    * **GitTools:** A suite of tools (`Finder`, `Dumper`, `Extractor`) specifically designed to find and download exposed `.git` repositories from web servers.

* **Information Gathering Tools:**
    * **Nmap (Network Mapper):** Can be used for version scanning to identify services and their versions running on a server.
    * **Wappalyzer / WhatWeb:** Identifies technologies used on websites, such as frameworks, server software, and analytics tools, which helps focus your security testing.
 
### References

  * [https://owasp.org/www-project-top-ten/2017/A3\_2017-Sensitive\_Data\_Exposure](https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure)
  * [https://owasp.org/www-project-web-security-testing-guide/v4.2/4-Web\_Application\_Security\_Testing/01-Information\_Gathering](https://www.google.com/search?q=https://owasp.org/www-project-web-security-testing-guide/v4.2/4-Web_Application_Security_Testing/01-Information_Gathering)
  * [https://portswigger.net/web-security/information-disclosure](https://portswigger.net/web-security/information-disclosure)
  * [https://tryhackme.com/path/outline/web](https://tryhackme.com/path/outline/web)
  * [https://www.hackerone.com/hackers/hacker101](https://www.hackerone.com/hackers/hacker101)
  * [https://www.exploit-db.com/google-hacking-database](https://www.exploit-db.com/google-hacking-database)
  * [https://github.com/internetwache/GitTools](https://github.com/internetwache/GitTools)
  * [https://portswigger.net/burp/documentation](https://portswigger.net/burp/documentation)
