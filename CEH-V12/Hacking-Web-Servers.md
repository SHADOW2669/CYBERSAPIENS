# Hacking Web Servers

## 1. What is a Web Server and How Does it Work?

A **Web Server** is a computer program that stores web content (like HTML pages, CSS stylesheets, JavaScript files, and images) and delivers it to users' web browsers upon request. The most common web server software includes Apache, Nginx, and Microsoft IIS.

### Core Components
* **Physical/Virtual Server:** The underlying hardware and operating system (e.g., Linux, Windows Server).
* **Web Server Software:** The application that handles HTTP/S requests (e.g., Apache).
* **Web Content:** The actual files that make up the website.
* **Database Server:** Stores dynamic data for the website (e.g., MySQL, PostgreSQL).

### How It Works: The Request-Response Cycle
1.  **Request:** A user types a URL (e.g., `http://www.example.com`) into their web browser. The browser sends an **HTTP Request** to the web server's IP address.
2.  **Processing:** The web server receives the request, finds the requested file (`index.html` in this case), and processes it. If it's a dynamic page, it may query a database.
3.  **Response:** The server sends back an **HTTP Response** containing the requested content and a status code (e.g., `200 OK`).
4.  **Rendering:** The user's web browser receives the response and renders the content, displaying the webpage.

---

## 2. Common Web Server Security Issues (and their Impact)

As your slide indicates, web servers are vulnerable when their configuration is weak. An attacker's goal is to exploit these misconfigurations.

| Security Issue | Impact / Why it's a Problem |
| :--- | :--- |
| **Server installed with default settings.** | Defaults are publicly known and often include weak security settings or sample pages with vulnerabilities. |
| **Improper file and directory permissions.** | Can allow an attacker to read sensitive files (e.g., `wp-config.php`), or write/execute a malicious file (a web shell). |
| **Enabling of unnecessary services.** | Every running service (like FTP, Telnet, or remote admin) increases the attack surface, providing more potential entry points. |
| **Priority given to ease of usage rather than security.** | Disabling security features for convenience (e.g., turning off a WAF) can leave the server exposed. |
| **Lack of proper security policies and maintenance.** | Without a plan for patching, monitoring, and responding to incidents, the server will eventually become vulnerable. |
| **Improper authentication with external systems.** | Using weak or hardcoded credentials to connect to databases or APIs can allow an attacker to pivot to other systems. |
| **Default account credentials are used.** | Attackers have lists of default usernames and passwords (e.g., `admin`/`admin`) and will always try them first. |
| **Software not updated regularly.** | Unpatched web servers, CMS (like WordPress), or OS versions have known vulnerabilities (CVEs) that can be easily exploited. |
| **Misconfigured SSL certificates and encryption.** | Using weak encryption ciphers or expired certificates can allow attackers to perform Man-in-the-Middle (MitM) attacks. |
| **Unnecessary default, backup, or sample files not deleted.** | These files can leak information about the server's configuration, framework versions, or even contain old credentials. |

---

## 3. Types of Web Server Attacks

The following attack types, listed on your slide, are common methods used to compromise web servers:

* **DoS/DDoS:** Overwhelming the server with traffic to make it unavailable to legitimate users.
* **DNS Server Hijacking / Amplification:** Manipulating the DNS system to redirect users to a malicious site or use DNS servers to amplify a DDoS attack.
* **Directory/Path Traversal:** Using sequences like `../` to navigate outside the web root directory and access sensitive system files (e.g., `/etc/passwd`).
* **MITM Attacks:** Intercepting the communication between a user and the web server to steal or modify data.
* **Website Defacement:** Illegally changing a website's visual appearance, often to display the attacker's message.
* **Webserver Password Cracking / Brute Forcing:** Using tools like THC Hydra to guess credentials for services running on the server (FTP, SSH, admin panels).
* **HTTP Response Splitting:** An attack where the attacker can send a single HTTP request that is interpreted by the server as two separate responses, allowing for cache poisoning and other attacks.
* **Web Cache Poisoning:** Forcing the server's cache to store and serve malicious content to other users.
* **SSRF (Server-Side Request Forgery):** A vulnerability where an attacker can force the web server to make requests to internal or external resources on their behalf.

---

## 4. Web Server Attack Methodology (The Hacking Lifecycle)

An ethical hacker follows a structured process to test a web server's security.

1.  **Information Gathering (Reconnaissance):** Collect basic information about the target, such as IP addresses, domains, and technologies used (e.g., using `whois`, `nslookup`).
2.  **Web Server Footprinting:** Actively probe the server to identify its OS, web server software version, and running services. This is also known as **Banner Grabbing**.
3.  **Mirroring a Website:** Using tools like **HTTrack** to download a complete copy of a website. This allows the attacker to analyze its structure, find comments in the source code, and examine scripts offline for vulnerabilities.
4.  **Vulnerability Scanning:** Using automated tools like **Nessus** or **Nikto** to scan the web server for known vulnerabilities, misconfigurations, and outdated software.
5.  **Session Hijacking:** Stealing a user's session cookie to impersonate them and gain unauthorized access.
6.  **Gaining & Maintaining Access:** Exploiting a vulnerability to gain control (e.g., by uploading a web shell) and then establishing persistence to maintain access over time.

---

## 5. Web Server Penetration Testing Tools and Commands

As shown in your notes, specific tools are used during a penetration test to footprint and attack a web server.

### A. Using Telnet for Banner Grabbing
**Telnet** is a simple, text-based client. You can use it to manually connect to a web server's port (like port 80 for HTTP) and send a basic HTTP request to see the server's response headers, which often contain its version information.

* **Command:** `telnet <IP Address> 80`
* **Example from your notes:** `telnet 65.61.137.117 80`
* **How it works:** After connecting, you would manually type `GET / HTTP/1.1` and press Enter twice. The server's response will include headers like `Server: Apache/2.4.52 (Ubuntu)`.

### B. Using Netcat for Banner Grabbing
**Netcat (`nc`)** is often called the "Swiss-army knife of networking." It's more powerful than Telnet and is used for similar banner grabbing tasks.

* **Command:** `nc -vv <domain.name> <Port>`
* **Explanation:**
    * `nc`: The Netcat command.
    * `-vv`: Very verbose. Shows detailed connection information.
    * `<domain.name> <Port>`: The target and the port to connect to.
* **How it works:** Similar to Telnet, after connecting you would type a basic HTTP request to get the server's banner.

### C. Using Nmap Scripting Engine (NSE) for Footprinting
**Nmap** is a powerful network scanner. Its scripting engine (NSE) uses Lua scripts to automate advanced scanning and vulnerability detection tasks.

* **Command 1:** `nmap --script https-trace -d <Domain.name>`
    * **Explanation:** This runs the `https-trace` script, which checks if the `TRACE` method is enabled on the server. An enabled `TRACE` method can sometimes be used for Cross-Site Tracing (XST) attacks.
* **Command 2:** `nmap --script hostmap-bfk --script-args hostmap-bfk.prefix=<prefix> <domain.name>`
    * **Explanation:** This runs the `hostmap-bfk` script, which is used to discover virtual hosts (different websites running on the same IP address) by brute-forcing potential hostnames.

### D. Perform FTP Bruteforcing using THC Hydra
**THC Hydra** is a very fast and popular password cracking tool used to perform brute-force attacks against many different network services.

* **Command from your notes:** `hydra -L ../../Usernames.txt -P ../../Passwords.txt ftp://<Target IP>`
* **Explanation:**
    * `hydra`: The command to run the tool.
    * `-L ../../Usernames.txt`: Specifies the path to the list of usernames to try.
    * `-P ../../Passwords.txt`: Specifies the path to the list of passwords to try.
    * `ftp://<Target IP>`: Specifies that the attack protocol is FTP and defines the target server.

---

## 6. Countermeasures and Mitigation Strategies

To defend a web server, a layered security approach is required:

* **Harden the Server:**
    * Change all default passwords.
    * Remove or disable unnecessary services, modules, and sample files.
    * Apply proper file and directory permissions (e.g., web files should not be executable).
* **Regular Patch Management:** Consistently update the OS, web server software, and all applications (like WordPress, Joomla) to patch known vulnerabilities.
* **Use a Web Application Firewall (WAF):** A WAF can detect and block common web attacks like SQL Injection and XSS before they reach the server.
* **Secure Configuration:** Properly configure SSL/TLS with strong encryption ciphers.
* **Use Strong Authentication:** Enforce strong password policies and multi-factor authentication (MFA), especially for admin panels.
* **Regular Auditing and Monitoring:** Use log monitoring and file integrity checking tools to detect any unauthorized changes or suspicious activity.

