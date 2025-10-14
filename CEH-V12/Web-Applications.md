
# Web Applications

## 1. What is a Web Application?

A **Web Application** is a client-server computer program that a user accesses via a web browser over a network like the Internet. Unlike a simple static website (which just displays information), a web application is interactive. It processes user input, performs logic, and interacts with backend resources like databases.

### Core Architecture
As shown in your slide, a web application has two main parts:

* **Frontend (Client-Side):** This is what the user sees and interacts with in their browser. It's built with technologies like HTML (structure), CSS (style), and JavaScript (interactivity).
* **Backend (Server-Side):** This is the engine of the application. It contains the application logic (written in PHP, Python, Java, etc.), a web server to handle requests, a file system for storing assets, and a database for storing application data.

```
              +-------------------------------------------------+
              |             Web Application Architecture        |
              |                                                 |


\+-------+         |  +-----------------+       +------------------+  |
|       |         |  |    Frontend     |\<-----\>|     Backend      | |
| Users |\<-------\>|  | (HTML, CSS, JS) |       | (App Logic, DB)  | |
|       |         |  +-----------------+       +------------------+ | |
\+-------+         |                                                  |
\+-------------------------------------------------+

```

### How Web Applications Work in Detail
The second slide you provided shows a great example of a request for a *dynamic* page:

1.  **Request for Static Content:** The user's browser sends a `GET` request for an HTML page (e.g., `123.html`).
2.  **Response for Static Content:** The **Web Server** (like Apache or Nginx) finds the file and sends it directly back.
3.  **Request for Dynamic Content:** The user clicks a link that requests a dynamic page (e.g., `123.php`).
4.  **Hand-off to App Server:** The Web Server receives this request and, seeing that it's a `.php` file, knows it can't handle it alone. It passes the request to the **Web Application Server** (in the diagram, PHP-FPM).
5.  **Processing:** The Web App Server executes the PHP script. This script might connect to a database to fetch user data.
6.  **Final Response:** The Web App Server generates an HTML page from the script's result and sends it back to the Web Server, which then forwards it to the user's browser.

---

## 2. What are Web Services?

A **Web Service** is a standardized way for applications to communicate with each other over the internet, regardless of their programming language or operating system. It's a set of functions that one application makes available for other applications to use.

Think of it as a service offered by one machine to another. For example, a server might offer a "PDF Conversion Service" that can take any document and turn it into a PDF. Other applications can "call" this service to use its functionality without knowing how it works internally.

```

\+--------------------+                         +----------------------+
|                    | -- 1. Request Service -- \> |                      |
|   Client App (A)   |    (e.g., "Convert Doc")   | Server with          |
|                    |                         | Web Service (B)      |
|                    | \< -- 2. Return Result --  |                      |
\+--------------------+      (e.g., "PDF File")   +----------------------+

```

---

## 3. What is a Web API?

A **Web API (Application Programming Interface)** is the specific *interface* through which one interacts with a web service. If the web service is the engine, the API is the control panel, complete with buttons, labels, and a user manual. It defines the exact rules, commands, and data formats an application must use to access the service.

As your slide shows, a centralized Web API allows many different backend resources (databases, file services, etc.) to be accessed in a simple, unified way by many different clients (mobile apps, web apps).

```

\+-----------+    +-------------+    +------------+      +----------------+
|           |    |             |    |            |      |                |
| Database, |    |             |    |  REST:API  |      |   Mobile Apps, |
| File Svs, | -\> |   Web APIs  | -\> | (The Rules)|  -\>  |   Web Apps,    |
| Other Svs |    | (The Service) |    |            |      |   Other Apps   |
|           |    |             |    |            |      |                |
\+-----------+    +-------------+    +------------+      +----------------+

````

### SOAP vs. REST
SOAP and REST are two major architectural styles for creating web APIs, as detailed in your comparison table.

* **SOAP (Simple Object Access Protocol):** A formal, standards-based **protocol**. It is highly structured, uses XML for all messages, and has strict rules defined in a WSDL (Web Services Description Language) file.
* **REST (REpresentational State Transfer):** A more flexible and lightweight **architectural style**. It uses standard HTTP methods (`GET`, `POST`, `PUT`, `DELETE`) to interact with resources and can use either XML or JSON (more common) for data transfer.

---

### SOAP Message Example
As requested, here is an example of a simple SOAP request and response. The request asks for user information based on a `UserID`, and the response returns the user's name and email.

**SOAP Request:**
```xml
<?xml version="1.0"?>
<soap:Envelope xmlns:soap="[http://www.w3.org/2003/05/soap-envelope/](http://www.w3.org/2003/05/soap-envelope/)" 
               xmlns:m="[http://www.example.org/users](http://www.example.org/users)">
  <soap:Header>
    </soap:Header>
  <soap:Body>
    <m:GetUserDetails>
      <m:UserID>12345</m:UserID>
    </m:GetUserDetails>
  </soap:Body>
</soap:Envelope>
````

**SOAP Response:**

```xml
<?xml version="1.0"?>
<soap:Envelope xmlns:soap="[http://www.w3.org/2003/05/soap-envelope/](http://www.w3.org/2003/05/soap-envelope/)"
               xmlns:m="[http://www.example.org/users](http://www.example.org/users)">
  <soap:Header>
  </soap:Header>
  <soap:Body>
    <m:GetUserDetailsResponse>
      <m:UserName>John Doe</m:UserName>
      <m:UserEmail>john.doe@example.com</m:UserEmail>
    </m:GetUserDetailsResponse>
  </soap:Body>
</soap:Envelope>
```

-----

## 4\. What are Web Hooks?

A **Web Hook** is sometimes called a "Reverse API" or an "inverted API." Instead of your application constantly asking the server for new information, a web hook allows the server to send your application information automatically whenever a specific event occurs.

> **Analogy:**
>
>   * **Standard API:** You repeatedly call the pizza shop to ask, "Is my pizza ready yet?" (This is called **polling**).
>   * **Web Hook:** You give the pizza shop your phone number, and they **text you** as soon as your pizza is ready. (This is **event-driven**).

### How Web Hooks Work

1.  **Registration:** Your application (the client) gives another service (the server) a unique URL and tells it, "When event X happens, send a message to this URL."
2.  **Event Trigger:** The specified event occurs on the server (e.g., a new user signs up, a payment is processed, a code commit is pushed).
3.  **Push Notification:** The server automatically sends an HTTP `POST` request containing data about the event to the URL you registered.

This is a much more efficient way for applications to get real-time updates.

```
+----------------+                       +----------------+
|                |  1. Something happens |                |
|   Server App   | <---- (Event) ----    |  External Svc  |
| (e.g., GitHub) |                       |                |
|                |                       |                |
|                |  2. Server sends data |                |
|                | ---- (HTTP POST) ---> | Your App       |
+----------------+                       +----------------+
```

## 1. Web Application Threats (OWASP Top 10)

Web application threats are security risks that can lead to the compromise of the application, its data, or its users. The Open Web Application Security Project (OWASP) provides the industry-standard lists of the most critical risks.

### The OWASP Top 10 for Web Applications - 2021
This list, evolving from the 2017 version as shown in your slide, represents the most critical security risks to web applications today.

* **A01:2021 - Broken Access Control:** Users can access data or perform actions beyond their intended permissions. (e.g., a regular user accessing an admin page by guessing the URL).
* **A02:2021 - Cryptographic Failures:** Failures related to cryptography, which often lead to the exposure of sensitive data (e.g., storing passwords in plaintext).
* **A03:2021 - Injection:** An attacker sends malicious data to an application, which is then processed and executed as a command (e.g., SQL Injection, Cross-Site Scripting).
* **A04:2021 - Insecure Design:** Flaws in the fundamental design and architecture of the application, which cannot be fixed by a simple patch.
* **A05:2021 - Security Misconfiguration:** Incorrectly configured security settings, such as running with default credentials, having verbose error messages, or improper HTTP headers.
* **A06:2021 - Vulnerable and Outdated Components:** Using libraries, frameworks, or other software components with known, unpatched vulnerabilities.
* **A07:2021 - Identification and Authentication Failures:** Weaknesses in user identity management, authentication, and session management (e.g., weak password policies, session hijacking).
* **A08:2021 - Software and Data Integrity Failures:** Failures related to code and infrastructure that protect against unauthorized modification (e.g., insecure deserialization).
* **A09:2021 - Security Logging and Monitoring Failures:** Insufficient logging and monitoring, which allows attackers to operate undetected for long periods.
* **A10:2021 - Server-Side Request Forgery (SSRF):** A vulnerability where an attacker can force the server-side application to make requests to an unintended location.

### The OWASP Top 10 for APIs - 2023
Modern applications heavily rely on APIs, which have their own specific set of critical risks.

1.  **API1 - Broken Object Level Authorization (BOLA):** An attacker accesses data belonging to other users by manipulating the ID of an object in the API request.
2.  **API2 - Broken Authentication:** Weak authentication mechanisms that can be bypassed or compromised.
3.  **API3 - Broken Object Property Level Authorization:** An endpoint exposes more data fields than necessary, allowing an attacker to read or modify object properties they shouldn't have access to.
4.  **API4 - Unrestricted Resource Consumption:** The API does not have proper limits on the resources a client can request, leading to Denial of Service (DoS).
5.  **API5 - Broken Function Level Authorization:** An attacker can access API functions meant only for other user roles (e.g., a regular user calling an admin-only endpoint).
6.  **API6 - Unrestricted Access to Sensitive Business Flows:** An attacker can exploit a business logic flow, such as buying a product by manipulating the API to bypass payment steps.
7.  **API7 - Server-Side Request Forgery (SSRF):** The same as the web app threat, but specifically exploited through an API endpoint.
8.  **API8 - Security Misconfiguration:** Similar to the web app threat, including misconfigured CORS, missing security headers, or verbose error messages.
9.  **API9 - Improper Inventory Management:** The organization does not have a full inventory of all its APIs, leading to old or "shadow" APIs remaining unpatched and vulnerable.
10. **API10 - Unsafe Consumption of APIs:** The application insecurely trusts and integrates with third-party APIs, which may be malicious or vulnerable.

---

## 2. Web Application Hacking Methodology

As shown in your slide, an ethical hacker follows a structured, multi-step process to test a web application thoroughly.

1.  **Footprint Web Infrastructure:**
    * **Objective:** Gather as much information as possible about the target's infrastructure.
    * **Actions:** As per your lab objectives, this involves using tools like `nmap`, `whois`, and `nslookup` to retrieve the **target machine name, NetBIOS name, DNS name, MAC address, and OS details**.

2.  **Analyze Web Applications:**
    * **Objective:** Understand the application's structure, technology stack, and identify potential entry points.
    * **Actions:** Manually browse the entire application, analyze the sitemap, and identify the frameworks (e.g., WordPress, React) and languages (e.g., PHP, Java) being used.

3.  **Bypass Client-Side Controls:**
    * **Objective:** Defeat security controls implemented in the user's browser (JavaScript).
    * **Actions:** Use browser developer tools or a proxy like **Burp Suite** to disable or manipulate client-side scripts that perform tasks like input validation or price calculations.

4.  **Attack Authentication Mechanism:**
    * **Objective:** Compromise the login mechanism.
    * **Actions:** Test for weak password policies, username enumeration, and perform **Brute Force Attacks** using a tool like **Burp Suite Intruder** or THC Hydra to guess credentials.

5.  **Attack Authorization Schemes:**
    * **Objective:** Test if users can access functions or data they are not authorized for.
    * **Actions:** This involves testing for horizontal privilege escalation (accessing another user's data) and vertical privilege escalation (a regular user accessing admin functions).

6.  **Attack Access Controls:**
    * **Objective:** A deeper dive into authorization, specifically trying to access protected resources directly.
    * **Actions:** Attempting to browse directly to admin URLs, or manipulating URL parameters (e.g., changing `?userID=123` to `?userID=124`) to test for Broken Object Level Authorization (BOLA).

7.  **Attack Session Management Mechanism:**
    * **Objective:** Hijack a legitimate user's session.
    * **Actions:** Test for session fixation, predictable session tokens, and use sniffing or XSS to steal a user's session cookie.

8.  **Perform Injection Attacks:**
    * **Objective:** Inject malicious code or data that the application will execute.
    * **Actions:** This includes testing for SQL Injection, Command Injection, and, as mentioned in your lab objectives, **exploiting Cross-Site Scripting (XSS) vulnerabilities**. This step also includes **Parameter Tampering**, where tools like **Burp Suite** are used to modify data sent to the server (e.g., changing the price of an item in a hidden form field).

9.  **Attack Application Logic Flaws:**
    * **Objective:** Exploit flaws in the business logic of the application.
    * **Actions:** Manipulating a multi-step process, such as bypassing the payment step in a shopping cart checkout flow or exploiting a password reset function.

10. **Attack Shared Environments:**
    * **Objective:** If the application is on shared hosting, attempt to break out of its environment to access other applications on the same server.
    * **Actions:** Exploiting file system vulnerabilities or kernel-level exploits.

11. **Attack Database Connectivity:**
    * **Objective:** Directly attack the backend database.
    * **Actions:** Using SQL Injection to exfiltrate data, or scanning for open database ports and attempting to connect with default credentials.

12. **Attack Web App Client:**
    * **Objective:** Attack the end-user's browser or system.
    * **Actions:** Exploiting XSS to perform actions in the user's browser, or tricking users into downloading malicious files.

13. **Attack Web Services:**
    * **Objective:** Find and exploit vulnerabilities in the backend APIs.
    * **Actions:** Testing for the OWASP API Security Top 10 risks, such as BOLA and Broken Function Level Authorization.

---

## 3. Mitigation and Security Testing

### Web Application Hacking Mitigation Measures
These are the defensive actions organizations should take to protect their web applications.

* **Automated vulnerability scanning and Security Testing:** Regularly scan applications with tools like Nessus or DAST scanners.
* **Web Application Firewalls (WAFs):** Deploy a WAF to filter malicious traffic and block common attacks like SQLi and XSS.
* **Secure Development Testing (SDT):** Integrate security into the software development lifecycle (SDLC) from the beginning.
* **Access control:** Implement strong authorization to ensure users can only access what they are permitted to.
* **Secure communication:** Enforce HTTPS (TLS/SSL) across the entire application.
* **Server and network security:** Harden the underlying OS and network infrastructure.
* **Regular updates and patches:** Consistently update all frameworks, libraries, and server software.
* **User education:** Train users to recognize and avoid phishing and other social engineering attacks.
* **Incident response planning:** Have a plan in place to detect, respond to, and recover from a security breach.
* **Input Validation and Sanitization:** This is the primary defense against all injection attacks. Never trust user input; always validate and sanitize it.

### Web Application Security Testing Types

* **Manual Web App Security Testing:** A security expert manually attempts to find vulnerabilities. This is best for finding business logic flaws that automated tools miss.
* **Automated Web App Security Testing:** Using scanners to automatically find common vulnerabilities. It is fast but can have false positives and miss complex flaws.
* **Static Application Security Testing (SAST):** A "white-box" approach where the application's source code is analyzed for vulnerabilities *without* running the application.
* **Dynamic Application Security Testing (DAST):** A "black-box" approach where the *running* application is tested from the outside, simulating how a real attacker would interact with it.
