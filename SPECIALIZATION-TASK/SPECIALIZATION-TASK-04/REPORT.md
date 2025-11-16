# Host Header Injection and Password Reset Poisoning

## 1. Introduction

In the rapidly expanding digital landscape, the security of web applications is paramount. While high-profile vulnerabilities like SQL Injection and Cross-Site Scripting (XSS) receive significant attention, lesser-known but equally damaging exploits such as Host Header Injection can lead to critical security breaches. This report aims to dissect this vulnerability, explain its methodology, and explore one of its most severe consequences: Password Reset Poisoning. We will provide clear attack scenarios, real-world implications, and robust mitigation techniques for developers and security professionals.

## 2. Host Header Injection

Host Header Injection is a web vulnerability where an attacker manipulates the Host header in an HTTP request to exploit the application's URL generation or request routing logic. Web applications and servers often trust the Host header to determine the server's domain name, which is then used to construct absolute URLs for links, scripts, and redirects. If this input is not properly validated, an attacker can supply a malicious domain, leading to a variety of attacks.

### Host Header Injection Methodology

The core of the attack involves modifying the Host header, which is trivial to do with proxy tools like Burp Suite or command-line clients like curl.

**Example 1: Basic Host Header Spoofing**

An attacker sends a request to a legitimate server but sets the Host header to a domain they control.

```http
GET /some/page HTTP/1.1
Host: attacker-controlled-site.com
User-Agent: Brave/5.0
````

If the application uses this Host header to generate a link on the page, the HTML might render as:

```html
<a href="[http://attacker-controlled-site.com/login](http://attacker-controlled-site.com/login)">Login</a>
```

This can be used to redirect users to a phishing site.

**Example 2: Injection via X-Forwarded-Host**

When an application is behind a reverse proxy or load balancer, it may be configured to prioritize the `X-Forwarded-Host` header to determine the original host requested by the client. An attacker can inject this header directly.

```http
GET / HTTP/1.1
Host: legitimate-site.com
X-Forwarded-Host: attacker-controlled-site.com
```

If the application prioritizes `X-Forwarded-Host` over the `Host` header, it will use `attacker-controlled-site.com` for its logic, making it vulnerable even if the web server itself validates the primary `Host` header.

## 3\. Password Reset Poisoning

Password Reset Poisoning is a specific, high-impact attack that is often a direct result of a Host Header Injection vulnerability. It allows an attacker to take over a user's account by manipulating the password reset link sent to them via email.

### Password Reset Poisoning Methodology

The attack exploits the trust an application places in the Host header when generating a one-time password reset link.

1.  **Initiate Reset with Malicious Header**: The attacker navigates to the "Forgot Password" page and requests a password reset for the victim's account (e.g., `victim@email.com`). They intercept this request and modify the Host header to point to a domain they control.

    **Original Request:**

    ```http
    POST /request-password-reset HTTP/1.1
    Host: [www.vulnerable-app.com](https://www.vulnerable-app.com)
    Content-Type: application/x-www-form-urlencoded

    email=victim@email.com
    ```

    **Poisoned Request:**

    ```http
    POST /request-password-reset HTTP/1.1
    Host: evil-server.net
    Content-Type: application/x-w-form-urlencoded

    email=victim@email.com
    ```

2.  **Generate Poisoned Link**: The application server receives the request. It generates a unique, secret password reset token (e.g., `a1b2c3d4e5f6`) and constructs the reset link. Because it incorrectly uses the Host header from the attacker's request, the generated link is:
    `https://evil-server.net/reset?token=a1b2c3d4e5f6`

3.  **Deliver Link to Victim**: The application sends this poisoned link in an email to the legitimate user (`victim@email.com`).

4.  **Capture the Token**: The victim receives the email, which appears legitimate. They click the link, and their browser sends a request containing the secret token directly to the attacker's server (`evil-server.net`).

5.  **Account Takeover**: The attacker's server logs the incoming request, capturing the secret token. The attacker then uses this token on the actual application (`www.vulnerable-app.com`) to reset the victim's password and gain complete control of their account.

## 4\. Real-World Examples & Impact

Numerous high-profile companies have been affected by vulnerabilities stemming from Host Header Injection.

  * **Phishing and Credential Theft**: A major e-commerce platform was found vulnerable, allowing attackers to generate password reset links pointing to a perfectly replicated phishing site. Users, trusting the email's origin, would enter their credentials on the attacker's site.
  * **Internal Network Pivoting**: Researchers demonstrated on an open-source collaboration tool how a forged Host header could be used to generate URLs pointing to internal, non-public services. This could be used to perform Server-Side Request Forgery (SSRF) attacks.
  * **Web Cache Poisoning**: An attacker can poison the cache of a CDN or reverse proxy by making a request with a malicious Host header. Subsequent users who request the same resource would be served the poisoned content, potentially leading to widespread XSS attacks.

These incidents underscore the critical need to treat all HTTP headers as untrusted, user-controlled input.

## 5\. Mitigation Strategies

Preventing these attacks requires a layered approach focusing on strict input validation and secure configuration.

  * **Use a Server-Side Whitelist for Hostnames**: The most robust defense is to avoid using the Host header entirely for server-side code. Store the application's canonical hostname in a configuration file and use that to build all absolute URLs. If dynamic hostnames are required (e.g., for a multi-tenant application), validate the incoming Host header against a strict whitelist of allowed domains.

  * **Reject Unrecognized Hosts at the Web Server Level**: Configure your web server (e.g., Nginx, Apache) to have a default virtual host that rejects any request with an unrecognized Host header. This acts as a first line of defense.

    **Nginx Example:**

    ```nginx
    server {
        listen 80 default_server;
        server_name _;
        return 404; // Or 400
    }

    server {
        listen 80;
        server_name [www.your-app.com](https://www.your-app.com);
        # ... your main application config
    }
    ```

  * **Securely Handle Proxied Requests**: If your application is behind a load balancer or reverse proxy, do not blindly trust headers like `X-Forwarded-Host`. Configure your proxy to overwrite or strip any incoming `X-Forwarded-Host` headers from the client before forwarding the request.

  * **Regular Security Audits and Penetration Testing**: Actively test your applications for header-based vulnerabilities. Automated scanners can find low-hanging fruit, but manual analysis is often required to discover business logic flaws related to Host Header Injection.

## 6\. Conclusion

Host Header Injection and its derivative, Password Reset Poisoning, are serious threats that exploit a web application's fundamental trust in HTTP headers. While conceptually simple, their impact can be devastating, leading to full account takeovers, data breaches, and further system compromise. By adopting a "zero-trust" policy for all user-supplied input, including headers, and implementing robust validation and secure configuration, organizations can effectively defend against this insidious class of vulnerabilities.

## 7\. References

  * [OWASP: Testing for Host Header Injection](https://www.google.com/search?q=https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Host_Header_Injection)
  * [PortSwigger Web Security Academy: Host header attacks](https://portswigger.net/web-security/host-header)
  * [MDN Web Docs: Host - HTTP Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Host)
