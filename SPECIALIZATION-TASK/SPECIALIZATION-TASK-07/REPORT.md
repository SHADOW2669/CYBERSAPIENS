# CORS & HSTS

## Introduction

In the landscape of web security, browsers enforce strict policies to protect users from malicious attacks. Cross-Origin Resource Sharing (CORS) and HTTP Strict Transport Security (HSTS) are two critical security mechanisms, implemented via HTTP headers, that help developers build safer applications. CORS provides a way to relax the Same-Origin Policy (SOP) securely, while HSTS enforces the use of encrypted connections. However, misconfigurations in either can neutralize their benefits and expose applications to significant risks. This report explores both mechanisms, their common vulnerabilities, and best practices for implementation.

## Cross-Origin Resource Sharing (CORS)

### What is CORS?

By default, web browsers enforce the **Same-Origin Policy (SOP)**, a security measure that prevents a web page from making requests to a different domain (origin) than the one that served the page. CORS is a mechanism that uses additional HTTP headers to tell browsers to give a web application running at one origin, access to selected resources from a different origin. In essence, it is a controlled way to bypass the SOP.

**Key HTTP headers involved in CORS:**
* **Request Header**: `Origin` (sent by the browser)
* **Response Headers**: `Access-Control-Allow-Origin`, `Access-Control-Allow-Methods`, `Access-Control-Allow-Headers`, `Access-Control-Allow-Credentials`

### How can CORS be Misconfigured?

The security of CORS relies entirely on the server's configuration. A misconfiguration can completely undermine the Same-Origin Policy.

* **Improperly Configured `Access-Control-Allow-Origin` Header**: This is the most common and critical misconfiguration.
    * **Reflecting the Origin Header**: A server might be configured to read the `Origin` header from the incoming request and reflect it in the `Access-Control-Allow-Origin` response header. This makes the application vulnerable because any malicious website can make a request, and the browser will authorize it.
    * **Using a Wildcard (`*`) with Credentials**: Setting `Access-Control-Allow-Origin: *` allows any website to make a request. While this is acceptable for public, unauthenticated data, it becomes dangerous if `Access-Control-Allow-Credentials: true` is also set. Browsers will block this combination, but misconfigured proxies or applications might still permit it, leading to data theft.
    * **Allowing `null` Origin**: Some servers are configured to allow requests from the `null` origin. This is risky because certain scenarios, like local HTML files or sandboxed iframes, can generate requests with a `null` origin, potentially allowing them to access sensitive data.
    * **Weak Regular Expressions**: If a server uses a regular expression to validate origins, a poorly constructed one might be bypassed by a cleverly named attacker domain (e.g., `trusted-domain.com.attacker.com`).

### Attack Methodology

1.  **Discovery**: An attacker sends a cross-origin request to the target application and inspects the response headers for CORS-related headers.
2.  **Probing**: The attacker sends a request with a custom `Origin` header, such as `Origin: https://evil-site.com`.
3.  **Exploitation**: If the server reflects this malicious origin in the `Access-Control-Allow-Origin` header, the attacker knows the application is vulnerable. They can then host a malicious script on their own website. When a logged-in user visits the attacker's site, the script makes an authenticated cross-domain request to the vulnerable application, stealing sensitive user data (e.g., personal information from an API) or performing actions on behalf of the user.

## HTTP Strict Transport Security (HSTS)

### What is HSTS?

HTTP Strict Transport Security (HSTS) is a web security policy mechanism that helps to protect websites against protocol downgrade attacks and cookie hijacking. It allows web servers to declare that web browsers should only interact with them using secure HTTPS connections, and never via the insecure HTTP protocol.

The server enables HSTS by sending the following HTTP response header:
`Strict-Transport-Security: max-age=<seconds>; includeSubDomains; preload`

* `max-age`: The time, in seconds, that the browser should remember to only access the site using HTTPS.
* `includeSubDomains`: An optional parameter that applies the rule to all of the site's subdomains as well.
* `preload`: An optional parameter that signals consent to have the domain included in the browser's HSTS preload list, offering the highest level of protection.

### How can HSTS be Misconfigured or Bypassed?

* **Short `max-age`**: A very short `max-age` value (e.g., a few minutes) minimizes the effectiveness of the policy, as the browser will soon "forget" the rule, leaving the user vulnerable to downgrade attacks again.
* **Omission of `includeSubDomains`**: If this directive is missing, an attacker could potentially perform a man-in-the-middle attack on an insecure subdomain and hijack session cookies that are not marked as secure.
* **"Trust on First Use" (TOFU) Problem**: A user is vulnerable on their very first visit to a site before their browser has received the HSTS header. An attacker can perform a downgrade attack during this initial HTTP connection. The `preload` directive solves this by hardcoding the domain into the browser itself.

## Mitigations and Best Practices

### For CORS:

* **Use a Strict Allow-List**: The most secure approach is to maintain a server-side list of specific, trusted origins that are permitted to make requests.
* **Avoid Reflecting Origins**: Never copy the value of the `Origin` request header into the `Access-Control-Allow-Origin` response header.
* **Avoid Wildcards with Credentials**: Never use `Access-Control-Allow-Origin: *` for any endpoint that requires authentication or handles sensitive data.
* **Be Specific**: If possible, specify the exact HTTP methods (`GET`, `POST`, etc.) and headers that are allowed from cross-origin locations.

### For HSTS:

* **Set a Long `max-age`**: A typical value is one or two years (e.g., `max-age=63072000`).
* **Include Subdomains**: Use the `includeSubDomains` directive after ensuring all subdomains are configured with HTTPS.
* **Use the HSTS Preload List**: Ensure your site meets the submission criteria and submit it to [hstspreload.org](https://hstspreload.org/) to protect users from their very first visit.

## Conclusion

CORS and HSTS are powerful tools for enhancing web application security. CORS is designed for the controlled relaxation of the Same-Origin Policy, while HSTS is for the strict enforcement of secure connections. Their effectiveness, however, is entirely dependent on correct and robust configuration. Developers must understand the risks of misconfiguration—which can lead to complete cross-origin data theft (CORS) or man-in-the-middle attacks (HSTS)—and implement these headers according to established best practices.

## References

* [MDN Web Docs: CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
* [MDN Web Docs: HSTS](https://developer.mozilla.org/en-US/docs/Web/HTTP/HSTS)
* [PortSwigger Web Security Academy: CORS](https://portswigger.net/web-security/cors)
* [OWASP Secure Headers Project: HSTS](https://owasp.org/www-project-secure-headers/#strict-transport-security)
* [HSTS Preload List Submission](https://hstspreload.org/)
