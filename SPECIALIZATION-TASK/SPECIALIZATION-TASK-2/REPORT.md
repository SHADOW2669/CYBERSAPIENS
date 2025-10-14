# A Technical Report on Cross-Site Request Forgery (CSRF)

## Abstract

In the modern digital landscape, the security of web applications is paramount. Among the array of sophisticated cyber threats, Cross-Site Request Forgery (CSRF) remains a persistent and dangerous vulnerability. This attack methodology exploits the inherent trust between a user and a web application, allowing an attacker to execute unauthorized commands on behalf of an authenticated user. This report provides a detailed analysis of CSRF, its mechanics, real-world impact, and robust mitigation strategies, incorporating practical examples from PortSwigger's Web Security Academy labs.

## 1\. What is Cross-Site Request Forgery (CSRF)?

Cross-Site Request Forgery, also known as a "one-click attack" or "session riding," is an attack vector that tricks an authenticated user's web browser into submitting a malicious, forged request to a web application. The application, unable to differentiate between a legitimate request and the forged one, processes the command.

The core of the attack lies in exploiting an active user session. If a user is logged into a web application (e.g., their bank, social media, or corporate portal), an attacker can craft a request for an action within that application and embed it into a different website. If the user visits the attacker's website while their session on the target application is still active, the malicious request is sent to the target application with the user's session credentials (like cookies), making it appear as a legitimate, user-initiated action.

## 2\. The Mechanics of a CSRF Attack

A CSRF attack hinges on the browser's standard behavior of automatically including authentication credentials, such as session cookies, with every request sent to a specific domain.

**Simplified Attack Flow:**

1.  **Legitimate Login:** A user logs into a trusted web application, `https://vulnerable-website.com`. The server authenticates the user and sets a session cookie in their browser.
2.  **Attacker's Trap:** The user, in a new tab, visits a malicious website controlled by an attacker, `https://test-website.com`.
3.  **Forged Request:** The attacker's website contains hidden code (e.g., an HTML form or JavaScript) that automatically triggers a request to the vulnerable application. This request is designed to perform a sensitive action, such as changing the user's email address.
4.  **Cookie Inclusion:** The user's browser, upon sending the request to `https://vulnerable-website.com`, automatically includes the session cookie associated with that domain.
5.  **Unauthorized Action:** The vulnerable server receives the forged request. Since the request includes a valid session cookie, the server processes it as a legitimate action performed by the authenticated user, without their knowledge or consent.

For a CSRF attack to be successful, three key conditions must generally be met:

  * **A Relevant Action:** The target application must have an action that the attacker wishes to exploit (e.g., changing a password, updating profile details, sending a message).
  * **Cookie-Based Session Handling:** The application must rely solely on session cookies to identify the user and authenticate their requests.
  * **No Unpredictable Parameters:** The request parameters for the action must be known or guessable by the attacker. If the request required a secret, random token that the attacker couldn't predict, the attack would fail.

## 3\. Practical Example: PortSwigger CSRF Lab

To illustrate the attack, let's analyze a common scenario from PortSwigger's Web Security Academy labs: a CSRF vulnerability in an email change function.

**Scenario:** A web application allows authenticated users to change their account email address via a simple POST request.

**Capturing a Legitimate Request:** An attacker first analyzes the legitimate process. When a normal user changes their email to `shadow@gmail.com`, their browser sends the following HTTP request:

```http
POST /my-account/change-email HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 27
Cookie: session=aBcDeFgHiJkLmNoPqRsTuVwXyZ

email=shadow@gmail.com
```

**Generating the CSRF Proof-of-Concept (PoC):** The attacker notes that the request only requires one predictable parameter: `email`. There are no anti-CSRF tokens. The attacker then creates a malicious webpage (`https://test-website.com`) containing the following HTML:

```html
<html>
  <body>
    <form action="https://vulnerable-website.com/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="pwned@hack-user.net" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```

This code creates a hidden form that targets the email change endpoint. The value of the `email` field is set to an address the attacker controls. The JavaScript automatically submits this form the moment the page loads.

**Executing the Attack:** The attacker convinces the victim (who is logged into `vulnerable-website.com`) to visit `https://test-website.com`. When the victim's browser loads the page, the script executes, the form is submitted, the browser attaches the victim's session cookie, and the application changes the victim's email address to `pwned@hack-user.net`. The attacker can then use the "forgot password" functionality to take over the account completely.

## 4\. Impact of CSRF Attacks

The severity of a CSRF attack is directly proportional to the sensitivity of the action being exploited.

  * **Low Impact:** An attack might force a user to log out, change minor settings on their profile, or post a spam message on a forum. While annoying, the damage is minimal.
  * **High Impact:** If the vulnerable action is critical, the consequences can be severe. This includes changing the account password or email (leading to full account takeover), transferring funds from a bank account, deleting critical data, or, in the case of an administrative user, compromising the entire web application.

## 5\. Mitigations and Defense Strategies

Preventing CSRF requires breaking one of the core conditions for the attack. Modern web frameworks often have built-in protections, but it is crucial to understand and correctly implement them.

  * **Synchronizer Token Pattern (CSRF Tokens):** This is the most robust defense. The server generates a unique, random, and unpredictable token for each user session. This token is embedded as a hidden field in every state-changing form. When the form is submitted, the server validates that the token from the request body matches the one stored in the user's session. Since the attacker cannot guess this token, any forged request will be rejected.

  * **SameSite Cookies:** This is a browser-level defense mechanism controlled by the `SameSite` cookie attribute.

      * **`SameSite=Strict`:** The browser will not send the cookie with any cross-site request, completely preventing CSRF. However, it can break legitimate functionality.
      * **`SameSite=Lax`:** This is the default in modern browsers. It provides a balance by blocking cookies on cross-site subrequests (like those initiated by forms or scripts), which stops most CSRF attacks.

  * **Referer Header Validation:** The server can check the `Referer` HTTP header to verify that the request originated from its own domain. This method is less reliable as the header can be suppressed or spoofed but can be used as part of a layered defense.

  * **User Interaction Confirmation:** For highly sensitive actions (e.g., password changes, fund transfers), require the user to re-authenticate by entering their password or a one-time password (OTP). This ensures that the user is present and intentionally performing the action.

## 6\. Conclusion

Cross-Site Request Forgery is a powerful attack that capitalizes on the implicit trust web applications place in user browsers. As demonstrated, an attacker does not need to steal a user's credentials to perform devastating actions on their behalf. By understanding the mechanics of the attack and implementing robust, layered defenses—primarily the Synchronizer Token Pattern and SameSite cookie policies—developers can effectively neutralize this threat and safeguard user accounts and data from unauthorized manipulation.

## 7\. References

  * [OWASP: Cross-Site Request Forgery (CSRF)](https://owasp.org/www-community/attacks/csrf)
  * [PortSwigger: What is CSRF (Cross-site request forgery)? Web Security Academy](https://portswigger.net/web-security/csrf)
  * [OWASP: Cross-Site Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)