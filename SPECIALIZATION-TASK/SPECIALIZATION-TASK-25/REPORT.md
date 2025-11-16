# OWASP Mobile Top 10

## 1. What is OWASP Mobile Top 10?

The **OWASP Mobile Top 10** is a standard awareness document created and maintained by the Open Web Application Security Project (OWASP). Its primary purpose is to educate developers, security professionals, and organizations about the most critical security risks facing mobile applications.

Similar to the standard OWASP Top 10 (which focuses on web applications), the Mobile Top 10 list is compiled from real-world data, bug reports, and a consensus of opinions from a wide range of security experts. It highlights the most common and impactful vulnerabilities found in mobile apps, providing a starting point for developers and security teams to prioritize their efforts in building and maintaining secure mobile applications.

---

## 2. Briefly Explain about OWASP Top 10 List

The list details the 10 most critical mobile security risks. Here is a brief explanation of each item from the most recent official list (OWASP Mobile Top 10 2016):



### M1: Improper Platform Usage

This category covers the misuse of a mobile platform's features or security controls. This includes things like improperly using the Android Keychain, misconfigured Android Intents, or failing to use iOS security features correctly.

### M2: Insecure Data Storage

This vulnerability occurs when an application stores sensitive data (like passwords, session tokens, or personal information) on the device in an insecure manner, allowing an attacker with physical or malware-based access to the device to steal it.

### M3: Insecure Communication

This refers to applications that transmit sensitive data over the network without proper encryption or validation. This includes using plain HTTP, failing to validate SSL/TLS certificates (Man-in-the-Middle attacks), or using weak encryption algorithms.

### M4: Insecure Authentication

This involves weaknesses in how an application authenticates a user. Examples include allowing weak passwords, not protecting against brute-force attacks, or managing user sessions (session tokens) insecurely, allowing an attacker to impersonate a legitimate user.

### M5: Insufficient Cryptography

This vulnerability arises when an application uses weak, broken, or custom-built encryption algorithms to "protect" sensitive data. If an attacker can break this encryption, the data is compromised, even if it was stored or transmitted "securely."

### M6: Insecure Authorization

This is about flaws in what a user is allowed to do after they have logged in. A vulnerable app might allow a regular user to access administrative functions or view/modify another user's data by simply manipulating a request.

### M7: Client Code Quality

This covers a broad range of poor coding practices in the mobile app's code itself. This can include issues like buffer overflows, format string vulnerabilities, or other memory-related bugs that could be exploited by an attacker.

### M8: Code Tampering

This vulnerability relates to an application's lack of protection against modification. An attacker could download the app, modify its code (e.g., to bypass a login check or insert malware), and then redistribute the tampered version.

### M9: Reverse Engineering

This is the risk of an attacker being able to easily decompile or analyze the application's binary. By reverse-engineering, an attacker can discover how the app works, find hidden API keys, steal intellectual property (proprietary algorithms), and find other vulnerabilities.

### M10: Extraneous Functionality

This occurs when developers leave hidden or "backend" functionality in the production version of an app. This could include old test code, debug flags, or other administrative features that an attacker could discover and abuse to compromise the application.

---

## References

* [OWASP Mobile Top 10 Project](https://owasp.org/www-project-mobile-top-10/)
* [OWASP Mobile Top 10 2016 List](https://owasp.org/www-project-mobile-top-10/2016-risk-list/)
* [OWASP Mobile Security Testing Guide (MSTG)](https://owasp.org/www-project-mobile-security-testing-guide/)