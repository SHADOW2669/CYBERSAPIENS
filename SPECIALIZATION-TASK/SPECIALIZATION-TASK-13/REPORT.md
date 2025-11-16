# Remote Code Execution & OS Command Injection

## Introduction

Modern web applications always rely on external systems and user input. However, if input is not properly handled, it opens the door to dangerous vulnerabilities like Remote Code Execution (RCE) and OS command injection. These attacks can allow an attacker to execute malicious code or commands on a target system, potentially gaining full control of the application or server.

---

## What is RCE (Remote Code Execution)?

RCE is a vulnerability that allows an attacker to run malicious code on a server or application from a remote location. If successful, the attacker can:

* Access sensitive data.
* Modify or delete files.
* Install malware or web shells.
* Take full control of the system.



RCE often results from insecure use of functions like `eval()`, `exec()`, or deserialization of untrusted data.

---

## What is OS Command Injection?

OS Command Injection is a type of vulnerability where untrusted input is passed directly into system-level commands. If the input is not properly sanitized, attackers can inject additional commands to be executed by the operating system.

**Example:**

```python
# Vulnerable code
os.system("ping " + user_input)

# If user_input = "127.0.0.1; rm -rf /"
# The system will ping and then delete everything.
````

This attack allows the execution of arbitrary operating system commands and can compromise the entire host.

-----

## Attack Methodology

### Remote Code Execution (RCE)

1.  **Injection Point:** User input reaches a dangerous function (`eval()`, `exec()`, etc.).
2.  **Code Execution:** Input is executed as code on the server.
3.  **Remote Access:** Attacker may use a reverse shell or web shell for persistent access.

### OS Command Injection

1.  **Unsafe Input Handling:** User input is used directly in system commands.
2.  **Command Chaining:** Attacker injects commands using symbols like `;`, `&&`, or `|`.
3.  **Command Execution:** The system executes the attacker-controlled instructions.

-----

## Real-World Examples

  * **RCE: Equifax Data Breach (2017)**
    Attackers exploited an RCE vulnerability in Apache Struts (CVE-2017-5638), allowing them to access the sensitive records of 147 million people. The issue was in a file upload feature that failed to validate input before passing it to an interpreter.

  * **OS Command Injection in IoT Devices**
    Researchers discovered several smart home devices in 2022 that were vulnerable to OS command injection through poorly validated web interfaces, allowing remote attackers to control the devices via crafted HTTP requests.

-----

## Mitigation Techniques

  * **Input Validation:**
      * Use allowlists for acceptable inputs.
      * Reject or sanitize unexpected characters.
  * **Avoid Dangerous Functions:**
      * Don’t use `eval()`, `exec()`, `system()`, etc., on user input unless absolutely necessary.
  * **Use Safe APIs:**
      * Prefer safer alternatives like `subprocess.run()` with argument lists (e.g., `['ping', '127.0.0.1']`) instead of raw command strings.
  * **Sanitize All Input:**
      * If system commands *must* be used, escape user input correctly or avoid mixing user data in command strings.
  * **Web Application Firewalls (WAF):**
      * Deploy WAFs to detect and block malicious requests in real-time.
  * **Least Privilege:**
      * Applications should run with the minimum permissions required.

-----

## Conclusion

Remote Code Execution and OS Command Injection are among the most dangerous security vulnerabilities in web applications. They allow attackers to take full control of affected systems if left unpatched. Developers must follow secure coding practices, validate all user inputs, and avoid insecure functions to protect applications from these threats.

-----

## References

  * [NVD: CVE-2017-5638 (Equifax Breach)](https://nvd.nist.gov/vuln/detail/CVE-2017-5638)
  * [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
  * [PortSwigger: OS Command Injection](https://portswigger.net/web-security/os-command-injection)
  * [OWASP: Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
  * [OWASP: Code Injection](https://owasp.org/www-community/attacks/Code_Injection)
