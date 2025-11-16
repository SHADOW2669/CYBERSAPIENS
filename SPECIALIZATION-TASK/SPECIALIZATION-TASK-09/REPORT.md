# Structured Query Language Injection (SQLI)

## Introduction

In the rapidly growing digital world, web applications are the backbone of digital services from online banking to shopping to social networking. But with great convenience comes great risk. One of the most common and dangerous web vulnerabilities is SQL Injection (SQLi). This report aims to explain what SQL is, how SQL injection works, and mitigations all in plain English language accessible for both tech and non-tech audiences.

## What is SQL?

SQL (Structured Query Language) is the standard language used to manage and interact with databases. It allows applications to:

* Retrieve data (e.g., “Get all users”)
* Insert Data (e.g., “Add new product”)
* Update Data (e.g., “Change Password”)
* Delete data (e.g., “Remove old orders”)

When you log into a website or search for something online, chances are your request is turned into an SQL query behind the scenes.

## What is SQL injection?

SQL injection (SQLi) is a type of cyberattack where malicious users “inject” harmful SQL code into input fields, like login forms or search boxes. If the application doesn’t handle these inputs securely, the attacker can trick the system into running unintended commands on the database.

This could lead to:

* Unauthorized access to sensitive data.
* Data manipulation or deletion.
* Full control over the database.
* Compromise of the entire system or application.

## Real-World Example

Let's say a login form processes input like this:

```sql
SELECT * FROM users WHERE username = 'John' AND password = '1234';
````

Now, an attacker types this instead:

  * **Username:** `' OR '1'='1`
  * **Password:** `anything`

The query becomes:

```sql
SELECT * FROM users WHERE username = '' OR '1'='1' AND password = 'anything';
```

Since `'1'='1'` is always true, the attacker gains access without knowing any real credentials. This is a classic authentication bypass using SQL injection.

## Attack Methodologies

Here’s how attackers typically exploit SQL injection:

1.  **Reconnaissance:** Identify input fields connected to database queries.
2.  **Injection:** Enter crafted SQL code into input fields.
3.  **Observation:** Look at error messages or application behavior.
4.  **Exploitation:** Use extracted information to access, modify, or delete data.
5.  **Escalation:** If possible, gain admin-level access or execute system commands.

## Mitigation Techniques

To defend against SQL injection:

  * **Use prepared statements:** Prevent user input from being executed as SQL code.
  * **Input validation and escaping:** Never trust user input; validate type, length, and format.
  * **Use ORM Frameworks:** Object-Relational Mappers like SQLAlchemy or Hibernate reduce direct SQL handling.
  * **Least Privilege Principle:** Restrict database permissions, like no root/admin rights for app users.
  * **Error Handling:** Don’t expose raw error messages to users; it helps attackers.
  * **Regular Security Testing:** Use penetration testing, code reviews, and vulnerability scanners.

## Conclusion

SQL injection is a simple yet powerful attack that preys on insecure coding practices. It has been responsible for major data breaches globally, but the good news is, it’s preventable. By writing secure code, validating input, and staying aware of threats, we can build safer, more trustworthy web applications.

## References

  * [OWASP: SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
  * [Acunetix: SQL Injection](https://www.acunetix.com/websitesecurity/sql-injection/)
  * [PortSwigger: SQL Injection](https://portswigger.net/web-security/sql-injection)
  * [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
  * [NIST NVD Search](https://nvd.nist.gov/vuln/search)

