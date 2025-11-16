# XML External Entity (XXE) Injection

## Introduction

XML is a widely used format for data exchange in web services and enterprise applications. However, if not securely implemented, XML parsing can introduce severe vulnerabilities. One such threat is XXE injection, which can lead to unauthorized data access, server-side request forgery (SSRF), Denial of Service (DoS), or even full server compromise. Understanding XXE is essential for developers and security professionals alike to build and maintain secure applications.

## What is XXE?

XML External Entity (XXE) Injection is a vulnerability that occurs when an application processes XML input and fails to securely configure its XML parser. XXE allows attackers to inject external entities into XML, potentially enabling access to sensitive files, internal services, or other unintended data.

This attack takes advantage of the ability to define custom entities in XML using the `<!DOCTYPE>` declaration. When these entities reference local files or network resources, insecure XML parsers may resolve and return their content.

## Attack Methodology



1.  **Injecting a malicious DOCTYPE:** An attacker sends XML data with a crafted `DOCTYPE` that defines an external entity.
2.  **Referencing Internal Files or Services:** The entity points to sensitive files (e.g., `/etc/passwd`) or internal network services (SSRF).
3.  **Parser Processes the Payload:** A vulnerable parser reads and includes the referenced content in the response.

> If the XML parser is vulnerable, it processes `&xxe;`, leaking the content of `/etc/passwd`.

## Real-World Example: Uber XXE Vulnerability

In 2017, a security researcher discovered an XXE flaw in Uber's documentation parser. The parser accepted user-uploaded XML files and processed them insecurely. By crafting a malicious XML document, the attacker accessed AWS metadata and internal resources. Uber awarded a bug bounty and fixed the vulnerability by disabling external entity resolution.

## Mitigation Strategies

* **Disable DTDs and External Entities:**
    * **In Java (SAXParserFactory):**
        ```java
        factory.setFeature("[http://apache.org/xml/features/disallow-doctype-decl](http://apache.org/xml/features/disallow-doctype-decl)", true);
        factory.setFeature("[http://xml.org/sax/features/external-general-entities](http://xml.org/sax/features/external-general-entities)", false);
        factory.setFeature("[http://xml.org/sax/features/external-parameter-entities](http://xml.org/sax/features/external-parameter-entities)", false);
        ```
    * **In .NET:**
        ```csharp
        XmlReaderSettings settings = new XmlReaderSettings();
        settings.DtdProcessing = DtdProcessing.Prohibit;
        settings.XmlResolver = null;
        ```
* **Use Secure Parsers:**
    Prefer libraries and parsers that are secure by default, such as `defusedxml` in Python.
* **Input Validation:**
    Sanitize and validate XML input. Avoid accepting malicious user-generated XML unless absolutely necessary.
* **Use Less Dangerous Formats:**
    Use JSON or other data formats unless XML is required.
* **Static and Dynamic Analysis:**
    Employ automated tools (SAST/DAST) and manual reviews to detect vulnerable code patterns.

## Conclusion

XXE is a critical vulnerability that often arises due to insecure XML parsing configurations. With the continued use of XML in many APIs and legacy systems, it's vital to configure parsers securely and follow defensive coding practices. As security professionals, we must be vigilant in identifying and mitigating such risks to protect sensitive data and infrastructure.

## References

* [OWASP: XML External Entity (XXE) Processing](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)
* [PortSwigger: XXE Injection](https://portswigger.net/web-security/xxe)
* [OWASP Cheat Sheet: XXE Prevention](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
* [Snyk: XXE Vulnerability](https://learn.snyk.io/lessons/xxe/java/)
* [Acunetix: XXE Vulnerabilities](https://www.acunetix.com/blog/articles/xml-external-entity-xxe-vulnerabilities/)