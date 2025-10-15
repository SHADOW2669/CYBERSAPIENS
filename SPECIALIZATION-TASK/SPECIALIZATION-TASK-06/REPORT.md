# SSRF: Server-Side Request Forgery

## Introduction

Server-Side Request Forgery (SSRF) is a web security vulnerability that allows an attacker to induce a server-side application to make requests to an unintended location. In a typical SSRF attack, the attacker can make the server connect to internal-only services within the organization's infrastructure, arbitrary external systems, or loop back to itself. This report provides a high-level, technically-grounded overview of SSRF, common exploitation techniques, real-world impact, and critical mitigation strategies.

## What is Server-Side Request Forgery (SSRF)?

SSRF occurs when an application fetches a remote resource based on user-supplied input without properly validating the target URL. This functionality is common in modern applications, for example, when importing a user's profile picture from a URL, processing webhooks, or fetching data from an external API endpoint specified by the user. An attacker can manipulate this input to make the web server itself issue a request to a resource that it was never intended to access. Because the request originates from the trusted server, it can bypass firewalls and access internal, non-public network resources.

## How can SSRF Attacks Happen?

SSRF vulnerabilities can manifest in several ways, with varying levels of impact:

* **Basic SSRF**: The server's response from the forged back-end request is fully or partially returned to the attacker. This provides direct feedback, allowing the attacker to easily scan the internal network, read files using the `file://` protocol, or interact with internal web services.

* **Blind SSRF**: The server's response from the back-end request is not returned to the attacker. This makes exploitation more difficult, but still possible. Attackers must use inferential techniques, such as measuring the time it takes for the application to respond (time-based) or triggering an out-of-band network interaction (e.g., forcing a DNS lookup to a server they control).

### Abuse of URL Schemas
Attackers can leverage different URL protocols (schemas) to interact with various services:

* `http(s)://`: Used to access internal web applications, admin panels, and, most critically, cloud provider metadata services (e.g., `http://169.254.169.254` on AWS).
* `file://`: Can be used to read arbitrary files from the server's local filesystem, such as configuration files (`/etc/passwd`, `web.config`).
* `gopher://`, `dict://`: These protocols provide more control over the request format and can be used to interact with non-HTTP services like Redis, Memcached, or SMTP servers, potentially leading to Remote Code Execution (RCE).

## Attack Methodology

1.  **Identify Vulnerable Inputs**: Search the application for any functionality that accepts a URL or hostname as input. Common parameters include `url`, `uri`, `path`, `image_url`, `webhook_url`, etc.
2.  **Probe for the Vulnerability**: Provide the URL of a server you control (e.g., a Burp Collaborator instance) as input and check if the application makes a request back to it.
3.  **Internal Reconnaissance**: Once SSRF is confirmed, begin probing the internal network.
    * Scan for common internal IP addresses (`127.0.0.1/localhost`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
    * Attempt to connect to the cloud metadata endpoint (`169.254.169.254`) to steal access credentials.
    * Perform port scanning on internal hosts by observing differences in responses or timeouts.
4.  **Bypass Filters**: Many applications have blocklists to prevent SSRF. Attackers use various techniques to bypass them, including:
    * Using alternative IP representations (Decimal, Octal, Hex).
    * Registering a DNS record that resolves to an internal IP address.
    * Using URL encoding or case variation.
    * Exploiting parsing discrepancies between the validation library and the request library.
5.  **Exploit and Exfiltrate Data**: Access sensitive internal services, read local files, or retrieve cloud credentials to pivot further into the infrastructure.

## Real-World Examples

* **Capital One Breach (2019)**: This is one of the most famous examples of SSRF exploitation. An attacker leveraged an SSRF vulnerability in a misconfigured Web Application Firewall (WAF) to send requests to the internal AWS metadata service. This allowed them to retrieve temporary IAM credentials, which they then used to access and exfiltrate the data of over 100 million customers from S3 buckets.

* **Shopify Bug Bounty (2019)**: A researcher discovered an SSRF vulnerability in a Shopify service that allowed them to read local files and make internal requests, leading to a significant bug bounty payout and demonstrating the risk even in well-secured environments.

## Mitigations

To protect applications from SSRF, a defense-in-depth approach is required:

* **Use Strict Allow-Lists**: This is the most effective defense. Instead of trying to block malicious inputs (block-listing), maintain a strict list of allowed domains, IPs, and protocols that the application is authorized to request. Reject all other requests.
* **Validate and Sanitize All User Input**: Never trust user input. Ensure that any supplied URL points to the expected destination and conforms to the expected format. The response from the request should also be validated.
* **Disable Unused URL Schemas**: Configure HTTP client libraries to only permit necessary schemas (e.g., `HTTP` and `HTTPS`) and explicitly disable dangerous ones like `file://`, `gopher://`, and `dict://`.
* **Network Segmentation and Egress Filtering**: Isolate the server in a minimal network environment. Use firewall rules (egress controls) to prevent the server from initiating connections to internal network ranges.
* **Enforce Least Privilege**: Run the application with the minimum permissions necessary. For example, in a cloud environment, disable access to the instance metadata service for roles that do not strictly require it.

## Conclusion

SSRF is a powerful and dangerous vulnerability that effectively turns a trusted application server into an attacker's proxy inside the network perimeter. The risk is significantly amplified in modern cloud-based architectures where metadata services can provide direct access to sensitive credentials. A robust defense requires a combination of strict input validation at the application layer and strong network-level controls to limit the server's ability to make unauthorized outbound requests.

## References

* [OWASP Community: Server Side Request Forgery](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
* [PortSwigger Web Security Academy: SSRF](https://portswigger.net/web-security/ssrf)
* [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
* [Imperva: SSRF (Server-Side Request Forgery)](https://www.imperva.com/learn/application-security/ssrf-server-side-request-forgery/)
