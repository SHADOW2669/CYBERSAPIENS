# Subdomain Takeover & Broken Link Hijacking

## Introduction

As web applications grow massively in complexity, they often rely on multiple subdomains and third-party services. While this helps with scalability and modular development, it also introduces new security risks. Two notable vulnerabilities in this context are **subdomain takeover** and **broken link hijacking**. These attacks exploit misconfigured or abandoned resources, often leading to phishing, defamation, or data theft. This report explores these vulnerabilities, their methodologies, and how organizations can defend against them.

---

## What is Subdomain Takeover?

Subdomain Takeover occurs when a subdomain points to a resource (such as GitHub Pages, AWS S3, Heroku, etc.) that has been deleted or is no longer controlled by the organization, but the **DNS entry (e.g., a CNAME record) still exists**. An attacker can claim the abandoned resource and host malicious content under the trusted subdomain.



### Why is it critical?

* **Phishing:** Attackers can host malicious content under your organization’s trusted domain (e.g., `login.example.com`) to perform sophisticated phishing attacks.
* **Cookie/Session Theft:** They can steal cookies or session tokens if the compromised subdomain is in the same scope as the main application.
* **Brand Reputation:** Brand reputation is at risk, as users may assume malicious content is a legitimate part of your site.

### Attack Methodology

1.  **Reconnaissance:** Attackers begin by scanning the internet or specific organizations using tools like **Amass**, **Subfinder**, or **Assetfinder** to enumerate all subdomains.
2.  **Detection of Dangling Subdomains:** They identify subdomains that point to services (e.g., `app.example.com`) but return `404` or “No such app” errors, indicating the service is unclaimed.
3.  **Claim the Unused Service:** The attacker registers a new resource at the third-party service (e.g., creating a new app or repository) with the *same name* that matches the dangling DNS record.
4.  **Deploy Malicious Payloads:** After taking over, the attacker can host fake login pages, distribute malware, or redirect users to scam sites, all under a legitimate subdomain of the target.

### Real-World Examples

A major airline once had a subdomain pointing to an AWS S3 bucket that had been deleted. An attacker created a new bucket with the same name and hosted a phishing site targeting frequent flyer accounts, successfully bypassing many security tools due to the trusted domain.

---

## What is Broken Link Hijacking?

Broken Link Hijacking (BLH) is similar in concept but targets **external links** rather than subdomains. Websites often link to GitHub repos, social media profiles, image hosts, or other external services. If any of these links break (e.g., the account is deleted, the username changes, or the repo is made private), an attacker can claim the missing resource and inject malicious or misleading content.



### Common Targets

* GitHub Pages or Repos
* Twitter, Instagram, LinkedIn usernames
* External blog platforms (e.g., Medium)
* CDN or image hosting platforms
* Package repositories like npm or PyPI

### Broken Link Hijacking Attack Methodology

1.  **Link Discovery:** Attackers crawl a website and its documentation to identify external links, especially in footers, “about us” pages, or blog posts.
2.  **Identify Broken or Expired Links:** Tools like **BrokenLinkChecker**, **Ahrefs**, or manual validation help find dead links (HTTP 404s).
3.  **Claim the Link or Account:** If the linked account or repo is available, the attacker registers it using the original name.
4.  **Exploit for Gain:** The attacker can host malicious JavaScript files, impersonate brands, inject ads, or redirect traffic to affiliate/malicious sites.

---

## Mitigation Strategies

### Preventing Subdomain Takeover

* **Perform Regular DNS Audits:** Inventory all subdomains and match them against active, provisioned services.
* **Remove Unused DNS Records:** Delete DNS entries for decommissioned services *immediately*.
* **Monitor for Dangling CNAMEs:** Use automated tools like **CanITakeOver.XYZ**, **Subjack**, or **dnsreaper** to detect vulnerable configurations.
* **Least Privilege on External Services:** Don’t allow every team to create CNAME records; centralize and control DNS changes.
* **Cloud Provider Security Alerts:** Subscribe to deprecation or deletion notifications from services like GitHub, AWS, and Azure.

### Preventing Broken Link Hijacking

* **Automate Broken Link Checks:** Use continuous scanning tools in your CI/CD pipelines to detect dead links early.
* **Avoid Linking to Third-Party Resources You Don’t Own:** Especially avoid linking to personal GitHub repos or social media accounts unless you control them.
* **Secure Your External Assets:** Maintain control over all linked accounts, and if decommissioned, ensure redirections are set up properly or remove the links.
* **Use URL Shorteners with Tracking:** This can help monitor and manage external links in real-time (though it introduces another dependency).

---

## Conclusion

Subdomain Takeover and Broken Link Hijacking are often underrepresented in security assessments but can cause significant damage. As cloud adoption and third-party integrations increase, these attack surfaces continue to grow.

Organizations must adopt a “Security in Depth” approach that includes external asset monitoring, automation, and regular audits. By proactively managing DNS and external links, companies can protect their infrastructure, data, and brand from silent takeovers and hijacking.

> Security is not just about firewalls and passwords; it’s also about visibility and ownership.

## References

* [GitHub: can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)
* [OWASP: Test for Subdomain Takeover](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover)
* [HackerOne: A Guide To Subdomain Takeovers](https://www.hackerone.com/blog/guide-subdomain-takeovers)
* [Spyboy Blog: The Ultimate Guide to Finding Subdomain Takeover](https://spyboy.blog/2025/04/28/the-ultimate-guide-to-finding-subdomain-takeover-vulnerabilities-step-by-step-payloads-tools/)