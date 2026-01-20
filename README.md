# [CYBERSAPIENS](https://cybersapiens.com.au/) - Cybersecurity Internship Journey


A log of my learning, progress, and experiences during my cybersecurity internship. This document tracks the skills, tools, and vulnerabilities I've studied on a monthly basis.

-----

## Monthly Progress Log

### 🗓️ December 2026

> December was a pivotal month dedicated to bridging the gap between theoretical knowledge and infrastructure-level security. I focused heavily on the **OWASP API Security Top 10 (2023)**, moving beyond simple web pages to analyze the logic, authentication, and resource management of modern APIs. By building a local home lab, I was able to simulate enterprise environments, integrating security monitoring tools with live vulnerable targets.

#### Key Learnings

* **API Security & Logic Flaws:** Mastered the identification of modern API risks, specifically focusing on **BOPLA (Broken Object Property Level Authorization)** and **BFLA (Broken Function Level Authorization)**. I learned that API security is less about "breaking" code and more about manipulating the intended business logic.
* **Infrastructure & Monitoring Integration:** Developed a strong "Purple Team" perspective by deploying the **Wazuh SIEM** alongside vulnerable targets. This allowed me to see how my attacks (like Brute Forcing or SQLi) appeared in security logs in real-time.
* **Homelab Systems Administration:** Gained hands-on experience with virtualization using **Proxmox** and containerization with **LXC**, learning how to network multiple services securely.

#### Vulnerabilities Studied (OWASP API Top 10)

* **Broken Authentication (API2:2023):** Exploited logic flaws in password update mechanisms where the "current password" was not required, leading to full account takeovers.
* **BOPLA (API3:2023):** Successfully performed excessive data exposure by identifying hidden properties in JSON responses and manipulating inputs via Mass Assignment to escalate privileges.
* **Unrestricted Resource Consumption (API4:2023):** Executed high-volume brute force attacks to demonstrate how a lack of rate-limiting can exhaust server CPU and memory.
* **BFLA (API5:2023):** Exploited "Admin API" hints leaked in error messages to bypass functional restrictions and delete resources using non-privileged tokens.
* **Unrestricted Access to Sensitive Business Flows (API6:2023):** Researched real-world logic flaws (like the 2022 Coinbase vulnerability) to understand how unauthorized trades and transactions are processed.
* **Security Misconfiguration (API8:2023):** Identified verbose error messages and stack traces in **crAPI** that leaked internal system architecture and software versions.
* **Unsafe Consumption of APIs (API10:2023):** Studied the risks of implicit trust in third-party integrations, using the **SolarWinds** attack as a case study for supply chain security.

#### Tools & Platforms

* **Virtualization & Lab Setup:** * **Proxmox VE:** Used as the primary hypervisor for the lab.
* **TrueNAS:** Configured for network-attached storage and data management.
* **LXC (Linux Containers):** Deployed Pi-hole, Wazuh, and Grafana for a lightweight monitoring stack.


* **Security Tools:**
* **Wazuh:** Installed server and agents to monitor host integrity and detect attacks.
* **Burp Suite & Postman:** Essential for intercepting, modifying, and testing API requests/responses.
* **Nuclei:** Used for automated vulnerability scanning against lab targets.


* **Vulnerable Targets:**
* **VAmPI (Vulnerable API):** Used for testing Broken Authentication and BOPLA.
* **crAPI (Completely Ridiculous API):** Analyzed for BFLA and Security Misconfigurations.



#### Live Findings & Lab Progress

* **Wazuh Integration:** Successfully connected Wazuh agents to an Ubuntu PC and Pi-hole LXC to monitor for unauthorized SSH attempts and privilege escalation.
* **Lab Deployment:** Resolved service issues with **BeEF-XSS** and **Speedtest Tracker** on TrueNAS, ensuring a stable environment for cross-site scripting and resource monitoring tests.
* **Dashboards:** Built a custom **Grafana** dashboard connected to lab metrics to visualize system performance during "Unrestricted Resource Consumption" attacks.

#### Overall Experience

December has transformed my approach from a "hacker" to a "security researcher." Building the infrastructure myself—configuring the networking, the monitoring, and the targets—provided a 360-degree view of cybersecurity. I now understand that a single misconfigured API or a missing rate-limit can be just as devastating as a zero-day exploit. I feel confident moving into February with a robust lab environment capable of simulating complex, multi-stage attack scenarios.



### 🗓️ October 2025

> October was a month of intense, focused effort on making significant progress on core web vulnerabilities and validating my broader cybersecurity knowledge. I dedicated significant time to working through entire modules within the PortSwigger Web Security Academy, moving from foundational concepts to advanced exploitation in several key areas.

#### Key Learnings

* **Core Vulnerability Proficiency:** Significantly solidified my understanding of **Cross-Site Scripting (XSS)**, **SQL Injection (SQLi)**, **Server-Side Request Forgery (SSRF)**, and **CORS** configurations through exhaustive, hands-on practice.
* **Ethical Hacking Methodologies:** The preparation for and successful completion of the **CEH Assessment Exam** broadened my knowledge of the complete ethical hacking lifecycle, from reconnaissance and scanning to gaining and maintaining access.

#### Vulnerabilities Studied

* **Cross-Site Scripting (XSS):** Completed all PortSwigger labs, covering Reflected, Stored, and DOM-based XSS with various contexts and bypasses.
* **SQL Injection (SQLi):** Worked through numerous labs to exploit SQLi, including UNION-based, blind, and out-of-band techniques.
* **Server-Side Request Forgery (SSRF):** Completed the full module, learning to exploit SSRF for internal network reconnaissance and data exfiltration.
* **Path Traversal:** Finished all labs, learning techniques to access and read arbitrary files from the server's file system.
* **CORS Vulnerabilities:** Learned how to identify and exploit misconfigured Cross-Origin Resource Sharing (CORS) to bypass security controls.
* **Password Reset Poisoning:** Understood how to manipulate password reset tokens by poisoning host headers or other inputs to achieve account takeover.
* **JWT Authentication Bypass:** Learned to bypass authentication by exploiting **unverified signatures** in JSON Web Tokens.

#### Tools & Platforms

* **Primary Tool:** `` `Burp Suite` `` remained my essential tool for all PortSwigger labs. It was used extensively for intercepting, manipulating, and analyzing web traffic to find and exploit all vulnerabilities listed above.
* **Platforms & Challenges:**
    * **PortSwigger Web Security Academy:**
        * Completed all labs for the **Cross-Site Scripting (XSS)** module.
        * Completed all labs for the **Path Traversal** module.
        * Completed all labs for the **SSRF** module.
        * Completed numerous labs for the **SQL Injection** module.
        * Completed labs for the **CORS** module.
        * Completed specific labs for **Password Reset Poisoning**.
        * Completed the lab for **JWT Authentication Bypass via Unverified Signature**.
    * **CEH Assessment Exam:** Successfully prepared for and completed the certification exam.

#### Live Findings & Bug Bounties

* 🔒 **Status:** As my work in October was confined to educational platforms (PortSwigger) and certification assessments (CEH), no live vulnerabilities or bug bounties were reported.

<br>

### 🗓️ September 2025

> My primary activity in September was consistently working through the PortSwigger Web Security Academy labs, which allowed me to apply theoretical knowledge to hands-on challenges. A major highlight was progressing through the Google Cybersecurity Professional Certificate on Coursera, which provided a broad and structured understanding of the cybersecurity landscape.

#### Key Learnings

  * **Web Application Security:** Deepened my understanding by working extensively on practical PortSwigger labs covering a range of common vulnerabilities.
  * **Vulnerability Analysis:** Gained specific, practical knowledge of Server-Side Request Forgery (SSRF), Path Traversal, and various Business Logic Vulnerabilities.
  * **Comprehensive Cybersecurity Fundamentals:** Acquired broad knowledge through the Google Cybersecurity Professional Certificate, covering topics from security frameworks and risk assessment to network security and threat intelligence.

#### Vulnerabilities Studied

  * **Server-Side Request Forgery (SSRF):** Gained hands-on experience in identifying and exploiting SSRF vulnerabilities, understanding its impact on internal systems.
  * **Path Traversal:** Learned to exploit file path traversal vulnerabilities to access restricted files and directories.
  * **Business Logic Vulnerabilities:** Explored flaws in application logic that could be exploited for unintended purposes.

#### Tools & Platforms

  * **Primary Tool:** Continued extensive use of `` `Burp Suite` `` for all web application testing.
  * **Platforms & Challenges:**
      * **PortSwigger Web Security Academy:** Focused on completing labs for SSRF, Path Traversal, and Business Logic Vulnerabilities.
      * **Google Cybersecurity Professional Certificate:** Actively progressed through modules on Coursera.
      * **Specialization Task:** Continued work on the assigned specialization task.

#### Live Findings & Bug Bounties

  * 🔒 **Status:** All activities were conducted in controlled lab environments. No live vulnerabilities were reported.

<br>

### 🗓️ August 2025

> This past month has been a period of intensive learning, building directly on the foundational knowledge I gained in late July. My journey progressed from reconnaissance to more advanced topics like Web Application, API, and even iOS Security, with a strong focus on practical application.

#### Key Learnings

  * **Network Security:** Gained a deeper understanding of network scanning and methodologies (CEH Module 4).
  * **Enumeration:** Learned the principles and techniques of enumeration (CEH Module 5).
  * **Web Application Security:** Studied advanced modules on web app architecture and common security flaws.
  * **Vulnerability Analysis:** Acquired specific knowledge on the mechanics, impact, and mitigation of Cross-Site Request Forgery (CSRF).
  * **API & Mobile Security:** Gained foundational knowledge of API security concepts and iOS application architecture.

#### Vulnerabilities Studied

  * **Cross-Site Request Forgery (CSRF):** Gained hands-on experience in identifying and exploiting different types of CSRF vulnerabilities.
  * **Information Disclosure:** Learned to identify vulnerabilities from network scanning and footprinting (e.g., open ports, service banners).
  * **API Security Risks:** Introduced to common risks like insecure endpoints and improper data handling.

#### Tools & Platforms

  * **Reconnaissance & Scanning:** `` `knockpy` ``, `` `httpx` ``, `` `subfinder` ``, `` `Nmap` ``
  * **Web & API Testing:** `` `Burp Suite` ``, `` `Postman` ``
  * **Information Gathering:** `` `Google Dorks` ``
  * **Platforms & Challenges:**
      * **PortSwigger Web Security Academy:** Completed labs focused on CSRF.
      * **Try Hack Me:** Completed rooms focusing on Web Fundamentals.
      * **Internal Assignments:** Worked on Task 2 (Advanced), Task 3, and Specialization Task 4.
      * **Personal Lab:** Set up a multi-VM lab for remote access and network practice.

#### Live Findings & Bug Bounties

  * 🔒 **Status:** The primary objective was skill acquisition in a training environment. No live vulnerabilities were reported.
