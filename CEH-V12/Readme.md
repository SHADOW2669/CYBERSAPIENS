# CEH v12 - The Ultimate Cheat Sheet

A quick reference guide for the core concepts, tools, and techniques covered in the Certified Ethical Hacker v12 curriculum.

---

## 1. Introduction to Ethical Hacking
- **White Hat:** An ethical hacker who has permission to test systems.
- **Black Hat:** A malicious hacker who exploits systems for illegal personal gain.
- **Grey Hat:** A hacker who may violate laws but without malicious intent.
- **CIA Triad:**
  - **Confidentiality:** Keeping data secret.
  - **Integrity:** Ensuring data is not altered.
  - **Availability:** Ensuring data is accessible.
- **Hacking Phases:**
  1. Reconnaissance
  2. Scanning
  3. Gaining Access
  4. Maintaining Access
  5. Covering Tracks

---

## 2. Footprinting and Reconnaissance
- **Passive Recon:** Gathering info without direct interaction (e.g., WHOIS, Google Dorking).
- **Active Recon:** Directly interacting with the target to gather info (e.g., port scanning).
- **Tools & Techniques:**
  - `whois [domain]`: Get registration info for a domain.
  - `nslookup [domain]`: Query DNS records.
  - `dig [domain]`: Advanced DNS query tool.
  - **Google Dorks:**
    - `site:[target].com`: Limit search to a specific site.
    - `filetype:pdf`: Search for specific file types.
    - `inurl:login`: Find URLs containing "login".
  - **Shodan:** Search engine for internet-connected devices.

---

## 3. Scanning Networks
- **Goal:** Identify live hosts, open ports, and running services.
- **Scan Types:**
  - **TCP Connect Scan (`-sT`):** Completes the 3-way handshake (noisy).
  - **SYN Stealth Scan (`-sS`):** Half-open scan (stealthy).
  - **UDP Scan (`-sU`):** Scans for open UDP ports (slow).
- **Nmap Commands:**
  - `nmap -sn [target]`: Ping scan (host discovery only).
  - `nmap -sS -p- [target]`: SYN scan on all 65535 ports.
  - `nmap -sV -O [target]`: Service version and OS detection.
  - `nmap -A [target]`: Aggressive scan (enables OS, version, script scanning, and traceroute).
  - `nmap --script=vuln [target]`: Scan for known vulnerabilities using NSE scripts.

---

## 4. Enumeration
- **Goal:** Actively extract detailed system info: usernames, network shares, machine names, and services.
- **Protocols & Ports:**
  - **NetBIOS:** 139 (TCP) - Usernames, shares.
  - **SNMP:** 161 (UDP) - Network device configuration.
  - **LDAP:** 389 (TCP) - Directory information.
- **Tools:**
  - `enum4linux [target]`: Powerful tool for enumerating Windows/Samba systems.
  - `snmpwalk -v2c -c public [target]`: Enumerate a device with a default SNMP community string.

---

## 5. Vulnerability Analysis
- **Goal:** Identify, quantify, and prioritize vulnerabilities in a system.
- **Types:**
  - **Active:** Probes the system for vulnerabilities.
  - **Passive:** Monitors network traffic to identify vulnerable software.
- **Process:**
  1. **Discovery:** Identify systems and applications.
  2. **Analysis:** Correlate findings with known vulnerability databases (CVE).
  3. **Reporting:** Document and rank vulnerabilities.
- **Tools:**
  - **Nessus:** Popular commercial vulnerability scanner.
  - **OpenVAS:** Open-source vulnerability scanner.
  - **Nmap Scripting Engine (NSE):** Can be used for basic vulnerability checks.

---

## 6. System Hacking
- **Goal:** Gain unauthorized access, escalate privileges, and maintain control.
- **Phases:**
  1. **Gaining Access:** Exploit a vulnerability (e.g., buffer overflow, weak password).
  2. **Privilege Escalation:** Move from a low-level user to an admin/root user.
  3. **Maintaining Access:** Install backdoors, rootkits, or trojans.
- **Password Cracking Tools:**
  - **John the Ripper:** Cracks password hashes using wordlists and brute force.
  - **Hashcat:** Advanced GPU-based password cracking.
- **Frameworks:**
  - **Metasploit Framework:** The most popular tool for exploitation and post-exploitation.

---

## 7. Malware Threats
- **Virus:** Attaches itself to a legitimate file and requires human action to spread.
- **Worm:** Self-replicates and spreads across networks without human action.
- **Trojan:** Disguises itself as legitimate software to trick users into installing it.
- **Ransomware:** Encrypts a victim's files and demands a ransom for the decryption key.
- **Spyware:** Secretly gathers information about the user.
- **Rootkit:** Gains root/admin access and hides its presence on the system.

---

## 8. Sniffing
- **Goal:** Capture, decode, and analyze network traffic.
- **Passive Sniffing:** Performed on a hub; you see all traffic.
- **Active Sniffing:** Performed on a switch; requires techniques like ARP spoofing.
- **Tools:**
  - **Wireshark:** Powerful GUI-based network protocol analyzer.
  - `tcpdump`: Command-line packet analyzer.
- **ARP Poisoning/Spoofing:** A Man-in-the-Middle (MITM) attack where an attacker sends spoofed ARP messages to link their MAC address with the IP of a legitimate host.
  - **Tool:** `arpspoof`

---

## 9. Social Engineering
- **Goal:** Manipulate people into divulging confidential information.
- **Types:**
  - **Phishing:** Sending fraudulent emails to obtain sensitive info.
  - **Spear Phishing:** Highly targeted phishing attack aimed at an individual or organization.
  - **Vishing:** Phishing conducted over the phone (Voice Phishing).
  - **Baiting:** Leaving an infected device (like a USB drive) for a victim to find and use.
- **Countermeasures:** User awareness training, clear security policies.

---

## 10. Denial-of-Service (DoS) / DDoS
- **Goal:** Overwhelm a system's resources to make it unavailable to legitimate users.
- **DoS:** Attack from a single source.
- **DDoS:** Attack from multiple, distributed sources (a botnet).
- **Attack Types:**
  - **SYN Flood:** Sends a flood of TCP SYN packets, overwhelming the server's connection table.
  - **ICMP (Ping) Flood:** Overwhelms the target with ICMP Echo Request packets.
- **Tools:**
  - `hping3 --flood -S [target]`: SYN flood attack.
  - **LOIC (Low Orbit Ion Cannon):** Popular DoS tool.

---

## 11. Session Hijacking
- **Goal:** Take over an established user session to gain unauthorized access.
- **Methods:**
  - **Session Fixation:** Attacker fixes a user's session ID before they log in.
  - **Session Side-jacking:** Sniffing a valid session token from unencrypted traffic (e.g., public Wi-Fi) and using it to impersonate the user.
  - **Cross-Site Scripting (XSS):** Injecting malicious scripts to steal session cookies.

---

## 12. Evading IDS, Firewalls, and Honeypots
- **IDS (Intrusion Detection System):** Monitors for malicious activity and alerts.
- **Firewall:** Filters network traffic based on a set of rules.
- **Honeypot:** A decoy system designed to lure attackers.
- **Evasion Techniques:**
  - **Fragmentation:** Splitting packets into tiny pieces to bypass detection signatures.
  - **Spoofing IP Address:** Hiding the attacker's true identity.
  - **Using Proxies/VPNs:** Obfuscating the source of the attack.
  - **Nmap Evasion:** `-f` (fragment packets), `--source-port` (use specific source port).

---

## 13. Hacking Web Servers and Web Applications
- **OWASP Top 10:** A standard awareness document for the most critical web application security risks.
- **Common Vulnerabilities:**
  - **Cross-Site Scripting (XSS):** Injecting malicious scripts into a trusted website.
  - **Cross-Site Request Forgery (CSRF):** Tricking a victim into submitting a malicious request.
  - **Directory Traversal:** Accessing files outside the web root directory (`../../..`).
- **Tools:**
  - **Burp Suite:** The industry-standard web proxy for testing web app security.
  - **Nikto:** Web server scanner.

---

## 14. SQL Injection
- **Goal:** Inject malicious SQL queries via user input to manipulate a backend database.
- **Types:**
  - **In-band (Classic):** Data is extracted using the same channel.
  - **Blind SQLi:** The web app doesn't show errors, forcing the attacker to infer data based on true/false responses.
- **Example Payload:** ` ' OR 1=1 -- `
- **Tools:**
  - `sqlmap`: Automated SQL injection and database takeover tool.

---

## 15. Hacking Wireless Networks
- **Security Protocols (Weakest to Strongest):** WEP -> WPA -> WPA2 -> WPA3.
- **Common Attacks:**
  - **Deauthentication Attack:** Forcing a user to disconnect from the AP, allowing the attacker to capture the 4-way handshake when they reconnect.
  - **Evil Twin:** A fraudulent Wi-Fi AP that appears legitimate.
- **Tool Suite:**
  - **Aircrack-ng:** A complete suite for Wi-Fi network security assessment.
    - `airodump-ng`: Capture packets.
    - `aireplay-ng`: Perform deauth attacks.
    - `aircrack-ng`: Crack WEP/WPA/WPA2 passphrases.

---

## 16. Hacking Mobile Platforms
- **Attack Vectors:** Malicious apps, repackaged apps, unencrypted traffic, OS vulnerabilities.
- **Android:** Open source, easier to sideload apps, prone to fragmentation issues.
- **iOS:** Closed source, strict app review, but not immune to jailbreaking and targeted attacks.
- **Tools:**
  - **Drozer:** Security and attack framework for Android.
  - **Objection:** Runtime mobile exploration toolkit.

---

## 17. IoT and OT Hacking
- **IoT (Internet of Things):** Network of physical devices (e.g., smart homes, wearables).
- **OT (Operational Technology):** Systems used in industrial control (e.g., SCADA).
- **Challenges:** Weak default credentials, lack of updates, insecure protocols.
- **Protocols:**
  - **MQTT:** Common IoT messaging protocol.
  - **Modbus:** Common OT protocol.

---

## 18. Cloud Computing
- **Models:**
  - **IaaS (Infrastructure):** You manage OS, apps.
  - **PaaS (Platform):** You manage apps.
  - **SaaS (Software):** You manage data.
- **Common Attacks:**
  - **Misconfigured S3 Buckets:** Publicly exposed cloud storage.
  - **API Key Theft:** Stolen credentials leading to account takeover.
  - **Insecure Serverless Functions:** Vulnerabilities in cloud functions (e.g., AWS Lambda).
- **Tools:**
  - **Pacu:** AWS exploitation framework.

---

## 19. Cryptography
- **Symmetric Encryption:** One key for both encryption and decryption (e.g., AES). Fast.
- **Asymmetric Encryption:** Two keys, public and private (e.g., RSA). Slow. Used for key exchange.
- **Hashing:** One-way function that creates a unique, fixed-length string from data (e.g., SHA-256, MD5). Used for integrity.
- **Digital Signature:** Hashing a message and encrypting the hash with a private key to ensure authenticity and non-repudiation.
