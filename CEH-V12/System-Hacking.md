# System Hacking: Methodology and Techniques

Welcome to this in-depth guide on System Hacking. This document provides a detailed, chapter-by-chapter explanation of the complete system hacking lifecycle, mirroring the methodology used by ethical hackers in a professional penetration test. We will explore the techniques used to gain initial access, escalate privileges, maintain a persistent presence, and finally, erase all evidence of the intrusion.

---

## Chapter 1: The System Hacking Methodology

System Hacking is the phase in the ethical hacking lifecycle where an attacker, having completed reconnaissance and scanning, attempts to gain unauthorized access, escalate privileges, maintain control, and cover their tracks on a target system. This process is not random; it follows a structured methodology to ensure a thorough and effective compromise.

The five core stages are:
1.  **Gaining Access:** The initial breach of the system.
2.  **Privilege Escalation:** Elevating access from a standard user to an administrator.
3.  **Executing Applications & Hiding Files:** Running malicious tools and concealing them.
4.  **Maintaining Access:** Creating persistent backdoors.
5.  **Clearing Logs & Covering Tracks:** Removing all evidence of the intrusion.

---

## Chapter 2: Gaining Access - The Initial Foothold

This is the most critical phase, where an attacker first breaches the target's defenses. A primary method is to circumvent authentication, which requires a deep understanding of how systems, particularly Microsoft Windows, handle credentials.

### 2.1 Understanding Microsoft Authentication

-   **SAM (Security Account Manager) Database:** The SAM is a database file located at `C:\Windows\System32\config\SAM` on all non-domain-joined (workgroup) Windows systems. It serves as the primary storage for local user accounts and their password hashes. The SAM database does not store passwords in plaintext. Instead, it stores a hashed representation (typically the NTLM hash). While Windows is running, the operating system kernel maintains an exclusive lock on the SAM file, making it impossible for a user to simply copy or read it. An attacker's goal is to dump the hashes from the SAM, either by extracting them from system memory (e.g., using Mimikatz) or by booting the machine into another operating system to access the file directly.

-   **NTLM (New Technology LAN Manager) Authentication:** The default authentication protocol used in Windows workgroup environments (non-domain). It is a challenge-response protocol. When a user attempts to access a resource, the server sends a "challenge" (a random piece of data). The client encrypts the challenge using the user's NTLM password hash as the key. The server performs the same calculation and, if the results match, grants access. The protocol is susceptible to "Pass-the-Hash" attacks, where an attacker who has stolen a user's NTLM hash can use it to authenticate to other systems without ever needing to know the plaintext password.

-   **Kerberos Authentication:** The default, ticket-based authentication protocol for systems within a Microsoft Active Directory domain. It is significantly more secure than NTLM. Kerberos uses a trusted third party, the Key Distribution Center (KDC), to issue "tickets" for authentication. A user logs in and their client requests a **Ticket-Granting Ticket (TGT)** from the KDC. When the user wants to access a service (like a file share), they present the TGT to the KDC and request a **Service Ticket**. The user then presents the Service Ticket to the application server to gain access. While robust, Kerberos is vulnerable to attacks like "Kerberoasting," where an attacker can request a Service Ticket for a specific service and extract the service account's password hash from it for offline cracking.

### 2.2 Password Cracking: A Deep Dive

Password cracking is the process of recovering passwords from the hashes that are stored or transmitted by a system. The attacks are categorized based on where and how they are performed.

#### Non-Digital Attacks
-   **Shoulder Surfing:** Directly observing a user typing their password.
-   **Social Engineering:** Manipulating a user into divulging their password.
-   **Dumpster Diving:** Searching through discarded materials (paper, old hard drives) for written passwords or sensitive information.

#### Active Online Attacks
The attacker directly interacts with a live login service (e.g., RDP, SSH, web form), getting an immediate success/failure response.

-   **Dictionary Attack:** Using a wordlist of common passwords.
-   **Brute Forcing:** Trying every possible character combination.
-   **Hash Injection (Pass-the-Hash):** Using a captured NTLM hash to authenticate to a remote server without needing the plaintext password.
-   **LLMNR/NBT-NS Poisoning:** A man-in-the-middle attack that intercepts authentication requests on a local network when a DNS lookup fails, allowing the attacker to capture password hashes.
-   **Malware:** Using Trojans, spyware, or keyloggers to capture credentials directly from the user's machine.
-   **Other Specialized Attacks:**
    -   **Combinator Attack:** Combines words from multiple dictionaries.
    -   **Fingerprint Attack:** Breaks passphrases into smaller parts to crack complex passwords.
    -   **PRINCE Attack:** Builds password candidates by chaining words from a single dictionary.
    -   **Toggle-Case Attack:** Tries all upper and lower case combinations of a word.
    -   **Markov-Chain Attack:** Analyzes a password database to learn common password patterns and generate more intelligent guesses.

#### Passive Online Attacks
The attacker captures data from the network without actively trying to log in.

-   **Wire Sniffing / Packet Sniffing:** Using tools like **Wireshark** or **tcpdump** to capture network traffic. If an application uses an insecure, unencrypted protocol (FTP, Telnet, HTTP), passwords can be read in plain text. Tapping refers to using physical hardware to intercept network signals.
-   **MITM (Man-in-the-Middle) Attacks:** An attacker places themselves between a user and a server, intercepting and potentially modifying traffic to steal credentials. Tools like **Ettercap** and **Bettercap** are used for this.
-   **Replay Attacks:** Capturing a valid authentication session (e.g., a cookie or an NTLM response) and replaying it later to impersonate the user without needing the password.

#### Offline Attacks
This is the most powerful and preferred method. The attacker first obtains the password hashes and cracks them on their own dedicated hardware.

-   **Rainbow Table Attacks:** Using pre-computed lookup tables to find the plaintext password for a given hash. **RainbowCrack** is a key tool for this.
-   **Distributed Network Attacks (DNA):** Using the combined power of multiple machines (often with powerful GPUs) to crack hashes. Modern tools like **Hashcat** and **John the Ripper** are the industry standard and can make billions of guesses per second.

---

## Chapter 3: Privilege Escalation

Once on a system as a standard user, the goal is to gain administrator, root, or SYSTEM privileges.

-   **Types of Privilege Escalation:**
    -   **Vertical:** Gaining higher privileges than the current user (e.g., user to admin).
    -   **Horizontal:** Gaining access as another user with a similar privilege level.

### Key Techniques
-   **Exploiting Known Vulnerabilities:** The most common method. An attacker identifies the patch level of the OS or installed software and uses a public exploit for an unpatched vulnerability.
-   **DLL Hijacking:** A Windows-specific attack where an attacker places a malicious DLL with the same name as a legitimate one in a location where a high-privilege application will load and execute it first.
-   **Exploiting Misconfigured Services:** Abusing services with weak permissions on their executable files or "unquoted service paths," which can allow an attacker to trick the service into running a malicious program.
-   **Abusing SUID/SGID Permissions (Linux):** Exploiting misconfigured executable files that run with the privileges of the file owner (e.g., root).
-   **Abusing `sudo` Rights (Linux):** Exploiting an overly permissive `/etc/sudoers` file.
-   **Kernel Exploits:** Targeting a vulnerability in the core of the operating system.
-   **Access Token Manipulation (Windows):** Stealing and impersonating access tokens from higher-privileged processes.
-   **Web Shells:** Using a shell uploaded to a web server to execute system commands.
-   **Other Techniques:** DyLib Hijacking (macOS), Spectre/Meltdown, Named Pipe Impersonation, Pivot and Relay attacks, Launch Daemon exploits, and replacing binaries of Scheduled Tasks.

### Privilege Escalation Tools
-   **LinPEAS / WinPEAS:** Scripts that automatically find a wide range of privilege escalation vectors on Linux and Windows.
-   **PowerSploit:** A PowerShell framework for post-exploitation on Windows.
-   **Windows Exploit Suggester:** A script that compares a target's patch level against a database of known Microsoft exploits.
-   **BeRoot:** A tool to check for common misconfigurations to escalate privileges.
-   **Metasploit's Local Exploit Suggester.**

---

## Chapter 4: Hiding Files

To maintain long-term access and avoid detection by antivirus or system administrators, an attacker must hide their malicious tools.

-   **Rootkits:** A type of malware specifically designed to modify the core of the operating system (the kernel) to hide its own presence. A rootkit can conceal files, running processes, and network connections, making the attacker's presence invisible.
-   **NTFS Alternate Data Streams (ADS):** A feature of the Windows NTFS file system that allows data to be stored in hidden "streams" attached to a legitimate file. A malicious executable can be hidden inside a harmless text file and will not be visible in a standard directory listing.
-   **Steganography:** The practice of concealing a file, message, image, or video within another file. An attacker can hide a malicious script or payload inside a seemingly innocent image or audio file to bypass security scans.

---

## Chapter 5: Maintaining Access

The attacker ensures they can get back into the system at any time, even if the original vulnerability is patched or the user changes their password.

-   **Remote Code Execution (Backdoors):** This involves installing a piece of software that creates a persistent entry point. Common methods include:
    -   **Trojans:** Malicious programs disguised as legitimate software that open a backdoor for the attacker.
    -   **Web Shells:** A malicious script uploaded to a web server that provides a command-line interface to the attacker through their web browser.
    -   **Creating New Admin Accounts:** The simplest method is to create a new, hidden administrative account.
-   **Keyloggers and Spyware:** These are forms of malware installed on the compromised system for continuous intelligence gathering.
    -   **Keyloggers:** Capture every keystroke the user types, including passwords, credit card numbers, and private messages.
    -   **Spyware:** Gathers a broader range of information, including screenshots, browsing history, and files.

---

## Chapter 6: Clearing Logs and Covering Tracks

This is the final phase, where the attacker removes all evidence of their activities to evade detection and hinder forensic investigation.

-   **Disabling Auditing:** An attacker with administrative rights can turn off system auditing policies (e.g., via Group Policy in Windows) to prevent their subsequent actions from being logged.
-   **Manual Clearing:** This involves selectively editing or deleting specific entries from system logs.
    -   **Windows:** Using tools to clear the Windows Event Logs (Application, Security, System).
    -   **Linux:** Modifying or deleting log files in `/var/log` (e.g., `auth.log`, `syslog`) and clearing the user's command history (`.bash_history`).
-   **Track-Covering Tools:** Using dedicated tools designed to securely wipe logs, modify timestamps, and remove forensic artifacts in a way that is difficult to trace.
