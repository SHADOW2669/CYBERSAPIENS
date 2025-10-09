# Wireless and Bluetooth Hacking

This guide details the common attack vectors against wireless (Wi-Fi) and Bluetooth technologies, the tools used by ethical hackers to test them, and the essential countermeasures to secure these connections.

---

## 1. Hacking Wireless (Wi-Fi) Networks

Wireless Local Area Networks (WLANs), commonly known as Wi-Fi, are defined by the IEEE 802.11 standards. They allow devices to connect to a network without physical cables, but this convenience also introduces unique security risks.

### Common Wi-Fi Attacks

#### A. MAC Spoofing
* **Concept:** A technique where an attacker changes the Media Access Control (MAC) address of their network interface to impersonate another legitimate device. Each network card has a unique, hardcoded MAC address, but it can be changed in software.
* **Attacker's Goal:**
    1.  **Bypass MAC Filtering:** If a network only allows devices with specific MAC addresses to connect, an attacker can spoof a permitted MAC address to gain access.
    2.  **Impersonate a Client:** An attacker can impersonate an already authenticated client to hijack their session or bypass captive portals.
* **Key Tool:** `macchanger` (on Linux).
    * **Example Command:** `macchanger -r wlan0` (This sets a random MAC address on the `wlan0` interface).

#### B. Deauthentication & Disassociation Attacks
* **Concept:** These are Denial-of-Service (DoS) attacks that target the 802.11 management frames used to control a client's connection state.
    * **Deauthentication Attack:** The attacker sends spoofed "deauth" frames to a connected client, pretending to be the Access Point (AP). This forces the client to disconnect and immediately try to re-authenticate.
    * **Disassociation Attack:** Similar, but sends "disassoc" frames, which just terminates the current connection without forcing a full re-authentication. The deauth attack is more common and disruptive.
* **Attacker's Goal:**
    1.  **Denial of Service:** To kick a user or all users off the network.
    2.  **Capture WPA/WPA2 Handshake:** When the client automatically tries to reconnect, the attacker can capture the 4-way handshake, which can then be taken offline to crack the Wi-Fi password.
* **Key Tool:** `aireplay-ng` (part of the Aircrack-ng suite).
    * **Example Command:** `aireplay-ng --deauth 0 -a <AP_BSSID> -c <Client_MAC> wlan0mon` (This sends a continuous stream of deauth packets to a specific client).

#### C. Man-in-the-Middle (MitM) Attack
* **Concept:** An attacker positions themselves between the user and the Access Point, intercepting all traffic that flows between them.
* **Attacker's Goal:** To eavesdrop on, steal, or modify sensitive information like passwords, session cookies, and financial data transmitted over the network.
* **Methodology:** This is often achieved by first performing a deauth attack and then setting up an **Evil Twin** AP.

#### D. Rogue Access Point
* **Concept:** An unauthorized Access Point that has been physically connected to the trusted, wired corporate network without permission.
* **Attacker's Goal:** To create an unsecured backdoor into a secure network, bypassing the main firewall and other perimeter defenses.
* **Example:** An employee or an attacker with physical access brings in a cheap personal Wi-Fi router and plugs it into an active Ethernet port in an office, creating an open network that connects directly to the internal LAN.

#### E. Evil Twin
* **Concept:** A fraudulent Access Point set up by an attacker that appears to be a legitimate one. It is configured with the same SSID (network name) as a nearby trusted network.
* **Attacker's Goal:** To trick users into connecting to the attacker's AP instead of the real one. Attackers often boost their signal to be stronger than the legitimate AP's, causing devices to prefer it. Once a user connects, the attacker can launch a MitM attack to steal their data or present them with a fake "captive portal" to harvest credentials.

### Wireless Hacking Tools

* **Aircrack-ng Suite:** This is the essential, all-in-one command-line toolkit for Wi-Fi security auditing.
    * **`airmon-ng`:** Used to enable "monitor mode" on a wireless network card, which is necessary for capturing all 802.11 frames.
    * **`airodump-ng`:** Used for discovering Wi-Fi networks, viewing connected clients, and capturing packets, especially the WPA/WPA2 handshake.
    * **`aireplay-ng`:** Used for injecting packets, most famously for performing deauthentication attacks.
    * **`aircrack-ng`:** The password cracking tool. It uses a wordlist to perform a dictionary attack on a captured handshake file (`.cap`).

* **Wifite:** An automated Python script that uses the Aircrack-ng suite in the background. It simplifies the entire process of scanning, attacking, and cracking Wi-Fi networks into a few simple menu-driven steps.

* **Kismac / Kismet:** Powerful wireless network detectors, sniffers, and intrusion detection systems. They can passively collect information about networks, detect hidden SSIDs, and identify suspicious activity. (Kismet is the cross-platform tool, Kismac was a popular older tool for macOS).

* **Fern Wifi Cracker:** A GUI-based security auditing and attack tool written in Python. It provides a user-friendly interface for running various wireless attacks, making it accessible to those who are not experts with command-line tools.

---

## 2. Hacking Bluetooth

Bluetooth is a short-range wireless technology used to create Personal Area Networks (PANs). While convenient for connecting peripherals, it has its own set of vulnerabilities.

### Common Bluetooth Attacks

#### A. Bluejacking
* **Concept:** The act of sending unsolicited messages (typically a contact card or a note) to other Bluetooth-enabled devices.
* **Goal:** Primarily an annoyance or a prank. It does not involve stealing data or taking control of the device. However, it can be the first step in a social engineering attack if the message tricks the user into a malicious action.
* **How it works:** Exploits the OBEX (Object Exchange) protocol to push a message to a device set in "discoverable" mode.

#### B. Bluesnarfing
* **Concept:** A much more serious attack involving the unauthorized **theft of information** from a wireless device through a Bluetooth connection.
* **Goal:** To access and steal sensitive data such as the victim's contacts list (phonebook), calendar, emails, and text messages without their knowledge.
* **How it works:** Exploits vulnerabilities in the OBEX protocol on older, unpatched devices that have poor authentication mechanisms.

#### C. Bluebugging
* **Concept:** The most severe Bluetooth attack. An attacker gains **total control** over a target device, effectively turning it into a "bug."
* **Goal:** To use the phone's features without the owner's knowledge. This includes:
    * Making and listening to phone calls.
    * Sending and receiving text messages.
    * Reading and modifying contacts.
    * Eavesdropping on conversations through the phone's microphone.
* **How it works:** Exploits critical firmware vulnerabilities in older Bluetooth devices, allowing the attacker to install a backdoor.

### Bluetooth Hacking Prevention

Implementing the following best practices can significantly reduce the risk of Bluetooth attacks:

* **Turn Off Bluetooth:** If you are not actively using it, turn it off. This is the most effective defense.
* **Use "Hidden" or "Non-Discoverable" Mode:** When Bluetooth is on, make sure it is not visible to other devices unless you are actively trying to pair a new device.
* **Use Strong Pairing Codes:** Avoid default passcodes like `0000` or `1234`. Use a long, random PIN when pairing.
* **Keep Firmware Updated:** Regularly update your phone, headset, and other Bluetooth devices to ensure they have the latest security patches.
* **Be Wary of Pairing Requests:** Do not accept pairing requests from unknown or unexpected devices.
* **Unpair Unused Devices:** Remove old pairings from your device's list that you no longer use.
