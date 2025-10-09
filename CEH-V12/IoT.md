# IoT Hacking and Security

This module provides a comprehensive overview of the Internet of Things (IoT) ecosystem, including its architecture, technologies, security challenges, and the tools and techniques used by ethical hackers to assess its security.

## 1. Introduction to the Internet of Things (IoT)

The **Internet of Things (IoT)** refers to a vast network of interconnected physical objects ("things") that are embedded with sensors, software, and other technologies for the purpose of connecting and exchanging data with other devices and systems over the internet.

### IoT Components
A typical IoT ecosystem is made up of four main components:
1.  **The "Thing" (Device/Sensor):** The physical hardware that gathers data from its environment (e.g., a temperature sensor, a smart camera, a connected car) or performs an action (e.g., a smart lock).
2.  **The Gateway:** A device that aggregates data from multiple sensors and provides a connection to a wider network like the internet. It often translates proprietary sensor protocols into standard internet protocols like Wi-Fi or Ethernet.
3.  **The Cloud / Network Infrastructure:** The backend servers (often in the cloud) that receive, process, and store the massive amounts of data from IoT devices. This is where the heavy lifting and data analytics happen.
4.  **The User Interface (Application):** The mobile or web application that allows users to interact with and control their IoT devices.

### IoT Architecture (The Four-Stage Model)
```

\+-----------+    +-----------+    +---------------+    +-------------------+
|  Stage 1  | -\> |  Stage 2  | -\> |    Stage 3    | -\> |      Stage 4      |
|  Sensors/ |    |   Gateway |    |   Edge / IT   |    |  Data Center /    |
| Actuators |    | (Aggregator)|    | (Pre-process) |    |   Cloud Analytics |
\+-----------+    +-----------+    +---------------+    +-------------------+

```
1.  **Stage 1: Sensors/Actuators:** Collect data from the environment.
2.  **Stage 2: Data Acquisition Systems (Gateway):** Aggregate and convert data from analog to digital.
3.  **Stage 3: Edge IT:** Performs some pre-processing of data before sending it to the cloud.
4.  **Stage 4: Cloud/Data Center:** In-depth analysis, management, and storage of data.

---

## 2. IoT Deployment Areas

IoT technology is used across many industries:
* **Smart Home:** Connected thermostats, lighting, locks, and voice assistants.
* **Wearables:** Smartwatches and fitness trackers.
* **Smart City:** Smart traffic lights, waste management, and environmental monitoring.
* **Industrial IoT (IIoT):** Connected machinery, predictive maintenance sensors, and supply chain tracking.
* **Connected Vehicles:** Cars with internet access for navigation, remote diagnostics, and entertainment.
* **Smart Agriculture:** Soil sensors, automated irrigation, and drone monitoring.

---

## 3. IoT Technologies, Protocols, and Operating Systems

### Common IoT Technologies and Protocols
As shown in your slide, IoT devices use a variety of communication technologies tailored to their specific needs (range, power consumption, data rate).

| Technology / Protocol | Description | Common Use Case |
| :--- | :--- | :--- |
| **RFID** (Radio Frequency Identification) | Uses radio waves to read information stored on a tag. One-way communication. | Access cards, inventory tracking. |
| **NFC** (Near Field Communication) | A very short-range (a few cm), two-way communication protocol. | Contactless payments, easy device pairing. |
| **BLE** (Bluetooth Low Energy) | A low-power version of Bluetooth for short-range communication. | Wearables, beacons, smart home sensors. |
| **Zigbee** | A low-power, low-data-rate protocol for creating wireless mesh networks. | Smart home automation (lights, switches). |
| **LoRa/LoRaWAN** (Long Range) | A low-power, wide-area network (LPWAN) protocol for long-range communication. | Smart city sensors, agriculture monitoring. |
| **MQTT** (Message Queuing Telemetry Transport) | A lightweight publish/subscribe messaging protocol, ideal for low-bandwidth, high-latency networks. | Sending sensor data to a central broker. |
| **CoAP** (Constrained Application Protocol) | A protocol designed for simple, constrained devices (low memory/power). It's like HTTP but much lighter. | Industrial sensors, smart energy grids. |

### Common IoT Operating Systems
IoT devices often use specialized, lightweight operating systems:
* **TinyOS, Contiki, Riot OS, Zephyr:** Real-time operating systems designed for low-power, memory-constrained devices.
* **Linux (Embedded):** Many more powerful IoT devices (like gateways and routers) run a stripped-down, embedded version of Linux, such as **OpenWrt**.

### IoT Communication Models
* **Device-to-Device:** Devices communicate directly with each other without an intermediary server (e.g., Bluetooth).
* **Device-to-Cloud:** The device connects directly to a cloud service to send data and receive commands.
* **Device-to-Gateway:** The device connects to a local gateway, which then connects to the cloud.

---

## 4. IoT Security Landscape

### Key Security Challenges
* **Weak Credentials:** Many devices ship with default, hardcoded, or easily guessable passwords.
* **Lack of Updates:** Difficult or non-existent firmware update mechanisms leave devices permanently vulnerable.
* **Insecure Communication:** Data is often transmitted without encryption.
* **Physical Security:** Devices are often physically accessible and can be tampered with.
* **Privacy Concerns:** Devices collect vast amounts of potentially sensitive personal data.

### OWASP IoT Top 10 Risks and Vulnerabilities (2018)

| ID | Risk | Description |
| :--- | :--- | :--- |
| **I1** | Weak, Guessable, or Hardcoded Passwords | The most common issue, allowing easy unauthorized access. |
| **I2** | Insecure Network Services | Unnecessary or insecure services (e.g., Telnet, FTP) running on the device. |
| **I3** | Insecure Ecosystem Interfaces | Vulnerabilities in the web, mobile, or cloud interfaces used to manage the device. |
| **I4** | Lack of Secure Update Mechanism | No ability to securely patch firmware, leaving vulnerabilities unpatched forever. |
| **I5** | Use of Insecure or Outdated Components | Using third-party hardware or software with known vulnerabilities. |
| **I6** | Insufficient Privacy Protection | The device or its ecosystem stores or transmits user's personal information insecurely. |
| **I7**| Insecure Data Transfer and Storage| Lack of encryption for data in transit and at rest. |
| **I8**| Lack of Device Management| The inability to securely manage and decommission devices. |
| **I9**| Insecure Default Settings| Shipping devices with insecure settings enabled by default. |
| **I10**| Lack of Physical Hardening| The device is susceptible to physical tampering to extract keys or firmware. |

### Common IoT Attacks
* **SQL Injection:** Exploiting the web interface of a device or its cloud backend.
* **Ransomware:** Infecting and disabling a smart device (like a thermostat or smart lock) until a ransom is paid.
* **Denial of Service (DoS):** Overwhelming a device or its network to make it unresponsive.
* **Man-in-the-Middle (MitM):** Intercepting traffic between the device, gateway, app, and cloud.
* **Remote Code Execution (RCE):** The ultimate goal for an attacker, allowing them to take full control of the device.

---

## 5. IoT Hacking Tools

Ethical hackers use a variety of tools to test the security of an IoT ecosystem.

| Tool | Primary Use in IoT Hacking |
| :--- | :--- |
| **Nmap** | Scanning IoT devices and gateways for open ports and running services. |
| **Metasploit** | Exploiting known firmware vulnerabilities to gain remote access. |
| **Fiddler / OWASP ZAP** | Intercepting and analyzing API traffic between the mobile app and the cloud backend. |
| **Maltego** | Mapping out the relationships between the device, company, cloud infrastructure, and personnel. |
| **Wireshark** | Sniffing and analyzing network traffic to decode IoT protocols like MQTT and CoAP. |
| **Binwalk** | A firmware analysis tool used to extract file systems and other data from firmware images. |
| **Firmwalker** | A script that scans an extracted firmware file system for sensitive information like passwords, keys, and certificates. |
| **GhostTouch** | An advanced attack/tool that can inject fake touch events into a device's touchscreen via electromagnetic interference. |

---

## 6. IoT Security Precautions (Countermeasures)
* **Change Default Credentials:** This is the most important first step. Always change the default username and password on any new device.
* **Create an Isolated Network:** Use a separate Wi-Fi network (or VLAN) for your IoT devices to keep them isolated from your primary computers and sensitive data.
* **Keep Firmware Updated:** Always install firmware updates from the manufacturer as soon as they are available.
* **Disable Unnecessary Features:** Turn off features you don't use, such as UPnP (Universal Plug and Play), remote access, and Telnet.
* **Do Your Research:** Before buying a device, research the manufacturer's security reputation and its policy on updates.
* **Secure Your Wi-Fi:** Ensure your main Wi-Fi network is secured with a strong WPA2/WPA3 password.
