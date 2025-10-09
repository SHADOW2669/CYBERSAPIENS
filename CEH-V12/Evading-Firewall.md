# Evading Firewall, IDS and HoneyPOTS

This module covers the essential security defenses an ethical hacker must understand (Firewalls, IDS, IPS, Honeypots) and the techniques used by attackers to bypass them.

---

## 1. Firewall and Firewall Rules

A **Firewall** is a network security device that monitors and controls incoming and outgoing network traffic based on a predetermined set of security rules. It acts as a barrier or a "gatekeeper" between a trusted internal network and an untrusted external network, such as the Internet.



```
  +------------------+                    +---------------------+
  |                  |   <-- Traffic -->  |                     |
  |  Internal (LAN)  | ================== |  Internet (Untrusted) |
  |    (Trusted)     | |   **Firewall** | |                     |
  |                  | ================== +---------------------+
  +------------------+
```


### Firewall Rules
Firewall rules are the instructions that tell the firewall what to do with network traffic. Each rule specifies criteria for traffic (like source/destination IP, port, protocol) and an action to take (Allow, Deny, Reject). Rules are processed in a specific order (usually top-down), and the first rule that matches the traffic is applied. Most firewalls end with an implicit "deny all" rule.

**Example Firewall Rule Set:**
| Rule # | Source IP | Destination IP | Port | Protocol | Action | Description |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | Any | 192.168.1.100 | 80, 443 | TCP | **Allow** | Allow web traffic to the web server. |
| 2 | 192.168.1.0/24| Any | 53 | UDP | **Allow** | Allow internal DNS lookups. |
| 3 | Any | Any | 23 | TCP | **Deny** | Block all incoming Telnet traffic. |
| 4 | Any | Any | Any | Any | **Deny** | Implicit Deny All (Default Rule). |

---

## 2. Intrusion Detection System (IDS)

An **Intrusion Detection System (IDS)** is a device or software application that monitors a network or system for malicious activity or policy violations. Its job is to **detect** a potential incident, log the details, and report it by sending an alert.

> **Analogy:** An IDS is like a **burglar alarm**. It alerts you when someone breaks in, but it doesn't stop them on its own.

### Types of IDS

#### A. Network Intrusion Detection System (NIDS)
A NIDS is placed at a strategic point within the network to monitor traffic to and from all devices. It analyzes passing traffic and matches it against a library of known attacks (signatures) or identifies anomalous behavior.

```

   Switch
  +--------+


...--| Port 1 |------ Host A
| Port 2 |------ Host B
| Port 3 |------ Host C
| SPAN   |------[ **NIDS** ] (Listens passively)
\+--------+

```

#### B. Host-based Intrusion Detection System (HIDS)
A HIDS runs on an individual host or device. It monitors the host's internal activity, such as critical system file changes, application logs, and system calls, to detect malicious behavior.

* **Monitors:** Log files, file integrity (checksums), running processes, registry changes (on Windows).
* **Benefit:** Can detect attacks that a NIDS might miss (e.g., malware run from a USB drive).

### IDS Alerts
When an IDS signature or rule is matched, it generates an **alert**. A useful alert typically contains:
* **Timestamp:** When the event occurred.
* **Source and Destination IP/Port:** Who is talking to whom.
* **Alert Description:** The name of the suspected attack (e.g., "SQL Injection Attempt").
* **Severity Level:** The assessed risk (e.g., Low, Medium, High).
* **Key Concepts:**
    * **False Positive:** The IDS flags legitimate traffic as malicious.
    * **False Negative:** The IDS fails to detect a real attack.

---

## 3. Intrusion Prevention System (IPS)

An **Intrusion Prevention System (IPS)** is a security device that not only detects malicious activity but also takes automated action to **prevent** the attack from succeeding.

> **Analogy:** An IPS is like an **armed security guard**. It detects the break-in and actively stops the intruder at the gate.

The key difference is that an IPS sits **inline** with the network traffic, meaning the traffic must pass *through* the IPS.

### Types of IPS
The types mirror IDS:
* **Network Intrusion Prevention System (NIPS):** Sits inline on the network and blocks malicious network traffic in real-time.
* **Host-based Intrusion Prevention System (HIPS):** Software on a host that can prevent malicious actions, such as stopping a process from overwriting a critical system file.

### IPS Over IDS: The Key Advantage
The main advantage of an IPS is its ability to provide a proactive, automated response to threats.

**Diagram: IDS (Passive) vs. IPS (Inline)**
```

  // IDS (Out-of-Band)
  Traffic --> [ Switch ] --> Destination
                 |
                 V
              [ **IDS** ] (Alerts)

  // IPS (In-Band)
  Traffic --> [ **IPS** ] --> [ Switch ] --> Destination
              (Blocks)


```
* **IPS Advantage:** Can stop attacks automatically without human intervention.
* **IPS Disadvantage:** A false positive can cause a **denial of service** by blocking legitimate users.

---

## 4. Honeypot

A **Honeypot** is a security mechanism set up to be a decoy. It is intentionally designed to look like a legitimate, valuable target to attract attackers. The goal is to distract attackers from real targets and to study their methods and tools in a safe, monitored environment.

```
                              +------------+
                              | Attacker   |
                              +------------+
                                    |
                                    V
  +------------------+        +------------+
  |  Real Servers    |        | Firewall   |
  | (Protected)      | <----- |            |
  +------------------+        +------------+
                                    |
                                    V
                              +------------+
                              | Honeypot   | (Looks real, but is a trap)
                              +------------+
```


### Advantages of a Honeypot
* **Early Warning:** Can provide an early warning of an attack.
* **Distraction:** Diverts attackers from critical production systems.
* **Threat Intelligence:** Allows security teams to gather information about new attack methods, malware, and the origin of attacks.
* **Low False Positives:** Any traffic directed to the honeypot is, by definition, suspicious.

---

## 5. Evasion: Bypassing Defenses

**Evasion** refers to the techniques used by attackers to bypass security defenses like Firewalls and IDS/IPS.

### General Evasion Techniques

* **Fragmentation:** Splitting a malicious packet into multiple smaller packets (fragments). Simple IDS may fail to reassemble the fragments correctly and therefore miss the signature of the attack payload.
* **Obfuscation:** Making the payload difficult for an IDS to read by encoding it (e.g., using Base64, Hex, or URL encoding) to bypass simple signature matching.
* **Encryption:** Using encrypted protocols like HTTPS, SSH, or VPNs. A standard NIDS/NIPS cannot inspect the encrypted payload, rendering it blind to the attack.
* **Flood the Network:** Sending a massive amount of traffic or generating thousands of low-priority alerts to overwhelm the security device or the security analyst. The real attack is hidden within this "noise."

### Evasion Using Nmap

Nmap includes several features specifically designed to evade detection during a network scan.

* **Fragment Scan (`-f`)**
    * **Technique:** This command tells Nmap to split its probe packets into tiny 8-byte fragments. This can sometimes confuse less sophisticated firewalls or IDS that are configured to block standard TCP header patterns.
    * **Command:** `nmap -f <target_ip>`

* **Decoy Scan (`-D`)**
    * **Technique:** This makes a scan appear to be coming from multiple source IP addresses, not just the attacker's. The attacker's real IP is mixed in with a series of fake "decoy" IPs. This floods the target's logs, making it very difficult to determine the true source of the scan.
    * **Command:** `nmap -D RND:10,ME <target_ip>` (This generates 10 random decoy IPs and includes your own `ME`).
    * **Diagram:**
        ```
          Decoy IP 1 --\
          Decoy IP 2 ----\
          Attacker IP -----> [ Target ] (Logs show scans from many IPs)
          Decoy IP 3 ----/
          Decoy IP 4 --/
        ```

* **Idle Scan (`-sI`)**
    * **Technique:** This is a highly advanced and stealthy scan that uses a "zombie" host to conduct the scan on the attacker's behalf. The attacker sends no packets directly to the target from their own IP. It works by analyzing the IPID (IP Identification) number changes on the zombie host.
    * **Command:** `nmap -sI <zombie_ip> <target_ip>`
    * **Diagram:**
        ```
          1. Attacker probes Zombie's IPID
             +----------+      +-----------+
             | Attacker |----->| Zombie    |
             +----------+      +-----------+

          2. Attacker sends spoofed packet
             (from Zombie) to Target
                               +-----------+
                               | Zombie    | <--- SYN/ACK (if port open)
                               +-----------+      |
                                     ^            |
                                     | RST (zombie didn't initiate)
                                     |
             +----------+      +-----------+
             | Attacker |----->|  Target   |
             +----------+      +-----------+
               (Spoofed)

          3. Attacker re-probes Zombie's IPID
             to see if it changed, determining
             the Target's port state.
        ```
