# Network Scanning: An In-Depth Overview

Network scanning is the second phase in the ethical hacking methodology, following the reconnaissance (footprinting) phase. While footprinting is largely passive, network scanning is an active process. It involves directly probing the target's network and systems to gather specific technical information.

If footprinting is like studying a map and blueprints of a building, network scanning is like walking around the building and rattling every door and window to see which ones are unlocked.

## The Primary Objectives of Network Scanning

The goal of network scanning is to create a detailed service-level map of the target organization. This involves achieving several key objectives:

#### 1. Discover Live Hosts
-   **Objective:** To identify which IP addresses within the target's network range are active and responsive. A network can have thousands of potential IP addresses, but only a fraction may be in use. This step filters out the inactive hosts, allowing the hacker to focus their efforts.
-   **Technique:** This is often done using a **Ping Sweep** or **Network Sweep**, which sends ICMP Echo requests (or other types of probes like TCP/UDP packets) to a range of IP addresses to see which ones reply.

#### 2. Identify Open Ports
-   **Objective:** To discover which TCP and UDP ports are open on the live hosts. An open port indicates that a service is listening and potentially accessible. Each open port is a potential gateway into the system.
-   **Technique:** This is done via **Port Scanning**, where a scanner sends packets to a range of port numbers (from 1 to 65,535) on a target host to analyze the responses and determine which ports are open, closed, or filtered by a firewall.

#### 3. Discover Running Services
-   **Objective:** To go beyond just identifying an open port and to determine the specific service and its version number running on that port. For example, it's not enough to know port 80 is open; the goal is to know it's running `Microsoft-IIS/10.0` or `Apache httpd 2.4.52`.
-   **Technique:** This is known as **Service Version Detection** or **Banner Grabbing**. The scanner sends specific probes designed to elicit a response from the service that reveals its identity and version. This is critical because vulnerabilities are often tied to specific software versions.

#### 4. Fingerprint the Operating System
-   **Objective:** To determine the underlying operating system (OS) of the target host (e.g., `Windows Server 2022`, `Ubuntu Linux 22.04`).
-   **Technique:** **OS Fingerprinting** works by analyzing the subtle differences in how various operating systems respond to network packets. The scanner sends a series of specially crafted packets and compares the target's TCP/IP stack responses to a database of known OS fingerprints.

#### 5. Map the Network Architecture
-   **Objective:** To understand the network topology and identify security devices that may be in place between the attacker and the target.
-   **Technique:** By analyzing the results of scans and traceroutes, an attacker can infer the presence of firewalls, Intrusion Detection Systems (IDS), and load balancers. For example, if a port scan shows a port as "filtered" instead of "open" or "closed," it usually indicates a firewall is blocking the probe.

---

## Key Scanning Tools

-   **Nmap (Network Mapper):** The undisputed industry-standard tool for network scanning. It is a powerful and versatile command-line utility that can perform host discovery, port scanning, service version detection, OS fingerprinting, and even vulnerability scanning through its Nmap Scripting Engine (NSE).
-   **Nessus / OpenVAS:** These are dedicated vulnerability scanners. They use the information gathered from a port scan to actively test services for thousands of known vulnerabilities and misconfigurations.
-   **Masscan:** An extremely fast TCP port scanner designed to scan very large networks, or even the entire internet, at incredible speeds.

---

## Scanning Countermeasures

Organizations use several methods to detect and prevent unauthorized network scanning.

-   **Firewalls and Access Control Lists (ACLs):** These are the primary defense, configured to block probes to non-public ports and drop traffic from untrusted sources.
-   **Intrusion Detection/Prevention Systems (IDS/IPS):** These systems are specifically designed to recognize scanning patterns (e.g., a single IP probing many ports sequentially or randomly) and can either raise an alert (IDS) or actively block the traffic (IPS).
-   **Log Monitoring:** Regularly reviewing firewall, server, and IDS/IPS logs can help security teams detect scanning activities that may indicate an impending attack.
-   **Honeypots:** Decoy systems set up to lure and trap attackers. Any interaction with a honeypot is, by definition, malicious and provides an early warning of scanning and reconnaissance activities.

-   Of course. Here is a detailed breakdown of network scanning methodology and the key tools used in the process, presented in markdown format.

-----

# Scanning Methodology and Tools

This guide outlines the systematic methodology used for network scanning and provides details on the essential tools that every ethical hacker should know.

## Scanning Methodology: A Step-by-Step Approach

A successful network scan is not a random process but a structured approach to progressively uncover more detailed information about a target.

### Step 1: Check for Live Systems (Host Discovery)

Before you can scan for open ports, you must first identify which hosts on the network are active. This is done by "sweeping" the network to see which IP addresses respond.

  - **Goal:** To create a list of live targets.
  - **Techniques:**
      - **Ping Sweep:** Sending ICMP Echo requests to a range of IP addresses. Hosts that respond are considered live.
      - **TCP/UDP Probes:** For networks that block ICMP (ping), tools can send TCP SYN or UDP packets to common ports to elicit a response.
  - **Nmap Command:**
    ```bash
    # Perform a ping scan on the 192.168.1.0/24 network (no port scan)
    nmap -sn 192.168.1.0/24
    ```

### Step 2: Check for Open Ports (Port Scanning)

Once you have a list of live hosts, the next step is to probe each host to discover which TCP and UDP ports are open. Open ports represent potential entry points.

  - **Goal:** To identify all accessible services on a target host.
  - **Common Scan Types:**
      - **TCP Connect Scan (`-sT`):** The most basic and reliable scan. It completes the full three-way TCP handshake. **Advantage:** Very accurate. **Disadvantage:** Very "noisy" and easily logged by the target system.
      - **TCP SYN "Stealth" Scan (`-sS`):** The most popular scan type. It performs a "half-open" scan by sending a SYN packet and waiting for a SYN/ACK response. If it gets one, it knows the port is open but immediately sends a RST packet to tear down the connection before it is fully established. **Advantage:** Stealthier and less likely to be logged.
      - **UDP Scan (`-sU`):** Scans for open UDP ports. **Advantage:** Necessary for finding services like DNS, SNMP, and DHCP. **Disadvantage:** Much slower and less reliable than TCP scans because UDP is connectionless.
      - **FIN, Null, & Xmas Scans:** Extremely stealthy scan types that send malformed TCP packets. They are designed to bypass older, non-stateful firewalls and some IDS.

### Step 3: Perform Banner Grabbing / Service Version Detection

Knowing a port is open is useful, but knowing the exact software and version running on that port is critical. Vulnerabilities are almost always tied to specific software versions.

  - **Goal:** To identify the application name and version number of each running service.
  - **Technique:** The scanner sends specific probes to the open ports to analyze the service's response "banner."
  - **Nmap Command:**
    ```bash
    # Probe open ports to determine service/version info
    nmap -sV target.com
    ```

### Step 4: Scan for Vulnerabilities

With a list of services and their versions, you can now check for known security flaws.

  - **Goal:** To map the identified services to a database of known vulnerabilities (like CVEs).
  - **Technique:** This is typically done with a dedicated vulnerability scanner or by using a powerful scripting engine.
  - **Nmap Command:**
    ```bash
    # Run a script scan using the "vuln" category of scripts
    nmap --script=vuln target.com
    ```

### Step 5: Document Findings

Throughout the process, all findings—live hosts, open ports, service versions, potential vulnerabilities—must be meticulously documented. This documentation forms the basis for the next phase: Gaining Access.
---

# A Deep Dive into Scanning Tools and Nmap Commands

This guide provides a detailed look at the most common scanning tools used in ethical hacking. It features a comprehensive command reference for Nmap and an overview of other powerful scanners.

## Nmap (Network Mapper): The Ultimate Command Guide

Nmap is the industry-standard tool for network exploration and security auditing. Its flexibility and power are unmatched. Below is a detailed breakdown of its most essential commands.

### Target Specification
How you define your target(s).

-   **Single Target:** `nmap 192.168.1.1` or `nmap target.com`
-   **Multiple Targets:** `nmap 192.168.1.1 192.168.1.5`
-   **Range of IPs:** `nmap 192.168.1.1-20` (Scans IPs from 1 to 20)
-   **Subnet (CIDR Notation):** `nmap 192.168.1.0/24` (Scans all 256 IPs in the subnet)
-   **From a File:** `nmap -iL /path/to/targets.txt` (Scans all targets listed in the file)

### Host Discovery (Ping Scans)
Used to find live hosts without performing a full port scan.

-   **`nmap -sn <target>`:** (No Port Scan) The standard ping scan. It only discovers which hosts are online.
-   **`nmap -Pn <target>`:** (No Ping) Skips host discovery entirely and scans every port on every target IP. Use this if you know the hosts are online but are blocking ping requests.
-   **`nmap -PS<portlist> <target>`:** TCP SYN Ping. Sends a SYN packet to specified ports (default is 80). Good for bypassing firewalls that only block ICMP.
-   **`nmap -PA<portlist> <target>`:** TCP ACK Ping. Similar to SYN ping but sends ACK packets.

### Port Scanning Techniques
The core of Nmap's functionality.

-   **`traceroute <target>`:** **Trace Route.** Maps the hop-by-hop network path to a destination by sending active probes, revealing the IP addresses of intermediary routers and helping to identify network topology.
-   **`nmap -sL <target>`:** **List Scan.** Performs a reverse DNS lookup for a target range to identify hostnames without sending any packets to the targets, making it a completely stealthy reconnaissance method.
-   **`nmap -sS <target>`:** **TCP SYN (Stealth) Scan.** The default for privileged (root) users. It performs a "half-open" scan, which is fast and less likely to be logged. This is the most popular scan type.
-   **`nmap -sT <target>`:** **TCP Connect Scan.** The default for non-privileged users. It completes the full three-way handshake. It's reliable but very noisy and easily detected.
-   **`nmap -sU <target>`:** **UDP Scan.** Scans for open UDP ports. It is much slower and less reliable than TCP scans.
-   **`nmap -sA <target>`:** **TCP ACK Scan.** Used to map out firewall rulesets by determining if ports are statefully filtered.
-   **`nmap -sF, -sX, -sN <target>`:** **FIN, Xmas, and Null Scans.** Very stealthy scans designed to bypass some older firewalls and IDS.

### Port and Scan Range Specification
How you define which ports to scan.

-   **`nmap -p 80,443 <target>`:** Scans only the specified ports.
-   **`nmap -p- <target>`:** Scans all 65,535 TCP ports.
-   **`nmap -F <target>`:** **Fast Scan.** Scans the 100 most common ports.
-   **`nmap --top-ports 1000 <target>`:** Scans the 1,000 most common ports.

### Service and Version Detection
Discovering what is running on the open ports.

-   **`nmap -sV <target>`:** Probes open ports to determine the service and version information (e.g., `Apache httpd 2.4.52`). This is critical for finding vulnerable software.

### OS Detection
Fingerprinting the target's operating system.

-   **`nmap -O <target>`:** Enables OS detection by analyzing the target's TCP/IP stack responses.

### Timing and Performance
Controlling the speed and aggressiveness of your scan.

-   **`nmap -T<0-5> <target>`:** Sets the timing template.
    -   `-T0` (paranoid) and `-T1` (sneaky) are very slow for IDS evasion.
    -   `-T2` (polite) is slow to conserve bandwidth.
    -   `-T3` (normal) is the default.
    -   **`-T4` (aggressive)** is fast and assumes a reliable network. This is the most common for penetration tests.
    -   `-T5` (insane) is extremely fast but can sacrifice accuracy.

### Nmap Scripting Engine (NSE)
Unlocking Nmap's true power with scripts.the scripts are located in a shared system directory.
```
/usr/share/nmap/scripts/
```

-   **`nmap -sC <target>` or `nmap --script=default <target>`:** Runs the default set of scripts. Safe and useful for discovery.
-   **`nmap --script=<script-name> <target>`:** Runs a specific script (e.g., `http-title`).
-   **`nmap --script=vuln <target>`:** A powerful command that runs all scripts in the `vuln` category to actively check for known vulnerabilities.

### Output Formats
Saving your scan results.

-   **`nmap -oN output.txt <target>`:** Normal Output.
-   **`nmap -oX output.xml <target>`:** XML Output.
-   **`nmap -oG output.grep <target>`:** Grepable Output.
-   **`nmap -oA output_basename <target>`:** Outputs in all three major formats at once.

### The Aggressive "A" Flag
-   **`nmap -A <target>`:** A convenient shortcut that enables **OS detection (`-O`), version detection (`-sV`), script scanning (`-sC`), and traceroute (`--traceroute`)**.

---

## Other Scanning Tools

### Hping3
-   **What it is:** A command-line oriented TCP/IP packet crafter and analyzer.
-   **Primary Use:** Unlike Nmap's automated scans, Hping3 is used for manually building and sending custom packets. It's excellent for firewall testing, advanced port scanning, and network protocol analysis.
-   **Key Features:** Can craft TCP, UDP, ICMP, and RAW-IP packets; has traceroute and DoS testing modes; supports IP spoofing.

### Angry IP Scanner
-   **What it is:** A very fast, cross-platform, and user-friendly network scanner with a graphical user interface (GUI).
-   **Primary Use:** Quickly scanning large IP ranges to find live hosts and their open ports.
-   **Key Features:** Multithreaded for speed, GUI-based, extensible with plugins, and provides information like Ping time, hostname, and open ports.

### SolarWinds Engineer's Toolset
-   **What it is:** A comprehensive, commercial suite of over 60 network management and diagnostic tools for IT professionals.
-   **Primary Use:** It's an all-in-one toolkit for network monitoring, troubleshooting, and discovery in an enterprise environment.
-   **Key Features:** The toolset includes a Port Scanner, IP Network Browser, MAC Address Discovery, a Subnet Calculator, and many other utilities for deep network analysis.

### Advanced IP Scanner
-   **What it is:** A free, fast, and easy-to-use network scanner designed for Windows.
-   **Primary Use:** Ideal for system administrators and home users to get a quick overview of their Local Area Network (LAN).
-   **Key Features:** Simple GUI, discovers all network devices (including Wi-Fi devices), finds shared folders, and provides one-click access to remote control functions like RDP and Radmin.

### Pinkie
-   **What it is:** A versatile command-line and GUI network troubleshooting tool, often described as a "super-ping" or a "packet pinger."
-   **Primary Use:** Advanced network diagnostics and information gathering from a single tool.
-   **Key Features:** Can perform Ping, Traceroute, Port Scanning, Subnet Calculation, and even has a basic TFTP server/client and an interactive shell. It's a multi-tool packed into one lightweight executable.
