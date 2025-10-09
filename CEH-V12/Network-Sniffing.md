# Network Sniffing

## 1. Sniffing and its Types: Hubs vs. Switches

### What is Sniffing?

Sniffing, in the context of network security, is the process of capturing, decoding, and inspecting data packets that are passing over a network. It's the digital equivalent of wiretapping a phone line. A network "sniffer" (also known as a packet analyzer or protocol analyzer) is the software or hardware used to perform this interception. While network administrators use sniffers for legitimate purposes like troubleshooting, performance analysis, and monitoring, attackers use them for malicious activities, such as stealing sensitive unencrypted information like passwords, credit card numbers, and confidential data.

Sniffing can be categorized into two main types based on the network infrastructure:

* **Passive Sniffing:** This type of sniffing is effective on networks that use **hubs** or wireless access points. Hubs are simple Layer 1 (Physical Layer) devices that operate as a shared medium. When a hub receives a data packet on one port, it regenerates and broadcasts that packet to *all* other ports on the device. This means every device connected to the hub can see all the traffic. In this environment, a sniffer can operate in "promiscuous mode," capturing all traffic without needing to send any packets of its own. This makes it "passive" and extremely difficult to detect.

* **Active Sniffing:** This is required on networks built with **switches**. Switches are more intelligent Layer 2 (Data Link Layer) devices. They maintain a Content Addressable Memory (CAM) table, which maps the MAC address of each connected device to its physical port. When a packet arrives, the switch looks up the destination MAC address in its CAM table and forwards the packet *only* to the intended recipient's port. To capture traffic in a switched network, an attacker must actively inject malicious packets into the network to manipulate its behavior. Common techniques include ARP poisoning and MAC flooding. This activity is "active" because it involves interaction, making it more detectable than passive sniffing.

## 2. Sniffing Attacks (Expanded)

Here are some of the most common sniffing attacks in greater detail:

* **MAC Flooding:** An attack against a network switch. The attacker floods the switch with a huge number of Ethernet frames with different, random source MAC addresses. The goal is to overwhelm the switch's CAM table, which has a limited size. When the CAM table is full, the switch can no longer store new MAC addresses and enters a "fail-open" mode. In this mode, it starts behaving like a hub, broadcasting all incoming packets to every port on the network. This allows the attacker to sniff all the traffic.

* **ARP Poisoning (or ARP Spoofing):** This is a powerful active sniffing technique. The Address Resolution Protocol (ARP) is used to map an IP address to a physical MAC address. In an ARP poisoning attack, the attacker sends forged ARP messages onto the local network. The goal is to associate the attacker's MAC address with the IP address of another host, such as the default gateway. Any traffic that other hosts on the network try to send to the gateway is instead sent to the attacker. The attacker can then forward the traffic to the actual gateway and relay the response back to the original host, acting as a "man-in-the-middle" and sniffing all the traffic in both directions.

* **DNS Poisoning (or DNS Spoofing):** In a DNS poisoning attack, the attacker corrupts the Domain Name System (DNS) cache on a victim's machine or a DNS server. The goal is to redirect traffic from a legitimate website to a fake one controlled by the attacker. An attacker can combine this with ARP poisoning to intercept a user's DNS request. When the user tries to go to `www.bank.com`, the attacker intercepts the request and sends back a forged DNS response pointing to their own malicious server's IP address.

* **DHCP Starvation Attack:** The Dynamic Host Configuration Protocol (DHCP) automatically assigns IP addresses to devices. This attack targets the DHCP server. The attacker uses a tool to broadcast a massive number of DHCP DISCOVER requests with spoofed MAC addresses. The DHCP server responds with DHCP OFFERs and reserves an IP address for each request, quickly exhausting its pool of available IPs. This constitutes a denial-of-service attack against legitimate users trying to connect. The attacker can then launch a **Rogue DHCP Server Attack** by setting up their own malicious DHCP server. This rogue server responds to legitimate requests, assigning them an IP address and configuring the attacker's machine as the default gateway and DNS server, thus intercepting all of the victims' traffic.

* **MAC Spoofing:** This involves an attacker changing their device's MAC address to impersonate another legitimate device on the network. This can be used to bypass security controls like MAC filtering on a wireless access point or to take over the identity of a trusted host after identifying its MAC address through sniffing.

## 3. Sniffing Attack Methodology

A typical sniffing attack follows a series of steps:

1.  **Gaining Access:** The attacker connects to the target network, either physically or wirelessly.
2.  **Reconnaissance:** The attacker maps out the network to identify potential targets, such as the default gateway, DNS servers, and active clients.
3.  **Poisoning/Flooding:** The attacker launches an active attack to redirect traffic. For example, they might flood the switch's CAM table or poison the ARP cache of the target machines.
4.  **Data Interception:** With the attack in place, the attacker starts their sniffing tool to capture the redirected data packets. They will look for unencrypted protocols like HTTP, FTP, Telnet, and POP3, which transmit credentials in cleartext.
5.  **Analysis and Exploitation:** The captured data is analyzed to extract valuable information. This can be done in real-time or offline.

## 4. Sniffing Tools and Commands

Here are some of the most popular sniffing tools with command-line examples:

* **tcpdump:** A powerful command-line packet analyzer.
    * **Capture traffic from a specific interface:**
        `tcpdump -i eth0`
    * **Capture a specific number of packets:**
        `tcpdump -i eth0 -c 100`
    * **Save captured packets to a file:**
        `tcpdump -i eth0 -w capture.pcap`
    * **Read packets from a file:**
        `tcpdump -r capture.pcap`
    * **Filter traffic for a specific host (source or destination):**
        `tcpdump -i eth0 host 192.168.1.10`
    * **Filter for a specific port:**
        `tcpdump -i eth0 port 80`
    * **Verbose output with packet contents:**
        `tcpdump -i eth0 -A -vv`

* **Wireshark:** The world's most popular graphical network protocol analyzer. While it's primarily a GUI tool, it comes with `tshark`, its command-line equivalent.
    * **Start a capture on an interface (like tcpdump):**
        `tshark -i eth0`
    * **Use a display filter to capture only HTTP traffic and print a summary:**
        `tshark -i eth0 -Y "http.request" -T fields -e frame.number -e ip.src -e http.host -e http.request.uri`

* **Ettercap:** A comprehensive suite for man-in-the-middle attacks. It can be run in GUI, ncurses, or command-line mode.
    * **Run in command-line mode and perform ARP poisoning between a target and the gateway:**
        `ettercap -T -q -M arp:remote /192.168.1.10/ /192.168.1.1/`
        * `-T`: Use text-only interface
        * `-q`: Quiet mode
        * `-M arp:remote`: Perform an ARP poisoning MitM attack
        * `/192.168.1.10/`: Target 1
        * `/192.168.1.1/`: Target 2 (gateway)

* **Bettercap:** A modern, powerful, and modular framework for network attacks.
    * **Start bettercap on a specific interface:**
        `sudo bettercap -iface eth0`
    * **Inside the bettercap interactive shell, you can run modules. For example, to start an ARP spoofer:**
        `net.probe on` (discover hosts)
        `set arp.spoof.targets 192.168.1.10` (set the target)
        `set arp.spoof.gateway 192.168.1.1` (set the gateway)
        `arp.spoof on` (start the attack)
        `net.sniff on` (start the built-in sniffer)

## 5. Everything About Wireshark in Detail

### The Wireshark Interface

The Wireshark interface is divided into three main panes:

1.  **Packet List Pane:** A list of all captured packets, with columns for packet number, timestamp, source, destination, protocol, and info. You can customize these columns.
2.  **Packet Details Pane:** A detailed, expandable view of the selected packet, broken down by OSI model layers (Frame, Ethernet, IP, TCP/UDP, Application Protocol).
3.  **Packet Bytes Pane:** The raw data of the selected packet in hexadecimal and ASCII.

### Capturing and Filtering

* **Capture Filters:** These are applied *before* starting a capture to reduce the size of the captured data. They use the `pcap` filter syntax (same as `tcpdump`). For example, `host 192.168.1.10` will only capture packets going to or from that IP.
* **Display Filters:** These are applied *after* the capture to sift through the data without deleting anything. This is one of Wireshark's most powerful features. You can build complex filters.
    * `ip.addr == 192.168.1.50`
    * `tcp.port == 443`
    * `http.request.method == "POST"`
    * `dns.qry.name == "www.example.com"`
    * `tcp.flags.syn == 1 && tcp.flags.ack == 1` (Filter for SYN/ACK packets)

### Advanced Analysis Features

* **Follow TCP/UDP/HTTP Stream:** This feature reconstructs the full data stream from a conversation. If you find a packet from an unencrypted login, you can right-click -> "Follow" -> "TCP Stream" to see the entire exchange, often revealing the username and password in plain text.
* **Statistics Menu:** This menu provides invaluable insights into the capture.
    * **Protocol Hierarchy:** Shows a tree of all protocols found in the capture and the percentage of traffic for each.
    * **Conversations:** Lists all conversations (e.g., between two IP addresses) and shows packet and byte counts.
    * **Endpoints:** Lists all unique endpoints (e.g., IP addresses, MAC addresses) and their traffic stats.
* **Expert Information:** Found under the "Analyze" menu, this feature analyzes the capture for potential network issues (like retransmissions, duplicate ACKs, and window size problems) and categorizes them by severity (Chat, Note, Warn, Error).

## 6. Sniffing Countermeasures

Defending against sniffing attacks requires a multi-layered approach:

* **Use Encryption:** The most effective countermeasure. If traffic is encrypted, an attacker can capture it but cannot read its contents. Always use protocols like HTTPS, SSH, SFTP, and VPNs to encrypt data in transit.
* **Use a Switched Network:** Switches limit the effectiveness of passive sniffing by design.
* **Port Security:** On managed switches, you can configure port security to limit the number of MAC addresses allowed on a port or to bind a specific MAC address to a port. This can help mitigate MAC flooding and spoofing attacks.
* **ARP Detection Tools:** Use software like `arpwatch` to monitor for unusual ARP activity and changes to the local ARP cache.
* **DHCP Snooping:** A security feature on switches that allows you to designate "trusted" ports where a DHCP server can be connected. It drops DHCP server messages from any untrusted port, preventing rogue DHCP servers.
* **Use DNSSEC:** DNS Security Extensions provide authentication for DNS responses, preventing DNS cache poisoning by validating the origin and integrity of the data.
```eof
