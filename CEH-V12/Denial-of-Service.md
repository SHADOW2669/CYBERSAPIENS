# Advanced Guide to DoS/DDoS Attacks, Analysis, and Defense

## 1. Denial of Service (DoS) Attack

### Purpose Behind a DoS Attack (Expanded)

A Denial of Service (DoS) attack aims to exhaust the resources of a target system, rendering it unable to serve legitimate users. The "resource" being targeted can vary, from network bandwidth to CPU cycles or application connection slots. The core purpose is **disruption**, driven by motivations ranging from hacktivism to creating a smokescreen for other attacks like data exfiltration.

---

### Types of DoS Attacks (In-depth with Commands)

#### A. UDP Flood Attack

* **Deeper Explanation:** This is a volumetric, network-layer attack. Since UDP is connectionless, it requires very little effort for the attacker to send packets. The target system, however, must expend significant resources. For each incoming UDP packet to a closed port, the server's CPU must:
    1.  Process the packet.
    2.  Check for a listening application on the destination port.
    3.  Find none.
    4.  Generate and send an `ICMP Destination Unreachable` (Type 3, Code 3) response.
    This combination of consuming inbound bandwidth and using CPU/network resources to generate outbound ICMP responses quickly overwhelms the target.

* **Analysis & Testing Command (hping3):**
    `hping3` is a packet crafting tool used by security professionals for network testing. The following command can be used to test how a firewall or server responds to a flood of UDP packets.

    ```bash
    # Sends UDP packets to port 80 of <target_ip> as fast as possible (--flood)
    # from a random (--rand-source) IP address, with a data size of 120 bytes.
    # WARNING: Only use this against systems you own or have explicit permission to test.
    sudo hping3 --udp -p 80 --flood --rand-source -d 120 <target_ip>
    ```

#### B. TCP SYN Flood Attack (Half-Open Attack)

* **Deeper Explanation:** This attack targets a server's "backlog queue," a finite memory buffer where details of pending TCP connections are stored. When a `SYN` packet arrives, the server places the connection details in this queue and sends back a `SYN-ACK`. It then waits for the final `ACK`. By sending a high volume of `SYN` packets from spoofed IPs, an attacker fills this queue with "half-open" connections. When the queue is full, the server's kernel will start dropping all new, incoming `SYN` packets from legitimate users, making it impossible for them to connect.

* **Analysis & Testing Command (hping3):**

    ```bash
    # Sends TCP SYN packets (-S) to port 443 of <target_ip> as fast as possible (--flood)
    # from a random (--rand-source) IP address.
    # WARNING: For testing purposes only.
    sudo hping3 -S -p 443 --flood --rand-source <target_ip>
    ```

#### C. HTTP Flood Attack & Slowloris

* **Deeper Explanation:** These are application-layer (Layer 7) attacks.
    * **Standard HTTP Flood:** This is a brute-force attack that uses seemingly legitimate `GET` or `POST` requests. A `POST` flood can be particularly effective, as it often requires the server to perform more work (e.g., database lookups). The goal is to exhaust server resources like CPU, memory, and max database connections.
    * **Slowloris:** This is a "low-and-slow" attack that targets connection slots. Instead of high volume, it uses stealth. The tool opens a connection and sends a partial HTTP header (e.g., `GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: ...\r\n`) but never sends the final `\r\n\r\n` that signals the end of the headers. It periodically sends more header lines (e.g., `X-a: b\r\n`) to keep the connection alive. Since web servers like Apache have a limited number of concurrent connections they can handle, Slowloris gradually consumes all of them, blocking legitimate users.

* **Analysis & Command Concept:**
    While we won't provide an attack script, a defender can spot a Slowloris attack by checking the number of connections in a specific state.

    ```bash
    # This command counts the number of established connections from each IP address to port 80.
    # A large number of connections from a single IP in an ESTABLISHED state could indicate an attack.
    netstat -ntp | grep ':80' | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr
    ```

---

## 2. Distributed Denial of Service (DDoS)

### Botnets and How They Work (Expanded)

A botnet is a network of hijacked devices (bots), controlled by a "botmaster." The control structure has evolved:

* **Centralized (Star Topology):** Early botnets used a single **Command and Control (C&C)** server, often running on an IRC channel. The botmaster would issue a command in the channel, and all bots would execute it. This model is effective but fragile—if the C&C server is found and shut down, the entire botnet is disabled.
* **Decentralized (P2P):** Modern botnets often use a peer-to-peer (P2P) structure. There is no single C&C server. Instead, bots communicate with each other to relay commands and updates. This makes the botnet far more resilient and difficult to dismantle.

---

## 3. Prevention and Mitigation Methods (Expanded with Commands)

#### A. Web Application Firewall (WAF)

* **Deeper Explanation:** A WAF is essential for mitigating Layer 7 attacks like HTTP floods. It can analyze incoming HTTP/S requests to distinguish between human and bot traffic.
* **Command Example (Conceptual ModSecurity Rule):** ModSecurity is a popular open-source WAF. A simple rule to block a known malicious user-agent might look like this:

    ```apache
    # This rule for the ModSecurity WAF will deny any request with the user-agent "BadBot".
    SecRuleEngine On
    SecRule REQUEST_HEADERS:User-Agent "BadBot" "id:101,phase:1,deny,status:403"
    ```

#### B. Rate Limiting

* **Deeper Explanation:** This is a crucial defense against brute-force volumetric attacks. It restricts how many times a user or IP can perform an action in a given timeframe.
* **Command Example (iptables - Network Layer):** This `iptables` rule limits new incoming connections on port 80 to 20 per minute from a single IP.

    ```bash
    # Create a new chain to handle the rate-limited packets
    sudo iptables -N http_ratelimit

    # Send new TCP connections on port 80 to our new chain
    sudo iptables -A INPUT -p tcp --dport 80 --syn -j http_ratelimit

    # In our custom chain, use the 'hashlimit' module to enforce the limit
    # Log packets that exceed the limit before dropping them
    sudo iptables -A http_ratelimit -m hashlimit --hashlimit-name http_limit --hashlimit-mode srcip --hashlimit-upto 20/minute -j ACCEPT
    sudo iptables -A http_ratelimit -j LOG --log-prefix "HTTP_FLOOD: "
    sudo iptables -A http_ratelimit -j DROP
    ```

* **Command Example (Nginx - Application Layer):** This Nginx configuration limits requests to 10 per second from a single IP.

    ```nginx
    # In your http {} block: define the rate limiting zone
    # The zone is named 'mylimit', is 10MB in size, and rates are based on the client IP.
    limit_req_zone $binary_remote_addr zone=mylimit:10m rate=10r/s;

    # In your server {} or location {} block: apply the zone
    server {
        location / {
            limit_req zone=mylimit burst=20; # Allow a burst of 20 requests
            # ... rest of your server config
        }
    }
    ```

#### C. Load Balancing

* **Deeper Explanation:** Load balancers distribute traffic across a pool of servers, increasing resilience. Common algorithms include:
    * **Round Robin:** Sends requests to servers in a simple, rotating order.
    * **Least Connections:** Sends the new request to the server that currently has the fewest active connections. This is more effective during high traffic.
    By using a load balancer, an attack's volume is spread out, preventing any single server from being the point of failure.

#### D. Enable SYN Cookies (Kernel-level Defense)

* **Deeper Explanation:** SYN Cookies are a defense against SYN flood attacks. When the connection queue (backlog) is full, instead of dropping the packet, the kernel responds with a `SYN-ACK` packet containing a specially crafted sequence number (a "cookie") calculated from the source/destination IPs, ports, and a secret. The server does not store the state in its queue. If a legitimate client responds with the final `ACK`, the server can mathematically verify the cookie and establish the connection. Spoofed attackers will not respond, so no resources are consumed.
* **Activation Command (Linux):**

    ```bash
    # Check if SYN cookies are enabled (1 means enabled)
    cat /proc/sys/net/ipv4/tcp_syncookies

    # Enable SYN cookies
    sudo sysctl -w net.ipv4.tcp_syncookies=1
    ```
