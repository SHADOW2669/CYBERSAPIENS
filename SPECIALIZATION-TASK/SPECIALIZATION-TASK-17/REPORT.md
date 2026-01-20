# Unrestricted Resource Consumption (API4:2023)

## 1. Summary

This report documents the research and practical analysis of **Unrestricted Resource Consumption**, categorized as **API4:2023** in the OWASP API Security Top 10. Formerly known as "Lack of Resources & Rate Limiting," this vulnerability highlights the risks associated with APIs that do not enforce limits on the number or size of requests they process.

Practical analysis conducted on the **VAmPI lab** demonstrated how an attacker can exploit this flaw to launch a high-volume Brute Force attack, consuming significant server resources without restriction.

---

## 2. What is Unrestricted Resource Consumption?

Unrestricted Resource Consumption occurs when an API allows clients to consume system resources (CPU, memory, network bandwidth, or storage) without appropriate limitations.

### Vulnerability Triggers

* **No Rate Limits:** A single user or bot can send thousands of requests per second.
* **Unrestricted File Uploads:** Uploading massive files (e.g., multi-gigabyte videos) to endpoints intended for small images.
* **No Payload Limits:** Requesting massive datasets that cause memory exhaustion.
* **Inefficient Algorithms:** Requests that trigger complex calculations, hanging the CPU.

> **Why the name change?** > In the 2023 update, the focus shifted from the *mechanism* (Rate Limiting) to the *consequence* (Resource Exhaustion).

---

## 3. Practical Analysis & Case Study

Based on exercises conducted in the **VAmPI** environment.

### Scenario 1: OTP/Login Brute Force Attack

**Concept:** An attacker attempts to guess a 4-digit OTP or password. Without restrictions, the API processes every guess, consuming CPU cycles and database lookups.

#### A. Attack Setup

* **Target Endpoint:** `POST /identity/api/auth/login`
* **Tool Used:** Burp Suite Intruder.
* **Payload Configuration:** Targeted the password field with a Brute Force character set (`abcdefghijklmnopqrstuvwxyz0123456789`) at a fixed length of 4 characters.
* **Volume:** ~1,679,616 possible requests.

#### B. Attack Execution

* **Server Response:** The server responded with `401 Unauthorized` for failed attempts.
* **Observation:** The server **did not block** the attack. It continued to process every incoming request.
* **Conclusion:** This confirms the vulnerability. A secure API should return a **429 Too Many Requests** error or block the IP after a set number of failed attempts.

### Scenario 2: Unrestricted File Upload

**Concept:** Attackers exploit endpoints that accept files but fail to enforce size limits.

* **Disk Exhaustion:** Filling storage, causing database or logging crashes.
* **Bandwidth Saturation:** Clogging the network for legitimate users.
* **Memory Spikes:** RAM exhaustion if the server buffers the upload before writing to disk.

---

## 4. Impact Analysis

| Impact Type | Description |
| --- | --- |
| **Denial of Service (DoS)** | The API becomes unresponsive as CPU/Memory is fully consumed. |
| **Financial Loss** | Cloud "Auto-scaling" costs can skyrocket as new instances spin up to handle the attack. |
| **Performance Degradation** | High latency leads to a poor user experience for legitimate customers. |
| **Operational Costs** | Triggering thousands of SMS/Email verifications can lead to massive service fees. |

---

## 5. Mitigation Strategies

To remediate this vulnerability, implement the following controls:

1. **Rate Limiting:** Limit requests per timeframe (e.g., 5 login attempts per minute).
2. **File Size Limits:** Configure web servers (like Nginx) to enforce `client_max_body_size`.
3. **Input Validation:** Enforce maximum lengths for all JSON payloads and parameters.
4. **Resource Quotas:** Set hard limits on CPU/Memory per container or process.
5. **Monitoring:** Implement real-time alerts for spikes in traffic or 4xx/5xx error rates.

---

## 6. References

* [OWASP API4:2023 Unrestricted Resource Consumption](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/)
* [Snyk: Unrestricted Resource Consumption Tutorial](https://learn.snyk.io/lesson/unrestricted-resource-consumption/)
* [Wallarm: API4:2023 Research](https://lab.wallarm.com/api42023-unrestricted-resource-consumption/)

