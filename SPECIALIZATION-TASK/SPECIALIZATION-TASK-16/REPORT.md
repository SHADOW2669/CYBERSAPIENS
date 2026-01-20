# Broken Object Property Level Authorization (BOPLA) Report

## 1. Summary

This report documents the research and practical analysis of **Broken Object Property Level Authorization (BOPLA)**. Formerly recognized as two separate vulnerabilities in the 2019 OWASP API Top 10, BOPLA (API3:2023) consolidates the risks associated with unauthorized access to specific object properties.

Practical analysis conducted on the **VAmPI lab** successfully demonstrated both aspects of BOPLA:

1. **Excessive Data Exposure** (unauthorized reading of sensitive fields)
2. **Mass Assignment** (unauthorized modification of sensitive fields)

Together, these vulnerabilities led to a verified **Privilege Escalation**.

---

## 2. What is BOPLA?

BOPLA occurs when an API endpoint exposes an object (such as a User or Order) but fails to validate whether the user has access to **specific properties** within that object.

While an endpoint might correctly authorize a user to view an object (e.g., "User A can view User B's public profile"), it often fails to filter out sensitive internal properties (like `email`, `password_hash`, or `admin_status`) or fails to prevent the user from updating those properties.

### The Core Issue

The vulnerability stems from a lack of granular validation at the property level:

* **Read Operations:** The API returns the full object and relies on the client (frontend) to hide sensitive data (**Excessive Data Exposure**).
* **Write Operations:** The API binds client input directly to internal objects without filtering, allowing users to update fields they shouldn't (**Mass Assignment**).

---

## 3. Comparison: OWASP API 2019 vs. 2023

The transition reflects a shift towards grouping vulnerabilities by their **root cause** rather than their symptom.

| OWASP API 2019 | OWASP API 2023 | Reason for Change |
| --- | --- | --- |
| **API3:2019** (Excessive Data Exposure) | **API3:2023 (BOPLA)** | Both 2019 vulnerabilities are two sides of the same coin. |
| **API6:2019** (Mass Assignment) | **Merged into API3:2023** | One is the Read vector (Output), the other is the Write vector (Input). |

---

## 4. Practical Analysis & Case Studies

Findings based on exercises conducted in the **VAmPI** environment.

### A. Excessive Data Exposure (The "Read" Vulnerability)

**Concept:** Developers often rely on the frontend to filter data. However, attackers can bypass the UI and inspect raw API responses to view hidden fields.

* **Target Endpoint:** `GET /users/v1/_debug`
* **Methodology:** Request intercepted using Burp Suite.
* **Observation:** The API returned a JSON list of all users containing sensitive properties.
* **Exposed Data:**
```json
{
    "users": [
        {
            "admin": false,
            "email": "mail1@mail.com",
            "password": "pass1",  // CRITICAL: Plaintext password exposed
            "username": "name1"
        }
    ]
}

```


* **Risk:** Credential harvesting and PII exposure leading to account takeovers.

### B. Mass Assignment (The "Write" Vulnerability)

**Concept:** Modern frameworks automatically bind JSON input to code objects. Without an "allowlist," an attacker can "guess" internal fields and inject them into the request.

* **Target Endpoint:** `POST /users/v1/register`
* **Methodology:** A registration request was crafted. A malicious property, `"admin": true`, was injected into the JSON body.
* **Payload:**
```json
{
    "admin": true, 
    "username": "test3",
    "password": "test3",
    "email": "test3@test3.com"
}

```


* **Observation:** The API returned `"status": "success"`.
* **Verification:** The user `test3` was successfully created with `admin` privileges.
* **Risk:** Immediate **Privilege Escalation**.

---

## 5. Impact Analysis

The impact of BOPLA is severe as it grants unauthorized control over application logic:

* **Privilege Escalation:** Promoting accounts to administrator roles.
* **Account Takeover:** Exposing hashes or overwriting recovery emails.
* **Data Breach:** Exposure of PII (GDPR/CCPA violations).
* **Business Logic Bypass:** Modifying payment statuses or order prices.

---

## 6. References

* [OWASP API3:2023 Broken Object Property Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/)
* [Snyk: BOPLA Tutorial and Examples](https://learn.snyk.io/lesson/broken-object-property-level-authorization/)
* [AppSentinels: OWASP API Top 10 2023 Changes](https://appsentinels.ai/blog/owasp-api-top-10-2023-what-changed-and-why-its-important/)

