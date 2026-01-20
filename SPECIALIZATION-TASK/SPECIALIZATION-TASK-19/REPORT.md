# Broken Function Level Authorization (BFLA) Report

**Subject:** Analysis of API Logic Flaws and Privilege Escalation in crAPI

---

## 1. Summary

This report details the successful identification and exploitation of **Broken Function Level Authorization (BFLA)** within the target environment. BFLA allows attackers to perform administrative actions or access privileged functions due to weak authorization checks in APIs.

The assessment confirms that the API relies on the client side to hide administrative functions rather than enforcing strict **Role-Based Access Control (RBAC)** on the server. This allowed for a successful **Vertical Privilege Escalation** from a standard user to an administrator.

---

## 2. Research Phase: Understanding the Vulnerability

### 2.1 Privilege Escalation

Privilege escalation occurs when an attacker exploits a flaw to gain elevated access to protected resources. In this lab, the focus was on **Vertical Privilege Escalation**, where a lower-privileged user accesses functions reserved for an administrator.

### 2.2 BFLA in API Testing

BFLA results from inadequate authorization enforcement, letting unauthorized users exploit privileged actions. Unlike vulnerabilities targeting specific data, BFLA targets the **action or function** itself. It often arises from "blind trust" in user input or the assumption that restricted URLs cannot be guessed.

### 2.3 Key Differences: BOLA vs. BFLA

| Feature | BOLA (Broken Object Level Auth) | BFLA (Broken Function Level Auth) |
| --- | --- | --- |
| **Focus** | Accessing specific data (e.g., User A viewing User B's profile). | Using restricted functions (e.g., User A deleting User B). |
| **Exploitation** | Modifying IDs or filenames. | Accessing restricted endpoints or HTTP methods (GET vs DELETE). |
| **Scope** | Targeted data access. | Broad impact on application logic and administrative control. |

---

## 3. Practical Assessment: Laboratory Execution

**Objective:** Perform an administrative action (Deleting a Video) using a low-privileged user account.
**Target Application:** crAPI (Completely Ridiculous API)
**Tool Used:** Burp Suite Repeater

### Step 1: Discovery and Information Leakage

The initial request targeted the standard user endpoint: `DELETE /identity/api/v2/user/videos/152`.

* **Observation:** The server blocked the request but provided a verbose error message.
* **Server Response:**
```json
{
  "message": "This is an admin function. Try to access the admin API",
  "status": 403
}

```


* **Analysis:** The error message leaked the existence of an "admin API," providing the specific attack vector needed for exploitation.

### Step 2: Exploitation (The Admin Bypass)

I hypothesized that the API differentiates between users and admins solely via the **URL structure** rather than verifying the session token's permissions.

* **Action:** Modified the URL path in Burp Repeater from `/user/` to `/admin/`.
* **Modified Endpoint:** `DELETE /identity/api/v2/admin/videos/152`
* **Outcome:** The server processed the request successfully with a **200 OK** status.
* **Evidence:**
```json
{
  "message": "User video deleted successfully.",
  "status": 200 
}

```


* **Conclusion:** The backend logic checked *where* the request came from (the URL) but failed to verify *who* sent it (the user token).

---

## 4. Mitigation Strategies

To remediate this vulnerability, the following industry best practices should be implemented:

1. **Implement Server-Side RBAC:** Do not rely on URL paths for security. The server must validate the user's role and permissions for every request against the session token.
2. **Principle of Least Privilege:** Users should only have access to the functions strictly necessary for their specific role.
3. **Sanitize Error Messages:** Remove verbose error messages that leak internal API structures or suggest alternative endpoints.
4. **Regular Authorization Audits:** Use automated tools and manual testing to ensure that administrative endpoints are not reachable by non-admin tokens.

---

## 5. References

* **OWASP API Security Top 10:** [API5:2023 Broken Function Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/)
* **Lab Documentation:** Broken Function Level Authorization.pptx
