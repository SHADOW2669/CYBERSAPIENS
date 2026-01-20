# Broken Authentication (API2:2023) Report

**Subject:** Analysis of Authentication Logic Flaws and Account Takeover in VAmPI

---

## 1. Summary

This report documents the research and practical exploitation of **Broken Authentication** vulnerabilities within the target API environment (**VAmPI**). Broken Authentication allows attackers to compromise passwords, keys, or session tokens, effectively assuming the identities of legitimate users.

My assessment identified a critical logic flaw in the password update mechanism, allowing for a complete **Account Takeover (ATO)** without requiring the victim's current credentials.

---

## 2. Research Phase: Understanding the Vulnerability

### 2.1 What is Authentication?

Authentication is the fundamental process of verifying the identity of an individual, entity, or website. It ensures that a user is truly who they claim to be through factors like passwords, biometrics, or security tokens.

### 2.2 Broken Authentication and its Types

Broken API authentication occurs when these mechanisms are implemented incorrectly. Common types include:

* **Credential Stuffing:** Using leaked credentials from other breaches to brute-force login endpoints via automated tools.
* **Weak Auth-Token Generation:** Using predictable or insecure session tokens (like poorly signed JWTs) that can be guessed or hijacked.
* **Unrestricted Password Changes:** Allowing a password update without requiring the user's current password. This is a critical logic flaw that enables an attacker to lock legitimate users out.

### 2.3 Business Impact

* **Illegal Access:** Attackers gain full entry to end-user accounts and administrative panels.
* **Data Leakage:** Personal Identifiable Information (PII) and proprietary data can be exfiltrated.
* **Reputational Damage:** Loss of customer trust and potential legal penalties under data protection laws (GDPR/CCPA).

---

## 3. Practical Assessment: Laboratory Execution

**Objective:** To demonstrate Account Takeover (ATO) by exploiting a logic flaw in the user profile update workflow.
**Target Application:** VAmPI (Vulnerable API)
**Tools Used:** Postman

### Step 1: Baseline Authentication

I authenticated with a known user `test3` to verify the standard login flow.

* **Action:** `POST` request to `/users/v1/login`.
* **Result:** Server returned **200 OK** and a valid `auth_token`.
* **Analysis:** The API issues a JWT (JSON Web Token) for session management.

### Step 2: Exploiting the Password Update Logic

I identified that the endpoint `/users/v1/:username/password` failed to enforce a security check requiring the "Old Password."

* **Target User:** `test2`
* **Attack Vector:** `PUT` request to update the password.
* **Payload:** ```json
{
"password": "test2-hack"
}
```

```


* **Observation:** The API only required the target username in the URL. It did not require proof of the original identity (the current password).
* **Server Response:** **204 No Content** (Success).

### Step 3: Verification of Account Takeover

I attempted to log in as the victim (`test2`) using the injected password.

* **Action:** `POST` request to `/users/v1/login`.
* **Credentials:** Username: `test2` / Password: `test2-hack`.
* **Result:** **200 OK** with a new `auth_token` issued for the victim's account.
* **Conclusion:** The account was successfully compromised due to the lack of identity verification during sensitive profile changes.

---

## 4. Mitigation Strategies

To secure the application, I recommend the following controls:

1. **Require Current Password:** Enforce a "Current Password" field for all sensitive updates (passwords, emails, or MFA settings) to verify the user is the actual account owner.
2. **Multi-Factor Authentication (MFA):** Implement MFA to add a secondary layer of security that a simple password update cannot bypass.
3. **Implement Rate Limiting:** Prevent automated brute-force attacks by limiting login and password change attempts per IP/account.
4. **Secure Session Management:** Invalidate all active session tokens immediately after a password change to ensure any active malicious sessions are terminated.

---

## 5. References

* **OWASP API Security Top 10:** [API2:2023 Broken Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/)
* **Lab Documentation:** Broken Authentication.pptx

