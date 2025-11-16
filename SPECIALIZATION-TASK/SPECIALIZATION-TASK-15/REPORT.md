# Broken Object Level Authorization (BOLA)

## 1. Introduction: What is Authorization?

Authorization is a fundamental security mechanism that determines what a user is permitted to do within an application.

* **Authentication** is the process of verifying *who a user is* (their identity).
* **Authorization** is the process of verifying *what data or functions they are allowed to access* (their permissions).

For example, an authenticated user might be authorized to view their own profile but not the profile of an administrator. When these authorization checks are missing, weak, or incorrectly implemented at the object level, it leads to a critical vulnerability known as Broken Object Level Authorization (BOLA).

---

## 2. What is BOLA in API testing?

Broken Object Level Authorization (BOLA), also known as **Insecure Direct Object Reference (IDOR)**, is a critical vulnerability that occurs when an application’s API endpoint fails to properly validate if an authenticated user has the permission to access a specific object or resource.

In API testing, this vulnerability is commonly found in endpoints that retrieve, modify, or delete data using an object's ID in the URL path, a query parameter, or the request body (e.g., `GET /api/users/123/profile` or `POST /api/vehicles/456/update`).



An attacker can exploit this by simply changing the ID (`123`) to another valid ID (`124`) to illegitimately access, modify, or delete data belonging to another user. The core of the flaw is that the API endpoint correctly checks for **authentication** (a valid session token) but completely forgets the crucial **authorization** step (checking if the current user *owns* the object they are requesting).

---

## 3. What is the impact of this issue?

The impact of BOLA is almost always severe and can directly lead to significant data breaches and system compromise. Key impacts include:

* **Massive Data Breaches:** Attackers can automate requests to iterate through object IDs, scraping sensitive personal, financial, or health data for all users on the platform.
* **Data Destruction or Modification:** An attacker could gain unauthorized access to modify or delete another user's data, such as changing profile details, deleting files, or modifying financial records.
* **Full Account Takeover:** In some cases, by accessing or modifying another user's profile data, an attacker might be able to escalate privileges or trigger a password reset, leading to a full account takeover.
* **Reputation Damage and Fines:** A public breach of this nature can destroy user trust in the organization and lead to significant regulatory penalties for non-compliance with data protection laws like GDPR, HIPAA, or PCI DSS.

---

## 4. Lab Work—Practical Exercise

To gain hands-on experience, the **crAPI (Completely Ridiculous API)** vulnerable application was set up locally. A test user account was used to log in and analyze the application's API traffic to identify authorization weaknesses.

### Step 1 - Analyzing Application Traffic

While using the application's dashboard to view vehicle details, the API traffic was intercepted using a local proxy tool. When the feature to fetch a vehicle's current location was used, the following API request was captured.

### Step 2 - Observed Vulnerability (BOLA)

The intercepted request was sent to the vehicle location endpoint:

> `GET /identity/v2/vehicle/4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5/location`

* **Request:** This request included a valid `Authorization: Bearer` token, proving the user was successfully authenticated. The URL clearly contains a unique identifier for the object (the vehicle ID).
* **Response:** The server responded with an `HTTP/1.1 200 OK` and a JSON body containing sensitive information. This included the vehicle's real-time location (`"latitude": "37.746880", "longitude": "-84.301460"`) and personal details of the owner (`"fullName": "Robot", "email": "robot001@example.com"`).

**Finding:** The vulnerability is that the server only checked for a valid authentication token. It **failed to perform an authorization check** to verify if the logged-in user (associated with the bearer token) actually *owned* the vehicle with the ID `4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5`.

An attacker could exploit this by simply replacing that ID with other valid, guessable, or brute-forced vehicle IDs. This would allow them to track the real-time location of any user on the platform, leading to a massive privacy and safety breach.

---

## 5. Knowledge Gained

Based on this practical lab work, the following knowledge was gained:

### Conceptual Understanding

* **Authentication vs. Authorization:** A clear, practical understanding of the difference between authentication (verifying who a user is) and authorization (verifying what a user is allowed to access).
* **BOLA Defined:** A solid definition of Broken Object Level Authorization (BOLA/IDOR) as a flaw where an API fails to check if an authenticated user has permission to access a specific requested object.
* **Impact Assessment:** An understanding of the severe, real-world consequences of BOLA, including mass data breaches and unauthorized data manipulation.

### Practical Skills & Application

* **Lab Setup:** Experience in setting up a vulnerable lab environment (crAPI) for hands-on security testing.
* **Traffic Interception:** The ability to use a proxy tool to intercept and analyze live API requests between a web client and the server.
* **Vulnerability Analysis:** The skill to analyze an intercepted API request to identify a BOLA flaw by:
    1.  Recognizing the object ID in the URL.
    2.  Observing that the server only checked for authentication.
    3.  Confirming the lack of an authorization check (i.e., does the user own this object?).
* **Exploitation Concept:** A clear understanding of the exploit path, where an attacker can simply change the object ID to access data belonging to other users.

### Mitigation & Best Practices

* **Core Prevention:** Knowledge of the most critical mitigation strategies, including:
    * **Enforcing Server-Side Checks:** Always verifying on the server that the logged-in user has the right to access the specific object ID.
    * **Using User-Scoped Queries:** Writing code that retrieves objects relative to the user (e.g., `current_user.vehicles.find(id)`).
    * **Using Non-Guessable IDs:** Implementing UUIDs to make it harder for attackers to guess other users' resource IDs.

---

## 6. Conclusion

Broken Object Level Authorization is one of the most dangerous and widespread API vulnerabilities because it stems from a simple but critical logical flaw: trusting that an authenticated user will only request their own resources. As demonstrated in the lab, this flaw can be easily exploited to compromise all user data on the platform.

Effective mitigation strategies must be implemented at the code level:

* **Enforce Object-Level Checks:** For every request that accesses an object by its ID, the server must verify that the authenticated user has the explicit permission to access that specific object.
* **Use User-Scoped Queries:** Instead of a direct lookup like `vehicle.find(vehicle_id)`, developers should use queries scoped to the logged-in user, such as `current_user.vehicles.find(vehicle_id)`.
* **Avoid Guessable IDs:** Use non-sequential, random, and unique identifiers (like UUIDs) for resources to make it harder for attackers to guess the IDs of other users' objects.
* **Regularly Test API Endpoints:** Actively test all API endpoints for BOLA vulnerabilities, as they are not always obvious and can be missed during development.

---

## 7. References

* [OWASP API Security Top 10: API1:2023—Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
* [OWASP Top 10: A01:2021—Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
* [PortSwigger Web Security Academy: Insecure direct object references (IDOR)](https://portswigger.net/web-security/access-control/idor)