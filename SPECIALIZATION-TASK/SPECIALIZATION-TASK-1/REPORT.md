# Session Fixation and Session Hijacking

### Key Concepts

* **Session:** A session is the time a user interacts with a website, starting from logging in and ending when they log out or the session expires.
* **Session ID:** A Session ID is a unique string of text given by a website's server to a user's browser to identify them during their session.
* **Cookie:** The website stores the unique Session ID in a cookie. When a user visits a new page on that site, their browser sends this cookie to the server.

## The Attacks

Both session fixation and session hijacking aim to steal an active Session ID and impersonate the user. The main difference is **how** and **when** the attacker obtains the Session ID.

### Session Fixation

1.  **Attacker Gets a Session ID:** First, the attacker visits the website to get a valid but unused session ID from the server.
2.  **Attacker Tricks the Victim:** The attacker puts this ID into a link and tricks a victim into clicking it.
3.  **Victim Logs In:** The victim uses this link, visits the site, and enters their username and password. The server sees the Session ID provided by the attacker, authenticates the user, and links their logged-in state to that specific ID.
4.  **Attacker Takes Over:** Since the attacker already knows the Session ID, they can now access the victim's account. They have successfully "fixed" the session to one they control.

### Session Hijacking

In a typical session hijacking attack, the attacker steals a user's Session ID *after* they have logged in.

## The Tool: Cookie Editor

A cookie editor is a browser extension or tool that allows a user to view, create, and change the cookies stored in their browser.

This tool is essential for session attacks. Once an attacker steals a victim's Session ID, they can use a cookie editor to open their own browser, visit the target website, and manually insert the stolen Session ID into a new cookie. When they refresh the page, the website reads the cookie and gives them full access to the victim's account.

## The Consequences: Impact

* **Information Theft:** The attacker gains access to all the information in the victim's account, including their name, address, email history, credit card details, and personal messages.
* **Identity Theft:** The attacker can use the stolen information to impersonate the victim, potentially opening new accounts, making fraudulent purchases, or damaging the victim's reputation.
* **Account Takeover:** They can change the user's password, lock them out of their own account, and perform any action the user could, like transferring money, deleting files, or sending messages as the user.