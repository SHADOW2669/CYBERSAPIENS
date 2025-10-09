# SQL Injection (SQLi)

This module covers the fundamentals of SQL, the critical web vulnerability known as SQL Injection, its various types, and the tools used to detect and exploit it for penetration testing purposes.

---

## 1. What is SQL?

**SQL (Structured Query Language)** is the standard language used to communicate with and manage relational databases. Think of a database as a massive, organized library of information (like user credentials, product details, etc.). SQL is the language you use to ask the librarian (the database management system) to find, add, change, or remove books.

### Common SQL Commands
Based on the list you provided, here are the common commands broken down by their function:

#### Data Manipulation Language (DML)
Used to manage the data *within* the tables.
* **`SELECT`**: Retrieves data from one or more tables.
* **`INSERT`**: Adds new rows of data into a table.
* **`UPDATE`**: Modifies existing data within a table.
* **`DELETE`**: Removes rows of data from a table.

#### Data Definition Language (DDL)
Used to define and manage the database's structure (the tables, columns, and indexes themselves). The `CREATE`, `ALTER`, and `DROP` commands are the core of DDL.
* **`CREATE TABLE`**: Creates a new table with specified columns.
* **`ALTER TABLE`**: Modifies the structure of an existing table, such as adding, deleting, or changing columns.
* **`DROP TABLE`**: Deletes an entire table, including its structure and all its data.
* **`CREATE INDEX`**: Creates an index on a table. Indexes are used to speed up the performance of `SELECT` queries.
* **`DROP INDEX`**: Deletes an index from a table.

### Basic SQL Query Structure
The most common query is `SELECT`. Its basic structure is:

```sql
SELECT column1, column2 FROM table_name WHERE condition;
````

  * `SELECT`: Specifies the columns (data fields) you want to retrieve.
  * `FROM`: Specifies the table you want to retrieve the data from.
  * `WHERE`: Filters the results based on a specific condition.

-----

## 2\. What is SQL Injection (SQLi)?

**SQL Injection (SQLi)** is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. It generally allows an attacker to view data that they are not normally able to retrieve.

**The root cause** is the application's failure to properly validate or sanitize user-supplied input. If an application takes user input (e.g., from a search box or a URL parameter) and directly embeds it into an SQL query, an attacker can insert their own malicious SQL code. This tricks the database into running the attacker's commands.

-----

## 3\. Types of SQL Injection

SQLi attacks are categorized based on how the attacker receives the output.

### A. In-band SQLi (The Noisy Attack)

This is the most common type, where the attacker is able to use the same communication channel to launch the attack and gather the results.

#### 1\. Error-based SQLi

This technique relies on forcing the database to generate an error message. Web applications that are improperly configured will display these detailed database errors to the user, potentially revealing information about the database's structure, version, and schema.

  * **Payload Example:** An attacker might input `'` into a search field. If the application is vulnerable, the server might return an error like: `You have an error in your SQL syntax...`

#### 2\. Union-based SQLi

This technique leverages the `UNION` SQL operator to combine the results of a legitimate query with the results of a malicious query crafted by the attacker. The application then displays the combined results, allowing the attacker to extract data directly from the database tables.

  * **Payload Example:**
    ```sql
    ' UNION SELECT username, password FROM users--
    ```
    This would attempt to display all usernames and passwords from the `users` table on the web page.

### B. Inferential SQLi (Blind SQLi - The Quiet Attack)

This type of attack is used when the web application does not return the results of the query or any database errors directly. The attacker must infer the results by observing the application's behavior.

#### 1\. Boolean-based SQLi

The attacker sends a series of SQL queries that are designed to return either TRUE or FALSE. The attacker then observes whether the application's response changes.

  * **Example:**
      * `http://vulnerable.lab/photo.php?id=1' and 1=1` -\> Returns `TRUE`, page loads normally.
      * `http://vulnerable.lab/photo.php?id=1' and 1=0` -\> Returns `FALSE`, page returns blank or differently.
      * By asking a series of these questions (e.g., "Does the first letter of the admin password equal 'a'?"), the attacker can slowly extract data one character at a time.

#### 2\. Time-based SQLi

This is the final resort when Boolean-based SQLi is not possible. The attacker sends a query that instructs the database to wait for a specified amount of time (e.g., 10 seconds) *if* a certain condition is true.

  * **Example Payloads:**
      * **SQL Server:** `' WAITFOR DELAY '00:00:10'--`
      * **MySQL:** `' OR IF(1=1, SLEEP(10), 0)--`
      * If the website takes 10 seconds to load, the attacker knows the condition was TRUE.

### C. Out-of-band SQLi (The Advanced Attack)

This is a less common technique used when the server's response is not stable. It relies on the database server's ability to make network requests (like DNS or HTTP) to an external server that the attacker controls. The attacker can then exfiltrate data through these network channels.

-----

## 4\. The SQLmap Tool

**SQLmap** is a powerful, open-source penetration testing tool that automates the process of detecting and exploiting SQL injection vulnerabilities. It can identify the database type, enumerate users, tables, and columns, and dump entire databases.

### Common SQLmap Commands

An ethical hacker uses these commands to test a target with permission.

| Command / Flag | Purpose | Example |
| :--- | :--- | :--- |
| `-u <URL>` | Specifies the target URL to test. | `sqlmap -u "http://test.com/index.php?id=1"` |
| `--dbs` | Enumerates (lists) all available databases. | `sqlmap -u ... --dbs` |
| `-D <db>` | Specifies a particular database to work with. | `sqlmap -u ... -D user_db --tables` |
| `--tables` | Enumerates all tables within a specified database. | `sqlmap -u ... -D user_db --tables` |
| `-T <table>` | Specifies a particular table to work with. | `sqlmap -u ... -T users --columns` |
| `--columns` | Enumerates all columns within a specified table. | `sqlmap -u ... -T users --columns` |
| `--dump` | Dumps the data from a table, column, or database. | `sqlmap -u ... -T users -C "user,pass" --dump` |
| `--current-user` | Retrieves the current database user. | `sqlmap -u ... --current-user` |
| `--current-db` | Retrieves the current database name. | `sqlmap -u ... --current-db` |
| `--hostname` | Retrieves the database server's hostname. | `sqlmap -u ... --hostname` |
| `--batch` | Never asks for user input; uses default behaviors. | `sqlmap -u ... --dbs --batch` |
| `--level=<1-5>` | Sets the level of tests to perform (1=default, 5=heavy). | `sqlmap -u ... --level=5 --risk=3` |
| `--risk=<1-3>` | Sets the risk of tests (1=default, 3=risky). | `sqlmap -u ... --level=5 --risk=3` |
| `--os-shell` | Attempts to gain an interactive operating system shell. | `sqlmap -u ... --os-shell` |

-----

## 5\. Impacts of a Successful SQLi Attack

A single SQLi vulnerability can lead to a complete compromise of a system and its data.

  * **Data Theft (Confidentiality Breach):** Attackers can steal sensitive data, including user credentials, personal information (PII), and credit card numbers.
  * **Data Manipulation (Integrity Breach):** Attackers can modify or delete data, causing major disruptions.
  * **Authentication Bypass:** Attackers can bypass login forms and gain access to applications as privileged users.
  * **Loss of Control (Full System Compromise):** In some cases, an attacker can escalate an SQLi vulnerability to gain a command shell on the underlying operating system, giving them complete control over the server.
  * **Denial of Service (DoS):** Attackers can run queries that are resource-intensive, effectively shutting down the database server and making the application unavailable.

<!-- end list -->
