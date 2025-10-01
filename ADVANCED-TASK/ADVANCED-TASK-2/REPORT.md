# API Penetration Testing Process

## The 5 Phases of API Pentesting

1.  **Planning and Preparation**
    This initial phase is about setting the stage for the test. It involves defining the scope—clarifying which API endpoints and functions are to be tested and which are off-limits. Testers and the client agree on the rules of engagement, timeline, and objectives. The goal is to ensure the pentest is effective, legal, and doesn't cause unexpected disruptions.

2.  **Discovery**
    This phase involves mapping out the target API. Pentesters work to discover all accessible endpoints, understand the authentication mechanisms (like API keys or tokens), and analyze the API's overall functionality. The aim is to create a comprehensive picture of the API's attack surface before active testing begins.

3.  **Testing**
    This is the core phase where testers actively try to find and exploit vulnerabilities. Using the information from the discovery phase, they look for common security flaws.

4.  **Reporting**
    Findings are compiled into a detailed report. The report documents each vulnerability, its potential business impact, and a severity rating (e.g., Critical, High, Medium, Low).

5.  **Remediation & Re-testing**
    The development team fixes the identified vulnerabilities. The system is then re-tested to verify that the vulnerabilities have been successfully patched and that the fixes haven't introduced any new security issues.

-----

## Tools Used

### Postman

Postman is an API platform for building and using APIs. For pentesters, it's an indispensable tool for sending, modifying, and analyzing HTTP requests to an API. It allows you to organize requests into collections, automate tests, and collaborate with teams.

  * **Installation Source:** [https://www.postman.com/downloads/](https://www.postman.com/downloads/)

#### Installation Process on Linux:

1.  **Extract the `tar.gz` file:**

    ```bash
    cd ~/Downloads
    tar -xzf postman-linux-x64.tar.gz
    ```

2.  **Move the extracted folder to `/opt`:**

    ```bash
    sudo mv Postman /opt/
    ```

3.  **Create a Symlink for Easy Launch from the terminal:**

    ```bash
    sudo ln -s /opt/Postman/Postman /usr/local/bin/postman
    ```

-----

## Lab Setup: VAmPI

**VAmPI** is a vulnerable API made with Flask and it includes vulnerabilities from the OWASP top 10 vulnerabilities for APIs. It was created to evaluate the efficiency of tools used to detect security issues in APIs. It includes a switch to turn vulnerabilities on or off, which helps in analyzing false positives/negatives. VAmPI can also be used for learning/teaching purposes.

### Installation Process:

1.  Clone the repository:
    `git clone https://github.com/erev0s/VAmPI`

2.  Install `venv` if it is not already installed:
    `sudo apt install python3-venv`

3.  Create a virtual environment:
    `python3 -m venv myvampi`

4.  Activate the virtual environment:
    `source myvampi/bin/activate`

5.  Install the required packages:
    `pip install -r requirements.txt`

-----

## References

  * **VAmPI GitHub Repository:** [https://github.com/erev0s/VAmPI](https://github.com/erev0s/VAmPI)
  * **Postman Official Website:** [https://www.postman.com](https://www.postman.com)