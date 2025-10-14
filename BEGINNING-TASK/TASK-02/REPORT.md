# Security Reconnaissance Tools

This document provides a summary of several security tools useful for reconnaissance and discovery.

## Subfinder: Subdomain Discovery
Subfinder is a lightning-fast subdomain discovery tool that uses exclusively passive sources to uncover an organization's attack surface. By querying dozens of trusted data sources, it finds valid subdomains without ever sending traffic to the target, making it an essential tool for security professionals and bug bounty hunters.

### Core Features
- **High-Speed Enumeration:** Engineered for performance. Its concurrent resolution engine and advanced wildcard filtering deliver accurate results in seconds, not minutes.
- **Curated Passive Sources:** Pulls data from numerous curated passive sources—including search engines, certificate transparency logs, and internet archives—to guarantee maximum subdomain discovery.
- **Flexible Output Formats:** Supports multiple output formats including JSON, text files, and standard output for seamless integration.
- **Lightweight and Modular:** Designed with a simple, modular architecture that minimizes resource usage while maintaining scalability.
- **Workflow Integration:** Full STDIN/STDOUT support makes it easy to integrate into automation pipelines and existing security toolchains.

### Usage
```bash
subfinder -h
subfinder -d example.com
````

**Source:** [subfinder](https://github.com/projectdiscovery/subfinder)

---

## Knock Subdomain Scan

Knockpy is a portable and modular python3 tool designed to quickly enumerate subdomains on a target domain through passive reconnaissance and dictionary scan.

### Core Features

  - **Wordlist-Based Enumeration:** Knockpy uses custom or built-in wordlists to perform brute-force subdomain discovery, enabling detection of hidden or obscure subdomains that may not appear in passive datasets.
  - **DNS Resolution & Wildcard Filtering:** Automatically resolves discovered subdomains and detects wildcard DNS entries, reducing false positives and improving accuracy.
  - **SQLite Logging:** Stores results in a local SQLite database, making it easy to review and analyze findings over time.
  - **Extensible & Scriptable:** Easily integrate Knockpy into larger scripts or workflows thanks to its Python codebase and clean CLI interface.
  - **TLD Support:** Supports scanning across various TLDs, helping uncover domain variations and typo-squatting opportunities.

### Usage

```bash
knockpy -h
knockpy -d example.com
```

**Source:** [knock](https://github.com/guelfoweb/knock)

-----

## HTTPX: Next-Gen HTTP Client for Python

HTTPX is a powerful, fully featured HTTP client for Python 3 that supports both HTTP/1.1 and HTTP/2. It offers a modern API design, seamless sync and async capabilities, and an integrated command-line interface—making it an ideal choice for developers and testers working with web requests.

### Core Features

  - **HTTP/1.1 & HTTP/2 Compatibility:** Handles both HTTP/1.1 and HTTP/2 out of the box, ensuring high performance and compatibility with modern web infrastructure.
  - **Command-Line Interface:** Includes an intuitive CLI (`httpx`) for quick testing and inspection of HTTP requests directly from the terminal.
  - **Modern Standards:** First-class support for modern HTTP standards like connection pooling, timeouts, redirects, cookie persistence, and more.
  - **Fully Compatible with Requests:** Familiar API design inspired by the popular `requests` library, with enhancements for modern use cases.

### Usage

```bash
httpx [https://example.com](https://example.com)
httpx --http2 [https://example.com](https://example.com)
httpx -m POST [https://example.com](https://example.com)
```

**Source:** [httpx](https://github.com/encode/httpx)

-----

## pagodo: Passive Google Dork Automation

pagodo (Passive Google Dork) is a command-line tool that automates the process of using Google Dorks to discover sensitive information exposed on the web. It allows security researchers and bug bounty hunters to perform passive reconnaissance without directly touching the target’s infrastructure.

### Core Features

  - **Passive Reconnaissance:** Performs non-intrusive scanning by querying Google, not the target. This reduces the chance of detection or triggering security alerts.
  - **Preloaded Dork List:** Ships with an extensive, categorized set of Google Dorks curated from the infamous Google Hacking Database (GHDB).
  - **Custom Dork Lists:** Supports user-provided dork files for tailored recon based on your needs.
  - **CLI Tooling:** Simple command-line interface with options for target domains, dork files, and output formatting.

### Usage

```bash
python3 pagodo.py -d github.com -g dork.txt
```

**Source:** [pagodo](https://github.com/opsdisk/pagodo)

```
```
