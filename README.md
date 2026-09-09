# Reverse Shell Receiver

A high-performance, elegant, and modern Burp Suite extension tailored for penetration testers and red team operators. It combines an **HTTP/HTTPS Webhook Listener (OAST Engine)**, a **Multi-Session Interactive Reverse Shell Manager**, an **Extensive Multi-Platform Payload Generator (40+ Templates)**, and a **Mock Endpoint / SSRF Redirector Router** within a clean, luxury, icon-free user interface.

---

## Overview

**Reverse Shell Receiver** eliminates the need for separate terminal listeners (netcat, socat, python HTTP servers) during web application security assessments. It provides an all-in-one testing suite directly inside Burp Suite to capture out-of-band application interactions, manage multiple concurrent reverse shells, host dynamic payload stagers, and generate tailored exploitation payloads.

---

## Core Capabilities & Architecture

### 1. HTTP / HTTPS Webhook Listener (OAST & Mock Engine)

- **Dual-Protocol Server Binding:**
  - Listens on all local and VPN network interfaces (`0.0.0.0`) on any user-configured port.
  - Native **TLS/SSL Encryption toggle** backed by an embedded 2048-bit RSA PKCS#12 certificate for handling HTTPS OAST callbacks and SSL reverse shells.
- **Dynamic Endpoint Routing (Mock Routes & SSRF Redirector):**
  - Built-in **Mock Routes Manager** with Exact, Prefix, and Regex URL path matching.
  - Preloaded with essential assessment routes:
    - `/redirect`: Returns `302 Found` redirecting to Cloud Metadata (`http://169.254.169.254/latest/meta-data/`).
    - `/aws-meta`: Serves mock AWS IAM instance JSON metadata for SSRF validation.
    - `/payload`, `/rev.ps1`, `/shell.sh`: Dynamic stagers for reverse shells.
- **Dynamic Query Parameter Overrides:**
  - Modify response status codes, content types, and redirect locations on-the-fly via URL query parameters (e.g. `?status=302&location=https://target.internal` or `?status=401&body=Unauthorized`).
- **Interactive Telemetry Dashboard & Exfil Dropzone:**
  - Dark-themed responsive HTML5 telemetry dashboard returning real-time client IP (`{{client_ip}}`), HTTP method (`{{method}}`), requested path (`{{path}}`), port (`{{port}}`), timestamp (`{{timestamp}}`), payload size (`{{content_length}} Bytes`), and raw captured headers.
  - Embedded file exfiltration dropzone form (`/exfil`) for testing file uploads and POST callbacks.
- **Burp Ecosystem Integration:**
  - Real-time search and filter across method, path, client IP, and timestamp.
  - Full side-by-side inspection in native Burp `IMessageEditor` panels with context menu actions (**Send to Repeater**, **Send to Intruder**).
  - Memory safeguard clamping inbound request bodies to `10 MB` maximum.

---

### 2. Multi-Session Interactive Reverse Shell Manager

- **Concurrent Multi-Session Engine:**
  - Concurrently manages multiple inbound reverse shell connections without overwriting or terminating previous sessions.
  - Interactive session table displaying: Session ID, Remote Host, Port, Detected OS, Connected Timestamp, Live Uptime, and Active/Closed status.
  - Seamless session switching with independent terminal buffers and isolated command histories.
- **Encrypted Sockets Support:**
  - Native support for encrypted reverse shells (`PowerShell TLS`, `Ncat SSL`, `Socat OpenSSL`) via the TLS/SSL listener toggle.
- **Dynamic OS & Path Tracking:**
  - Silently fingerprints target OS (**Linux/UNIX**, **Windows CMD**, and **Windows PowerShell**).
  - Live remote directory tracking (`PWD` / `(pwd).Path`) displayed in a clean prompt:
    ```text
    [192.168.1.50:4444] [DIR: /var/www/html] $ whoami
    ```
- **Built-in File Transfer Helper:**
  - `UPLOAD FILE TO SHELL`: Automated Base64 chunked transfer uploading local files directly into remote Linux (`/tmp/`) or Windows (`C:\Users\Public\`) targets with one click.
- **Session Transcript Exporter:**
  - `EXPORT SESSION LOG`: One-click export of complete interactive session transcripts to formatted Markdown (`.md`) or text files for penetration testing reports.
- **Command History & Quick Assist Actions:**
  - Cycle through command history with `Up` and `Down` arrow keys.
  - Quick assist dropdown for instant post-exploitation shortcuts:
    - Spawn Bash / Python 3 PTY
    - Full TTY Terminal Upgrade (`stty raw -echo; fg`)
    - Fast System, User, and Network Enumeration (`whoami`, `uname -a`, `sudo -l`, `ip a`)
    - PowerShell AMSI Bypass (Memory Patch & Reflection)
    - Signal Handling (`Ctrl+C` / `SIGINT`)

---

### 3. Extensive Payload Generator (40+ Templates) & Auto-Host

Organized into 5 distinct categories with real-time keyword search, auto-detection, and auto-generation:

| Category | Supported Platforms | Notable Templates |
|---|---|---|
| **Reverse Shells** | Linux, Windows, macOS, Cross-Platform | Bash TCP (`/dev/tcp`), Bash UDP, Bash Readline, Python 3 PTY, Python 3 IPv6, Netcat (`-e` & `mkfifo`), Ncat SSL Encrypted, Socat TTY, Socat OpenSSL, OpenSSL `s_client`, Perl (Std & No-sh), PHP (`fsockopen` & `proc_open`), Ruby (Std & No-sh), Java Runtime, Golang, Node.js, Lua, Awk, Telnet, PowerShell TCPClient, PowerShell TLS/SSL, PowerShell IEX Cradle, Windows Netcat, Windows C# (`csc.exe`), MSHTA Stager, Certutil Exec |
| **Bind Shells** | Linux, Windows | Netcat Linux, Netcat Windows, Python 3 Bind, Socat Bind, PowerShell Bind |
| **Web Shells** | PHP, Java JSP, .NET ASPX, Node.js | PHP Simple CMD, PHP Full-Featured Web Shell, PHP Base64 Eval, JSP ProcessBuilder Shell, ASPX C# Command Shell, Node.js Express Route |
| **Data Exfiltration** | Linux, Windows | cURL POST File, Wget POST File, PowerShell IWR POST, Linux DNS Exfil (`dig` hex chunks), Windows DNS Exfil (`Resolve-DnsName`) |
| **Stagers & Helpers** | Windows, Cross-Platform | PowerShell AMSI Bypass (Memory Patch), Python 3 HTTP Server, PHP Built-in Server, Windows Download Cradles Cheat Sheet |

#### Auto-Host Stager Integration:
- **`HOST AS STAGER ON WEBHOOK` Button:** Instantly publishes the active generated payload to the Webhook listener (`http://<ip>:<port>/payload`, `/rev.ps1`, `/shell.sh`) for immediate use with download cradles (`IEX (New-Object Net.WebClient)...`, `curl | sh`).

#### Advanced Encodings & Wrappers:
- `None (Raw)`
- `Base64 (Standard)`
- `Base64 (Linux sh wrapped)` (`echo <b64> | base64 -d | sh`)
- `Base64 (Linux bash wrapped)` (`echo <b64> | base64 -d | bash`)
- `PowerShell EncodedCommand (-enc)` (UTF-16LE Base64)
- `URL Encode (Standard)`
- `URL Encode All (Full Hex %XX)`
- `Double URL Encode`
- `Hex Escaped (\x41\x42...)`
- `HTML Entity (&#x41;&#x42;...)`

---

### 4. Icon-Free Visual Styling & Port Management

- **Minimalist Aesthetic:** Clean, typography-first user interface with strictly zero icons, emojis, or unicode box-drawing clutter.
- **Smart Interactive Address Chips:**
  - Displays all active network interfaces and VPN IPs.
  - Automatically formats and copies complete `https://<ip>:<port>/` URLs when TLS/SSL is active, or `http://<ip>:<port>/` / `<ip>:<port>` in standard modes.
- **Integrated Port Manager:** Scan and terminate conflicting listening processes on Windows (`netstat` + `taskkill`) and Linux (`netstat` + `kill`).

---

## Usage Guide

### 1. Starting the Listener
1. Open the **Reverse Shell Receiver** tab in Burp Suite.
2. Select your desired mode: **HTTP Webhook** or **Reverse Shell**.
3. Enter the listening port number (e.g. `8080` or `4444`).
4. (Optional) Check **TLS/SSL Socket** if you wish to accept encrypted HTTPS callbacks or SSL reverse shells.
5. Click **START** to bring the listener online; the status badge will transition to **ONLINE** and the address chips will populate.
6. Click any listening address chip to copy the full URL (`https://...` or `http://...`) to your clipboard.

### 2. Capturing Out-of-Band Webhook Interactions
1. Direct target callbacks, SSRF payloads, or webhook beacons to your listening address.
2. Inbound requests appear in the Webhook table; click any row to inspect the full request and response side-by-side.
3. Right-click inside the request viewer to send the request to **Repeater**, **Intruder**, or other Burp Suite tools.
4. Click **MOCK ROUTES & SSRF** to configure custom routes (such as `/redirect` for cloud metadata redirection or `/aws-meta`).
5. Click **CONFIGURE RESPONSE** to customize default HTTP status codes, headers, and CORS settings.

### 3. Interacting with Multi-Session Reverse Shells
1. Ensure the listener is running in **Reverse Shell** mode.
2. Execute your reverse shell payload on the remote target.
3. When connected, the session is registered in the **Active Reverse Shell Sessions** table with detected OS and live uptime.
4. If multiple targets connect, click any row in the session table to switch to that session's interactive terminal.
5. Type commands into the command input field and press Enter or click **SEND**.
6. Use the **QUICK ACTION** dropdown to spawn PTYs, upgrade TTYs, or bypass AMSI.
7. Click **UPLOAD FILE TO SHELL** to transfer local files to the target, or **EXPORT SESSION LOG** to save the terminal transcript as Markdown.

### 4. Generating & Auto-Hosting Payloads
1. Navigate to the **Payload Generator** tab.
2. Filter templates using the search bar, category dropdown, or target OS selector.
3. Click **AUTO-FILL FROM LISTENER** to synchronize IP and Port with your active listener.
4. Select an encoding format from the **ENCODING** dropdown.
5. Click **GENERATE PAYLOAD** to render the payload in the editor, and **COPY PAYLOAD** to copy it to clipboard.
6. Click **HOST AS STAGER ON WEBHOOK** to make the script downloadable immediately from your HTTP listener (`/payload`, `/rev.ps1`, `/shell.sh`).

### 5. Managing Port Conflicts
1. If a port is occupied by another process, click **KILL PORTS**.
2. Select the conflicting process from the dialog table.
3. Click **TERMINATE SELECTED** to terminate the process and release the port immediately.

---

## Build & Installation

### Requirements
- Java 8 or higher (`source/target 1.8`)
- Apache Maven 3.x

### Build from Source
```bash
git clone https://github.com/your-repo/reverse-shell-receiver.git
cd reverse-shell-receiver
mvn clean package
```

The resulting compiled JAR will be located at:
```text
target/reverse-shell-receiver-1.0.0-jar-with-dependencies.jar
```

### Installing in Burp Suite
1. Open Burp Suite and navigate to **Extensions** -> **Installed**.
2. Click **Add**, select Extension type **Java**, and choose `target/reverse-shell-receiver-1.0.0-jar-with-dependencies.jar`.
3. Click **Next** to load the extension. The **Reverse Shell Receiver** tab will appear in the top navigation bar.

---

## Author

**Joel Indra**
