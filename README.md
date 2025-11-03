# WP-Guardian
A PyQt5 GUI tool for WordPress security auditing. Features XML-RPC probing, REST API user enumeration, rate-limited brute-forcing, and OOB SSRF detection via Interactsh.


# WP Guardian 🛡️

WP Guardian is a PyQt5-based GUI tool for auditing the security of WordPress sites. It focuses on enumerating vulnerabilities and misconfigurations in the **XML-RPC** interface and the **WP REST API**.

It features out-of-band (OOB) vulnerability testing by correlating actions with callbacks received by an **Interactsh** instance and generates a simple PDF Proof-of-Concept report with a risk rating.

<img width="1901" height="1076" alt="image" src="https://github.com/user-attachments/assets/f99b0432-c9f0-464e-aab3-6dfa72214830" />


---

## 🚀 Key Features

* **XML-RPC Probing**: Checks for an enabled `xmlrpc.php` endpoint and fingerprints available methods (`system.listMethods`, `wp.getUsersBlogs`, etc.).
* **REST API User Enumeration**: Fetches and lists all discoverable users from the `/wp-json/wp/v2/users` endpoint.
* **Memory-Safe Brute-Force**: A rate-limited, multi-threaded brute-force module for `wp.getUsersBlogs` to test for weak passwords. It safely streams large password lists without loading them into memory.
* **Interactsh (OOB) Integration**: A full UI to run the `interactsh-client` in the background. It automatically detects and correlates OOB interactions (like SSRF) with sent payloads.
* **Custom XML-RPC Sender**: A flexible interface to send custom XML-RPC payloads, with a one-click template for `pingback.ping` SSRF testing.
* **PDF PoC Export**: Generates a clean PDF proof-of-concept report summarizing all findings, including a final **Critical/High/Medium/Low** risk assessment.

---

## ⚠️ Disclaimer

This tool is intended for educational purposes and **authorized security testing only**. Use this tool exclusively on targets you own or have explicit permission to test. The developer is not responsible for any misuse or damage caused by this program.

---

## 🔧 Installation

WP Guardian has two main dependencies: the `interactsh-client` binary and its own Python packages.

### 1. Install interactsh-client

You must have the `interactsh-client` from **ProjectDiscovery** installed and available in your system's PATH.

1.  Go to the [Interactsh releases page](https://github.com/projectdiscovery/interactsh/releases).
2.  Download the binary for your operating system.
3.  Place it in a directory that is part of your system's `PATH` (e.g., `/usr/local/bin` on Linux/macOS or a configured folder on Windows).
4.  You can verify it's working by opening a terminal and typing `interactsh-client`.

### 2. Install Python Dependencies

```bash
# 1. Clone this repository
git clone [https://github.com/](https://github.com/)[YourUsername]/[YourRepoName].git
cd [YourRepoName]

# 2. Create a virtual environment (recommended)
python3 -m venv venv

# 3. Activate the environment
# On Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# On Linux/macOS:
source venv/bin/activate

# 4. Install the required packages
pip install -r requirements.txt
```

---

## 🖥️ Usage

1.  Ensure your virtual environment is activated.
2.  Run the application:
    ```bash
    python wp_guardian_pyqt_interactsh.py
    ```
3.  **Start Interactsh**: In the GUI, go to the "Interactsh (OOB)" box and click "Start Interactsh". This will run the client to listen for hits.
4.  **Set Target**: Enter your target URL (e.g., `https://example.com`).
5.  **Probe & Test**: Use the "Probe XML-RPC" and "Fetch REST users" buttons.
6.  **Test SSRF**: Use the "Custom XML-RPC" section to send a `pingback.ping` payload. Watch the "Interactsh hits" table for a correlation.
7.  **Run Brute-Force**: Select a user, load a password list, and click "Start Brute".
8.  **Export**: Click "Export PoC (PDF)" to generate your report.
