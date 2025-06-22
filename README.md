# 🕵️‍♂️ Website Information Gathering & Vulnerability Scanner

Website Information Gathering & Vulnerability Scanner is a Python-based reconnaissance and vulnerability assessment tool designed to collect in-depth technical and structural details about a target website or domain. Its primary purpose is to assist ethical hackers, cybersecurity researchers, penetration testers, and bug bounty hunters in identifying valuable insights about a web application's infrastructure.

This tool gathers publicly accessible data such as WHOIS registration info, DNS records, IP address, server response headers, web technologies in use (like CMS, frameworks, and server software), and active subdomains. Additionally, it leverages scanning tools like Nmap and wafw00f to detect open ports, potential vulnerabilities (CVE-based), and the presence of Web Application Firewalls (WAFs).

By automating and organizing these tasks, the tool helps security professionals map the attack surface, assess weak points, and determine the potential exposure of a website — all in a streamlined, fast, and user-friendly terminal interface.

> 🔰 **Created by:** SANTOSH CHHETRI <br>
> 🎬 **YouTube Channel:** Master in White Devil

---

## 🔍 About This Tool

This is a powerful Python-based **website information gathering and vulnerability scanner tool** designed for ethical hackers, penetration testers, and bug bounty hunters. It gathers detailed data about any target domain and performs basic vulnerability checks using tools like Nmap and WAF detection.

Whether you're a beginner or a pro, this tool simplifies reconnaissance and helps you understand the target infrastructure quickly.

---

## 🚀 Features

- ✅ WHOIS Lookup (creation/expiry date, registrar, country)
- ✅ DNS Records (A, MX, NS, TXT)
- ✅ Header Grabber (get server type and security headers)
- ✅ IP & Location Fetcher
- ✅ BuiltWith Technology Detection
- ✅ Subdomain Detection (optional extension)
- ✅ Nmap Vulnerability Scan (with `--script=vuln`)
- ✅ WAF (Web Application Firewall) Detection using wafw00f
- ✅ Clean CLI Interface with Hacker-Style Banner

---

## ⚙️ How It Works

1. You enter the domain (e.g., `google.com`)
2. The tool fetches:
   - WHOIS details
   - IP address & DNS records
   - HTTP headers and server info
   - Detected technologies
   - Runs `nmap` on target IP for open ports and known CVEs
   - Checks for WAF presence
3. Outputs all info in your terminal — easy to copy or analyze.

---

## 🛠 Installation

Make sure you're using **Linux (Kali, Parrot, Ubuntu)** or **Termux** for full functionality.

```bash
# Step 1: Clone the repository
git clone https://github.com/yourusername/website-info-scanner

# Step 2: Change directory
cd website-info-scanner

# Step 3: Install Python dependencies
pip install -r requirements.txt

# Step 4: Make sure Nmap and wafw00f are installed
sudo apt install nmap wafw00f
