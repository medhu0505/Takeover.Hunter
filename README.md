# Takeover.Hunter
⚡ TAKEOVER.HUNTER - A professional, multi-threaded subdomain takeover auditor featuring recursive CNAME chaining, real-time DNS triage, and automated HackerOne report generation.

**TAKEOVER.SH** is a high-performance subdomain takeover discovery and verification engine. Designed for bug bounty hunters and security researchers, it automates the tedious process of enumerating subdomains, triaging DNS records, and verifying dangling CNAMEs against a database of vulnerable cloud providers.

![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Status](https://img.shields.io/badge/status-active-success)

## 🚀 Features

- **Recursive CNAME Chaining:** Follows the full DNS path to find orphaned targets, even through multiple layers of aliases.
- **Wildcard Detection:** Intelligent logic to detect and flag wildcard DNS records, preventing thousands of false positives.
- **Real-Time Streaming:** Uses Server-Sent Events (SSE) to stream live tool output and discovery logs to the dashboard.
- **Signature Engine:** Pre-configured fingerprints for high-value targets (Seismic, CloudFront, S3, Heroku, etc.).
- **Auto-Reporting:** One-click generation of professional Markdown reports formatted specifically for HackerOne and Bugcrowd.
- **Multi-Tool Integration:** Bridges the gap between `subfinder`, `assetfinder`, and manual verification.

## 🛠️ Installation

### 1. Prerequisites
Ensure you have the following tools installed and in your system PATH:
- [Subfinder](https://github.com/projectdiscovery/subfinder)
- [Assetfinder](https://github.com/tomnomnom/assetfinder)

### 2. Setup
```bash
# Clone the repository
git clone [https://github.com/YOUR_USERNAME/takeover-sh.git](https://github.com/YOUR_USERNAME/takeover-sh.git)
cd takeover-sh

# Install Python dependencies
pip install -r requirements.txt
