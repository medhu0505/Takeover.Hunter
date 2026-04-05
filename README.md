# 🎯 Takeover Hunter

A powerful and lightweight **subdomain takeover detection tool** built with Flask and Python. Automatically discovers dangling DNS records pointing to unclaimed cloud resources, exposing critical security vulnerabilities.

## 🚀 Live Demo

**[Launch Takeover Hunter](https://web-production-88530.up.railway.app)**

## ✨ Features

- **Automated Subdomain Enumeration** — Integrates `subfinder` and `assetfinder` for comprehensive discovery
- **DNS Intelligence** — Detects CNAME chains, wildcard domains, and NXDOMAIN records
- **18+ Cloud Provider Signatures** — Identifies vulnerable hosting platforms:
  - Heroku, GitHub Pages, AWS S3, CloudFront, Azure, Fastly, Netlify, Vercel
  - Shopify, Webflow, WordPress, Ghost, Tumblr, Zendesk, and more
- **High-Velocity Scanning** — 30 concurrent workers for fast vulnerability assessment
- **Real-time Streaming** — Live SSE event updates for long-running scans
- **Confidence Scoring** — High/Medium/Low confidence ratings with severity classification
- **Verification System** — Double-checks vulnerabilities before reporting
- **Professional Reporting** — HackerOne-ready Markdown reports with attack vectors

## 🛠️ Installation

### Local (Emergency Use)
```bash
cd ~/takeover-hunter
bash run.sh
# Opens on http://localhost:5000
```

### With Docker
```bash
docker build -t takeover-hunter .
docker run -p 5000:5000 takeover-hunter
```

## 📋 Requirements

- **Python 3.13** (or 3.10+)
- **pip** (Python package manager)
- **Optional**: `subfinder`, `assetfinder`, `amass` (Go recon tools)

## 📦 Dependencies

```
flask>=3.0.0
dnspython>=2.6.0
requests>=2.31.0
urllib3>=2.0.0
```

## 🔧 Configuration

The app automatically detects and uses optional recon tools:
- **subfinder** — ProjectDiscovery's subdomain enumeration
- **assetfinder** — TomNomNom's asset finder
- **amass** — OWASP Amass for passive reconnaissance

## 📁 Project Structure

```
takeover-hunter/
├── app.py                 # Core Flask application
├── requirements.txt       # Python dependencies
├── Dockerfile            # Docker build configuration
├── Procfile              # Railway deployment config
├── run.sh                # Local startup script
├── README.md             # This file
└── templates/
    └── index.html        # Web UI (terminal-dark theme)
```

## 🎮 Usage

### Web Interface
Navigate to the deployed app and use the interactive terminal interface:
1. **Enumerate** — Discover subdomains for your target
2. **Triage** — Filter by CNAME records and DNS status
3. **Scan** — Check each CNAME for takeover vulnerabilities
4. **Verify** — Confirm vulnerable CNAMEs are genuinely exploitable
5. **Report** — Generate professional vulnerability reports

### API Endpoints

#### `/api/enumerate?target=example.com`
Stream subdomain enumeration results

#### `/api/triage` (POST)
Classify subdomains by CNAME presence
```json
{"subdomains": ["api.example.com", "cdn.example.com"]}
```

#### `/api/scan` (POST)
Parallel vulnerability scanning
```json
{"cname_records": [{"sub": "api.example.com", "cname": "api.heroku.com"}]}
```

#### `/api/verify` (POST)
Double-check vulnerable findings

#### `/api/quickscan` (POST)
Single-subdomain instant assessment

#### `/api/dns` (POST)
Custom DNS lookups (A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, ANY)

#### `/api/report` (POST)
Generate HackerOne-formatted reports

## 🚂 Deployment

### Railway
```bash
git push heroku main
```
Dockerfile and Procfile enable automatic Go tools + dependencies.

### Manual Docker
```bash
docker build -t takeover-hunter .
docker run -p 5000:5000 -e PORT=5000 takeover-hunter
```

## 🔍 How It Works

1. **Enumeration** — Uses `subfinder` and `assetfinder` to discover subdomains
2. **DNS Triage** — Resolves CNAME records and identifies delegation patterns
3. **Fingerprinting** — Matches CNAME targets against known cloud provider patterns
4. **Vulnerability Check** — Confirms NXDOMAIN + CNAME presence
5. **HTTP Probing** — Tests status codes and response bodies
6. **Verification** — Re-checks findings to eliminate false positives
7. **Reporting** — Generates detailed vulnerability assessments

## ⚠️ Legal Disclaimer

Use this tool **only on systems you have explicit permission to test**. Unauthorized access is illegal. Designed for defensive security research and authorized penetration testing.

## 📚 Resources

- [OWASP — Subdomain Takeover](https://owasp.org/www-community/attacks/Subdomain_Takeover)
- [Project Discovery — Subfinder](https://github.com/projectdiscovery/subfinder)
- [Tomnomnom — Assetfinder](https://github.com/tomnomnom/assetfinder)

---

**Built with ❤️ for security researchers and bug bounty hunters**
