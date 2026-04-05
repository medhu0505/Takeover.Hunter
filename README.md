# TAKEOVER.HUNTER — Subdomain Takeover Hunter

A fully local subdomain takeover hunting tool. No API keys. Real DNS queries.

## Stack
- **Backend**: Python / Flask + dnspython + requests
- **Frontend**: Vanilla HTML/CSS/JS (terminal dark UI)
- **DNS**: Real `dig`-equivalent queries via dnspython (8.8.8.8 + 1.1.1.1)

## Fingerprint DB
30+ providers — Heroku, GitHub Pages, AWS ELB, AWS S3, Azure, Fastly, Netlify,
Vercel, Shopify, Zendesk, Tumblr, WordPress, Typepad, Acquia, Surge.sh,
Pantheon, Ghost, SendGrid, Unbounce, Helpjuice, HelpScout, Bitbucket,
Cargo, StatusPage, Strikingly, Webflow, Fly.io, and more.

## Quick Start (Local)

```bash
cd ~/takeover-hunter
chmod +x run.sh
bash run.sh
```

Then open: http://127.0.0.1:5000

## Pipeline

### Stage 1 — Enumerate
Runs subfinder + assetfinder + amass (if installed) + DNS brute-force wordlist.
Resolves which subdomains are live.

### Stage 2 — DNS Triage (runs automatically after enumeration)
For every subdomain:
- `CNAME` → resolved and fingerprinted against provider DB
- `A` → records with IPs
- `DEAD` → no resolution

### Stage 3 — Scan CNAMEs for Vulns
Click **⚡ Scan CNAMEs for Vulns** button.
For each CNAME:
1. Checks NXDOMAIN on CNAME target
2. HTTP probe with body fingerprint matching
3. Classifies: vulnerable / confidence level / severity

### Stage 4 — Verify
Click **✓ Verify Findings** button.
Double-checks each vulnerable finding:
- NXDOMAIN × 2 (anti-flap)
- CNAME still present
- HTTP re-probe
- Outputs: CONFIRMED or NOT CONFIRMED

### Report
Click any verified finding → **Generate H1 Report**
Full HackerOne-ready report with CVSS score, steps to reproduce, impact.

## Optional Tools (install for better enumeration)

```bash
# subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# assetfinder
go install github.com/tomnomnom/assetfinder@latest

# amass
go install -v github.com/owasp-amass/amass/v4/...@master
```

## File Structure
```
takeover-hunter/
├── app.py              # Flask backend, DNS logic, fingerprints
├── templates/
│   └── index.html      # Full frontend UI
├── requirements.txt
├── run.sh              # Local setup script
├── Procfile            # For Railway deployment
├── .gitignore
└── README.md
```
