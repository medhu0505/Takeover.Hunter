#!/usr/bin/env python3
"""
TAKEOVER.SH — Full Deadly Edition
Features: Wildcard Detection, CNAME Chaining, Seismic/CloudFront Logic, & High-Pressure Reporting
"""

import subprocess
import socket
import json
import time
import threading
import queue
import re
import sys
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, render_template, request, jsonify, Response, stream_with_context
import dns.resolver
import dns.exception
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

def command_exists(name: str) -> bool:
    return shutil.which(name) is not None

# ─── FINGERPRINT DB ───────────────────────────────────────────────────────────
FINGERPRINTS = [
    {"provider": "Heroku",         "patterns": ["herokuapp.com"],                     "takeover": True,  "status_match": "No such app"},
    {"provider": "GitHub Pages",   "patterns": ["github.io", "githubusercontent.com"], "takeover": True,  "status_match": "There isn't a GitHub Pages site here"},
    {"provider": "AWS S3",         "patterns": ["s3.amazonaws.com", "s3-website"],    "takeover": True,  "status_match": "NoSuchBucket"},
    {"provider": "AWS CloudFront", "patterns": ["cloudfront.net"],                    "takeover": True,  "status_match": "Bad Request"},
    {"provider": "Seismic",        "patterns": ["seismic.com", "tenant-services"],    "takeover": True,  "status_match": "The page you are looking for doesn't exist"},
    {"provider": "Azure",          "patterns": ["azurewebsites.net", "cloudapp.net"], "takeover": True,  "status_match": "404 Web Site not found"},
    {"provider": "Fastly",         "patterns": ["fastly.net"],                        "takeover": True,  "status_match": "Fastly error: unknown domain"},
    {"provider": "Netlify",        "patterns": ["netlify.app", "netlify.com"],        "takeover": True,  "status_match": "Not Found"},
    {"provider": "Vercel",         "patterns": ["vercel.app", "now.sh"],              "takeover": True,  "status_match": "The deployment could not be found"},
    {"provider": "Webflow",        "patterns": ["proxy.webflow.com", "webflow.io"],   "takeover": True,  "status_match": "The page you are looking for doesn't exist"},
    {"provider": "Pantheon",       "patterns": ["pantheonsite.io"],                   "takeover": True,  "status_match": "404 error unknown site"},
    {"provider": "AWS ELB",        "patterns": ["elb.amazonaws.com"],                 "takeover": True,  "status_match": ""},
    {"provider": "Ghost",          "patterns": ["ghost.io"],                          "takeover": True,  "status_match": "The thing you were looking for is no longer here"},
    {"provider": "Shopify",        "patterns": ["myshopify.com"],                     "takeover": True,  "status_match": "Sorry, this shop is currently unavailable"},
    {"provider": "Tumblr",         "patterns": ["tumblr.com"],                        "takeover": True,  "status_match": "There's nothing here"},
    {"provider": "WordPress",      "patterns": ["wordpress.com"],                     "takeover": True,  "status_match": "Do you want to register"},
    {"provider": "Zendesk",        "patterns": ["zendesk.com"],                       "takeover": True,  "status_match": "Help Center Closed"},
    {"provider": "Bitbucket",      "patterns": ["bitbucket.io"],                      "takeover": True,  "status_match": "Repository not found"},
]

# ─── DNS HELPERS ─────────────────────────────────────────────────────────────
resolver = dns.resolver.Resolver()
resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
resolver.timeout = 2
resolver.lifetime = 4

def is_wildcard(domain):
    try:
        random_sub = f"takeover-test-{int(time.time())}.{domain}"
        resolver.resolve(random_sub, "A")
        return True
    except:
        return False

def resolve_cname_chain(subdomain):
    chain = []
    curr = subdomain
    try:
        for _ in range(5):
            ans = resolver.resolve(curr, "CNAME")
            target = str(ans[0].target).rstrip(".")
            chain.append(target)
            curr = target
        return chain
    except:
        return chain

def check_nxdomain(host):
    try:
        resolver.resolve(host, "A")
        return False
    except dns.resolver.NXDOMAIN:
        return True
    except:
        return False

def resolve_a(host):
    try:
        ans = resolver.resolve(host, "A")
        return [str(r) for r in ans]
    except:
        return []

def resolve_cname(host):
    try:
        ans = resolver.resolve(host, "CNAME")
        return str(ans[0].target).rstrip(".")
    except:
        return None

def http_probe(subdomain):
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)",
        "X-Bug-Bounty": "stickybugger"
    }
    for scheme in ["https", "http"]:
        try:
            r = requests.get(
                f"{scheme}://{subdomain}",
                timeout=3,          # reduced for speed
                verify=False,
                allow_redirects=True,
                headers=headers
            )
            return {"code": r.status_code, "body": r.text[:1500], "headers": dict(r.headers)}
        except:
            continue
    return {"code": 0, "body": "", "headers": {}}

def match_fingerprint(cname_target):
    for fp in FINGERPRINTS:
        if any(p in cname_target.lower() for p in fp["patterns"]):
            return fp
    return None

# ─── SSE HELPER ──────────────────────────────────────────────────────────────
def sse_event(event, data):
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"

# ─── ENUMERATION ─────────────────────────────────────────────────────────────
def enumerate_subdomains_stream(target, q):
    collected = set()
    wildcard = is_wildcard(target)
    if wildcard:
        q.put(("log", "warn", "Wildcard DNS detected — expect false positives."))

    tool_q = queue.Queue()
    tools = []

    if command_exists("subfinder"):
        tools.append(threading.Thread(
            target=_run_tool,
            args=(f"subfinder -d {target} -silent", "subfinder", tool_q)
        ))
    if command_exists("assetfinder"):
        tools.append(threading.Thread(
            target=_run_tool,
            args=(f"assetfinder --subs-only {target}", "assetfinder", tool_q)
        ))

    if not tools:
        q.put(("log", "warn", "No tools found (subfinder/assetfinder). Install them for real enumeration."))

    for t in tools:
        t.daemon = True
        t.start()

    for _ in range(len(tools)):
        try:
            _, label, lines, err = tool_q.get(timeout=130)
            if err:
                q.put(("log", "err", f"{label} error: {err}"))
            for l in lines:
                if target in l.lower():
                    collected.add(l.lower().strip())
            q.put(("log", "ok", f"{label}: {len(lines)} results"))
        except:
            break

    subdomains = list(collected)
    q.put(("enum_done", subdomains, len(subdomains)))

def _run_tool(cmd, label, q):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
        lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        q.put(("tool_done", label, lines, None))
    except Exception as e:
        q.put(("tool_done", label, [], str(e)))

@app.route("/api/enumerate")
def api_enumerate():
    target = request.args.get("target", "").strip().lower()
    if not target:
        return jsonify({"error": "No target"}), 400

    q = queue.Queue()
    threading.Thread(target=enumerate_subdomains_stream, args=(target, q), daemon=True).start()

    def gen():
        while True:
            msg = q.get()
            if msg[0] == "log":
                yield sse_event("log", {"level": msg[1], "msg": msg[2]})
            elif msg[0] == "enum_done":
                yield sse_event("done", {"subdomains": msg[1], "count": msg[2]})
                break

    return Response(stream_with_context(gen()), content_type="text/event-stream")

# ─── DNS TRIAGE ──────────────────────────────────────────────────────────────
def triage_worker(subdomains, q):
    total = len(subdomains)
    cnames = []
    dead = []
    a_records = []

    for i, sub in enumerate(subdomains):
        q.put(("progress", i + 1, total))

        cname = resolve_cname(sub)
        if cname:
            fp = match_fingerprint(cname)
            cnames.append({
                "sub": sub,
                "cname": cname,
                "provider": fp["provider"] if fp else "Unknown",
                "takeover_possible": fp["takeover"] if fp else False,
            })
            continue

        ips = resolve_a(sub)
        if ips:
            a_records.append({"sub": sub, "ips": ips})
        else:
            dead.append({"sub": sub})

    q.put(("triage_done", cnames, dead, a_records))

@app.route("/api/triage", methods=["POST"])
def api_triage():
    subdomains = request.json.get("subdomains", [])
    if not subdomains:
        return Response(
            sse_event("done", {"cname": [], "dead": [], "a": []}),
            content_type="text/event-stream"
        )

    q = queue.Queue()
    threading.Thread(target=triage_worker, args=(subdomains, q), daemon=True).start()
    total = len(subdomains)

    def gen():
        while True:
            msg = q.get()
            if msg[0] == "progress":
                yield sse_event("progress", {"done": msg[1], "total": msg[2]})
            elif msg[0] == "triage_done":
                yield sse_event("done", {
                    "cname": msg[1],
                    "dead": msg[2],
                    "a": msg[3],
                })
                break

    return Response(stream_with_context(gen()), content_type="text/event-stream")

# ─── PARALLEL VULN SCAN (NEW) ────────────────────────────────────────────────
def vuln_scan_worker_parallel(cname_records, q, max_workers=30):
    total = len(cname_records)
    vulnerable = []
    semaphore = threading.Semaphore(35)   # concurrent cap

    def check_one(rec):
        with semaphore:
            sub = rec["sub"]
            chain = resolve_cname_chain(sub)
            target = chain[-1] if chain else rec.get("cname", "")

            nx = check_nxdomain(target)
            probe = http_probe(sub)
            fp = match_fingerprint(target)

            is_v = False
            conf = "low"
            body_match = False
            match_string = ""

            if nx:
                is_v = True
                conf = "high"
            elif fp and fp.get("status_match") and fp["status_match"].lower() in probe["body"].lower():
                is_v = True
                conf = "high"
                body_match = True
                match_string = fp["status_match"]
            elif fp and fp.get("takeover_possible") and probe["code"] in [0, 404]:
                is_v = True
                conf = "medium"

            if is_v:
                sev = "Critical" if any(x in sub for x in ["auth", "login", "api", "sso", "account"]) else "High"
                result = {
                    "sub": sub,
                    "cname": target,
                    "provider": fp["provider"] if fp else "Orphaned",
                    "nxdomain": nx,
                    "http_code": probe["code"],
                    "body_match": body_match,
                    "match_string": match_string,
                    "vulnerable": True,
                    "confidence": conf,
                    "severity": sev,
                }
                q.put(("vuln", result))
                return result
            return None

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(check_one, rec) for rec in cname_records]
        for i, future in enumerate(as_completed(futures)):
            q.put(("progress", i + 1, total))
            try:
                res = future.result()
                if res:
                    vulnerable.append(res)
            except Exception as e:
                q.put(("log", "err", f"Worker error on {rec.get('sub', 'unknown')}: {str(e)}"))

    q.put(("scan_done", vulnerable))


@app.route("/api/scan", methods=["POST"])
def api_scan():
    recs = request.json.get("cname_records", [])
    if not recs:
        return Response(
            sse_event("done", {"count": 0, "vulnerable": []}),
            content_type="text/event-stream"
        )

    q = queue.Queue()
    threading.Thread(
        target=vuln_scan_worker_parallel,
        args=(recs, q, 30),   # 30 workers — fast but safe
        daemon=True
    ).start()

    def gen():
        while True:
            msg = q.get()
            if msg[0] == "progress":
                yield sse_event("progress", {"done": msg[1], "total": msg[2]})
            elif msg[0] == "vuln":
                yield sse_event("vuln", msg[1])
            elif msg[0] == "scan_done":
                yield sse_event("done", {"count": len(msg[1]), "vulnerable": msg[1]})
                break
            elif msg[0] == "log":
                yield sse_event("log", {"level": msg[1], "msg": msg[2]})

    return Response(stream_with_context(gen()), content_type="text/event-stream")

# ─── VERIFY ──────────────────────────────────────────────────────────────────
def verify_worker(vulnerable_list, q):
    verified_results = []

    for vuln in vulnerable_list:
        sub = vuln["sub"]
        cname = vuln["cname"]
        q.put(("log", "info", f"Verifying {sub}..."))

        nx1 = check_nxdomain(cname)
        time.sleep(0.3)
        nx2 = check_nxdomain(cname)

        probe = http_probe(sub)
        live_cname = resolve_cname(sub)
        cname_still_present = live_cname is not None and cname.lower() in live_cname.lower()

        confirmed = nx1 and nx2 and cname_still_present

        result = {
            **vuln,
            "verified": confirmed,
            "verify_nxdomain_1": nx1,
            "verify_nxdomain_2": nx2,
            "verify_http": probe["code"],
            "cname_still_present": cname_still_present,
        }
        verified_results.append(result)

        if confirmed:
            q.put(("log", "ok", f"✓ CONFIRMED: {sub} — reportable"))
        else:
            q.put(("log", "warn", f"✗ Not confirmed: {sub}"))

        q.put(("verified", result))

    q.put(("verify_done", verified_results))

@app.route("/api/verify", methods=["POST"])
def api_verify():
    vulnerable_list = request.json.get("vulnerable", [])
    q = queue.Queue()
    threading.Thread(target=verify_worker, args=(vulnerable_list, q), daemon=True).start()

    def gen():
        while True:
            msg = q.get()
            if msg[0] == "log":
                yield sse_event("log", {"level": msg[1], "msg": msg[2]})
            elif msg[0] == "verified":
                yield sse_event("verified", msg[1])
            elif msg[0] == "verify_done":
                yield sse_event("done", {"verified": msg[1]})
                break

    return Response(stream_with_context(gen()), content_type="text/event-stream")

# ─── REPORT ──────────────────────────────────────────────────────────────────
@app.route("/api/report", methods=["POST"])
def api_report():
    f = request.json.get("finding", {})
    user = request.json.get("h1_user", "stickybugger")

    nx_status = "NXDOMAIN confirmed" if f.get("nxdomain") else "resolved (check manually)"
    body_note = f"Body match: `{f.get('match_string')}` — confirmed." if f.get("body_match") else "No body match — verify manually."

    report = f"""# Subdomain Takeover: {f.get('sub')}

## Summary
The subdomain `{f.get('sub')}` has a dangling CNAME pointing to `{f.get('cname')}`, \
an unclaimed resource on **{f.get('provider')}**. This allows an attacker to register \
the orphaned resource and serve arbitrary content under the trusted domain.

## Severity
**{f.get('severity')}** — Confidence: {f.get('confidence', 'high').upper()}

## Steps to Reproduce
1. `dig {f.get('sub')} CNAME +short`
   → Returns: `{f.get('cname')}`

2. `dig @8.8.8.8 {f.get('cname')} A +short`
   → {nx_status}

3. `curl -sk -o /dev/null -w "%{{http_code}}" https://{f.get('sub')}`
   → HTTP {f.get('http_code')}

4. {body_note}

## Impact
Full subdomain takeover. An attacker can:
- Serve phishing pages under `{f.get('sub')}`
- Steal session cookies scoped to the parent domain
- Bypass CSP/CORS policies trusting this subdomain
- Send authenticated-looking emails via SPF bypass

## Remediation
Remove or update the dangling CNAME record for `{f.get('sub')}` in DNS.

## Reporter
HackerOne: @{user}"""

    return jsonify({"report": report})

# ─── QUICK SCAN ──────────────────────────────────────────────────────────────
@app.route("/api/quickscan", methods=["POST"])
def api_quickscan():
    data  = request.json or {}
    sub   = data.get("sub", "").strip()
    cname = data.get("cname", "").strip()

    if not cname:
        return jsonify({"error": "cname required"}), 400

    chain  = resolve_cname_chain(sub) if sub and sub != cname else []
    target = chain[-1] if chain else cname

    nx     = check_nxdomain(target)
    probe  = http_probe(sub if sub else cname)
    fp     = match_fingerprint(target)

    is_v       = False
    conf       = "low"
    body_match = False
    match_str  = ""

    if nx:
        is_v = True
        conf = "high"
    elif fp and fp.get("status_match") and fp["status_match"].lower() in probe["body"].lower():
        is_v       = True
        conf       = "high"
        body_match = True
        match_str  = fp["status_match"]
    elif fp and fp.get("takeover_possible") and probe["code"] in [0, 404]:
        is_v = True
        conf = "medium"

    sev = "Critical" if any(x in (sub or cname) for x in ["auth","login","api","sso","account"]) else "High"

    return jsonify({
        "sub":          sub or cname,
        "cname":        target,
        "provider":     fp["provider"] if fp else "Unknown",
        "nxdomain":     nx,
        "http_code":    probe["code"],
        "body_match":   body_match,
        "match_string": match_str,
        "confidence":   conf,
        "severity":     sev,
        "vulnerable":   is_v,
        "cname_chain":  chain,
    })

# ─── DNS LOOKUP ──────────────────────────────────────────────────────────────
@app.route("/api/dns", methods=["POST"])
def api_dns():
    data   = request.json or {}
    host   = data.get("host", "").strip()
    rtype  = data.get("type", "A").strip().upper()

    ALLOWED_TYPES = {"A","AAAA","CNAME","MX","TXT","NS","SOA","PTR","ANY","SRV"}
    if rtype not in ALLOWED_TYPES:
        return jsonify({"error": f"Unsupported record type: {rtype}"}), 400
    if not host:
        return jsonify({"error": "host required"}), 400

    try:
        if rtype == "ANY":
            records = []
            for t in ["A","AAAA","CNAME","MX","NS","TXT"]:
                try:
                    ans = resolver.resolve(host, t)
                    records += [f"[{t}] {str(r)}" for r in ans]
                except:
                    pass
            return jsonify({"records": records or ["No records found"]})

        ans = resolver.resolve(host, rtype)
        records = []
        for r in ans:
            if rtype == "MX":
                records.append(f"{r.preference} {str(r.exchange).rstrip('.')}")
            elif rtype in ("CNAME", "NS"):
                records.append(str(r.target).rstrip("."))
            elif rtype == "TXT":
                records.append(" ".join(s.decode() for s in r.strings))
            else:
                records.append(str(r))
        return jsonify({"records": records})

    except dns.resolver.NXDOMAIN:
        return jsonify({"records": [], "error": "NXDOMAIN — host does not exist"})
    except dns.resolver.NoAnswer:
        return jsonify({"records": [], "error": f"No {rtype} records found"})
    except dns.exception.Timeout:
        return jsonify({"records": [], "error": "DNS query timed out"})
    except Exception as e:
        return jsonify({"records": [], "error": str(e)})


# ─── INDEX ───────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=False, port=5000, threaded=True)