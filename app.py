#!/usr/bin/env python3
"""
TAKEOVER.HUNTER V2 — Formal Edition
Subdomain Takeover Scanner
Clean, stable, production-ready for bug bounty use.
"""

import subprocess
import json
import time
import threading
import queue
import re
import os
import shutil
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, render_template, request, jsonify, Response, stream_with_context
import dns.resolver
import dns.exception
import requests
import urllib3
from shlex import quote

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# Professional random User-Agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
]

def cmd_exists(name):
    return shutil.which(name) is not None

# ─── FINGERPRINTS ────────────────────────────────────────────────────────────
FINGERPRINTS = [
    {"provider": "Heroku", "patterns": ["herokuapp.com"], "takeover": True, "claimable": True, "free_account": True, "status_match": "No such app"},
    {"provider": "GitHub Pages", "patterns": ["github.io", "githubusercontent.com"], "takeover": True, "claimable": True, "free_account": True, "status_match": "There isn't a GitHub Pages site"},
    {"provider": "AWS S3", "patterns": ["s3.amazonaws.com", "s3-website"], "takeover": True, "claimable": True, "free_account": False, "status_match": "NoSuchBucket"},
    {"provider": "AWS CloudFront", "patterns": ["cloudfront.net"], "takeover": True, "claimable": True, "free_account": False, "status_match": "Bad Request"},
    {"provider": "AWS ELB", "patterns": ["elb.amazonaws.com"], "takeover": True, "claimable": False, "free_account": False, "status_match": ""},
    {"provider": "Azure TM", "patterns": ["trafficmanager.net"], "takeover": True, "claimable": True, "free_account": True, "status_match": ""},
    {"provider": "Azure Web", "patterns": ["azurewebsites.net", "cloudapp.net"], "takeover": True, "claimable": True, "free_account": True, "status_match": "404 Web Site not found"},
    {"provider": "Fastly", "patterns": ["fastly.net"], "takeover": True, "claimable": True, "free_account": False, "status_match": "Fastly error: unknown domain"},
    {"provider": "Netlify", "patterns": ["netlify.app", "netlify.com"], "takeover": True, "claimable": True, "free_account": True, "status_match": "Not Found"},
    {"provider": "Vercel", "patterns": ["vercel.app", "now.sh"], "takeover": True, "claimable": True, "free_account": True, "status_match": "The deployment could not be found"},
    {"provider": "Webflow", "patterns": ["proxy.webflow.com", "webflow.io"], "takeover": True, "claimable": True, "free_account": False, "status_match": "The page you are looking for does not exist"},
    {"provider": "Pantheon", "patterns": ["pantheonsite.io"], "takeover": True, "claimable": True, "free_account": False, "status_match": "404 error unknown site"},
    {"provider": "Ghost", "patterns": ["ghost.io"], "takeover": True, "claimable": True, "free_account": False, "status_match": "The thing you were looking for is no longer here"},
    {"provider": "Shopify", "patterns": ["myshopify.com"], "takeover": True, "claimable": True, "free_account": False, "status_match": "Sorry, this shop is currently unavailable"},
    {"provider": "Tumblr", "patterns": ["tumblr.com"], "takeover": True, "claimable": True, "free_account": True, "status_match": "There's nothing here"},
    {"provider": "WordPress", "patterns": ["wordpress.com"], "takeover": True, "claimable": True, "free_account": True, "status_match": "Do you want to register"},
    {"provider": "Zendesk", "patterns": ["zendesk.com"], "takeover": True, "claimable": True, "free_account": False, "status_match": "Help Center Closed"},
    {"provider": "Bitbucket", "patterns": ["bitbucket.io"], "takeover": True, "claimable": True, "free_account": True, "status_match": "Repository not found"},
    {"provider": "Seismic", "patterns": ["seismic.com", "tenant-services"], "takeover": True, "claimable": False, "free_account": False, "status_match": "The page you are looking for does not exist"},
    {"provider": "Marketo", "patterns": ["mktoweb.com", "marketo.com"], "takeover": True, "claimable": True, "free_account": False, "status_match": ""},
]

JS_SECRET_PATTERNS = [
    (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9\-_]{16,})["\']', "API Key"),
    (r'(?i)(secret|token|auth)\s*[=:]\s*["\']([A-Za-z0-9\-_]{16,})["\']', "Secret/Token"),
    (r'(?i)(aws_access_key_id)\s*[=:]\s*["\']([A-Z0-9]{20})["\']', "AWS Access Key"),
    (r'(?i)(aws_secret)\s*[=:]\s*["\']([A-Za-z0-9/+=]{40})["\']', "AWS Secret"),
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^\s"\']{8,})["\']', "Password"),
    (r'Bearer\s+([A-Za-z0-9\-_\.]{20,})', "Bearer Token"),
]

# ─── DNS SETUP ───────────────────────────────────────────────────────────────
resolver = dns.resolver.Resolver()
resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
resolver.timeout = 2
resolver.lifetime = 4

def is_wildcard(domain):
    try:
        test = f"takeover-test-{int(time.time())}.{domain}"
        resolver.resolve(test, "A")
        return True
    except:
        return False

def resolve_cname_chain(subdomain):
    chain, curr = [], subdomain
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
        return [str(r) for r in resolver.resolve(host, "A")]
    except:
        return []

def resolve_cname(host):
    try:
        return str(resolver.resolve(host, "CNAME")[0].target).rstrip(".")
    except:
        return None

def match_fingerprint(cname_target):
    for fp in FINGERPRINTS:
        if any(p in cname_target.lower() for p in fp["patterns"]):
            return fp
    return None

# ─── HTTP PROBE (safe + jitter + random UA) ──────────────────────────────────
def http_probe(subdomain):
    time.sleep(random.uniform(0.4, 1.1))
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    for scheme in ["https", "http"]:
        try:
            r = requests.head(f"{scheme}://{subdomain}", timeout=4, verify=False,
                              allow_redirects=True, headers=headers)
            if r.status_code in (0, 404, 502, 503):
                r = requests.get(f"{scheme}://{subdomain}", timeout=4, verify=False,
                                 allow_redirects=True, headers=headers)
            return {"code": r.status_code, "body": r.text[:1500], "headers": dict(r.headers)}
        except:
            continue
    return {"code": 0, "body": "", "headers": {}}

# ─── SAFE TOOL RUNNER ────────────────────────────────────────────────────────
def _run_tool(cmd, label, q):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=180)
        lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        q.put(("tool_done", label, lines, None))
    except Exception as e:
        q.put(("tool_done", label, [], str(e)[:150]))

# ─── ENUMERATION ─────────────────────────────────────────────────────────────
def enumerate_subdomains_stream(target, q):
    collected = set()
    wildcard = is_wildcard(target)
    if wildcard:
        q.put(("log", "warn", "⚠ Wildcard DNS detected — expect false positives."))
    
    tool_q = queue.Queue()
    tools = []
    safe_target = quote(target)

    if cmd_exists("subfinder"):
        tools.append(threading.Thread(target=_run_tool, args=(f"subfinder -d {safe_target} -silent -all", "subfinder", tool_q)))
    if cmd_exists("assetfinder"):
        tools.append(threading.Thread(target=_run_tool, args=(f"assetfinder --subs-only {safe_target}", "assetfinder", tool_q)))
    if cmd_exists("amass"):
        tools.append(threading.Thread(target=_run_tool, args=(f"amass enum -passive -d {safe_target} -timeout 60", "amass", tool_q)))
    if cmd_exists("gau"):
        tools.append(threading.Thread(target=_run_tool, args=(f"gau --subs {safe_target} 2>/dev/null | grep -oE 'https?://[^/]+' | sort -u", "gau", tool_q)))
    if cmd_exists("waybackurls"):
        tools.append(threading.Thread(target=_run_tool, args=(f"echo {safe_target} | waybackurls 2>/dev/null | grep -oE 'https?://[^/]+' | sort -u", "waybackurls", tool_q)))

    if not tools:
        q.put(("log", "warn", "⚠ No enumeration tools found. Install recommended tools."))

    for t in tools:
        t.daemon = True
        t.start()

    for _ in range(len(tools)):
        try:
            _, label, lines, err = tool_q.get(timeout=200)
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

# ─── DNS TRIAGE ──────────────────────────────────────────────────────────────
def dnsx_resolve_bulk(subdomains):
    if not cmd_exists("dnsx"):
        return {}
    try:
        inp = "\n".join(subdomains)
        result = subprocess.run(["dnsx", "-silent", "-cname", "-resp", "-json"], input=inp, capture_output=True, text=True, timeout=120)
        out = {}
        for line in result.stdout.splitlines():
            try:
                d = json.loads(line)
                host = d.get("host", "")
                cnames = d.get("cname", [])
                if host and cnames:
                    out[host] = cnames[0].rstrip(".")
            except:
                pass
        return out
    except:
        return {}

def triage_worker(subdomains, q):
    cnames, dead, a_records = [], [], []
    total = len(subdomains)
    q.put(("log", "info", f"Running DNS triage on {total} subdomains"))
    bulk_cnames = dnsx_resolve_bulk(subdomains)
    for i, sub in enumerate(subdomains):
        q.put(("progress", i + 1, total))
        cname = bulk_cnames.get(sub) or resolve_cname(sub)
        if cname:
            fp = match_fingerprint(cname)
            cnames.append({
                "sub": sub, "cname": cname,
                "provider": fp["provider"] if fp else "Unknown",
                "takeover_possible": fp["takeover"] if fp else False,
                "claimable": fp.get("claimable", False) if fp else False,
                "free_account": fp.get("free_account", False) if fp else False,
            })
            continue
        ips = resolve_a(sub)
        if ips:
            a_records.append({"sub": sub, "ips": ips})
        else:
            dead.append({"sub": sub})
    q.put(("triage_done", cnames, dead, a_records))

# ─── VULN SCAN ───────────────────────────────────────────────────────────────
def vuln_scan_worker_parallel(cname_records, q, max_workers=30):
    total = len(cname_records)
    vulnerable = []
    semaphore = threading.Semaphore(35)

    def check_one(rec):
        with semaphore:
            sub = rec["sub"]
            chain = resolve_cname_chain(sub)
            target = chain[-1] if chain else rec.get("cname", "")
            nx = check_nxdomain(target)
            probe = http_probe(sub)
            fp = match_fingerprint(target)
            is_v = conf = False
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
            elif fp and fp.get("takeover") and probe["code"] in [0, 404]:
                is_v = True
                conf = "medium"
            if is_v:
                sev = "Critical" if any(x in sub for x in ["auth","login","api","sso","account","id","pay","wallet"]) else "High"
                result = {
                    "sub": sub, "cname": target,
                    "provider": fp["provider"] if fp else "Orphaned",
                    "claimable": fp.get("claimable", False) if fp else False,
                    "free_account": fp.get("free_account", False) if fp else False,
                    "nxdomain": nx, "http_code": probe["code"],
                    "body_match": body_match, "match_string": match_string,
                    "vulnerable": True, "confidence": conf, "severity": sev,
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
            except:
                pass
    q.put(("scan_done", vulnerable))

# ─── JS RECON (parallel liveness) ────────────────────────────────────────────
def _probe_live_fast(sub):
    time.sleep(random.uniform(0.3, 0.8))
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    for scheme in ["https", "http"]:
        try:
            r = requests.head(f"{scheme}://{sub}", timeout=3, verify=False, allow_redirects=True, headers=headers)
            if r.status_code not in [0, 502, 503, 504]:
                return True
        except:
            continue
    return False

def js_recon_worker(target, subdomains, q):
    if not subdomains:
        q.put(("js_done", {"js_urls": [], "js_count": 0, "secrets": [], "scanned": 0}))
        return

    q.put(("log", "info", f"JS Recon: probing liveness for {len(subdomains)} subdomains..."))
    live_subs = []
    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(_probe_live_fast, s): s for s in subdomains[:50]}
        for fut in as_completed(futures):
            if fut.result():
                live_subs.append(futures[fut])

    q.put(("log", "ok", f"Live subdomains: {len(live_subs)}"))

    js_urls = set()
    secrets_found = []

    # Katana
    if cmd_exists("katana") and live_subs:
        q.put(("log", "info", f"katana: crawling {min(10, len(live_subs))} live hosts..."))
        try:
            inp = "\n".join([f"https://{s}" for s in live_subs[:10]])
            result = subprocess.run(["katana", "-silent", "-jc", "-d", "2", "-f", "endpoint", "-list", "-"],
                                    input=inp, capture_output=True, text=True, timeout=90)
            for line in result.stdout.splitlines():
                if ".js" in line.lower() and line.strip():
                    js_urls.add(line.strip())
        except Exception as e:
            q.put(("log", "err", f"katana: {str(e)[:60]}"))

    # waybackurls + gau (safe)
    for tool in ["waybackurls", "gau"]:
        if cmd_exists(tool):
            q.put(("log", "info", f"{tool}: mining archives..."))
            try:
                cmd_str = f"echo {quote(target)} | {tool} 2>/dev/null | grep '\\.js' | sort -u" if tool == "waybackurls" else f"{tool} {quote(target)} 2>/dev/null | grep '\\.js' | sort -u"
                result = subprocess.run(cmd_str, shell=True, capture_output=True, text=True, timeout=60)
                for line in result.stdout.splitlines():
                    if line.strip():
                        js_urls.add(line.strip())
            except:
                pass

    q.put(("log", "ok", f"Total JS files found: {len(js_urls)}"))
    q.put(("log", "info", "Scanning up to 50 JS files for secrets..."))

    scanned = 0
    for url in list(js_urls)[:50]:
        try:
            r = requests.get(url, timeout=5, verify=False, headers={"User-Agent": random.choice(USER_AGENTS)})
            if r.status_code == 200:
                content = r.text
                for pattern, label in JS_SECRET_PATTERNS:
                    matches = re.findall(pattern, content)
                    for match in matches:
                        val = match[-1] if isinstance(match, tuple) else match
                        if len(val) > 8:
                            entry = {"url": url, "type": label, "value": val[:40] + "..."}
                            secrets_found.append(entry)
                            q.put(("secret", entry))
            scanned += 1
        except:
            pass

    q.put(("js_done", {
        "js_urls": list(js_urls)[:100],
        "js_count": len(js_urls),
        "secrets": secrets_found,
        "scanned": scanned
    }))

# ─── ARCHIVE RECON ───────────────────────────────────────────────────────────
def archive_recon_worker(target, q):
    urls = set()
    safe_target = quote(target)
    for tool in ["gau", "waybackurls"]:
        if cmd_exists(tool):
            q.put(("log", "info", f"{tool}: mining archives..."))
            try:
                cmd_str = f"{tool} --subs {safe_target} 2>/dev/null | sort -u" if tool == "gau" else f"echo {safe_target} | {tool} 2>/dev/null | sort -u"
                result = subprocess.run(cmd_str, shell=True, capture_output=True, text=True, timeout=120)
                for l in result.stdout.splitlines():
                    if l.strip():
                        urls.add(l.strip())
            except:
                pass

    params = [u for u in urls if "=" in u]
    admin = [u for u in urls if any(x in u.lower() for x in ["admin","login","dashboard","panel","auth","api"])]
    js_files = [u for u in urls if ".js" in u.lower()]
    interesting = [u for u in urls if any(x in u.lower() for x in ["config","backup","env","secret","key","token",".git",".env"])]

    q.put(("archive_done", {
        "total": len(urls),
        "params": params[:200],
        "admin": admin[:100],
        "js": js_files[:100],
        "interesting": interesting[:100],
    }))

# ─── VERIFY ──────────────────────────────────────────────────────────────────
def verify_worker(vulnerable_list, q):
    verified_results = []
    for vuln in vulnerable_list:
        sub, cname = vuln["sub"], vuln["cname"]
        q.put(("log", "info", f"Verifying {sub}..."))
        nx1 = check_nxdomain(cname)
        time.sleep(0.3)
        nx2 = check_nxdomain(cname)
        probe = http_probe(sub)
        live_cname = resolve_cname(sub)
        cname_still_present = live_cname is not None and cname.lower() in live_cname.lower()
        confirmed = nx1 and nx2 and cname_still_present
        result = {**vuln, "verified": confirmed, "verify_nxdomain_1": nx1,
                  "verify_nxdomain_2": nx2, "verify_http": probe["code"],
                  "cname_still_present": cname_still_present}
        verified_results.append(result)
        q.put(("verified", result))
    q.put(("verify_done", verified_results))

# ─── REPORT ──────────────────────────────────────────────────────────────────
@app.route("/api/report", methods=["POST"])
def api_report():
    f = request.json.get("finding", {})
    user = request.json.get("h1_user", "researcher")
    report = f"""# Subdomain Takeover: {f.get('sub')}
## Summary
`{f.get('sub')}` points to an unclaimed `{f.get('provider')}` resource.
## Severity
**{f.get('severity')}** — Confidence: {f.get('confidence', 'high').upper()}
## Steps To Reproduce
1. dig {f.get('sub')} CNAME
2. dig {f.get('cname')}
3. curl -I https://{f.get('sub')}
## Impact
Full subdomain takeover possible.
## Remediation
Remove the dangling CNAME record.
"""
    return jsonify({"report": report})

# ─── QUICK SCAN ──────────────────────────────────────────────────────────────
@app.route("/api/quickscan", methods=["POST"])
def api_quickscan():
    data = request.json or {}
    sub = data.get("sub", "").strip()
    cname = data.get("cname", "").strip()
    if not cname:
        return jsonify({"error": "cname required"}), 400
    chain = resolve_cname_chain(sub) if sub else []
    target = chain[-1] if chain else cname
    nx = check_nxdomain(target)
    probe = http_probe(sub if sub else cname)
    fp = match_fingerprint(target)
    is_v = False
    conf = "low"
    if nx:
        is_v = True
        conf = "high"
    elif fp and fp.get("status_match") and fp["status_match"].lower() in probe["body"].lower():
        is_v = True
        conf = "high"
    elif fp and fp.get("takeover") and probe["code"] in [0, 404]:
        is_v = True
        conf = "medium"
    sev = "Critical" if any(x in (sub or cname) for x in ["auth","login","api","sso","account","id","pay"]) else "High"
    return jsonify({
        "sub": sub or cname, "cname": target,
        "provider": fp["provider"] if fp else "Unknown",
        "claimable": fp.get("claimable", False) if fp else False,
        "free_account": fp.get("free_account", False) if fp else False,
        "nxdomain": nx, "http_code": probe["code"],
        "confidence": conf, "severity": sev, "vulnerable": is_v,
    })

# ─── API ROUTES ──────────────────────────────────────────────────────────────
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
                yield f"event: log\ndata: {json.dumps({'level': msg[1], 'msg': msg[2]})}\n\n"
            elif msg[0] == "enum_done":
                yield f"event: done\ndata: {json.dumps({'subdomains': msg[1], 'count': msg[2]})}\n\n"
                break
    return Response(stream_with_context(gen()), content_type="text/event-stream")

@app.route("/api/triage", methods=["POST"])
def api_triage():
    subdomains = request.json.get("subdomains", [])
    if not subdomains:
        return Response(stream_with_context("event: done\ndata: {}\n\n"), content_type="text/event-stream")
    q = queue.Queue()
    threading.Thread(target=triage_worker, args=(subdomains, q), daemon=True).start()
    def gen():
        while True:
            msg = q.get()
            if msg[0] == "progress":
                yield f"event: progress\ndata: {json.dumps({'done': msg[1], 'total': msg[2]})}\n\n"
            elif msg[0] == "log":
                yield f"event: log\ndata: {json.dumps({'level': msg[1], 'msg': msg[2]})}\n\n"
            elif msg[0] == "triage_done":
                yield f"event: done\ndata: {json.dumps({'cname': msg[1], 'dead': msg[2], 'a': msg[3]})}\n\n"
                break
    return Response(stream_with_context(gen()), content_type="text/event-stream")

@app.route("/api/scan", methods=["POST"])
def api_scan():
    recs = request.json.get("cname_records", [])
    if not recs:
        return Response(stream_with_context("event: done\ndata: {\"count\":0}\n\n"), content_type="text/event-stream")
    q = queue.Queue()
    threading.Thread(target=vuln_scan_worker_parallel, args=(recs, q), daemon=True).start()
    def gen():
        while True:
            msg = q.get()
            if msg[0] == "progress":
                yield f"event: progress\ndata: {json.dumps({'done': msg[1], 'total': msg[2]})}\n\n"
            elif msg[0] == "vuln":
                yield f"event: vuln\ndata: {json.dumps(msg[1])}\n\n"
            elif msg[0] == "scan_done":
                yield f"event: done\ndata: {json.dumps({'count': len(msg[1]), 'vulnerable': msg[1]})}\n\n"
                break
    return Response(stream_with_context(gen()), content_type="text/event-stream")

@app.route("/api/jsrecon", methods=["POST"])
def api_jsrecon():
    target = request.json.get("target", "").strip()
    subdomains = request.json.get("subdomains", [])
    if not target:
        return jsonify({"error": "target required"}), 400
    q = queue.Queue()
    threading.Thread(target=js_recon_worker, args=(target, subdomains, q), daemon=True).start()
    def gen():
        while True:
            msg = q.get()
            if msg[0] == "log":
                yield f"event: log\ndata: {json.dumps({'level': msg[1], 'msg': msg[2]})}\n\n"
            elif msg[0] == "secret":
                yield f"event: secret\ndata: {json.dumps(msg[1])}\n\n"
            elif msg[0] == "js_done":
                yield f"event: done\ndata: {json.dumps(msg[1])}\n\n"
                break
    return Response(stream_with_context(gen()), content_type="text/event-stream")

@app.route("/api/archive", methods=["POST"])
def api_archive():
    target = request.json.get("target", "").strip()
    if not target:
        return jsonify({"error": "target required"}), 400
    q = queue.Queue()
    threading.Thread(target=archive_recon_worker, args=(target, q), daemon=True).start()
    def gen():
        while True:
            msg = q.get()
            if msg[0] == "log":
                yield f"event: log\ndata: {json.dumps({'level': msg[1], 'msg': msg[2]})}\n\n"
            elif msg[0] == "archive_done":
                yield f"event: done\ndata: {json.dumps(msg[1])}\n\n"
                break
    return Response(stream_with_context(gen()), content_type="text/event-stream")

@app.route("/api/verify", methods=["POST"])
def api_verify():
    vulnerable_list = request.json.get("vulnerable", [])
    q = queue.Queue()
    threading.Thread(target=verify_worker, args=(vulnerable_list, q), daemon=True).start()
    def gen():
        while True:
            msg = q.get()
            if msg[0] == "log":
                yield f"event: log\ndata: {json.dumps({'level': msg[1], 'msg': msg[2]})}\n\n"
            elif msg[0] == "verified":
                yield f"event: verified\ndata: {json.dumps(msg[1])}\n\n"
            elif msg[0] == "verify_done":
                yield f"event: done\ndata: {json.dumps({'verified': msg[1]})}\n\n"
                break
    return Response(stream_with_context(gen()), content_type="text/event-stream")

@app.route("/api/tools")
def api_tools():
    tools = ["subfinder","assetfinder","amass","dnsx","httpx","katana","gau","waybackurls"]
    return jsonify({t: cmd_exists(t) for t in tools})

@app.route("/")
def index():
    return render_template("index.html")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="127.0.0.1", port=port, threaded=True)
