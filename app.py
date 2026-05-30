"""
Phishing Detector - Flask Web App v2.0
Real dataset (11,054 URLs) + VirusTotal API + Bulk Scanner
"""

from flask import Flask, request, jsonify, render_template_string, render_template
import pickle, os, json
import requests as req
from datetime import datetime

app = Flask(__name__)

import os
VT_API_KEY = os.environ.get("VT_API_KEY", "")
# Load model + metadata
with open("models/phishing_model.pkl", "rb") as f:
    model = pickle.load(f)

with open("models/metadata.json") as f:
    metadata = json.load(f)

FEATURE_COLS = metadata["features"]

# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def predict_from_features(features: dict):
    vector = [features.get(col, 0) for col in FEATURE_COLS]
    pred   = int(model.predict([vector])[0])
    proba  = model.predict_proba([vector])[0]
    return pred, round(float(proba[pred]) * 100, 2)

def map_features(raw: dict) -> dict:
    return {
        "UsingIP"            : raw["has_ip"],
        "LongURL"            : 1 if raw["url_length"] > 75 else 0,
        "ShortURL"           : 1 if raw["url_length"] < 20 else 0,
        "Symbol@"            : raw["has_at_symbol"],
        "Redirecting//"      : raw["has_double_slash"],
        "PrefixSuffix-"      : 1 if raw["hyphen_count"] > 0 else 0,
        "SubDomains"         : raw["subdomain_count"],
        "HTTPS"              : raw["is_https"],
        "DomainRegLen"       : 1 if raw["domain_length"] > 10 else -1,
        "Favicon"            : 0,
        "NonStdPort"         : 0,
        "HTTPSDomainURL"     : 1 if raw["is_https"] == 0 else -1,
        "RequestURL"         : 1 if raw["phishing_keywords"] > 2 else -1,
        "AnchorURL"          : 0,
        "LinksInScriptTags"  : 0,
        "ServerFormHandler"  : 0,
        "InfoEmail"          : 0,
        "AbnormalURL"        : 1 if raw["brand_in_domain"] else -1,
        "WebsiteForwarding"  : 0,
        "StatusBarCust"      : 0,
        "DisableRightClick"  : 0,
        "UsingPopupWindow"   : 0,
        "IframeRedirection"  : 0,
        "AgeofDomain"        : 1 if raw["suspicious_tld"] else -1,
        "DNSRecording"       : 1 if raw["domain_entropy"] < 3 else -1,
        "WebsiteTraffic"     : 1 if raw["brand_in_domain"] == 0 else -1,
        "PageRank"           : 1 if raw["suspicious_tld"] == 0 else -1,
        "GoogleIndex"        : 1 if raw["phishing_keywords"] < 2 else -1,
        "LinksPointingToPage": 1,
        "StatsReport"        : 1 if raw["suspicious_tld"] == 0 else -1,
    }

def apply_override(pred, conf, flags):
    high_flags     = [f for f in flags if f[0] == "HIGH"]
    warn_flags     = [f for f in flags if f[0] == "WARN"]
    override_score = (len(high_flags) * 2) + len(warn_flags)
    if override_score >= 4:
        pred = 1
        conf = max(conf, 85.0)
    elif override_score == 3:
        pred = 1
        conf = max(conf, 75.0)
    elif override_score == 2 and pred == 0 and conf < 75:
        pred = 1
        conf = 70.0
    return pred, conf, high_flags, warn_flags

def virustotal_check(url: str) -> dict:
    try:
        headers = {"x-apikey": VT_API_KEY}
        resp = req.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=10
        )
        if resp.status_code != 200:
            return {"error": f"VT submit failed: {resp.status_code}"}
        scan_id = resp.json()["data"]["id"]
        result  = req.get(
            f"https://www.virustotal.com/api/v3/analyses/{scan_id}",
            headers=headers,
            timeout=10
        )
        if result.status_code != 200:
            return {"error": "VT result fetch failed"}
        stats = result.json()["data"]["attributes"]["stats"]
        return {
            "malicious"  : stats.get("malicious", 0),
            "suspicious" : stats.get("suspicious", 0),
            "harmless"   : stats.get("harmless", 0),
            "undetected" : stats.get("undetected", 0),
            "total"      : sum(stats.values()),
            "verdict"    : "MALICIOUS"  if stats.get("malicious", 0) > 0
                           else "SUSPICIOUS" if stats.get("suspicious", 0) > 2
                           else "CLEAN"
        }
    except Exception as e:
        return {"error": str(e)}

# ─────────────────────────────────────────────
# MAIN HTML
# ─────────────────────────────────────────────

HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Phishing URL Detector</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Courier New',monospace;background:#0a0e1a;color:#c8d8f0;min-height:100vh;padding:2rem 1rem}
.page{max-width:800px;margin:0 auto}
h1{color:#00d4ff;font-size:1.8rem;margin-bottom:0.25rem;text-align:center}
.subtitle{color:#4a7a9b;font-size:0.85rem;margin-bottom:1.5rem;text-align:center}
.nav{display:flex;justify-content:center;gap:8px;margin-bottom:1.5rem}
.nav a{color:#00d4ff;text-decoration:none;font-size:0.85rem;padding:6px 14px;border:1px solid #1e3a5f;border-radius:6px}
.nav a:hover{background:#111827}
.card{background:#111827;border:1px solid #1e3a5f;border-radius:12px;padding:1.5rem;margin-bottom:1rem}
.section-title{font-size:0.75rem;letter-spacing:0.1em;color:#4a7a9b;text-transform:uppercase;margin-bottom:0.75rem}
.input-row{display:flex;gap:8px}
input[type=text]{flex:1;background:#060c18;border:1px solid #1e3a5f;color:#fff;font-family:'Courier New',monospace;font-size:14px;padding:10px 14px;border-radius:8px;outline:none}
input[type=text]:focus{border-color:#00d4ff}
.btn{border:none;border-radius:8px;padding:10px 20px;font-family:'Courier New',monospace;font-weight:bold;cursor:pointer;font-size:14px}
.btn-primary{background:#00d4ff;color:#000}
.btn-primary:hover{opacity:0.85}
.btn-primary:disabled{opacity:0.4;cursor:not-allowed}
.stats-bar{display:grid;grid-template-columns:repeat(4,1fr);gap:0.75rem;margin-bottom:1rem}
.stat{background:#111827;border:1px solid #1e3a5f;border-radius:10px;padding:1rem;text-align:center}
.stat-num{font-size:1.5rem;font-weight:bold;color:#00d4ff}
.stat-lbl{font-size:0.7rem;color:#4a7a9b;margin-top:2px}
.verdict{text-align:center;padding:1.5rem;border-radius:10px;margin-bottom:1rem}
.verdict.phishing{background:#2a0000;border:1px solid #ff4444}
.verdict.legit{background:#001a0d;border:1px solid #00cc66}
.verdict-title{font-size:1.4rem;font-weight:bold;margin-bottom:0.25rem}
.verdict.phishing .verdict-title{color:#ff4444}
.verdict.legit    .verdict-title{color:#00cc66}
.conf-text{font-size:0.85rem;color:#8aabcc;margin-bottom:0.75rem}
.bar-wrap{background:#060c18;border-radius:4px;height:8px;overflow:hidden}
.bar-fill{height:100%;border-radius:4px;transition:width 0.6s ease}
.phishing .bar-fill{background:#ff4444}
.legit    .bar-fill{background:#00cc66}
.vt-box{border-radius:8px;padding:1rem;margin-top:0.75rem}
.vt-clean{background:#001a0d;border:1px solid #00cc66}
.vt-malicious{background:#2a0000;border:1px solid #ff4444}
.vt-error{background:#111827;border:1px solid #1e3a5f}
.vt-title{font-size:0.75rem;letter-spacing:0.1em;color:#4a7a9b;margin-bottom:0.5rem}
.vt-stats{display:flex;gap:1rem;flex-wrap:wrap;font-size:0.85rem}
.flag{display:flex;gap:8px;padding:6px 0;border-bottom:1px solid #0d1a2e;font-size:0.85rem}
.flag:last-child{border-bottom:none}
.flag.high{color:#ff6666}
.flag.warn{color:#ffcc44}
.no-flags{color:#00cc66;font-size:0.85rem}
.features-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:0.5rem}
.feat{background:#060c18;border:1px solid #1e3a5f;border-radius:6px;padding:8px 12px}
.feat-label{font-size:0.7rem;color:#4a7a9b;margin-bottom:2px}
.feat-value{font-size:0.95rem;color:#fff}
.history-item{display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid #0d1a2e;font-size:0.8rem}
.history-item:last-child{border-bottom:none}
.tag{font-size:0.7rem;padding:2px 8px;border-radius:4px;font-weight:bold;white-space:nowrap}
.tag.phishing{background:#2a0000;color:#ff4444;border:1px solid #ff4444}
.tag.legit{background:#001a0d;color:#00cc66;border:1px solid #00cc66}
.tag.malicious{background:#3a0000;color:#ff2222;border:1px solid #ff2222}
.loading{text-align:center;color:#4a7a9b;padding:1rem;display:none}
.result{display:none}
.model-bar-bg{flex:1;background:#060c18;border-radius:3px;height:6px;overflow:hidden}
.model-bar-fill{height:100%;border-radius:4px;background:#00d4ff}
.footer{margin-top:2rem;font-size:0.75rem;color:#1e3a5f;text-align:center}
.spinner{display:inline-block;animation:spin 1s linear infinite}
@keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}
</style>
</head>
<body>
<div class="page">

<h1>⬡ Phishing URL Detector</h1>
<p class="subtitle">ML + VirusTotal — 97.29% accuracy on 11,054 real URLs</p>

<div class="nav">
  <a href="/">Dashboard</a>
  <a href="/bulk">Bulk Scanner</a>
  <a href="/email">Email Scanner</a>
</div>

<div class="stats-bar">
  <div class="stat"><div class="stat-num">{{ meta.accuracy }}%</div><div class="stat-lbl">Model Accuracy</div></div>
  <div class="stat"><div class="stat-num">{{ "{:,}".format(meta.total_samples) }}</div><div class="stat-lbl">Training URLs</div></div>
  <div class="stat"><div class="stat-num">{{ meta.cv_mean }}%</div><div class="stat-lbl">CV Score</div></div>
  <div class="stat"><div class="stat-num">{{ meta.model_name.split()[0] }}</div><div class="stat-lbl">Algorithm</div></div>
</div>

<div class="card">
  <div class="section-title">Scan a URL</div>
  <div class="input-row">
    <input type="text" id="url-input" placeholder="https://example.com" />
    <button class="btn btn-primary" id="scan-btn">▶ SCAN</button>
  </div>
</div>

<div class="loading" id="loading"><span class="spinner">&#10227</span> Analyzing URL + checking VirusTotal...</div>

<div class="result" id="result-card">
  <div class="card">
    <div class="verdict" id="verdict-box">
      <div class="verdict-title" id="verdict-title"></div>
      <div class="conf-text" id="verdict-conf"></div>
      <div class="bar-wrap"><div class="bar-fill" id="conf-bar" style="width:0%"></div></div>
    </div>
    <div id="vt-section">
      <div class="section-title">VirusTotal Intelligence</div>
      <div id="vt-box"></div>
    </div>
  </div>
  <div class="card">
    <div class="section-title">Warning Signals</div>
    <div id="flags-list"></div>
  </div>
  <div class="card">
    <div class="section-title">Feature Analysis</div>
    <div class="features-grid" id="features-grid"></div>
  </div>
</div>

<div class="card" id="history-card" style="display:none">
  <div class="section-title">Scan History</div>
  <div id="history-list"></div>
</div>

<div class="card">
  <div class="section-title">Model Details — Top Features</div>
  {% for feat, score in meta.top_features[:5] %}
  <div style="margin-bottom:8px">
    <div style="display:flex;justify-content:space-between;font-size:0.78rem;margin-bottom:3px">
      <span style="color:#8aabcc">{{ feat }}</span>
      <span style="color:#00d4ff">{{ "%.1f"|format(score*100) }}%</span>
    </div>
    <div class="model-bar-bg">
      <div class="model-bar-fill" style="width:{{ score*100 }}%"></div>
    </div>
  </div>
  {% endfor %}
</div>
<div id="report-section" style="display:none;margin-bottom:1rem">
  <button class="btn btn-primary" id="report-btn" style="width:100%">⬇ Download PDF Report</button>
</div>
<p class="footer">Python · scikit-learn · Flask · VirusTotal API — for security research only</p>
</div>

<script src="/static/main.js"></script>
</body>
</html>
"""

# ─────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(HTML, meta=metadata)

@app.route("/bulk")
def bulk():
    return render_template("bulk.html")

@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json()
        url  = data.get("url", "").strip()
        if not url:
            return jsonify({"error": "No URL provided"})

        from src.feature_extractor import extract_features, explain_features
        raw    = extract_features(url)
        flags  = explain_features(raw)
        mapped = map_features(raw)

        pred, conf = predict_from_features(mapped)
        pred, conf, high_flags, warn_flags = apply_override(pred, conf, flags)

        vt = virustotal_check(url)

        return jsonify({
            "prediction" : pred,
            "confidence" : conf,
            "vt"         : vt,
            "flags"      : flags,
            "features"   : mapped
        })

    except Exception as e:
        return jsonify({"error": str(e)})

@app.route("/bulk-scan", methods=["POST"])
def bulk_scan():
    try:
        data = request.get_json()
        urls = data.get("urls", [])
        if not urls:
            return jsonify({"error": "No URLs provided"})
        if len(urls) > 50:
            return jsonify({"error": "Max 50 URLs at once"})

        from src.feature_extractor import extract_features, explain_features
        results = []
        for url in urls:
            url = url.strip()
            if not url:
                continue
            try:
                raw    = extract_features(url)
                flags  = explain_features(raw)
                mapped = map_features(raw)

                pred, conf = predict_from_features(mapped)
                pred, conf, high_flags, warn_flags = apply_override(pred, conf, flags)

                results.append({
                    "url"        : url,
                    "prediction" : pred,
                    "confidence" : conf,
                    "high_flags" : len(high_flags),
                    "warn_flags" : len(warn_flags),
                    "verdict"    : "PHISHING" if pred == 1 else "LEGITIMATE"
                })
            except Exception as e:
                results.append({
                    "url"        : url,
                    "prediction" : -1,
                    "confidence" : 0,
                    "high_flags" : 0,
                    "warn_flags" : 0,
                    "verdict"    : "ERROR"
                })

        phishing_count = sum(1 for r in results if r["prediction"] == 1)
        legit_count    = sum(1 for r in results if r["prediction"] == 0)

        return jsonify({
            "results"        : results,
            "total"          : len(results),
            "phishing_count" : phishing_count,
            "legit_count"    : legit_count
        })

    except Exception as e:
        return jsonify({"error": str(e)})
@app.route("/generate-report", methods=["POST"])
def generate_report():
    try:
        from reports.pdf_generator import generate_pdf
        data        = request.get_json()
        output_path = generate_pdf(data)
        return jsonify({"success": True, "path": output_path})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route("/download-report/<filename>")
def download_report(filename):
    from flask import send_from_directory
    return send_from_directory("reports", filename, as_attachment=True)
@app.route("/email")
def email_scanner():
    return render_template("email_scanner.html")
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)