const history = [];
let lastScanData = null;

document.addEventListener("DOMContentLoaded", function() {
  document.getElementById("scan-btn").addEventListener("click", scanURL);
  document.getElementById("url-input").addEventListener("keydown", function(e) {
    if (e.key === "Enter") scanURL();
  });
  document.getElementById("report-btn").addEventListener("click", downloadPDF);
});

async function scanURL() {
  const url = document.getElementById("url-input").value.trim();
  if (!url) return;
  const btn = document.getElementById("scan-btn");
  btn.disabled = true;
  document.getElementById("loading").style.display = "block";
  document.getElementById("result-card").style.display = "none";
  document.getElementById("report-section").style.display = "none";

  try {
    const res  = await fetch("/predict", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({url: url})
    });
    const data = await res.json();
    if (data.error) { alert("Error: " + data.error); return; }

    lastScanData = {
      url        : url,
      prediction : data.prediction,
      confidence : data.confidence,
      flags      : data.flags,
      vt         : data.vt,
      features   : data.features
    };

    displayResult(url, data);
    addHistory(url, data);

  } catch(e) {
    alert("Connection error: " + e.message);
  } finally {
    btn.disabled = false;
    document.getElementById("loading").style.display = "none";
  }
}

function displayResult(url, data) {
  const isPhish = data.prediction === 1;
  const box     = document.getElementById("verdict-box");
  box.className = "verdict " + (isPhish ? "phishing" : "legit");
  document.getElementById("verdict-title").textContent = isPhish ? "PHISHING DETECTED" : "LEGITIMATE";
  document.getElementById("verdict-conf").textContent  = "ML Confidence: " + data.confidence + "%";
  setTimeout(function() {
    document.getElementById("conf-bar").style.width = data.confidence + "%";
  }, 100);

  // VirusTotal
  const vt    = data.vt;
  const vtBox = document.getElementById("vt-box");
  if (vt.error) {
    vtBox.innerHTML = '<div class="vt-box vt-error"><div class="vt-title">VIRUSTOTAL</div><span style="color:#4a7a9b;font-size:0.85rem">Could not reach VirusTotal: ' + vt.error + '</span></div>';
  } else {
    const isMal  = vt.verdict === "MALICIOUS";
    const cls    = isMal ? "vt-malicious" : "vt-clean";
    const status = isMal ? "MALICIOUS" : vt.verdict === "SUSPICIOUS" ? "SUSPICIOUS" : "CLEAN";
    vtBox.innerHTML =
      '<div class="vt-box ' + cls + '">' +
        '<div class="vt-title">VIRUSTOTAL — ' + status + ' (' + vt.malicious + '/' + vt.total + ' engines flagged)</div>' +
        '<div class="vt-stats">' +
          '<div><span style="color:#4a7a9b">Malicious: </span><span style="color:#ff4444">' + vt.malicious + '</span></div>' +
          '<div><span style="color:#4a7a9b">Suspicious: </span><span style="color:#ffaa00">' + vt.suspicious + '</span></div>' +
          '<div><span style="color:#4a7a9b">Harmless: </span><span style="color:#00cc66">' + vt.harmless + '</span></div>' +
          '<div><span style="color:#4a7a9b">Undetected: </span><span style="color:#8aabcc">' + vt.undetected + '</span></div>' +
        '</div>' +
      '</div>';
  }

  // Flags
  const flagsEl = document.getElementById("flags-list");
  flagsEl.innerHTML = "";
  if (!data.flags || data.flags.length === 0) {
    flagsEl.innerHTML = '<div class="no-flags">No suspicious signals detected</div>';
  } else {
    data.flags.forEach(function(f) {
      const d = document.createElement("div");
      d.className   = "flag " + (f[0] === "HIGH" ? "high" : "warn");
      d.textContent = (f[0] === "HIGH" ? "[HIGH] " : "[WARN] ") + f[1];
      flagsEl.appendChild(d);
    });
  }

  // Features
  const featsEl = document.getElementById("features-grid");
  featsEl.innerHTML = "";
  const show = [
    ["Protocol",    data.features.HTTPS === 1 ? "HTTPS" : "HTTP"],
    ["Has IP",      data.features.UsingIP === 1 ? "Yes" : "No"],
    ["Long URL",    data.features.LongURL === 1 ? "Yes" : "No"],
    ["Subdomains",  String(data.features.SubDomains)],
    ["At Symbol",   data.features["Symbol@"] === 1 ? "Yes" : "No"],
    ["Redirecting", data.features["Redirecting//"] === 1 ? "Yes" : "No"],
  ];
  show.forEach(function(item) {
    featsEl.innerHTML +=
      '<div class="feat">' +
        '<div class="feat-label">' + item[0] + '</div>' +
        '<div class="feat-value">' + item[1] + '</div>' +
      '</div>';
  });

  document.getElementById("result-card").style.display    = "block";
  document.getElementById("report-section").style.display = "block";
}

function addHistory(url, data) {
  history.unshift({url: url, data: data});
  const card = document.getElementById("history-card");
  const list = document.getElementById("history-list");
  card.style.display = "block";
  list.innerHTML = "";
  history.slice(0, 8).forEach(function(item) {
    const isPhish = item.data.prediction === 1;
    const short   = item.url.length > 45 ? item.url.slice(0, 45) + "..." : item.url;
    list.innerHTML +=
      '<div class="history-item">' +
        '<span style="color:#8aabcc">' + short + '</span>' +
        '<span class="tag ' + (isPhish ? "phishing" : "legit") + '">' + (isPhish ? "PHISHING" : "LEGIT") + '</span>' +
      '</div>';
  });
}

async function downloadPDF() {
  if (!lastScanData) return;
  const btn = document.getElementById("report-btn");
  btn.disabled    = true;
  btn.textContent = "Generating PDF...";
  try {
    const res  = await fetch("/generate-report", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(lastScanData)
    });
    const data = await res.json();
    if (data.error) { alert("PDF Error: " + data.error); return; }
    const filename = data.path.split("\\").pop().split("/").pop();
    window.location.href = "/download-report/" + filename;
  } catch(e) {
    alert("Error: " + e.message);
  } finally {
    btn.disabled    = false;
    btn.textContent = "Download PDF Report";
  }
}