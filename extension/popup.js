const BACKEND = "http://127.0.0.1:5000/predict";

async function getCurrentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function scanURL(url) {
  const res = await fetch(BACKEND, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url })
  });
  return await res.json();
}

function displayResult(data) {
  const isPhish = data.prediction === 1;
  const box     = document.getElementById("verdict-box");
  const title   = document.getElementById("verdict-title");
  const conf    = document.getElementById("verdict-conf");
  const bar     = document.getElementById("conf-bar");

  box.className  = "verdict " + (isPhish ? "phishing" : "legit");
  title.textContent = isPhish ? "⚠ PHISHING DETECTED" : "✓ LEGITIMATE";
  conf.textContent  = "ML Confidence: " + data.confidence + "%";
  setTimeout(() => { bar.style.width = data.confidence + "%"; }, 100);

  // VirusTotal
  if (data.vt && !data.vt.error) {
    document.getElementById("vt-section").style.display = "block";
    const vtBox = document.getElementById("vt-box");
    const isBad = data.vt.malicious > 0;
    vtBox.className   = "vt-box " + (isBad ? "vt-malicious" : "vt-clean");
    vtBox.textContent = isBad
      ? "🔴 " + data.vt.malicious + "/" + data.vt.total + " engines flagged"
      : "🟢 Clean — 0/" + data.vt.total + " engines flagged";
  }

  // Flags
  if (data.flags && data.flags.length > 0) {
    document.getElementById("flags-section").style.display = "block";
    const flagsEl = document.getElementById("flags-list");
    flagsEl.innerHTML = "";
    data.flags.slice(0, 4).forEach(function(f) {
      const d = document.createElement("div");
      d.className   = "flag " + (f[0] === "HIGH" ? "high" : "warn");
      d.textContent = (f[0] === "HIGH" ? "🔴 " : "🟡 ") + f[1];
      flagsEl.appendChild(d);
    });
  }
}

function showOffline() {
  const box   = document.getElementById("verdict-box");
  const title = document.getElementById("verdict-title");
  const conf  = document.getElementById("verdict-conf");
  box.className     = "verdict offline";
  title.textContent = "⚡ Backend Offline";
  conf.textContent  = "Run: python app.py";
}

function showScanning() {
  const box   = document.getElementById("verdict-box");
  const title = document.getElementById("verdict-title");
  const conf  = document.getElementById("verdict-conf");
  box.className     = "verdict scanning";
  title.textContent = "⟳ Scanning...";
  conf.textContent  = "";
}

async function rescan() {
  const btn = document.getElementById("rescan-btn");
  btn.disabled    = true;
  btn.textContent = "Scanning...";
  showScanning();

  const tab = await getCurrentTab();
  document.getElementById("current-url").textContent = tab.url;

  try {
    const data = await scanURL(tab.url);
    displayResult(data);
  } catch (e) {
    showOffline();
  } finally {
    btn.disabled    = false;
    btn.textContent = "↺ Rescan This Page";
  }
}

function openDashboard() {
  chrome.tabs.query({}, function(tabs) {
    const existing = tabs.find(t => t.url && t.url.includes("127.0.0.1:5000"));
    if (existing) {
      chrome.tabs.update(existing.id, { active: true });
      chrome.windows.update(existing.windowId, { focused: true });
    } else {
      chrome.tabs.create({ url: "http://127.0.0.1:5000/", active: true });
    }
  });
}

async function init() {
  const tab = await getCurrentTab();
  document.getElementById("current-url").textContent = tab.url;
  showScanning();

  chrome.storage.local.get([tab.url], async function(result) {
    if (result[tab.url]) {
      displayResult(result[tab.url]);
    } else {
      try {
        const data = await scanURL(tab.url);
        displayResult(data);
      } catch (e) {
        showOffline();
      }
    }
  });
}

// Attach event listeners here instead of onclick in HTML
document.getElementById("rescan-btn").addEventListener("click", rescan);
document.getElementById("dashboard-btn").addEventListener("click", openDashboard);

init();