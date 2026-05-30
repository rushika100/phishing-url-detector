
// background.js — scans every URL automatically

const BACKEND = "http://127.0.0.1:5000/predict";
const cache   = {};  // cache results so we don't scan same URL twice

async function scanURL(url) {
  // Skip non-http URLs
  if (!url || !url.startsWith("http")) return null;

  // Return cached result if available
  if (cache[url]) return cache[url];

  try {
    const res = await fetch(BACKEND, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });
    const data = await res.json();
    cache[url] = data;
    return data;
  } catch (e) {
    return null;  // backend not running
  }
}

function setBadge(tabId, prediction, confidence) {
  if (prediction === 1) {
    // Red badge — phishing
    chrome.action.setBadgeBackgroundColor({ color: "#ff4444", tabId });
    chrome.action.setBadgeText({ text: "⚠", tabId });
  } else {
    // Green badge — safe
    chrome.action.setBadgeBackgroundColor({ color: "#00cc66", tabId });
    chrome.action.setBadgeText({ text: "✓", tabId });
  }
}

// Scan every tab when it finishes loading
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete") return;
  if (!tab.url || !tab.url.startsWith("http")) return;

  // Set scanning badge
  chrome.action.setBadgeBackgroundColor({ color: "#4a7a9b", tabId });
  chrome.action.setBadgeText({ text: "...", tabId });

  const result = await scanURL(tab.url);
  if (!result || result.error) {
    chrome.action.setBadgeText({ text: "", tabId });
    return;
  }

  setBadge(tabId, result.prediction, result.confidence);

  // Show notification for phishing sites
  if (result.prediction === 1 && result.confidence > 70) {
    chrome.notifications.create({
      type:    "basic",
      iconUrl: "icons/icon48.png",
      title:   "⚠ Phishing Site Detected!",
      message: `${tab.url.slice(0, 60)}... — ${result.confidence}% confidence`
    });
  }

  // Save result for popup to read
  chrome.storage.local.set({ [tab.url]: result });
});