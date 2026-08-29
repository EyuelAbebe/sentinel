/* popup.js — Sentinel popup logic */

const SENTINEL_API = "http://localhost:7173";

async function pingApi() {
  try {
    const r = await fetch(`${SENTINEL_API}/health`, { signal: AbortSignal.timeout(1500) });
    return r.ok;
  } catch {
    return false;
  }
}

async function classifyDomain(hostname) {
  try {
    const r = await fetch(`${SENTINEL_API}/classify?domain=${encodeURIComponent(hostname)}`, {
      signal: AbortSignal.timeout(2000),
    });
    if (!r.ok) return null;
    return await r.json();
  } catch {
    return null;
  }
}

function setCategoryBadge(category) {
  const badge = document.getElementById("risk-badge");
  badge.textContent = (category || "unknown").toUpperCase().replace("_", " ");
  badge.className = `badge badge-${(category || "unknown").toLowerCase()}`;
}

function setStatusDot(connected) {
  const dot = document.getElementById("status-dot");
  dot.className = `dot ${connected ? "dot-connected" : "dot-disconnected"}`;
  dot.title = connected ? "Sentinel connected" : "Sentinel not running";
}

function setStatusMsg(connected) {
  const el = document.getElementById("status-message");
  if (connected) {
    el.textContent = "Sentinel connected";
    el.className = "status-msg status-connected";
  } else {
    el.innerHTML = "Sentinel not running — start with <code>sentinel</code>";
    el.className = "status-msg status-disconnected";
  }
}

function renderRecentDomains(domains) {
  const list = document.getElementById("domain-list");
  list.innerHTML = "";
  for (const { hostname, category } of domains.slice(0, 10)) {
    const li = document.createElement("li");
    li.innerHTML = `
      <span class="domain-name">${hostname}</span>
      <span class="badge badge-${(category || "unknown").toLowerCase()}">${(category || "UNKNOWN").toUpperCase().replace("_", " ")}</span>
    `;
    list.appendChild(li);
  }
}

async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  let hostname = "—";
  if (tab?.url) {
    try {
      hostname = new URL(tab.url).hostname;
    } catch {
      /* non-http page */
    }
  }
  document.getElementById("hostname").textContent = hostname || "—";

  const connected = await pingApi();
  setStatusDot(connected);
  setStatusMsg(connected);

  if (connected && hostname && hostname !== "—") {
    const result = await classifyDomain(hostname);
    if (result) {
      setCategoryBadge(result.category);
      if (result.organization) {
        document.getElementById("org-line").classList.remove("hidden");
        document.getElementById("org-value").textContent = result.organization;
      }
      if (result.category) {
        document.getElementById("category-line").classList.remove("hidden");
        document.getElementById("category-value").textContent = result.category.replace("_", " ");
      }
    }
  }

  // Load recent domains from local storage
  const stored = await chrome.storage.local.get("recentDomains");
  if (stored.recentDomains?.length) {
    renderRecentDomains(stored.recentDomains);
  }
}

document.addEventListener("DOMContentLoaded", init);
