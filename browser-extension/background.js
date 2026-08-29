/* background.js — Sentinel service worker (MV3) */

const SENTINEL_API = "http://localhost:7173";
const MAX_RECENT = 50;

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

async function recordVisit(hostname) {
  if (!hostname || hostname === "newtab" || hostname.startsWith("chrome")) return;

  const result = await classifyDomain(hostname);
  const category = result?.category ?? "unknown";
  const organization = result?.organization ?? null;

  const stored = await chrome.storage.local.get("recentDomains");
  const recent = stored.recentDomains ?? [];

  // Deduplicate — move to front if already present
  const filtered = recent.filter((d) => d.hostname !== hostname);
  filtered.unshift({ hostname, category, organization, visitedAt: Date.now() });

  await chrome.storage.local.set({
    recentDomains: filtered.slice(0, MAX_RECENT),
  });
}

chrome.webNavigation.onCommitted.addListener(
  (details) => {
    if (details.frameId !== 0) return; // main frame only
    try {
      const hostname = new URL(details.url).hostname;
      recordVisit(hostname);
    } catch {
      /* ignore non-http URLs */
    }
  },
  { url: [{ schemes: ["http", "https"] }] },
);
