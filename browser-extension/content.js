/* content.js — injected into every page; minimal footprint */

// Report the current page's hostname to the background script via storage.
// The background script handles the actual API call to avoid CORS issues.
(function () {
  const hostname = location.hostname;
  if (!hostname) return;

  // Notify background via a simple storage write that triggers background.js.
  // Background picks this up via webNavigation, so this is a no-op safety net.
  chrome.storage.local.get("pendingDomains", (stored) => {
    const pending = stored.pendingDomains ?? [];
    if (!pending.includes(hostname)) {
      pending.push(hostname);
      chrome.storage.local.set({ pendingDomains: pending.slice(-20) });
    }
  });
})();
