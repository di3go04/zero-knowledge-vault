// background.js — Service worker for ZK Vault Extension
const VAULT_URL = "http://localhost:3000";

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "FETCH_SECRETS") {
    chrome.storage.local.get(["sessionToken"], async (result) => {
      if (!result.sessionToken) {
        sendResponse({ error: "Not authenticated" });
        return;
      }
      try {
        const res = await fetch(`${VAULT_URL}/api/ext/fill`, {
          headers: { Authorization: `Bearer ${result.sessionToken}` },
        });
        const data = await res.json();
        sendResponse(data);
      } catch (err) {
        sendResponse({ error: err.message });
      }
    });
    return true;
  }
  if (msg.type === "AUTOFILL") {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      chrome.tabs.sendMessage(tabs[0].id, {
        type: "DO_AUTOFILL",
        secret: msg.secret,
      });
    });
  }
});
