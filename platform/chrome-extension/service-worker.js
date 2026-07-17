/// <reference lib="webworker" />
// Zero-Knowledge Vault — Service Worker (Manifest V3)
//
// Handles:
//   - Session token storage (chrome.storage.session — cleared on browser restart)
//   - Message relay between popup and content scripts
//   - Fetch interception for API requests (injects Authorization header)

const API_ORIGIN = "https://vault.zk.example.com";

async function getSessionToken() {
  const result = await chrome.storage.session.get(["sessionToken"]);
  return result.sessionToken ?? null;
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  switch (message.type) {
    case "GET_SESSION":
      getSessionToken().then(sendResponse);
      return true;

    case "SET_SESSION":
      chrome.storage.session.set({ sessionToken: message.token });
      sendResponse({ ok: true });
      return false;

    case "CLEAR_SESSION":
      chrome.storage.session.remove("sessionToken");
      sendResponse({ ok: true });
      return false;

    case "AUTO_FILL": {
      chrome.tabs.sendMessage(sender.tab?.id ?? 0, {
        type: "FILL_CREDENTIALS",
        username: message.username,
        password: message.password,
      });
      sendResponse({ ok: true });
      return false;
    }
  }
});

chrome.runtime.onInstalled.addListener(() => {
  console.log("[ZK-Vault] Extension installed");
});
