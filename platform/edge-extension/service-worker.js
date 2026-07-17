// Zero-Knowledge Vault — Edge Service Worker
//
// Edge follows Chrome's Manifest V3 exactly. This file is identical to the Chrome
// service worker. In a monorepo build, you'd symlink or copy:
//   platform/chrome-extension/service-worker.js

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

    case "AUTO_FILL":
      chrome.tabs.sendMessage(sender.tab?.id ?? 0, {
        type: "FILL_CREDENTIALS",
        username: message.username,
        password: message.password,
      });
      sendResponse({ ok: true });
      return false;
  }
});

chrome.runtime.onInstalled.addListener(() => {
  console.log("[ZK-Vault] Edge extension installed");
});
