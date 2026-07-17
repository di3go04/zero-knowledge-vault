// Zero-Knowledge Vault — Safari Web Extension Background Script
//
// Safari uses WKWebView's WKContentRuleList + Safari App Extensions.
// The web extension part runs in a WKWebView with access to safari.* API.
// Session token is stored via browser.storage.local.

const API_ORIGIN = "https://vault.zk.example.com";

async function getSessionToken() {
  const result = await browser.storage.local.get(["sessionToken"]);
  return result.sessionToken ?? null;
}

browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
  switch (message.type) {
    case "GET_SESSION":
      getSessionToken().then(sendResponse);
      return true;

    case "SET_SESSION":
      browser.storage.local.set({ sessionToken: message.token }).then(() => {
        sendResponse({ ok: true });
      });
      return true;

    case "CLEAR_SESSION":
      browser.storage.local.remove("sessionToken").then(() => {
        sendResponse({ ok: true });
      });
      return true;

    case "AUTO_FILL":
      browser.tabs.sendMessage(sender.tab?.id ?? 0, {
        type: "FILL_CREDENTIALS",
        username: message.username,
        password: message.password,
      });
      sendResponse({ ok: true });
      return false;
  }
});
