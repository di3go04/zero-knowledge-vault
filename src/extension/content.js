// content.js — Injects credentials into page forms
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "DO_AUTOFILL" && msg.secret) {
    const inputs = document.querySelectorAll('input[type="password"], input[type="text"], input[type="email"]');
    inputs.forEach((input) => {
      const name = (input.name || input.id || "").toLowerCase();
      if (name.includes("user") || name.includes("email") || name.includes("name")) {
        input.value = msg.secret.username || "";
      } else if (input.type === "password") {
        input.value = msg.secret.password || "";
      }
    });
  }
});
