// Zero-Knowledge Vault — Edge Content Script
// (Identical to Chrome version)

(function () {
  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === "FILL_CREDENTIALS") {
      fillCredentials(message.username, message.password);
    }
  });

  function fillCredentials(username, password) {
    const usernameField =
      document.querySelector('input[type="email"]') ??
      document.querySelector('input[name="username"]') ??
      document.querySelector('input[autocomplete="username"]');

    const passwordField =
      document.querySelector('input[type="password"]') ??
      document.querySelector('input[autocomplete="current-password"]');

    if (usernameField) {
      usernameField.value = username;
      usernameField.dispatchEvent(new Event("input", { bubbles: true }));
    }
    if (passwordField) {
      passwordField.value = password;
      passwordField.dispatchEvent(new Event("input", { bubbles: true }));
    }
  }
})();
