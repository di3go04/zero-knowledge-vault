// Zero-Knowledge Vault — Popup UI
//
// Minimal popup that authenticates with the vault API and lists recent secrets.
// In production, the heavy crypto logic lives in the web app; the extension
// delegates to the vault web UI for registration/login and caches a session token.

const API_ORIGIN = "https://vault.zk.example.com";

async function init() {
  const app = document.getElementById("app");
  if (!app) return;

  try {
    const token = await chrome.runtime.sendMessage({ type: "GET_SESSION" });

    if (!token) {
      renderLogin(app);
      return;
    }

    const secrets = await fetchSecrets(token);
    renderSecretList(app, secrets);
  } catch (err) {
    app.innerHTML = `<div class="error">Error: ${err.message}</div>`;
  }
}

function renderLogin(container) {
  container.innerHTML = `
    <div class="login-prompt">
      <p>Inicia sesión en la web para usar la extensión.</p>
      <a href="${API_ORIGIN}" target="_blank" class="btn">Abrir Vault</a>
    </div>
  `;
}

async function fetchSecrets(token) {
  const res = await fetch(`${API_ORIGIN}/api/secrets`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error("Failed to fetch secrets");
  return res.json();
}

function renderSecretList(container, secrets) {
  container.innerHTML = `
    <div class="search-box">
      <input type="text" id="search" placeholder="Buscar secreto..." />
    </div>
    <ul class="secret-list" data-testid="secret-list">
      ${(secrets.data ?? [])
        .map(
          (s) => `
        <li class="secret-item" data-id="${s.id}">
          <span class="title">${escapeHtml(s.title)}</span>
          <button class="btn-fill" data-id="${s.id}">Autocompletar</button>
        </li>
      `,
        )
        .join("")}
    </ul>
  `;

  container.querySelectorAll(".btn-fill").forEach((btn) => {
    btn.addEventListener("click", () => {
      chrome.runtime.sendMessage({ type: "AUTO_FILL", secretId: btn.dataset.id });
    });
  });
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

document.addEventListener("DOMContentLoaded", init);
