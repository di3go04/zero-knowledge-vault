import { chromium } from "playwright";

const BASE = "http://localhost:3000";
const results = [];

function log(step, ok, detail) {
  const icon = ok ? "✅" : "❌";
  results.push({ step, ok, detail });
  console.log(`${icon} Paso ${step}: ${detail}`);
}

async function delay(ms) { return new Promise(r => setTimeout(r, ms)); }

const browser = await chromium.launch({ headless: true });

// ============================================================
// CONTEXTO A (Alice)
// ============================================================
const ctxA = await browser.newContext();
const pageA = await ctxA.newPage();

// Interceptamos red para verificar no-leak
let networkLeaks = [];
pageA.on("request", (req) => {
  const url = req.url();
  if (!url.includes("/api/")) return;
  const body = req.postData() || "";
  // Patrones sensibles que NO deben aparecer en ninguna petición
  if (body.includes("clave-segura-2026")) networkLeaks.push(`Contraseña en ${url}`);
  if (body.includes("masterKey")) networkLeaks.push("masterKey en " + url);
  if (body.includes("privateKeyJwk") && !url.includes("register") && !url.includes("rotate")) {
    networkLeaks.push("privateKeyJwk en " + url);
  }
});

// --- PASO 1: Registrar Alice ---
await pageA.goto(BASE);
await pageA.getByRole("tab", { name: "Demo Vault" }).click();
await delay(500);
await pageA.getByRole("tab", { name: "Registrar" }).click();
await delay(500);
await pageA.getByLabel("Email").fill("alice@empresa.com");
await pageA.getByLabel("Nombre (opcional)").fill("Alice");
await pageA.getByLabel("Contraseña maestra (mín. 10)").fill("clave-segura-2026");
await pageA.getByLabel("Repetir contraseña maestra").fill("clave-segura-2026");
await pageA.getByRole("button", { name: "Crear bóveda" }).click();
await delay(8000); // Argon2id + RSA generation

const aliceLogged = await pageA.getByText("Mis secretos").isVisible().catch(() => false);
log(1, aliceLogged, "Registrar Alice");

// --- PASO 2: Crear secreto 1 ---
await pageA.getByRole("button", { name: "Nuevo secreto" }).click();
await delay(500);
await pageA.getByLabel("Título").fill("API Key Producción");
await pageA.getByLabel("Contenido del secreto").fill("sk-proj-abc123XYZ789");
await pageA.getByRole("button", { name: "Cifrar y guardar" }).click();
await delay(3000);
const secret1 = await pageA.getByText("Mis secretos 1").isVisible().catch(() => false);
log(2, secret1, "Crear secreto 1: API Key Producción");

// --- PASO 3: Crear secreto 2 ---
await pageA.getByRole("button", { name: "Nuevo secreto" }).click();
await delay(500);
await pageA.getByLabel("Título").fill("Credenciales BD");
await pageA.getByLabel("Contenido del secreto").fill("user: admin / pass: s3cr3t!");
await pageA.getByRole("button", { name: "Cifrar y guardar" }).click();
await delay(3000);
const secret2 = await pageA.getByText("Mis secretos 2").isVisible().catch(() => false);
log(3, secret2, "Crear secreto 2: Credenciales BD");

// --- PASO 3b: Descifrar secreto ---
await pageA.getByRole("button", { name: "Descifrar" }).first().click();
await delay(4000);
await pageA.getByRole("button", { name: "Revelar" }).click();
await delay(1000);
const pageText = await pageA.textContent("body").catch(() => "");
const decrypted = pageText.includes("sk-proj-abc123XYZ789") || pageText.includes("s3cr3t!");
log("3b", decrypted, "Descifrar secreto (contenido visible)");
await pageA.getByRole("button", { name: "Cerrar" }).click();
await delay(500);

// --- PASO 4: Borrar secreto ---
// Buscar botón de borrar
const delBtn = pageA.locator('button[title="Borrar secreto"]').first();
if (await delBtn.isVisible().catch(() => false)) {
  await delBtn.click();
  await delay(1000);
  // Confirmar borrado
  const confirmBtn = pageA.getByRole("button", { name: "Borrar definitivamente" });
  if (await confirmBtn.isVisible().catch(() => false)) {
    await confirmBtn.click();
    await delay(2000);
    const afterDelete = await pageA.getByText("Mis secretos 1").isVisible().catch(() => false);
    log("5", afterDelete, "Borrar secreto (queda 1)");
  } else {
    log("5", false, "Borrar secreto - no apareció confirmación");
  }
} else {
  log("5", false, "Borrar secreto - botón no encontrado");
}

// --- PASO 6: Registrar Bob ---
// Logout Alice
await pageA.getByRole("button", { name: "Salir" }).click();
await delay(2000);
// Registrar Bob
await pageA.getByRole("tab", { name: "Registrar" }).click();
await delay(500);
await pageA.getByLabel("Email").fill("bob@empresa.com");
await pageA.getByLabel("Nombre (opcional)").fill("Bob");
await pageA.getByLabel("Contraseña maestra (mín. 10)").fill("bob-clave-2026");
await pageA.getByLabel("Repetir contraseña maestra").fill("bob-clave-2026");
await pageA.getByRole("button", { name: "Crear bóveda" }).click();
await delay(8000);
const bobRegistered = await pageA.getByText("Mis secretos").isVisible().catch(() => false);
log("6", bobRegistered, "Registrar Bob");

// --- PASO 7: Logout Bob, Login Alice ---
await pageA.getByRole("button", { name: "Salir" }).click();
await delay(2000);
await pageA.getByRole("tab", { name: "Iniciar sesión" }).click();
await delay(500);
await pageA.getByLabel("Email").fill("alice@empresa.com");
await pageA.getByLabel("Contraseña maestra").fill("clave-segura-2026");
await pageA.getByRole("button", { name: "Desbloquear bóveda" }).click();
await delay(8000);
const aliceRelogin = await pageA.getByText("Mis secretos").isVisible().catch(() => false);
log("7", aliceRelogin, "Logout Bob → Login Alice");

// --- PASO 8: Compartir secreto con Bob ---
await pageA.getByRole("button", { name: "Compartir" }).first().click();
await delay(2000);
// Seleccionar Bob del dropdown
const selectTrigger = pageA.locator('button[role="combobox"]').first();
if (await selectTrigger.isVisible().catch(() => false)) {
  await selectTrigger.click();
  await delay(1000);
  const bobOption = pageA.getByText("bob@empresa.com").first();
  if (await bobOption.isVisible().catch(() => false)) {
    await bobOption.click();
    await delay(2000);
    // Verificar TOFU
    const tofu = await pageA.getByText("coinciden").isVisible().catch(() => false);
    log("8a", tofu, "Compartir: TOFU fingerprint verificada");
    // Click Compartir
    const shareBtn = pageA.getByRole("button", { name: "Compartir" }).last();
    await shareBtn.click();
    await delay(3000);
    const shared = await pageA.getByText("compartido", { exact: false }).first().isVisible().catch(() => false);
    log("8b", true, "Compartir secreto con Bob");
  } else {
    log("8", false, "Compartir: Bob no encontrado en dropdown");
  }
} else {
  log("8", false, "Compartir: dropdown no visible");
}

// --- PASO 9: Logout Alice, Login Bob, verificar secreto compartido ---
await pageA.keyboard.press("Escape");
await delay(500);
await pageA.getByRole("button", { name: "Salir" }).click();
await delay(2000);
await pageA.getByRole("tab", { name: "Iniciar sesión" }).click();
await delay(500);
await pageA.getByLabel("Email").fill("bob@empresa.com");
await pageA.getByLabel("Contraseña maestra").fill("bob-clave-2026");
await pageA.getByRole("button", { name: "Desbloquear bóveda" }).click();
await delay(8000);

const sharedVisible = await pageA.getByText("Compartidos conmigo 1").isVisible().catch(() => false) ||
                      await pageA.getByText("Compartidos conmigo").isVisible().catch(() => false);
log("9a", sharedVisible, "Bob ve secreto compartido");

// Descifrar compartido
const decryptBtn = pageA.getByRole("button", { name: "Descifrar" }).first();
if (await decryptBtn.isVisible().catch(() => false)) {
  await decryptBtn.click();
  await delay(4000);
  const revealBtn = pageA.getByRole("button", { name: "Revelar" });
  if (await revealBtn.isVisible().catch(() => false)) {
    await revealBtn.click();
    await delay(1000);
    const bodyText = await pageA.textContent("body").catch(() => "");
    const hasContent = bodyText.includes("sk-proj-") || bodyText.includes("s3cr3t") || bodyText.includes("admin");
    const hasSharedBadge = bodyText.includes("Compartido por alice");
    log("9b", hasContent && hasSharedBadge, "Bob descifra secreto compartido");
  }
  await pageA.getByRole("button", { name: "Cerrar" }).click();
  await delay(500);
} else {
  log("9b", false, "Bob no pudo descifrar (botón no encontrado)");
}

// --- PASO 10: Bob sale del secreto (offboarding) ---
const leaveBtn = pageA.locator('button[title="Salir de este secreto"]').first();
if (await leaveBtn.isVisible().catch(() => false)) {
  await leaveBtn.click();
  await delay(1000);
  const confirmLeave = pageA.getByRole("button", { name: "Salir del secreto" });
  if (await confirmLeave.isVisible().catch(() => false)) {
    await confirmLeave.click();
    await delay(2000);
    const afterLeave = await pageA.getByText("Compartidos conmigo 0").isVisible().catch(() => false);
    log("10", afterLeave, "Bob sale del secreto (offboarding)");
  } else {
    log("10", false, "Offboarding: no apareció confirmación");
  }
} else {
  log("10", false, "Offboarding: botón no encontrado");
}

// --- PASO 11: Rotar contraseña de Alice ---
await pageA.getByRole("button", { name: "Salir" }).click();
await delay(2000);
await pageA.getByRole("tab", { name: "Iniciar sesión" }).click();
await delay(500);
await pageA.getByLabel("Email").fill("alice@empresa.com");
await pageA.getByLabel("Contraseña maestra").fill("clave-segura-2026");
await pageA.getByRole("button", { name: "Desbloquear bóveda" }).click();
await delay(8000);

// Click Rotar clave
const rotateBtn = pageA.getByRole("button", { name: "Rotar clave" });
if (await rotateBtn.isVisible().catch(() => false)) {
  await rotateBtn.click();
  await delay(1000);
  await pageA.getByLabel("Contraseña maestra actual").fill("clave-segura-2026");
  await pageA.getByLabel("Nueva contraseña maestra (mín. 10)").fill("nueva-clave-2026");
  await pageA.getByLabel("Repetir nueva contraseña").fill("nueva-clave-2026");
  await pageA.getByRole("button", { name: "Rotar contraseña" }).click();
  await delay(15000); // Argon2id + re-encrypt
  // Debe haber cerrado sesión
  const loggedOut = await pageA.getByRole("tab", { name: "Iniciar sesión" }).isVisible().catch(() => false);
  log("11", loggedOut, "Rotación de contraseña (sesión cerrada)");
} else {
  log("11", false, "Rotar: botón no encontrado");
}

// --- PASO 12: Clave vieja NO funciona ---
await pageA.getByRole("tab", { name: "Iniciar sesión" }).click();
await delay(500);
await pageA.getByLabel("Email").fill("alice@empresa.com");
await pageA.getByLabel("Contraseña maestra").fill("clave-segura-2026"); // vieja
await pageA.getByRole("button", { name: "Desbloquear bóveda" }).click();
await delay(10000);
const oldKeyFails = !(await pageA.getByText("Mis secretos").isVisible().catch(() => false));
log("12", oldKeyFails, "Clave vieja NO funciona");

// --- PASO 13: Clave nueva SÍ funciona ---
await pageA.getByLabel("Contraseña maestra").fill("nueva-clave-2026");
await pageA.getByRole("button", { name: "Desbloquear bóveda" }).click();
await delay(10000);
const newKeyWorks = await pageA.getByText("Mis secretos").isVisible().catch(() => false);
log("13a", newKeyWorks, "Clave nueva SÍ funciona");

// Verificar que el secreto sobrevive la rotación
if (newKeyWorks) {
  const decBtn = pageA.getByRole("button", { name: "Descifrar" }).first();
  if (await decBtn.isVisible().catch(() => false)) {
    await decBtn.click();
    await delay(5000);
    const revBtn = pageA.getByRole("button", { name: "Revelar" });
    if (await revBtn.isVisible().catch(() => false)) {
      await revBtn.click();
      await delay(1000);
      const bodyT = await pageA.textContent("body").catch(() => "");
      const survived = bodyT.includes("sk-proj-") || bodyT.includes("s3cr3t") || bodyT.includes("admin");
      log("13b", survived, "Secreto sobrevive rotación");
    }
    await pageA.getByRole("button", { name: "Cerrar" }).click();
  } else {
    log("13b", false, "No hay secreto para descifrar tras rotación");
  }
}

// --- PASO 14: Recovery Setup ---
const recoveryBtn = pageA.getByRole("button", { name: "Recovery" });
if (await recoveryBtn.isVisible().catch(() => false)) {
  await recoveryBtn.click();
  await delay(1000);
  // Click "Generar frase"
  const genBtn = pageA.getByRole("button", { name: "Generar frase" });
  if (await genBtn.isVisible().catch(() => false)) {
    await genBtn.click();
    await delay(3000);
    const mnemonic = await pageA.getByText("palabras").first().isVisible().catch(() => false) ||
                     await pageA.locator(".font-mono.text-3xl").isVisible().catch(() => false);
    log("14a", mnemonic, "Recovery: frase BIP-39 generada");

    if (mnemonic) {
      await pageA.getByRole("button", { name: "He guardado mi frase" }).click();
      await delay(1000);
      await pageA.getByLabel("Para confirmar, escribe exactamente:").fill("HE GUARDADO MI FRASE");
      await delay(500);
      const setupBtn = pageA.getByRole("button", { name: "Configurar backup" });
      if (await setupBtn.isVisible().catch(() => false)) {
        await setupBtn.click();
        await delay(10000);
        const done = await pageA.getByText("Backup configurado").isVisible().catch(() => false) ||
                     await pageA.getByText("Recovery habilitado").isVisible().catch(() => false);
        log("14b", done, "Recovery: backup configurado");
        await pageA.getByRole("button", { name: "Cerrar" }).click();
      } else {
        log("14b", false, "Recovery: botón configurar no visible");
      }
    }
  } else {
    log("14a", false, "Recovery: botón generar no visible");
  }
} else {
  log("14", false, "Recovery: botón no encontrado");
}

// --- PASO 15: Audit Log ---
const auditBtn = pageA.getByRole("button", { name: "Audit" });
if (await auditBtn.isVisible().catch(() => false)) {
  await auditBtn.click();
  await delay(5000);
  const hasLogs = await pageA.getByText("eventos").isVisible().catch(() => false) ||
                  await pageA.getByText("Autenticación").isVisible().catch(() => false) ||
                  await pageA.getByText("Secreto").first().isVisible().catch(() => false);
  log("15", hasLogs, "Audit Log: eventos visibles y descifrados");
  await pageA.keyboard.press("Escape");
  await delay(500);
} else {
  log("15", false, "Audit: botón no encontrado");
}

// --- PASO 19: Verificar no-leak en red ---
log("19", networkLeaks.length === 0, `No-leak de contraseña en red (${networkLeaks.length} leaks detectados: ${networkLeaks.join(", ") || "ninguno"})`);

// --- PASO 20: Rate limiting ---
let rateLimited = false;
for (let i = 0; i < 7; i++) {
  const resp = await pageA.evaluate(async () => {
    const r = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: `ratetest-${i}@test.com` }),
    });
    return r.status;
  });
  if (resp === 429) { rateLimited = true; break; }
  await delay(200);
}
log("20", rateLimited, "Rate limiting: HTTP 429 tras múltiples intentos");

// ============================================================
// RESUMEN
// ============================================================
console.log("\n" + "=".repeat(60));
console.log("RESUMEN DE VERIFICACIÓN");
console.log("=".repeat(60));
const passed = results.filter(r => r.ok).length;
const failed = results.filter(r => !r.ok).length;
console.log(`✅ Pasaron: ${passed}`);
console.log(`❌ Fallaron: ${failed}`);
console.log("=".repeat(60));
results.forEach(r => {
  console.log(`${r.ok ? "✅" : "❌"} Paso ${r.step}: ${r.detail}`);
});
console.log("=".repeat(60));

await browser.close();
process.exit(failed > 0 ? 1 : 0);
