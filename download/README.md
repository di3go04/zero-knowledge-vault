# Descargador de archivos para auditoría — Windows 11

Este script te permite descargar los archivos clave del repositorio **Zero-Knowledge Vault** directamente a tu carpeta de Descargas, organizados en subcarpetas, para que puedas auditarlos localmente o pasarlos a un LLM.

## Archivos incluidos

| Script | Cuándo usarlo |
|--------|---------------|
| `descargar-zk-vault.ps1` | Recomendado — PowerShell con colores, mensajes claros y validación |
| `descargar-zk-vault.bat`  | Alternativa — funciona con `curl` incluido en Windows 11, sin PowerShell |

## Cómo usar el script PowerShell (.ps1)

1. **Descarga** el archivo `descargar-zk-vault.ps1` a tu equipo (por ejemplo, en `C:\Temp\`).
2. Abre **PowerShell** (Win+X → "Terminal" o "Windows PowerShell").
3. Navega a la carpeta donde guardaste el script:
   ```powershell
   cd C:\Temp
   ```
4. Habilita la ejecución de scripts (solo para esta sesión):
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   ```
5. Ejecuta el script:
   ```powershell
   .\descargar-zk-vault.ps1
   ```

## Cómo usar el script .bat (más simple)

1. **Descarga** el archivo `descargar-zk-vault.bat` a tu equipo.
2. **Doble clic** sobre el archivo.
3. Listo — se abre una ventana de comandos que descarga todo y al final abre Explorer en la carpeta de destino.

## Carpeta de destino

El script crea esta estructura en tu carpeta de Descargas:

```
C:\Users\<tu-usuario>\Downloads\zk-vault-audit\
├── 01-config\          # package.json, tsconfig.json, next.config.ts, schema.prisma
├── 02-crypto\          # crypto-client.ts, crypto-server.ts, key-rotation.ts, pq-kem-real.ts, memory-zero.ts, subkey-derivation.ts
├── 03-backend\         # auth-register-route.ts, auth-login-route.ts, secrets-route.ts, layout.tsx
├── 04-frontend\        # page.tsx, AuthView.tsx, VaultView.tsx, ViewSecretDialog.tsx, CreateSecretDialog.tsx
└── 05-audit\           # AUDITING.md, SECURITY_CHECKLIST.md, ARCHITECTURE.md, AI_AUDIT_PROMPT.md, SECURITY_AUDIT_REPORT.md, crypto-audit.mjs, zk-property-audit.mjs, semgrep.yml, gitleaks.toml, README.md
```

## Aclaraciones sobre archivos que pediste pero no existen

Algunos nombres que mencionaste no existen literalmente en el repo. El script descarga las **alternativas correctas** automáticamente:

| Pediste | No existe — alternativa descargada |
|---------|-----------------------------------|
| `src/lib/key-management.ts` | `src/lib/key-rotation.ts` (rotación de claves) |
| `src/middleware.ts` | `src/app/layout.tsx` (el proyecto no usa middleware Next.js) |
| `src/app/login/page.tsx` | `src/components/AuthView.tsx` (auth por componente SPA) |
| `src/components/dashboard/SecretList.tsx` | `src/components/VaultView.tsx` + `ViewSecretDialog.tsx` |

## Pasos siguientes (auditoría)

Una vez tengas los archivos descargados:

1. **Revisión manual rápida** — abre `01-config/` y `02-crypto/` en tu editor y lee los archivos clave.
2. **Checklist de verificación** — abre `05-audit/SECURITY_CHECKLIST.md` (120 puntos verificables).
3. **Auditoría con LLM** (recomendado para obtener 30+ hallazgos concretos):
   - Abre `05-audit/AI_AUDIT_PROMPT.md` y copia el prompt.
   - Pega en Claude / GPT-4 / Gemini / etc.
   - Adjunta los archivos de `02-crypto/`, `03-backend/` y `05-audit/AUDITING.md`.
   - El LLM devolverá una tabla Markdown con 30+ hallazgos (Severity, Category, File:Line, Finding, Recommendation, Effort).
4. **Auditoría automática local** (opcional, requiere Bun instalado):
   ```powershell
   git clone https://github.com/di3go04/zero-knowledge-vault.git
   cd zero-knowledge-vault
   bun install
   bun run audit:full
   ```
   Genera `audit-reports/latest.md` con todos los análisis automáticos.

## Importante

El commit con toda la infraestructura de auditoría es el `10378cc`. Si al ejecutar el script fallan las descargas de archivos como `AUDITING.md` o `crypto-audit.mjs`, significa que ese commit aún no se ha subido a GitHub.

En ese caso, ejecuta primero desde el sandbox o desde una clonación local del repo:

```bash
git push origin main
```

O usa el script `scripts/push-to-github.sh` (incluido en el repo) con tu token de GitHub.
