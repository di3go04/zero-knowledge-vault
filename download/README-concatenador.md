# Concatenador a archivo único de texto — Windows 11

Este script descarga todos los archivos clave del repositorio **Zero-Knowledge Vault** y los combina en **UN SOLO archivo `.txt`** listo para subir a un LLM (Claude, GPT, Gemini) o para compartir como archivo único.

## Archivos disponibles

| Script | Cuándo usarlo |
|--------|---------------|
| `concatenar-zk-vault.ps1` | **Recomendado** — PowerShell con colores, conteo de líneas, validación |
| `concatenar-zk-vault.bat`  | Alternativa — funciona con `curl` incluido en Windows 11, sin PowerShell |

## Cómo usar el script PowerShell (.ps1)

1. **Descarga** `concatenar-zk-vault.ps1` a tu equipo (por ejemplo, en `C:\Temp\`).
2. Abre **PowerShell** (Win+X → "Terminal" o "Windows PowerShell").
3. Navega a la carpeta:
   ```powershell
   cd C:\Temp
   ```
4. Habilita la ejecución de scripts (solo esta sesión):
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   ```
5. Ejecuta:
   ```powershell
   .\concatenar-zk-vault.ps1
   ```

## Cómo usar el script .bat (más simple)

1. **Descarga** `concatenar-zk-vault.bat`.
2. **Doble clic** sobre el archivo.
3. Se abre una ventana CMD que descarga todo, lo concatena y al final abre Explorer con el archivo seleccionado.

## Archivo de salida

```
C:\Users\<tu-usuario>\Downloads\zk-vault-codigo-completo.txt
```

## Estructura del archivo generado

```
================================================================================
 ZERO-KNOWLEDGE VAULT - CODIGO COMPLETO CONCATENADO
================================================================================
 Repositorio:  https://github.com/di3go04/zero-knowledge-vault
 Branch:       main
 Generado:     <fecha y hora>
 Total archivos: 27
================================================================================

================================================================================
 CONFIG: package.json
================================================================================
 Ruta original:  package.json
 Tamaño:         3888 bytes
 Líneas:         108
================================================================================
----- inicio del archivo -----

{
  "name": "nextjs_tailwind_shadcn_ts",
  ...
  (contenido completo del archivo)
}

----- fin del archivo -----


================================================================================
 CONFIG: tsconfig.json
================================================================================
... (siguiente archivo)

...

================================================================================
 PROMPT DE AUDITORIA PARA LLM (CLAUDE / GPT / GEMINI / ETC.)
================================================================================

Copia el bloque a continuación y pégalo en un chat con un LLM después de subir
este archivo. El LLM producirá una tabla con 30+ hallazgos concretos.

----- inicio del prompt -----

Eres un ingeniero de seguridad senior auditando un Zero-Knowledge Password
Manager en TypeScript / Next.js 16...

[Todo el prompt completo listo para usar]

----- fin del prompt -----

================================================================================
 FIN DEL ARCHIVO
================================================================================
 Estadísticas:
   Archivos descargados OK:  27
   Total líneas concatenadas: 5000+
   Total bytes de código:    150KB+

 Próximo paso:
   1. Sube este archivo a tu LLM favorito
   2. Copia el prompt de arriba y pégalo como mensaje
   3. El LLM devolverá una tabla con 30+ hallazgos
================================================================================
```

## Archivos incluidos en el .txt (27 total)

### 1. Configuración (4 archivos)
- `package.json`
- `tsconfig.json`
- `next.config.ts`
- `prisma/schema.prisma`

### 2. Criptografía — el corazón del proyecto (9 archivos)
- `src/lib/crypto-client.ts` — cifrado en cliente (54 KB)
- `src/lib/crypto-server.ts` — operaciones en servidor
- `src/lib/key-rotation.ts` — rotación de claves (alternativa a key-management.ts)
- `src/lib/pq-kem-real.ts` — ML-KEM-768 post-cuántico
- `src/lib/memory-zero.ts` — zeroización de memoria
- `src/lib/subkey-derivation.ts` — HKDF para subkeys
- `src/lib/session-token.ts` — tokens HS256 con jti
- `src/lib/rate-limit.ts` — rate limiting Redis/Map
- `src/lib/validation-schemas.ts` — esquemas Zod

### 3. Backend (4 rutas API)
- `src/app/api/auth/register/route.ts`
- `src/app/api/auth/login/route.ts`
- `src/app/api/secrets/route.ts`
- `src/app/layout.tsx` (no hay `middleware.ts` en este proyecto)

### 4. Frontend (5 componentes)
- `src/app/page.tsx`
- `src/components/AuthView.tsx` (no hay `login/page.tsx`, la auth es SPA)
- `src/components/VaultView.tsx` (dashboard principal)
- `src/components/ViewSecretDialog.tsx`
- `src/components/CreateSecretDialog.tsx`

### 5. Documentación de auditoría (5 archivos)
- `ARCHITECTURE.md`
- `AUDITING.md`
- `SECURITY_CHECKLIST.md`
- `docs/AI_AUDIT_PROMPT.md`
- `docs/SECURITY_AUDIT_REPORT.md`
- `README.md`

## Aclaraciones sobre archivos que no existen

| Pediste originalmente | No existe — alternativa incluida |
|-----------------------|----------------------------------|
| `src/lib/key-management.ts` | `src/lib/key-rotation.ts` ✅ |
| `src/middleware.ts` | `src/app/layout.tsx` ✅ (no hay middleware Next.js) |
| `src/app/login/page.tsx` | `src/components/AuthView.tsx` ✅ (auth por SPA) |
| `src/components/dashboard/SecretList.tsx` | `VaultView.tsx` + `ViewSecretDialog.tsx` ✅ |

## Prompt de auditoría incluido al final

El archivo `.txt` termina con un **prompt completo de auditoría** listo para copiar y pegar en cualquier LLM. El prompt:

- Define el contexto (zero-knowledge, Web Crypto API, stack)
- Especifica la propiedad fundamental (server crypto-blind)
- Pide **al menos 30 hallazgos** en formato tabla estandarizado
- Define columnas: `#`, `Severity`, `Category`, `File:Line`, `Finding`, `Recommendation`, `Effort`
- Define categorías permitidas: crypto, auth, authz, injection, zk-property, secret-leak, supply-chain, i18n, a11y, performance, reliability, compliance, docs
- Define niveles de severidad: CRITICAL, HIGH, MEDIUM, LOW, INFO
- Define esfuerzos: S (<1h), M (1-4h), L (4-16h), XL (>16h)
- Lista las primitivas criptográficas aprobadas
- Pide un "Verdict" final con top 3 riesgos

## Flujo recomendado

1. **Ejecuta** el script `.ps1` o `.bat` → genera `zk-vault-codigo-completo.txt`
2. **Sube** el `.txt` a Claude / GPT / Gemini como adjunto
3. **Copia** el prompt que está al final del archivo
4. **Pega** el prompt como mensaje en el chat con el LLM
5. **Recibe** la tabla con 30+ hallazgos estructurados
6. **Triaga** por Severity (CRITICAL → XL primero)
7. **File** cada hallazgo aceptado como GitHub Issue con label `audit-finding`

## Importante

Si al ejecutar el script fallan las descargas de archivos como `AUDITING.md` o `crypto-audit.mjs`, significa que el commit `10378cc` aún no se ha subido a GitHub. En ese caso, primero ejecuta desde el sandbox o desde una clonación local:

```bash
git push origin main
```

Después vuelve a ejecutar el script de concatenación.
