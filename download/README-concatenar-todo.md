# Concatenador de TODO el código fuente a un único .txt

Estos scripts recorren **absolutamente todo** el proyecto y concatenan cada archivo de código fuente en **UN SOLO archivo `.txt`**, listo para subir a un LLM (Claude, GPT, Gemini) o para revisión manual.

## Archivos disponibles

| Script | Cuándo usarlo |
|--------|---------------|
| `concatenar-todo.ps1` | **Recomendado** — PowerShell con progreso, conteo de líneas, validación |
| `concatenar-todo.bat`  | Alternativa — funciona con `cmd.exe` nativo de Windows 11 |

## Cómo usar el script PowerShell (.ps1)

1. **Copia** `concatenar-todo.ps1` a la **raíz del proyecto** (donde está `package.json`).
2. Abre **PowerShell** (Win+X → "Terminal" o "Windows PowerShell").
3. Navega a la carpeta del proyecto:
   ```powershell
   cd C:\ruta\al\zero-knowledge-vault
   ```
4. Habilita la ejecución de scripts (solo esta sesión):
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   ```
5. Ejecuta:
   ```powershell
   .\concatenar-todo.ps1
   ```

## Cómo usar el script .bat (más simple)

1. **Copia** `concatenar-todo.bat` a la **raíz del proyecto**.
2. **Doble clic** sobre el archivo.
3. Se abre una ventana CMD que procesa todo y al final pregunta si quieres abrir el archivo.

## Archivo de salida

```
<raiz-del-proyecto>\zk-vault-codigo-completo.txt
```

**Tamaño aproximado:** 740 KB / 23000+ líneas (según el estado actual del proyecto).

## Estructura del archivo generado

```
================================================================================
 ZERO-KNOWLEDGE VAULT - CODIGO COMPLETO CONCATENADO
================================================================================
 Proyecto:        C:\ruta\al\zero-knowledge-vault
 Generado:        2026-07-17 12:34:56
 Total archivos:  130
================================================================================

================================================================================
  tsconfig.json
================================================================================
  Lenguaje:  JSON
  Lineas:    53
  Bytes:     974
================================================================================
----- inicio del archivo -----

{
  "compilerOptions": {
    ...
  }
}

----- fin del archivo -----


================================================================================
  src/lib/crypto/client.ts
================================================================================
  Lenguaje:  TypeScript
  Lineas:    1516
  Bytes:     54463
================================================================================
----- inicio del archivo -----

import { ... } from "...";

export async function deriveMasterKey(...) {
  ...
}

----- fin del archivo -----

... (todos los archivos del proyecto)


================================================================================
 RESUMEN FINAL
================================================================================
 Archivos concatenados OK:  130
 Total lineas de codigo:    23000+
 Tamano del archivo final:  740 KB
================================================================================
```

## Qué incluye

### Extensiones de archivo procesadas
- **TypeScript/JavaScript**: `.ts`, `.tsx`, `.js`, `.jsx`, `.mjs`, `.cjs`
- **Datos**: `.json`, `.prisma`
- **Documentación**: `.md`
- **Estilos**: `.css`, `.scss`
- **Configuración**: `.yml`, `.yaml`, `.toml`
- **Scripts**: `.sh`, `.bat`, `.ps1`
- **Especiales**: `.env.example`, `.gitignore`, `.gitattributes`, `eslint.config.mjs`, `postcss.config.cjs`

### Directorios EXCLUIDOS (no se procesan)
- `node_modules/` — dependencias (500+ MB)
- `.next/` — build artifacts de Next.js
- `.git/` — historial git
- `coverage/` — reportes de coverage
- `skills/` — no son parte del código del proyecto
- `upload/`, `download/` — carpetas de subida/descarga
- `db/` — base de datos SQLite binaria
- `dist/`, `build/`, `out/` — build artifacts (si existen)

### Archivos EXCLUIDOS por nombre
- `bun.lock`, `package-lock.json`, `yarn.lock` — lockfiles (muy grandes, no son código)
- `tsconfig.tsbuildinfo` — generado por TypeScript
- `dev.log`, `server.log` — logs
- `next-env.d.ts` — generado por Next.js
- `.env` — contiene secretos reales (solo se incluye `.env.example`)

## Verificación probada en el sandbox

Antes de entregar estos scripts, ejecuté la lógica equivalente en bash sobre el proyecto actual y confirmé:

- ✅ **130+ archivos** procesados correctamente
- ✅ **740 KB** tamaño final del .txt
- ✅ **23000+ líneas** totales concatenadas
- ✅ Estructura de separadores correcta (encabezado → metadata → contenido → fin)
- ✅ Exclusión de `node_modules`, `.next`, `.git`, etc. funciona
- ✅ Archivos especiales (`.env.example`, `.gitignore`) se incluyen

## Casos de uso

### 1. Auditoría con LLM
```powershell
.\concatenar-todo.ps1
# Sube el .txt a Claude / GPT / Gemini
# Pídele: "Audita este código y dame 30 mejoras concretas con file:line"
```

### 2. Implementar una feature nueva
```powershell
.\concatenar-todo.ps1
# Sube el .txt al LLM
# Pídele: "Implementa [feature X] siguiendo el patrón del código existente"
```

### 3. Buscar en todo el código
```powershell
.\concatenar-todo.ps1
# Abre el .txt en tu editor
# Ctrl+F para buscar cualquier función, variable o comentario
```

### 4. Compartir el proyecto
```powershell
.\concatenar-todo.ps1
# Comprime el .txt y envíalo (740 KB vs 500+ MB de node_modules)
```

## Importante

- El script **no incluye** archivos binarios (imágenes, fuentes, .db)
- El script **no incluye** `node_modules/` (pesa 500+ MB y no es código tuyo)
- El script **no incluye** `.env` real (puede tener secretos), solo `.env.example`
- Si añades un nuevo tipo de archivo al proyecto, edita `$IncludeExtensions` en el `.ps1` o las extensiones en el `.bat`
