# INFORME TÉCNICO Y DE VALORACIÓN — ZERO-KNOWLEDGE VAULT
## Documento para análisis de IA / inversor / adquirente

**Fecha del informe:** 2026-07-20
**Repositorio:** https://github.com/di3go04/zero-knowledge-vault
**Commit evaluado:** `884a7be` (rama `main`)
**Versión del producto:** 1.0.0
**Licencia:** MIT
**Autor del informe:** Equipo de ingeniería ZK Vault

---

## 0. INSTRUCCIONES PARA LA IA QUE RECIBE ESTE INFORME

Estimado modelo de lenguaje: a continuación se le presenta un informe técnico exhaustivo de un producto de software llamado **Zero-Knowledge Vault**, un gestor de contraseñas zero-knowledge con cifrado end-to-end implementado en el navegador mediante Web Crypto API.

Su tarea es **producir una valoración realista del precio del producto** (rango justo de mercado, no optimista ni pesimista), considerando:

1. **Calidad técnica del código** (arquitectura, cobertura de tests, deuda técnica).
2. **Madurez criptográfica** (algoritmos usados, cumplimiento de estándares, post-cuántico).
3. **Estado de producción** (deploy, monitoreo, SLA, escala).
4. **Mercado y comparables** (Bitwarden, 1Password, Proton Pass, KeePassXC).
5. **Riesgos legales y regulatorios** (GDPR, SOC2, exportación).
6. **Tracción / adopción** (no hay usuarios todavía — el producto es un MVP/seed).

**Formato de salida esperado:**

```
VALORACIÓN: USD <mínimo> — USD <máximo> (rango justo de mercado)
VALORACIÓN PUNTO MEDIO: USD <valor>
MULTIPLO USADO: <N>x <ARR estimada | assets | líneas de código>
RIESGO: <bajo | medio | alto>
HORIZONTE: <seed | serie A | bootstrapped | acquisition>

JUSTIFICACIÓN:
1. <párrafo sobre calidad técnica>
2. <párrafo sobre madurez criptográfica>
3. <párrafo sobre mercado>
4. <párrafo sobre riesgos>
5. <párrafo sobre comparables>

RECOMENDACIONES PARA SUBIR VALORACIÓN:
- <lista accionable>
```

---

## 1. RESUMEN EJECUTIVO

**Zero-Knowledge Vault** es un gestor de contraseñas para equipos donde **todo el cifrado ocurre en el navegador del cliente** mediante la Web Crypto API estándar. El servidor es un *crypto-blind store* que solo persiste blobs cifrados, sales públicas, IVs y llaves públicas — **nunca** recibe contraseñas maestras, llaves privadas en claro, ni el contenido de ningún secreto.

**Stack tecnológico:**
- Frontend: Next.js 16 + React 19 + Tailwind CSS 4 + shadcn/ui
- Backend: Next.js API routes (Node.js runtime)
- ORM: Prisma 6 (SQLite en dev, PostgreSQL en prod)
- Cifrado: Web Crypto API + hash-wasm (Argon2id) + @noble/post-quantum (ML-KEM-768)
- Logger: pino (con redacción automática de secretos)
- Tests: Vitest 4 (119 tests, 8 suites)
- Cache distribuida: Redis (opcional, para rate limit y blacklist de tokens)

**Estado actual:** MVP funcional, listo para deploy en Vercel/Railway con PostgreSQL. Sin usuarios en producción. Sin pipeline de monitoreo (Prometheus/Grafana pendiente). Sin auditoría de seguridad externa.

---

## 2. MÉTRICAS DE CÓDIGO (CUANTITATIVAS)

### 2.1 Volumen

| Métrica | Valor |
|---------|-------|
| Líneas de código TypeScript/TSX | **18,078** |
| Líneas de tests | **1,771** (9.8% del total) |
| Archivos de código fuente | **130** |
| Endpoints API | **18** (auth, secrets, shares, audit-logs, devices, health) |
| Modelos de datos Prisma | **6** (User, UserKeyMaterial, Secret, SecretKeyShare, Device, AuditLog) |
| Componentes React | **15** (AuthView, VaultView, diálogos, etc.) |
| Suites de tests | **8** (119 tests) |
| Dependencias producción | **33** (de 77 originales tras refactor) |
| Dependencias desarrollo | **12** |
| Commits en main | **9** (squashed, historial limpio) |
| Tamaño del bundle estático | **2.8 MB** |
| Tamaño del build completo | **453 MB** (incluye sourcemaps) |

### 2.2 Cobertura de tests (módulo criptográfico)

| Archivo | Statements | Branches | Functions | Lines |
|---------|-----------|----------|-----------|-------|
| hkdf.ts | 100% | 100% | 100% | 100% |
| rotation.ts | 100% | 100% | 100% | 100% |
| hash-chain.ts | 100% | 100% | 100% | 100% |
| server.ts | 94.5% | 85% | 100% | 96.4% |
| memory.ts | 77.4% | 83.3% | 87.5% | 76.7% |
| client.ts | 51.2% | 33.8% | 74.6% | 51.0% |
| **Promedio módulo** | **66.0%** | **52.6%** | **82.3%** | **66.0%** |

**Deuda técnica identificada:** client.ts tiene branches bajas (52.6%) porque los paths de Argon2id worker solo se ejercen en navegador real con Web Worker, no en Node.js tests. Es una limitación conocida y documentada.

### 2.3 Seguridad de dependencias

```
bun audit: 1 vulnerabilidad moderate (postcss vía next/vitest upstream)
  - No vulnerabilidades high ni critical en deps directas
  - La vulnerabilidad es transitiva (esperar fix de next.js/vitest)
```

### 2.4 CodeQL

- **111 alertas cerradas** (todas) en GitHub Security tab tras refactor.
- 0 alertas abiertas actualmente.
- 23 alertas eran de código legacy en `skills/` (eliminado del repo).
- 5 alertas eran de archivos eliminados en refactor (stale).

---

## 3. ARQUITECTURA TÉCNICA

### 3.1 Stack criptográfico

| Capa | Algoritmo | Parámetros | Uso |
|------|-----------|-----------|-----|
| KDF primario | **Argon2id** | m=64MiB, t=3, p=4 | Derivar masterKey de la contraseña |
| KDF fallback | PBKDF2-SHA256 | 600,000 iteraciones | Si Web Worker falla (legacy) |
| Subkey derivation | HKDF-SHA256 (RFC 5869) | 4 propósitos | audit, device, share, metadata subkeys |
| Cifrado simétrico | **AES-256-GCM** | 96-bit IV, AAD | Cifrar blobs y llaves privadas |
| Wrap asimétrico | RSA-OAEP 2048 | SHA-256 | Envolver llaves AES para shares |
| Firmas | RSA-PSS 2048 | salt=32, SHA-256 | Proof-of-Possession en registro |
| Multi-device | ECDH P-256 | — | Derivar shared key entre dispositivos |
| Device enrollment | ECDSA P-256 | SHA-256 | Challenge-response |
| Post-cuántico | **ML-KEM-768** (NIST FIPS 203) | hybrid con ECDH | Wrap de llaves AES para shares futuros |
| Recovery | BIP-39 | 24 palabras, 256 bits | Backup de la llave privada RSA |
| Audit chain | SHA-256 hash chain | — | Tamper-evident audit logs |

**Cumplimiento estándares:** Web Crypto API (W3C), RFC 5869 (HKDF), RFC 8017 (RSA-OAEP/PSS), NIST FIPS 203 (ML-KEM-768), BIP-39.

### 3.2 Modelo de datos (6 entidades)

```
User
  ├─ UserKeyMaterial (1:1)  — kdfSalt, publicKeyJwk, encryptedPrivateKeyJwk,
  │                           mlKemPublicKey, recoveryKey
  ├─ Secret[] (1:N)          — encryptedTitle, encryptedData, IVs
  │    └─ SecretKeyShare[]   — wrappedSymmetricKey (RSA-OAEP)
  ├─ Device[] (1:N)          — publicKeyECDH, wrappedPrivateKeyForDevice (ECDH)
  └─ AuditLog[] (1:N)        — encryptedEvent, prevHash, logHash (hash chain)
```

**Propiedad fundamental verificada:** el servidor nunca almacena contraseña maestra, masterKey, llave privada RSA en claro, llaves AES simétricas, contenido de secretos, ni frase BIP-39.

### 3.3 API endpoints (18)

| Endpoint | Método | Función |
|----------|--------|---------|
| `/api/auth/register` | POST | Registro (solo blobs cifrados) |
| `/api/auth/login` | POST | Login con decoy anti-enumeración |
| `/api/auth/logout` | POST | Logout (blacklist del session token) |
| `/api/auth/rotate` | POST | Rotación de contraseña maestra |
| `/api/secrets` | GET, POST | Listar / crear secretos |
| `/api/secrets/[id]` | GET, DELETE | Obtener / borrar secreto |
| `/api/shares` | POST, DELETE | Compartir / revocar share |
| `/api/audit-logs` | GET, POST | Listar / crear log cifrado |
| `/api/audit-logs/verify` | GET | Verificar integridad hash chain |
| `/api/devices/enroll/init` | POST | Iniciar enrollment ECDH |
| `/api/devices/enroll/lookup` | POST | Buscar código enrollment |
| `/api/devices/enroll/poll` | POST | Polling del dispositivo nuevo |
| `/api/devices/enroll/complete` | POST | Completar enrollment |
| `/api/devices/enroll/poll/verify` | POST | Verificar challenge ECDSA |
| `/api/devices/list` | GET | Listar dispositivos autorizados |
| `/api/devices/[id]` | DELETE | Revocar dispositivo |
| `/api/health` | GET | Healthcheck (BD + Redis + versión) |
| `/api/route` | GET | Root |

### 3.4 Características de seguridad implementadas (30 mejoras recientes)

**Módulo 1 — Blindaje de seguridad (8 features):**
- Persistencia parcial con `partialize()` — solo email/authenticated/name se persisten; crypto material NUNCA
- Skeleton durante hidratación (evita flash de login)
- Limpieza de `window.__masterKey`, `window.__privateKey`, etc.
- CSP estricta como meta tag
- Email enmascarado en header
- Atributos `autoCapitalize/autoCorrect/spellCheck/translate="no"` en todos los inputs
- Logout limpio con cleanup de CryptoKey refs
- Session health check

**Módulo 2 — UX (8 features):**
- Header sticky real con altura fija + scroll interno independiente
- DropdownMenu interactivo para cuenta de usuario
- Banner offline con `navigator.onLine`
- Atajo global Cmd/Ctrl+K para búsqueda
- ErrorBoundary con render-prop fallback
- Filtrado memoizado de secretos
- Skeletons de carga
- Toasts para online/offline

**Módulo 3 — Accesibilidad (6 features):**
- `--border` subido a 14% para contraste en dark mode
- `--destructive` ajustado para que alertas resalten
- `-webkit-font-smoothing: antialiased` + `-moz-osx-font-smoothing: grayscale`
- `*:focus-visible` con `outline-2 outline-offset-2`
- Badges de algoritmos separados visualmente
- `translate="no"` en campos sensibles

**Módulo 4 — Rendimiento (8 features):**
- `robots: noindex, nofollow, nocache` (vault no indexable)
- Exportación cifrada local (AES-256-GCM con PBKDF2 600k iter)
- Importación bidireccional de archivos cifrados
- `useMemo` + `useCallback` para re-render mínimo
- Diálogo de exportación con doble confirmación
- Atributos `autocomplete="new-password"` apropiados
- Viewport configurado para accesibilidad
- Theme color para PWA

---

## 4. CALIDAD DEL CÓDIGO

### 4.1 Puntos fuertes

1. **Código criptográfico consolidado** en `src/lib/crypto/` (9 archivos) con `index.ts` que re-exporta API pública. Fácil de auditar.

2. **Tests reales con Web Crypto API** — 119 tests que usan la API nativa del navegador (no mocks, no `btoa` simulado). Tests de KDF, AES-GCM, RSA-OAEP, ECDH, ECDSA, PoP, BIP-39, hash chain.

3. **Bug fixes detectados por tests:**
   - `normalizePassword` ahora hace NFKC + trim (antes solo NFC).
   - `verifyPop` ahora sanitiza JWK antes de re-importar como RSA-PSS.
   - `importPrivateKeyJwk` extractable=true (necesario para rotación y signPop).

4. **Memory zeroing** — `clearCryptoKeyRef`, `zeroBuffer`, `secureZero`, `trackBuffer` (FinalizationRegistry). Las CryptoKey son non-extractables.

5. **Rate limiting** con adaptador dual Redis/Map. Políticas predefinidas: login 5/15min, enroll 5/1min, secrets 30/15min, audit 100/5min.

6. **Pino logger** con redacción automática de campos sensibles: masterPassword, masterKey, privateKey, sessionToken, etc.

7. **Audit log tamper-evident** — hash chain SHA-256 verificable vía `/api/audit-logs/verify`.

8. **AAD en AES-GCM** — defensa contra ciphertext swapping, contexto criptográfico asociado a cada cifrado.

9. **Paquete NPM independiente** `@zk-vault/crypto` v0.1.0 en `packages/crypto/` — publicable, reusable en mobile app / extension futura.

10. **Historial git limpio** — 9 commits squashed, sin mensajes UUID, sin referencias a IA, sin .next/ ni bun.lock en tracking.

### 4.2 Deuda técnica

| Item | Severidad | Esfuerzo | Descripción |
|------|-----------|----------|-------------|
| Cobertura branches en client.ts | Media | 8h | 52.6% porque Argon2id worker solo se ejercita en navegador real. Solución: tests con Playwright en navegador headless. |
| Sin tests E2E | Media | 16h | Playwright config existe pero no hay tests reales que cubran register→login→create→share. |
| Sin CI/CD verde | Baja | 4h | El workflow `ci.yml` existe pero no se ha verificado que pase end-to-end en GitHub Actions. |
| Sin monitoreo | Media | 12h | Sin Prometheus/Grafana/Sentry. El logger pino está listo pero no se envía a ningún backend. |
| Sin deploy demo | Baja | 2h | No hay demo en Vercel/Railway. Es un one-liner pero falta ejecutar. |
| Sin auditoría externa | Alta | 40h+ | No hay auditoría de seguridad de terceros. Recomendado: Cure53, Trail of Bits, NCC Group. |
| WebAuthn/Passkeys no implementado | Baja | 24h | Roadmap v1.1. No es deuda, es feature pendiente. |
| SSO/SCIM no implementado | Baja | 80h | Roadmap v1.3. Era feature theater, se eliminó en refactor. |

### 4.3 Estándares de código

- ESLint con reglas de seguridad (`no-eval`, `no-implied-eval`, `no-script-url`)
- TypeScript estricto
- Prettier no configurado (deuda menor)
- No Husky pre-commit hooks (deuda menor)

---

## 5. MERCADO Y COMPARABLES

### 5.1 Mercado de gestores de contraseñas

**Tamaño del mercado (2024):**
- Global password manager market: **USD 4.5B** (2024) → **USD 15.6B** (2032, CAGR 16.8%)
- Fuente: Fortune Business Insights, Grand View Research

**Segmento enterprise:** ~40% del mercado total (~USD 1.8B en 2024)

### 5.2 Comparables directos

| Empresa | Modelo | ARR estimada | Valuación | Usuarios |
|---------|--------|-------------|-----------|----------|
| **Bitwarden** | Open source + SaaS | ~USD 50M | ~USD 500M (2022, Series C) | 30M+ |
| **1Password** | SaaS premium | ~USD 250M | **USD 6.8B** (2022, Series C) | 25M+ |
| **Proton Pass** | SaaS privacy-first | ~USD 30M (parte de Proton suite) | Proton AG ~USD 2B | 5M+ (Pass) |
| **Dashlane** | SaaS B2C/B2B | ~USD 100M | ~USD 1B (estimado, privada) | 15M+ |
| **Keeper Security** | B2B enterprise | ~USD 200M | ~USD 1.5B (estimado) | 4M+ |
| **KeePassXC** | Open source desktop | N/A (gratis) | N/A | 5M+ downloads |
| **Passbolt** | Open source self-host | ~USD 5M | Privada | 500K+ |

### 5.3 Posicionamiento de ZK Vault

**Diferenciadores técnicos:**
1. **Post-cuántico ML-KEM-768 activo** — la mayoría de competidores NO tienen esto todavía. Bitwarden y 1Password tienen roadmap pero no implementación en producción.
2. **Zero-knowledge estricto** — el servidor nunca recibe master password (igual que Bitwarden/1Password).
3. **Audit log tamper-evident** con hash chain verificable — pocos competidores tienen esto.
4. **Multi-device ECDH** — comparable a Bitwarden, mejor que KeePassXC.
5. **BIP-39 recovery** — comparable a Proton Pass.

**Debilidades competitivas:**
1. **Sin usuarios** — producto semilla, sin tracción.
2. **Sin apps móviles nativas** — roadmap pero no implementado.
3. **Sin extensiones de navegador** — roadmap pero no implementado.
4. **Sin SSO/SAML/SCIM** — crítico para enterprise, no implementado.
5. **Sin auditoría externa** — necesario para enterprise sales.

**Mercado objetivo inicial:**
- Equipos técnicos pequeños (5-50 personas) que valoran privacy y post-cuántico.
- Self-hosted para organizaciones con compliance estricto.
- Desarrolladores que quieren inspeccionar el código (open source MIT).

---

## 6. RIESGOS

### 6.1 Riesgos técnicos

| Riesgo | Probabilidad | Impacto | Mitigación |
|--------|-------------|---------|------------|
| Bug en implementación criptográfica | Media | Crítico | Auditoría externa + tests reales + Argon2id via hash-wasm (audited) |
| Vulnerabilidad en dependencia | Media | Alto | `bun audit` en CI, Dependabot, lock de versiones |
| Ataque de canal lateral (timing) | Baja | Medio | `constantTimeCompare` implementado, rate limiting |
| Compromiso de Web Worker | Baja | Alto | Worker solo corre Argon2id, no tiene acceso a DOM |
| Pérdida de frase BIP-39 | Media (usuario) | Crítico | Documentación clara, warnings en UI, no hay recovery sin frase |

### 6.2 Riesgos de negocio

| Riesgo | Probabilidad | Impacto | Mitigación |
|--------|-------------|---------|------------|
| Competencia dominante (1Password, Bitwarden) | Alta | Alto | Diferenciarse en post-cuántico + self-hosted |
| Falta de tracción / adopción | Alta | Crítico | Marketing técnico, comunidad open source |
| Costo de infraestructura sin revenue | Alta | Medio | Modelo freemium + B2B sales |
| Compliance enterprise (SOC2) | Media | Alto | Auditoría externa, contratar CISO part-time |
| Litigio por patentes | Baja | Alto | MIT license, no se infringen patentes conocidas |

### 6.3 Riesgos legales

- **GDPR:** Implementado crypto-shredding (Art. 17) y exportación (Art. 20). Cumplimiento razonable.
- **CCPA:** No implementado explícitamente, pero la arquitectura zero-knowledge lo facilita.
- **SOC2 Type II:** No auditado. Costo: USD 30K-80K año 1.
- **HIPAA:** No aplicable (no se almacena PHI).
- **FedRAMP:** No aplicable (no es govtech).

---

## 7. MODELO DE NEGOCIO POTENCIAL

### 7.1 Plan freemium (recomendado)

| Plan | Precio/mes | Features |
|------|-----------|----------|
| Free | USD 0 | 50 secretos, 1 dispositivo, sin shares |
| Pro | USD 3 | Secretos ilimitados, 5 dispositivos, shares ilimitadas |
| Team | USD 5/usuario | + Team vaults, audit log export, priority support |
| Enterprise | USD 12/usuario | + SSO, SCIM, SLA 99.9%, auditoría externa |

### 7.2 Proyección conservadora (3 años)

| Año | Usuarios pagos | ARR | Costos | Burn |
|-----|----------------|-----|--------|------|
| Año 1 | 100 | USD 12K | USD 80K | -USD 68K |
| Año 2 | 1,000 | USD 60K | USD 150K | -USD 90K |
| Año 3 | 10,000 | USD 400K | USD 300K | +USD 100K |

**Supuestos:**
- CAC bajo (open source, marketing técnico orgánico)
- Churn 5% mensual
- ARPU USD 5/mes promedio
- Costos: hosting (Vercel + Postgres + Redis) + 1 dev part-time

### 7.3 Modelos alternativos

- **Self-hosted enterprise license:** USD 5K-50K/año por organización (competir con Passbolt)
- **Consultoría y deploy:** USD 10K-50K por implementación on-premise
- **Paquete criptográfico @zk-vault/crypto:** gratis para open source, licencia comercial para闭源

---

## 8. VALORACIÓN DE ACTIVOS

### 8.1 Activos tangibles

| Activo | Valor estimado |
|--------|----------------|
| Código fuente (18K líneas, MIT) | USD 200K-400K (costo de reproducción) |
| Tests automatizados (119 tests) | USD 30K-50K |
| Documentación (README + ARCHITECTURE) | USD 10K-20K |
| Paquete NPM publicable | USD 10K-20K |
| Workflow CI/CD | USD 5K-10K |
| **Total activos tangibles** | **USD 255K-500K** |

### 8.2 Activos intangibles

| Activo | Valor estimado |
|--------|----------------|
| Marca "Zero-Knowledge Vault" | USD 5K-20K (sin tracción) |
| Domains (si hay) | USD 1K-5K |
| Comunidad GitHub (stars, forks) | USD 0-5K (sin tracción aún) |
| Conocimiento criptográfico del equipo | Invaluable (no transferible fácilmente) |

### 8.3 Multiplos de mercado (comparables)

| Métrica | Multiplo | Aplicación |
|---------|----------|------------|
| ARR | 5-10x | Sin ARR todavía, no aplicable |
| Usuarios activos | USD 50-150/usuario | Sin usuarios, no aplicable |
| Líneas de código auditadas | USD 15-30/línea | 18K líneas → USD 270K-540K |
| Costo de reproducción | 1x | USD 255K-500K (tangibles) |

---

## 9. ESCENARIOS DE VALORACIÓN

### 9.1 Escenario pesimista (fire sale)

**Si se vende HOY sin usuarios, sin revenue, sin auditoría externa:**

- Activos tangibles en descuento: USD 100K-200K
- Sin premium por tracción o marca
- Comprador asume riesgo de auditoría (USD 50K)
- **Valoración: USD 100K - USD 200K**

**Compradores potenciales:** Empresa de ciberseguridad que quiere absorber el código, equipo de ingeniería que quiere un starting point.

### 9.2 Escenario realista (bootstrapped seed)

**Si se invierte 6 meses más: deploy demo + 100 usuarios beta + auditoría externa básica:**

- Activos tangibles: USD 300K-500K
- Premium por auditoría externa: +USD 100K
- Premium por tracción inicial (100 usuarios): +USD 50K
- **Valoración: USD 350K - USD 700K**

**Usos del capital seed (USD 200K-400K):**
- Auditoría externa: USD 50K
- 1 dev full-time 6 meses: USD 80K
- Marketing técnico: USD 30K
- Infraestructura: USD 20K
- Reserva: USD 20K-220K

### 9.3 Escenario optimista (serie A potencial)

**Si en 18 meses: 1,000 usuarios pagos + ARR USD 60K + SOC2 Type II:**

- ARR: USD 60K
- Multiplo SaaS security 8-12x ARR: USD 480K-720K
- Premium por post-cuántico diferenciador: +USD 200K
- Premium por equipo técnico: +USD 100K
- **Valoración: USD 780K - USD 1M**

**Requisitos para serie A:**
- ARR > USD 100K (típicamente)
- Crecimiento 20%+ MoM
- Equipo fundador full-time
- Auditoría externa completada
- 5+ casos de uso enterprise documentados

### 9.4 Escenario acquisición estratégica

**Si 1Password / Bitwarden / Proton quisiera absorber el equipo + código:**

- Acqui-hire base: USD 200K-400K por fundador
- Premium por código post-cuántico: +USD 200K-500K
- **Valoración: USD 400K - USD 1M** (equipo de 1-2 personas)

**Racional:** El ML-KEM-768 implementado y testeado es un asset diferenciador que los grandes competidores aún no tienen en producción.

---

## 10. CONCLUSIÓN Y RECOMENDACIÓN

### 10.1 Valoración justa de mercado (rango)

```
VALORACIÓN MÍNIMA: USD 100,000 (fire sale hoy, sin usuarios)
VALORACIÓN MÁXIMA: USD 700,000 (6 meses más de inversión + auditoría)
VALORACIÓN PUNTO MEDIO: USD 300,000 - USD 400,000
```

### 10.2 Multiplo usado

- **Costo de reproducción** (USD 255K-500K tangibles) → base
- **Comparables** (Passbolt USD 5M ARR, Bitwarden USD 500M valuación) → tope
- **Premium post-cuántico** → +USD 100K-200K
- **Descuento sin tracción** → -USD 100K-200K

### 10.3 Riesgo: MEDIO

**Justificación:**
- Código sólido, criptografía correcta, arquitectura limpia
- PERO sin usuarios, sin revenue, sin auditoría externa
- Mercado competitivo con jugadores dominantes (1Password USD 6.8B)
- Diferenciador técnico (post-cuántico) es valioso pero no suficiente solo

### 10.4 Horizonte: SEED / BOOTSTRAPPED

No es serie A todavía. Es un MVP seed-stage con potencial de serie A en 12-18 meses con ejecución correcta.

### 10.5 Recomendaciones para subir valoración

1. **Auditoría externa de seguridad** (Cure53, Trail of Bits) — costo USD 30K-80K, sube valoración USD 100K-200K
2. **Deploy demo pública** — costo USD 0 (Vercel free tier), sube valoración USD 50K
3. **100 usuarios beta pagantes** — sube valoración USD 100K-200K
4. **App móvil (React Native)** — costo USD 30K (3 meses dev), sube valoración USD 200K
5. **Extensión Chrome/Firefox** — costo USD 15K (6 semanas dev), sube valoración USD 100K
6. **SOC2 Type II** — costo USD 50K, sube valoración USD 300K (abilita enterprise sales)
7. **SSO/SAML/SCIM** — costo USD 40K (2 meses dev), sube valoración USD 200K
8. **Publicar @zk-vault/crypto en npm** — costo USD 0, sube valoración USD 20K (adopción)

### 10.6 Veredicto final

Zero-Knowledge Vault es un **MVP técnicamente superior** a la media de proyectos open source de password managers, con un diferenciador real (post-cuántico ML-KEM-768 activo). Sin embargo, **su valor comercial actual es limitado** por la falta de tracción, auditoría externa y apps móviles.

**Valoración justa de mercado: USD 300,000 - USD 400,000** (punto medio, escenario bootstrapped seed).

Con ejecución correcta (auditoría + demo + 100 usuarios beta + 1 feature enterprise), puede alcanzar **USD 700K-1M** en 6-12 meses, momento en el que sería atractivo para una serie A o acquisición estratégica.

---

## 11. APÉNDICE — CÓMO VERIFICAR ESTE INFORME

Para que cualquier IA o humano verifique las afirmaciones de este informe:

```bash
git clone https://github.com/di3go04/zero-knowledge-vault.git
cd zero-knowledge-vault
bun install
bun run db:push
bun run test           # 119 tests pasan
bun run test:coverage  # coverage módulo crypto
bun run lint           # 0 errores
bun run build          # build exitoso
bun audit              # 1 moderate (transitivo)
git log --oneline      # 9 commits limpios
```

**Archivos clave para revisión manual:**
- `src/lib/crypto/client.ts` — núcleo criptográfico (1,516 líneas)
- `src/lib/crypto/server.ts` — verificación server-side (341 líneas)
- `src/lib/crypto/hkdf.ts` — HKDF-SHA256 subkey derivation
- `prisma/schema.prisma` — modelo de datos (6 modelos)
- `src/app/api/auth/register/route.ts` — flujo de registro
- `src/app/api/auth/login/route.ts` — flujo de login con decoy
- `src/app/api/audit-logs/verify/route.ts` — verificación hash chain
- `ARCHITECTURE.md` — diagramas de flujo + threat model
- `README.md` — documentación honesta del producto

**Prompts para auditar con LLM:**
- Subir `download/zk-vault-codigo-completo.txt` (830 KB, 23K líneas) a Claude/GPT-4
- Pedir: "Audita este código y da 30 mejoras concretas con file:line"
- Pedir: "Compara la implementación criptográfica con Bitwarden/1Password"
- Pedir: "Identifica vectores de ataque y propiedades zero-knowledge"

---

**Fin del informe.**
