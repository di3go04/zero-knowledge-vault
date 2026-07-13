/**
 * GET /api/docs/openapi.json — Especificación OpenAPI 3.0 completa.
 *
 */
import { NextResponse } from "next/server";

const spec = {
  openapi: "3.0.3",
  info: {
    title: "Zero-Knowledge Vault API",
    version: "1.0.0",
    description: "Gestor de contraseñas Zero-Knowledge. El servidor es un crypto-blind store — nunca recibe contraseñas maestras, llaves privadas en claro, ni contenido de secretos.",
    contact: { name: "ZK Vault Team" },
    license: { name: "MIT" },
  },
  servers: [{ url: "/api", description: "API base" }],
  tags: [
    { name: "Auth", description: "Autenticación y gestión de cuenta" },
    { name: "Secrets", description: "Gestión de secretos cifrados" },
    { name: "Shares", description: "Compartir secretos entre usuarios" },
    { name: "Devices", description: "Multi-Device Sync con ECDH" },
    { name: "Audit", description: "Logs de auditoría cifrados" },
    { name: "Ops", description: "Operaciones del sistema" },
  ],
  components: {
    securitySchemes: {
      bearerAuth: { type: "http", scheme: "bearer", bearerFormat: "JWT" },
    },
  },
  paths: {
    "/auth/register": {
      post: {
        tags: ["Auth"],
        summary: "Registrar usuario con Proof-of-Possession RSA-PSS",
        description: "El cliente deriva masterKey con Argon2id, genera par RSA-OAEP 2048, cifra privateKey con masterKey, firma PoP con RSA-PSS.",
        requestBody: { required: true, content: { "application/json": { schema: { type: "object", properties: {
          email: { type: "string", format: "email" },
          kdfAlgorithm: { type: "string", enum: ["argon2id", "pbkdf2"] },
          kdfSalt: { type: "string", description: "base64, 16-64 bytes" },
          kdfIterations: { type: "integer" },
          kdfMemoryKiB: { type: "integer" },
          kdfParallelism: { type: "integer" },
          publicKeyJwk: { type: "object" },
          popSignature: { type: "string", description: "base64 RSA-PSS" },
          encryptedPrivateKeyJwk: { type: "string", description: "base64 AES-256-GCM" },
          privateKeyIv: { type: "string", description: "base64 12 bytes" },
        } } } } },
        responses: { "200": { description: "Registro exitoso" }, "403": { description: "PoP inválida" }, "409": { description: "Email ya registrado" } },
      },
    },
    "/auth/login": {
      post: {
        tags: ["Auth"],
        summary: "Login + emisión de sessionToken HS256",
        description: "Solo recibe { email }. Devuelve material criptográfico público + sessionToken. El cliente descifra localmente.",
        requestBody: { required: true, content: { "application/json": { schema: { type: "object", properties: { email: { type: "string" } } } } } },
        responses: { "200": { description: "Material + token" }, "429": { description: "Rate limited (5/15min)" } },
      },
    },
    "/auth/logout": {
      post: { tags: ["Auth"], summary: "Revocar token en Redis blacklist", security: [{ bearerAuth: [] }], responses: { "200": { description: "Token revocado" } } },
    },
    "/auth/rotate": {
      post: { tags: ["Auth"], summary: "Rotar contraseña maestra", security: [{ bearerAuth: [] }], responses: { "200": { description: "Rotación exitosa" }, "403": { description: "PoP inválida" } } },
    },
    "/auth/recovery/setup": {
      post: { tags: ["Auth"], summary: "Configurar backup BIP-39", security: [{ bearerAuth: [] }], responses: { "200": { description: "Backup configurado" } } },
    },
    "/auth/recovery/recover": {
      post: { tags: ["Auth"], summary: "Recuperar cuenta con frase BIP-39", responses: { "200": { description: "Cuenta recuperada" }, "429": { description: "Rate limited (3/hora)" } } },
    },
    "/secrets": {
      get: { tags: ["Secrets"], summary: "Listar secretos propios + compartidos", security: [{ bearerAuth: [] }], responses: { "200": { description: "Lista de secretos cifrados" } } },
      post: { tags: ["Secrets"], summary: "Crear secreto cifrado AES-256-GCM", security: [{ bearerAuth: [] }], responses: { "200": { description: "Secreto creado" } } },
    },
    "/secrets/{id}": {
      delete: { tags: ["Secrets"], summary: "Borrar secreto (owner-only, cascade)", security: [{ bearerAuth: [] }], parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }], responses: { "200": { description: "Secreto borrado" }, "404": { description: "No encontrado" } } },
    },
    "/shares": {
      post: { tags: ["Shares"], summary: "Compartir secreto (RSA-OAEP wrap)", security: [{ bearerAuth: [] }], responses: { "200": { description: "Secreto compartido" } } },
      delete: { tags: ["Shares"], summary: "Revocar share (offboarding)", security: [{ bearerAuth: [] }], responses: { "200": { description: "Share revocado" } } },
    },
    "/devices/enroll/init": {
      post: { tags: ["Devices"], summary: "Iniciar enrollment (Dispositivo B)", responses: { "200": { description: "enrollCode + deviceId" } } },
    },
    "/devices/enroll/complete": {
      post: { tags: ["Devices"], summary: "Completar enrollment (Dispositivo A)", security: [{ bearerAuth: [] }], responses: { "200": { description: "Dispositivo autorizado" } } },
    },
    "/devices/enroll/lookup": {
      get: { tags: ["Devices"], summary: "Buscar dispositivo por enrollCode", security: [{ bearerAuth: [] }], parameters: [{ name: "code", in: "query", required: true, schema: { type: "string" } }], responses: { "200": { description: "Dispositivo encontrado" } } },
    },
    "/devices/enroll/poll": {
      post: { tags: ["Devices"], summary: "Obtener challenge ECDSA P-256", responses: { "200": { description: "Challenge nonce 32 bytes" } } },
    },
    "/devices/enroll/poll/verify": {
      post: { tags: ["Devices"], summary: "Verificar challenge-response ECDSA", responses: { "200": { description: "wrappedPrivateKey + enrollerPublicKeyECDH" }, "429": { description: "Rate limited (5/min)" } } },
    },
    "/devices/list": {
      get: { tags: ["Devices"], summary: "Listar dispositivos autorizados", security: [{ bearerAuth: [] }], responses: { "200": { description: "Lista de dispositivos" } } },
    },
    "/devices/{id}": {
      delete: { tags: ["Devices"], summary: "Revocar dispositivo", security: [{ bearerAuth: [] }], parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }], responses: { "200": { description: "Dispositivo revocado" } } },
    },
    "/users/lookup": {
      get: { tags: ["Auth"], summary: "Buscar usuario por email (devuelve publicKey)", parameters: [{ name: "email", in: "query", required: true, schema: { type: "string" } }], responses: { "200": { description: "userId + publicKeyJwk + fingerprint" } } },
    },
    "/users/list": {
      get: { tags: ["Auth"], summary: "Listar usuarios del equipo", security: [{ bearerAuth: [] }], responses: { "200": { description: "Lista de usuarios" } } },
    },
    "/audit-logs": {
      get: { tags: ["Audit"], summary: "Listar logs cifrados", security: [{ bearerAuth: [] }], responses: { "200": { description: "Logs cifrados" } } },
      post: { tags: ["Audit"], summary: "Crear log cifrado", security: [{ bearerAuth: [] }], responses: { "200": { description: "Log creado" } } },
    },
    "/health": {
      get: { tags: ["Ops"], summary: "Healthcheck (BD + Redis)", responses: { "200": { description: "Healthy" }, "503": { description: "Degraded" } } },
    },
    "/metrics": {
      get: { tags: ["Ops"], summary: "Métricas Prometheus", responses: { "200": { description: "Métricas JSON" } } },
    },
  },
};

export async function GET() {
  return NextResponse.json(spec);
}
