/**
 * openapi-spec.ts — Especificación OpenAPI 3.0 de los 16+ endpoints.
 *
 */
export const openApiSpec = {
  openapi: "3.0.3",
  info: {
    title: "Zero-Knowledge Vault API",
    version: "1.0.0",
    description: "Gestor de contraseñas Zero-Knowledge. El servidor es un crypto-blind store.",
  },
  servers: [{ url: "/api", description: "API base" }],
  paths: {
    "/auth/register": {
      post: {
        summary: "Registrar usuario con PoP RSA-PSS",
        tags: ["Auth"],
        requestBody: { required: true, content: { "application/json": { schema: { type: "object" } } } },
        responses: { "200": { description: "Registro exitoso" }, "403": { description: "PoP inválida" } },
      },
    },
    "/auth/login": {
      post: {
        summary: "Login + emisión de sessionToken HS256",
        tags: ["Auth"],
        responses: { "200": { description: "Material criptográfico + token" }, "429": { description: "Rate limited" } },
      },
    },
    "/auth/logout": {
      post: { summary: "Revocar token (Redis blacklist)", tags: ["Auth"], security: [{ bearerAuth: [] }] },
    },
    "/auth/rotate": {
      post: { summary: "Rotar contraseña maestra", tags: ["Auth"], security: [{ bearerAuth: [] }] },
    },
    "/secrets": {
      get: { summary: "Listar secretos propios + compartidos", tags: ["Secrets"], security: [{ bearerAuth: [] }] },
      post: { summary: "Crear secreto cifrado", tags: ["Secrets"], security: [{ bearerAuth: [] }] },
    },
    "/secrets/{id}": {
      delete: { summary: "Borrar secreto (owner-only)", tags: ["Secrets"], security: [{ bearerAuth: [] }] },
    },
    "/shares": {
      post: { summary: "Compartir secreto", tags: ["Shares"], security: [{ bearerAuth: [] }] },
      delete: { summary: "Revocar share", tags: ["Shares"], security: [{ bearerAuth: [] }] },
    },
    "/devices/enroll/init": { post: { summary: "Iniciar enrollment (Dispositivo B)", tags: ["Devices"] } },
    "/devices/enroll/complete": { post: { summary: "Completar enrollment (Dispositivo A)", tags: ["Devices"], security: [{ bearerAuth: [] }] } },
    "/devices/enroll/poll": { post: { summary: "Obtener challenge ECDSA", tags: ["Devices"] } },
    "/devices/enroll/poll/verify": { post: { summary: "Verificar challenge-response", tags: ["Devices"] } },
    "/audit-logs": {
      get: { summary: "Listar logs cifrados", tags: ["Audit"], security: [{ bearerAuth: [] }] },
      post: { summary: "Crear log cifrado", tags: ["Audit"], security: [{ bearerAuth: [] }] },
    },
    "/health": { get: { summary: "Healthcheck", tags: ["Ops"] } },
    "/metrics": { get: { summary: "Métricas Prometheus", tags: ["Ops"] } },
  },
  components: {
    securitySchemes: {
      bearerAuth: { type: "http", scheme: "bearer", bearerFormat: "JWT" },
    },
  },
};
