/**
 * Email templates — plantillas para notificaciones.
 * Los emails se envían vía SendGrid/Resend/etc (configurable).
 * El contenido NUNCA incluye secretos — solo notificaciones.
 */

export interface EmailTemplate {
  subject: string;
  html: string;
  text: string;
}

export function welcomeEmail(name: string | null, email: string): EmailTemplate {
  return {
    subject: "Bienvenido a Zero-Knowledge Vault",
    html: `<h1>¡Bienvenido${name ? `, ${name}` : ""}!</h1><p>Tu cuenta en Zero-Knowledge Vault ha sido creada. Tu bóveda está cifrada con AES-256-GCM y Argon2id. El servidor nunca tiene acceso a tus secretos.</p><p>Guarda tu contraseña maestra en un lugar seguro — no podemos recuperarla por ti.</p>`,
    text: `Bienvenido${name ? `, ${name}` : ""}! Tu cuenta en ZK Vault ha sido creada. Guarda tu contraseña maestra — no podemos recuperarla.`,
  };
}

export function shareNotificationEmail(recipientEmail: string, senderEmail: string): EmailTemplate {
  return {
    subject: `${senderEmail} ha compartido un secreto contigo`,
    html: `<h1>Nuevo secreto compartido</h1><p><strong>${senderEmail}</strong> ha compartido un secreto contigo en Zero-Knowledge Vault.</p><p>Inicia sesión para verlo.</p>`,
    text: `${senderEmail} ha compartido un secreto contigo. Inicia sesión para verlo.`,
  };
}

export function deviceAuthorizedEmail(email: string, deviceName: string): EmailTemplate {
  return {
    subject: `Nuevo dispositivo autorizado: ${deviceName}`,
    html: `<h1>Dispositivo autorizado</h1><p>Se ha autorizado <strong>${deviceName}</strong> para acceder a tu cuenta.</p><p>Si no fuiste tú, revoca el dispositivo inmediatamente.</p>`,
    text: `Dispositivo autorizado: ${deviceName}. Si no fuiste tú, revócalo inmediatamente.`,
  };
}

export function trialExpiringEmail(email: string, daysLeft: number): EmailTemplate {
  return {
    subject: `Tu prueba gratuita expira en ${daysLeft} días`,
    html: `<h1>Tu prueba expira pronto</h1><p>Tu prueba gratuita de Zero-Knowledge Vault expira en ${daysLeft} días.</p><p>Actualiza tu plan para seguir usando todas las funciones.</p>`,
    text: `Tu prueba gratuita expira en ${daysLeft} días. Actualiza tu plan.`,
  };
}
