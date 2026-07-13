/**
 * input-sanitizer.ts — Sanitización de inputs del cliente.
 */

export function sanitizeEmail(email: string): string {
  return email.toLowerCase().trim().slice(0, 320);
}

export function sanitizeDeviceName(name: string): string {
  return name.trim().slice(0, 80).replace(/[<>]/g, "");
}

export function sanitizeSecretTitle(title: string): string {
  return title.trim().slice(0, 120).replace(/[<>]/g, "");
}

export function sanitizeSecretContent(content: string): string {
  return content.slice(0, 64 * 1024); // max 64 KiB
}

export function sanitizeCommentText(text: string): string {
  return text.trim().slice(0, 4096);
}

export function sanitizeVaultName(name: string): string {
  return name.trim().slice(0, 80).replace(/[<>]/g, "");
}
