/**
 * secret-templates.ts — Plantillas predefinidas para crear secretos.
 *
 */

export interface SecretTemplate {
  id: string;
  label: string;
  icon: string;
  fields: { key: string; label: string; type: "text" | "password" | "url" }[];
  generateContent: (values: Record<string, string>) => string;
}

export const SECRET_TEMPLATES: SecretTemplate[] = [
  {
    id: "aws",
    label: "AWS Credentials",
    icon: "☁️",
    fields: [
      { key: "accessKeyId", label: "Access Key ID", type: "text" },
      { key: "secretAccessKey", label: "Secret Access Key", type: "password" },
      { key: "region", label: "Region", type: "text" },
    ],
    generateContent: (v) =>
      `AWS_ACCESS_KEY_ID=${v.accessKeyId}\nAWS_SECRET_ACCESS_KEY=${v.secretAccessKey}\nAWS_DEFAULT_REGION=${v.region}`,
  },
  {
    id: "database",
    label: "Database Connection",
    icon: "🗄️",
    fields: [
      { key: "host", label: "Host", type: "text" },
      { key: "port", label: "Port", type: "text" },
      { key: "user", label: "Username", type: "text" },
      { key: "password", label: "Password", type: "password" },
      { key: "database", label: "Database", type: "text" },
    ],
    generateContent: (v) =>
      `host: ${v.host}\nport: ${v.port}\nuser: ${v.user}\npassword: ${v.password}\ndatabase: ${v.database}`,
  },
  {
    id: "ssh",
    label: "SSH Key",
    icon: "🔑",
    fields: [
      { key: "host", label: "Host", type: "text" },
      { key: "user", label: "Username", type: "text" },
      { key: "privateKey", label: "Private Key", type: "password" },
    ],
    generateContent: (v) =>
      `Host: ${v.host}\nUser: ${v.user}\nPrivate Key:\n${v.privateKey}`,
  },
  {
    id: "apikey",
    label: "API Key",
    icon: "🔌",
    fields: [
      { key: "service", label: "Service", type: "text" },
      { key: "key", label: "API Key", type: "password" },
      { key: "url", label: "Base URL", type: "url" },
    ],
    generateContent: (v) =>
      `Service: ${v.service}\nAPI Key: ${v.key}\nBase URL: ${v.url}`,
  },
  {
    id: "custom",
    label: "Custom",
    icon: "📝",
    fields: [],
    generateContent: () => "",
  },
];
