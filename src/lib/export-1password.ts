/**
 * Export to 1Password format — convierte secretos a CSV 1Password.
 * El cliente descifra los secretos localmente y genera el CSV.
 */
export function secretsTo1PasswordCsv(secrets: Array<{ title: string; content: string }>): string {
  const headers = ["Title", "Username", "Password", "URL", "Notes"];
  const rows = secrets.map((s) => {
    // Intentar parsear el contenido como user/pass
    const lines = s.content.split("\n");
    let username = "";
    let password = "";
    let url = "";
    const notes: string[] = [];

    for (const line of lines) {
      const lower = line.toLowerCase().trim();
      if (lower.startsWith("user:") || lower.startsWith("username:")) {
        username = line.split(":").slice(1).join(":").trim();
      } else if (lower.startsWith("pass:") || lower.startsWith("password:")) {
        password = line.split(":").slice(1).join(":").trim();
      } else if (lower.startsWith("url:") || lower.startsWith("host:")) {
        url = line.split(":").slice(1).join(":").trim();
      } else {
        notes.push(line);
      }
    }

    return [s.title, username, password, url, notes.join("\n")];
  });

  const csv = [headers, ...rows]
    .map((row) => row.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(","))
    .join("\n");

  return csv;
}
