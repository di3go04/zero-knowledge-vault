/**
 * Bulk import from CSV — importa secretos desde CSV genérico.
 * El cliente parsea el CSV y cifra cada fila antes de enviar.
 */
export interface CsvSecret {
  title: string;
  content: string;
}

export function parseSecretsCsv(csv: string): CsvSecret[] {
  const lines = csv.split("\n").filter((l) => l.trim());
  if (lines.length < 2) return [];

  // Asumir primera línea = headers
  const headers = parseCsvLine(lines[0]).map((h) => h.toLowerCase().trim());
  const secrets: CsvSecret[] = [];

  for (let i = 1; i < lines.length; i++) {
    const fields = parseCsvLine(lines[i]);
    const title = fields[0] || `Importado ${i}`;
    const content = headers
      .map((h, idx) => `${h}: ${fields[idx] || ""}`)
      .join("\n");
    secrets.push({ title, content });
  }

  return secrets;
}

function parseCsvLine(line: string): string[] {
  const result: string[] = [];
  let current = "";
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    if (char === '"') {
      if (inQuotes && line[i + 1] === '"') {
        current += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (char === "," && !inQuotes) {
      result.push(current);
      current = "";
    } else {
      current += char;
    }
  }
  result.push(current);
  return result.map((s) => s.trim());
}
