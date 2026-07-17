import { db } from "@/lib/db";

export interface CsvRecord {
  title: string;
  username: string;
  password: string;
  url: string;
  notes: string;
}

type PasswordManagerSource = "bitwarden" | "1password" | "dashlane" | "lastpass" | "proton-pass" | "keeper";

export function parseCsv(text: string, source: PasswordManagerSource): CsvRecord[] {
  switch (source) {
    case "bitwarden":
      return parseBitwardenCsv(text);
    case "1password":
      return parse1PasswordCsv(text);
    case "dashlane":
      return parseDashlaneCsv(text);
    case "lastpass":
      return parseLastPassCsv(text);
    case "proton-pass":
      return parseProtonPassCsv(text);
    case "keeper":
      return parseKeeperCsv(text);
    default:
      throw new Error(`Unsupported source: ${source}`);
  }
}

function splitCsvLine(line: string): string[] {
  const result: string[] = [];
  let current = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && i + 1 < line.length && line[i + 1] === '"') {
        current += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (ch === "," && !inQuotes) {
      result.push(current.trim());
      current = "";
    } else {
      current += ch;
    }
  }
  result.push(current.trim());
  return result;
}

function parseBitwardenCsv(text: string): CsvRecord[] {
  const lines = text.trim().split(/\r?\n/);
  if (lines.length < 2) return [];
  const header = splitCsvLine(lines[0].toLowerCase());
  const nameIdx = header.indexOf("name");
  const usernameIdx = header.indexOf("username");
  const passwordIdx = header.indexOf("password");
  const urlIdx = header.indexOf("login_uri") !== -1 ? header.indexOf("login_uri") : header.indexOf("url");
  const notesIdx = header.indexOf("notes");

  return lines.slice(1).filter((l) => l.trim()).map((line) => {
    const cols = splitCsvLine(line);
    return {
      title: cols[nameIdx] || "",
      username: cols[usernameIdx] || "",
      password: cols[passwordIdx] || "",
      url: cols[urlIdx] || "",
      notes: cols[notesIdx] || "",
    };
  });
}

function parse1PasswordCsv(text: string): CsvRecord[] {
  const lines = text.trim().split(/\r?\n/);
  if (lines.length < 2) return [];
  const header = splitCsvLine(lines[0].toLowerCase());
  const titleIdx = header.indexOf("title");
  const usernameIdx = header.indexOf("username");
  const passwordIdx = header.indexOf("password");
  const urlIdx = header.indexOf("url");
  const notesIdx = header.indexOf("notes");

  return lines.slice(1).filter((l) => l.trim()).map((line) => {
    const cols = splitCsvLine(line);
    return {
      title: cols[titleIdx] || "",
      username: cols[usernameIdx] || "",
      password: cols[passwordIdx] || "",
      url: cols[urlIdx] || "",
      notes: cols[notesIdx] || "",
    };
  });
}

function parseDashlaneCsv(text: string): CsvRecord[] {
  const lines = text.trim().split(/\r?\n/);
  if (lines.length < 2) return [];
  const header = splitCsvLine(lines[0].toLowerCase());
  const titleIdx = header.indexOf("title") !== -1 ? header.indexOf("title") : header.indexOf("name");
  const usernameIdx = header.indexOf("username") !== -1 ? header.indexOf("username") : header.indexOf("login");
  const passwordIdx = header.indexOf("password");
  const urlIdx = header.indexOf("url") !== -1 ? header.indexOf("url") : header.indexOf("website");
  const notesIdx = header.indexOf("notes");

  return lines.slice(1).filter((l) => l.trim()).map((line) => {
    const cols = splitCsvLine(line);
    return {
      title: cols[titleIdx] || "",
      username: cols[usernameIdx] || "",
      password: cols[passwordIdx] || "",
      url: cols[urlIdx] || "",
      notes: cols[notesIdx] || "",
    };
  });
}

function parseLastPassCsv(text: string): CsvRecord[] {
  const lines = text.trim().split(/\r?\n/);
  if (lines.length < 2) return [];
  const header = splitCsvLine(lines[0].toLowerCase());
  const urlIdx = header.indexOf("url");
  const usernameIdx = header.indexOf("username");
  const passwordIdx = header.indexOf("password");
  const extraIdx = header.indexOf("extra");
  const nameIdx = header.indexOf("name");

  return lines.slice(1).filter((l) => l.trim()).map((line) => {
    const cols = splitCsvLine(line);
    const url = cols[urlIdx] || "";
    return {
      title: cols[nameIdx] || url || "",
      username: cols[usernameIdx] || "",
      password: cols[passwordIdx] || "",
      url,
      notes: cols[extraIdx] || "",
    };
  });
}

function parseProtonPassCsv(text: string): CsvRecord[] {
  const lines = text.trim().split(/\r?\n/);
  if (lines.length < 2) return [];
  const header = splitCsvLine(lines[0].toLowerCase());
  const nameIdx = header.indexOf("name") !== -1 ? header.indexOf("name") : header.indexOf("title");
  const usernameIdx = header.indexOf("username") !== -1 ? header.indexOf("username") : header.indexOf("email");
  const passwordIdx = header.indexOf("password");
  const urlIdx = header.indexOf("url") !== -1 ? header.indexOf("url") : header.indexOf("login_uri");
  const notesIdx = header.indexOf("note") !== -1 ? header.indexOf("note") : header.indexOf("notes");

  return lines.slice(1).filter((l) => l.trim()).map((line) => {
    const cols = splitCsvLine(line);
    return {
      title: cols[nameIdx] || "",
      username: cols[usernameIdx] || "",
      password: cols[passwordIdx] || "",
      url: cols[urlIdx] || "",
      notes: cols[notesIdx] || "",
    };
  });
}

function parseKeeperCsv(text: string): CsvRecord[] {
  const lines = text.trim().split(/\r?\n/);
  if (lines.length < 2) return [];
  const header = splitCsvLine(lines[0].toLowerCase());
  const nameIdx = header.indexOf("name") !== -1 ? header.indexOf("name") : header.indexOf("title");
  const usernameIdx = header.indexOf("login_name") !== -1 ? header.indexOf("login_name") : header.indexOf("username");
  const passwordIdx = header.indexOf("password");
  const urlIdx = header.indexOf("url");
  const notesIdx = header.indexOf("notes");

  return lines.slice(1).filter((l) => l.trim()).map((line) => {
    const cols = splitCsvLine(line);
    return {
      title: cols[nameIdx] || "",
      username: cols[usernameIdx] || "",
      password: cols[passwordIdx] || "",
      url: cols[urlIdx] || "",
      notes: cols[notesIdx] || "",
    };
  });
}

export interface ConversionResult {
  encryptedTitle: string;
  titleIv: string;
  encryptedData: string;
  dataIv: string;
  secretType: "password";
  encryptedMetadata?: string;
  metadataIv?: string;
}

export function convertRecordToSecret(_record: CsvRecord, _userId: string): ConversionResult {
  throw new Error("Client-side encryption needed for ZK vault. Use importPasswordsSchema with pre-encrypted blobs.");
}

export async function logImportExport(
  userId: string,
  action: "import" | "export",
  source: string | undefined,
  itemCount: number,
  status: "completed" | "failed",
  errorMsg?: string,
): Promise<void> {
  await db.importExportLog.create({
    data: { userId, action, source, format: "csv", itemCount, status, errorMsg },
  });
}
