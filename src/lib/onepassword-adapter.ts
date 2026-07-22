import JSZip from "jszip";

export interface OnePasswordField {
  id: string;
  type: string;
  label: string;
  value: string;
}

export interface OnePasswordItem {
  id: string;
  title: string;
  category: string;
  fields: OnePasswordField[];
  notes?: string;
  urls?: string[];
}

export interface OnePasswordExport {
  vaultName: string;
  exportedAt: string;
  items: OnePasswordItem[];
}

export class OnePasswordError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OnePasswordError";
  }
}

async function extractJsonFrom1pux(buffer: Buffer): Promise<unknown> {
  const zip = await JSZip.loadAsync(buffer);

  const exportDataFile = zip.file("export.data");
  if (!exportDataFile) {
    throw new OnePasswordError(".1pux file is missing export.data — not a valid 1Password export");
  }

  const content = await exportDataFile.async("string");

  try {
    return JSON.parse(content);
  } catch {
    throw new OnePasswordError("export.data is not valid JSON");
  }
}

const CATEGORY_MAP: Record<string, string> = {
  "001": "login",
  "002": "credit_card",
  "003": "secure_note",
  "004": "identity",
  "005": "password",
  "006": "document",
};

function mapFields(details: Record<string, unknown> | undefined): OnePasswordField[] {
  if (!details) return [];

  const sections = (details.sections as Array<Record<string, unknown>>) ?? [];
  const fields: OnePasswordField[] = [];

  for (const section of sections) {
    const sectionFields = (section.fields as Array<Record<string, unknown>>) ?? [];
    for (const f of sectionFields) {
      fields.push({
        id: (f.id as string) ?? "",
        type: (f.type as string) ?? "string",
        label: (f.label as string) ?? (f.id as string) ?? "",
        value: (f.value as string) ?? "",
      });
    }
  }

  const topFields = (details.fields as Array<Record<string, unknown>>) ?? [];
  for (const f of topFields) {
    fields.push({
      id: (f.id as string) ?? "",
      type: (f.type as string) ?? "string",
      label: (f.label as string) ?? (f.id as string) ?? "",
      value: (f.value as string) ?? "",
    });
  }

  return fields;
}

export async function parse1pux(buffer: Buffer): Promise<OnePasswordExport> {
  const raw = await extractJsonFrom1pux(buffer);

  if (!raw || typeof raw !== "object") {
    throw new OnePasswordError("export.data root is not an object");
  }

  const root = raw as Record<string, unknown>;
  const rawAccounts = root.accounts as Array<Record<string, unknown>> | undefined;

  if (!rawAccounts || !Array.isArray(rawAccounts) || rawAccounts.length === 0) {
    throw new OnePasswordError("export.data missing accounts array");
  }

  const account = rawAccounts[0] as Record<string, unknown>;
  const attrs = account.attrs as Record<string, unknown> | undefined;
  const vaultName = (attrs?.vaultName as string) ?? "Imported";
  const exportedAt = (attrs?.exportedAt as string) ?? new Date().toISOString();

  const rawItems = account.items as Array<Record<string, unknown>> | undefined;

  const items: OnePasswordItem[] = (rawItems ?? []).map((item) => {
    const overview = item.overview as Record<string, unknown> | undefined;
    const details = item.details as Record<string, unknown> | undefined;

    const categoryCode = (item.categoryUuid as string) ?? (overview?.category as string) ?? "003";
    const category = CATEGORY_MAP[categoryCode] ?? categoryCode;

    const urls = (overview?.urls as Array<{ l?: string; u?: string }>) ?? [];
    const parsedUrls = urls.map((u) => u.u ?? u.l ?? "").filter(Boolean);

    return {
      id: (item.uuid as string) ?? "",
      title: (overview?.title as string) ?? (overview?.ainfo as string) ?? "Untitled",
      category,
      fields: mapFields(details),
      notes: (details?.notesPlain as string) ?? undefined,
      urls: parsedUrls.length > 0 ? parsedUrls : undefined,
    };
  });

  return { vaultName, exportedAt, items };
}

export function itemsToSecrets(items: OnePasswordItem[]): Array<{
  title: string;
  data: Record<string, string>;
}> {
  return items.map((item) => {
    const data: Record<string, string> = {};
    for (const f of item.fields) {
      if (f.value) {
        data[f.label || f.id] = f.value;
      }
    }
    if (item.notes) data["notes"] = item.notes;
    if (item.urls && item.urls.length > 0) data["url"] = item.urls[0];

    return { title: item.title, data };
  });
}
