import { describe, it, expect } from "vitest";
import JSZip from "jszip";
import { parse1pux, itemsToSecrets, OnePasswordError } from "../onepassword-adapter";

function buildMinimal1pux(items: unknown[]): Promise<Buffer> {
  const zip = new JSZip();

  const exportData = {
    accounts: [
      {
        attrs: {
          vaultName: "Personal",
          exportedAt: "2025-01-01T00:00:00.000Z",
        },
        items,
      },
    ],
  };

  zip.file("export.data", JSON.stringify(exportData));
  return zip.generateAsync({ type: "nodebuffer" });
}

describe("OnePasswordAdapter", () => {
  it("parsea un .1pux válido con un item login", async () => {
    const buffer = await buildMinimal1pux([
      {
        uuid: "item-1",
        categoryUuid: "001",
        overview: {
          title: "GitHub",
          urls: [{ u: "https://github.com" }],
        },
        details: {
          sections: [
            {
              fields: [
                { id: "username", type: "string", label: "username", value: "testuser" },
                { id: "password", type: "concealed", label: "password", value: "s3cret!" },
              ],
            },
          ],
        },
      },
    ]);

    const result = await parse1pux(buffer);

    expect(result.vaultName).toBe("Personal");
    expect(result.items).toHaveLength(1);

    const item = result.items[0];
    expect(item.id).toBe("item-1");
    expect(item.title).toBe("GitHub");
    expect(item.category).toBe("login");
    expect(item.urls).toEqual(["https://github.com"]);

    expect(item.fields).toHaveLength(2);
    expect(item.fields[0].label).toBe("username");
    expect(item.fields[0].value).toBe("testuser");
    expect(item.fields[1].label).toBe("password");
    expect(item.fields[1].value).toBe("s3cret!");
  });

  it("convierte items a formato secrets", async () => {
    const buffer = await buildMinimal1pux([
      {
        uuid: "item-2",
        categoryUuid: "001",
        overview: { title: "Example" },
        details: {
          sections: [
            {
              fields: [
                { id: "email", type: "string", label: "email", value: "a@b.com" },
              ],
            },
          ],
          notesPlain: "Some notes here",
        },
      },
    ]);

    const parsed = await parse1pux(buffer);
    const secrets = itemsToSecrets(parsed.items);

    expect(secrets).toHaveLength(1);
    expect(secrets[0].title).toBe("Example");
    expect(secrets[0].data.email).toBe("a@b.com");
    expect(secrets[0].data.notes).toBe("Some notes here");
  });

  it("rechaza .1pux sin export.data", async () => {
    const emptyZip = new JSZip();
    const buffer = await emptyZip.generateAsync({ type: "nodebuffer" });

    await expect(parse1pux(buffer)).rejects.toThrow(OnePasswordError);
    await expect(parse1pux(buffer)).rejects.toThrow("missing export.data");
  });

  it("rechaza .1pux con export.data inválido", async () => {
    const zip = new JSZip();
    zip.file("export.data", "not-json");
    const buffer = await zip.generateAsync({ type: "nodebuffer" });

    await expect(parse1pux(buffer)).rejects.toThrow(OnePasswordError);
    await expect(parse1pux(buffer)).rejects.toThrow("not valid JSON");
  });

  it("rechaza .1pux sin accounts", async () => {
    const zip = new JSZip();
    zip.file("export.data", JSON.stringify({}));
    const buffer = await zip.generateAsync({ type: "nodebuffer" });

    await expect(parse1pux(buffer)).rejects.toThrow(OnePasswordError);
    await expect(parse1pux(buffer)).rejects.toThrow("missing accounts");
  });

  it("maneja items sin details (solo overview)", async () => {
    const buffer = await buildMinimal1pux([
      {
        uuid: "item-3",
        categoryUuid: "003",
        overview: { title: "Secure Note" },
      },
    ]);

    const result = await parse1pux(buffer);
    expect(result.items).toHaveLength(1);
    expect(result.items[0].title).toBe("Secure Note");
    expect(result.items[0].category).toBe("secure_note");
    expect(result.items[0].fields).toEqual([]);
  });

  it("parsea multiples items", async () => {
    const buffer = await buildMinimal1pux([
      {
        uuid: "i1",
        categoryUuid: "001",
        overview: { title: "Login 1" },
        details: { sections: [{ fields: [{ id: "u", type: "string", label: "user", value: "a" }] }] },
      },
      {
        uuid: "i2",
        categoryUuid: "005",
        overview: { title: "Password 2" },
        details: { sections: [{ fields: [{ id: "p", type: "concealed", label: "password", value: "b" }] }] },
      },
    ]);

    const result = await parse1pux(buffer);
    expect(result.items).toHaveLength(2);
    expect(result.items[0].title).toBe("Login 1");
    expect(result.items[1].title).toBe("Password 2");
    expect(result.items[1].category).toBe("password");
  });
});
