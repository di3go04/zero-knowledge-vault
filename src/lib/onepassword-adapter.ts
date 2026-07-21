/** 1Password 1PUX import adapter. Parses .1pux (zip) structure. */
export interface OnePasswordItem { title: string; username: string | null; password: string | null; url: string | null; notes: string | null; }
export interface OnePasswordExport { accounts: Array<{ vaults: Array<{ items: OnePasswordItem[] }> }>; }
export function importFromOnePassword(data: OnePasswordExport): Array<{title:string;content:string}> {
  const out: Array<{title:string;content:string}> = [];
  for (const acc of data.accounts ?? []) for (const v of acc.vaults ?? []) for (const item of v.items ?? []) {
    out.push({ title: item.title, content: JSON.stringify({ username: item.username ?? "", password: item.password ?? "", url: item.url ?? "", notes: item.notes ?? "" }) });
  }
  return out;
}
