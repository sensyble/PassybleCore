// The pure part of the one-line "where is this vault" caption. It never shows a file path or a vault
// UUID file name: the path stays in the hover tooltip only.

export function isLoopbackHost(host) {
  const h = String(host || "").trim().toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  return h === "localhost" || h.endsWith(".localhost") || h === "::1" || /^127\.\d+\.\d+\.\d+$/.test(h);
}

/** Whether a host is on a home or office network (the core's rule for plain http, is_private_host). */
export function isPrivateHost(host) {
  const h = String(host || "").trim().toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  if (!h) return false;
  const v4 = h.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])];
    return a === 10 || a === 0 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
      (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127) || a === 255;
  }
  if (h.includes(":")) return /^f[cd][0-9a-f]{2}:/.test(h) || /^fe[89ab][0-9a-f]:/.test(h);
  if (!h.includes(".")) return true;
  return ["local", "lan", "home.arpa", "home", "internal", "intranet", "localdomain", "test", "example", "invalid"]
    .some((s) => h === s || h.endsWith(`.${s}`));
}

const PROVIDERS = [
  [/^onedrive/i, "OneDrive"],
  [/^dropbox$/i, "Dropbox"],
  [/^(google drive|my drive)$/i, "Google Drive"],
  [/^icloud ?drive$/i, "iCloud Drive"],
  [/^syncthing$/i, "Syncthing"],
];

export function folderLabel(path) {
  const parts = String(path || "").split(/[\/]+/).filter(Boolean);
  parts.pop();
  for (const part of parts) {
    const hit = PROVIDERS.find(([re]) => re.test(part));
    if (hit) return hit[1];
  }
  return parts.length ? parts[parts.length - 1] : "";
}

/**
 * The caption as `{ key, params }` for t(), or null when nothing is known. `vault` is a vault
 * from the Rust list: webdav_host, google_email, managed (the app keeps the file itself), path.
 */
export function vaultWhere(vault) {
  if (vault.webdav_host) {
    const host = vault.webdav_host;
    if (isLoopbackHost(host)) return { key: "vaultwhere.server_this_pc", params: {} };
    if (isPrivateHost(host)) return { key: "vaultwhere.network", params: { host } };
    return { key: "vaultwhere.host", params: { host } };
  }
  if (vault.google_email) return { key: "unlock.google_backup", params: { email: vault.google_email } };
  if (vault.managed) return { key: "vaultwhere.this_pc", params: {} };
  const folder = folderLabel(vault.path);
  return folder ? { key: "vaultwhere.folder", params: { folder } } : { key: "vaultwhere.this_pc", params: {} };
}

export function whereText(vault, translate) {
  const w = vaultWhere(vault);
  return w ? translate(w.key, w.params) : "";
}
