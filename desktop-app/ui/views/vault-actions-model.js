// What a vault's own menu offers and the typed confirmation of "Delete vault from your account".
// Pure, so node can test it.

/**
 * Actions for vault `v`, in menu order: "rename", "reveal", "remove" and, where the account may
 * delete it (never a home or shared vault: `account_deletable`), "delete_account".
 */
export function vaultActionKeys(v) {
  if (!v) return [];
  const keys = ["rename", "reveal", "remove"];
  if (v.account_deletable) keys.push("delete_account");
  return keys;
}

/**
 * Whether `typed` is the vault's name, as account_vaults.rs `name_confirmed` rules it: surrounding
 * spaces and letter case don't matter, an empty name never matches.
 */
export function deleteNameConfirmed(typed, name) {
  const a = String(typed ?? "").trim();
  const b = String(name ?? "").trim();
  return b !== "" && a.toLowerCase() === b.toLowerCase();
}

/** "Export first" works for the vault that is open and unlocked here; others are opened first. */
export function canExportFirst(v, locked) {
  return Boolean(v && v.active && !locked);
}
