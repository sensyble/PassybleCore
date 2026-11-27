// Pinned vaults (switcher, "All vaults" filter, locked vault list): kept in the open vault, in pin
// order, so they follow the user to every device (`vault_pins` / `set_vault_pins`).

export const MAX_PINS = 5;

// The pins last seen unlocked on this PC, for the locked vault list (the pins live in the vault).
const LAST_PINS_KEY = "passyble.pins.last";

/** Every vault list's order: the active vault, then the pinned ones in pin order, then the rest. */
export function pinnedFirst(vaults, pins, key = (v) => v.id, isActive = () => false) {
  const list = vaults || [];
  const order = new Map((pins || []).map((id, i) => [id, i]));
  const rank = (v) => (isActive(v) ? -1 : order.has(key(v)) ? order.get(key(v)) : Infinity);
  return list
    .map((v, i) => [v, i])
    .sort(([a, i], [b, j]) => rank(a) - rank(b) || i - j)
    .map(([v]) => v);
}

/**
 * The pins after pinning or unpinning vault `id`: ids this window doesn't show are kept, a new pin
 * goes last. `{ pins }`, or `{ full: true }` when `visible` already holds {@link MAX_PINS}.
 */
export function togglePin(pins, id, pin, visible) {
  const current = (pins || []).filter((p) => p !== id);
  if (!pin) return { pins: current };
  if ((pins || []).includes(id)) return { pins: pins.slice() };
  const shown = new Set(visible || []);
  if (current.filter((p) => shown.has(p)).length >= MAX_PINS) return { full: true };
  return { pins: [...current, id] };
}

export function rememberPins(vault, pins, storage = globalThis.localStorage) {
  try {
    storage.setItem(LAST_PINS_KEY, JSON.stringify({ vault, pins: pins || [] }));
  } catch {
    // No storage: the locked list keeps the active vault first and the others as they are.
  }
}

export function lastPins(vault, storage = globalThis.localStorage) {
  try {
    const saved = JSON.parse(storage.getItem(LAST_PINS_KEY) || "null");
    return saved && saved.vault === vault && Array.isArray(saved.pins) ? saved.pins : [];
  } catch {
    return [];
  }
}
