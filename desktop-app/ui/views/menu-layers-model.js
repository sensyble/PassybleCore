// The vault switcher's row menu opens over the switcher (views/vault.js `openMenu`): which layer an
// outside press or Escape closes. Pure: tested in test/menu-layers-model.test.mjs.

export function pressCloses({ inMenu, inSub, hasSub }) {
  if (inSub || (inMenu && !hasSub)) return "none";
  if (inMenu) return "sub";
  return hasSub ? "all" : "menu";
}

/** Escape closes the row menu first, then the switcher. */
export function escapeCloses(hasSub) {
  return hasSub ? "sub" : "menu";
}
