// An explanation tooltip on an (i) button (WCAG 1.4.13): hover or focus shows it, the pointer may
// move onto it, Esc hides it. On touch a tap toggles it and a tap outside closes it. The bubble lives
// inside its button (fixed, kept inside the window). No imports, so tests can run it on a fake DOM.

let seq = 0;
const GAP = 6;
const EDGE = 8;

function noHover(view) {
  try { return !!view?.matchMedia?.("(hover: none)").matches; } catch { return false; }
}

/** Places `el` below `anchor` (above when it doesn't fit), kept inside the window. */
export function placeTooltip(anchor, el) {
  const view = anchor.ownerDocument.defaultView;
  const r = anchor.getBoundingClientRect();
  const w = el.offsetWidth || 0;
  const h = el.offsetHeight || 0;
  const vw = view?.innerWidth || 800;
  const vh = view?.innerHeight || 600;
  let top = r.bottom + GAP;
  let side = "below";
  if (top + h > vh - EDGE && r.top - GAP - h >= EDGE) { top = r.top - GAP - h; side = "above"; }
  const left = Math.max(EDGE, Math.min(r.left + r.width / 2 - w / 2, vw - w - EDGE));
  el.style.top = `${Math.round(Math.max(EDGE, top))}px`;
  el.style.left = `${Math.round(left)}px`;
  el.dataset.side = side;
}

/** Gives `anchor` (a button with an accessible name) a tooltip with `text`. */
export function attachTooltip(anchor, text) {
  const doc = anchor.ownerDocument;
  const view = doc.defaultView;
  const el = doc.createElement("span");
  el.className = "tooltip";
  el.id = `tooltip-${++seq}`;
  el.setAttribute("role", "tooltip");
  el.hidden = true;
  el.textContent = text;
  anchor.append(el);
  const described = (anchor.getAttribute("aria-describedby") || "").split(/\s+/).filter(Boolean);
  anchor.setAttribute("aria-describedby", [...described, el.id].join(" "));

  let over = false;
  let kbd = false;
  let leaveTimer = 0;
  let pointer = "";
  const visible = () => !el.hidden;
  const reposition = () => { if (visible()) placeTooltip(anchor, el); };

  const onKey = (e) => {
    if (e.key !== "Escape" || !visible()) return;
    e.preventDefault();
    e.stopImmediatePropagation();
    hide();
  };
  const onDown = (e) => {
    if (anchor.contains(e.target)) return;
    hide();
  };

  function show() {
    view?.clearTimeout(leaveTimer);
    if (visible() || !anchor.isConnected) return;
    el.hidden = false;
    anchor.classList.add("open");
    placeTooltip(anchor, el);
    // On the window, so it runs before a dialog's own Esc (those listen on the document).
    view?.addEventListener("keydown", onKey, true);
    doc.addEventListener("pointerdown", onDown, true);
    view?.addEventListener("resize", reposition);
    view?.addEventListener("scroll", reposition, true);
  }
  function hide() {
    view?.clearTimeout(leaveTimer);
    if (!visible()) return;
    el.hidden = true;
    anchor.classList.remove("open");
    view?.removeEventListener("keydown", onKey, true);
    doc.removeEventListener("pointerdown", onDown, true);
    view?.removeEventListener("resize", reposition);
    view?.removeEventListener("scroll", reposition, true);
  }

  anchor.addEventListener("pointerenter", (e) => {
    if (e.pointerType === "touch") return;
    over = true;
    show();
  });
  anchor.addEventListener("pointerleave", (e) => {
    if (e.pointerType === "touch") return;
    over = false;
    view?.clearTimeout(leaveTimer);
    leaveTimer = view?.setTimeout(() => { if (!over && !kbd) hide(); }, 150);
  });
  anchor.addEventListener("pointerdown", (e) => { pointer = e.pointerType || ""; });
  anchor.addEventListener("focus", () => { if (!pointer) { kbd = true; show(); } });
  anchor.addEventListener("blur", () => { kbd = false; if (!over) hide(); });
  anchor.addEventListener("click", (e) => {
    e.preventDefault();
    e.stopPropagation(); // not the row or label it sits in
    const tap = pointer === "touch" || pointer === "pen" || noHover(view);
    pointer = "";
    if (tap && visible()) hide();
    else show();
  });

  return { el, show, hide, get open() { return visible(); } };
}
