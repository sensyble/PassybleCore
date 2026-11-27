// Website icons on item avatars. `watchIcons(container)` asks for the icons of avatars as they
// scroll into view, one `site_icons` call per frame. Answers are cached per domain until a full
// lock; late fetches arrive as `site-icon` and swap in place, so lists never re-render. The icon
// lies over the letter, which shows again if the image fails or the setting is turned off.

import { avatar, h, initials, invoke, listen } from "./lib.js";

// domain -> PNG data URL, or null (no icon, or a fetch is on its way).
const icons = new Map();
const observers = new Map();
let batch = null;

export function itemAvatar(item) {
  const id = item.kind === "identity" ? item.identity : null;
  const name = id ? id.full_name || [id.first_name, id.middle_name, id.last_name].filter(Boolean).join(" ") : "";
  const el = avatar(item.title, item.kind, name ? initials(name) : null);
  if (item.site) {
    el.dataset.site = item.site;
    const url = icons.get(item.site);
    if (url) showIcon(el, url);
  }
  return el;
}

export function watchIcons(container) {
  const previous = observers.get(container);
  if (previous) previous.disconnect();
  const observer = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (!entry.isIntersecting) continue;
      observer.unobserve(entry.target);
      request(entry.target.dataset.site);
    }
  }, { rootMargin: "200px 0px" });
  observers.set(container, observer);
  for (const el of container.querySelectorAll(".avatar[data-site]")) {
    if (!icons.has(el.dataset.site)) observer.observe(el);
  }
}

function request(site) {
  if (!site || icons.has(site)) return;
  if (!batch) {
    batch = new Set();
    requestAnimationFrame(flush);
  }
  batch.add(site);
}

function flush() {
  const domains = [...batch];
  batch = null;
  // A fetch the call queued answers later with `site-icon`.
  for (const d of domains) icons.set(d, null);
  invoke("site_icons", { domains })
    .then((list) => { for (const { domain, icon } of list) if (icon) setIcon(domain, icon); })
    .catch(() => { for (const d of domains) icons.delete(d); });
}

function setIcon(domain, url) {
  icons.set(domain, url || null);
  for (const el of document.querySelectorAll(`.avatar[data-site="${CSS.escape(domain)}"]`)) {
    if (url) showIcon(el, url);
    else hideIcon(el);
  }
}

function showIcon(el, url) {
  let img = el.querySelector("img.site-icon");
  if (!img) {
    img = h("img", { class: "site-icon", alt: "", draggable: "false" });
    img.addEventListener("error", () => hideIcon(el));
    el.append(img);
  }
  if (img.getAttribute("src") !== url) img.src = url;
  el.classList.add("has-icon");
}

function hideIcon(el) {
  el.classList.remove("has-icon");
  const img = el.querySelector("img.site-icon");
  if (img) img.remove();
}

listen("site-icon", (p) => {
  if (p && p.domain) setIcon(String(p.domain), typeof p.icon === "string" ? p.icon : null);
});
listen("site-icons-enabled", (p) => {
  icons.clear();
  batch = null;
  for (const el of document.querySelectorAll(".avatar.has-icon")) hideIcon(el);
  if (p && p.enabled) {
    for (const [container, observer] of [...observers]) {
      if (container.isConnected) {
        watchIcons(container);
      } else {
        observer.disconnect();
        observers.delete(container);
      }
    }
  }
});
// A soft lock keeps the list on screen, and its icons with it.
listen("lock-state", (p) => {
  if (!p || !p.locked || p.soft) return;
  icons.clear();
  for (const observer of observers.values()) observer.disconnect();
  observers.clear();
});
