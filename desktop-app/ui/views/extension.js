// The browser extension setup guide (setup_guide.rs). The extension isn't in the browser stores yet,
// so it is loaded from the copy installed with Passyble. One browser at a time: numbered steps, then
// a live check that watches for the extension to connect. Firefox loads it only as a temporary
// add-on, and the guide says so.

import { errorText, h, icon, invoke, keyLabel, modal, mount, t, toast } from "../lib.js";

const POLL_MS = 2000;
/** Paste, as the keyboard of the user's language names it ("Strg+V"). */
const PASTE = keyLabel("Mod+V");

export function setupChanged() {
  window.dispatchEvent(new CustomEvent("pass-get-started"));
}

function button(iconName, label, onClick, { primary = false, disabled = false } = {}) {
  return h("button", { class: `btn small${primary ? " primary" : ""}`, type: "button", disabled, on: { click: onClick } }, icon(iconName), label);
}

const fail = (e) => toast(errorText(e), "error");

export async function openExtensionGuide({ onClose = null } = {}) {
  let info;
  try {
    info = await invoke("extension_setup");
  } catch (e) {
    fail(e);
    return;
  }
  const browsers = info.browsers || [];
  let connected = info.connected || null;
  let timer = null;
  const m = modal({
    label: t("extsetup.title"),
    cls: "guide",
    onClose: () => {
      clearInterval(timer);
      setupChanged();
      if (onClose) onClose();
    },
  });
  let current = browsers.find((b) => b.id === connected)
    || browsers.find((b) => b.default && b.installed)
    || browsers.find((b) => b.installed)
    || browsers[0];

  const seg = h("div", { class: "seg", role: "radiogroup", "aria-label": t("extsetup.browser") });
  const steps = h("ol", { class: "guide-steps" });
  const status = h("div", { class: "col", role: "status", "aria-live": "polite" });
  const actions = h("div", { class: "row modal-actions" });
  const firefoxNote = h("div", { class: "banner warn" }, icon("alert"), h("span", { class: "grow", text: t("extsetup.firefox_temporary") }));

  const copy = async (what, label) => {
    try {
      await invoke("extension_copy", { what, browser: current.id });
      toast(t("extsetup.copied", { what: label }));
    } catch (e) {
      fail(e);
    }
  };
  const show = (what) => invoke("extension_show", { what }).catch(fail);
  const openBrowser = async () => {
    try {
      // Chromium browsers don't open their own pages from the command line: paste the address.
      await invoke("extension_copy", { what: "page", browser: current.id });
      await invoke("extension_open_browser", { browser: current.id });
      // Firefox opens the page itself, so there is nothing to paste.
      if (current.id !== "firefox") toast(t("extsetup.address_copied", { page: current.page }), "", 6000);
    } catch (e) {
      fail(e);
    }
  };

  const step = (title, text, ...extra) => h("li", {},
    h("div", { class: "t", text: title }),
    text ? h("div", { class: "muted", text }) : null,
    ...extra);
  const buttons = (...list) => h("div", { class: "row wrap" }, list);
  const path = (p) => (p ? h("div", { class: "guide-path mono selectable", text: p }) : null);
  const missing = () => h("div", { class: "banner warn" }, icon("alert"),
    h("span", { class: "grow", text: t("extsetup.no_files") }),
    button("external", t("help.downloads_open"), () => invoke("open_releases_page").catch(fail)));

  const openStep = () => {
    const b = current;
    const firefox = b.id === "firefox";
    return step(t("extsetup.open_title"),
      firefox ? t("extsetup.open_text_firefox", { page: b.page, paste: PASTE }) : t("extsetup.open_text", { browser: b.name, page: b.page, paste: PASTE }),
      b.installed ? null : h("div", { class: "hint", text: t("extsetup.not_found", { browser: b.name }) }),
      buttons(
        button("external", t("extsetup.open_browser", { browser: b.name }), openBrowser, { primary: true, disabled: !b.installed }),
        button("copy", t("extsetup.copy_address"), () => copy("page", b.page))));
  };

  const checkStep = () => step(t("extsetup.check_title"), t("extsetup.check_text"), status);

  const render = () => {
    const b = current;
    firefoxNote.hidden = b.id !== "firefox";
    for (const el of seg.children) {
      const on = el.dataset.id === b.id;
      el.classList.toggle("active", on);
      el.setAttribute("aria-checked", String(on));
    }
    if (b.id === "firefox") {
      mount(steps,
        openStep(),
        step(t("extsetup.ff_load_title"), t("extsetup.ff_load_text", { paste: PASTE }),
          info.firefox_package
            ? [path(info.firefox_package), buttons(
                button("copy", t("extsetup.copy_file"), () => copy("firefox", info.firefox_package)),
                button("folder", t("extsetup.show_file"), () => show("firefox")))]
            : missing()),
        step(t("extsetup.pin_title"), t("extsetup.pin_text_firefox")),
        checkStep());
    } else {
      mount(steps,
        openStep(),
        step(t("extsetup.dev_title"), t("extsetup.dev_text")),
        step(t("extsetup.load_title"), t("extsetup.load_text", { paste: PASTE }),
          info.folder
            ? [path(info.folder), buttons(
                button("copy", t("extsetup.copy_folder"), () => copy("folder", info.folder)),
                button("folder", t("extsetup.show_folder"), () => show("folder")))]
            : missing()),
        step(t("extsetup.pin_title"), t(b.id.startsWith("opera") ? "extsetup.pin_text_opera" : "extsetup.pin_text")),
        checkStep());
    }
    renderStatus();
  };

  const renderStatus = () => {
    if (connected) {
      const known = browsers.find((x) => x.id === connected);
      mount(status,
        h("div", { class: "banner ok-banner" }, icon("check"),
          h("span", { class: "grow", text: known ? t("extsetup.connected", { browser: known.name }) : t("extsetup.connected_other") })),
        h("div", { class: "hint", text: t("extsetup.test_it", { keys: keyLabel("Mod+Shift+L") }) }));
    } else {
      mount(status, h("div", { class: "hint guide-wait" }, icon("sync", "spin"), t("extsetup.waiting")));
    }
    const close = h("button", { class: `btn${connected ? " primary" : ""}`, type: "button", text: connected ? t("common.done") : t("common.close"), on: { click: () => m.close() } });
    mount(actions,
      connected ? null : h("button", {
        class: "btn ghost",
        type: "button",
        title: t("extsetup.mark_done_title"),
        text: t("extsetup.mark_done"),
        on: {
          click: async () => {
            await invoke("get_started_show", { browserDone: true }).catch(fail);
            m.close();
          },
        },
      }),
      h("span", { class: "spacer" }),
      close);
  };

  for (const b of browsers) {
    seg.append(h("button", {
      type: "button",
      role: "radio",
      dataset: { id: b.id },
      title: b.installed ? (b.default ? t("extsetup.default_browser") : null) : t("extsetup.not_found_short"),
      class: b.installed ? null : "faint",
      text: b.name,
      on: {
        click: () => {
          current = b;
          render();
        },
      },
    }));
  }

  mount(m.box,
    h("div", { class: "row" }, h("span", { class: "modal-icon" }, icon("globe")), h("h2", { class: "grow", text: t("extsetup.title") })),
    h("p", { text: t("extsetup.intro") }),
    info.host_exists === false ? h("div", { class: "banner error", text: t("settings.helper_missing_info") }) : null,
    info.native_error ? h("div", { class: "banner error", text: info.native_error }) : null,
    h("div", { class: "row wrap" }, h("span", { class: "muted", text: t("extsetup.browser") }), seg),
    firefoxNote,
    steps,
    actions);
  render();
  const first = steps.querySelector("button.primary:not([disabled])") || actions.querySelector("button");
  if (first) first.focus();

  timer = setInterval(async () => {
    if (!m.isOpen()) return;
    const now = await invoke("extension_connected").catch(() => null);
    // The native host exits with the browser: once connected, keep showing it (only a browser
    // that reports in changes the status).
    if (now && now !== connected) {
      const firstTime = !connected;
      connected = now;
      renderStatus();
      if (firstTime) toast(t("extsetup.connected_toast"));
    }
  }, POLL_MS);
}
