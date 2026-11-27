// Settings → Signed-in devices: every device signed in to the account, with when it signed in and
// was last used, badges, and "Sign out" (devices.rs). Signing out this device forgets its token
// here, as does the server refusing it (a password change on another device signs out the others).

import { errorText, formatDate, h, icon, invoke, mount, settingsRow, t, tn, toast } from "../lib.js";
import { openSignInAgainDialog } from "./signin.js";

const MINUTE = 60 * 1000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

const dateText = (ms) => formatDate(ms);

function deviceIcon(d) {
  const text = `${d.platform || ""} ${d.os || ""} ${d.name || ""}`;
  return /phone|android|ios|ipad|tablet|mobile|pixel|galaxy/i.test(text) ? "phoneApp" : "monitor";
}

export function lastUsedText(ms, now = Date.now()) {
  if (!ms) return t("devices.last_used_never");
  const diff = Math.max(0, now - ms);
  // The server records use to within a few minutes.
  if (diff < 5 * MINUTE) return t("devices.last_used_now");
  if (diff < HOUR) return tn("devices.last_used_minutes", Math.round(diff / MINUTE));
  if (diff < DAY) return tn("devices.last_used_hours", Math.round(diff / HOUR));
  const days = Math.round(diff / DAY);
  if (days === 1) return t("devices.last_used_yesterday");
  if (days < 30) return tn("devices.last_used_days", days);
  return t("devices.last_used_date", { date: dateText(ms) });
}

function confirmSignOut(device) {
  return new Promise((resolve) => {
    const done = (value) => {
      document.removeEventListener("keydown", keys, true);
      backdrop.remove();
      resolve(value);
    };
    const keys = (e) => {
      if (e.key === "Escape") {
        e.preventDefault();
        e.stopPropagation();
        done(false);
      }
    };
    const title = device.current ? t("devices.sign_out_this_title") : t("devices.sign_out_title", { device: device.name });
    const go = h("button", { class: "btn primary", type: "button", on: { click: () => done(true) } }, t("devices.sign_out"));
    const backdrop = h(
      "div",
      { class: "modal-backdrop" },
      h(
        "div",
        { class: "modal narrow", role: "dialog", "aria-modal": "true", "aria-label": title },
        h("div", { class: "row" }, h("span", { class: "modal-icon" }, icon("monitor")), h("h2", { class: "grow", text: title })),
        h("p", {
          text: device.current
            ? t("devices.sign_out_this_text")
            : t("devices.sign_out_text"),
        }),
        h("div", { class: "row modal-actions" },
          h("span", { class: "spacer" }),
          h("button", { class: "btn", type: "button", text: t("common.cancel"), on: { click: () => done(false) } }),
          go),
      ),
    );
    document.addEventListener("keydown", keys, true);
    document.body.append(backdrop);
    go.focus();
  });
}

/** The section's content; `el` goes into the Settings card. `onSignedIn()` after "Sign in again". */
export class DevicesList {
  constructor({ onSignedIn } = {}) {
    this.onSignedIn = onSignedIn;
    this.el = h("div", { class: "set-rows" });
    this.signedOut = false;
    this.load();
  }

  async load() {
    mount(this.el, settingsRow("clock", t("common.loading"), {}));
    try {
      const r = await invoke("server_devices");
      if (r.signed_out) this.showSignedOut();
      else this.render(r.devices || []);
    } catch (e) {
      this.signedOut = false;
      mount(this.el,
        settingsRow("alert", t("devices.load_failed"), {
          value: errorText(e),
          valueClass: "warn",
          control: h("button", { class: "btn small", type: "button", on: { click: () => this.load() } }, icon("retry"), t("common.try_again")),
        }));
    }
  }

  /** `sync-status`: follows this device being signed out, or signed in again elsewhere. */
  syncStatus(status) {
    if (status.running) return;
    if (status.signed_out && !this.signedOut) this.showSignedOut();
    else if (!status.signed_out && this.signedOut && !status.last_error) this.load();
  }

  showSignedOut() {
    this.signedOut = true;
    mount(this.el,
      settingsRow("cloudOff", t("devices.signed_out_title"), {
        value: t("devices.signed_out_value"),
        valueClass: "warn",
        info: t("devices.signed_out_info"),
        control: h("button", { class: "btn small tonal", type: "button", on: { click: () => this.signIn() } }, icon("logIn"), t("common.sign_in_ellipsis")),
      }));
  }

  signIn() {
    openSignInAgainDialog({
      onDone: () => {
        this.load();
        if (this.onSignedIn) this.onSignedIn();
      },
    });
  }

  render(devices) {
    this.signedOut = false;
    if (!devices.length) {
      mount(this.el, settingsRow("monitor", t("devices.none"), {}));
      return;
    }
    mount(this.el, devices.map((d) => this.deviceRow(d)));
  }

  deviceRow(d) {
    // Sign out is only here (also for this PC), so every row keeps the same outlined pill.
    const button = h("button", {
      class: "btn small", type: "button",
      title: d.current ? t("devices.sign_out_this_pc") : t("devices.sign_out_device", { device: d.name }),
      on: { click: () => this.signOut(d, button) },
    }, t("devices.sign_out"));
    const sub = d.current
      ? t("devices.this_device_active")
      : [d.created_at ? t("devices.signed_in_on", { date: dateText(d.created_at) }) : null, lastUsedText(d.last_used_at)].filter(Boolean).join(" · ");
    return settingsRow(deviceIcon(d), [
      h("span", { class: "ellipsis", text: d.name || t("devices.unnamed"), title: d.name || null }),

      d.limited
        ? h("span", { class: "chip warn", text: t("devices.must_change"), title: t("devices.must_change_title") })
        : null,
    ], { value: sub, valueClass: d.current ? "ok" : "", control: button });
  }

  async signOut(device, button) {
    if (!(await confirmSignOut(device))) return;
    button.disabled = true;
    try {
      const r = await invoke("server_sign_out_device", { deviceId: device.id });
      if (r.current) {
        toast(t("devices.this_pc_signed_out"));
        this.showSignedOut();
        this.signIn();
        return;
      }
      toast(t("devices.signed_out_device", { device: device.name }));
    } catch (e) {
      toast(errorText(e), "error");
    }
    this.load();
  }
}
