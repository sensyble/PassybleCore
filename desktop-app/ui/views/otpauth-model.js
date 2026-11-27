// otpauth:// links opened from outside (otpauth.js): the pure part of the confirmation and the
// Settings row.

import { t } from "../i18n.js";
import { hiddenOn } from "../linux-hidden.js";

/** The radio value of "a new login"; every other value is a login's id. */
export const NEW_LOGIN = "";

/** The confirmation's rows: the link's own values, shown as plain text. */
export function detailRows(link) {
  return [
    { label: t("otpauth.service"), value: link.issuer || t("otpauth.not_given") },
    { label: t("otpauth.account"), value: link.account || t("otpauth.not_given") },
    {
      label: t("otpauth.code"),
      value: t("otpauth.settings", { digits: link.digits, period: link.period, algorithm: link.algorithm }),
    },
  ];
}

/** What is selected at first: the core's suggestion, else a new login. Never a login with a code. */
export function initialChoice(matches) {
  const best = matches.find((m) => m.suggested && !m.has_totp);
  return best ? best.id : NEW_LOGIN;
}

/** Adding to this choice replaces a 2FA code. */
export function replaces(matches, choice) {
  return matches.some((m) => m.id === choice && m.has_totp);
}

export function addLabel(matches, choice) {
  return replaces(matches, choice) ? t("otpauth.replace") : t("otpauth.add");
}

/** The name a new login gets (the core uses the same order). */
export function newLoginTitle(link) {
  return link.issuer || link.account || t("otpauth.default_title");
}

export function matchDetail(match) {
  return [match.username, match.has_totp ? t("otpauth.has_code") : ""].filter(Boolean).join(" · ");
}

export function unlockNotice(link) {
  const name = link.issuer || link.account;
  return name ? t("otpauth.unlock_named", { name }) : t("otpauth.unlock");
}

/**
 * The Settings row for who opens these links. `handler`: "this", "none" or "other"; `claimed`: the
 * user just tried, and Windows' own choice can still say another app. Linux has no Windows
 * settings page, so there "other" always offers the claim again. `action`: "claim", "windows" or null.
 */
export function handlerRow(handler, claimed = false, platform = "") {
  if (handler === "this") return { value: t("settings.otpauth_this"), valueClass: "ok", action: null, label: "" };
  if (handler === "other" && claimed && !hiddenOn(platform, "settings.otpauth_open_windows")) {
    return { value: t("settings.otpauth_chooser"), valueClass: "warn", action: "windows", label: t("settings.otpauth_open_windows") };
  }
  const value = handler === "other" ? t("settings.otpauth_other") : t("settings.otpauth_none");
  return { value, valueClass: "", action: "claim", label: t("settings.otpauth_claim") };
}
