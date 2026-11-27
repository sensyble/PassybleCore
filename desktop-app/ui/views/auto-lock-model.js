// How often the vault locks by itself: the choices of Settings → Unlock → Auto-lock and how a
// choice maps onto the settings (`auto_lock`: "restart", "system" or "idle" with
// `auto_lock_minutes`). A choice is "restart", "system" or the minutes as text ("15"). Pure.

import { t, tn } from "../i18n.js";

export const SETTINGS_CHOICES = ["restart", "system", "1", "5", "10", "15", "30", "60", "240"];

const isMode = (value) => value === "restart" || value === "system";

export function autoLockValue(s) {
  const mode = s && s.auto_lock;
  if (isMode(mode)) return mode;
  const minutes = Math.round(Number(s && s.auto_lock_minutes));
  return String(Number.isFinite(minutes) && minutes > 0 ? minutes : 15);
}

export function autoLockUpdate(value) {
  if (isMode(value)) return { auto_lock: value };
  return { auto_lock: "idle", auto_lock_minutes: Math.max(1, Math.round(Number(value)) || 15) };
}

/** `choices`, with `current` added (in minute order) when it isn't one of them: a time an older
 * version or a hand-edited file chose. */
export function choicesWith(choices, current) {
  if (!current || choices.includes(current)) return choices.slice();
  const minutes = choices.filter((c) => !isMode(c));
  const after = minutes.find((c) => Number(c) > Number(current));
  const out = choices.slice();
  out.splice(after ? out.indexOf(after) : out.length, 0, current);
  return out;
}

export function autoLockLabel(value) {
  if (value === "restart") return t("settings.auto_lock_restart");
  if (value === "system") return t("settings.auto_lock_system");
  const minutes = Number(value);
  return minutes >= 60 && minutes % 60 === 0 ? tn("settings.hours", minutes / 60) : tn("settings.minutes", minutes);
}

/** Whether an organisation's maximum auto-lock (`max` minutes; none: null) allows a choice. On every
 * restart and when the computer locks never lock for being idle, so a maximum rules them out. */
export function autoLockAllowed(value, max) {
  if (!max) return true;
  if (isMode(value)) return false;
  return Number(value) <= Number(max);
}

export function locksWithComputer(value) {
  return value !== "restart";
}
