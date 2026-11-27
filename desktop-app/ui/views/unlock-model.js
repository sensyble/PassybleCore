// The pure part of the unlock form's Windows Hello start (unlock.js).

/**
 * Whether the unlock form starts Windows Hello by itself: "never", "now" (`auto`: the user just asked
 * for a password, a code or an edit), or "if-opened" (only when the user just opened the window,
 * per the app's one-time grant `take_auto_hello`: a hidden window, a lock or a resume never start it).
 */
export function autoHelloMode({ auto, ready, active, usePassword, typed }) {
  if (auto === false || !ready || !active || usePassword || typed) return "never";
  return auto === true ? "now" : "if-opened";
}
