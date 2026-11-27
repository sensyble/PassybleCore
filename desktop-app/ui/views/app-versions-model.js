// What the main window shows for the version requirements (app_versions.rs `status`):
// * below the minimum: the full-window "Update required" screen, until the user picks "View my
//   passwords"; then the read-only bar, whose Update brings the screen back;
// * below the recommended version: the "Update available" bar, until it is closed for that version.
// The admin's message is plain text: the view puts it in with textContent, never as markup.

const MESSAGE_MAX = 280;

/** The admin's message as shown: a string of at most 280 characters, or "" (Rust cleans it too). */
export function messageText(message) {
  if (typeof message !== "string") return "";
  return [...message.replace(/\s+/g, " ").trim()].slice(0, MESSAGE_MAX).join("");
}

/** `{ screen, bar, banner }` for `status` (`null` or malformed: nothing). `viewing`: the user left the Update screen. */
export function appVersionsView(status, viewing = false) {
  const none = { screen: false, bar: false, banner: null };
  if (!status || typeof status !== "object") return none;
  const message = messageText(status.message);
  if (status.state === "required") {
    return { screen: !viewing, bar: true, banner: null, minimum: String(status.minimum || ""), current: String(status.current || ""), message };
  }
  if (status.state === "recommended" && !status.dismissed && status.version) {
    return { screen: false, bar: false, banner: { version: String(status.version), message } };
  }
  return none;
}
