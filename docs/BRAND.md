# Passyble brand and visual design

Passyble should not look like a stock Windows, Material or browser UI. The look is **neutral with a
hint of lime**: greys, near-black and near-white do almost all the work, and one lime green marks the
few things that matter (the logo, that the vault is unlocked).
Every surface (desktop app, browser extension, Android app) uses the same tokens below and follows
the system light or dark setting.

## Rules

- Lime is a signal, not a fill. It appears only on: the logo, the "unlocked" / "ok" status dot and
  small brand accents (an onboarding hero mark, the current vault's check mark, the
  "Recommended" marker on a first-run choice: --lime-soft fill with --lime-ink text).
  Never as a button background, page background, large card, row marker or border, or body text colour.
- Cards on a grey page: the window or page is --bg; content sits on white cards (--surface) with no
  outline and no shadow. Rows inside a card are divided by hairlines inset from the card's edges. No
  1px outline around cards or sections, no zebra rows, no alternating panel tints, no outlined card on
  grey. A surface that floats (dialog, popover, menu, tooltip, toast) uses --surface-raised and a soft
  shadow, never an outline plus a grey background. See "Card and pill language" below.
- Callouts and messages: icon and text on a soft tint (low-opacity success, warning, error or
  neutral), rounded, with no border and no coloured stripe.
- Buttons are pills: primary filled, secondary outlined, tonal (soft fill, no border) for a
  recommended action, danger as red text on the outline. Icon buttons are round. Text inputs are
  one style everywhere: an inset fill (--surface-2, #f0f0f0 / #212124) with a 1px --border-strong
  outline; keyboard focus is the same 2px text-colour ring with a 2px offset as everything else.
  Text areas grow with their text (no resize grip).
- Primary buttons are near-black in light mode and near-white in dark mode. One primary per view.
  The one exception is the desktop window's top bar: its New is the window's main action, filled
  in the brand blue (--brand) in both themes, so it reads apart from a page's own primary.
- Space Grotesk is the UI font everywhere Latin text appears. CJK and Devanagari keep their native
  system fonts as fallbacks after it. Passwords, codes and keys stay in the monospace font.
- Shapes are soft: 10 to 12 px for inputs and rows, 14 px for menus and toasts, 16 to 18 px for cards
  and dialogs, 24 px for the one centred card of a sign-in or unlock screen, pills for buttons and chips.
- No gradients of any kind (no colour gradients, no gradient or mask fades), no glows. Shadows are
  neutral and low. Scroll edges are solid page-colour bands with a 1px hairline.
- Text colours meet WCAG AA (4.5:1) on --bg, --surface and --surface-2; non-text marks (focus ring,
  selection bar, status dot) meet 3:1.

## Colour tokens

| Token | Light | Dark | Use |
| --- | --- | --- | --- |
| --bg | #f6f6f6 | #0f0f10 | Page / window background |
| --surface | #ffffff | #18181a | Cards, panes, inputs |
| --surface-2 | #f0f0f0 | #212124 | Button hover, avatar tiles |
| --surface-3 | #e6e6e6 | #2a2a2e | Pressed |
| --fill-hover | rgba(17,17,17,.04) | rgba(237,237,237,.05) | Row hover (text colour at low opacity) |
| --fill-selected | rgba(17,17,17,.10) | rgba(237,237,237,.11) | Selected / current row |
| --surface-raised | #ffffff | #222225 | Menus, dialogs, tooltips, toasts (with --shadow, no outline) |
| --border | #e4e4e4 | #2a2a2d | Hairlines |
| --border-strong | #cfcfcf | #3a3a3e | Input borders, emphasized dividers |
| --text | #111111 | #ededed | Body text |
| --text-2 | #555555 | #b4b4b8 | Secondary text |
| --text-3 | #6b6b6b | #8e8e93 | Captions, placeholders |
| --accent | #111111 | #ededed | Primary button background, links, active icons |
| --accent-hover | #2a2a2a | #ffffff | Primary button hover |
| --accent-text | #ffffff | #111111 | Text on --accent |
| --accent-soft | #ececec | #2a2a2e | Ghost button hover, soft tint behind accent text |
| --lime | #c6f432 | #c6f432 | Brand lime: the logo's fill (with its #4f6b00 border, see Logo) |
| --lime-mark | #6e9a00 | #c6f432 | Status dot, check marks, small accents (3:1 on surfaces); not the logo |
| --lime-ink | #4f6b00 | #c6f432 | Rare lime-tinted text or icon (4.5:1); #4f6b00 is also the logo's border |
| --lime-soft | #f1f9d9 | rgba(198,244,50,.12) | Very light lime wash, used sparingly (e.g. "ok" chip) |
| --brand | #2563eb | #2563eb | The desktop top bar's New only (white text 5.2:1) |
| --brand-hover | #1d4ed8 | #1d4ed8 | Its hover (white text 6.7:1); pressed #1e40af |
| --focus | 2px #111111 ring, 2px offset | 2px #ededed ring, 2px offset | Keyboard focus only (:focus-visible; not after a click or for a button focused on open); never lime |
| --danger | #b42318 | #ff8a80 | Destructive text and icons |
| --danger-soft | #fdecea | #3a1d1b | Danger banner background |
| --ok | #4f6b00 | #c6f432 | Success icons and dots (lime family; never a text colour) |
| --ok-soft | #f1f9d9 | rgba(198,244,50,.12) | Success chip background |
| --warn | #555555 | #b4b4b8 | Warning text and icons (neutral, with a warning glyph) |
| --warn-soft | #ececec | #2a2a2e | Warning background (neutral) |
| --shadow | 0 8px 24px rgba(0,0,0,.10), 0 1px 2px rgba(0,0,0,.06) | 0 8px 24px rgba(0,0,0,.55), 0 1px 2px rgba(0,0,0,.4) | Popovers, dialogs |

Rows (list items, nav items, settings rows): rounded 10 to 12 px and inset from the list's or card's edges.
Hover is a soft neutral fill, the text colour at about 4% opacity (--fill-hover); selected or current
is a stronger one (about 10%, --fill-selected) plus a bolder title (700 against 450 to 500) and, in
the item list, a darker avatar tile. No bar, no coloured
border, no lime fill. Keyboard focus keeps the visible focus ring (outline with an offset).

Avatars and item tiles: neutral (--surface-2 background, --text-2 icon or letter), no per-item colours.

## Card and pill language

The same language as passyble.com and account.passyble.com, adapted per platform (desktop window
conventions, Material 3 on Android, iOS idioms).

- **Page**: --bg. On desktop the list and the open item or page share it; nothing is boxed but the
  content cards. Floating navigation, where a surface has it, is a white rounded bar or pill on the
  grey page, with no outline.
- **Page title**: large and tight (700, letter-spacing -0.03em; desktop about 30 px, phone 30 to
  34 px), with an optional short sub-line in --text-2.
- **Section**: a heading (700, about 18 px on desktop) and, when it helps, one plain intro line
  (14 px, --text-2, at most about 62 characters wide) outside the card, then a white card (radius
  16 px) of rows; about 38 px between sections, 10 px from heading to card. Each row: an optional outline icon, a title (600) with a
  caption under it, and a trailing control (pill button, switch, chevron, value).
- **Item detail**: a large neutral tile (white on the grey page), the title in the page-title style,
  a caption, tag pills, a round star and an outlined pill Edit. The fields (username, password, 2FA,
  websites, custom fields) are rows of one white card; notes get a card of their own; Delete is an
  outlined danger pill at the foot.
- **Lists on the page** (the item list, tags, vaults): no card; rows rounded 10 px with the hover and
  selected fills below, avatar tile + title + caption.
- **Tonal = recommended** (Use this password): #ececec / #2a2a2e with text-colour 600 text, no
  border. It differs from the disabled primary by its text colour.
- **Secrets**: one mask (the same dots, size and text colour) for passwords, card numbers and 2FA
  codes; the 2FA ring sits left of the code with a #cfcfcf / #3a3a3e track and a text-colour arc.
- **Settings row buttons**: text only (no icons); an ellipsis only when a dialog follows.
- **Selection** (list rows, the open page's toolbar button): the tonal --surface-3 fill
  (#e6e6e6 / #2a2a2e) and a bolder title (rows 700 against 500), never a solid black or white fill.
- **Chips**: pills, tonal (--fill-selected), for status and tags only. Lists are filtered from one
  Filter button that opens a menu (sections with small grey headings, the chosen row checked), never
  from rows of filter chips.
- **Segmented controls**: a pill track (#f0f0f0 / #18181a) with a raised thumb for the chosen segment
  (#ffffff / #2a2a2e, a soft shadow, 600); the others only get the 5% hover fill.
- **Switches**: off is a #cfcfcf / #3a3a3e track with a white / #8e8e93 knob; on is --accent. A switch
  that can't change is the whole control at 45% with a not-allowed cursor.
- **Checkboxes**: an 18 px box, radius 5, --border-strong edge; checked is --accent with a check in
  --accent-text. **Selects**: the input's field with a chevron, not the native control.
- **Text links**: underlined, 1.5 px, offset 4 px.
- **Status text**: warnings are secondary text after a small warning glyph (no amber); "OK" lines are
  secondary text after a small lime check or a 6 px lime dot (lime is never a text colour). Counts
  of problems stay in the text colour; red is for destructive actions only.
- **Switches**: a pill track, --accent when on.
- **First-run and lock screens** (welcome, create, sign-in, restore, unlock): top-anchored like the
  account sign-in: the wordmark at the same height on every step (clamp(40px, 9vh, 88px) from the
  top), one white card right under it (radius 24 px, 460 px wide; Welcome wider for its tiles), one
  centred display title (35 px, 700, -0.02em, line height 1.1), full-width pill buttons, free space
  below. Everything fits 980 x 680 without scrolling; "Made by Sensyble" sits under the card on
  Welcome only.
- **Sticky footers** (Save / Close): on the page grey with a hairline above, pill buttons, one primary.
  One height token (--footer-h, 56 px) for the list's footer and a page's Save bar, so their hairlines
  line up; the bar runs to the window's right edge. Close only on a page without a back arrow.
- **Mono**: only for secrets and codes, weight 400 (no synthesis); dates and expiry stay in the UI font.
  Save looks quiet until something changed.
- **One filled primary per view**: on desktop, New in the list is the filled primary while browsing
  (the list, an item, the empty pane) and a white outlined pill while the open page has its own
  primary (Save, Check for breaches, Choose file, the soft lock's Unlock). Secondary actions inside a
  panel (Use this password) are tonal.
- **Disabled primary** (Save with nothing to save): an inset look, #e6e6e6 / #2a2a2e with #6b6b6b /
  #8e8e93 text, no border, a not-allowed cursor and a "No changes to save" tooltip.
- **Soft lock**: one full-width inset banner (#f0f0f0 / #222225, radius 16 px) with a lock icon, one
  line of copy and the filled Unlock; the secrets below show a quiet "Locked" caption.
- **Disabled controls**: 45% opacity, no hover, a not-allowed cursor.
- **Frameless helper windows** (auto-type pick, 2FA code): a 1px --border edge and the system shadow.
- **Subpages** (everything reached from Settings, Password health, Trash, Import): a round back
  arrow before the page title; the toolbar button of the open page keeps the selection fill.
- **Menus, popovers, dialogs, toasts**: --surface-raised, --shadow, radius 14 px (dialogs 18 px), no
  outline; menu rows with the hover fill. Inside a dialog, cards and field lists lose their white box
  (the dialog is already the surface).
- **Frameless popups** (auto-type pick, 2FA code, prompts): a white window with a hairline edge,
  since it sits on any desktop rather than on the grey page.

## Type

- Font: "Space Grotesk" (variable, weights 300 to 700), bundled, SIL OFL 1.1.
  Files: `Core/desktop-app/ui/fonts/`, `Extension/src/ui/fonts/` (latin, latin-ext, vietnamese woff2),
  `Android/app/src/main/res/font/space_grotesk.ttf`.
- Body 400, labels 500 to 600, buttons 600, headings 700 with letter-spacing -0.02em (page titles
  and the centred screens' titles -0.03em to -0.035em).
- Scale on desktop: captions 12 px, body 14 px, section headings 16 to 18 px, page titles 30 px,
  centred-screen titles 32 px. Other surfaces keep their own scale with the same steps.

## Shape and spacing

- Radii: --radius-sm 6px, --radius / --r-input 10px, rows 10px, --radius-lg 14px (menus, toasts),
  --r-card 16px, --r-dialog 18px, --r-hero 24px, --r-pill 999px.
- Spacing stays on the existing 4 px scale.
- Buttons and inputs: 36 px tall on desktop and in the popup (30 px small, 44 to 46 px on the centred
  screens); 1px borders.

## Logo

The mark is the "y" of the wordmark ("Pass", the lime "y", "ble", as on passyble.com): Sensyble's
stylised "y" turned into a key (the ring is the key's bow, the stroke its shaft, the short arm its
bit, with a ward slot). It stands exactly as in the wordmark: the bow at the bottom left, the shaft
rising to the right, the bit at the top right. There is no tile and no background anywhere.

- **Full colour** (everywhere the logo appears in colour: Windows .ico and tray, installer, Linux and
  macOS icons, extension toolbar, favicons and link previews, the Android launcher and in-app logo,
  the passkey provider logo, the wordmark's "y" in every app and on passyble.com, account.passyble.com,
  help.passyble.com and the admin panel): the mark in the brand lime #c6f432 with a darker green
  border #4f6b00, on transparent, the same in light and dark themes. The border is drawn outside the
  lime and counted in the mark's size (the lime shrinks to make room, so layouts keep their spacing).
  Weight: about 6% of the lime mark's height (1.2 of 24 icon units; about 26 px on the 512 px icon,
  13 px at 256, 2.4 px at 48), never under 1.5 px. The border is 4.8:1 against the lime and 6.1:1 on
  white, so the shape holds on light taskbars, tab bars and pages; on dark surfaces (2.9:1 on #18181a)
  it reads as a green rim and the lime does the work. #3d5400 was tried and rejected: it sinks into
  dark surfaces (2.1:1) and reads as a shadow rather than a border.
- **Geometry for the border**: the bow's hole is 0.63 of the bow (so it stays open inside the
  border) and the ward slot is wider (0.32 to 0.68 of the bit's end); the border fills the slot, so
  the bit's end reads as a dark notch between two teeth.
- **Monochrome** (Android notification and themed icon, the macOS menu bar template): the bare mark
  in one colour (white, or black for the template image, which macOS tints), no border. The themed
  icon reaches as far as the full-colour launcher icon's border, so both are the same size.
- **Small sizes**: at 20 px and below the ward slot is dropped and the bow is drawn heavier with a
  larger hole (0.76) that survives the 1.5 px border; up to 48 px the mark is moved to the sub-pixel
  position where the lime and the border together are crispest.
- `--lime-mark` (#6e9a00 / #c6f432) is no longer used for the logo, only for status dots, checks and
  other small accents.

Generated by `Core/desktop-app/scripts/make-icons.mjs` (desktop, extension and Android icons, the
extension's in-page logo, `wordmarkSvg()` for the wordmark's "y"; the Mac and website icon scripts
import it, and the websites' inline wordmarks, the Accounts and admin static logos and
`ui/lib.js wordmark()` carry its output). On Android the adaptive icon's
background layer is transparent, so the launcher shows the lime mark on the wallpaper.
