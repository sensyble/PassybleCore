# Translating Passyble

This guide is for anyone who translates Passyble or adds a language. Passyble has four apps, and each
one keeps its texts in its own format. A fifth catalog belongs to pass-core, the library the Windows
and Android apps share: its error messages, import warnings and merge descriptions. English is always
the source. You translate the English text and never change the keys or the code.

Languages shipped so far: Spanish (`es`), French (`fr`), German (`de`), Chinese Simplified (`zh-CN`),
Japanese (`ja`), Korean (`ko`), Hindi (`hi`) and Indonesian (`id`).

Contents:

1. [Where the files are](#where-the-files-are)
2. [Start a new language](#start-a-new-language)
3. [Placeholders](#placeholders)
4. [Plurals](#plurals)
5. [Escaping](#escaping)
6. [Words to keep in English, and suggested terms](#words-to-keep-in-english-and-suggested-terms)
7. [Tone and register](#tone-and-register)
8. [Check your work](#check-your-work)
9. [Missing texts fall back to English](#missing-texts-fall-back-to-english)
10. [When the English text changes](#when-the-english-text-changes)
11. [The Windows installer](#the-windows-installer)
12. [See your translation in the apps](#see-your-translation-in-the-apps)

## Where the files are

| app | English source | your language | format |
|---|---|---|---|
| Windows app | `Core/desktop-app/ui/i18n/en.json` | `Core/desktop-app/ui/i18n/<tag>.json` | flat JSON |
| Browser extension | `Extension/_locales/en/messages.json` | `Extension/_locales/<locale>/messages.json` | WebExtension `messages.json` |
| Android app | `Android/app/src/main/res/values/strings.xml`, `strings_services.xml`, `strings_ui.xml` | `Android/app/src/main/res/values-<qualifier>/` (same three file names) | Android string resources |
| Passyble Server | `Server/locales/en/` (`strings.toml` and 12 e-mail templates) | `Server/locales/<tag>/` (same file names) | TOML and text/HTML templates |
| pass-core (shared by the Windows and Android apps) | `Core/core/locales/en.json` | `Core/core/locales/<tag>.json` | flat JSON, same as the Windows app |

Each app names a language a little differently:

| language | Windows, server, core | extension folder | Android folder | Android `locales_config.xml` |
|---|---|---|---|---|
| Spanish | `es` | `es` | `values-es` | `es` |
| French | `fr` | `fr` | `values-fr` | `fr` |
| German | `de` | `de` | `values-de` | `de` |
| Chinese (Simplified) | `zh-CN` | `zh_CN` | `values-zh-rCN` | `zh-CN` |
| Japanese | `ja` | `ja` | `values-ja` | `ja` |
| Korean | `ko` | `ko` | `values-ko` | `ko` |
| Hindi | `hi` | `hi` | `values-hi` | `hi` |
| Indonesian | `id` | `id` | `values-in` (Android's old code) | `id` |

The app READMEs have more detail: `Core/desktop-app/README.md`, `Extension/README.md` and
`Android/README.md` (section "Translations"), and `Server/README.md` (section "Languages").

**pass-core** writes the texts both apps show as they come from the core: why an import skipped an
entry, what a merge adds ("2 websites"), a malformed link, a server or Google Drive error. One
translation serves Windows and Android; each app tells the core its language (`set_language`), and
the core's messages follow it. Short words such as "upload" or "sign-in" (keys `action.*`) start
error messages ("upload: storage quota reached"), so translate them as such a label. Item titles the
core makes up ("Imported note", "Card •••• 1234") and custom field names it gives imported data
("Phone", keys `import.field.*`) are saved into the vault in the language that was active.

## Start a new language

The examples add Portuguese (Brazil): `pt-BR`. Replace it with your language.

**Windows app.** The app finds every file in the folder at build time; nothing to register.

```sh
cp Core/desktop-app/ui/i18n/en.json Core/desktop-app/ui/i18n/pt-BR.json
```

Set `_meta` to the English name and the native name of the language:
`"_meta": { "name": "Portuguese (Brazil)", "native": "Português (Brasil)" }`. Then translate every value.
Keep the keys and their order. Set `size.decimal_separator` to your language's decimal mark.

**pass-core.** The same format as the Windows app. The core finds every file in the folder at build
time (`Core/core/build.rs`); nothing to register.

```sh
cp Core/core/locales/en.json Core/core/locales/pt-BR.json
```

Set `_meta` as for the Windows app and translate every value. Keep `{action}: ` (with this colon and
space) at the start of a text where English has it: the apps cut the label off there.

**Browser extension.** The folder is all you need.

```sh
mkdir Extension/_locales/pt_BR
cp Extension/_locales/en/messages.json Extension/_locales/pt_BR/messages.json
```

Translate every `"message"`. Set the `catalogLocale` message to the folder name with `-`
(`"pt-BR"`). You may delete the `"description"` fields or keep them. Keep the `"placeholders"`
blocks exactly as they are. `extName` may have at most 75 characters and `extDescription` at most 132
(store limits).

**Android app.**

```sh
mkdir Android/app/src/main/res/values-pt-rBR
cp Android/app/src/main/res/values/strings*.xml Android/app/src/main/res/values-pt-rBR/
```

Translate the text of every `<string>` and `<item>`. Delete every entry marked
`translatable="false"`. You may delete the `<!-- comments -->` (read them first: they say where each
text appears and what each placeholder holds). Keep `xmlns:xliff="..."` on `<resources>`.

Then register the language in `Android/app/src/main/res/xml/locales_config.xml`, or Android 13+ won't
offer it:

```xml
<locale android:name="pt-BR" />
```

**Passyble Server.** The server compiles every folder in `Server/locales/` at build time; nothing
to register.

```sh
cp -r Server/locales/en Server/locales/pt-BR
```

Translate `strings.toml` and the 12 templates. In `[meta]`, set `name` to the language's own name;
leave `dir = "ltr"` (or `"rtl"` for a right-to-left language).

**Where to register a language, in short:**

| app | register it |
|---|---|
| Windows app | nothing; the file is found automatically |
| Browser extension | nothing; the folder is enough |
| Android app | add `<locale android:name="..."/>` to `res/xml/locales_config.xml` |
| Passyble Server | nothing; the folder is found automatically |
| pass-core | nothing; the file is found automatically |

## Placeholders

Placeholders are replaced by a value when the app runs: a name, a number, a website. Copy them
exactly. You may move them to where your language needs them. Never translate the name inside.
The checker reports a missing, extra or renamed placeholder as an error.

| app | placeholder | English | example translation (German) |
|---|---|---|---|
| Windows, core | `{name}` | `"Can't reach {host}."` | `"{host} ist nicht erreichbar."` |
| Extension | `$NAME$` plus a `placeholders` block | `"Look up $SITE$"` | `"$SITE$ nachschlagen"` |
| Android | `%1$s`, `%2$d` (numbered) inside `<xliff:g>` | `Unlock with <xliff:g id="method">%1$s</xliff:g>` | `Mit <xliff:g id="method">%1$s</xliff:g> entsperren` |
| Server | `{{name}}` | `"Reset your Passyble password on {{server_name}}"` | `"Passyble-Passwort auf {{server_name}} zurücksetzen"` |

Details per app:

* **Windows and core:** every placeholder of the English text must be in your text. In a plural, one
  form may leave out `{count}` (for example "a minute" instead of "1 minute").
* **Extension:** the message uses `$SITE$`; the `"placeholders"` block defines `site` with
  `"content": "$1"`. Keep the block the same as in English (same names, same `$1`, `$2`).
* **Android:** the number in `%1$s` says which value it is; keep the numbers even if you change the
  order. `%%` is a literal percent sign; keep it where English has it. Keep each `<xliff:g>` element
  and the text inside it. In a `<plurals>`, the `other` item must have every placeholder of English
  `other`; the other items may leave out the count.
* **Server:** `{{#name}}...{{/name}}` is a section that only shows when `name` has a value. Keep both
  tags and translate the text between them.

## Plurals

Many texts change with a number ("1 day", "2 days"). Each app stores the forms by
[CLDR plural category](https://cldr.unicode.org/index/cldr-spec/plural-rules): `zero`, `one`, `two`,
`few`, `many`, `other`. Give the categories your language uses. `other` is always required.

The shipped languages:

| language | categories | notes |
|---|---|---|
| English | `one`, `other` | |
| Spanish | `one`, `many`, `other` | `many` is for very large round numbers (1 000 000); optional, usually the same text as `other` |
| French | `one`, `many`, `other` | `one` covers 0 and 1; `many` as in Spanish (optional) |
| German | `one`, `other` | |
| Hindi | `one`, `other` | `one` covers 0 and 1 |
| Chinese, Japanese, Korean, Indonesian | `other` | no plural forms: give only `other` |

To see the categories of any language: `node -e "console.log(new Intl.PluralRules('pt-BR').resolvedOptions().pluralCategories)"`.

How each app writes them:

* **Windows and core:** an object: `"trash.purge_in_days": { "one": "{count} day", "other": "{count} days" }`.
  Japanese: `{ "other": "{count} 日" }`. The core picks the category by its own rules
  (`plural_category` in `Core/core/src/i18n.rs`, the same as the Windows app's).
* **Extension:** one message per form, with a suffix: `badgeLogins_one`, `badgeLogins_other`
  (and `_many`, `_few` and so on). Japanese has only `badgeLogins_other`. If you translate a plural,
  give every form your language needs for 0 to 1000 (the checker says which).
* **Android:** `<plurals>` with `<item quantity="one">` and `<item quantity="other">`. A quantity
  your language doesn't have (for example `one` in Japanese) is an error.
* **Server:** a TOML table:

  ```toml
  [time.days]
  one = "{{count}} day"
  other = "{{count}} days"
  ```

  The server picks only `one` or `other`, by its own rule (`plural_category` in `Server/src/i18n.rs`):
  French and Hindi use `one` for 0 and 1; Chinese, Japanese, Korean and Indonesian need only
  `other`. A language that needs `few` or `many` also needs a code change there.

A text that says something different for exactly one ("The item is back.") is a separate key, not
a plural. Translate it as it is.

## Escaping

**Android** (the most strict):

* Write an apostrophe as `\'` and a double quote as `\"`. An unescaped `'` breaks the build. You
  may use typographic quotes instead (’ “ ” « »); they need no escaping.
* A text must not start with `@` or `?`. Write `\@` or `\?` if it must.
* `\n` is a line break. Keep the ones English has.
* XML rules: write `&` as `&amp;` and `<` as `&lt;`.
* `%` alone starts a placeholder. Write a literal percent sign as `%%` (only where English does).

**Server:**

* Strings under `[page]` in `strings.toml` are HTML. Keep the tags (`<b>`, `<a href="{{download_url}}" ...>`)
  and translate the text around and inside them. Write `&` as `&amp;` and `<` as `&lt;`. Values put
  into placeholders are escaped by the server; don't escape them yourself.
* The `.html` templates are HTML e-mails: keep every tag and attribute; translate only the visible
  text. Keep `lang="{{language}}"`.
* The `.txt` templates and all other strings are plain text.
* In TOML, a `"..."` string needs `\"` for a quote and `\\` for a backslash. `'...'` strings take
  the text as it is, but can't contain `'`. `"""..."""` strings may span lines.

**Windows, core and extension:** these are JSON files. Write a quote as `\"`, a backslash as `\\` and a
line break as `\n`. In the extension, a literal `$` is written `$$`.

## Words to keep in English, and suggested terms

**Never translate:** Passyble, Passyble Server, Windows, Windows Hello, Android, Google, Google
Drive, Google Authenticator, WebDAV, Nextcloud, OneDrive, Dropbox, Syncthing, Bitwarden, 1Password,
KeePassXC, LastPass, Dashlane, Proton Pass, Aegis, 2FAS, Chrome, Edge, Firefox, Safari, CSV, JSON,
ZIP, QR, URL, HTTPS, TOTP, ES256, card brands (Visa, Mastercard), file names, paths, commands
(`pass-server ...`), URLs and addresses (`pass+server://`, `otpauth://`, `pass.example.com`,
`about:addons`), e-mail addresses, code names, and anything inside backticks.

**Key names.** The Windows app shows shortcuts with the key names of your language: the `keys.*`
texts (`keys.ctrl`, `keys.shift`, `keys.page_up`, ...). Use the names a Windows keyboard and
Windows' own help use in your language: German `Strg`, `Umschalt`, `Leertaste`, `Einfg`, `Pos1`,
`Ende`, `Bild↑`, `Bild↓`; French `Maj`, `Inser`, `Origine`; Spanish `Mayús`, `Inicio`, `Re Pág`.
Many languages keep the English names. When a text mentions a shortcut ("Lock (Ctrl+L)"), write
it with the same names (German `Strg+L`, `Strg+Umschalt+L`). The letter keys and Win stay as they
are.

**Suggested terms.** Use one word for one thing, in every app.

| English | es | fr | de | zh-CN | ja | ko | hi | id |
|---|---|---|---|---|---|---|---|---|
| passkey | llave de acceso | clé d'accès | Passkey | 通行密钥 | パスキー | 패스키 | पासकी | kunci sandi |
| 2FA code | código 2FA | code 2FA | 2FA-Code | 两步验证码 / 2FA 验证码 | 2FA コード (or 確認コード) | 2FA 코드 | 2FA कोड | kode 2FA |
| vault | bóveda | coffre | Tresor | 密码库 | 保管庫 | 보관함 | वॉल्ट | brankas |
| master password | contraseña maestra | mot de passe principal | Master-Passwort | 主密码 | マスターパスワード | 마스터 비밀번호 | मास्टर पासवर्ड | kata sandi utama |
| login (saved item) | inicio de sesión | identifiant | Login / Anmeldedaten | 登录信息 | ログイン情報 | 로그인 정보 | लॉगिन | info masuk |
| autofill | autocompletar | saisie automatique | Autofill / automatisch ausfüllen | 自动填充 | 自動入力 | 자동 완성 | ऑटोफ़िल | isi otomatis |
| recovery code | código de recuperación | code de récupération | Wiederherstellungscode | 恢复码 | 復旧コード | 복구 코드 | रिकवरी कोड | kode pemulihan |
| trash | papelera | corbeille | Papierkorb | 回收站 | ゴミ箱 | 휴지통 | ट्रैश | sampah |

For autofill, use the word Android and Windows use in your language. Names of menus in the Windows
app (Settings → Autofill) should match between the Windows app and the extension, which refers to them.

## Tone and register

Write natural, short UI text, as a native speaker expects in a well-localized password manager.
Short labels stay short. Buttons are verbs.

| language | register |
|---|---|
| Spanish | informal "tú" |
| French | formal "vous" |
| German | informal "du" (as Google, Apple and Bitwarden do) |
| Chinese (Simplified) | neutral and concise |
| Japanese | です/ます style |
| Korean | 해요체 for sentences, plain nouns for labels |
| Hindi | standard Hindi in Devanagari; common English tech words (ऐप) are fine |
| Indonesian | formal-neutral "Anda" |

French may use the typographic apostrophe ’ (no escaping needed on Android).

## Check your work

From the Passyble-Core repository's root, with Node 20 or later (no install needed). It checks the apps whose
repositories are cloned next to it (`../Extension`, `../Android`, `../Server`) and skips the others:

```sh
node scripts/i18n-check.mjs --lang pt-BR
```

It checks all four apps and pass-core without building anything and prints a coverage table, then
errors and warnings. Options:

| option | does |
|---|---|
| `--lang <tag>` | only this language; any spelling works (`zh-CN`, `zh_CN`, `zh-rCN`; `id` or `in`). Lists every missing key |
| `--app <name>` | only `windows`, `extension`, `android`, `server` or `core` (comma-separate for several) |
| `--strict` | warnings (missing texts too) count as errors |
| `--json` | machine-readable output |
| `--verbose` | list every missing key for every language |

Errors make it exit with code 1: unknown keys, wrong placeholders, invalid plural forms, empty texts,
bad escaping, broken files, a language missing from Android's `locales_config.xml`. Warnings
(missing texts, missing plural forms, hints) keep exit code 0 unless you pass `--strict`.

Sample output (a small test tree, `--lang fr`):

```text
Coverage (translated/total, -missing):

  lang   windows   android
  ----   -------   -------
  fr      3/4 -1    2/5 -3

Warnings (2):
  fr: Core/desktop-app/ui/i18n/fr.json
    1 of 4 texts missing (English is shown)
      app.title
  fr: Android/app/src/main/res/values-fr/strings.xml
    3 of 5 strings missing (English is shown)
      app_name
      save_sync
      markup

i18n-check: ok (2 warnings; missing texts fall back to English)
```

An error looks like this:

```text
Errors (2):
  de: Android/app/src/main/res/values-de/strings.xml
    greet: unescaped ' (write \' or use ’)
    greet: placeholders {%1$s}, English has {%%, %1$s, %2$d}
```

The apps' own tests check the same things and more (for example that every key the code uses
exists in English):

| app | test |
|---|---|
| Windows | `node --test desktop-app/ui/test/*.test.mjs` (in Passyble-Core) |
| Extension | `cd ../Extension && npm install && npm test` |
| Android | `cd ../Android && gradle testDebugUnitTest` (needs Gradle and the Android SDK) |
| Server | `cd ../Server && cargo test -p pass-server` (needs Rust) |
| pass-core | `cargo test -p pass-core` (needs Rust; `Core/core/src/i18n_tests.rs`: every key the code uses is in `en.json` with its placeholders, no unused keys, other files only known keys and valid plurals) |

For Android XML, a quick well-formedness check:
`python3 -c "import xml.dom.minidom,sys;xml.dom.minidom.parse(sys.argv[1])" FILE`.

## Missing texts fall back to English

A partial translation works in every app. A text you haven't translated yet shows in English.

| app | a missing text | a missing plural form |
|---|---|---|
| Windows | English, then the key itself (with a console warning) | `other` |
| Extension | English, message by message (the browser does it) | `_other` |
| Android | English (`values/`), string by string | `other` |
| Server | English, string by string and file by file | `other` |
| pass-core | English, then the key itself | `other` |

The server's tests (`cargo test -p pass-server`) still require every file and every string for a
built-in language, so finish a server translation before you ship it. Leave a text out rather than
leave it empty: an empty text is an error, because it would show nothing.

## When the English text changes

When a developer adds, renames or removes an English text, run the checker for your language:

```sh
node scripts/i18n-check.mjs --lang de
```

* **Missing keys** (warnings) are new or renamed English texts. The checker lists them by file.
  Translate them and add them in the same place as in English.
* **Unknown keys** (errors: "not in en.json", "not an English message", "not in values/",
  "not in en/strings.toml") were removed or renamed in English. Delete them, or move your
  translation to the new key.
* **Placeholder errors** mean the English text gained or lost a placeholder. Update your text.

A key whose English meaning changed but whose name stayed the same doesn't show up. Check `git log -p`
on the English file for changed texts.

## The Windows installer

The Windows app has two installers. Their texts are not in the catalogs:

* **NSIS setup** (what users download, and what the app's updates install) follows the Windows
  display language: English, Spanish, French, German, Chinese (Simplified), Japanese, Korean, Hindi
  and Indonesian, else English. NSIS translates its own pages; Tauri adds 27 texts of its own
  ("... is running", WebView2), which it ships for most languages but not for Hindi and Indonesian:
  those are in `Windows/installer/nsis-lang/Hindi.nsh` and `Indonesian.nsh`.
  Passyble's few installer texts are in `Windows/installer/nsis-lang/Passyble.nsh`, for every language.
* **MSI** (WiX, per-machine installs that IT departments deploy) stays in English (`en-US`).

**Add a language to the NSIS setup:** add its NSIS name (as in NSIS's `Contrib/Language files`,
e.g. `PortugueseBR`) to `bundle.windows.nsis.languages` in `Core/desktop-app/src-tauri/tauri.conf.json`,
and its ID and texts to `Windows/installer/nsis-lang/Passyble.nsh`. If Tauri doesn't ship its texts for that
language (the build warns), translate Tauri's English file (`src/bundle/windows/nsis/languages/English.nsh`
in the `tauri-bundler` crate, the same 27 lines as `Hindi.nsh`) into
`Windows/installer/nsis-lang/<Language>.nsh` with `${LANG_<LANGUAGE>}` in place of `${LANG_ENGLISH}`, and
list it in `customLanguageFiles`. Keep `{{product_name}}`, `${PRODUCTNAME}`, `${VERSION}`, `$R4`,
`$0`, `$1` and `$\n` as they are.

## See your translation in the apps

**Windows app:** Settings → Display → Language. "System default" follows the Windows display
language. Every window reloads in the new language.

**Android app:** on Android 13 and later, Settings → Apps → Passyble → Language (Passyble's own
Settings → Display → Language opens it). The language must be in `locales_config.xml`. On older
Android versions, Passyble follows the phone's language.

**pass-core:** its messages follow the language of the app that shows them (Windows or Android, as
above). Rebuild the app after you change `Core/core/locales/`.

**Browser extension:** the extension uses the browser's UI language.

* Chrome and Edge on Windows: Settings → Languages; choose "Display in this language" for your
  language and restart the browser. Or start Chrome once with `chrome.exe --lang=pt-BR`.
* Firefox: Settings → General → Language, or set `intl.locale.requested` in `about:config`.

After you change a translation, reload the extension (`chrome://extensions` → reload, or
`about:debugging` in Firefox).

**Passyble Server:** e-mails use the account's language, else `server.default_language`.

* Set an account's language: `pass-server user set-language bob pt-BR` (or `--clear`). The apps also
  send their language at sign-up and sign-in.
* `pass-server email test you@example.com` sends a test e-mail in the server's default language
  (`server.default_language` in the config). Invites, resets and notifications use the account's
  language.
* The pages behind invite and reset links use the account's language, else the browser's language
  (`Accept-Language`). To try a page in another language:
  `curl -H 'Accept-Language: pt-BR' https://pass.example.com/...`, or change the browser's language.
* Rebuild the server after you change the files in `Server/locales/`. Without rebuilding, an admin can
  test files from `email.templates_dir/<tag>/` (see `Server/README.md`).
