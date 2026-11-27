# Third-party notices

## Lucide icons

The user-interface icons of the desktop app (`Core/desktop-app/ui/icons.js`) and the browser extension
(`Extension/src/shared/icons.js`) are SVG data from [Lucide](https://lucide.dev), vendored (only the
icons in use, no runtime dependency).

```
ISC License

Copyright (c) for portions of Lucide are held by Cole Bemis 2013-2022 as part of Feather (MIT). All other copyright (c) for Lucide are held by Lucide Contributors 2022.

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
```

Portions derived from Feather (https://github.com/feathericons/feather):

```
The MIT License (MIT)

Copyright (c) 2013-2023 Cole Bemis

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## ZXing

The Android app draws and decodes QR codes (camera scan, QR codes in an image) with
[ZXing](https://github.com/zxing/zxing) core (`com.google.zxing:core`), on the device.

```
Copyright (C) 2008 ZXing authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

## 2FA Directory

Password health's "Turn on two-factor sign-in" check uses an offline list of the sites that offer a
second step at sign-in, with links to how to turn it on (`Core/core/data/2fa-directory.tsv`). It is data
from the [2FA Directory](https://2fa.directory) ([2factorauth/twofactorauth](https://github.com/2factorauth/twofactorauth)),
reduced to each site's domain, methods and documentation link by `scripts/update-site-security.mjs`.

```
The MIT License (MIT)

Copyright © 2021 2factorauth (https://github.com/2factorauth) and Contributors.

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
```

```
The MIT License (MIT)

Copyright (c) 2014-2020 Josh Davis

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

## Passkeys Directory

Password health's "Add a passkey" suggestion uses an offline list of the sites that support
passkeys, with links to how to add one (`Core/core/data/passkeys-directory.tsv`). It is data from the
[Passkeys Directory](https://passkeys.2fa.directory) ([2factorauth/passkeys](https://github.com/2factorauth/passkeys))
by 2factorauth and contributors, licensed under the
[Creative Commons Attribution 4.0 International License](https://creativecommons.org/licenses/by/4.0/)
(CC BY 4.0). Changes: reduced to each site's domain, passkey modes and documentation link by
`scripts/update-site-security.mjs`. No icons from the directory are used.

## EFF large wordlist (passphrases)

Generated passphrases use real English words from the [EFF large wordlist](https://www.eff.org/dice)
(7,776 words, `Core/core/src/wordlist/eff_large.txt`, embedded in the core). The list is by the
Electronic Frontier Foundation, licensed under the
[Creative Commons Attribution 3.0 United States License](https://creativecommons.org/licenses/by/3.0/us/)
(CC BY 3.0 US). Changes: the dice numbers in front of each word were removed, leaving one word per line.

## Common passwords list (no third-party data)

The password checks of the save prompts and editors, and the strength estimate, look passwords up
in `Core/core/data/common-passwords.txt` (about 1,300 entries: number runs, keyboard rows, common
words, names, pets, teams and places, and words of love in the apps' languages). The list was
written for Passyble from general knowledge of what people pick; no third-party password list was
copied into it, so it is covered by the project's own licence. It is bundled into the core and
used on the device only. If a larger published list replaces it later (for example the MIT-licensed
SecLists `Passwords/Common-Credentials` lists), its source and licence go here.

## Rust crates for encrypted imports

The core (`Core/core/`, linked into the Windows app and the Android library) opens password-protected exports of other
apps with these crates from crates.io, pinned in `Core/core/Cargo.toml` and `Cargo.lock`. Each is used under the licence
named; their full texts ship with the crates' sources.

| crate | version | licence | used for |
|---|---|---|---|
| [keepass](https://github.com/sseemayer/keepass-rs) | 0.15.3 | MIT | KeePass `.kdbx` / `.kdb` databases (feature `import-kdbx`) |
| [pgp](https://github.com/rpgp/rpgp) (rPGP) | 0.21.0 | MIT OR Apache-2.0 | passphrase-encrypted OpenPGP messages, Proton Pass (feature `import-pgp`) |
| [aes](https://github.com/RustCrypto/block-ciphers) | 0.8.4 | MIT OR Apache-2.0 | Bitwarden AES-256-CBC |
| [cbc](https://github.com/RustCrypto/block-modes) | 0.1.2 | MIT OR Apache-2.0 | Bitwarden AES-256-CBC |
| [aes-gcm](https://github.com/RustCrypto/AEADs) | 0.10.3 | Apache-2.0 OR MIT | Aegis and 2FAS AES-256-GCM |
| [hkdf](https://github.com/RustCrypto/KDFs) | 0.12.4 | MIT OR Apache-2.0 | Bitwarden key stretching |
| [pbkdf2](https://github.com/RustCrypto/password-hashes) | 0.12.2 | MIT OR Apache-2.0 | Bitwarden and 2FAS key derivation |
| [scrypt](https://github.com/RustCrypto/password-hashes) | 0.11.0 | MIT OR Apache-2.0 | Aegis key derivation |
| [zip](https://github.com/zip-rs/zip2) feature `aes-crypto` | 9.x (already used) | MIT | AES-encrypted ZIP members |

Pulled in by `keepass` and `pgp` (all permissive): RustCrypto ciphers, hashes, curves and modes (MIT OR Apache-2.0:
`aes` 0.9, `cipher` 0.5, `cbc` 0.2, `block-modes`, `salsa20`, `chacha20` 0.10, `twofish`, `blowfish`, `cast5`, `des`,
`idea`, `camellia`, `cfb-mode`, `ctr`, `eax`, `ocb3`, `aes-kw`, `cmac`, `ghash`, `polyval`, `md-5`, `ripemd`, `sha3`,
`sha1-checked`, `rsa`, `dsa`, `k256`, `p384`, `p521`, `ed25519`, `pkcs1`), `rust-argon2` (MIT/Apache-2.0),
`secrecy`, `snafu`, `derive_builder`, `num-bigint-dig`, `buffer-redux`, `crc24`, `replace_with`, `hex-literal`
(MIT OR Apache-2.0), `bitfields`, `bitvec`, `funty`, `radium`, `tap`, `wyz`, `darling`, `spin`, `libm`,
`blake2b_simd`, `convert_case` (MIT), `curve25519-dalek`, `ed25519-dalek`, `x25519-dalek`, `cx448` (BSD-3-Clause),
`fiat-crypto` (MIT OR Apache-2.0 OR BSD-1-Clause) and `constant_time_eq` (CC0-1.0 OR MIT-0 OR Apache-2.0). Only
symmetric (password) decryption is used from `pgp`; its public-key code, including `rsa` (RUSTSEC-2023-0071, a timing
side channel in RSA decryption), is never called. `zip` 9 also pulls in `typed-path` (MIT OR Apache-2.0) and, on
Unix-like systems (Android, iOS, macOS, Linux), `nix` and `cfg_aliases` (MIT).

## UniFFI (Android and iOS bindings)

The Android and iOS apps call the core through bindings made with [UniFFI](https://github.com/mozilla/uniffi-rs)
0.29.5 (`uniffi`, `uniffi_core`, `uniffi_macros`, and `uniffi_bindgen`, which generates the Kotlin and Swift files),
licensed under the Mozilla Public License 2.0 (MPL-2.0). Its runtime code is compiled into the Android library and
the iOS framework, and the generated `pass_core.kt` and `pass_core.swift` come from its templates. MPL-2.0 is a
file-level copyleft: those files stay under MPL-2.0 and are used unmodified; their source is available at
https://github.com/mozilla/uniffi-rs (tag v0.29.5) and the licence text at https://mozilla.org/MPL/2.0/. The rest
of Passyble is not affected.

## Rust crates for passkeys

Passkeys (ES256, `Core/core/src/passkey.rs`) are made and signed with [p256](https://github.com/RustCrypto/elliptic-curves)
0.14 and the RustCrypto crates it pulls in: `ecdsa` 0.17, `elliptic-curve` 0.14, `crypto-bigint` 0.7, `primeorder`,
`primefield`, `sec1`, `pkcs8`, `spki`, `der`, `signature` 3, `rfc6979`, `ff`, `group`, `wnaf`, `base16ct`,
`pem-rfc7468` and `serdect` (all MIT OR Apache-2.0).

## Rust crates for shared vaults

The core's shared vaults (Family, Teams and direct shares; `Core/core/src/share/`, docs/ARCHITECTURE.md §15) wrap
the vault key for each member with HPKE and sign the members list with Ed25519, with these crates from crates.io,
pinned in `Core/core/Cargo.toml` and `Cargo.lock`. They are in every build of the core (the Windows app, the Android
library and the browser extension's WebAssembly).

| crate | version | licence | used for |
|---|---|---|---|
| [hpke](https://github.com/rozbb/rust-hpke) | 0.12.0 | MIT OR Apache-2.0 | HPKE (RFC 9180): the vault key wrapped for each member |
| [ed25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) | 2.2.0 | BSD-3-Clause | signatures of members lists and of each user's public keys |
| [x25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) | 2.0.1 | BSD-3-Clause | X25519 inside HPKE (named for its `zeroize` feature) |
| [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) | 4.1.3 | BSD-3-Clause | the curve arithmetic of both (pulled in) |

Everything else they use was already in the tree (RustCrypto `aead`, `aes-gcm`, `chacha20poly1305`, `hkdf`, `hmac`,
`sha2`, `digest`, `generic-array`, `subtle`, `zeroize`, `rand_core`; `fiat-crypto`). The BSD-3-Clause crates ask for
their notice in binary distributions:

```
Copyright (c) 2016-2021 isis agora lovecruft. All rights reserved.
Copyright (c) 2016-2021 Henry de Valence. All rights reserved.
Copyright (c) 2019-2021 DebugSteven. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

Portions of curve25519-dalek were derived from Adam Langley's Go ed25519 implementation:

```
Copyright (c) 2012 The Go Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google Inc. nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## Rust crates of the connector for AI tools

The connector for AI tools (`Core/mcp`, `passyble-mcp`) adds no crate the Passyble apps didn't already ship. It names
these directly, all already in `Cargo.lock` through pass-core, pass-agent and the native host:

| crate | licence | used for |
|---|---|---|
| [memchr](https://github.com/BurntSushi/memchr) | MIT OR Unlicense | finding secret values in command output (`mcp/src/mask.rs`) |
| [base64](https://github.com/marshallpierce/rust-base64) | MIT OR Apache-2.0 | the base64 forms of secret values to conceal |
| [zeroize](https://github.com/RustCrypto/utils) | MIT OR Apache-2.0 | clearing secret values and captured output |
| [serde](https://github.com/serde-rs/serde), [serde_json](https://github.com/serde-rs/json) | MIT OR Apache-2.0 | JSON-RPC (MCP) messages |
| [windows-sys](https://github.com/microsoft/windows-rs) | MIT OR Apache-2.0 | Windows: job objects, the process snapshot |
| [libc](https://github.com/rust-lang/libc) | MIT OR Apache-2.0 | unix: stopping the command's process group |

MCP itself is implemented by hand (no MCP SDK).

## Space Grotesk

The user-interface font of the desktop app (`Core/desktop-app/ui/fonts/`), the browser extension
(`Extension/src/ui/fonts/`) and the Android app (`Android/app/src/main/res/font/space_grotesk.ttf`)
is [Space Grotesk](https://github.com/floriankarsten/space-grotesk), bundled unmodified (the
woff2 subsets come from the Fontsource package). A copy of the license sits next to the web font files
as `OFL.txt`.

```
Copyright 2020 The Space Grotesk Project Authors (https://github.com/floriankarsten/space-grotesk)

This Font Software is licensed under the SIL Open Font License, Version 1.1.
This license is copied below, and is also available with a FAQ at:
http://scripts.sil.org/OFL


-----------------------------------------------------------
SIL OPEN FONT LICENSE Version 1.1 - 26 February 2007
-----------------------------------------------------------

PREAMBLE
The goals of the Open Font License (OFL) are to stimulate worldwide
development of collaborative font projects, to support the font creation
efforts of academic and linguistic communities, and to provide a free and
open framework in which fonts may be shared and improved in partnership
with others.

The OFL allows the licensed fonts to be used, studied, modified and
redistributed freely as long as they are not sold by themselves. The
fonts, including any derivative works, can be bundled, embedded,
redistributed and/or sold with any software provided that any reserved
names are not used by derivative works. The fonts and derivatives,
however, cannot be released under any other type of license. The
requirement for fonts to remain under this license does not apply
to any document created using the fonts or their derivatives.

DEFINITIONS
"Font Software" refers to the set of files released by the Copyright
Holder(s) under this license and clearly marked as such. This may
include source files, build scripts and documentation.

"Reserved Font Name" refers to any names specified as such after the
copyright statement(s).

"Original Version" refers to the collection of Font Software components as
distributed by the Copyright Holder(s).

"Modified Version" refers to any derivative made by adding to, deleting,
or substituting -- in part or in whole -- any of the components of the
Original Version, by changing formats or by porting the Font Software to a
new environment.

"Author" refers to any designer, engineer, programmer, technical
writer or other person who contributed to the Font Software.

PERMISSION & CONDITIONS
Permission is hereby granted, free of charge, to any person obtaining
a copy of the Font Software, to use, study, copy, merge, embed, modify,
redistribute, and sell modified and unmodified copies of the Font
Software, subject to the following conditions:

1) Neither the Font Software nor any of its individual components,
in Original or Modified Versions, may be sold by itself.

2) Original or Modified Versions of the Font Software may be bundled,
redistributed and/or sold with any software, provided that each copy
contains the above copyright notice and this license. These can be
included either as stand-alone text files, human-readable headers or
in the appropriate machine-readable metadata fields within text or
binary files as long as those fields can be easily viewed by the user.

3) No Modified Version of the Font Software may use the Reserved Font
Name(s) unless explicit written permission is granted by the corresponding
Copyright Holder. This restriction only applies to the primary font name as
presented to the users.

4) The name(s) of the Copyright Holder(s) or the Author(s) of the Font
Software shall not be used to promote, endorse or advertise any
Modified Version, except to acknowledge the contribution(s) of the
Copyright Holder(s) and the Author(s) or with their explicit written
permission.

5) The Font Software, modified or unmodified, in part or in whole,
must be distributed entirely under this license, and must not be
distributed under any other license. The requirement for fonts to
remain under this license does not apply to any document created
using the Font Software.

TERMINATION
This license becomes null and void if any of the above conditions are
not met.

DISCLAIMER
THE FONT SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO ANY WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT
OF COPYRIGHT, PATENT, TRADEMARK, OR OTHER RIGHT. IN NO EVENT SHALL THE
COPYRIGHT HOLDER BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
INCLUDING ANY GENERAL, SPECIAL, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL
DAMAGES, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF THE USE OR INABILITY TO USE THE FONT SOFTWARE OR FROM
OTHER DEALINGS IN THE FONT SOFTWARE.
```
