# ps3pupextractor

A self-contained **PS3 firmware update (PUP) unpacker** for Windows, with a GUI.

It reproduces the full `pupexplode` pipeline from fail0verflow's *ps3tools* natively (no
external tools, no key files) — split the `SCEUF` container, verify HMACs, decrypt every
inner SCE package, split `CORE_OS_PACKAGE`, and decrypt every SELF/SPRX to ELF — all from a
single executable.

## Features

- **Full explode**: `PUP → sections → untar update_files.tar → unpkg each package →
  cosunpkg CORE_OS_PACKAGE → SELF/SPRX/ldr/lv0 → ELF`.
- **Self-contained**: SCE decryption (AES-128-CBC/CTR), zlib, tar and the firmware key
  database are all built in. No `~/.ps3` key files, no OpenSSL.
- **HMAC verification** of the PUP header and every section (embedded `pup-hmac` key).
- **Optional `dev_flash`** extraction (checkbox — it's large).
- **Batch mode**: point it at a folder and it processes every `*.pup` into its own output
  folder.
- Runs on the **.NET Framework 4.x** that ships with Windows — the `.exe` is tiny.

## Usage

Double-click `ps3pupextractor_gui.exe`:

1. Browse to (or drag-drop) a `PS3UPDAT.PUP`.
2. Pick an output folder (auto-filled as `<name>_extracted`).
3. Tick **Full explode** to decrypt everything to ELF (leave it off for a plain container
   split). **Include dev_flash** is optional.
4. **Extract**, or use **Batch…** to process a whole folder of PUPs.

A command-line container-splitter is also included as `ps3pupextractor.c` (build with any C
compiler, e.g. `x86_64-w64-mingw32-gcc -O2 -o ps3pupextractor.exe ps3pupextractor.c`).

## Build

No .NET SDK required — just the compiler that ships with Windows:

```
build.cmd
```

(which calls `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe`). GitHub Actions
builds a Windows release on every `v*` tag (see `.github/workflows/release.yml`).

## Credits & license

The PUP/SCE format logic and the firmware key database are ported from:

- **fail0verflow / Sven Peter — ps3tools** (`pupunpack.c`, `puppack.c`, `tools.c`,
  `unself.c`, `unpkg.c`, `cosunpkg.c`, `pupexplode`), GPL-2.0.
- Public PS3 key sets (`pup-hmac`, loader/`pkg` keys) from the *ps3keys* / *scetool* key
  collections.

Accordingly this project is licensed under the **GNU GPL v2** — see [LICENSE](LICENSE).
This is reverse-engineering / homebrew tooling for firmware you own; all keys used are
already public. No warranty.
