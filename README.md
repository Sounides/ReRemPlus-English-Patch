# Re:Rem Plus — English Translation Patch

An unofficial **AI Generated** English translation patch for the Japanese visual novel **Re:Rem Plus** (*Re:レムプラス*, Grand Cross, Shiina Rio v2.50 engine).

> **Legal / Copyright Notice:** This repository contains **no copyrighted game files** — no game executables, `.WAR` archives, audio, video, original Japanese scripts, engine bytecode, or original artwork/textures. It contains only our original English translation strings, an open-source DLL hook, and a PowerShell installer that patches **your own legally obtained copy** of the game locally.

## Features
* **Full English Script Translation:** All 25 scenario scripts (`Opening`, all 8 event chapters + branches, and `Ending`) with *Re:Zero*-accurate terminology (`Metia`, `Return by Death`, `Forbidden Library`, `Hour of the Wind`, `Beako`, `Roswaal`, etc.).
* **Clean English Word-Wrapping & Engine Stability Fixes:** Automatically wraps all dialogue/narration on word boundaries (`≤ 56` columns, `≤ 3` rows, `≤ 124` characters per box) and fixes Shiina Rio v2.50's off-by-one S25 frame bounds bug that otherwise causes crashes on longer English text.
* **Translated UI Textures:** Programmatically translates all Japanese UI textures directly from your own game files — including all 10 choice buttons (all 4 hover/selected/cleared states), Option menu, confirmation dialogs, navigation buttons, Quick-Save notification, and startup disclaimer.
* **No Locale Emulator Required:** `RioShiinaTL.dll` includes built-in Shift-JIS (`CP932`) GDI font/glyph, window, menu, dialog, and registry hooks so the game runs directly on English Windows with zero mojibake.
* **Non-Destructive:** Leaves your original `REMPLUS.exe` and `.WAR` archives completely untouched.

---

## Installation (Windows 10 / 11)

No Python, no Visual Studio, and no Locale Emulator required!

1. Make sure you have your own extracted or installed copy of **Re:Rem Plus** (the folder containing `REMPLUS.exe`, `REMPLUS_D.WAR`, `REMPLUS_T.WAR`, etc.).
2. Download this repository (click **Code → Download ZIP** on GitHub and extract it).
3. Copy **`install.bat`**, **`uninstall.bat`**, and the **`patch\`** folder directly into your `REMPLUS` game folder (right next to `REMPLUS.exe`).
4. Double-click **`install.bat`** and wait ~5–10 seconds for it to finish.
   * The installer creates `REMPLUS_tl.exe`, installs `RioShiinaTL.dll`, sets up `savedata\` and the game's registry keys, extracts your own original scripts/UI textures locally, applies the English text and UI textures into `p\` and `d\`, and cleans up temporary files automatically.
5. Double-click **`REMPLUS_tl.exe`** to play *Re:Rem Plus* in English!

### Alternative: Running from Outside the Game Folder (or Offline with GARbro)
You can also invoke `patch\install.ps1` directly from PowerShell:
```powershell
powershell -ExecutionPolicy Bypass -File .\patch\install.ps1 -GameDir "C:\Path\To\REMPLUS"
```
If your system cannot briefly launch `REMPLUS_tl.exe` during asset extraction (e.g., headless / Wine / virtual display without Direct3D), you can extract using [GARbro](https://github.com/morkt/GARbro/releases) (MIT License) instead:
```powershell
powershell -ExecutionPolicy Bypass -File .\patch\install.ps1 -GameDir "C:\Path\To\REMPLUS" -GarbroDir "C:\Path\To\GARbro"
```

### Uninstalling
Double-click **`uninstall.bat`** inside your game folder. It removes `REMPLUS_tl.exe`, `RioShiinaTL.dll`, `p\`, and `d\` while keeping your original `REMPLUS.exe`, `.WAR` files, and `savedata\` intact.

---

## Repository Contents
* `install.bat` / `uninstall.bat` — One-click Windows installer & uninstaller.
* `patch/install.ps1` — Pure PowerShell + inline C# PE patcher, S25 image codec, script word-wrapper, and UI texture translator.
* `patch/RioShiinaTL.dll` — Prebuilt 32-bit x86 Shiina Rio v2.50 hook DLL (static CRT `/MT`, zero external runtime dependencies).
* `patch/translations/rem*.json` — Line-indexed English translation strings only (zero original Japanese text or engine commands).
* `src/` — Full C++ source code (`RioShiinaTL.cpp`, `RioShiinaTL.def`, `build.bat`) to rebuild `RioShiinaTL.dll` from scratch with MSVC x86 + [Microsoft Detours](https://github.com/microsoft/Detours).

## Building `RioShiinaTL.dll` from Source
1. Install Visual Studio Build Tools with the **Desktop development with C++** (x86) workload.
2. Clone [Microsoft Detours](https://github.com/microsoft/Detours).
3. Run:
   ```bat
   cd src
   set DETOURS_DIR=C:\path\to\Detours\src
   build.bat
   ```

## License
MIT License — see [LICENSE](LICENSE) and [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
