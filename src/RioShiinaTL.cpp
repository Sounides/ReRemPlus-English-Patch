#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <detours.h>

static constexpr UINT CP_SHIFTJIS = 932;

// Original Win32 function pointers captured before IAT hooking
static decltype(&GetACP) Real_GetACP = &GetACP;
static decltype(&GetOEMCP) Real_GetOEMCP = &GetOEMCP;
static decltype(&GetCPInfo) Real_GetCPInfo = &GetCPInfo;
static decltype(&MultiByteToWideChar) Real_MultiByteToWideChar = &MultiByteToWideChar;
static decltype(&WideCharToMultiByte) Real_WideCharToMultiByte = &WideCharToMultiByte;
static decltype(&CreateFontA) Real_CreateFontA = &CreateFontA;
static decltype(&EnumFontFamiliesExA) Real_EnumFontFamiliesExA = &EnumFontFamiliesExA;
static decltype(&GetGlyphOutlineA) Real_GetGlyphOutlineA = &GetGlyphOutlineA;
static decltype(&TextOutA) Real_TextOutA = &TextOutA;
static decltype(&GetTextExtentPoint32A) Real_GetTextExtentPoint32A = &GetTextExtentPoint32A;
static decltype(&RegisterClassA) Real_RegisterClassA = &RegisterClassA;
static decltype(&FindWindowA) Real_FindWindowA = &FindWindowA;
static decltype(&CreateWindowExA) Real_CreateWindowExA = &CreateWindowExA;
static decltype(&DefWindowProcA) Real_DefWindowProcA = &DefWindowProcA;
static decltype(&SetWindowTextA) Real_SetWindowTextA = &SetWindowTextA;
static decltype(&SetDlgItemTextA) Real_SetDlgItemTextA = &SetDlgItemTextA;
static decltype(&AppendMenuA) Real_AppendMenuA = &AppendMenuA;
static decltype(&MessageBoxA) Real_MessageBoxA = &MessageBoxA;
static decltype(&RegOpenKeyA) Real_RegOpenKeyA = &RegOpenKeyA;
static decltype(&RegOpenKeyExA) Real_RegOpenKeyExA = &RegOpenKeyExA;
static decltype(&RegCreateKeyExA) Real_RegCreateKeyExA = &RegCreateKeyExA;

// Shiina Rio v2.50 internal loader: LPVOID RioLoadFileEx(LPCSTR lpName, LPDWORD lpSize)
static LPVOID (*pfnRioLoadFileEx)(LPCSTR, LPDWORD) =
    reinterpret_cast<LPVOID (*)(LPCSTR, LPDWORD)>(0x00405940);

// Shiina Rio v2.50 sprite/text frame offset getter & setter
// Note: obj[1] is frame count (valid indices: 0 .. obj[1]-1).
// The original engine uses unsigned '>' (ja) instead of '>=' (jae), reading frame[0].width at obj[2 + obj[1]] as a pointer!
static void (__cdecl *pfnGetFrameOffset_411F80)(DWORD*, DWORD, DWORD*, DWORD*) =
    reinterpret_cast<void (__cdecl *)(DWORD*, DWORD, DWORD*, DWORD*)>(0x00411F80);
static void (__cdecl *pfnSetFrameOffset_411FB0)(DWORD*, DWORD, DWORD, DWORD) =
    reinterpret_cast<void (__cdecl *)(DWORD*, DWORD, DWORD, DWORD)>(0x00411FB0);
static void (__cdecl *pfnFillFrame_4114B0)(DWORD*, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD) =
    reinterpret_cast<void (__cdecl *)(DWORD*, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD)>(0x004114B0);

static int g_guardLogCount = 0;

static void LogGuard(const char* fn, DWORD* obj, DWORD idx, DWORD* slot, DWORD x, DWORD y)
{
    if (g_guardLogCount >= 20) return;
    ++g_guardLogCount;
    FILE* fp = nullptr;
    if (fopen_s(&fp, "tl_guard.log", "a") == 0 && fp) {
        fprintf(fp, "%s: obj=%p count=%u idx=%u slot=%p x=%u y=%u\n",
                fn, obj, obj ? obj[1] : 0u, idx, slot, x, y);
        fclose(fp);
    }
}

static bool IsReadablePtr(const void* p, size_t len)
{
    if (!p || reinterpret_cast<uintptr_t>(p) < 0x10000) return false;
    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery(p, &mbi, sizeof(mbi)) == 0) return false;
    if (mbi.State != MEM_COMMIT) return false;
    DWORD prot = mbi.Protect & 0xFF;
    if (prot == PAGE_NOACCESS || (mbi.Protect & PAGE_GUARD)) return false;
    uintptr_t end = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
    return reinterpret_cast<uintptr_t>(p) + len <= end;
}

static bool IsWritablePtr(const void* p, size_t len)
{
    if (!p || reinterpret_cast<uintptr_t>(p) < 0x10000) return false;
    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery(p, &mbi, sizeof(mbi)) == 0) return false;
    if (mbi.State != MEM_COMMIT) return false;
    DWORD prot = mbi.Protect & 0xFF;
    bool ok = (prot == PAGE_READWRITE || prot == PAGE_WRITECOPY ||
               prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY);
    if (!ok || (mbi.Protect & PAGE_GUARD)) return false;
    uintptr_t end = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
    return reinterpret_cast<uintptr_t>(p) + len <= end;
}

static void __cdecl Hook_GetFrameOffset_411F80(DWORD* obj, DWORD idx, DWORD* outX, DWORD* outY)
{
    if (!IsReadablePtr(obj, 8) || idx >= obj[1]) {
        LogGuard("GetFrameOffset", obj, idx, nullptr, 0, 0);
        if (outX) *outX = 0;
        if (outY) *outY = 0;
        return;
    }
    DWORD* slot = reinterpret_cast<DWORD*>(obj[2 + idx]);
    if (!IsReadablePtr(slot, 16)) {
        LogGuard("GetFrameOffset_badslot", obj, idx, slot, 0, 0);
        if (outX) *outX = 0;
        if (outY) *outY = 0;
        return;
    }
    if (outX) *outX = slot[2];
    if (outY) *outY = slot[3];
}

static void __cdecl Hook_SetFrameOffset_411FB0(DWORD* obj, DWORD idx, DWORD x, DWORD y)
{
    if (!IsReadablePtr(obj, 8) || idx >= obj[1]) {
        LogGuard("SetFrameOffset", obj, idx, nullptr, x, y);
        return;
    }
    DWORD* slot = reinterpret_cast<DWORD*>(obj[2 + idx]);
    if (!IsWritablePtr(slot, 16)) {
        LogGuard("SetFrameOffset_badslot", obj, idx, slot, x, y);
        return;
    }
    slot[2] = x;
    slot[3] = y;
}

static void __cdecl Hook_FillFrame_4114B0(
    DWORD* obj, DWORD idx, DWORD a3, DWORD a4, DWORD a5, DWORD a6, DWORD a7)
{
    if (!IsReadablePtr(obj, 8) || idx >= obj[1]) {
        LogGuard("FillFrame_4114B0", obj, idx, nullptr, a3, a4);
        return;
    }
    DWORD* slot = reinterpret_cast<DWORD*>(obj[2 + idx]);
    if (!IsReadablePtr(slot, 0x18)) {
        LogGuard("FillFrame_4114B0_badslot", obj, idx, slot, a3, a4);
        return;
    }
    pfnFillFrame_4114B0(obj, idx, a3, a4, a5, a6, a7);
}

static void PatchByteIfExpected(uintptr_t addr, BYTE expected, BYTE replacement)
{
    auto* p = reinterpret_cast<BYTE*>(addr);
    if (*p != expected) return;
    DWORD oldProt = 0;
    if (VirtualProtect(p, 1, PAGE_EXECUTE_READWRITE, &oldProt)) {
        *p = replacement;
        VirtualProtect(p, 1, oldProt, &oldProt);
        FlushInstructionCache(GetCurrentProcess(), p, 1);
    }
}

static std::wstring SjisToWide(LPCSTR src, int len = -1)
{
    if (!src) return std::wstring();
    if (len == 0) return std::wstring();
    int wlen = Real_MultiByteToWideChar(CP_SHIFTJIS, 0, src, len, nullptr, 0);
    if (wlen <= 0) return std::wstring();
    std::wstring out(static_cast<size_t>(wlen), L'\0');
    Real_MultiByteToWideChar(CP_SHIFTJIS, 0, src, len, &out[0], wlen);
    if (len == -1 && !out.empty() && out.back() == L'\0') {
        out.pop_back();
    }
    return out;
}

static void WideToSjisBuf(LPCWSTR src, char* dst, size_t dstCap)
{
    if (!dst || dstCap == 0) return;
    dst[0] = '\0';
    if (!src) return;
    int n = Real_WideCharToMultiByte(CP_SHIFTJIS, 0, src, -1, dst, static_cast<int>(dstCap), nullptr, nullptr);
    if (n <= 0) {
        dst[0] = '\0';
    } else {
        dst[dstCap - 1] = '\0';
    }
}

//=============================================================================
// Shiina Rio File Loader Hook (loose files override .WAR archives)
//=============================================================================

static bool g_checkedExtractFlag = false;

static void RunOneTimeAssetDump()
{
    static const char* kScripts[] = {
        "p\\rem00_00.txt", "p\\rem01_00.txt", "p\\rem01_01.txt", "p\\rem01_02.txt", "p\\rem01_03.txt",
        "p\\rem02_00.txt", "p\\rem03_00.txt", "p\\rem04_00.txt", "p\\rem04_01.txt", "p\\rem04_02.txt",
        "p\\rem04_03.txt", "p\\rem05_00.txt", "p\\rem05_01.txt", "p\\rem05_02.txt", "p\\rem05_03.txt",
        "p\\rem06_00.txt", "p\\rem06_01.txt", "p\\rem06_02.txt", "p\\rem06_03.txt", "p\\rem07_00.txt",
        "p\\rem07_01.txt", "p\\rem07_02.txt", "p\\rem07_03.txt", "p\\rem08_00.txt", "p\\rem09_00.txt",
    };
    static const char* kDataFiles[] = {
        "d\\sys.s25", "d\\caution.s25", "d\\b_logo.s25",
    };

    CreateDirectoryW(L"_patch_tmp", nullptr);
    CreateDirectoryW(L"_patch_tmp\\p", nullptr);
    CreateDirectoryW(L"_patch_tmp\\d", nullptr);

    auto dumpOne = [](const char* relPath) {
        DWORD sz = 0;
        LPVOID ptr = pfnRioLoadFileEx(relPath, &sz);
        if (ptr && sz > 0) {
            std::wstring outPath = L"_patch_tmp\\" + SjisToWide(relPath);
            FILE* fp = nullptr;
            if (_wfopen_s(&fp, outPath.c_str(), L"wb") == 0 && fp) {
                fwrite(ptr, 1, sz, fp);
                fclose(fp);
            }
            GlobalFree(ptr);
        }
    };

    for (const char* s : kScripts) dumpOne(s);
    for (const char* d : kDataFiles) dumpOne(d);

    DeleteFileW(L"_patch_extract.flag");
    ExitProcess(0);
}

static LPVOID RioLoadFileEx_Hook(LPCSTR lpName, LPDWORD lpSize)
{
    if (lpName && lpSize) {
        if (!g_checkedExtractFlag && _stricmp(lpName, "d\\sys.s25") == 0) {
            g_checkedExtractFlag = true;
            if (GetFileAttributesW(L"_patch_extract.flag") != INVALID_FILE_ATTRIBUTES) {
                RunOneTimeAssetDump();
            }
        }
        std::wstring wpath = SjisToWide(lpName);
        FILE* fp = nullptr;
        if (!wpath.empty() && _wfopen_s(&fp, wpath.c_str(), L"rb") == 0 && fp) {
            fseek(fp, 0, SEEK_END);
            long size = ftell(fp);
            fseek(fp, 0, SEEK_SET);
            if (size > 0) {
                PVOID ptr = GlobalAlloc(GPTR, static_cast<SIZE_T>(size));
                if (ptr) {
                    if (fread(ptr, static_cast<size_t>(size), 1, fp) == 1) {
                        fclose(fp);
                        *lpSize = static_cast<DWORD>(size);
                        return ptr;
                    }
                    GlobalFree(ptr);
                }
            }
            fclose(fp);
        }
    }
    return pfnRioLoadFileEx(lpName, lpSize);
}

//=============================================================================
// KERNEL32 Locale / Code Page Hooks
//=============================================================================

static UINT WINAPI Hook_GetACP()
{
    return CP_SHIFTJIS;
}

static UINT WINAPI Hook_GetOEMCP()
{
    return CP_SHIFTJIS;
}

static BOOL WINAPI Hook_GetCPInfo(UINT CodePage, LPCPINFO lpCPInfo)
{
    if (CodePage == CP_ACP || CodePage == CP_OEMCP || CodePage == CP_THREAD_ACP) {
        CodePage = CP_SHIFTJIS;
    }
    return Real_GetCPInfo(CodePage, lpCPInfo);
}

static int WINAPI Hook_MultiByteToWideChar(
    UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte,
    LPWSTR lpWideCharStr, int cchWideChar)
{
    if (CodePage == CP_ACP || CodePage == CP_OEMCP || CodePage == CP_THREAD_ACP) {
        CodePage = CP_SHIFTJIS;
    }
    return Real_MultiByteToWideChar(CodePage, dwFlags, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar);
}

static int WINAPI Hook_WideCharToMultiByte(
    UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar,
    LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar)
{
    if (CodePage == CP_ACP || CodePage == CP_OEMCP || CodePage == CP_THREAD_ACP) {
        CodePage = CP_SHIFTJIS;
    }
    return Real_WideCharToMultiByte(
        CodePage, dwFlags, lpWideCharStr, cchWideChar,
        lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);
}

//=============================================================================
// GDI32 Font & Glyph Rendering Hooks (removes Locale Emulator requirement)
//=============================================================================

static HFONT WINAPI Hook_CreateFontA(
    int cHeight, int cWidth, int cEscapement, int cOrientation,
    int cWeight, DWORD bItalic, DWORD bUnderline, DWORD bStrikeOut,
    DWORD iCharSet, DWORD iOutPrecision, DWORD iClipPrecision,
    DWORD iQuality, DWORD iPitchAndFamily, LPCSTR pszFaceName)
{
    std::wstring wface = SjisToWide(pszFaceName);
    if (iCharSet == DEFAULT_CHARSET || iCharSet == ANSI_CHARSET) {
        iCharSet = SHIFTJIS_CHARSET;
    }
    return CreateFontW(
        cHeight, cWidth, cEscapement, cOrientation,
        cWeight, bItalic, bUnderline, bStrikeOut,
        iCharSet, iOutPrecision, iClipPrecision,
        iQuality, iPitchAndFamily,
        pszFaceName ? wface.c_str() : nullptr);
}

struct EnumFontCtx {
    FONTENUMPROCA origProc;
    LPARAM origParam;
};

static int CALLBACK EnumFontThunkW(
    const LOGFONTW* lpelfe, const TEXTMETRICW* lpntme, DWORD FontType, LPARAM lParam)
{
    auto* ctx = reinterpret_cast<EnumFontCtx*>(lParam);
    ENUMLOGFONTEXA lfA = {};
    auto* elfW = reinterpret_cast<const ENUMLOGFONTEXW*>(lpelfe);
    lfA.elfLogFont.lfHeight = elfW->elfLogFont.lfHeight;
    lfA.elfLogFont.lfWidth = elfW->elfLogFont.lfWidth;
    lfA.elfLogFont.lfEscapement = elfW->elfLogFont.lfEscapement;
    lfA.elfLogFont.lfOrientation = elfW->elfLogFont.lfOrientation;
    lfA.elfLogFont.lfWeight = elfW->elfLogFont.lfWeight;
    lfA.elfLogFont.lfItalic = elfW->elfLogFont.lfItalic;
    lfA.elfLogFont.lfUnderline = elfW->elfLogFont.lfUnderline;
    lfA.elfLogFont.lfStrikeOut = elfW->elfLogFont.lfStrikeOut;
    lfA.elfLogFont.lfCharSet = elfW->elfLogFont.lfCharSet;
    lfA.elfLogFont.lfOutPrecision = elfW->elfLogFont.lfOutPrecision;
    lfA.elfLogFont.lfClipPrecision = elfW->elfLogFont.lfClipPrecision;
    lfA.elfLogFont.lfQuality = elfW->elfLogFont.lfQuality;
    lfA.elfLogFont.lfPitchAndFamily = elfW->elfLogFont.lfPitchAndFamily;
    WideToSjisBuf(elfW->elfLogFont.lfFaceName, lfA.elfLogFont.lfFaceName, LF_FACESIZE);
    WideToSjisBuf(elfW->elfFullName, reinterpret_cast<char*>(lfA.elfFullName), LF_FULLFACESIZE);
    WideToSjisBuf(elfW->elfStyle, reinterpret_cast<char*>(lfA.elfStyle), LF_FACESIZE);
    WideToSjisBuf(elfW->elfScript, reinterpret_cast<char*>(lfA.elfScript), LF_FACESIZE);

    NEWTEXTMETRICEXA tmA = {};
    auto* ntmW = reinterpret_cast<const NEWTEXTMETRICEXW*>(lpntme);
    tmA.ntmTm.tmHeight = ntmW->ntmTm.tmHeight;
    tmA.ntmTm.tmAscent = ntmW->ntmTm.tmAscent;
    tmA.ntmTm.tmDescent = ntmW->ntmTm.tmDescent;
    tmA.ntmTm.tmInternalLeading = ntmW->ntmTm.tmInternalLeading;
    tmA.ntmTm.tmExternalLeading = ntmW->ntmTm.tmExternalLeading;
    tmA.ntmTm.tmAveCharWidth = ntmW->ntmTm.tmAveCharWidth;
    tmA.ntmTm.tmMaxCharWidth = ntmW->ntmTm.tmMaxCharWidth;
    tmA.ntmTm.tmWeight = ntmW->ntmTm.tmWeight;
    tmA.ntmTm.tmOverhang = ntmW->ntmTm.tmOverhang;
    tmA.ntmTm.tmDigitizedAspectX = ntmW->ntmTm.tmDigitizedAspectX;
    tmA.ntmTm.tmDigitizedAspectY = ntmW->ntmTm.tmDigitizedAspectY;
    tmA.ntmTm.tmFirstChar = static_cast<BYTE>(ntmW->ntmTm.tmFirstChar & 0xFF);
    tmA.ntmTm.tmLastChar = static_cast<BYTE>(ntmW->ntmTm.tmLastChar & 0xFF);
    tmA.ntmTm.tmDefaultChar = static_cast<BYTE>(ntmW->ntmTm.tmDefaultChar & 0xFF);
    tmA.ntmTm.tmBreakChar = static_cast<BYTE>(ntmW->ntmTm.tmBreakChar & 0xFF);
    tmA.ntmTm.tmItalic = ntmW->ntmTm.tmItalic;
    tmA.ntmTm.tmUnderlined = ntmW->ntmTm.tmUnderlined;
    tmA.ntmTm.tmStruckOut = ntmW->ntmTm.tmStruckOut;
    tmA.ntmTm.tmPitchAndFamily = ntmW->ntmTm.tmPitchAndFamily;
    tmA.ntmTm.tmCharSet = ntmW->ntmTm.tmCharSet;
    tmA.ntmTm.ntmFlags = ntmW->ntmTm.ntmFlags;
    tmA.ntmTm.ntmSizeEM = ntmW->ntmTm.ntmSizeEM;
    tmA.ntmTm.ntmCellHeight = ntmW->ntmTm.ntmCellHeight;
    tmA.ntmTm.ntmAvgWidth = ntmW->ntmTm.ntmAvgWidth;
    tmA.ntmFontSig = ntmW->ntmFontSig;

    return ctx->origProc(
        reinterpret_cast<const LOGFONTA*>(&lfA),
        reinterpret_cast<const TEXTMETRICA*>(&tmA),
        FontType,
        ctx->origParam);
}

static int WINAPI Hook_EnumFontFamiliesExA(
    HDC hdc, LPLOGFONTA lpLogfont, FONTENUMPROCA lpProc, LPARAM lParam, DWORD dwFlags)
{
    LOGFONTW lfW = {};
    if (lpLogfont) {
        lfW.lfCharSet = (lpLogfont->lfCharSet == DEFAULT_CHARSET || lpLogfont->lfCharSet == ANSI_CHARSET)
                            ? SHIFTJIS_CHARSET
                            : lpLogfont->lfCharSet;
        lfW.lfPitchAndFamily = lpLogfont->lfPitchAndFamily;
        std::wstring wface = SjisToWide(lpLogfont->lfFaceName);
        wcsncpy_s(lfW.lfFaceName, wface.c_str(), _TRUNCATE);
    } else {
        lfW.lfCharSet = SHIFTJIS_CHARSET;
    }
    EnumFontCtx ctx{lpProc, lParam};
    return EnumFontFamiliesExW(hdc, &lfW, EnumFontThunkW, reinterpret_cast<LPARAM>(&ctx), dwFlags);
}

static DWORD WINAPI Hook_GetGlyphOutlineA(
    HDC hdc, UINT uChar, UINT fuFormat, LPGLYPHMETRICS lpgm,
    DWORD cjBuffer, LPVOID pvBuffer, const MAT2* lpmat2)
{
    UINT wideChar = uChar;
    if ((fuFormat & GGO_GLYPH_INDEX) == 0) {
        char mb[2];
        int mbLen = 0;
        if (uChar > 0xFF) {
            mb[0] = static_cast<char>((uChar >> 8) & 0xFF);
            mb[1] = static_cast<char>(uChar & 0xFF);
            mbLen = 2;
        } else {
            mb[0] = static_cast<char>(uChar & 0xFF);
            mbLen = 1;
        }
        wchar_t wc = 0;
        if (Real_MultiByteToWideChar(CP_SHIFTJIS, 0, mb, mbLen, &wc, 1) == 1) {
            wideChar = static_cast<UINT>(wc);
        }
    }
    return GetGlyphOutlineW(hdc, wideChar, fuFormat, lpgm, cjBuffer, pvBuffer, lpmat2);
}

static BOOL WINAPI Hook_TextOutA(HDC hdc, int x, int y, LPCSTR lpString, int c)
{
    if (!lpString || c <= 0) {
        return TextOutW(hdc, x, y, L"", 0);
    }
    std::wstring ws = SjisToWide(lpString, c);
    return TextOutW(hdc, x, y, ws.c_str(), static_cast<int>(ws.size()));
}

static BOOL WINAPI Hook_GetTextExtentPoint32A(HDC hdc, LPCSTR lpString, int c, LPSIZE psizl)
{
    if (!lpString || c <= 0) {
        return GetTextExtentPoint32W(hdc, L"", 0, psizl);
    }
    std::wstring ws = SjisToWide(lpString, c);
    return GetTextExtentPoint32W(hdc, ws.c_str(), static_cast<int>(ws.size()), psizl);
}

//=============================================================================
// USER32 Window Class, Title & Dialog Hooks (Unicode window -> no CP1252 mojibake)
//=============================================================================

static ATOM WINAPI Hook_RegisterClassA(const WNDCLASSA* lpWndClass)
{
    if (!lpWndClass) return 0;
    WNDCLASSW wcW = {};
    wcW.style = lpWndClass->style;
    wcW.lpfnWndProc = lpWndClass->lpfnWndProc;
    wcW.cbClsExtra = lpWndClass->cbClsExtra;
    wcW.cbWndExtra = lpWndClass->cbWndExtra;
    wcW.hInstance = lpWndClass->hInstance;
    wcW.hIcon = lpWndClass->hIcon;
    wcW.hCursor = lpWndClass->hCursor;
    wcW.hbrBackground = lpWndClass->hbrBackground;

    std::wstring wmenu, wcls;
    if (lpWndClass->lpszMenuName) {
        if (IS_INTRESOURCE(lpWndClass->lpszMenuName)) {
            wcW.lpszMenuName = reinterpret_cast<LPCWSTR>(lpWndClass->lpszMenuName);
        } else {
            wmenu = SjisToWide(lpWndClass->lpszMenuName);
            wcW.lpszMenuName = wmenu.c_str();
        }
    }
    if (lpWndClass->lpszClassName) {
        if (IS_INTRESOURCE(lpWndClass->lpszClassName)) {
            wcW.lpszClassName = reinterpret_cast<LPCWSTR>(lpWndClass->lpszClassName);
        } else {
            wcls = SjisToWide(lpWndClass->lpszClassName);
            wcW.lpszClassName = wcls.c_str();
        }
    }
    return RegisterClassW(&wcW);
}

static HWND WINAPI Hook_FindWindowA(LPCSTR lpClassName, LPCSTR lpWindowName)
{
    std::wstring wcls = lpClassName ? SjisToWide(lpClassName) : std::wstring();
    std::wstring wwin = lpWindowName ? SjisToWide(lpWindowName) : std::wstring();
    return FindWindowW(
        lpClassName ? wcls.c_str() : nullptr,
        lpWindowName ? wwin.c_str() : nullptr);
}

static std::wstring TranslateUiTitleOrMenu(const std::wstring& ws)
{
    if (ws == L"\xFF32\xFF45\xFF1A\x30EC\x30E0\x30D7\x30E9\x30B9") return L"Re:Rem Plus";
    if (ws == L"\x7D42\x4E86") return L"Exit";
    if (ws == L"\x30A6\x30A3\x30F3\x30C9\x30A6\x30B5\x30A4\x30BA") return L"Window Size";
    // Replace "(標準)" -> "(Default)" in window size submenu items
    std::wstring out = ws;
    size_t pos = out.find(L"\x6A19\x6E96");
    if (pos != std::wstring::npos) {
        out.replace(pos, 2, L"Default");
    }
    return out;
}

static HWND WINAPI Hook_CreateWindowExA(
    DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName, DWORD dwStyle,
    int X, int Y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu,
    HINSTANCE hInstance, LPVOID lpParam)
{
    std::wstring wcls;
    LPCWSTR pCls = nullptr;
    if (lpClassName) {
        if (IS_INTRESOURCE(lpClassName)) {
            pCls = reinterpret_cast<LPCWSTR>(lpClassName);
        } else {
            wcls = SjisToWide(lpClassName);
            pCls = wcls.c_str();
        }
    }
    std::wstring wtitle = lpWindowName ? TranslateUiTitleOrMenu(SjisToWide(lpWindowName)) : std::wstring();
    return CreateWindowExW(
        dwExStyle, pCls, lpWindowName ? wtitle.c_str() : nullptr, dwStyle,
        X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
}

static LRESULT WINAPI Hook_DefWindowProcA(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
    return DefWindowProcW(hWnd, Msg, wParam, lParam);
}

static BOOL WINAPI Hook_SetWindowTextA(HWND hWnd, LPCSTR lpString)
{
    if (!lpString) {
        return SetWindowTextW(hWnd, nullptr);
    }
    std::wstring ws = TranslateUiTitleOrMenu(SjisToWide(lpString));
    return SetWindowTextW(hWnd, ws.c_str());
}

static BOOL WINAPI Hook_SetDlgItemTextA(HWND hDlg, int nIDDlgItem, LPCSTR lpString)
{
    if (!lpString) {
        return SetDlgItemTextW(hDlg, nIDDlgItem, nullptr);
    }
    std::wstring ws = TranslateUiTitleOrMenu(SjisToWide(lpString));
    return SetDlgItemTextW(hDlg, nIDDlgItem, ws.c_str());
}

static BOOL WINAPI Hook_AppendMenuA(HMENU hMenu, UINT uFlags, UINT_PTR uIDNewItem, LPCSTR lpNewItem)
{
    if ((uFlags & (MF_BITMAP | MF_OWNERDRAW | MF_SEPARATOR)) != 0 || !lpNewItem) {
        return AppendMenuW(hMenu, uFlags, uIDNewItem, reinterpret_cast<LPCWSTR>(lpNewItem));
    }
    std::wstring ws = TranslateUiTitleOrMenu(SjisToWide(lpNewItem));
    return AppendMenuW(hMenu, uFlags, uIDNewItem, ws.c_str());
}

static int WINAPI Hook_MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    std::wstring wtext = SjisToWide(lpText);
    std::wstring wcap = SjisToWide(lpCaption);
    return MessageBoxW(
        hWnd,
        lpText ? wtext.c_str() : nullptr,
        lpCaption ? wcap.c_str() : nullptr,
        uType);
}

//=============================================================================
// ADVAPI32 Registry Key Hooks (clean Unicode Shift-JIS registry paths)
//=============================================================================

static LSTATUS WINAPI Hook_RegOpenKeyA(HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult)
{
    if (!lpSubKey) return RegOpenKeyW(hKey, nullptr, phkResult);
    std::wstring wsub = SjisToWide(lpSubKey);
    return RegOpenKeyW(hKey, wsub.c_str(), phkResult);
}

static LSTATUS WINAPI Hook_RegOpenKeyExA(
    HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
{
    if (!lpSubKey) return RegOpenKeyExW(hKey, nullptr, ulOptions, samDesired, phkResult);
    std::wstring wsub = SjisToWide(lpSubKey);
    return RegOpenKeyExW(hKey, wsub.c_str(), ulOptions, samDesired, phkResult);
}

static LSTATUS WINAPI Hook_RegCreateKeyExA(
    HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions,
    REGSAM samDesired, const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    PHKEY phkResult, LPDWORD lpdwDisposition)
{
    std::wstring wsub = SjisToWide(lpSubKey);
    std::wstring wcls = SjisToWide(lpClass);
    return RegCreateKeyExW(
        hKey,
        lpSubKey ? wsub.c_str() : nullptr,
        Reserved,
        lpClass ? &wcls[0] : nullptr,
        dwOptions,
        samDesired,
        lpSecurityAttributes,
        phkResult,
        lpdwDisposition);
}

//=============================================================================
// IAT Hook Helper (patches main executable imports only, keeping system DLLs untouched)
//=============================================================================

static bool PatchIAT(HMODULE hModule, LPCSTR dllName, LPCSTR procName, PVOID newProc, PVOID* origProcOut)
{
    if (!hModule) hModule = GetModuleHandleW(nullptr);
    auto* base = reinterpret_cast<BYTE*>(hModule);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    DWORD impRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!impRva) return false;

    auto* imp = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + impRva);
    for (; imp->Name != 0; ++imp) {
        auto* modName = reinterpret_cast<LPCSTR>(base + imp->Name);
        if (_stricmp(modName, dllName) != 0) continue;

        auto* origThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(
            base + (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
        auto* firstThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + imp->FirstThunk);

        for (; origThunk->u1.AddressOfData != 0; ++origThunk, ++firstThunk) {
            if (IMAGE_SNAP_BY_ORDINAL(origThunk->u1.Ordinal)) continue;
            auto* ibn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + origThunk->u1.AddressOfData);
            if (strcmp(reinterpret_cast<LPCSTR>(ibn->Name), procName) != 0) continue;

            DWORD oldProtect = 0;
            PVOID* slot = reinterpret_cast<PVOID*>(&firstThunk->u1.Function);
            if (VirtualProtect(slot, sizeof(PVOID), PAGE_READWRITE, &oldProtect)) {
                if (origProcOut) *origProcOut = *slot;
                *slot = newProc;
                VirtualProtect(slot, sizeof(PVOID), oldProtect, &oldProtect);
                return true;
            }
            return false;
        }
    }
    return false;
}

template <typename Fn>
static void HookImport(LPCSTR dll, LPCSTR name, Fn hookFn, Fn& realFn)
{
    PVOID orig = nullptr;
    if (PatchIAT(nullptr, dll, name, reinterpret_cast<PVOID>(hookFn), &orig) && orig) {
        realFn = reinterpret_cast<Fn>(orig);
    }
}

static void InstallHooks()
{
    // 1. Inline-hook Shiina Rio v2.50 file loader (0x00405940) and S25 off-by-one/bad-slot guards
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(reinterpret_cast<PVOID*>(&pfnRioLoadFileEx), reinterpret_cast<PVOID>(RioLoadFileEx_Hook));
    DetourAttach(reinterpret_cast<PVOID*>(&pfnGetFrameOffset_411F80), reinterpret_cast<PVOID>(Hook_GetFrameOffset_411F80));
    DetourAttach(reinterpret_cast<PVOID*>(&pfnSetFrameOffset_411FB0), reinterpret_cast<PVOID>(Hook_SetFrameOffset_411FB0));
    DetourAttach(reinterpret_cast<PVOID*>(&pfnFillFrame_4114B0), reinterpret_cast<PVOID>(Hook_FillFrame_4114B0));
    DetourTransactionCommit();

    // Fix off-by-one S25 frame bounds checks (ja->jae / jbe->jb) in 0x00411C60 and 0x00411FD0
    PatchByteIfExpected(0x00411C98, 0x77, 0x73);
    PatchByteIfExpected(0x00411CB4, 0x77, 0x73);
    PatchByteIfExpected(0x00411D24, 0x76, 0x72);
    PatchByteIfExpected(0x00411D3B, 0x76, 0x72);
    PatchByteIfExpected(0x00411FDE, 0x76, 0x72);
    PatchByteIfExpected(0x00411FF1, 0x77, 0x73);
    PatchByteIfExpected(0x00412004, 0x77, 0x73);

    // 2. IAT-hook Win32 ANSI APIs in REMPLUS_tl.exe for native Shift-JIS / CP932 support
    HookImport("KERNEL32.dll", "GetACP", Hook_GetACP, Real_GetACP);
    HookImport("KERNEL32.dll", "GetOEMCP", Hook_GetOEMCP, Real_GetOEMCP);
    HookImport("KERNEL32.dll", "GetCPInfo", Hook_GetCPInfo, Real_GetCPInfo);
    HookImport("KERNEL32.dll", "MultiByteToWideChar", Hook_MultiByteToWideChar, Real_MultiByteToWideChar);
    HookImport("KERNEL32.dll", "WideCharToMultiByte", Hook_WideCharToMultiByte, Real_WideCharToMultiByte);

    HookImport("GDI32.dll", "CreateFontA", Hook_CreateFontA, Real_CreateFontA);
    HookImport("GDI32.dll", "EnumFontFamiliesExA", Hook_EnumFontFamiliesExA, Real_EnumFontFamiliesExA);
    HookImport("GDI32.dll", "GetGlyphOutlineA", Hook_GetGlyphOutlineA, Real_GetGlyphOutlineA);
    HookImport("GDI32.dll", "TextOutA", Hook_TextOutA, Real_TextOutA);
    HookImport("GDI32.dll", "GetTextExtentPoint32A", Hook_GetTextExtentPoint32A, Real_GetTextExtentPoint32A);

    HookImport("USER32.dll", "RegisterClassA", Hook_RegisterClassA, Real_RegisterClassA);
    HookImport("USER32.dll", "FindWindowA", Hook_FindWindowA, Real_FindWindowA);
    HookImport("USER32.dll", "CreateWindowExA", Hook_CreateWindowExA, Real_CreateWindowExA);
    HookImport("USER32.dll", "DefWindowProcA", Hook_DefWindowProcA, Real_DefWindowProcA);
    HookImport("USER32.dll", "SetWindowTextA", Hook_SetWindowTextA, Real_SetWindowTextA);
    HookImport("USER32.dll", "SetDlgItemTextA", Hook_SetDlgItemTextA, Real_SetDlgItemTextA);
    HookImport("USER32.dll", "AppendMenuA", Hook_AppendMenuA, Real_AppendMenuA);
    HookImport("USER32.dll", "MessageBoxA", Hook_MessageBoxA, Real_MessageBoxA);

    HookImport("ADVAPI32.dll", "RegOpenKeyA", Hook_RegOpenKeyA, Real_RegOpenKeyA);
    HookImport("ADVAPI32.dll", "RegOpenKeyExA", Hook_RegOpenKeyExA, Real_RegOpenKeyExA);
    HookImport("ADVAPI32.dll", "RegCreateKeyExA", Hook_RegCreateKeyExA, Real_RegCreateKeyExA);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        DetourRestoreAfterWith();
        InstallHooks();
    }
    return TRUE;
}

extern "C" BOOL APIENTRY RioShiinaTL()
{
    return TRUE;
}
