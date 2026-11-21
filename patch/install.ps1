<#
.SYNOPSIS
    One-click copyright-free English patch installer for Re:Rem Plus (Grand Cross / Shiina Rio v2.50).
.DESCRIPTION
    Patches your local copy of Re:Rem Plus in place (without modifying original REMPLUS.exe or .WAR archives):
      1. Creates REMPLUS_tl.exe (imports RioShiinaTL.dll) and installs RioShiinaTL.dll (with built-in Shift-JIS locale hooks).
      2. Sets up savedata\ and HKCU\Software\GrandCross\Ｒｅ：レムプラス registry keys if needed.
      3. Extracts your own original scripts & UI .S25 files (automatically via REMPLUS_tl.exe, or optionally via -GarbroDir / -ExtractedDir).
      4. Applies the English script translations with word-wrapping (<=56 cols, <=3 rows, <=124 chars/box) into p\rem*.txt.
      5. Translates and repacks your own CAUTION.S25 and SYS.S25 into d\caution.s25 and d\sys.s25.
#>
param(
    [string]$GameDir = "",
    [string]$GarbroDir = "",
    [string]$ExtractedDir = ""
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Drawing

try { [System.Text.Encoding]::RegisterProvider([System.Text.CodePagesEncodingProvider]::Instance) } catch {}
$cp932 = [System.Text.Encoding]::GetEncoding(932)

$patchDir = $PSScriptRoot
$repoRoot = Split-Path -Parent $patchDir

# Auto-detect GameDir: current directory, repo parent, or repo root
if (-not $GameDir) {
    foreach ($cand in @((Get-Location).Path, $repoRoot, (Split-Path -Parent $repoRoot))) {
        if (Test-Path (Join-Path $cand "REMPLUS.exe")) {
            $GameDir = (Resolve-Path $cand).Path
            break
        }
    }
}
if (-not $GameDir -or -not (Test-Path (Join-Path $GameDir "REMPLUS.exe"))) {
    Write-Host "ERROR: Could not find REMPLUS.exe!" -ForegroundColor Red
    Write-Host "Please copy this patch folder into your Re:Rem Plus game folder (next to REMPLUS.exe),"
    Write-Host "or run:  install.ps1 -GameDir `"C:\path\to\REMPLUS`""
    exit 1
}
$GameDir = (Resolve-Path $GameDir).Path
Write-Host "=== Re:Rem Plus English Patch Installer ===" -ForegroundColor Cyan
Write-Host "Game folder : $GameDir"

# =============================================================================
# Inline C# Helpers: PE Import Patcher + S25 Codec (zero external binaries!)
# =============================================================================
$csharpCode = @'
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

public static class RemPlusPatchHelpers
{
    private static uint AlignUp(uint val, uint align)
    {
        return ((val + align - 1) / align) * align;
    }

    public static byte[] AddImportDll(byte[] origExe, string dllName, string funcName)
    {
        var data = new List<byte>(origExe);
        int eLfanew = BitConverter.ToInt32(origExe, 0x3C);
        if (origExe[eLfanew] != 'P' || origExe[eLfanew + 1] != 'E' || origExe[eLfanew + 2] != 0 || origExe[eLfanew + 3] != 0)
            throw new InvalidOperationException("Not a valid PE file.");

        ushort numSec = BitConverter.ToUInt16(origExe, eLfanew + 6);
        ushort optSize = BitConverter.ToUInt16(origExe, eLfanew + 20);
        int optOff = eLfanew + 24;
        ushort magic = BitConverter.ToUInt16(origExe, optOff);
        if (magic != 0x10B)
            throw new InvalidOperationException("Expected 32-bit PE32 executable.");

        uint secAlign = BitConverter.ToUInt32(origExe, optOff + 32);
        uint fileAlign = BitConverter.ToUInt32(origExe, optOff + 36);
        uint sizeOfHeaders = BitConverter.ToUInt32(origExe, optOff + 60);

        int impDirOff = optOff + 96 + 8;
        uint origImpRva = BitConverter.ToUInt32(origExe, impDirOff);

        int secTableOff = optOff + optSize;
        int newSecHdrOff = secTableOff + numSec * 40;
        if (newSecHdrOff + 40 > sizeOfHeaders)
            throw new InvalidOperationException("Not enough space in PE header for .newimp section.");

        var secs = new List<uint[]>();
        for (int i = 0; i < numSec; i++)
        {
            int s = secTableOff + i * 40;
            uint vs = BitConverter.ToUInt32(origExe, s + 8);
            uint va = BitConverter.ToUInt32(origExe, s + 12);
            uint rs = BitConverter.ToUInt32(origExe, s + 16);
            uint ra = BitConverter.ToUInt32(origExe, s + 20);
            secs.Add(new[] { va, vs, ra, rs });
        }

        Func<uint, int> rvaToOff = rva => {
            foreach (var sec in secs)
            {
                uint span = Math.Max(sec[1], sec[3]);
                if (rva >= sec[0] && rva < sec[0] + span)
                    return (int)(sec[2] + (rva - sec[0]));
            }
            throw new InvalidOperationException("RVA not mapped: 0x" + rva.ToString("X"));
        };

        int impOff = rvaToOff(origImpRva);
        var origDescs = new List<byte>();
        for (int idx = 0; ; idx++)
        {
            int o = impOff + idx * 20;
            bool allZero = true;
            for (int k = 0; k < 20; k++) { if (origExe[o + k] != 0) { allZero = false; break; } }
            if (allZero) break;
            for (int k = 0; k < 20; k++) origDescs.Add(origExe[o + k]);
        }

        var last = secs[secs.Count - 1];
        uint newVa = AlignUp(last[0] + Math.Max(last[1], last[3]), secAlign);
        uint newRa = AlignUp((uint)Math.Max(data.Count, (int)(last[2] + last[3])), fileAlign);
        while (data.Count < newRa) data.Add(0);

        uint newImpSize = (uint)(origDescs.Count + 40);
        uint ftRel = AlignUp(newImpSize, 4);
        uint oftRel = ftRel + 8;
        uint dllRel = oftRel + 8;
        byte[] dllBytes = Encoding.ASCII.GetBytes(dllName + "\0");
        uint ibnRel = AlignUp(dllRel + (uint)dllBytes.Length, 2);
        byte[] funcBytes = Encoding.ASCII.GetBytes(funcName + "\0");

        uint ftRva = newVa + ftRel;
        uint oftRva = newVa + oftRel;
        uint dllRva = newVa + dllRel;
        uint ibnRva = newVa + ibnRel;

        var secPayload = new List<byte>();
        secPayload.AddRange(origDescs);
        secPayload.AddRange(BitConverter.GetBytes(oftRva));
        secPayload.AddRange(BitConverter.GetBytes(0u));
        secPayload.AddRange(BitConverter.GetBytes(0u));
        secPayload.AddRange(BitConverter.GetBytes(dllRva));
        secPayload.AddRange(BitConverter.GetBytes(ftRva));
        secPayload.AddRange(new byte[20]); // null terminator descriptor
        while (secPayload.Count < ftRel) secPayload.Add(0);
        secPayload.AddRange(BitConverter.GetBytes(ibnRva));
        secPayload.AddRange(BitConverter.GetBytes(0u));
        secPayload.AddRange(BitConverter.GetBytes(ibnRva));
        secPayload.AddRange(BitConverter.GetBytes(0u));
        secPayload.AddRange(dllBytes);
        while (secPayload.Count < ibnRel) secPayload.Add(0);
        secPayload.AddRange(BitConverter.GetBytes((ushort)0));
        secPayload.AddRange(funcBytes);

        uint newVSize = AlignUp((uint)secPayload.Count, secAlign);
        uint newRSize = AlignUp((uint)secPayload.Count, fileAlign);
        while (secPayload.Count < newRSize) secPayload.Add(0);
        data.AddRange(secPayload);

        byte[] res = data.ToArray();

        // Write .newimp section header
        byte[] hdr = new byte[40];
        Encoding.ASCII.GetBytes(".newimp").CopyTo(hdr, 0);
        BitConverter.GetBytes(newVSize).CopyTo(hdr, 8);
        BitConverter.GetBytes(newVa).CopyTo(hdr, 12);
        BitConverter.GetBytes(newRSize).CopyTo(hdr, 16);
        BitConverter.GetBytes(newRa).CopyTo(hdr, 20);
        BitConverter.GetBytes(0xC0000040u).CopyTo(hdr, 36);
        Array.Copy(hdr, 0, res, newSecHdrOff, 40);

        BitConverter.GetBytes((ushort)(numSec + 1)).CopyTo(res, eLfanew + 6);
        BitConverter.GetBytes(AlignUp(newVa + newVSize, secAlign)).CopyTo(res, optOff + 56);
        BitConverter.GetBytes(0u).CopyTo(res, optOff + 64);
        BitConverter.GetBytes(newVa).CopyTo(res, impDirOff);
        BitConverter.GetBytes(newImpSize).CopyTo(res, impDirOff + 4);
        BitConverter.GetBytes(0u).CopyTo(res, optOff + 96 + 11 * 8);
        BitConverter.GetBytes(0u).CopyTo(res, optOff + 96 + 11 * 8 + 4);

        return res;
    }

    public class S25Frame
    {
        public int Index;
        public int Width;
        public int Height;
        public int X;
        public int Y;
        public uint Unk;
        public Bitmap Image;
    }

    private static void DecompressLine(byte[] dst, int dstOffset, byte[] src, int srcOffset, int width)
    {
        int x = width;
        int op = dstOffset;
        int ip = srcOffset;
        while (x > 0)
        {
            if (((ip - srcOffset) & 1) != 0) ip++;
            int cmd = BitConverter.ToUInt16(src, ip);
            ip += 2;
            int flag = cmd >> 13;
            ip += (cmd & 0x1800) >> 11;
            int cnt = cmd & 0x7FF;
            if (x < cnt) { cnt = x; x = 0; } else { x -= cnt; }

            if (flag == 2)
            {
                for (int i = 0; i < cnt; i++)
                {
                    dst[op++] = src[ip++];
                    dst[op++] = src[ip++];
                    dst[op++] = src[ip++];
                    dst[op++] = 0xFF;
                }
            }
            else if (flag == 3)
            {
                byte b = src[ip++], g = src[ip++], r = src[ip++];
                for (int i = 0; i < cnt; i++)
                {
                    dst[op++] = b; dst[op++] = g; dst[op++] = r; dst[op++] = 0xFF;
                }
            }
            else if (flag == 4)
            {
                for (int i = 0; i < cnt; i++)
                {
                    byte a = src[ip++];
                    dst[op++] = src[ip++];
                    dst[op++] = src[ip++];
                    dst[op++] = src[ip++];
                    dst[op++] = a;
                }
            }
            else if (flag == 5)
            {
                byte a = src[ip++], b = src[ip++], g = src[ip++], r = src[ip++];
                for (int i = 0; i < cnt; i++)
                {
                    dst[op++] = b; dst[op++] = g; dst[op++] = r; dst[op++] = a;
                }
            }
            else
            {
                op += cnt * 4;
            }
        }
    }

    public static S25Frame DecodeS25Frame(byte[] s25, int frameIndex)
    {
        if (s25.Length < 8 || s25[0] != 'S' || s25[1] != '2' || s25[2] != '5' || s25[3] != 0)
            throw new InvalidOperationException("Not a valid S25 file.");
        int count = BitConverter.ToInt32(s25, 4);
        if (frameIndex < 0 || frameIndex >= count) return null;
        int off = BitConverter.ToInt32(s25, 8 + frameIndex * 4);
        if (off == 0) return null;

        int w = BitConverter.ToInt32(s25, off);
        int h = BitConverter.ToInt32(s25, off + 4);
        int fx = BitConverter.ToInt32(s25, off + 8);
        int fy = BitConverter.ToInt32(s25, off + 12);
        uint unk = BitConverter.ToUInt32(s25, off + 16);

        byte[] bgra = new byte[w * h * 4];
        for (int row = 0; row < h; row++)
        {
            int lineOff = BitConverter.ToInt32(s25, off + 20 + row * 4);
            int lineStart = lineOff + 2;
            if ((lineStart & 1) != 0) lineStart++;
            DecompressLine(bgra, row * w * 4, s25, lineStart, w);
        }

        var bmp = new Bitmap(w, h, PixelFormat.Format32bppArgb);
        var bd = bmp.LockBits(new Rectangle(0, 0, w, h), ImageLockMode.WriteOnly, PixelFormat.Format32bppArgb);
        for (int row = 0; row < h; row++)
        {
            Marshal.Copy(bgra, row * w * 4, IntPtr.Add(bd.Scan0, row * bd.Stride), w * 4);
        }
        bmp.UnlockBits(bd);

        return new S25Frame { Index = frameIndex, Width = w, Height = h, X = fx, Y = fy, Unk = unk, Image = bmp };
    }

    private static byte[] EncodeScanline(byte[] bgra, int rowOffset, int width)
    {
        var ms = new MemoryStream(width * 4);
        int x = 0;
        while (x < width)
        {
            int p = rowOffset + x * 4;
            byte b = bgra[p], g = bgra[p + 1], r = bgra[p + 2], a = bgra[p + 3];

            // Transparent black run (flag 0)
            if (a == 0 && r == 0 && g == 0 && b == 0)
            {
                int run = 1;
                while (x + run < width && run < 2047)
                {
                    int q = rowOffset + (x + run) * 4;
                    if (bgra[q] == 0 && bgra[q + 1] == 0 && bgra[q + 2] == 0 && bgra[q + 3] == 0) run++;
                    else break;
                }
                ushort cmd = (ushort)run;
                ms.WriteByte((byte)(cmd & 0xFF));
                ms.WriteByte((byte)(cmd >> 8));
                x += run;
                continue;
            }

            // Solid identical pixel run >= 3 (flag 5)
            int srun = 1;
            while (x + srun < width && srun < 2047)
            {
                int q = rowOffset + (x + srun) * 4;
                if (bgra[q] == b && bgra[q + 1] == g && bgra[q + 2] == r && bgra[q + 3] == a) srun++;
                else break;
            }
            if (srun >= 3)
            {
                ushort cmd = (ushort)(0xA000 | srun);
                ms.WriteByte((byte)(cmd & 0xFF));
                ms.WriteByte((byte)(cmd >> 8));
                ms.WriteByte(a); ms.WriteByte(b); ms.WriteByte(g); ms.WriteByte(r);
                x += srun;
                continue;
            }

            // Literal run (flag 4) until next >=3 identical run or transparent run
            int lstart = x;
            int lrun = 0;
            while (x + lrun < width && lrun < 2047)
            {
                int q = rowOffset + (x + lrun) * 4;
                byte qb = bgra[q], qg = bgra[q + 1], qr = bgra[q + 2], qa = bgra[q + 3];
                if (lrun > 0 && qa == 0 && qr == 0 && qg == 0 && qb == 0) break;
                if (lrun > 0 && x + lrun + 2 < width)
                {
                    int q1 = q + 4, q2 = q + 8;
                    if (bgra[q1] == qb && bgra[q1 + 1] == qg && bgra[q1 + 2] == qr && bgra[q1 + 3] == qa &&
                        bgra[q2] == qb && bgra[q2 + 1] == qg && bgra[q2 + 2] == qr && bgra[q2 + 3] == qa)
                        break;
                }
                lrun++;
            }
            ushort lcmd = (ushort)(0x8000 | lrun);
            ms.WriteByte((byte)(lcmd & 0xFF));
            ms.WriteByte((byte)(lcmd >> 8));
            for (int k = 0; k < lrun; k++)
            {
                int q = rowOffset + (lstart + k) * 4;
                ms.WriteByte(bgra[q + 3]); // A
                ms.WriteByte(bgra[q]);     // B
                ms.WriteByte(bgra[q + 1]); // G
                ms.WriteByte(bgra[q + 2]); // R
            }
            x += lrun;
        }
        return ms.ToArray();
    }

    public static byte[] RepackS25(byte[] origS25, Dictionary<int, Bitmap> overrides)
    {
        int count = BitConverter.ToInt32(origS25, 4);
        int[] newOffsets = new int[count];

        using (var ms = new MemoryStream())
        using (var bw = new BinaryWriter(ms))
        {
            bw.Write(new byte[] { (byte)'S', (byte)'2', (byte)'5', 0 });
            bw.Write(count);
            bw.Write(new byte[count * 4]); // placeholder offset table

            for (int i = 0; i < count; i++)
            {
                int origOff = BitConverter.ToInt32(origS25, 8 + i * 4);
                if (origOff == 0) { newOffsets[i] = 0; continue; }

                int w = BitConverter.ToInt32(origS25, origOff);
                int h = BitConverter.ToInt32(origS25, origOff + 4);
                int fx = BitConverter.ToInt32(origS25, origOff + 8);
                int fy = BitConverter.ToInt32(origS25, origOff + 12);
                uint unk = BitConverter.ToUInt32(origS25, origOff + 16);

                Bitmap bmp;
                bool ownBmp = false;
                if (overrides.ContainsKey(i))
                {
                    bmp = overrides[i];
                }
                else
                {
                    var fr = DecodeS25Frame(origS25, i);
                    bmp = fr.Image;
                    ownBmp = true;
                }

                byte[] bgra = new byte[w * h * 4];
                var bd = bmp.LockBits(new Rectangle(0, 0, w, h), ImageLockMode.ReadOnly, PixelFormat.Format32bppArgb);
                for (int row = 0; row < h; row++)
                    Marshal.Copy(IntPtr.Add(bd.Scan0, row * bd.Stride), bgra, row * w * 4, w * 4);
                bmp.UnlockBits(bd);
                if (ownBmp) bmp.Dispose();

                if ((ms.Position & 1) != 0) bw.Write((byte)0);
                int frameOff = (int)ms.Position;
                newOffsets[i] = frameOff;

                bw.Write(w); bw.Write(h); bw.Write(fx); bw.Write(fy); bw.Write(unk);
                long lineTblPos = ms.Position;
                bw.Write(new byte[h * 4]);
                int[] lineOffsets = new int[h];

                for (int row = 0; row < h; row++)
                {
                    if ((ms.Position & 1) != 0) bw.Write((byte)0);
                    lineOffsets[row] = (int)ms.Position;
                    byte[] enc = EncodeScanline(bgra, row * w * 4, w);
                    bw.Write((ushort)enc.Length);
                    bw.Write(enc);
                }

                long endPos = ms.Position;
                ms.Position = lineTblPos;
                for (int row = 0; row < h; row++) bw.Write(lineOffsets[row]);
                ms.Position = endPos;
            }

            ms.Position = 8;
            for (int i = 0; i < count; i++) bw.Write(newOffsets[i]);
            return ms.ToArray();
        }
    }
}
'@

Add-Type -TypeDefinition $csharpCode -ReferencedAssemblies "System.Drawing"

# =============================================================================
# Step 1: Patch REMPLUS.exe -> REMPLUS_tl.exe & install RioShiinaTL.dll
# =============================================================================
Write-Host "[1/5] Patching REMPLUS.exe -> REMPLUS_tl.exe and installing RioShiinaTL.dll..." -ForegroundColor Green
$origExeBytes = [System.IO.File]::ReadAllBytes((Join-Path $GameDir "REMPLUS.exe"))
$patchedExeBytes = [RemPlusPatchHelpers]::AddImportDll($origExeBytes, "RioShiinaTL.dll", "RioShiinaTL")
[System.IO.File]::WriteAllBytes((Join-Path $GameDir "REMPLUS_tl.exe"), $patchedExeBytes)
Copy-Item (Join-Path $patchDir "RioShiinaTL.dll") (Join-Path $GameDir "RioShiinaTL.dll") -Force

# =============================================================================
# Step 2: Ensure savedata folder and HKCU registry keys exist
# =============================================================================
Write-Host "[2/5] Setting up savedata folder and registry entries..." -ForegroundColor Green
$saveDir = Join-Path $GameDir "savedata"
New-Item -ItemType Directory -Force -Path $saveDir | Out-Null
$regPath = "HKCU:\Software\GrandCross\Ｒｅ：レムプラス"
New-Item -Path $regPath -Force | Out-Null
New-ItemProperty -Path $regPath -Name "InstPath" -Value $GameDir -PropertyType String -Force | Out-Null
New-ItemProperty -Path $regPath -Name "DataPath" -Value $saveDir -PropertyType String -Force | Out-Null
New-ItemProperty -Path $regPath -Name "InstMode" -Value 0 -PropertyType DWord -Force | Out-Null

# =============================================================================
# Step 3: Extract user's own original scripts & UI S25 files to temporary folder
# =============================================================================
Write-Host "[3/5] Extracting original scripts and UI archives from your local game files..." -ForegroundColor Green
$tmpDir = Join-Path $GameDir "_patch_tmp"
if (Test-Path $tmpDir) { Remove-Item $tmpDir -Recurse -Force }
New-Item -ItemType Directory -Force -Path (Join-Path $tmpDir "p"), (Join-Path $tmpDir "d") | Out-Null

$extractedOk = $false

if ($ExtractedDir -and (Test-Path $ExtractedDir)) {
    foreach ($sub in @("REMPLUS_T", "p", "")) {
        $cand = if ($sub) { Join-Path $ExtractedDir $sub } else { $ExtractedDir }
        if (Test-Path (Join-Path $cand "REM00_00.TXT")) {
            Copy-Item (Join-Path $cand "REM*.TXT") (Join-Path $tmpDir "p") -Force
            break
        }
    }
    foreach ($sub in @("REMPLUS_D", "d", "")) {
        $cand = if ($sub) { Join-Path $ExtractedDir $sub } else { $ExtractedDir }
        if (Test-Path (Join-Path $cand "SYS.S25")) {
            foreach ($f in @("SYS.S25", "CAUTION.S25", "B_LOGO.S25")) {
                Copy-Item (Join-Path $cand $f) (Join-Path $tmpDir "d\$($f.ToLower())") -Force
            }
            break
        }
    }
    $extractedOk = (Test-Path (Join-Path $tmpDir "p\REM00_00.TXT")) -and (Test-Path (Join-Path $tmpDir "d\sys.s25"))
}

if (-not $extractedOk -and $GarbroDir -and (Test-Path (Join-Path $GarbroDir "ArcFormats.dll"))) {
    Add-Type -Path (Join-Path $GarbroDir "GameRes.dll")
    Add-Type -Path (Join-Path $GarbroDir "ArcFormats.dll")
    $fs = [System.IO.File]::OpenRead((Join-Path $GarbroDir "GameData\Formats.dat"))
    try { [GameRes.FormatCatalog]::Instance.DeserializeScheme($fs) } finally { $fs.Close() }
    $warc = [GameRes.FormatCatalog]::Instance.ArcFormats | Where-Object { $_.Tag -eq "WAR" }
    $opts = $warc.GetDefaultOptions()
    $opts.Scheme = $warc.Scheme.KnownSchemes | Where-Object { $_.Name -eq "Re: Rem Plus" }
    $handler = [GameRes.ParametersRequestEventHandler]{ param($s, $e) $e.Options = $opts }
    [GameRes.FormatCatalog]::Instance.add_ParametersRequest($handler)

    foreach ($pair in @(
        @{ war = "REMPLUS_T.WAR"; out = (Join-Path $tmpDir "p"); filter = "^REM.*\.TXT$" },
        @{ war = "REMPLUS_D.WAR"; out = (Join-Path $tmpDir "d"); filter = "^(SYS|CAUTION|B_LOGO)\.S25$" }
    )) {
        $view = New-Object GameRes.ArcView((Join-Path $GameDir $pair.war))
        $arc = $warc.TryOpen($view)
        try {
            foreach ($entry in $arc.Dir) {
                if ($entry.Name -match $pair.filter) {
                    $inS = $warc.OpenEntry($arc, $entry)
                    $outS = [System.IO.File]::Create((Join-Path $pair.out $entry.Name.ToLower()))
                    try { $inS.CopyTo($outS) } finally { $outS.Close(); $inS.Close() }
                }
            }
        } finally { if ($arc) { $arc.Dispose() }; $view.Dispose() }
    }
    $extractedOk = (Test-Path (Join-Path $tmpDir "p\rem00_00.txt")) -and (Test-Path (Join-Path $tmpDir "d\sys.s25"))
}

if (-not $extractedOk) {
    # Primary zero-dependency path: ask REMPLUS_tl.exe + RioShiinaTL.dll to dump user's own .WAR assets cleanly
    $flagFile = Join-Path $GameDir "_patch_extract.flag"
    [System.IO.File]::WriteAllText($flagFile, "1")
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = Join-Path $GameDir "REMPLUS_tl.exe"
    $psi.WorkingDirectory = $GameDir
    $proc = [System.Diagnostics.Process]::Start($psi)
    if (-not $proc.WaitForExit(15000)) {
        try { $proc.Kill() } catch {}
    }
    if (Test-Path $flagFile) { Remove-Item $flagFile -Force }
    $extractedOk = (Test-Path (Join-Path $tmpDir "p\rem00_00.txt")) -and (Test-Path (Join-Path $tmpDir "d\sys.s25"))
}

if (-not $extractedOk) {
    Write-Host "ERROR: Automatic asset extraction did not complete." -ForegroundColor Red
    Write-Host "If your system cannot initialize Direct3D during extraction, you can run with GARbro:"
    Write-Host "  powershell -ExecutionPolicy Bypass -File patch\install.ps1 -GameDir `"$GameDir`" -GarbroDir `"C:\path\to\GARbro`""
    exit 1
}

# =============================================================================
# Step 4: Apply English JSON translations & word-wrap (<=56 cols, <=3 rows, <=124 chars/box)
# =============================================================================
Write-Host "[4/5] Applying English translations and word-wrapping all 25 scripts..." -ForegroundColor Green

$MAX_COLS = 56
$MAX_ROWS = 3
$MAX_BOX_CHARS = 124

function Get-ColWidth([string]$s) {
    return $cp932.GetByteCount($s)
}

function Wrap-Rows([string]$text) {
    $words = $text -split ' '
    $rows = New-Object System.Collections.Generic.List[string]
    $cur = ""

    foreach ($w in $words) {
        $queue = New-Object System.Collections.Generic.Queue[string]
        $queue.Enqueue($w)
        while ($queue.Count -gt 0) {
            $word = $queue.Dequeue()
            if (-not $cur) {
                if ((Get-ColWidth $word) -le $MAX_COLS) { $cur = $word; continue }
            } else {
                $cand = "$cur $word"
                if ((Get-ColWidth $cand) -le $MAX_COLS) { $cur = $cand; continue }
            }

            $dashIdx = $word.IndexOf([char]0x2015)
            if ($dashIdx -ge 0 -and $dashIdx -lt ($word.Length - 1)) {
                $first = $word.Substring(0, $dashIdx + 1)
                $rest = $word.Substring($dashIdx + 1)
                if ($cur -and ((Get-ColWidth "$cur $first") -le $MAX_COLS)) {
                    $rows.Add("$cur $first"); $cur = ""; $queue.Enqueue($rest); continue
                }
                if (-not $cur -and ((Get-ColWidth $first) -le $MAX_COLS)) {
                    $rows.Add($first); $queue.Enqueue($rest); continue
                }
            }

            if ($cur) { $rows.Add($cur); $cur = "" }
            if ((Get-ColWidth $word) -gt $MAX_COLS) {
                $chunk = ""
                foreach ($ch in $word.ToCharArray()) {
                    if ((Get-ColWidth ($chunk + $ch)) -gt $MAX_COLS) { $rows.Add($chunk); $chunk = "$ch" }
                    else { $chunk += $ch }
                }
                $cur = $chunk
            } else {
                $cur = $word
            }
        }
    }
    if ($cur) { $rows.Add($cur) }
    return ,$rows.ToArray()
}

function Test-BoxFits([string[]]$rows) {
    if ($rows.Length -gt $MAX_ROWS) { return $false }
    $total = 0
    foreach ($r in $rows) { $total += $r.Length }
    $total += [Math]::Max(0, $rows.Length - 1)
    return $total -le $MAX_BOX_CHARS
}

function Split-IntoBoxes([string]$text) {
    $rows = Wrap-Rows $text
    if (Test-BoxFits $rows) {
        $single = New-Object System.Collections.Generic.List[string[]]
        $single.Add($rows)
        return ,$single
    }

    $mid = [int]($text.Length / 2)
    $patterns = @('(?:[.!?]+["'']?)\s+', '[;:]\s+', [string][char]0x2015, ',\s+', '\s+')
    $bestIdx = -1

    foreach ($pat in $patterns) {
        $bestBoth = 2; $bestDist = 999999; $candIdx = -1
        foreach ($m in [regex]::Matches($text, $pat)) {
            $idx = $m.Index + $m.Length
            $left = $text.Substring(0, $idx).Trim()
            $right = $text.Substring($idx).Trim()
            if (-not $left -or -not $right) { continue }
            $lr = Wrap-Rows $left
            if (Test-BoxFits $lr) {
                $rr = Wrap-Rows $right
                $both = if (Test-BoxFits $rr) { 0 } else { 1 }
                $dist = [Math]::Abs($idx - $mid)
                if (($both -lt $bestBoth) -or ($both -eq $bestBoth -and $dist -lt $bestDist)) {
                    $bestBoth = $both; $bestDist = $dist; $candIdx = $idx
                }
            }
        }
        if ($candIdx -ge 0) { $bestIdx = $candIdx; break }
    }

    $res = New-Object System.Collections.Generic.List[string[]]
    if ($bestIdx -ge 0) {
        $left = $text.Substring(0, $bestIdx).Trim()
        $right = $text.Substring($bestIdx).Trim()
        $res.Add((Wrap-Rows $left))
        foreach ($b in (Split-IntoBoxes $right)) { $res.Add($b) }
        return ,$res
    }
    $left2 = $text.Substring(0, $mid).Trim()
    $right2 = $text.Substring($mid).Trim()
    foreach ($b in (Split-IntoBoxes $left2)) { $res.Add($b) }
    foreach ($b in (Split-IntoBoxes $right2)) { $res.Add($b) }
    return ,$res
}

$gamePDir = Join-Path $GameDir "p"
New-Item -ItemType Directory -Force -Path $gamePDir | Out-Null
$tlJsonDir = Join-Path $patchDir "translations"
$scriptCount = 0

foreach ($jsonFile in (Get-ChildItem $tlJsonDir -Filter "rem*.json" | Sort-Object Name)) {
    $stem = [System.IO.Path]::GetFileNameWithoutExtension($jsonFile.Name)
    $origTxtPath = Join-Path $tmpDir "p\$stem.txt"
    if (-not (Test-Path $origTxtPath)) { $origTxtPath = Join-Path $tmpDir "p\$($stem.ToUpper()).TXT" }
    if (-not (Test-Path $origTxtPath)) { throw "Missing extracted script: $stem.txt" }

    $origRaw = [System.IO.File]::ReadAllBytes($origTxtPath)
    $origLines = $cp932.GetString($origRaw) -split "\r?\n"
    if ($origLines.Length -gt 0 -and $origLines[$origLines.Length - 1] -eq "") {
        $origLines = $origLines[0..($origLines.Length - 2)]
    }

    $tlObj = Get-Content $jsonFile.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
    $tlMap = @{}
    foreach ($prop in $tlObj.PSObject.Properties) { $tlMap[$prop.Name] = [string]$prop.Value }

    $outLines = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $origLines.Length; $i++) {
        $lineNum = [string]($i + 1)
        $line = $origLines[$i]
        if (-not $tlMap.ContainsKey($lineNum)) {
            $outLines.Add($line)
            continue
        }
        $en = $tlMap[$lineNum].Replace([char]0x2014, [char]0x2015).Trim()
        if ($en.StartsWith([char]0x3010)) {
            $outLines.Add($en)
            continue
        }

        $speaker = $null
        if ($outLines.Count -gt 0 -and $outLines[$outLines.Count - 1].StartsWith([char]0x3010)) {
            $speaker = $outLines[$outLines.Count - 1]
        }

        $boxes = Split-IntoBoxes $en
        for ($b = 0; $b -lt $boxes.Count; $b++) {
            if ($b -gt 0) {
                $outLines.Add("")
                if ($speaker) { $outLines.Add($speaker) }
            }
            $outLines.Add(($boxes[$b] -join "_r"))
        }
    }

    $outText = ($outLines -join "`r`n") + "`r`n"
    [System.IO.File]::WriteAllBytes((Join-Path $gamePDir "$stem.txt"), $cp932.GetBytes($outText))
    $scriptCount++
}
Write-Host "    Installed $scriptCount translated scripts into p\"

# =============================================================================
# Step 5: Translate & repack UI textures (CAUTION.S25 and SYS.S25) into d\
# =============================================================================
Write-Host "[5/5] Translating UI textures (caution.s25 and sys.s25) into d\..." -ForegroundColor Green

function New-UiGraphics([System.Drawing.Bitmap]$bmp) {
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    return $g
}

function Draw-UiText(
    [System.Drawing.Graphics]$g, [string]$text, [string]$fontName, [float]$emSize,
    [System.Drawing.FontStyle]$style, [System.Drawing.RectangleF]$rect,
    [System.Drawing.Color]$fillColor, [System.Drawing.Color]$strokeColor, [float]$strokeWidth,
    [System.Drawing.StringAlignment]$hAlign = [System.Drawing.StringAlignment]::Center,
    [System.Drawing.StringAlignment]$vAlign = [System.Drawing.StringAlignment]::Center
) {
    $fam = New-Object System.Drawing.FontFamily($fontName)
    $sf = New-Object System.Drawing.StringFormat
    $sf.Alignment = $hAlign; $sf.LineAlignment = $vAlign
    $sf.FormatFlags = [System.Drawing.StringFormatFlags]::NoWrap

    $size = $emSize
    while ($size -gt 10) {
        $f = New-Object System.Drawing.Font($fam, $size, $style, [System.Drawing.GraphicsUnit]::Pixel)
        $sz = $g.MeasureString($text, $f, 2000, $sf)
        $f.Dispose()
        if ($sz.Width -le ($rect.Width - 4)) { break }
        $size -= 1.0
    }

    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $path.AddString($text, $fam, [int]$style, $size, $rect, $sf)
    if ($strokeWidth -gt 0) {
        $pen = New-Object System.Drawing.Pen($strokeColor, $strokeWidth)
        $pen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
        $g.DrawPath($pen, $path)
        $pen.Dispose()
    }
    $brush = New-Object System.Drawing.SolidBrush($fillColor)
    $g.FillPath($brush, $path)
    $brush.Dispose(); $path.Dispose(); $sf.Dispose(); $fam.Dispose()
}

function Wipe-ByColumn([System.Drawing.Bitmap]$bmp, [int]$sampleX, [int]$x1, [int]$x2, [int]$y1, [int]$y2) {
    for ($y = $y1; $y -le $y2; $y++) {
        $c = $bmp.GetPixel($sampleX, $y)
        for ($x = $x1; $x -le $x2; $x++) { $bmp.SetPixel($x, $y, $c) }
    }
}

$white = [System.Drawing.Color]::White
$gameDDir = Join-Path $GameDir "d"
New-Item -ItemType Directory -Force -Path $gameDDir | Out-Null

# --- CAUTION.S25 ---
$origCautionBytes = [System.IO.File]::ReadAllBytes((Join-Path $tmpDir "d\caution.s25"))
$origLogoBytes = [System.IO.File]::ReadAllBytes((Join-Path $tmpDir "d\b_logo.s25"))
$logoFr = [RemPlusPatchHelpers]::DecodeS25Frame($origLogoBytes, 0)
$cBmp = New-Object System.Drawing.Bitmap(1280, 720, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
$g = New-UiGraphics $cBmp
$g.Clear([System.Drawing.Color]::FromArgb(255, 178, 178, 178))
for ($y = 0; $y -lt $logoFr.Image.Height; $y++) {
    for ($x = 0; $x -lt $logoFr.Image.Width; $x++) {
        $p = $logoFr.Image.GetPixel($x, $y)
        $lum = ($p.R + $p.G + $p.B) / 3.0
        if ($lum -lt 245) {
            $t = (245.0 - $lum) / 245.0
            $cBmp.SetPixel($x, $y, [System.Drawing.Color]::FromArgb(
                255,
                [int](178 * (1 - $t * 0.85) + $p.R * ($t * 0.85)),
                [int](178 * (1 - $t * 0.85) + $p.G * ($t * 0.85)),
                [int](178 * (1 - $t * 0.85) + $p.B * ($t * 0.85))))
        }
    }
}
$logoFr.Image.Dispose()
$pink = [System.Drawing.Color]::FromArgb(255, 224, 15, 128)
foreach ($ln in @(
    @{ y = 145; text = "This game is for adults aged 18 and older only." },
    @{ y = 250; text = "This story is a work of fiction." },
    @{ y = 306; text = "All characters, organizations, places, and settings depicted" },
    @{ y = 362; text = "are entirely fictitious and bear no relation to reality." },
    @{ y = 468; text = "For sale and distribution in Japan only." },
    @{ y = 524; text = "Japan Sales Only" }
)) {
    Draw-UiText $g $ln.text "Segoe UI" 38 ([System.Drawing.FontStyle]::Bold) (New-Object System.Drawing.RectangleF(110, $ln.y, 1080, 52)) $pink $white 10 ([System.Drawing.StringAlignment]::Near)
}
$g.Dispose()
$cautionOverrides = New-Object 'System.Collections.Generic.Dictionary[int,System.Drawing.Bitmap]'
$cautionOverrides[0] = $cBmp
$newCaution = [RemPlusPatchHelpers]::RepackS25($origCautionBytes, $cautionOverrides)
[System.IO.File]::WriteAllBytes((Join-Path $gameDDir "caution.s25"), $newCaution)
$cBmp.Dispose()

# --- SYS.S25 ---
$origSysBytes = [System.IO.File]::ReadAllBytes((Join-Path $tmpDir "d\sys.s25"))
$sysOverrides = New-Object 'System.Collections.Generic.Dictionary[int,System.Drawing.Bitmap]'

# Yes / No
foreach ($pair in @(@{ ids = @(260,261,262); text = "YES" }, @{ ids = @(270,271,272); text = "NO" })) {
    $b0 = New-Object System.Drawing.Bitmap(107, 67, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = New-UiGraphics $b0; $g.Clear([System.Drawing.Color]::Transparent)
    Draw-UiText $g $pair.text "Segoe UI" 30 ([System.Drawing.FontStyle]::Bold) (New-Object System.Drawing.RectangleF(0,0,107,67)) ([System.Drawing.Color]::FromArgb(255,25,25,35)) ([System.Drawing.Color]::Transparent) 0
    $g.Dispose(); $sysOverrides[$pair.ids[0]] = $b0

    foreach ($id in @($pair.ids[1], $pair.ids[2])) {
        $b = ([RemPlusPatchHelpers]::DecodeS25Frame($origSysBytes, $id)).Image
        $g = New-UiGraphics $b
        $br = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255,64,75,219))
        $g.FillRectangle($br, 10, 8, 87, 51); $br.Dispose()
        Draw-UiText $g $pair.text "Segoe UI" 30 ([System.Drawing.FontStyle]::Bold) (New-Object System.Drawing.RectangleF(0,0,107,67)) $white ([System.Drawing.Color]::Transparent) 0
        $g.Dispose(); $sysOverrides[$id] = $b
    }
}

# Confirmation prompts
foreach ($kv in @{ 281="Exit the game?"; 282="Return to title screen?"; 283="Reset to default settings?"; 284="Overwrite this save data?"; 285="Load this save data?" }.GetEnumerator()) {
    $fr = [RemPlusPatchHelpers]::DecodeS25Frame($origSysBytes, $kv.Key)
    $w = $fr.Width; $h = $fr.Height; $fr.Image.Dispose()
    $b = New-Object System.Drawing.Bitmap($w, $h, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = New-UiGraphics $b; $g.Clear([System.Drawing.Color]::Transparent)
    Draw-UiText $g $kv.Value "Segoe UI" 22 ([System.Drawing.FontStyle]::Bold) (New-Object System.Drawing.RectangleF(0,0,$w,$h)) $white ([System.Drawing.Color]::FromArgb(200,15,30,60)) 3
    $g.Dispose(); $sysOverrides[$kv.Key] = $b
}

# 10 Choice buttons x 4 states (310..349)
foreach ($ch in @(
    @{ base = 310; text = "Let's Clean the Bath!" },
    @{ base = 314; text = "A Wake-Up Surprise!" },
    @{ base = 318; text = "Imagining a Future with Rem!" },
    @{ base = 322; text = "Trying to Act Like a Man..." },
    @{ base = 326; text = "Let's Tend the Garden!" },
    @{ base = 330; text = "The Big Metia Incident!" },
    @{ base = 334; text = "Rem's Secret!" },
    @{ base = 338; text = "Memories of Our First Time!" },
    @{ base = 342; text = "Finish Inside" },
    @{ base = 346; text = "Finish Outside" }
)) {
    for ($st = 0; $st -lt 4; $st++) {
        $id = $ch.base + $st
        $b = ([RemPlusPatchHelpers]::DecodeS25Frame($origSysBytes, $id)).Image
        Wipe-ByColumn $b 30 30 473 7 50
        $g = New-UiGraphics $b
        $txtCol = if ($st -eq 3) { [System.Drawing.Color]::FromArgb(200,130,175,200) } else { $white }
        $outCol = if ($st -eq 3) { [System.Drawing.Color]::FromArgb(180,10,35,55) } else { [System.Drawing.Color]::FromArgb(220,0,35,90) }
        Draw-UiText $g $ch.text "Segoe UI" 26 ([System.Drawing.FontStyle]::Bold) (New-Object System.Drawing.RectangleF(24,2,455,54)) $txtCol $outCol 4
        $g.Dispose(); $sysOverrides[$id] = $b
    }
}

# Nav buttons
foreach ($nb in @(
    @{ ids=@(920,921,922); text="Return to Game"; strokes=@([System.Drawing.Color]::FromArgb(255,155,45,35),[System.Drawing.Color]::FromArgb(255,175,115,20),[System.Drawing.Color]::FromArgb(255,175,115,20)) },
    @{ ids=@(1060,1061,1062); text="Return to Title"; strokes=@([System.Drawing.Color]::FromArgb(255,170,40,105),[System.Drawing.Color]::FromArgb(255,175,80,55),[System.Drawing.Color]::FromArgb(255,175,80,55)) },
    @{ ids=@(1070,1071,1072); text="Return to Game"; strokes=@([System.Drawing.Color]::FromArgb(255,155,45,35),[System.Drawing.Color]::FromArgb(255,175,115,20),[System.Drawing.Color]::FromArgb(255,175,115,20)) },
    @{ ids=@(1080,1081,1082); text="Exit Game"; strokes=@([System.Drawing.Color]::FromArgb(255,20,95,150),[System.Drawing.Color]::FromArgb(255,35,125,115),[System.Drawing.Color]::FromArgb(255,35,125,115)) },
    @{ ids=@(1090,1091,1092); text="Reset Defaults"; strokes=@([System.Drawing.Color]::FromArgb(255,20,120,75),[System.Drawing.Color]::FromArgb(255,105,130,30),[System.Drawing.Color]::FromArgb(255,105,130,30)) },
    @{ ids=@(3030,3031,3032); text="Return to Game"; strokes=@([System.Drawing.Color]::FromArgb(255,155,45,35),[System.Drawing.Color]::FromArgb(255,175,115,20),[System.Drawing.Color]::FromArgb(255,175,115,20)) }
)) {
    for ($s = 0; $s -lt 3; $s++) {
        $id = $nb.ids[$s]
        $b = ([RemPlusPatchHelpers]::DecodeS25Frame($origSysBytes, $id)).Image
        Wipe-ByColumn $b 22 22 243 6 44
        $g = New-UiGraphics $b
        Draw-UiText $g $nb.text "Segoe UI" 24 ([System.Drawing.FontStyle]::Bold) (New-Object System.Drawing.RectangleF(12,2,241,47)) $white $nb.strokes[$s] 5
        $g.Dispose(); $sysOverrides[$id] = $b
    }
}

# Option toggles (1300..1362)
$hotPink = [System.Drawing.Color]::FromArgb(255,232,24,130)
foreach ($tg in @(
    @{ base=1300; text="Read" }, @{ base=1310; text="All" }, @{ base=1320; text="Stop" },
    @{ base=1330; text="Keep" }, @{ base=1340; text="None" }, @{ base=1350; text="Shadow" }, @{ base=1360; text="Outline" }
)) {
    for ($st = 0; $st -lt 3; $st++) {
        $id = $tg.base + $st
        $fr = [RemPlusPatchHelpers]::DecodeS25Frame($origSysBytes, $id)
        $w = $fr.Width; $h = $fr.Height; $fr.Image.Dispose()
        $b = New-Object System.Drawing.Bitmap($w, $h, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
        $g = New-UiGraphics $b; $g.Clear([System.Drawing.Color]::Transparent)
        if ($st -eq 0) {
            Draw-UiText $g $tg.text "Segoe UI" 20 ([System.Drawing.FontStyle]::Bold) (New-Object System.Drawing.RectangleF(0,0,$w,$h)) $white ([System.Drawing.Color]::FromArgb(140,20,50,100)) 2
        } else {
            Draw-UiText $g $tg.text "Segoe UI" 20 ([System.Drawing.FontStyle]::Bold) (New-Object System.Drawing.RectangleF(0,0,$w,$h)) $white $hotPink 5
        }
        $g.Dispose(); $sysOverrides[$id] = $b
    }
}

# Quick Saved banner (4200)
$qsBmp = ([RemPlusPatchHelpers]::DecodeS25Frame($origSysBytes, 4200)).Image
$g = New-UiGraphics $qsBmp
$qsBrush = New-Object System.Drawing.SolidBrush($qsBmp.GetPixel(168, 12))
$g.FillRectangle($qsBrush, 11, 11, 314, 34); $qsBrush.Dispose()
Draw-UiText $g "Quick Saved" "Segoe UI" 25 ([System.Drawing.FontStyle]::Bold) (New-Object System.Drawing.RectangleF(12,10,313,36)) $white ([System.Drawing.Color]::FromArgb(210,10,55,130)) 4
$g.Dispose(); $sysOverrides[4200] = $qsBmp

# Option menu background (1000)
$optBmp = ([RemPlusPatchHelpers]::DecodeS25Frame($origSysBytes, 1000)).Image
$g = New-UiGraphics $optBmp
$navyOutline = [System.Drawing.Color]::FromArgb(255,22,62,130)
foreach ($row in @(
    @{ y1=93; y2=127; label="Display Mode" }, @{ y1=147; y2=181; label="Screen Effects" },
    @{ y1=201; y2=235; label="Stop Voice on Click" }, @{ y1=255; y2=289; label="Recolor Read Text" }
)) {
    Wipe-ByColumn $optBmp 400 42 365 $row.y1 $row.y2
    Draw-UiText $g $row.label "Segoe UI" 22 ([System.Drawing.FontStyle]::Bold) (New-Object System.Drawing.RectangleF(46,$row.y1,315,($row.y2-$row.y1))) $white ([System.Drawing.Color]::Transparent) 0 ([System.Drawing.StringAlignment]::Near)
}
foreach ($row in @(
    @{ y1=309; y2=343; label="Window Opacity"; lo="Min"; hi="Max" },
    @{ y1=472; y2=505; label="Master Volume";  lo="Min"; hi="Max" },
    @{ y1=525; y2=559; label="BGM";            lo="Min"; hi="Max" },
    @{ y1=580; y2=613; label="Voice";          lo="Min"; hi="Max" },
    @{ y1=634; y2=667; label="SFX";            lo="Min"; hi="Max" }
)) {
    Wipe-ByColumn $optBmp 360 42 308 $row.y1 $row.y2
    Wipe-ByColumn $optBmp 360 478 525 $row.y1 $row.y2
    Draw-UiText $g $row.label "Segoe UI" 21 ([System.Drawing.FontStyle]::Bold) (New-Object System.Drawing.RectangleF(46,$row.y1,212,($row.y2-$row.y1))) $white ([System.Drawing.Color]::Transparent) 0 ([System.Drawing.StringAlignment]::Near)
    Draw-UiText $g $row.lo "Segoe UI" 17 ([System.Drawing.FontStyle]::Bold) (New-Object System.Drawing.RectangleF(262,$row.y1,46,($row.y2-$row.y1))) $white $navyOutline 4
    Draw-UiText $g $row.hi "Segoe UI" 17 ([System.Drawing.FontStyle]::Bold) (New-Object System.Drawing.RectangleF(476,$row.y1,48,($row.y2-$row.y1))) $white $navyOutline 4
}
foreach ($row in @(
    @{ y1=39; y2=72; label="Text Speed"; lo="Slow"; hi="Fast" },
    @{ y1=93; y2=127; label="Auto-Mode Wait"; lo="Slow"; hi="Fast" }
)) {
    Wipe-ByColumn $optBmp 1010 674 938 $row.y1 $row.y2
    Wipe-ByColumn $optBmp 1010 1110 1158 $row.y1 $row.y2
    Draw-UiText $g $row.label "Segoe UI" 21 ([System.Drawing.FontStyle]::Bold) (New-Object System.Drawing.RectangleF(678,$row.y1,212,($row.y2-$row.y1))) $white ([System.Drawing.Color]::Transparent) 0 ([System.Drawing.StringAlignment]::Near)
    Draw-UiText $g $row.lo "Segoe UI" 16 ([System.Drawing.FontStyle]::Bold) (New-Object System.Drawing.RectangleF(890,$row.y1,52,($row.y2-$row.y1))) $white $navyOutline 4
    Draw-UiText $g $row.hi "Segoe UI" 16 ([System.Drawing.FontStyle]::Bold) (New-Object System.Drawing.RectangleF(1108,$row.y1,52,($row.y2-$row.y1))) $white $navyOutline 4
}
for ($x = 700; $x -le 1205; $x++) {
    $tc = $optBmp.GetPixel($x, 139); $bc = $optBmp.GetPixel($x, 202)
    for ($y = 141; $y -le 201; $y++) {
        $t = ($y - 140.0) / 62.0
        $optBmp.SetPixel($x, $y, [System.Drawing.Color]::FromArgb(255, [int]($tc.R*(1-$t)+$bc.R*$t), [int]($tc.G*(1-$t)+$bc.G*$t), [int]($tc.B*(1-$t)+$bc.B*$t)))
    }
}
Draw-UiText $g 'Preview both "Text Speed" and "Auto-Mode Wait"' "Segoe UI" 19 ([System.Drawing.FontStyle]::Bold) (New-Object System.Drawing.RectangleF(700,144,510,26)) $navyOutline $white 4 ([System.Drawing.StringAlignment]::Near)
Draw-UiText $g 'in the sample window below.' "Segoe UI" 19 ([System.Drawing.FontStyle]::Bold) (New-Object System.Drawing.RectangleF(700,172,510,26)) $navyOutline $white 4 ([System.Drawing.StringAlignment]::Near)
foreach ($row in @(
    @{ y1=309; y2=343; label="Text Skip" }, @{ y1=363; y2=397; label="Skip After Choices" },
    @{ y1=417; y2=451; label="Text Style" }, @{ y1=472; y2=505; label="Font" }
)) {
    Wipe-ByColumn $optBmp 950 674 940 $row.y1 $row.y2
    Draw-UiText $g $row.label "Segoe UI" 22 ([System.Drawing.FontStyle]::Bold) (New-Object System.Drawing.RectangleF(678,$row.y1,260,($row.y2-$row.y1))) $white ([System.Drawing.Color]::Transparent) 0 ([System.Drawing.StringAlignment]::Near)
}
$g.Dispose(); $sysOverrides[1000] = $optBmp

$newSys = [RemPlusPatchHelpers]::RepackS25($origSysBytes, $sysOverrides)
[System.IO.File]::WriteAllBytes((Join-Path $gameDDir "sys.s25"), $newSys)
foreach ($v in $sysOverrides.Values) { $v.Dispose() }

# Clean up temporary extracted originals
Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Installation complete!" -ForegroundColor Cyan
Write-Host "  Launcher : $(Join-Path $GameDir 'REMPLUS_tl.exe')"
Write-Host "  Scripts  : $scriptCount English scripts installed in p\"
Write-Host "  Textures : d\caution.s25 ($([int]($newCaution.Length/1KB)) KB), d\sys.s25 ($([int]($newSys.Length/1KB)) KB)"
Write-Host ""
Write-Host "Double-click REMPLUS_tl.exe to play Re:Rem Plus in English (no Locale Emulator needed)!" -ForegroundColor Green
