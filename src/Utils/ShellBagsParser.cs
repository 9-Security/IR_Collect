using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using IR_Collect;

namespace IR_Collect.Utils
{
    /// <summary>
    /// Phase-1 ShellBags parser for Windows Registry Editor 5.00 exports of BagMRU/Bags
    /// (produced by reg export …\Windows\Shell). Facts-only path recovery; no verdicts.
    /// </summary>
    public static class ShellBagsParser
    {
        public const string ShellBagsRegGlob = "ShellBags_*.reg";
        private const int MaxRowsTotal = 150000;
        private const int MaxHexBytesPerValue = 65536;

        /// <summary>Writes Registry\shellbags.csv under baseDir when stale or missing. Returns row count or -1 on error.</summary>
        public static int TryEnsureShellBagsCsv(string extractPath, bool force, out string detail)
        {
            detail = "";
            if (string.IsNullOrEmpty(extractPath) || !Directory.Exists(extractPath))
            {
                detail = "extract path missing";
                return -1;
            }

            var regFiles = new List<string>();
            try
            {
                foreach (string f in Directory.GetFiles(extractPath, ShellBagsRegGlob, SearchOption.AllDirectories))
                {
                    try
                    {
                        if (IsPathSafeUnder(f, extractPath))
                            regFiles.Add(Path.GetFullPath(f));
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                detail = ex.Message ?? "enumerate failed";
                return -1;
            }

            if (regFiles.Count == 0)
            {
                detail = "no ShellBags_*.reg";
                return 0;
            }

            string registryDir = Path.Combine(extractPath, "Registry");
            string outPath = Path.Combine(registryDir, ArtifactNames.ShellBagsCsv);
            try
            {
                if (!force && File.Exists(outPath))
                {
                    DateTime csvW = File.GetLastWriteTimeUtc(outPath);
                    bool anyNewer = false;
                    foreach (string r in regFiles)
                    {
                        try
                        {
                            if (File.GetLastWriteTimeUtc(r) > csvW.AddSeconds(2))
                            {
                                anyNewer = true;
                                break;
                            }
                        }
                        catch { }
                    }
                    if (!anyNewer)
                    {
                        detail = "shellbags.csv up to date";
                        return 0;
                    }
                }

                if (!Directory.Exists(registryDir))
                    Directory.CreateDirectory(registryDir);

                int rows = WriteCsvFromRegs(regFiles, outPath, out detail);
                return rows;
            }
            catch (Exception ex)
            {
                detail = ex.Message ?? "write failed";
                return -1;
            }
        }

        internal static bool IsPathSafeUnder(string fileFull, string rootFull)
        {
            try
            {
                string a = Path.GetFullPath(fileFull).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                string b = Path.GetFullPath(rootFull).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                return a.StartsWith(b + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
                    || string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>Generate CSV after collection (registryDir = …\Registry).</summary>
        public static int TryGenerateAfterCollection(string registryDir, out string detail)
        {
            detail = "";
            if (string.IsNullOrEmpty(registryDir) || !Directory.Exists(registryDir))
            {
                detail = "registry dir missing";
                return -1;
            }
            string root = Path.GetDirectoryName(Path.GetFullPath(registryDir.TrimEnd(Path.DirectorySeparatorChar))) ?? registryDir;
            return TryEnsureShellBagsCsv(root, true, out detail);
        }

        private static int WriteCsvFromRegs(List<string> regFiles, string outPath, out string detail)
        {
            detail = "";
            var allRows = new List<ShellBagCsvRow>();
            foreach (string reg in regFiles.OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
            {
                try
                {
                    ParseRegFile(reg, allRows);
                    if (allRows.Count >= MaxRowsTotal)
                        break;
                }
                catch (Exception ex)
                {
                    Logger.Warning("ShellBagsParser " + reg + ": " + ex.Message);
                }
            }

            using (var sw = new StreamWriter(outPath, false, new UTF8Encoding(false)))
            {
                sw.WriteLine("Sid,User,BagPath,RegistryKey,ValueName,DecodedPath,MruSlot,LastWriteTime,ParserNote,SourceFile");
                int n = 0;
                foreach (ShellBagCsvRow row in allRows)
                {
                    if (++n > MaxRowsTotal) break;
                    sw.WriteLine(string.Format("{0},{1},{2},{3},{4},{5},{6},{7},{8},{9}",
                        CsvUtils.EscapeField(row.Sid ?? ""),
                        CsvUtils.EscapeField(row.User ?? ""),
                        CsvUtils.EscapeField(row.BagPath ?? ""),
                        CsvUtils.EscapeField(row.RegistryKey ?? ""),
                        CsvUtils.EscapeField(row.ValueName ?? ""),
                        CsvUtils.EscapeField(row.DecodedPath ?? ""),
                        CsvUtils.EscapeField(row.MruSlot ?? ""),
                        CsvUtils.EscapeField(row.LastWriteTime ?? ""),
                        CsvUtils.EscapeField(row.ParserNote ?? ""),
                        CsvUtils.EscapeField(row.SourceFile ?? "")));
                }
                detail = n + " row(s)";
                return n;
            }
        }

        private sealed class ShellBagCsvRow
        {
            public string Sid;
            public string User;
            public string BagPath;
            public string RegistryKey;
            public string ValueName;
            public string DecodedPath;
            public string MruSlot;
            public string LastWriteTime;
            public string ParserNote;
            public string SourceFile;
        }

        private static void ParseRegFile(string regPath, List<ShellBagCsvRow> sink)
        {
            string sidFromFile = ExtractSidFromFileName(Path.GetFileName(regPath));
            List<string> lines = ReadLogicalLines(regPath);
            string currentKey = null;
            foreach (string line in lines)
            {
                if (string.IsNullOrWhiteSpace(line) || line.StartsWith(";")) continue;
                if (line.StartsWith("Windows Registry Editor", StringComparison.OrdinalIgnoreCase)) continue;

                if (line.Length >= 2 && line[0] == '[')
                {
                    int end = line.IndexOf(']');
                    currentKey = end > 1 ? line.Substring(1, end - 1).Trim() : null;
                    continue;
                }

                if (currentKey == null) continue;
                if (!IsRelevantShellBagsKey(currentKey)) continue;

                ParseValueLine(currentKey, line, sidFromFile, regPath, sink);
            }
        }

        internal static string ExtractSidFromFileName(string fileName)
        {
            if (string.IsNullOrEmpty(fileName)) return "";
            if (!fileName.StartsWith("ShellBags_", StringComparison.OrdinalIgnoreCase)) return "";
            string mid = fileName.Substring("ShellBags_".Length);
            if (mid.EndsWith(".reg", StringComparison.OrdinalIgnoreCase))
                mid = mid.Substring(0, mid.Length - 4);
            return mid.Trim();
        }

        /// <summary>
        /// Phase-1: accept BagMRU branches; <c>...\Bags\&lt;n&gt;\Shell</c> / <c>ShellNoRoam</c> keys
        /// (registry key name is <c>Shell</c>, so the path often ends with <c>\Shell</c> and does not contain a <c>\Shell\</c> segment).
        /// </summary>
        private static bool IsRelevantShellBagsKey(string keyPath)
        {
            if (string.IsNullOrEmpty(keyPath)) return false;
            if (keyPath.IndexOf("\\BagMRU", StringComparison.OrdinalIgnoreCase) >= 0) return true;
            if (keyPath.IndexOf("\\Shell\\", StringComparison.OrdinalIgnoreCase) >= 0) return true;
            if (keyPath.IndexOf("\\Shell]", StringComparison.OrdinalIgnoreCase) >= 0) return true;
            if (keyPath.IndexOf("\\Bags\\", StringComparison.OrdinalIgnoreCase) < 0) return false;
            if (keyPath.EndsWith("\\ShellNoRoam", StringComparison.OrdinalIgnoreCase)) return true;
            if (keyPath.EndsWith("\\Shell", StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        private static List<string> ReadLogicalLines(string path)
        {
            return ReadLogicalLinesFromText(ReadRegText(path));
        }

        /// <summary>Merge .reg physical lines when a line ends with <c>\</c> (hex/value continuation). Continuation fragments strip trailing <c>\</c>; leading spaces on continuation lines are ignored.</summary>
        internal static List<string> ReadLogicalLinesFromText(string text)
        {
            var result = new List<string>();
            if (text == null) return result;
            var acc = new StringBuilder();
            using (var sr = new StringReader(text))
            {
                string line;
                while ((line = sr.ReadLine()) != null)
                {
                    line = line.TrimEnd('\r');
                    if (acc.Length > 0)
                    {
                        string cont = line.TrimStart();
                        if (string.IsNullOrEmpty(cont))
                            continue;
                        if (cont.Length > 0 && cont[cont.Length - 1] == '\\')
                        {
                            if (cont.Length > 1)
                                acc.Append(cont.Substring(0, cont.Length - 1));
                        }
                        else
                        {
                            acc.Append(cont);
                            result.Add(acc.ToString());
                            acc.Length = 0;
                        }
                        continue;
                    }
                    string head = line.TrimStart();
                    if (head.Length > 0 && head[head.Length - 1] == '\\')
                    {
                        if (head.Length > 1)
                            acc.Append(head.Substring(0, head.Length - 1));
                        continue;
                    }
                    result.Add(head);
                }
                if (acc.Length > 0)
                    result.Add(acc.ToString());
            }
            return result;
        }

        private static string ReadRegText(string path)
        {
            byte[] bom = new byte[4];
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                int n = fs.Read(bom, 0, bom.Length);
                fs.Position = 0;
                if (n >= 2 && bom[0] == 0xFF && bom[1] == 0xFE)
                {
                    using (var sr = new StreamReader(fs, Encoding.Unicode, false))
                        return sr.ReadToEnd();
                }
                if (n >= 3 && bom[0] == 0xEF && bom[1] == 0xBB && bom[2] == 0xBF)
                {
                    using (var sr = new StreamReader(fs, Encoding.UTF8, false))
                        return sr.ReadToEnd();
                }
                using (var sr = new StreamReader(fs, Encoding.Default, true))
                    return sr.ReadToEnd();
            }
        }

        private static void ParseValueLine(string keyPath, string line, string sidFromFile, string regPath, List<ShellBagCsvRow> sink)
        {
            int eq = line.IndexOf('=');
            if (eq <= 0) return;
            string lhs = line.Substring(0, eq).Trim();
            string rhs = line.Substring(eq + 1).Trim();
            if (lhs.Length < 2 || lhs[0] != '"' || !lhs.EndsWith("\"", StringComparison.Ordinal)) return;
            string valName = UnescapeRegName(lhs.Substring(1, lhs.Length - 2));

            string sid = !string.IsNullOrEmpty(sidFromFile) ? sidFromFile : ExtractSidFromRegistryKey(keyPath);
            string user = string.IsNullOrEmpty(sid) ? "" : sid;
            string bagRel = ExtractBagRelativePath(keyPath);
            string slot = IsAllDigits(valName) ? valName : "";

            if (rhs.StartsWith("hex(", StringComparison.OrdinalIgnoreCase))
            {
                int c2 = rhs.IndexOf(':');
                if (c2 > 0 && c2 + 1 < rhs.Length)
                    rhs = "hex:" + rhs.Substring(c2 + 1).TrimStart();
            }

            if (rhs.StartsWith("hex:", StringComparison.OrdinalIgnoreCase))
            {
                byte[] bytes = ParseHexBytes(rhs);
                if (bytes == null || bytes.Length == 0) return;
                if (string.Equals(valName, "MRUListEx", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(valName, "MRUList", StringComparison.OrdinalIgnoreCase))
                    return;

                bool isBagMru = keyPath.IndexOf("\\BagMRU", StringComparison.OrdinalIgnoreCase) >= 0;
                bool isBagsShell = keyPath.IndexOf("\\Bags\\", StringComparison.OrdinalIgnoreCase) >= 0
                    && (string.Equals(valName, "Shell", StringComparison.OrdinalIgnoreCase)
                        || string.Equals(valName, "ShellNoRoam", StringComparison.OrdinalIgnoreCase));
                if (!isBagMru && !isBagsShell) return;

                DecodeResult dec = DecodeShellItemBlob(bytes);
                string note = dec.ParserNote;
                if (string.IsNullOrEmpty(dec.Path) && string.IsNullOrEmpty(note))
                    note = "ShellBags hex value present but no path segments decoded in phase-1 parser.";
                note = AppendStaticExportNote(note);

                sink.Add(new ShellBagCsvRow
                {
                    Sid = sid,
                    User = user,
                    BagPath = bagRel,
                    RegistryKey = keyPath,
                    ValueName = valName,
                    DecodedPath = dec.Path ?? "",
                    MruSlot = slot,
                    LastWriteTime = FormatSourceRegLastWriteUtc(regPath),
                    ParserNote = note,
                    SourceFile = Path.GetFileName(regPath) ?? ""
                });
                return;
            }

            if (rhs.StartsWith("dword:", StringComparison.OrdinalIgnoreCase))
            {
                if (keyPath.IndexOf("\\BagMRU", StringComparison.OrdinalIgnoreCase) < 0) return;
                if (!string.Equals(valName, "NodeSlot", StringComparison.OrdinalIgnoreCase)
                    && !string.Equals(valName, "NodeSlots", StringComparison.OrdinalIgnoreCase)) return;
                uint dv;
                string note = AppendStaticExportNote(
                    uint.TryParse(rhs.Substring(6).Trim(), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out dv)
                        ? ("DWORD " + valName + "=" + dv.ToString(CultureInfo.InvariantCulture) + "; path not carried in this value (see sibling numbered hex values).")
                        : ("DWORD " + valName + " present; numeric parse failed."));
                sink.Add(new ShellBagCsvRow
                {
                    Sid = sid,
                    User = user,
                    BagPath = bagRel,
                    RegistryKey = keyPath,
                    ValueName = valName,
                    DecodedPath = "",
                    MruSlot = slot,
                    LastWriteTime = FormatSourceRegLastWriteUtc(regPath),
                    ParserNote = note,
                    SourceFile = Path.GetFileName(regPath) ?? ""
                });
            }
        }

        /// <summary>UTC LastWriteTime of the exported .reg file (collection artifact). Not the registry key timestamp.</summary>
        private static string FormatSourceRegLastWriteUtc(string regPath)
        {
            if (string.IsNullOrEmpty(regPath)) return "";
            try
            {
                return File.GetLastWriteTimeUtc(regPath).ToString("o", CultureInfo.InvariantCulture);
            }
            catch
            {
                return "";
            }
        }

        private static string AppendStaticExportNote(string note)
        {
            const string exportNote = "Registry key LastWriteTime is absent from .reg exports. LastWriteTime column (when present) is UTC LastWriteTime of the source ShellBags_*.reg file, not the original registry key timestamp.";
            if (string.IsNullOrEmpty(note)) return exportNote;
            if (note.IndexOf("Registry key LastWriteTime", StringComparison.OrdinalIgnoreCase) >= 0)
                return note;
            return note + " " + exportNote;
        }

        private static string UnescapeRegName(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            return s.Replace("\\\"", "\"").Replace("\\\\", "\\");
        }

        private static bool IsAllDigits(string s)
        {
            if (string.IsNullOrEmpty(s)) return false;
            for (int i = 0; i < s.Length; i++)
            {
                if (!char.IsDigit(s[i])) return false;
            }
            return true;
        }

        private static string ExtractSidFromRegistryKey(string keyPath)
        {
            if (string.IsNullOrEmpty(keyPath)) return "";
            int idx = keyPath.IndexOf("HKEY_USERS\\", StringComparison.OrdinalIgnoreCase);
            if (idx < 0) return "";
            string rest = keyPath.Substring(idx + 11);
            int slash = rest.IndexOf('\\');
            string first = slash >= 0 ? rest.Substring(0, slash) : rest;
            int cls = first.IndexOf("_Classes", StringComparison.OrdinalIgnoreCase);
            if (cls >= 0) first = first.Substring(0, cls);
            if (first.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase)) return first;
            return "";
        }

        private static string ExtractBagRelativePath(string keyPath)
        {
            if (string.IsNullOrEmpty(keyPath)) return "";
            int shell = keyPath.IndexOf("\\Shell\\", StringComparison.OrdinalIgnoreCase);
            if (shell < 0)
            {
                shell = keyPath.IndexOf("\\Windows\\Shell", StringComparison.OrdinalIgnoreCase);
                if (shell < 0) return "";
                shell += "\\Windows\\Shell".Length;
            }
            else
                shell += "\\Shell\\".Length;

            if (shell >= keyPath.Length) return "";
            return keyPath.Substring(shell).TrimStart('\\');
        }

        private static byte[] ParseHexBytes(string rhs)
        {
            int colon = rhs.IndexOf(':');
            if (colon < 0) return new byte[0];
            string body = rhs.Substring(colon + 1).Replace(" ", "").Replace("\t", "");
            if (body.Length == 0) return new byte[0];
            var parts = body.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length > MaxHexBytesPerValue) return new byte[0];
            var src = new List<byte>(parts.Length);
            foreach (string p in parts)
            {
                string t = p.Trim();
                if (t.Length != 2) return new byte[0];
                byte b;
                if (!byte.TryParse(t, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out b))
                    return new byte[0];
                src.Add(b);
            }
            return src.ToArray();
        }

        internal sealed class DecodeResult
        {
            public string Path;
            public string ParserNote;
        }

        internal static DecodeResult DecodeShellItemBlob(byte[] data)
        {
            var res = new DecodeResult();
            if (data == null || data.Length < 3)
            {
                res.ParserNote = "Shell item data too short.";
                return res;
            }

            var parts = new List<string>();
            var notes = new List<string>();
            int pos = 0;
            while (pos + 2 < data.Length)
            {
                ushort size = BitConverter.ToUInt16(data, pos);
                if (size <= 2)
                {
                    pos += 2;
                    if (size == 0) break;
                    continue;
                }
                if (pos + size > data.Length)
                {
                    notes.Add("Truncated shell item (declared size exceeds buffer); partial decode.");
                    break;
                }
                int end = pos + size;
                byte type = data[pos + 2];
                string seg;
                string n;
                TryDecodeOneItem(data, pos, end, type, out seg, out n);
                if (!string.IsNullOrEmpty(seg))
                    parts.Add(seg);
                if (!string.IsNullOrEmpty(n))
                    notes.Add(n);
                pos = end;
            }

            if (parts.Count > 0)
                res.Path = string.Join("\\", parts.ToArray());
            if (notes.Count > 0)
                res.ParserNote = string.Join(" ", notes.ToArray());
            return res;
        }

        internal static void TryDecodeOneItem(byte[] data, int start, int end, byte type, out string segment, out string note)
        {
            segment = null;
            note = null;
            int bodyStart = start + 3;
            switch (type)
            {
                case 0x31:
                    segment = ReadAsciiNull(data, bodyStart, end);
                    if (string.IsNullOrEmpty(segment))
                        note = "Type 0x31 shell item: ASCII path segment empty or unreadable.";
                    break;
                case 0x32:
                    segment = ReadUtf16Null(data, bodyStart, end);
                    if (string.IsNullOrEmpty(segment))
                        note = "Type 0x32 shell item: Unicode path segment empty or unreadable.";
                    break;
                case 0x35:
                    segment = ReadUtf16Null(data, bodyStart, end);
                    if (string.IsNullOrEmpty(segment))
                        segment = ReadAsciiNull(data, bodyStart, end);
                    if (string.IsNullOrEmpty(segment))
                        note = "Type 0x35 shell item: path segment not decoded.";
                    break;
                case 0x2f:
                    note = "Type 0x2F (computer/volume GUID) shell item; phase-1 parser does not expand to drive letter.";
                    break;
                case 0x2e:
                    note = "Type 0x2E shell item; network or special root — path segment not expanded.";
                    break;
                case 0x1f:
                    note = "Type 0x1F shell item (hidden root); path segment not expanded.";
                    break;
                case 0x3a:
                    note = "Type 0x3A shell item; partial semantics in phase-1 parser.";
                    break;
                case 0x3e:
                case 0x41:
                case 0x42:
                case 0x47:
                case 0x61:
                    note = string.Format(CultureInfo.InvariantCulture, "Type 0x{0:X2} shell item not expanded in phase-1 parser.", type);
                    break;
                default:
                    if (type != 0x00 && type != 0x01)
                        note = string.Format(CultureInfo.InvariantCulture, "Unmapped shell item type 0x{0:X2}; path segment skipped.", type);
                    break;
            }
        }

        private static string ReadAsciiNull(byte[] data, int start, int end)
        {
            var sb = new StringBuilder();
            for (int i = start; i < end; i++)
            {
                byte b = data[i];
                if (b == 0) break;
                if (b >= 0x20 && b < 0x7f)
                    sb.Append((char)b);
                else
                    return sb.Length > 0 ? sb.ToString() : null;
            }
            return sb.Length > 0 ? sb.ToString() : null;
        }

        private static string ReadUtf16Null(byte[] data, int start, int end)
        {
            if (start + 2 > end) return null;
            var sb = new StringBuilder();
            int i = start;
            while (i + 1 < end)
            {
                char c = (char)(data[i] | (data[i + 1] << 8));
                if (c == '\0') break;
                if (c < 0x20 && c != 0) break;
                sb.Append(c);
                i += 2;
            }
            return sb.Length > 0 ? sb.ToString() : null;
        }
    }
}
