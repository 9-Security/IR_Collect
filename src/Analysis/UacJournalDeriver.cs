using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using IR_Collect.Utils;

namespace IR_Collect.Analysis
{
    /// <summary>
    /// Derives bounded metadata from native systemd journal files and boot ranges from
    /// UAC's journalctl --list-boots output. Native journal entry payloads remain raw.
    /// </summary>
    public static class UacJournalDeriver
    {
        private const int MinimumJournalHeaderBytes = 208;
        private const int CurrentJournalHeaderBytes = 272;
        private const long MaxBootListBytes = 20L * 1024 * 1024;
        private const int MaxJournalRows = 100000;
        private const int MaxBootRows = 10000;

        public static void DeriveInto(string folder, List<string> warnings)
        {
            DeriveInto(folder, folder, warnings);
        }

        public static void DeriveInto(string sourceRoot, string outputRoot, List<string> warnings)
        {
            if (string.IsNullOrWhiteSpace(sourceRoot) || !Directory.Exists(sourceRoot)) return;
            if (string.IsNullOrWhiteSpace(outputRoot)) return;
            Directory.CreateDirectory(outputRoot);
            try { DeriveJournalFiles(sourceRoot, outputRoot, warnings); }
            catch (Exception ex) { Warn(warnings, "journal header derive failed: " + (ex.Message ?? "")); }
            try { DeriveBootSessions(sourceRoot, outputRoot, warnings); }
            catch (Exception ex) { Warn(warnings, "journal boot-session derive failed: " + (ex.Message ?? "")); }
        }

        public static bool IsJournalFilePath(string path)
        {
            string value = (path ?? "").Replace('\\', '/').ToLowerInvariant();
            return value.EndsWith(".journal", StringComparison.Ordinal) ||
                value.EndsWith(".journal~", StringComparison.Ordinal);
        }

        public static bool IsBootListPath(string path)
        {
            string name = Path.GetFileName((path ?? "").Replace('/', Path.DirectorySeparatorChar)) ?? "";
            string value = name.ToLowerInvariant();
            return value.IndexOf("journalctl", StringComparison.Ordinal) >= 0 &&
                value.IndexOf("list-boots", StringComparison.Ordinal) >= 0 &&
                value.EndsWith(".txt", StringComparison.Ordinal);
        }

        private static void DeriveJournalFiles(string sourceRoot, string outputRoot, List<string> warnings)
        {
            string output = Path.Combine(outputRoot, ArtifactNames.UacJournalFilesCsv);
            if (File.Exists(output)) return;

            var rows = new List<JournalFileRow>();
            int invalid = 0;
            foreach (string file in SafeEnumerate(sourceRoot)
                .Where(IsJournalFilePath)
                .OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
            {
                JournalFileRow row;
                string error;
                if (TryReadJournalHeader(sourceRoot, file, out row, out error))
                    rows.Add(row);
                else
                {
                    invalid++;
                    if (invalid <= 20) Warn(warnings, "journal header not parsed: " + RelativePath(sourceRoot, file) + ": " + error);
                }
                if (rows.Count >= MaxJournalRows) break;
            }
            if (rows.Count == 0) return;

            AtomicFile.WriteText(output, new UTF8Encoding(false), delegate(StreamWriter sw)
            {
                sw.WriteLine("ModifiedTimeUtc,SourcePath,FileSizeBytes,State,FileId,MachineId,TailBootId,HeaderSize,ArenaSize,ObjectCount,EntryCount,HeadEntrySequence,TailEntrySequence,HeadEntryTimeUtc,TailEntryTimeUtc,CompatibleFeatures,IncompatibleFeatures,ParseStatus,Details");
                foreach (JournalFileRow row in rows)
                {
                    sw.WriteLine(string.Join(",", new string[] {
                        CsvUtils.EscapeField(row.ModifiedTimeUtc),
                        CsvUtils.EscapeField(row.SourcePath),
                        row.FileSizeBytes.ToString(CultureInfo.InvariantCulture),
                        CsvUtils.EscapeField(row.State),
                        CsvUtils.EscapeField(row.FileId),
                        CsvUtils.EscapeField(row.MachineId),
                        CsvUtils.EscapeField(row.TailBootId),
                        row.HeaderSize,
                        row.ArenaSize,
                        row.ObjectCount,
                        row.EntryCount,
                        row.HeadEntrySequence,
                        row.TailEntrySequence,
                        CsvUtils.EscapeField(row.HeadEntryTimeUtc),
                        CsvUtils.EscapeField(row.TailEntryTimeUtc),
                        CsvUtils.EscapeField(row.CompatibleFeatures),
                        CsvUtils.EscapeField(row.IncompatibleFeatures),
                        CsvUtils.EscapeField(row.ParseStatus),
                        CsvUtils.EscapeField(row.Details)
                    }));
                }
            });

            if (rows.Count >= MaxJournalRows)
                Warn(warnings, "journal file rows were capped at " + MaxJournalRows.ToString(CultureInfo.InvariantCulture) + ".");
            if (invalid > 20)
                Warn(warnings, (invalid - 20).ToString(CultureInfo.InvariantCulture) + " additional journal headers were not parsed.");
            Logger.Info("Derived " + ArtifactNames.UacJournalFilesCsv + " (" +
                rows.Count.ToString(CultureInfo.InvariantCulture) + " rows).");
        }

        private static void DeriveBootSessions(string sourceRoot, string outputRoot, List<string> warnings)
        {
            string output = Path.Combine(outputRoot, ArtifactNames.UacBootSessionsCsv);
            if (File.Exists(output)) return;

            var rows = new List<BootSessionRow>();
            foreach (string file in SafeEnumerate(sourceRoot)
                .Where(IsBootListPath)
                .Where(IsInspectableBootList)
                .OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
            {
                string source = RelativePath(sourceRoot, file);
                string[] lines = ReadLines(file);
                for (int i = 0; i < lines.Length && rows.Count < MaxBootRows; i++)
                {
                    BootSessionRow row;
                    if (TryParseBootLine(lines[i], source, i + 1, out row))
                        rows.Add(row);
                }
                if (rows.Count >= MaxBootRows) break;
            }
            if (rows.Count == 0) return;

            AtomicFile.WriteText(output, new UTF8Encoding(false), delegate(StreamWriter sw)
            {
                sw.WriteLine("BootIndex,BootId,FirstEntry,FirstEntryUtc,LastEntry,LastEntryUtc,TimeParseStatus,SourcePath,LineNumber");
                foreach (BootSessionRow row in rows)
                {
                    sw.WriteLine(string.Join(",", new string[] {
                        row.BootIndex.ToString(CultureInfo.InvariantCulture),
                        CsvUtils.EscapeField(row.BootId),
                        CsvUtils.EscapeField(row.FirstEntry),
                        CsvUtils.EscapeField(row.FirstEntryUtc),
                        CsvUtils.EscapeField(row.LastEntry),
                        CsvUtils.EscapeField(row.LastEntryUtc),
                        CsvUtils.EscapeField(row.TimeParseStatus),
                        CsvUtils.EscapeField(row.SourcePath),
                        row.LineNumber.ToString(CultureInfo.InvariantCulture)
                    }));
                }
            });

            if (rows.Count >= MaxBootRows)
                Warn(warnings, "boot-session rows were capped at " + MaxBootRows.ToString(CultureInfo.InvariantCulture) + ".");
            Logger.Info("Derived " + ArtifactNames.UacBootSessionsCsv + " (" +
                rows.Count.ToString(CultureInfo.InvariantCulture) + " rows).");
        }

        private static bool TryReadJournalHeader(string root, string file, out JournalFileRow row, out string error)
        {
            row = null;
            error = "";
            try
            {
                FileInfo info = new FileInfo(file);
                if (info.Length < MinimumJournalHeaderBytes)
                    throw new InvalidDataException("file is shorter than the minimum journal header");

                byte[] header = new byte[Math.Min(CurrentJournalHeaderBytes, (int)Math.Min(info.Length, CurrentJournalHeaderBytes))];
                using (FileStream stream = File.OpenRead(file))
                {
                    int read = 0;
                    while (read < header.Length)
                    {
                        int count = stream.Read(header, read, header.Length - read);
                        if (count <= 0) break;
                        read += count;
                    }
                    if (read != header.Length) throw new InvalidDataException("journal header is truncated");
                }

                if (!string.Equals(Encoding.ASCII.GetString(header, 0, 8), "LPKSHHRH", StringComparison.Ordinal))
                    throw new InvalidDataException("journal signature is invalid");

                uint compatible = ReadUInt32LittleEndian(header, 8);
                uint incompatible = ReadUInt32LittleEndian(header, 12);
                byte stateValue = header[16];
                ulong headerSize = ReadUInt64LittleEndian(header, 88);
                ulong arenaSize = ReadUInt64LittleEndian(header, 96);
                if (headerSize < MinimumJournalHeaderBytes || headerSize > (ulong)info.Length)
                    throw new InvalidDataException("journal header_size is outside the file bounds");

                ulong objectCount = ReadUInt64LittleEndian(header, 144);
                ulong entryCount = ReadUInt64LittleEndian(header, 152);
                ulong tailSequence = ReadUInt64LittleEndian(header, 160);
                ulong headSequence = ReadUInt64LittleEndian(header, 168);
                ulong headRealtime = ReadUInt64LittleEndian(header, 184);
                ulong tailRealtime = ReadUInt64LittleEndian(header, 192);
                uint unknownCompatible = compatible & ~7U;
                uint unknownIncompatible = incompatible & ~31U;
                var details = new List<string>();
                ulong usedSize;
                if (TryAdd(headerSize, arenaSize, out usedSize) && usedSize > (ulong)info.Length)
                    details.Add("header_size_plus_arena_size_exceeds_file_size");
                if (unknownCompatible != 0)
                    details.Add("unknown_compatible_flags=0x" + unknownCompatible.ToString("x", CultureInfo.InvariantCulture));
                if (unknownIncompatible != 0)
                    details.Add("unknown_incompatible_flags=0x" + unknownIncompatible.ToString("x", CultureInfo.InvariantCulture));
                if (file.EndsWith(".journal~", StringComparison.OrdinalIgnoreCase))
                    details.Add("journal_file_marked_corrupt_or_unclean");

                row = new JournalFileRow
                {
                    ModifiedTimeUtc = info.LastWriteTimeUtc.ToString("o", CultureInfo.InvariantCulture),
                    SourcePath = RelativePath(root, file),
                    FileSizeBytes = info.Length,
                    State = JournalState(stateValue),
                    FileId = ReadId(header, 24),
                    MachineId = ReadId(header, 40),
                    TailBootId = ReadId(header, 56),
                    HeaderSize = headerSize.ToString(CultureInfo.InvariantCulture),
                    ArenaSize = arenaSize.ToString(CultureInfo.InvariantCulture),
                    ObjectCount = objectCount.ToString(CultureInfo.InvariantCulture),
                    EntryCount = entryCount.ToString(CultureInfo.InvariantCulture),
                    HeadEntrySequence = headSequence.ToString(CultureInfo.InvariantCulture),
                    TailEntrySequence = tailSequence.ToString(CultureInfo.InvariantCulture),
                    HeadEntryTimeUtc = FormatUnixMicroseconds(headRealtime),
                    TailEntryTimeUtc = FormatUnixMicroseconds(tailRealtime),
                    CompatibleFeatures = CompatibleFeatures(compatible),
                    IncompatibleFeatures = IncompatibleFeatures(incompatible),
                    ParseStatus = unknownIncompatible == 0 ? "header-parsed" : "header-parsed-unknown-features",
                    Details = string.Join("; ", details.ToArray())
                };
                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message ?? "journal header parse failed";
                return false;
            }
        }

        private static bool TryParseBootLine(string raw, string source, int lineNumber, out BootSessionRow row)
        {
            row = null;
            string line = (raw ?? "").Trim();
            Match prefix = Regex.Match(line, @"^(?<index>[+-]?\d+)\s+(?<boot>[0-9a-fA-F]{32})\s+(?<range>.+)$",
                RegexOptions.CultureInvariant);
            if (!prefix.Success) return false;

            string range = prefix.Groups["range"].Value.Trim();
            int separatorIndex = range.IndexOf('\u2014');
            int separatorLength = 1;
            if (separatorIndex < 0) separatorIndex = range.IndexOf('\u2013');
            if (separatorIndex < 0)
            {
                Match asciiSeparator = Regex.Match(range, @"\s+--\s+", RegexOptions.CultureInvariant);
                if (!asciiSeparator.Success) return false;
                separatorIndex = asciiSeparator.Index;
                separatorLength = asciiSeparator.Length;
            }
            string first = range.Substring(0, separatorIndex).Trim();
            string last = range.Substring(separatorIndex + separatorLength).Trim();
            if (first.Length == 0 || last.Length == 0) return false;

            int bootIndex;
            if (!int.TryParse(prefix.Groups["index"].Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out bootIndex))
                return false;
            string firstUtc = ParseJournalctlTime(first);
            string lastUtc = ParseJournalctlTime(last);
            string parseStatus = firstUtc.Length > 0 && lastUtc.Length > 0
                ? "utc-parsed"
                : firstUtc.Length > 0 || lastUtc.Length > 0 ? "partial" : "raw-time-only";
            row = new BootSessionRow
            {
                BootIndex = bootIndex,
                BootId = prefix.Groups["boot"].Value.ToLowerInvariant(),
                FirstEntry = first,
                FirstEntryUtc = firstUtc,
                LastEntry = last,
                LastEntryUtc = lastUtc,
                TimeParseStatus = parseStatus,
                SourcePath = source,
                LineNumber = lineNumber
            };
            return true;
        }

        private static string ParseJournalctlTime(string value)
        {
            Match match = Regex.Match(value ?? "",
                @"(?<date>\d{4}-\d{2}-\d{2})\s+(?<time>\d{2}:\d{2}:\d{2})(?:\s+(?<zone>Z|UTC|GMT|[+-]\d{2}:?\d{2}))?\s*$",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            if (!match.Success) return "";
            DateTime date;
            if (!DateTime.TryParseExact(match.Groups["date"].Value + " " + match.Groups["time"].Value,
                "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.None, out date))
                return "";

            string zone = match.Groups["zone"].Value;
            if (string.Equals(zone, "Z", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(zone, "UTC", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(zone, "GMT", StringComparison.OrdinalIgnoreCase))
                return DateTime.SpecifyKind(date, DateTimeKind.Utc).ToString("o", CultureInfo.InvariantCulture);
            if (zone.Length > 0)
            {
                string normalized = zone;
                if (normalized.Length == 5 && (normalized[0] == '+' || normalized[0] == '-'))
                    normalized = normalized.Insert(3, ":");
                TimeSpan offset;
                string magnitude = normalized.Substring(1);
                if (TimeSpan.TryParse(magnitude, CultureInfo.InvariantCulture, out offset))
                {
                    if (normalized[0] == '-') offset = -offset;
                    try { return new DateTimeOffset(date, offset).UtcDateTime.ToString("o", CultureInfo.InvariantCulture); }
                    catch { return ""; }
                }
            }
            return "";
        }

        private static string CompatibleFeatures(uint value)
        {
            var features = new List<string>();
            if ((value & 1U) != 0) features.Add("sealed");
            if ((value & 2U) != 0) features.Add("tail-entry-boot-id");
            if ((value & 4U) != 0) features.Add("sealed-continuous");
            return string.Join("|", features.ToArray());
        }

        private static string IncompatibleFeatures(uint value)
        {
            var features = new List<string>();
            if ((value & 1U) != 0) features.Add("compressed-xz");
            if ((value & 2U) != 0) features.Add("compressed-lz4");
            if ((value & 4U) != 0) features.Add("keyed-hash");
            if ((value & 8U) != 0) features.Add("compressed-zstd");
            if ((value & 16U) != 0) features.Add("compact");
            return string.Join("|", features.ToArray());
        }

        private static string JournalState(byte value)
        {
            if (value == 0) return "offline";
            if (value == 1) return "online";
            if (value == 2) return "archived";
            return "unknown-" + value.ToString(CultureInfo.InvariantCulture);
        }

        private static string ReadId(byte[] bytes, int offset)
        {
            var sb = new StringBuilder(32);
            for (int i = 0; i < 16; i++)
                sb.Append(bytes[offset + i].ToString("x2", CultureInfo.InvariantCulture));
            return sb.ToString();
        }

        private static uint ReadUInt32LittleEndian(byte[] bytes, int offset)
        {
            return (uint)(bytes[offset] |
                bytes[offset + 1] << 8 |
                bytes[offset + 2] << 16 |
                bytes[offset + 3] << 24);
        }

        private static ulong ReadUInt64LittleEndian(byte[] bytes, int offset)
        {
            ulong value = 0;
            for (int i = 7; i >= 0; i--)
                value = (value << 8) | bytes[offset + i];
            return value;
        }

        private static bool TryAdd(ulong left, ulong right, out ulong value)
        {
            value = left + right;
            return value >= left;
        }

        private static string FormatUnixMicroseconds(ulong microseconds)
        {
            if (microseconds == 0) return "";
            try
            {
                const ulong maxMicroseconds = 253402300799999999UL;
                if (microseconds > maxMicroseconds) return "";
                DateTime epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
                return epoch.AddTicks(checked((long)microseconds * 10L)).ToString("o", CultureInfo.InvariantCulture);
            }
            catch { return ""; }
        }

        private static bool IsInspectableBootList(string path)
        {
            try
            {
                long size = new FileInfo(path).Length;
                return size > 0 && size <= MaxBootListBytes;
            }
            catch { return false; }
        }

        private static IEnumerable<string> SafeEnumerate(string root)
        {
            try { return Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories); }
            catch { return new string[0]; }
        }

        private static string[] ReadLines(string file)
        {
            try { return File.ReadAllLines(file, Encoding.UTF8); }
            catch
            {
                try { return File.ReadAllLines(file, Encoding.Default); }
                catch { return new string[0]; }
            }
        }

        private static string RelativePath(string root, string file)
        {
            try
            {
                string rootFull = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, '/', '\\') + Path.DirectorySeparatorChar;
                string full = Path.GetFullPath(file);
                return (full.StartsWith(rootFull, StringComparison.OrdinalIgnoreCase)
                    ? full.Substring(rootFull.Length)
                    : Path.GetFileName(full)).Replace('\\', '/');
            }
            catch { return Path.GetFileName(file) ?? ""; }
        }

        private static void Warn(List<string> warnings, string message)
        {
            if (warnings != null) warnings.Add("UAC derive: " + message);
        }

        private sealed class JournalFileRow
        {
            public string ModifiedTimeUtc = "";
            public string SourcePath = "";
            public long FileSizeBytes;
            public string State = "";
            public string FileId = "";
            public string MachineId = "";
            public string TailBootId = "";
            public string HeaderSize = "";
            public string ArenaSize = "";
            public string ObjectCount = "";
            public string EntryCount = "";
            public string HeadEntrySequence = "";
            public string TailEntrySequence = "";
            public string HeadEntryTimeUtc = "";
            public string TailEntryTimeUtc = "";
            public string CompatibleFeatures = "";
            public string IncompatibleFeatures = "";
            public string ParseStatus = "";
            public string Details = "";
        }

        private sealed class BootSessionRow
        {
            public int BootIndex;
            public string BootId = "";
            public string FirstEntry = "";
            public string FirstEntryUtc = "";
            public string LastEntry = "";
            public string LastEntryUtc = "";
            public string TimeParseStatus = "";
            public string SourcePath = "";
            public int LineNumber;
        }
    }
}
