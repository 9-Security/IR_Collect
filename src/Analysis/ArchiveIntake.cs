using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using IR_Collect.Utils;

namespace IR_Collect.Analysis
{
    public sealed class ArchiveEntryRecord
    {
        public string OriginalPath { get; set; }
        public string ExtractedPath { get; set; }
        public string EntryType { get; set; }
        public string LinkTarget { get; set; }
        public long SizeBytes { get; set; }
        public string Status { get; set; }
    }

    public sealed class ArchiveExtractionResult
    {
        public string Format { get; set; }
        public int ExtractedFiles { get; set; }
        public long ExtractedBytes { get; set; }
        public int IndexedLinks { get; set; }
        public List<ArchiveEntryRecord> Entries { get; private set; }

        public ArchiveExtractionResult()
        {
            Entries = new List<ArchiveEntryRecord>();
        }
    }

    internal sealed class ArchiveIntakeOptions
    {
        public int MaxArchiveEntries { get; set; }
        public long MaxExtractedBytes { get; set; }
        public long MaxSingleEntryBytes { get; set; }
        public long ExpansionRatioMinimumBytes { get; set; }
        public double MaxExpansionRatio { get; set; }
        public long MinimumFreeSpaceBytes { get; set; }
        public long? AvailableFreeSpaceBytesOverride { get; set; }
        public CancellationToken CancellationToken { get; set; }

        public ArchiveIntakeOptions()
        {
            MaxArchiveEntries = 200000;
            MaxExtractedBytes = 750L * 1024 * 1024 * 1024;
            MaxSingleEntryBytes = 300L * 1024 * 1024 * 1024;
            ExpansionRatioMinimumBytes = 1024L * 1024 * 1024;
            MaxExpansionRatio = 1000.0;
            MinimumFreeSpaceBytes = 1024L * 1024 * 1024;
            CancellationToken = CancellationToken.None;
        }
    }

    /// <summary>
    /// Dependency-free archive intake for native cases and UAC output. UAC defaults to tar (usually
    /// gzip-compressed), while the original application accepted ZIP only.
    /// </summary>
    public static class ArchiveIntake
    {
        private const int MaxMetadataEntryBytes = 4 * 1024 * 1024;
        private const int TarBlockSize = 512;

        public static bool IsSupportedArchive(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                return false;

            string lower = path.ToLowerInvariant();
            if (lower.EndsWith(".zip") || lower.EndsWith(".tar") ||
                lower.EndsWith(".tar.gz") || lower.EndsWith(".tgz"))
                return true;

            byte[] magic = ReadMagic(path, 4);
            return IsZipMagic(magic) || IsGzipMagic(magic);
        }

        public static string DetectFormat(string path)
        {
            byte[] magic = ReadMagic(path, 4);
            if (IsZipMagic(magic)) return "zip";
            if (IsGzipMagic(magic)) return "tar.gz";

            string lower = (path ?? "").ToLowerInvariant();
            if (lower.EndsWith(".tar.gz") || lower.EndsWith(".tgz")) return "tar.gz";
            if (lower.EndsWith(".tar")) return "tar";
            if (lower.EndsWith(".zip")) return "zip";
            throw new InvalidDataException("Unsupported evidence archive. Supported formats: ZIP, TAR, TAR.GZ, TGZ.");
        }

        public static ArchiveExtractionResult ExtractSafely(string archivePath, string destination)
        {
            return ExtractSafely(archivePath, destination, new ArchiveIntakeOptions());
        }

        public static ArchiveExtractionResult ExtractSafely(string archivePath, string destination, CancellationToken cancellationToken)
        {
            var options = new ArchiveIntakeOptions();
            options.CancellationToken = cancellationToken;
            return ExtractSafely(archivePath, destination, options);
        }

        internal static ArchiveExtractionResult ExtractSafely(
            string archivePath,
            string destination,
            ArchiveIntakeOptions options)
        {
            if (string.IsNullOrWhiteSpace(archivePath))
                throw new ArgumentException("archivePath is null or empty.", "archivePath");
            if (!File.Exists(archivePath))
                throw new FileNotFoundException("Evidence archive not found.", archivePath);
            if (string.IsNullOrWhiteSpace(destination))
                throw new ArgumentException("destination is null or empty.", "destination");
            if (options == null)
                throw new ArgumentNullException("options");

            ValidateOptions(options);
            options.CancellationToken.ThrowIfCancellationRequested();

            archivePath = Path.GetFullPath(archivePath);
            destination = Path.GetFullPath(destination).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            string parent = Path.GetDirectoryName(destination);
            if (string.IsNullOrEmpty(parent))
                throw new InvalidDataException("Evidence extraction destination must have a parent directory.");
            Directory.CreateDirectory(parent);

            string staging = destination + ".partial-" + Guid.NewGuid().ToString("N");
            string format = DetectFormat(archivePath);
            try
            {
                Directory.CreateDirectory(staging);
                EnsureDiskCapacity(staging, 0, options);

                ArchiveExtractionResult result;
                if (string.Equals(format, "zip", StringComparison.Ordinal))
                    result = ExtractZip(archivePath, staging, options);
                else
                    result = ExtractTar(archivePath, staging, string.Equals(format, "tar.gz", StringComparison.Ordinal), options);

                options.CancellationToken.ThrowIfCancellationRequested();
                result.Format = format;
                if (result.ExtractedFiles <= 0 && result.IndexedLinks <= 0)
                    throw new InvalidDataException("Evidence archive did not contain any supported file entries.");

                WriteEntryIndex(staging, result.Entries);
                options.CancellationToken.ThrowIfCancellationRequested();
                PublishStagingDirectory(staging, destination);
                staging = null;
                return result;
            }
            finally
            {
                TryDeleteDirectory(staging);
            }
        }

        private static ArchiveExtractionResult ExtractZip(
            string archivePath,
            string destination,
            ArchiveIntakeOptions options)
        {
            var result = new ArchiveExtractionResult();
            PreflightZip(archivePath, destination, options);
            int entryCount = 0;
            using (ZipArchive archive = ZipFile.OpenRead(archivePath))
            {
                foreach (ZipArchiveEntry entry in archive.Entries)
                {
                    options.CancellationToken.ThrowIfCancellationRequested();
                    entryCount++;
                    EnsureArchiveLimits(entryCount, result.ExtractedBytes, 0, options);
                    if (string.IsNullOrEmpty(entry.FullName)) continue;

                    string safeRelative;
                    bool renamed;
                    if (!TryMapArchivePath(entry.FullName, destination, out safeRelative, out renamed))
                        throw new InvalidDataException("Archive entry path was rejected: " + entry.FullName);

                    bool isDirectory = entry.FullName.EndsWith("/", StringComparison.Ordinal) ||
                        entry.FullName.EndsWith("\\", StringComparison.Ordinal);
                    bool isSymlink = IsZipSymlink(entry);
                    long size = 0;
                    try { size = entry.Length; } catch { }
                    EnsureArchiveLimits(entryCount, result.ExtractedBytes, size, options);

                    if (isDirectory)
                    {
                        string dirPath = ResolveDestination(destination, safeRelative, ref renamed);
                        Directory.CreateDirectory(dirPath);
                        result.Entries.Add(CreateEntry(entry.FullName, ToRelative(destination, dirPath), "directory", "", 0,
                            renamed ? "renamed-for-windows" : "indexed"));
                        continue;
                    }

                    if (isSymlink)
                    {
                        string target = ReadZipLinkTarget(entry);
                        result.IndexedLinks++;
                        result.Entries.Add(CreateEntry(entry.FullName, safeRelative, "symbolic-link", target, size, "link-indexed"));
                        continue;
                    }

                    string destinationPath = ResolveDestination(destination, safeRelative, ref renamed);
                    destinationPath = MakeUniqueDestination(destinationPath, destination, entry.FullName, ref renamed);
                    string parent = Path.GetDirectoryName(destinationPath);
                    if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);
                    EnsureDiskCapacity(destination, size, options);

                    using (Stream input = entry.Open())
                    using (FileStream output = new FileStream(destinationPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    {
                        long copied = CopyLimited(input, output, options.MaxSingleEntryBytes, options.CancellationToken);
                        if (size > 0 && copied != size)
                            throw new InvalidDataException("ZIP entry size mismatch: " + entry.FullName);
                        result.ExtractedBytes += copied;
                        size = copied;
                    }

                    TrySetLastWriteTime(destinationPath, entry.LastWriteTime.UtcDateTime);
                    result.ExtractedFiles++;
                    result.Entries.Add(CreateEntry(entry.FullName, ToRelative(destination, destinationPath), "file", "", size,
                        renamed ? "renamed-for-windows" : "extracted"));
                }
            }
            return result;
        }

        private static ArchiveExtractionResult ExtractTar(
            string archivePath,
            string destination,
            bool gzip,
            ArchiveIntakeOptions options)
        {
            var result = new ArchiveExtractionResult();
            long compressedBytes = new FileInfo(archivePath).Length;
            using (FileStream file = new FileStream(archivePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (Stream input = gzip ? (Stream)new GZipStream(file, CompressionMode.Decompress) : file)
            {
                byte[] header = new byte[TarBlockSize];
                string pendingLongName = null;
                string pendingLongLink = null;
                var pendingPax = new Dictionary<string, string>(StringComparer.Ordinal);
                var globalPax = new Dictionary<string, string>(StringComparer.Ordinal);
                int entryCount = 0;

                while (ReadBlock(input, header))
                {
                    options.CancellationToken.ThrowIfCancellationRequested();
                    if (IsZeroBlock(header)) break;
                    ValidateTarChecksum(header);
                    entryCount++;
                    EnsureArchiveLimits(entryCount, result.ExtractedBytes, 0, options);

                    string name = ReadTarString(header, 0, 100);
                    string prefix = ReadTarString(header, 345, 155);
                    if (!string.IsNullOrEmpty(prefix)) name = prefix.TrimEnd('/') + "/" + name;
                    char type = (char)header[156];
                    long size = ReadTarNumber(header, 124, 12);
                    long mtime = ReadTarNumber(header, 136, 12);
                    string linkName = ReadTarString(header, 157, 100);
                    EnsureArchiveLimits(entryCount, result.ExtractedBytes, size, options);

                    if (type == 'L' || type == 'K' || type == 'x' || type == 'g')
                    {
                        if (size > MaxMetadataEntryBytes)
                            throw new InvalidDataException("TAR metadata entry exceeds the supported size limit.");
                        byte[] metadata = ReadTarPayload(input, size, options.CancellationToken);
                        SkipTarPadding(input, size, options.CancellationToken);
                        if (type == 'L') pendingLongName = Encoding.UTF8.GetString(metadata).TrimEnd('\0', '\r', '\n');
                        else if (type == 'K') pendingLongLink = Encoding.UTF8.GetString(metadata).TrimEnd('\0', '\r', '\n');
                        else ParsePax(metadata, type == 'g' ? globalPax : pendingPax);
                        continue;
                    }

                    if (!string.IsNullOrEmpty(pendingLongName)) name = pendingLongName;
                    string paxValue;
                    if (TryGetPaxValue(globalPax, pendingPax, "path", out paxValue) && !string.IsNullOrEmpty(paxValue)) name = paxValue;
                    if (!string.IsNullOrEmpty(pendingLongLink)) linkName = pendingLongLink;
                    if (TryGetPaxValue(globalPax, pendingPax, "linkpath", out paxValue) && !string.IsNullOrEmpty(paxValue)) linkName = paxValue;
                    if (TryGetPaxValue(globalPax, pendingPax, "size", out paxValue))
                    {
                        long paxSize;
                        if (long.TryParse(paxValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out paxSize))
                            size = paxSize;
                    }
                    if (TryGetPaxValue(globalPax, pendingPax, "mtime", out paxValue))
                    {
                        double paxTime;
                        if (double.TryParse(paxValue, NumberStyles.Float, CultureInfo.InvariantCulture, out paxTime))
                            mtime = (long)Math.Floor(paxTime);
                    }

                    pendingLongName = null;
                    pendingLongLink = null;
                    pendingPax.Clear();
                    EnsureArchiveLimits(entryCount, result.ExtractedBytes, size, options);
                    if (gzip && (type == '\0' || type == '0' || type == '7'))
                        EnsureExpansionRatio(result.ExtractedBytes + size, compressedBytes, options);

                    string safeRelative;
                    bool renamed;
                    if (!TryMapArchivePath(name, destination, out safeRelative, out renamed))
                        throw new InvalidDataException("Archive entry path was rejected: " + name);

                    bool isRegular = type == '\0' || type == '0' || type == '7';
                    bool isDirectory = type == '5';
                    bool isLink = type == '1' || type == '2';

                    if (isDirectory)
                    {
                        string dirPath = ResolveDestination(destination, safeRelative, ref renamed);
                        Directory.CreateDirectory(dirPath);
                        result.Entries.Add(CreateEntry(name, ToRelative(destination, dirPath), "directory", "", 0,
                            renamed ? "renamed-for-windows" : "indexed"));
                        SkipExactly(input, size, options.CancellationToken);
                    }
                    else if (isLink)
                    {
                        result.IndexedLinks++;
                        result.Entries.Add(CreateEntry(name, safeRelative, type == '2' ? "symbolic-link" : "hard-link",
                            linkName, size, "link-indexed"));
                        SkipExactly(input, size, options.CancellationToken);
                    }
                    else if (isRegular)
                    {
                        string destinationPath = ResolveDestination(destination, safeRelative, ref renamed);
                        destinationPath = MakeUniqueDestination(destinationPath, destination, name, ref renamed);
                        string parent = Path.GetDirectoryName(destinationPath);
                        if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);
                        EnsureDiskCapacity(destination, size, options);

                        using (FileStream output = new FileStream(destinationPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                            CopyExactly(input, output, size, options);
                        result.ExtractedBytes += size;
                        result.ExtractedFiles++;
                        TrySetUnixLastWriteTime(destinationPath, mtime);
                        result.Entries.Add(CreateEntry(name, ToRelative(destination, destinationPath), "file", "", size,
                            renamed ? "renamed-for-windows" : "extracted"));
                    }
                    else
                    {
                        SkipExactly(input, size, options.CancellationToken);
                        result.Entries.Add(CreateEntry(name, safeRelative, "special-" + type, linkName, size, "metadata-only"));
                    }

                    SkipTarPadding(input, size, options.CancellationToken);
                }
            }
            return result;
        }

        private static void WriteEntryIndex(string destination, List<ArchiveEntryRecord> entries)
        {
            string path = Path.Combine(destination, ArtifactNames.UacArchiveEntriesCsv);
            using (var sw = new StreamWriter(path, false, new UTF8Encoding(false)))
            {
                sw.WriteLine("OriginalPath,ExtractedPath,EntryType,LinkTarget,SizeBytes,Status");
                foreach (ArchiveEntryRecord entry in entries)
                {
                    sw.WriteLine(string.Join(",", new string[] {
                        CsvUtils.EscapeField(entry.OriginalPath ?? ""),
                        CsvUtils.EscapeField(entry.ExtractedPath ?? ""),
                        CsvUtils.EscapeField(entry.EntryType ?? ""),
                        CsvUtils.EscapeField(entry.LinkTarget ?? ""),
                        entry.SizeBytes.ToString(CultureInfo.InvariantCulture),
                        CsvUtils.EscapeField(entry.Status ?? "")
                    }));
                }
            }
        }

        private static ArchiveEntryRecord CreateEntry(string original, string extracted, string type, string target, long size, string status)
        {
            return new ArchiveEntryRecord
            {
                OriginalPath = (original ?? "").Replace('\\', '/'),
                ExtractedPath = (extracted ?? "").Replace('\\', '/'),
                EntryType = type ?? "",
                LinkTarget = target ?? "",
                SizeBytes = size,
                Status = status ?? ""
            };
        }

        private static bool TryMapArchivePath(string original, string destination, out string relative, out bool renamed)
        {
            relative = "";
            renamed = false;
            if (string.IsNullOrWhiteSpace(original)) return false;
            string normalized = original.Replace('\\', '/');
            if (normalized.StartsWith("/", StringComparison.Ordinal) ||
                normalized.StartsWith("//", StringComparison.Ordinal) ||
                (normalized.Length >= 2 && char.IsLetter(normalized[0]) && normalized[1] == ':'))
                return false;

            string[] parts = normalized.Split(new char[] { '/' }, StringSplitOptions.RemoveEmptyEntries);
            var safeParts = new List<string>();
            foreach (string part in parts)
            {
                if (part == "..") return false;
                if (part == ".") continue;
                string safe = SanitizeWindowsComponent(part);
                if (!string.Equals(safe, part, StringComparison.Ordinal)) renamed = true;
                safeParts.Add(safe);
            }
            if (safeParts.Count == 0) return false;

            relative = string.Join(Path.DirectorySeparatorChar.ToString(), safeParts.ToArray());
            string candidate = Path.Combine(destination, relative);
            if (candidate.Length > 240)
            {
                string fileName = safeParts[safeParts.Count - 1];
                relative = Path.Combine("__longpath__", HashText(normalized).Substring(0, 24), fileName);
                renamed = true;
            }
            return true;
        }

        private static string SanitizeWindowsComponent(string value)
        {
            if (string.IsNullOrEmpty(value)) return "%0000";
            var sb = new StringBuilder();
            for (int i = 0; i < value.Length; i++)
            {
                char c = value[i];
                bool trailingDotOrSpace = i == value.Length - 1 && (c == '.' || c == ' ');
                if (c < 32 || c == '<' || c == '>' || c == ':' || c == '"' || c == '/' ||
                    c == '\\' || c == '|' || c == '?' || c == '*' || c == '%' || trailingDotOrSpace)
                    sb.Append('%').Append(((int)c).ToString("X4", CultureInfo.InvariantCulture));
                else
                    sb.Append(c);
            }

            string safe = sb.ToString();
            string stem = safe;
            int dot = stem.IndexOf('.');
            if (dot >= 0) stem = stem.Substring(0, dot);
            string[] reserved = { "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
                                  "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9" };
            if (reserved.Any(x => string.Equals(x, stem, StringComparison.OrdinalIgnoreCase)))
                safe = "%005F" + safe;
            if (safe.Length > 120)
                safe = safe.Substring(0, 80) + "~" + HashText(value).Substring(0, 20);
            return safe;
        }

        private static string ResolveDestination(string destination, string relative, ref bool renamed)
        {
            string root = Path.GetFullPath(destination).TrimEnd(Path.DirectorySeparatorChar, '/', '\\') + Path.DirectorySeparatorChar;
            string full = Path.GetFullPath(Path.Combine(destination, relative));
            if (!full.StartsWith(root, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Archive entry escaped the extraction root.");
            return full;
        }

        private static string MakeUniqueDestination(string destinationPath, string root, string original, ref bool renamed)
        {
            if (!File.Exists(destinationPath) && !Directory.Exists(destinationPath))
                return destinationPath;

            string dir = Path.GetDirectoryName(destinationPath) ?? root;
            string name = Path.GetFileNameWithoutExtension(destinationPath);
            string ext = Path.GetExtension(destinationPath);
            string suffix = "~dup-" + HashText(original + "|" + destinationPath).Substring(0, 12);
            string candidate = Path.Combine(dir, name + suffix + ext);
            int counter = 1;
            while (File.Exists(candidate) || Directory.Exists(candidate))
            {
                candidate = Path.Combine(dir, name + suffix + "-" + counter.ToString(CultureInfo.InvariantCulture) + ext);
                counter++;
            }
            renamed = true;
            return candidate;
        }

        private static string ToRelative(string root, string path)
        {
            string rootFull = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, '/', '\\') + Path.DirectorySeparatorChar;
            string full = Path.GetFullPath(path);
            return full.StartsWith(rootFull, StringComparison.OrdinalIgnoreCase) ? full.Substring(rootFull.Length) : Path.GetFileName(full);
        }

        private static bool IsZipSymlink(ZipArchiveEntry entry)
        {
            try
            {
                int unixMode = (entry.ExternalAttributes >> 16) & 0xF000;
                return unixMode == 0xA000;
            }
            catch { return false; }
        }

        private static string ReadZipLinkTarget(ZipArchiveEntry entry)
        {
            try
            {
                if (entry.Length <= 0 || entry.Length > 65536) return "";
                using (StreamReader sr = new StreamReader(entry.Open(), Encoding.UTF8, true))
                    return sr.ReadToEnd().TrimEnd('\0', '\r', '\n');
            }
            catch { return ""; }
        }

        private static long CopyLimited(Stream input, Stream output, long limit, CancellationToken cancellationToken)
        {
            byte[] buffer = new byte[81920];
            long total = 0;
            int read;
            while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                total += read;
                if (total > limit) throw new InvalidDataException("Archive entry exceeded the supported size limit.");
                output.Write(buffer, 0, read);
            }
            return total;
        }

        private static void CopyExactly(Stream input, Stream output, long count, ArchiveIntakeOptions options)
        {
            if (count < 0 || count > options.MaxSingleEntryBytes)
                throw new InvalidDataException("Archive entry size is outside the supported range.");
            byte[] buffer = new byte[81920];
            long remaining = count;
            while (remaining > 0)
            {
                options.CancellationToken.ThrowIfCancellationRequested();
                int wanted = (int)Math.Min((long)buffer.Length, remaining);
                int read = input.Read(buffer, 0, wanted);
                if (read <= 0) throw new EndOfStreamException("Unexpected end of TAR entry.");
                output.Write(buffer, 0, read);
                remaining -= read;
            }
        }

        private static void SkipExactly(Stream input, long count, CancellationToken cancellationToken)
        {
            if (count <= 0) return;
            byte[] buffer = new byte[81920];
            long remaining = count;
            while (remaining > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                int wanted = (int)Math.Min((long)buffer.Length, remaining);
                int read = input.Read(buffer, 0, wanted);
                if (read <= 0) throw new EndOfStreamException("Unexpected end of TAR stream.");
                remaining -= read;
            }
        }

        private static bool ReadBlock(Stream input, byte[] block)
        {
            int offset = 0;
            while (offset < block.Length)
            {
                int read = input.Read(block, offset, block.Length - offset);
                if (read <= 0)
                {
                    if (offset == 0) return false;
                    throw new EndOfStreamException("Truncated TAR header.");
                }
                offset += read;
            }
            return true;
        }

        private static byte[] ReadTarPayload(Stream input, long size, CancellationToken cancellationToken)
        {
            byte[] data = new byte[(int)size];
            int offset = 0;
            while (offset < data.Length)
            {
                cancellationToken.ThrowIfCancellationRequested();
                int read = input.Read(data, offset, data.Length - offset);
                if (read <= 0) throw new EndOfStreamException("Truncated TAR metadata entry.");
                offset += read;
            }
            return data;
        }

        private static void SkipTarPadding(Stream input, long size, CancellationToken cancellationToken)
        {
            long remainder = size % TarBlockSize;
            if (remainder != 0) SkipExactly(input, TarBlockSize - remainder, cancellationToken);
        }

        private static string ReadTarString(byte[] buffer, int offset, int length)
        {
            int end = offset;
            int max = Math.Min(buffer.Length, offset + length);
            while (end < max && buffer[end] != 0) end++;
            return Encoding.UTF8.GetString(buffer, offset, end - offset).Trim();
        }

        private static long ReadTarNumber(byte[] buffer, int offset, int length)
        {
            if ((buffer[offset] & 0x80) != 0)
            {
                long value = buffer[offset] & 0x7f;
                for (int i = 1; i < length; i++) value = (value << 8) | buffer[offset + i];
                return value;
            }

            string text = Encoding.ASCII.GetString(buffer, offset, length).Trim('\0', ' ');
            if (text.Length == 0) return 0;
            long valueOctal = 0;
            foreach (char c in text)
            {
                if (c < '0' || c > '7') break;
                checked { valueOctal = (valueOctal * 8) + (c - '0'); }
            }
            return valueOctal;
        }

        private static void ValidateTarChecksum(byte[] header)
        {
            long expected = ReadTarNumber(header, 148, 8);
            long actual = 0;
            for (int i = 0; i < header.Length; i++)
                actual += (i >= 148 && i < 156) ? 32 : header[i];
            if (expected != 0 && expected != actual)
                throw new InvalidDataException("TAR header checksum mismatch.");
        }

        private static bool IsZeroBlock(byte[] block)
        {
            for (int i = 0; i < block.Length; i++)
                if (block[i] != 0) return false;
            return true;
        }

        private static void ParsePax(byte[] data, Dictionary<string, string> values)
        {
            if (data == null || data.Length == 0 || values == null) return;
            int offset = 0;
            while (offset < data.Length)
            {
                int space = offset;
                while (space < data.Length && data[space] != (byte)' ') space++;
                if (space <= offset) break;
                int length;
                string lengthText = Encoding.ASCII.GetString(data, offset, space - offset);
                if (!int.TryParse(lengthText, NumberStyles.Integer, CultureInfo.InvariantCulture, out length) || length <= 0)
                    break;
                int recordEnd = Math.Min(data.Length, offset + length);
                int valueLength = recordEnd - space - 1;
                if (valueLength <= 0) break;
                string record = Encoding.UTF8.GetString(data, space + 1, valueLength).TrimEnd('\0', '\r', '\n');
                int equals = record.IndexOf('=');
                if (equals > 0) values[record.Substring(0, equals)] = record.Substring(equals + 1);
                offset += length;
            }
        }

        private static bool TryGetPaxValue(Dictionary<string, string> globalValues, Dictionary<string, string> entryValues, string key, out string value)
        {
            value = null;
            if (entryValues != null && entryValues.TryGetValue(key, out value))
                return true;
            return globalValues != null && globalValues.TryGetValue(key, out value);
        }

        private static void EnsureArchiveLimits(
            int entryCount,
            long extractedBytes,
            long nextSize,
            ArchiveIntakeOptions options)
        {
            if (entryCount > options.MaxArchiveEntries)
                throw new InvalidDataException("Archive entry count exceeded the safety limit of " + options.MaxArchiveEntries + ".");
            if (nextSize < 0 || nextSize > options.MaxSingleEntryBytes)
                throw new InvalidDataException("Archive entry size exceeded the safety limit.");
            if (extractedBytes > options.MaxExtractedBytes - nextSize)
                throw new InvalidDataException("Archive expanded size exceeded the safety limit.");
        }

        private static void PreflightZip(string archivePath, string destination, ArchiveIntakeOptions options)
        {
            int entryCount = 0;
            long expandedBytes = 0;
            long compressedBytes = 0;
            using (ZipArchive archive = ZipFile.OpenRead(archivePath))
            {
                foreach (ZipArchiveEntry entry in archive.Entries)
                {
                    options.CancellationToken.ThrowIfCancellationRequested();
                    entryCount++;
                    long size = entry.Length;
                    EnsureArchiveLimits(entryCount, expandedBytes, size, options);

                    bool isDirectory = entry.FullName.EndsWith("/", StringComparison.Ordinal) ||
                        entry.FullName.EndsWith("\\", StringComparison.Ordinal);
                    if (!isDirectory && !IsZipSymlink(entry))
                    {
                        expandedBytes += size;
                        compressedBytes += entry.CompressedLength;
                        EnsureExpansionRatio(expandedBytes, compressedBytes, options);
                    }
                }
            }

            EnsureDiskCapacity(destination, expandedBytes, options);
        }

        private static void EnsureExpansionRatio(
            long expandedBytes,
            long compressedBytes,
            ArchiveIntakeOptions options)
        {
            if (expandedBytes < options.ExpansionRatioMinimumBytes)
                return;
            if (compressedBytes <= 0 ||
                ((double)expandedBytes / (double)compressedBytes) > options.MaxExpansionRatio)
                throw new InvalidDataException("Archive expansion ratio exceeded the safety limit.");
        }

        private static void EnsureDiskCapacity(
            string destination,
            long nextWriteBytes,
            ArchiveIntakeOptions options)
        {
            options.CancellationToken.ThrowIfCancellationRequested();
            long available;
            if (options.AvailableFreeSpaceBytesOverride.HasValue)
            {
                available = options.AvailableFreeSpaceBytesOverride.Value;
            }
            else
            {
                string root = Path.GetPathRoot(Path.GetFullPath(destination));
                if (string.IsNullOrEmpty(root))
                    throw new IOException("Unable to resolve the destination volume for archive extraction.");
                available = new DriveInfo(root).AvailableFreeSpace;
            }

            long required = nextWriteBytes;
            if (required > long.MaxValue - options.MinimumFreeSpaceBytes)
                required = long.MaxValue;
            else
                required += options.MinimumFreeSpaceBytes;
            if (available < required)
                throw new IOException(
                    "Insufficient free space for evidence extraction. Required " +
                    required.ToString(CultureInfo.InvariantCulture) + " bytes; available " +
                    available.ToString(CultureInfo.InvariantCulture) + " bytes.");
        }

        private static void ValidateOptions(ArchiveIntakeOptions options)
        {
            if (options.MaxArchiveEntries <= 0)
                throw new ArgumentOutOfRangeException("options.MaxArchiveEntries");
            if (options.MaxExtractedBytes <= 0 || options.MaxSingleEntryBytes <= 0)
                throw new ArgumentOutOfRangeException("options", "Archive byte limits must be positive.");
            if (options.MaxSingleEntryBytes > options.MaxExtractedBytes)
                throw new ArgumentException("The single-entry limit cannot exceed the total extraction limit.", "options");
            if (options.ExpansionRatioMinimumBytes < 0 || options.MaxExpansionRatio <= 1.0)
                throw new ArgumentOutOfRangeException("options", "Archive expansion-ratio limits are invalid.");
            if (options.MinimumFreeSpaceBytes < 0)
                throw new ArgumentOutOfRangeException("options.MinimumFreeSpaceBytes");
        }

        private static void PublishStagingDirectory(string staging, string destination)
        {
            if (Directory.Exists(destination))
            {
                if (Directory.EnumerateFileSystemEntries(destination).Any())
                    throw new IOException("Evidence extraction destination is not empty.");
                Directory.Delete(destination, false);
            }
            else if (File.Exists(destination))
            {
                throw new IOException("Evidence extraction destination is an existing file.");
            }

            Directory.Move(staging, destination);
        }

        private static void TryDeleteDirectory(string path)
        {
            if (string.IsNullOrEmpty(path)) return;
            try
            {
                if (Directory.Exists(path)) Directory.Delete(path, true);
            }
            catch (Exception ex)
            {
                Logger.Warning("ArchiveIntake staging cleanup: " + (ex.Message ?? ""));
            }
        }

        private static byte[] ReadMagic(string path, int count)
        {
            try
            {
                byte[] bytes = new byte[count];
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    int read = fs.Read(bytes, 0, bytes.Length);
                    if (read == bytes.Length) return bytes;
                    return bytes.Take(read).ToArray();
                }
            }
            catch { return new byte[0]; }
        }

        private static bool IsZipMagic(byte[] magic)
        {
            return magic != null && magic.Length >= 4 && magic[0] == 0x50 && magic[1] == 0x4b &&
                ((magic[2] == 0x03 && magic[3] == 0x04) || (magic[2] == 0x05 && magic[3] == 0x06) ||
                 (magic[2] == 0x07 && magic[3] == 0x08));
        }

        private static bool IsGzipMagic(byte[] magic)
        {
            return magic != null && magic.Length >= 2 && magic[0] == 0x1f && magic[1] == 0x8b;
        }

        private static string HashText(string value)
        {
            using (SHA256 sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(value ?? ""));
                var sb = new StringBuilder(hash.Length * 2);
                for (int i = 0; i < hash.Length; i++) sb.Append(hash[i].ToString("x2", CultureInfo.InvariantCulture));
                return sb.ToString();
            }
        }

        private static void TrySetLastWriteTime(string path, DateTime utc)
        {
            try
            {
                if (utc.Year >= 1970 && utc.Year <= 3000) File.SetLastWriteTimeUtc(path, utc);
            }
            catch { }
        }

        private static void TrySetUnixLastWriteTime(string path, long seconds)
        {
            if (seconds <= 0) return;
            try
            {
                DateTime utc = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(seconds);
                TrySetLastWriteTime(path, utc);
            }
            catch { }
        }
    }
}
