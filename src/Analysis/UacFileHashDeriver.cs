using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using IR_Collect.Utils;

namespace IR_Collect.Analysis
{
    /// <summary>
    /// Bounded intake for UAC hash collector output. Supports the common GNU,
    /// BSD, shasum, csum, digest, and OpenSSL text envelopes selected by UAC.
    /// </summary>
    public static class UacFileHashDeriver
    {
        private const long MaxSourceFileBytes = 512L * 1024 * 1024;
        private const int MaxSourceFiles = 64;
        private const int MaxLineCharacters = 64 * 1024;
        private const int MaxRows = 250000;
        private const int MaxPathCharacters = 32768;

        public static void DeriveInto(string folder, List<string> warnings)
        {
            DeriveInto(folder, folder, warnings);
        }

        public static void DeriveInto(string sourceRoot, string outputRoot,
            List<string> warnings)
        {
            if (string.IsNullOrWhiteSpace(sourceRoot) ||
                !Directory.Exists(sourceRoot) ||
                string.IsNullOrWhiteSpace(outputRoot))
                return;

            Directory.CreateDirectory(outputRoot);
            string output = Path.Combine(outputRoot, ArtifactNames.UacFileHashesCsv);
            if (File.Exists(output))
                return;

            List<string> files = EnumerateSourceFiles(sourceRoot)
                .Take(MaxSourceFiles + 1)
                .ToList();
            if (files.Count > MaxSourceFiles)
            {
                files.RemoveAt(files.Count - 1);
                Warn(warnings, "file-hash sources were capped at " +
                    MaxSourceFiles.ToString(CultureInfo.InvariantCulture) +
                    " files.");
            }

            var rows = new List<FileHashRow>();
            bool hitCap = false;
            for (int i = 0; i < files.Count && !hitCap; i++)
            {
                long size;
                try { size = new FileInfo(files[i]).Length; }
                catch { continue; }
                if (size <= 0)
                    continue;
                if (size > MaxSourceFileBytes)
                {
                    Warn(warnings, "file-hash source exceeded the " +
                        MaxSourceFileBytes.ToString(CultureInfo.InvariantCulture) +
                        "-byte parser limit and remained raw: " +
                        ToRelativeSourcePath(sourceRoot, files[i]) + ".");
                    continue;
                }

                int skipped;
                int oversized;
                try
                {
                    hitCap = ParseFile(sourceRoot, files[i], rows,
                        out skipped, out oversized);
                }
                catch (Exception ex)
                {
                    Warn(warnings, "file-hash source could not be parsed: " +
                        ToRelativeSourcePath(sourceRoot, files[i]) + " (" +
                        (ex.Message ?? "") + ")");
                    continue;
                }

                if (skipped > 0 || oversized > 0)
                {
                    Warn(warnings, "file-hash source retained " +
                        (skipped + oversized).ToString(CultureInfo.InvariantCulture) +
                        " unsupported, mismatched, or oversized line(s) as raw: " +
                        ToRelativeSourcePath(sourceRoot, files[i]) + ".");
                }
            }

            if (rows.Count == 0)
                return;

            AtomicFile.WriteText(output, new UTF8Encoding(false),
                delegate(StreamWriter sw)
                {
                    sw.WriteLine("Algorithm,Hash,Path,SourceKind,SourcePath,LineNumber,InputFormat");
                    for (int i = 0; i < rows.Count; i++)
                    {
                        FileHashRow row = rows[i];
                        sw.WriteLine(string.Join(",", new string[]
                        {
                            CsvUtils.EscapeField(row.Algorithm),
                            CsvUtils.EscapeField(row.Hash),
                            CsvUtils.EscapeField(row.Path),
                            CsvUtils.EscapeField(row.SourceKind),
                            CsvUtils.EscapeField(row.SourcePath),
                            row.LineNumber.ToString(CultureInfo.InvariantCulture),
                            CsvUtils.EscapeField(row.InputFormat)
                        }));
                    }
                });

            if (hitCap)
                Warn(warnings, "file-hash rows were capped at " +
                    MaxRows.ToString(CultureInfo.InvariantCulture) +
                    " entries.");
            Logger.Info("Derived " + ArtifactNames.UacFileHashesCsv + " (" +
                rows.Count.ToString(CultureInfo.InvariantCulture) + " rows).");
        }

        public static bool IsSupportedSourceRelativePath(string relativePath)
        {
            string path = "/" + (relativePath ?? "").Replace('\\', '/')
                .TrimStart('/').ToLowerInvariant();
            string name = Path.GetFileName(path) ?? "";
            string algorithm = GetAlgorithmFromFileName(name);
            if (algorithm.Length == 0)
                return false;

            return path.IndexOf("/hash_executables/", StringComparison.Ordinal) >= 0 &&
                    name == "hash_executables." + algorithm ||
                path.IndexOf("/live_response/process/", StringComparison.Ordinal) >= 0 &&
                    name == "hash_running_processes." + algorithm;
        }

        private static IEnumerable<string> EnumerateSourceFiles(string root)
        {
            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories); }
            catch { yield break; }

            foreach (string file in files.OrderBy(x => x,
                StringComparer.OrdinalIgnoreCase))
            {
                if (IsSupportedSourceRelativePath(
                    ToRelativeSourcePath(root, file)))
                    yield return file;
            }
        }

        private static bool ParseFile(string root, string file,
            List<FileHashRow> rows, out int skipped, out int oversized)
        {
            skipped = 0;
            oversized = 0;
            string sourcePath = ToRelativeSourcePath(root, file);
            string algorithm = GetAlgorithmFromFileName(file);
            string sourceKind = sourcePath.Replace('\\', '/').IndexOf(
                "/live_response/process/", StringComparison.OrdinalIgnoreCase) >= 0 ||
                sourcePath.Replace('\\', '/').StartsWith(
                    "live_response/process/", StringComparison.OrdinalIgnoreCase)
                ? "running-process"
                : "executable-inventory";

            using (var reader = new StreamReader(new FileStream(file,
                FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete), Encoding.UTF8, true))
            using (var bounded = new BoundedLineReader(reader,
                MaxLineCharacters))
            {
                string line;
                bool lineOversized;
                int lineNumber = 0;
                while ((line = bounded.ReadLine(out lineOversized)) != null)
                {
                    lineNumber++;
                    if (lineOversized)
                    {
                        oversized++;
                        continue;
                    }

                    string hash;
                    string path;
                    string inputFormat;
                    if (!TryParseLine(line, algorithm, out hash, out path,
                        out inputFormat))
                    {
                        if (!string.IsNullOrWhiteSpace(line))
                            skipped++;
                        continue;
                    }

                    rows.Add(new FileHashRow
                    {
                        Algorithm = algorithm,
                        Hash = hash.ToLowerInvariant(),
                        Path = path,
                        SourceKind = sourceKind,
                        SourcePath = sourcePath,
                        LineNumber = lineNumber,
                        InputFormat = inputFormat
                    });
                    if (rows.Count >= MaxRows)
                        return true;
                }
            }
            return false;
        }

        internal static bool TryParseLine(string line, string algorithm,
            out string hash, out string path, out string inputFormat)
        {
            hash = "";
            path = "";
            inputFormat = "";
            string value = (line ?? "").Trim('\uFEFF', '\r', '\n');
            int hashLength = GetHashLength(algorithm);
            if (value.Length == 0 || hashLength == 0)
                return false;

            bool escaped = value[0] == '\\';
            string standard = escaped ? value.Substring(1) : value;
            if (standard.Length > hashLength &&
                IsHex(standard, 0, hashLength) &&
                char.IsWhiteSpace(standard[hashLength]))
            {
                int pathStart;
                if (standard[hashLength] == ' ' &&
                    hashLength + 1 < standard.Length &&
                    (standard[hashLength + 1] == ' ' ||
                     standard[hashLength + 1] == '*'))
                {
                    pathStart = hashLength + 2;
                }
                else
                {
                    pathStart = hashLength;
                    while (pathStart < standard.Length &&
                        char.IsWhiteSpace(standard[pathStart]))
                        pathStart++;
                }
                if (pathStart < standard.Length)
                {
                    hash = standard.Substring(0, hashLength);
                    path = standard.Substring(pathStart);
                    inputFormat = escaped ?
                        "checksum-escaped-path" : "checksum-path";
                    if (escaped)
                        path = DecodeCoreutilsEscapes(path);
                    return IsUsablePath(path);
                }
            }

            int equals = value.LastIndexOf('=');
            if (equals <= 0)
                return false;
            string digest = value.Substring(equals + 1).Trim();
            if (digest.Length != hashLength ||
                !IsHex(digest, 0, digest.Length))
                return false;

            string envelope = value.Substring(0, equals).TrimEnd();
            int open = envelope.IndexOf('(');
            int close = envelope.LastIndexOf(')');
            if (open <= 0 || close <= open || close != envelope.Length - 1)
                return false;

            string label = NormalizeAlgorithmLabel(
                envelope.Substring(0, open));
            if (!string.Equals(label, algorithm,
                StringComparison.OrdinalIgnoreCase))
                return false;

            string candidatePath = envelope.Substring(open + 1,
                close - open - 1);
            if (!IsUsablePath(candidatePath))
                return false;

            hash = digest;
            path = candidatePath;
            inputFormat = "named-digest";
            return true;
        }

        private static bool IsUsablePath(string path)
        {
            return !string.IsNullOrEmpty(path) &&
                path.Length <= MaxPathCharacters &&
                path.IndexOf('\0') < 0;
        }

        private static string DecodeCoreutilsEscapes(string path)
        {
            var output = new StringBuilder(path.Length);
            for (int i = 0; i < path.Length; i++)
            {
                if (path[i] == '\\' && i + 1 < path.Length &&
                    path[i + 1] == '\\')
                {
                    output.Append('\\');
                    i++;
                }
                else
                {
                    // Keep \n and \r visible so one source record remains one CSV row.
                    output.Append(path[i]);
                }
            }
            return output.ToString();
        }

        private static string GetAlgorithmFromFileName(string path)
        {
            string extension = (Path.GetExtension(path) ?? "")
                .TrimStart('.').ToLowerInvariant();
            return extension == "md5" || extension == "sha1" ||
                extension == "sha256" ? extension : "";
        }

        private static string NormalizeAlgorithmLabel(string label)
        {
            string normalized = (label ?? "").Trim().ToLowerInvariant()
                .Replace("-", "").Replace("_", "").Replace(" ", "");
            if (normalized == "sha2256")
                return "sha256";
            return normalized;
        }

        private static int GetHashLength(string algorithm)
        {
            if (string.Equals(algorithm, "md5",
                StringComparison.OrdinalIgnoreCase)) return 32;
            if (string.Equals(algorithm, "sha1",
                StringComparison.OrdinalIgnoreCase)) return 40;
            if (string.Equals(algorithm, "sha256",
                StringComparison.OrdinalIgnoreCase)) return 64;
            return 0;
        }

        private static bool IsHex(string value, int offset, int length)
        {
            if (string.IsNullOrEmpty(value) || offset < 0 || length <= 0 ||
                offset + length > value.Length)
                return false;
            for (int i = offset; i < offset + length; i++)
            {
                char c = value[i];
                if (!((c >= '0' && c <= '9') ||
                    (c >= 'a' && c <= 'f') ||
                    (c >= 'A' && c <= 'F')))
                    return false;
            }
            return true;
        }

        private static string ToRelativeSourcePath(string root, string file)
        {
            try
            {
                string rootFull = Path.GetFullPath(root).TrimEnd(
                    Path.DirectorySeparatorChar,
                    Path.AltDirectorySeparatorChar) +
                    Path.DirectorySeparatorChar;
                string fileFull = Path.GetFullPath(file);
                if (fileFull.StartsWith(rootFull,
                    StringComparison.OrdinalIgnoreCase))
                    return fileFull.Substring(rootFull.Length)
                        .Replace('\\', '/');
            }
            catch
            {
            }
            return (file ?? "").Replace('\\', '/');
        }

        private static void Warn(List<string> warnings, string message)
        {
            if (warnings != null)
                warnings.Add("UAC derive: " + (message ?? ""));
        }

        private sealed class BoundedLineReader : IDisposable
        {
            private readonly TextReader _reader;
            private readonly int _maxLineCharacters;

            public BoundedLineReader(TextReader reader, int maxLineCharacters)
            {
                _reader = reader;
                _maxLineCharacters = maxLineCharacters;
            }

            public string ReadLine(out bool oversized)
            {
                oversized = false;
                var value = new StringBuilder();
                bool sawCharacter = false;
                while (true)
                {
                    int next = _reader.Read();
                    if (next < 0)
                        return sawCharacter ? value.ToString() : null;
                    sawCharacter = true;
                    char c = (char)next;
                    if (c == '\n')
                        return value.ToString();
                    if (c == '\r')
                        continue;
                    if (value.Length < _maxLineCharacters)
                        value.Append(c);
                    else
                        oversized = true;
                }
            }

            public void Dispose()
            {
            }
        }

        private sealed class FileHashRow
        {
            public string Algorithm = "";
            public string Hash = "";
            public string Path = "";
            public string SourceKind = "";
            public string SourcePath = "";
            public int LineNumber;
            public string InputFormat = "";
        }
    }
}
