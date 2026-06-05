using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using IR_Collect.Utils;

namespace IR_Collect.Analysis.Correlation.Normalizers
{
    public static class UsnNormalizer
    {
        public const string SourceName = "USN";

        private sealed class UsnData
        {
            public List<string> Headers = new List<string>();
            public List<string[]> Rows = new List<string[]>();
            public int HeaderLineNumber;
        }

        public static List<Fact> ToFacts(string usnJournalCsvPath, int limit)
        {
            var list = new List<Fact>();
            if (string.IsNullOrEmpty(usnJournalCsvPath) || !File.Exists(usnJournalCsvPath)) return list;

            UsnData data;
            if (!TryReadUsnData(usnJournalCsvPath, out data) || data == null || data.Rows == null || data.Rows.Count == 0)
                return list;

            int cappedLimit = limit <= 0 ? 50000 : Math.Min(limit, 200000);
            int timeIndex = FindHeaderIndex(data.Headers, "Time stamp", "Timestamp", "Time");
            int reasonIndex = FindHeaderIndex(data.Headers, "Reason");
            int fileNameIndex = FindHeaderIndex(data.Headers, "File name", "Filename", "Name");
            int pathIndex = FindHeaderIndex(data.Headers, "Path", "Full path", "FullPath");
            int attributesIndex = FindHeaderIndex(data.Headers, "File attributes", "Attributes");
            int fileRefIndex = FindHeaderIndex(data.Headers, "File reference number", "File reference", "FRN");
            int parentFileRefIndex = FindHeaderIndex(data.Headers, "Parent file reference number", "Parent file reference", "Parent FRN");

            for (int i = 0; i < data.Rows.Count && list.Count < cappedLimit; i++)
            {
                string[] row = data.Rows[i];
                if (row == null || row.Length == 0) continue;

                string timeText = GetCell(row, timeIndex);
                DateTime time = ParseUsnTime(timeText);
                string reason = CollapseSingleLine(GetCell(row, reasonIndex));
                string fileName = CollapseSingleLine(GetCell(row, fileNameIndex));
                string fullPath = CollapseSingleLine(GetCell(row, pathIndex));
                string attributes = CollapseSingleLine(GetCell(row, attributesIndex));
                string fileRef = CollapseSingleLine(GetCell(row, fileRefIndex));
                string parentFileRef = CollapseSingleLine(GetCell(row, parentFileRefIndex));

                string id = "USN_" + i;
                var fact = new Fact(id, time, SourceName, MapReasonToAction(reason));
                FactTimeMetadata.Apply(
                    fact,
                    FactTimeMetadata.HasUsableTime(time) ? FactTimeMetadata.EventTimeKind : FactTimeMetadata.UnknownTimeKind,
                    FactTimeMetadata.HasUsableTime(time) ? FactTimeMetadata.HighConfidence : FactTimeMetadata.LowConfidence);
                fact.SourceFile = ArtifactNames.UsnJournalCsv;
                fact.RawRef = ArtifactNames.UsnJournalCsv + ":" + (data.HeaderLineNumber + i + 2);
                fact.ParseLevel = FactProvenanceMetadata.MetadataDerivedParseLevel;
                fact.Details = BuildDetails(fullPath, fileName, reason, attributes, fileRef, parentFileRef);
                if (string.IsNullOrWhiteSpace(fullPath) && !string.IsNullOrWhiteSpace(fileName))
                {
                    fact.ParserNote = "USN row did not include a full path; this fact is linked at FileName level.";
                    fact.FallbackUsed = true;
                }

                if (!string.IsNullOrWhiteSpace(fullPath))
                    fact.AddEntity("Path", fullPath.Trim());
                if (!string.IsNullOrWhiteSpace(fileName))
                    fact.AddEntity("FileName", fileName.Trim());
                if (!string.IsNullOrWhiteSpace(reason))
                    fact.AddEntity("UsnReason", reason.Trim());
                if (!string.IsNullOrWhiteSpace(fileRef))
                    fact.AddEntity("FileReference", fileRef.Trim());

                list.Add(fact);
            }

            return list;
        }

        private static bool TryReadUsnData(string csvPath, out UsnData data)
        {
            data = null;
            try
            {
                string[] lines;
                try { lines = File.ReadAllLines(csvPath, Encoding.UTF8); }
                catch { lines = File.ReadAllLines(csvPath, Encoding.Default); }

                var validLines = lines.Where(l => !string.IsNullOrWhiteSpace((l ?? "").Trim())).ToList();
                if (validLines.Count == 0) return false;

                int headerIndex = -1;
                for (int i = 0; i < validLines.Count; i++)
                {
                    string line = validLines[i];
                    if (line.IndexOf("Usn", StringComparison.OrdinalIgnoreCase) >= 0 &&
                        line.IndexOf("File name", StringComparison.OrdinalIgnoreCase) >= 0 &&
                        line.IndexOf("Reason", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        headerIndex = i;
                        break;
                    }
                }
                if (headerIndex < 0) return false;

                var result = new UsnData();
                result.HeaderLineNumber = headerIndex + 1;
                result.Headers.AddRange(CsvUtils.SplitLine(validLines[headerIndex]).Select(h => (h ?? "").Trim()));
                int colCount = result.Headers.Count;
                if (colCount == 0) return false;

                for (int i = headerIndex + 1; i < validLines.Count; i++)
                {
                    string[] parts = CsvUtils.SplitLine(validLines[i]);
                    if (parts.Length == 0) continue;
                    if (parts.Length != colCount)
                    {
                        var padded = new string[colCount];
                        for (int j = 0; j < colCount; j++) padded[j] = j < parts.Length ? (parts[j] ?? "") : "";
                        result.Rows.Add(padded);
                    }
                    else
                    {
                        result.Rows.Add(parts);
                    }
                }

                data = result;
                return true;
            }
            catch (Exception ex)
            {
                Logger.Warning("UsnNormalizer.TryReadUsnData: " + (ex.Message ?? ""));
                return false;
            }
        }

        private static int FindHeaderIndex(List<string> headers, params string[] candidates)
        {
            if (headers == null || headers.Count == 0 || candidates == null) return -1;
            for (int i = 0; i < headers.Count; i++)
            {
                string header = headers[i] ?? "";
                foreach (string candidate in candidates)
                {
                    if (string.Equals(header.Trim(), candidate, StringComparison.OrdinalIgnoreCase))
                        return i;
                }
            }
            return -1;
        }

        private static string GetCell(string[] row, int index)
        {
            if (row == null || index < 0 || index >= row.Length) return "";
            return row[index] ?? "";
        }

        private static DateTime ParseUsnTime(string timeText)
        {
            if (string.IsNullOrWhiteSpace(timeText)) return DateTime.MinValue;

            DateTime parsed;
            if (DateTime.TryParse(timeText.Trim(), out parsed))
                return parsed;

            string normalized = timeText.Replace("UTC", "").Trim();
            return DateTime.TryParse(normalized, out parsed) ? parsed : DateTime.MinValue;
        }

        private static string MapReasonToAction(string reason)
        {
            string normalized = (reason ?? "").ToUpperInvariant();
            if (normalized.IndexOf("FILE_CREATE", StringComparison.Ordinal) >= 0) return "Created";
            if (normalized.IndexOf("FILE_DELETE", StringComparison.Ordinal) >= 0) return "Deleted";
            if (normalized.IndexOf("RENAME_", StringComparison.Ordinal) >= 0) return "Renamed";
            if (normalized.IndexOf("DATA_", StringComparison.Ordinal) >= 0 ||
                normalized.IndexOf("BASIC_INFO_CHANGE", StringComparison.Ordinal) >= 0 ||
                normalized.IndexOf("SECURITY_CHANGE", StringComparison.Ordinal) >= 0 ||
                normalized.IndexOf("COMPRESSION_CHANGE", StringComparison.Ordinal) >= 0 ||
                normalized.IndexOf("ENCRYPTION_CHANGE", StringComparison.Ordinal) >= 0 ||
                normalized.IndexOf("OBJECT_ID_CHANGE", StringComparison.Ordinal) >= 0 ||
                normalized.IndexOf("REPARSE_POINT_CHANGE", StringComparison.Ordinal) >= 0 ||
                normalized.IndexOf("STREAM_CHANGE", StringComparison.Ordinal) >= 0)
                return "Modified";
            if (normalized.IndexOf("CLOSE", StringComparison.Ordinal) >= 0) return "Closed";
            return "Changed";
        }

        private static string BuildDetails(string fullPath, string fileName, string reason, string attributes, string fileRef, string parentFileRef)
        {
            var parts = new List<string>();
            string displayPath = !string.IsNullOrWhiteSpace(fullPath) ? fullPath : fileName;
            if (!string.IsNullOrWhiteSpace(displayPath))
                parts.Add("Target=" + displayPath);
            if (!string.IsNullOrWhiteSpace(reason))
                parts.Add("Reason=" + reason);
            if (!string.IsNullOrWhiteSpace(attributes))
                parts.Add("Attributes=" + attributes);
            if (!string.IsNullOrWhiteSpace(fileRef))
                parts.Add("FileRef=" + fileRef);
            if (!string.IsNullOrWhiteSpace(parentFileRef))
                parts.Add("ParentRef=" + parentFileRef);

            string details = string.Join(" | ", parts.ToArray());
            if (details.Length > 500) details = details.Substring(0, 497) + "...";
            return details;
        }

        private static string CollapseSingleLine(string value)
        {
            if (string.IsNullOrWhiteSpace(value)) return "";
            string s = value.Replace("\r", " ").Replace("\n", " ").Trim();
            while (s.Contains("  ")) s = s.Replace("  ", " ");
            return s;
        }
    }
}
