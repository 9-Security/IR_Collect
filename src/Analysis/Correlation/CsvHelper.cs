using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using IR_Collect.Utils;

namespace IR_Collect.Analysis.Correlation
{
    internal static class CorrelationCsvHelper
    {
        /// <summary>Max file size (bytes) before refusing to load CSV; 0 = no limit.</summary>
        private const long MaxCsvFileBytes = 100L * 1024 * 1024;
        /// <summary>Max rows to read; 0 = no limit.</summary>
        private const int MaxCsvRows = 500000;
        [ThreadStatic]
        private static List<string> _diagnostics;

        internal static void ResetDiagnostics()
        {
            _diagnostics = new List<string>();
        }

        internal static List<string> ConsumeDiagnostics()
        {
            var result = _diagnostics ?? new List<string>();
            _diagnostics = null;
            return result;
        }

        private static void ReportDiagnostic(string message)
        {
            Logger.Warning(message);
            if (_diagnostics == null) _diagnostics = new List<string>();
            if (!_diagnostics.Contains(message)) _diagnostics.Add(message);
        }

        public static List<Dictionary<string, string>> ReadCsv(string path, StringComparer keyComparer = null)
        {
            var list = new List<Dictionary<string, string>>();
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return list;
            try
            {
                long fileLen = new FileInfo(path).Length;
                if (MaxCsvFileBytes > 0 && fileLen > MaxCsvFileBytes)
                {
                    ReportDiagnostic("CSV normalization skipped because the file exceeds 100 MiB (" +
                        (fileLen / 1024 / 1024) + " MiB): " + path);
                    return list;
                }
            }
            catch (Exception ex)
            {
                ReportDiagnostic("CSV normalization skipped because file size could not be read: " + path +
                    " (" + ex.Message + ")");
                return list;
            }

            var cmp = keyComparer ?? StringComparer.OrdinalIgnoreCase;
            try
            {
                using (var sr = new StreamReader(path, Encoding.UTF8))
                {
                    string headerLine = sr.ReadLine();
                    if (string.IsNullOrEmpty(headerLine)) return list;
                    string[] headers = SplitCsvLine(headerLine);

                    string line;
                    int row = 0;
                    while ((line = sr.ReadLine()) != null)
                    {
                        row++;
                        if (ExceedsRowLimit(row))
                        {
                            ReportDiagnostic("CSV normalization was truncated at " + MaxCsvRows + " rows: " + path);
                            break;
                        }
                        if (string.IsNullOrWhiteSpace(line)) continue;
                        string[] parts = SplitCsvLine(line);
                        var map = new Dictionary<string, string>(cmp);
                        for (int i = 0; i < headers.Length; i++)
                        {
                            string key = headers[i].Trim();
                            string val = (parts.Length > i) ? parts[i] ?? "" : "";
                            map[key] = val;
                        }
                        list.Add(map);
                    }
                }
            }
            catch (Exception ex)
            {
                ReportDiagnostic("CSV normalization stopped before end-of-file: " + path + " (" + ex.Message + ")");
            }

            return list;
        }

        internal static bool ExceedsRowLimit(int row)
        {
            return MaxCsvRows > 0 && row > MaxCsvRows;
        }

        /// <summary>委派至 <see cref="CsvUtils.SplitLine"/>，統一 RFC 4180 解析邏輯（含 escaped quote ""）。</summary>
        public static string[] SplitCsvLine(string line)
        {
            return CsvUtils.SplitLine(line);
        }

        public static string Get(Dictionary<string, string> row, string key, string defaultValue = "")
        {
            if (row == null || string.IsNullOrEmpty(key)) return defaultValue ?? "";
            string v;
            return row.TryGetValue(key, out v) ? (v ?? "") : (defaultValue ?? "");
        }

        public static DateTime ParseDateTime(string s, DateTime defaultVal)
        {
            if (string.IsNullOrWhiteSpace(s)) return defaultVal;
            DateTime d;
            return DateTime.TryParse(s, out d) ? d : defaultVal;
        }
    }
}
