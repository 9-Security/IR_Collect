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

        public static List<Dictionary<string, string>> ReadCsv(string path, StringComparer keyComparer = null)
        {
            var list = new List<Dictionary<string, string>>();
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return list;
            try
            {
                long fileLen = new FileInfo(path).Length;
                if (MaxCsvFileBytes > 0 && fileLen > MaxCsvFileBytes)
                {
                    Logger.Warning("ReadCsv: file too large (" + (fileLen / 1024 / 1024) + " MB): " + path);
                    return list;
                }
            }
            catch (Exception ex) { Logger.Warning("ReadCsv size check: " + ex.Message); return list; }

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
                        if (MaxCsvRows > 0 && row > MaxCsvRows) { Logger.Warning("ReadCsv: row limit " + MaxCsvRows + " reached: " + path); break; }
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
            catch (Exception ex) { Logger.Warning("ReadCsv: " + ex.Message); }

            return list;
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
