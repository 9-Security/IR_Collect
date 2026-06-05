using System;
using System.Collections.Generic;
using System.Text;

namespace IR_Collect.Utils
{
    /// <summary>共用 CSV 工具：EscapeField 與 SplitLine，各 Collector 統一使用。</summary>
    public static class CsvUtils
    {
        /// <summary>將欄位值包成符合 RFC 4180 的 CSV 欄：加雙引號並跳脫內部的雙引號。</summary>
        public static string EscapeField(string field)
        {
            if (string.IsNullOrEmpty(field)) return "";
            return "\"" + field.Replace("\"", "\"\"") + "\"";
        }

        /// <summary>
        /// CSV field for ANALYST-FACING EXPORTS only (e.g. Timeline Export CSV) — NOT for collection
        /// artifacts that the Fact Store re-reads (those must stay byte-stable for forensic fidelity).
        /// In addition to RFC-4180 quoting, neutralizes spreadsheet formula injection: a value starting
        /// with = + - @ (or TAB / CR) is prefixed with a single quote so Excel/Calc treat it as text
        /// rather than executing it. Safe here because these exports are terminal artifacts that the
        /// tool never parses back in.
        /// </summary>
        public static string EscapeFieldForExport(string field)
        {
            if (string.IsNullOrEmpty(field)) return "\"\"";
            char c0 = field[0];
            string v = (c0 == '=' || c0 == '+' || c0 == '-' || c0 == '@' || c0 == '\t' || c0 == '\r')
                ? "'" + field
                : field;
            return "\"" + v.Replace("\"", "\"\"") + "\"";
        }

        /// <summary>解析單行 CSV，支援 RFC 4180 引號跳脫（"" 代表一個 "）。</summary>
        public static string[] SplitLine(string line)
        {
            if (string.IsNullOrEmpty(line)) return new string[0];
            line = line.Trim();
            var result = new List<string>();
            var current = new StringBuilder();
            bool inQuotes = false;

            for (int i = 0; i < line.Length; i++)
            {
                char c = line[i];
                if (c == '"')
                {
                    if (inQuotes && i + 1 < line.Length && line[i + 1] == '"')
                    {
                        current.Append('"');
                        i++;
                    }
                    else
                    {
                        inQuotes = !inQuotes;
                    }
                }
                else if (c == ',' && !inQuotes)
                {
                    result.Add(current.ToString());
                    current.Clear();
                }
                else
                {
                    current.Append(c);
                }
            }
            result.Add(current.ToString());
            return result.ToArray();
        }
    }
}
