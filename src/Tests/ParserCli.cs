#if INCLUDE_TESTS
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using IR_Collect.Collectors;
using IR_Collect.MFT;

namespace IR_Collect.Tests
{
    /// <summary>
    /// Phase 2.2 — single-artifact parse CLI used by the differential-validation harness
    /// (scripts/DiffValidate.ps1). It runs IR_Collect's REAL production parser on one input
    /// file and emits a stable one-line JSON result, so the harness can diff our output against
    /// the corresponding Eric Zimmerman tool (LECmd / JLECmd / MFTECmd / …) on the same file.
    ///
    /// Invoked via:  IR_Collect_review.exe -parse &lt;kind&gt; &lt;file&gt;
    /// Output (stdout): {"kind":"lnk","file":"...","ok":true,"paths":["C:\\...", ...]}
    /// </summary>
    internal static class ParserCli
    {
        internal static int Run(string kind, string file, TextWriter o)
        {
            if (string.IsNullOrEmpty(kind) || string.IsNullOrEmpty(file))
            {
                o.WriteLine("{\"ok\":false,\"error\":\"usage: -parse <lnk|jumplist> <file>\"}");
                return 2;
            }
            if (!File.Exists(file))
            {
                o.WriteLine("{\"ok\":false,\"kind\":" + J(kind) + ",\"file\":" + J(file) + ",\"error\":\"file not found\"}");
                return 2;
            }

            // MFT has its own richer JSON shape and streams the file record-by-record via MftParser,
            // so it must be dispatched BEFORE the whole-file read below: a real $MFT routinely exceeds
            // 2 GB and File.ReadAllBytes would throw on it.
            if (string.Equals(kind, "mft", StringComparison.OrdinalIgnoreCase))
                return RunMft(file, o);

            byte[] data;
            try { data = File.ReadAllBytes(file); }
            catch (Exception ex)
            {
                o.WriteLine("{\"ok\":false,\"kind\":" + J(kind) + ",\"file\":" + J(file) + ",\"error\":" + J(ex.Message) + "}");
                return 2;
            }

            List<string> paths;
            try
            {
                switch (kind.ToLowerInvariant())
                {
                    case "lnk":
                        // Structured MS-SHLLINK LocalBasePath read (the parser hardened in 0.22.2).
                        paths = JumpListsCollector.ExtractPathsFromLnkStructures(data);
                        break;
                    case "jumplist":
                        // Full jump-list pipeline exactly as collection runs it.
                        paths = JumpListsCollector.ExtractJumpListPaths(data);
                        break;
                    default:
                        o.WriteLine("{\"ok\":false,\"kind\":" + J(kind) + ",\"error\":\"unknown kind (lnk|jumplist|mft)\"}");
                        return 2;
                }
            }
            catch (Exception ex)
            {
                o.WriteLine("{\"ok\":false,\"kind\":" + J(kind) + ",\"file\":" + J(file) + ",\"error\":" + J(ex.Message) + "}");
                return 1;
            }

            var sb = new StringBuilder();
            sb.Append("{\"ok\":true,\"kind\":").Append(J(kind)).Append(",\"file\":").Append(J(file));
            sb.Append(",\"paths\":[");
            for (int i = 0; i < paths.Count; i++)
            {
                if (i > 0) sb.Append(",");
                sb.Append(J(paths[i]));
            }
            sb.Append("]}");
            o.WriteLine(sb.ToString());
            return 0;
        }

        // Bounded so a multi-hundred-MB $MFT cannot produce an unbounded JSON blob; the harness
        // diffs the records we emit against MFTECmd's same EntryNumbers (a representative sample).
        private const int MftParseLimit = 60000;

        private static int RunMft(string file, TextWriter o)
        {
            List<MftParser.MftEntry> entries;
            try { entries = MftParser.Parse(file, MftParseLimit); }
            catch (Exception ex)
            {
                o.WriteLine("{\"ok\":false,\"kind\":\"mft\",\"file\":" + J(file) + ",\"error\":" + J(ex.Message) + "}");
                return 1;
            }

            var sb = new StringBuilder();
            sb.Append("{\"ok\":true,\"kind\":\"mft\",\"file\":").Append(J(file));
            sb.Append(",\"limit\":").Append(MftParseLimit).Append(",\"entries\":[");
            bool first = true;
            foreach (var e in entries)
            {
                if (e == null || string.IsNullOrEmpty(e.FullPath)) continue;
                if (!first) sb.Append(",");
                first = false;
                sb.Append("{\"rec\":").Append(e.RecordNumber)
                  .Append(",\"dir\":").Append(e.IsDirectory ? "true" : "false")
                  .Append(",\"inUse\":").Append(e.InUse ? "true" : "false")
                  .Append(",\"path\":").Append(J(e.FullPath))
                  .Append(",\"cr\":").Append(J(Iso(e.StdCreated)))
                  .Append(",\"mo\":").Append(J(Iso(e.StdModified)))
                  .Append("}");
            }
            sb.Append("]}");
            o.WriteLine(sb.ToString());
            return 0;
        }

        // Stable, comparable timestamp form (UTC, second precision). Sentinels -> empty.
        private static string Iso(DateTime dt)
        {
            if (dt == DateTime.MinValue || dt == DateTime.MaxValue || dt.Year <= 1601) return "";
            DateTime u = dt.Kind == DateTimeKind.Utc ? dt : dt.ToUniversalTime();
            return u.ToString("yyyy-MM-ddTHH:mm:ss");
        }

        private static string J(string s)
        {
            if (s == null) return "null";
            var sb = new StringBuilder("\"");
            foreach (char c in s)
            {
                switch (c)
                {
                    case '\\': sb.Append("\\\\"); break;
                    case '"': sb.Append("\\\""); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4"));
                        else sb.Append(c);
                        break;
                }
            }
            sb.Append("\"");
            return sb.ToString();
        }
    }
}
#endif
