#if INCLUDE_TESTS
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using IR_Collect.Collectors;
using IR_Collect.MFT;
using IR_Collect.Utils;

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

            // MFT/SRUM/Amcache parse a container file via their own readers (not a flat byte[]) and can
            // be huge, so they are dispatched BEFORE the whole-file read below.
            if (string.Equals(kind, "mft", StringComparison.OrdinalIgnoreCase))
                return RunMft(file, o);
            if (string.Equals(kind, "srum", StringComparison.OrdinalIgnoreCase))
                return RunSrum(file, o);
            if (string.Equals(kind, "amcache", StringComparison.OrdinalIgnoreCase))
                return RunAmcache(file, o);

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

        private static int RunSrum(string file, TextWriter o)
        {
            SrumExportResult r;
            try { r = SrumExporter.Export(file); }
            catch (Exception ex)
            {
                o.WriteLine("{\"ok\":false,\"kind\":\"srum\",\"file\":" + J(file) + ",\"error\":" + J(ex.Message) + "}");
                return 1;
            }
            var sb = new StringBuilder();
            sb.Append("{\"ok\":true,\"kind\":\"srum\",\"file\":").Append(J(file));
            sb.Append(",\"fallback\":").Append(r.FallbackUsed ? "true" : "false");
            sb.Append(",\"appRows\":").Append(r.AppRows.Count);
            sb.Append(",\"networkRows\":").Append(r.NetworkRows.Count);
            sb.Append(",\"notes\":[");
            for (int i = 0; i < r.ParserNotes.Count; i++) { if (i > 0) sb.Append(","); sb.Append(J(r.ParserNotes[i])); }
            sb.Append("],\"apps\":[");
            int n = 0;
            foreach (var a in r.AppRows)
            {
                if (n++ > 0) sb.Append(",");
                sb.Append("{\"ts\":").Append(J(a.Timestamp)).Append(",\"app\":").Append(J(a.AppId)).Append(",\"path\":").Append(J(a.Path)).Append(",\"user\":").Append(J(a.User)).Append("}");
            }
            sb.Append("]}");
            o.WriteLine(sb.ToString());
            return 0;
        }

        private static int RunAmcache(string file, TextWriter o)
        {
            AmcacheParseResult r;
            try { r = AmcacheParser.ParseHive(file); }
            catch (Exception ex)
            {
                o.WriteLine("{\"ok\":false,\"kind\":\"amcache\",\"file\":" + J(file) + ",\"error\":" + J(ex.Message) + "}");
                return 1;
            }
            var sb = new StringBuilder();
            sb.Append("{\"ok\":true,\"kind\":\"amcache\",\"file\":").Append(J(file));
            sb.Append(",\"fallback\":").Append(r.FallbackUsed ? "true" : "false");
            sb.Append(",\"fileRows\":").Append(r.Files.Count).Append(",\"programRows\":").Append(r.Programs.Count);
            sb.Append(",\"notes\":[");
            for (int i = 0; i < r.ParserNotes.Count; i++) { if (i > 0) sb.Append(","); sb.Append(J(r.ParserNotes[i])); }
            sb.Append("],\"files\":[");
            int n = 0;
            foreach (var f in r.Files)
            {
                if (n++ > 0) sb.Append(",");
                sb.Append("{\"path\":").Append(J(f.Path)).Append(",\"name\":").Append(J(f.FileName)).Append(",\"sha1\":").Append(J(f.Hash)).Append("}");
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
