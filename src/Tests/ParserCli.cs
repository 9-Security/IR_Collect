#if INCLUDE_TESTS
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using IR_Collect.Collectors;

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
                        o.WriteLine("{\"ok\":false,\"kind\":" + J(kind) + ",\"error\":\"unknown kind (lnk|jumplist)\"}");
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
