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
    /// Phase 2.1 — a persisted, git-tracked corpus of byte-level parser fixtures.
    ///
    /// Each fixture is a small, deterministic binary written to disk under tests/fixtures/.
    /// The corpus exists so that:
    ///   1. Every parser bug we fixed has a permanent, on-disk regression guard that is
    ///      independent of the inline test code (the exact malformed bytes are preserved).
    ///   2. Phase 2.2's differential-validation harness has real input files to feed both
    ///      IR_Collect and the external reference tools (MFTECmd / SBECmd / SrumECmd …).
    ///
    /// Only formats for which IR_Collect owns a pure byte-parser are synthesized here, so the
    /// validation is fully self-contained. Container formats that require a real registry hive
    /// or ESE database (Amcache / ShimCache / SRUDB / ShellBags) cannot be faithfully synthesized
    /// and are instead recorded in the manifest as requiresRealSample=true, with acquisition
    /// pointers, to be supplied for Phase 2.2.
    ///
    /// Regenerate the committed corpus with:  IR_Collect_review.exe -make-fixtures tests\fixtures
    /// </summary>
    internal static class FixtureCorpus
    {
        internal const string CorpusVersion = "1";

        /// <summary>Expected parse outcome category for a synthesized fixture.</summary>
        internal enum Outcome
        {
            /// <summary>Parser must extract the documented value.</summary>
            ParsesTo,
            /// <summary>Parser must return the documented count of items.</summary>
            CountIs,
            /// <summary>Malformed/truncated input: parser must degrade safely (no throw, empty/null).</summary>
            DegradesSafely
        }

        internal sealed class Fixture
        {
            public string Format;          // lnk | mft_runlist | srum_idblob
            public string RelativePath;    // path under the corpus root (forward slashes)
            public string Category;        // valid | malformed | truncated
            public string Description;     // human-readable provenance
            public Outcome Outcome;
            public string ExpectedValue;   // for ParsesTo
            public int ExpectedCount;      // for CountIs
            public byte[] Content;         // deterministic bytes
        }

        /// <summary>Build the full set of synthesized fixtures. Pure + deterministic.</summary>
        internal static List<Fixture> Build()
        {
            var list = new List<Fixture>();

            // ----- LNK (MS-SHLLINK) : JumpListsCollector.TryParseLnkLocalPath -----
            list.Add(new Fixture
            {
                Format = "lnk",
                RelativePath = "lnk/valid_unicode_localbasepath.lnk",
                Category = "valid",
                Description = "Modern jump-list LNK with LocalBasePath stored as Unicode at LinkInfo offset 0x1C.",
                Outcome = Outcome.ParsesTo,
                ExpectedValue = "C:\\Users\\x\\secret.docx",
                Content = IRCollectSelfTests.BuildLnkFixture("C:\\Users\\x\\secret.docx", true)
            });
            list.Add(new Fixture
            {
                Format = "lnk",
                RelativePath = "lnk/valid_ansi_localbasepath.lnk",
                Category = "valid",
                Description = "Legacy LNK with ANSI LocalBasePath at LinkInfo offset 0x10.",
                Outcome = Outcome.ParsesTo,
                ExpectedValue = "C:\\temp\\a.txt",
                Content = IRCollectSelfTests.BuildLnkFixture("C:\\temp\\a.txt", false)
            });
            list.Add(new Fixture
            {
                Format = "lnk",
                RelativePath = "lnk/truncated_header.lnk",
                Category = "truncated",
                Description = "Only 20 bytes — shorter than the 76-byte ShellLinkHeader. Must not over-read or throw.",
                Outcome = Outcome.DegradesSafely,
                Content = new byte[] { 0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00,
                                       0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x46 }
            });
            list.Add(new Fixture
            {
                Format = "lnk",
                RelativePath = "lnk/no_linkinfo_flag.lnk",
                Category = "malformed",
                Description = "Full 76-byte header but LinkFlags clears HasLinkInfo; there is no LinkInfo block to read.",
                Outcome = Outcome.DegradesSafely,
                Content = BuildLnkHeaderOnlyNoLinkInfo()
            });

            // ----- MFT run-list : MftDumper.ParseRunList -----
            list.Add(new Fixture
            {
                Format = "mft_runlist",
                RelativePath = "mft_runlist/valid_two_runs.bin",
                Category = "valid",
                Description = "Two 1+1-byte runs (header 0x11) then 0x00 terminator.",
                Outcome = Outcome.CountIs,
                ExpectedCount = 2,
                Content = new byte[] { 0x11, 0x10, 0x20, 0x11, 0x05, 0x03, 0x00 }
            });
            list.Add(new Fixture
            {
                Format = "mft_runlist",
                RelativePath = "mft_runlist/truncated_overclaim.bin",
                Category = "truncated",
                Description = "Header 0x44 claims 4 length + 4 offset bytes but only 2 trailing bytes exist.",
                Outcome = Outcome.DegradesSafely,
                Content = new byte[] { 0x44, 0x01, 0x02 }
            });
            list.Add(new Fixture
            {
                Format = "mft_runlist",
                RelativePath = "mft_runlist/zero_length_run.bin",
                Category = "malformed",
                Description = "Header 0x01 with a zero length byte — a 0-cluster run must terminate parsing, not loop.",
                Outcome = Outcome.DegradesSafely,
                Content = new byte[] { 0x01, 0x00, 0x10 }
            });

            // ----- SRUM identity blob : SrumExporter.DecodeIdBlob -----
            list.Add(new Fixture
            {
                Format = "srum_idblob",
                RelativePath = "srum_idblob/sid_localsystem.bin",
                Category = "valid",
                Description = "Binary SID S-1-5-18 (LocalSystem): rev=1, subAuthCount=1, authority=5, subAuth=18.",
                Outcome = Outcome.ParsesTo,
                ExpectedValue = "S-1-5-18",
                Content = new byte[] { 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00 }
            });
            list.Add(new Fixture
            {
                Format = "srum_idblob",
                RelativePath = "srum_idblob/utf16_appid_text.bin",
                Category = "valid",
                Description = "UTF-16LE application id text 'C:\\app.exe' that must NOT be misread as a SID.",
                Outcome = Outcome.ParsesTo,
                ExpectedValue = "C:\\app.exe",
                Content = Encoding.Unicode.GetBytes("C:\\app.exe")
            });
            list.Add(new Fixture
            {
                Format = "srum_idblob",
                RelativePath = "srum_idblob/malformed_subauth_overflow.bin",
                Category = "malformed",
                Description = "Claims rev=1 but subAuthCount=0xFF with no sub-authority bytes; must not be parsed as a SID or throw.",
                Outcome = Outcome.DegradesSafely,
                Content = new byte[] { 0x01, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 }
            });

            return list;
        }

        // 76-byte ShellLinkHeader with LinkFlags = 0 (no HasLinkInfo), no trailing blocks.
        private static byte[] BuildLnkHeaderOnlyNoLinkInfo()
        {
            var header = new byte[76];
            BitConverter.GetBytes(0x4C).CopyTo(header, 0x00);
            new Guid("00021401-0000-0000-C000-000000000046").ToByteArray().CopyTo(header, 0x04);
            // LinkFlags left at 0 at offset 0x14 — HasLinkInfo not set.
            return header;
        }

        /// <summary>Container formats we cannot faithfully synthesize; recorded for Phase 2.2.</summary>
        private static string[][] RealSampleNeeds()
        {
            return new string[][]
            {
                new[] { "amcache", "Amcache.hve registry hive", "MFTECmd is N/A; compare against AmcacheParser. Sample hives: github.com/EricZimmerman/Samples." },
                new[] { "shimcache", "AppCompatCache (SYSTEM hive value)", "Compare against AppCompatCacheParser. Needs a real SYSTEM hive." },
                new[] { "srudb", "SRUDB.dat ESE database", "Compare against SrumECmd. Needs a real ESE database; the idblob fixtures above only cover the SID sub-decode." },
                new[] { "shellbags", "UsrClass.dat / NTUSER.dat ShellBags", "Compare against SBECmd. Needs real user hives." },
                new[] { "mft", "Full $MFT", "Compare against MFTECmd. The run-list fixtures cover only the DATA run-list sub-parser." }
            };
        }

        /// <summary>Write the corpus (binaries + manifest.json + README.md) under <paramref name="root"/>.</summary>
        internal static int WriteCorpus(string root)
        {
            var fixtures = Build();
            Directory.CreateDirectory(root);

            foreach (var f in fixtures)
            {
                string full = Path.Combine(root, f.RelativePath.Replace('/', Path.DirectorySeparatorChar));
                Directory.CreateDirectory(Path.GetDirectoryName(full));
                File.WriteAllBytes(full, f.Content);
            }

            File.WriteAllText(Path.Combine(root, "manifest.json"), BuildManifestJson(fixtures), new UTF8Encoding(false));
            File.WriteAllText(Path.Combine(root, "README.md"), BuildReadme(fixtures), new UTF8Encoding(false));
            return fixtures.Count;
        }

        private static string BuildManifestJson(List<Fixture> fixtures)
        {
            var sb = new StringBuilder();
            sb.Append("{\n");
            sb.Append("  \"corpusVersion\": \"").Append(CorpusVersion).Append("\",\n");
            sb.Append("  \"synthesized\": [\n");
            for (int i = 0; i < fixtures.Count; i++)
            {
                var f = fixtures[i];
                sb.Append("    {\n");
                sb.Append("      \"format\": ").Append(JsonStr(f.Format)).Append(",\n");
                sb.Append("      \"path\": ").Append(JsonStr(f.RelativePath)).Append(",\n");
                sb.Append("      \"category\": ").Append(JsonStr(f.Category)).Append(",\n");
                sb.Append("      \"outcome\": ").Append(JsonStr(f.Outcome.ToString())).Append(",\n");
                if (f.Outcome == Outcome.ParsesTo)
                    sb.Append("      \"expectedValue\": ").Append(JsonStr(f.ExpectedValue)).Append(",\n");
                if (f.Outcome == Outcome.CountIs)
                    sb.Append("      \"expectedCount\": ").Append(f.ExpectedCount).Append(",\n");
                sb.Append("      \"sizeBytes\": ").Append(f.Content.Length).Append(",\n");
                sb.Append("      \"description\": ").Append(JsonStr(f.Description)).Append("\n");
                sb.Append(i == fixtures.Count - 1 ? "    }\n" : "    },\n");
            }
            sb.Append("  ],\n");
            sb.Append("  \"requiresRealSample\": [\n");
            var needs = RealSampleNeeds();
            for (int i = 0; i < needs.Length; i++)
            {
                sb.Append("    {\n");
                sb.Append("      \"format\": ").Append(JsonStr(needs[i][0])).Append(",\n");
                sb.Append("      \"artifact\": ").Append(JsonStr(needs[i][1])).Append(",\n");
                sb.Append("      \"validationPlan\": ").Append(JsonStr(needs[i][2])).Append("\n");
                sb.Append(i == needs.Length - 1 ? "    }\n" : "    },\n");
            }
            sb.Append("  ]\n");
            sb.Append("}\n");
            return sb.ToString();
        }

        private static string BuildReadme(List<Fixture> fixtures)
        {
            var sb = new StringBuilder();
            sb.Append("# IR_Collect parser fixture corpus\n\n");
            sb.Append("Corpus version: ").Append(CorpusVersion).Append("\n\n");
            sb.Append("These are small, deterministic binary fixtures for IR_Collect's byte-level parsers. ");
            sb.Append("They are generated by `FixtureCorpus.Build()` and regenerated with:\n\n");
            sb.Append("```\nIR_Collect_review.exe -make-fixtures tests\\fixtures\n```\n\n");
            sb.Append("The `-test` self-test suite validates every file here against the live parser, ");
            sb.Append("and also re-generates each fixture in memory and asserts byte-equality so the committed ");
            sb.Append("corpus can never silently drift from the builder.\n\n");
            sb.Append("## Synthesized fixtures\n\n");
            sb.Append("| Format | Path | Category | Expected |\n|---|---|---|---|\n");
            foreach (var f in fixtures)
            {
                string exp = f.Outcome == Outcome.ParsesTo ? ("parses to `" + f.ExpectedValue + "`")
                    : f.Outcome == Outcome.CountIs ? ("count == " + f.ExpectedCount)
                    : "degrades safely (no throw)";
                sb.Append("| ").Append(f.Format).Append(" | `").Append(f.RelativePath).Append("` | ")
                  .Append(f.Category).Append(" | ").Append(exp).Append(" |\n");
            }
            sb.Append("\n## Formats requiring a real sample (Phase 2.2)\n\n");
            sb.Append("Container formats below need a real registry hive or ESE database and cannot be ");
            sb.Append("faithfully synthesized. Supply real (sanitized) samples to enable differential ");
            sb.Append("validation against the reference tools listed.\n\n");
            sb.Append("| Format | Artifact | Validation plan |\n|---|---|---|\n");
            foreach (var n in RealSampleNeeds())
                sb.Append("| ").Append(n[0]).Append(" | ").Append(n[1]).Append(" | ").Append(n[2]).Append(" |\n");
            sb.Append("\nProvenance: all synthesized fixtures are constructed byte-by-byte from format ");
            sb.Append("specifications (MS-SHLLINK, NTFS run-list, MS-DTYP SID). They contain no real ");
            sb.Append("evidence and are safe to publish.\n");
            return sb.ToString();
        }

        private static string JsonStr(string s)
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
                    default: sb.Append(c); break;
                }
            }
            sb.Append("\"");
            return sb.ToString();
        }

        /// <summary>
        /// Validate fixtures against the live parsers. If the committed corpus is found on disk it is
        /// loaded and checked byte-for-byte against the builder (drift guard); otherwise fixtures are
        /// validated from memory so the parser assertions still run from a release directory.
        /// Returns the number of failed checks; appends per-check lines to <paramref name="sb"/>.
        /// </summary>
        internal static int Validate(StringBuilder sb)
        {
            var fixtures = Build();
            string root = LocateCorpusRoot();
            int failed = 0;

            if (root != null)
            {
                sb.AppendLine("INFO: corpus root = " + root);
                foreach (var f in fixtures)
                {
                    string full = Path.Combine(root, f.RelativePath.Replace('/', Path.DirectorySeparatorChar));
                    if (!File.Exists(full))
                    {
                        failed++;
                        sb.AppendLine("FAIL: corpus missing committed file " + f.RelativePath +
                                      " (run -make-fixtures tests\\fixtures)");
                        continue;
                    }
                    byte[] onDisk = File.ReadAllBytes(full);
                    if (!BytesEqual(onDisk, f.Content))
                    {
                        failed++;
                        sb.AppendLine("FAIL: corpus drift in " + f.RelativePath +
                                      " (committed bytes != builder; run -make-fixtures tests\\fixtures)");
                        continue;
                    }
                    if (!CheckParse(f, onDisk, sb)) failed++;
                }
            }
            else
            {
                sb.AppendLine("INFO: committed corpus not found near exe; validating fixtures from memory.");
                foreach (var f in fixtures)
                    if (!CheckParse(f, f.Content, sb)) failed++;
            }

            return failed;
        }

        private static bool CheckParse(Fixture f, byte[] data, StringBuilder sb)
        {
            try
            {
                switch (f.Format)
                {
                    case "lnk":
                    {
                        int consumed;
                        string p = JumpListsCollector.TryParseLnkLocalPath(data, 0, out consumed);
                        if (f.Outcome == Outcome.ParsesTo)
                            return Report(f, sb, string.Equals(p, f.ExpectedValue, StringComparison.Ordinal),
                                "got '" + (p ?? "<null>") + "'");
                        // DegradesSafely: any non-throwing result (null or non-matching garbage) is acceptable.
                        return Report(f, sb, string.IsNullOrEmpty(p) ||
                            p.IndexOf(':') < 0, "got '" + (p ?? "<null>") + "'");
                    }
                    case "mft_runlist":
                    {
                        var runs = MftDumper.ParseRunList(data, 0, data.Length);
                        if (f.Outcome == Outcome.CountIs)
                            return Report(f, sb, runs != null && runs.Count == f.ExpectedCount,
                                "count=" + (runs == null ? "null" : runs.Count.ToString()));
                        return Report(f, sb, runs != null && runs.Count == 0,
                            "count=" + (runs == null ? "null" : runs.Count.ToString()));
                    }
                    case "srum_idblob":
                    {
                        string s = SrumExporter.DecodeIdBlob(data);
                        if (f.Outcome == Outcome.ParsesTo)
                            return Report(f, sb, s != null &&
                                s.IndexOf(f.ExpectedValue, StringComparison.OrdinalIgnoreCase) >= 0,
                                "got '" + (s ?? "<null>") + "'");
                        // DegradesSafely: must not be reported as a valid SID.
                        return Report(f, sb, s == null || !s.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase),
                            "got '" + (s ?? "<null>") + "'");
                    }
                    default:
                        return Report(f, sb, false, "unknown format");
                }
            }
            catch (Exception ex)
            {
                // For DegradesSafely a throw IS the failure (parser must be hardened, not crash).
                return Report(f, sb, false, "threw " + ex.GetType().Name + ": " + ex.Message);
            }
        }

        private static bool Report(Fixture f, StringBuilder sb, bool ok, string detail)
        {
            sb.AppendLine((ok ? "PASS: fixture " : "FAIL: fixture ") + f.RelativePath +
                          (ok ? "" : " — " + detail));
            return ok;
        }

        private static bool BytesEqual(byte[] a, byte[] b)
        {
            if (a == null || b == null) return a == b;
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
            return true;
        }

        /// <summary>Walk up from the executable directory looking for tests/fixtures/manifest.json.</summary>
        private static string LocateCorpusRoot()
        {
            try
            {
                var dir = new DirectoryInfo(AppDomain.CurrentDomain.BaseDirectory);
                for (int i = 0; i < 8 && dir != null; i++)
                {
                    string candidate = Path.Combine(dir.FullName, Path.Combine("tests", "fixtures"));
                    if (File.Exists(Path.Combine(candidate, "manifest.json")))
                        return candidate;
                    dir = dir.Parent;
                }
            }
            catch { /* best-effort; fall back to in-memory validation */ }
            return null;
        }
    }
}
#endif
