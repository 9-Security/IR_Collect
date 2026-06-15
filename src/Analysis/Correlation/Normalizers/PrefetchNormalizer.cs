using System;
using System.Collections.Generic;
using IR_Collect.Utils;

namespace IR_Collect.Analysis.Correlation.Normalizers
{
    /// <summary>
    /// Turns parsed Windows Prefetch (.pf) execution evidence into facts: one "Executed" fact per
    /// recorded last-run time (Prefetch keeps up to 8), carrying the executable name and run count.
    /// Parser validated 60/60 vs Eric Zimmerman's PECmd on real samples.
    /// </summary>
    public static class PrefetchNormalizer
    {
        private const string SourceName = "Prefetch";

        public static List<Fact> ToFacts(string prefetchDir)
        {
            var list = new List<Fact>();
            PrefetchParseResult parsed;
            try { parsed = PrefetchParser.ParseDirectory(prefetchDir); }
            catch { return list; }
            if (parsed == null) return list;

            int idx = 0;
            foreach (PrefetchEntry e in parsed.Entries)
            {
                if (e == null || string.IsNullOrWhiteSpace(e.ExecutableName)) { idx++; continue; }
                string exe = e.ExecutableName.Trim();
                string detail = "RunCount=" + e.RunCount + "; PrefetchHash=" + (e.Hash ?? "") + "; v" + e.FormatVersion
                    + "; RefFiles=" + e.ReferencedFileCount
                    + (string.IsNullOrEmpty(e.SourceFile) ? "" : "; " + e.SourceFile);

                if (e.LastRunTimesUtc != null && e.LastRunTimesUtc.Count > 0)
                {
                    for (int i = 0; i < e.LastRunTimesUtc.Count; i++)
                    {
                        DateTime t = e.LastRunTimesUtc[i];
                        var fact = new Fact(SourceName + "_" + idx + "_run_" + i, t, SourceName, "Executed");
                        FactTimeMetadata.Apply(fact, FactTimeMetadata.MetadataTimeKind, FactTimeMetadata.HighConfidence);
                        fact.SourceFile = string.IsNullOrEmpty(e.SourceFile) ? "Prefetch" : e.SourceFile;
                        fact.RawRef = e.SourceFile ?? "";
                        fact.ParseLevel = FactProvenanceMetadata.StructuredParseLevel;
                        fact.Details = (i == 0 ? "Last run. " : "Prior run. ") + detail;
                        fact.AddEntity("FileName", exe);
                        // On the most-recent run, surface referenced files loaded from user-writable /
                        // non-system locations (high-signal for side-loading / malware); skip the noisy
                        // system DLLs. Bounded to keep the fact small.
                        if (i == 0) AddSuspiciousReferencedFiles(fact, e.ReferencedFiles);
                        if (!string.IsNullOrWhiteSpace(e.ParserNote)) fact.ParserNote = e.ParserNote;
                        list.Add(fact);
                    }
                }
                else
                {
                    // Execution evidence with no usable run time: still record it (low confidence).
                    var fact = new Fact(SourceName + "_" + idx + "_norun", DateTime.MinValue, SourceName, "Executed");
                    FactTimeMetadata.Apply(fact, FactTimeMetadata.UnknownTimeKind, FactTimeMetadata.LowConfidence);
                    fact.SourceFile = string.IsNullOrEmpty(e.SourceFile) ? "Prefetch" : e.SourceFile;
                    fact.ParseLevel = FactProvenanceMetadata.StructuredParseLevel;
                    fact.FallbackUsed = true;
                    fact.Details = detail;
                    fact.AddEntity("FileName", exe);
                    if (!string.IsNullOrWhiteSpace(e.ParserNote)) fact.ParserNote = e.ParserNote;
                    list.Add(fact);
                }
                idx++;
            }
            return list;
        }

        // Add up to 15 referenced files from user-writable / non-system paths as ReferencedFile entities.
        // System DLLs (\Windows\, \Program Files\) are noise; user-writable load locations are signal.
        private static void AddSuspiciousReferencedFiles(Fact fact, List<string> refs)
        {
            if (refs == null) return;
            int added = 0;
            foreach (string rf in refs)
            {
                if (added >= 15) break;
                if (string.IsNullOrWhiteSpace(rf)) continue;
                string up = rf.ToUpperInvariant();
                if (up.IndexOf("\\WINDOWS\\", StringComparison.Ordinal) >= 0 ||
                    up.IndexOf("\\PROGRAM FILES", StringComparison.Ordinal) >= 0) continue;
                if (up.IndexOf("\\USERS\\", StringComparison.Ordinal) >= 0 ||
                    up.IndexOf("\\TEMP\\", StringComparison.Ordinal) >= 0 ||
                    up.IndexOf("\\APPDATA\\", StringComparison.Ordinal) >= 0 ||
                    up.IndexOf("\\PROGRAMDATA\\", StringComparison.Ordinal) >= 0 ||
                    up.IndexOf("\\DOWNLOADS\\", StringComparison.Ordinal) >= 0)
                {
                    fact.AddEntity("ReferencedFile", rf);
                    added++;
                }
            }
        }
    }
}
