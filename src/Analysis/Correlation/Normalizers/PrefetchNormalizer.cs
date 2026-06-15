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
    }
}
