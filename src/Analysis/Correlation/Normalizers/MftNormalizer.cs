using System;
using System.Collections.Generic;
using IR_Collect.MFT;
using IR_Collect.Analysis.Correlation;

namespace IR_Collect.Analysis.Correlation.Normalizers
{
    public static class MftNormalizer
    {
        public const string SourceName = "MFT";

        /// <summary>將 MftEntry 清單轉為 Fact；可限制筆數以控制記憶體。</summary>
        public static List<Fact> ToFacts(List<MftParser.MftEntry> entries, int limit = 50000)
        {
            var list = new List<Fact>();
            if (entries == null) return list;
            int count = 0;
            foreach (var e in entries)
            {
                if (count >= limit) break;
                if (string.IsNullOrWhiteSpace(e.FullPath)) continue;

                bool hasCreated = e.Created.Year > 1980;
                DateTime time = hasCreated ? e.Created : e.Modified;
                if (time.Year < 1980) continue;

                string id = "MFT_" + e.RecordNumber;
                // Action must reflect the timestamp actually used: labeling a Modified-time fact as
                // "Created" places a false creation event on the timeline (facts-only mislabel).
                string action = hasCreated ? "Created" : "Modified";
                var fact = new Fact(id, time, SourceName, action);
                FactTimeMetadata.Apply(fact, FactTimeMetadata.MetadataTimeKind, FactTimeMetadata.MediumConfidence);
                fact.SourceFile = ArtifactNames.MftPreviewCsv;
                fact.RawRef = "MFT record " + e.RecordNumber;
                fact.ParseLevel = FactProvenanceMetadata.MetadataDerivedParseLevel;
                fact.Details = e.FullPath;
                if (e.Size > 0) fact.Details += " (" + e.Size + " bytes)";
                if (fact.Details.Length > 500) fact.Details = fact.Details.Substring(0, 497) + "...";
                if (!(e.Created.Year > 1980) && e.Modified.Year > 1980)
                {
                    fact.ParserNote = "MFT Created timestamp was unavailable; the fact time falls back to another usable metadata timestamp.";
                    fact.FallbackUsed = true;
                }

                fact.AddEntity("Path", e.FullPath.Trim());
                list.Add(fact);
                count++;
            }
            return list;
        }
    }
}
