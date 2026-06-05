using System;
using System.Collections.Generic;
using IR_Collect;

namespace IR_Collect.Analysis.Correlation.Normalizers
{
    public static class BitsJobNormalizer
    {
        public const string SourceName = "BITS";

        public static List<Fact> ToFacts(string csvPath)
        {
            var list = new List<Fact>();
            var rows = CorrelationCsvHelper.ReadCsv(csvPath);
            for (int i = 0; i < rows.Count; i++)
            {
                var row = rows[i];
                string displayName = CorrelationCsvHelper.Get(row, "DisplayName");
                string owner = CorrelationCsvHelper.Get(row, "OwnerAccount");
                string state = CorrelationCsvHelper.Get(row, "JobState");
                string remoteName = CorrelationCsvHelper.Get(row, "RemoteName");
                string localName = CorrelationCsvHelper.Get(row, "LocalName");
                string description = CorrelationCsvHelper.Get(row, "Description");
                string modified = CorrelationCsvHelper.Get(row, "ModificationTime");
                string created = CorrelationCsvHelper.Get(row, "CreationTime");

                DateTime time = CorrelationCsvHelper.ParseDateTime(modified, DateTime.MinValue);
                if (!FactTimeMetadata.HasUsableTime(time))
                    time = CorrelationCsvHelper.ParseDateTime(created, DateTime.MinValue);

                var fact = new Fact(SourceName + "_" + i.ToString(), time, SourceName, string.IsNullOrWhiteSpace(state) ? "JobObserved" : state.Trim());
                FactTimeMetadata.Apply(fact,
                    FactTimeMetadata.HasUsableTime(time) ? FactTimeMetadata.MetadataTimeKind : FactTimeMetadata.UnknownTimeKind,
                    FactTimeMetadata.HasUsableTime(time) ? FactTimeMetadata.MediumConfidence : FactTimeMetadata.LowConfidence);
                fact.SourceFile = ArtifactNames.BitsJobsCsv;
                fact.RawRef = ArtifactNames.BitsJobsCsv + ":" + (i + 2);
                fact.ParseLevel = FactProvenanceMetadata.StructuredParseLevel;
                fact.Details = string.IsNullOrWhiteSpace(description) ? remoteName : description;
                if (!string.IsNullOrWhiteSpace(displayName))
                    fact.AddEntity("BitsJob", displayName.Trim());
                if (!string.IsNullOrWhiteSpace(owner))
                    fact.AddEntity("User", owner.Trim());
                if (!string.IsNullOrWhiteSpace(remoteName))
                {
                    string rn = remoteName.Trim();
                    fact.AddEntity("RemoteName", rn);
                    ApplyUncDerivativesFromBitsRemoteName(fact, rn);
                }
                if (!string.IsNullOrWhiteSpace(localName))
                    fact.AddEntity("Path", localName.Trim());
                if (!FactTimeMetadata.HasUsableTime(time))
                {
                    fact.ParserNote = "BITS job row did not expose a usable creation or modification timestamp.";
                    fact.FallbackUsed = true;
                }
                list.Add(fact);
            }
            return list;
        }

        /// <summary>
        /// BITS collector may join multiple FileList.RemoteName values with "; ". Split conservatively on ';',
        /// trim segments, and derive Workstation / ShareName / RemoteIP per segment. Original RemoteName entity unchanged.
        /// </summary>
        private static void ApplyUncDerivativesFromBitsRemoteName(Fact fact, string remoteNameFull)
        {
            if (fact == null || string.IsNullOrWhiteSpace(remoteNameFull))
                return;

            string[] parts = remoteNameFull.Split(';');
            for (int p = 0; p < parts.Length; p++)
            {
                if (parts[p] == null)
                    continue;
                string seg = parts[p].Trim();
                if (seg.Length == 0)
                    continue;
                UncNetworkEntityHelper.AddFromUncOrUrl(fact, seg);
            }
        }
    }
}
