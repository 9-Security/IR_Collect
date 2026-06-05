using System;
using System.Collections.Generic;
using IR_Collect;

namespace IR_Collect.Analysis.Correlation.Normalizers
{
    public static class ShellBagsNormalizer
    {
        public const string SourceName = "ShellBags";

        public static List<Fact> ToFacts(string csvPath)
        {
            var list = new List<Fact>();
            var rows = CorrelationCsvHelper.ReadCsv(csvPath);
            for (int i = 0; i < rows.Count; i++)
            {
                var row = rows[i];
                string sid = CorrelationCsvHelper.Get(row, "Sid");
                string user = CorrelationCsvHelper.Get(row, "User");
                string decodedPath = CorrelationCsvHelper.Get(row, "DecodedPath");
                string bagPath = CorrelationCsvHelper.Get(row, "BagPath");
                string regKey = CorrelationCsvHelper.Get(row, "RegistryKey");
                string valName = CorrelationCsvHelper.Get(row, "ValueName");
                string mruSlot = CorrelationCsvHelper.Get(row, "MruSlot");
                string lastWrite = CorrelationCsvHelper.Get(row, "LastWriteTime");
                string parserNote = CorrelationCsvHelper.Get(row, "ParserNote");
                string srcFile = CorrelationCsvHelper.Get(row, "SourceFile");

                DateTime time = CorrelationCsvHelper.ParseDateTime(lastWrite, DateTime.MinValue);
                bool hasUsableTime = FactTimeMetadata.HasUsableTime(time);

                string factId = SourceName + "_" + i.ToString();
                var fact = new Fact(factId, hasUsableTime ? time : DateTime.MinValue, SourceName, "FolderBrowsed");
                FactTimeMetadata.Apply(fact, FactTimeMetadata.ObservedTimeKind, FactTimeMetadata.LowConfidence);
                fact.SourceFile = ArtifactNames.ShellBagsCsv;
                fact.RawRef = ArtifactNames.ShellBagsCsv + ":" + (i + 2);
                fact.ParseLevel = FactProvenanceMetadata.StructuredParseLevel;

                var details = new System.Text.StringBuilder();
                if (!string.IsNullOrWhiteSpace(bagPath))
                    details.Append("BagPath=").Append(bagPath.Trim()).Append("; ");
                if (!string.IsNullOrWhiteSpace(regKey))
                    details.Append("RegistryKey=").Append(regKey.Trim()).Append("; ");
                if (!string.IsNullOrWhiteSpace(valName))
                    details.Append("ValueName=").Append(valName.Trim()).Append("; ");
                if (!string.IsNullOrWhiteSpace(mruSlot))
                    details.Append("MruSlot=").Append(mruSlot.Trim()).Append("; ");
                if (!string.IsNullOrWhiteSpace(srcFile))
                    details.Append("SourceReg=").Append(srcFile.Trim());
                fact.Details = details.ToString().Trim();

                if (!string.IsNullOrWhiteSpace(decodedPath))
                    fact.AddEntity("Path", decodedPath.Trim());
                if (!string.IsNullOrWhiteSpace(user))
                    fact.AddEntity("User", user.Trim());
                if (!string.IsNullOrWhiteSpace(sid))
                    fact.AddEntity("Sid", sid.Trim());

                if (!string.IsNullOrWhiteSpace(parserNote))
                    fact.ParserNote = parserNote.Trim();

                if (!hasUsableTime)
                {
                    fact.Time = DateTime.MinValue;
                    fact.FallbackUsed = true;
                    string timeHint = "ShellBags: LastWriteTime column empty or unparsable (no source .reg file timestamp to use as observation anchor).";
                    fact.ParserNote = string.IsNullOrEmpty(fact.ParserNote)
                        ? timeHint
                        : (fact.ParserNote + " " + timeHint);
                }
                else
                {
                    if (time.Kind == DateTimeKind.Unspecified)
                        fact.Time = DateTime.SpecifyKind(time, DateTimeKind.Utc);
                    else
                        fact.Time = time.ToUniversalTime();
                    fact.FallbackUsed = false;
                }

                list.Add(fact);
            }

            return list;
        }
    }
}
