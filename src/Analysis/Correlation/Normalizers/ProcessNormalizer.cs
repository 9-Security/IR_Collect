using System;
using System.Collections.Generic;
using IR_Collect;

namespace IR_Collect.Analysis.Correlation.Normalizers
{
    public static class ProcessNormalizer
    {
        public const string SourceName = "Process";

        public static List<Fact> ToFacts(string processListCsvPath)
        {
            var list = new List<Fact>();
            var rows = CorrelationCsvHelper.ReadCsv(processListCsvPath);
            for (int i = 0; i < rows.Count; i++)
            {
                var row = rows[i];
                string path = CorrelationCsvHelper.Get(row, "Path");
                string pid = CorrelationCsvHelper.Get(row, "PID");
                string startTimeStr = CorrelationCsvHelper.Get(row, "StartTime");
                string name = CorrelationCsvHelper.Get(row, "Name");
                string cmd = CorrelationCsvHelper.Get(row, "CommandLine");
                string hash = CorrelationCsvHelper.Get(row, "SHA256");
                string user = CorrelationCsvHelper.Get(row, "User");

                DateTime time = CorrelationCsvHelper.ParseDateTime(startTimeStr, DateTime.MinValue);
                string id = "Process_" + (string.IsNullOrEmpty(pid) ? i.ToString() : pid);

                var fact = new Fact(id, time, SourceName, "Executed");
                FactTimeMetadata.Apply(fact, FactTimeMetadata.InferTimeKind(SourceName, time), FactTimeMetadata.InferTimeConfidence(SourceName, time));
                fact.SourceFile = ArtifactNames.ProcessListCsv;
                fact.RawRef = ArtifactNames.ProcessListCsv + ":" + (i + 2);
                fact.ParseLevel = FactProvenanceMetadata.StructuredParseLevel;
                fact.Details = string.IsNullOrEmpty(cmd) ? (name + " " + path) : cmd;
                if (fact.Details.Length > 500) fact.Details = fact.Details.Substring(0, 497) + "...";
                fact.ParserNote = BuildParserNote(path, cmd, time);
                fact.FallbackUsed = !string.IsNullOrWhiteSpace(fact.ParserNote);

                if (!string.IsNullOrWhiteSpace(path))
                    fact.AddEntity("Path", path.Trim());
                if (!string.IsNullOrWhiteSpace(hash) && !hash.StartsWith("[") && hash.Length >= 10)
                    fact.AddEntity("Hash", hash.Trim());
                if (!string.IsNullOrWhiteSpace(user))
                    fact.AddEntity("User", user.Trim());
                if (!string.IsNullOrWhiteSpace(cmd))
                    fact.AddEntity("CommandLine", cmd.Trim());

                list.Add(fact);
            }
            return list;
        }

        private static string BuildParserNote(string path, string cmd, DateTime time)
        {
            if (string.IsNullOrWhiteSpace(path) && !string.IsNullOrWhiteSpace(cmd))
                return "Process row did not include an executable path; this fact is linked by command line and any available hash/user fields.";
            if (!FactTimeMetadata.HasUsableTime(time))
                return "Process start time was unavailable or unparsable in the collected row.";
            return "";
        }
    }
}
