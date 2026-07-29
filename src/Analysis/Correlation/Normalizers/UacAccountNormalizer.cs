using System;
using System.Collections.Generic;
using IR_Collect;

namespace IR_Collect.Analysis.Correlation.Normalizers
{
    public static class UacAccountNormalizer
    {
        public const string SourceName = "UacAccount";

        public static List<Fact> ToFacts(string csvPath)
        {
            var facts = new List<Fact>();
            var rows = CorrelationCsvHelper.ReadCsv(csvPath);
            for (int i = 0; i < rows.Count; i++)
            {
                var row = rows[i];
                string recordType = CorrelationCsvHelper.Get(row, "RecordType");
                string name = CorrelationCsvHelper.Get(row, "Name");
                string id = CorrelationCsvHelper.Get(row, "Id");
                string primaryGroupId = CorrelationCsvHelper.Get(row, "PrimaryGroupId");
                string home = CorrelationCsvHelper.Get(row, "Home");
                string shell = CorrelationCsvHelper.Get(row, "Shell");
                string members = CorrelationCsvHelper.Get(row, "Members");
                string passwordState = CorrelationCsvHelper.Get(row, "PasswordState");
                string description = CorrelationCsvHelper.Get(row, "Description");
                string sourcePath = CorrelationCsvHelper.Get(row, "SourcePath");
                bool isGroup = string.Equals(recordType, "Group", StringComparison.OrdinalIgnoreCase);

                var fact = new Fact(SourceName + "_" + i.ToString(), DateTime.MinValue, SourceName,
                    isGroup ? "GroupAccountObserved" : "UserAccountObserved");
                FactTimeMetadata.Apply(fact, FactTimeMetadata.UnknownTimeKind, FactTimeMetadata.LowConfidence);
                fact.SourceFile = ArtifactNames.UacAccountsCsv;
                fact.RawRef = ArtifactNames.UacAccountsCsv + ":" + (i + 2);
                fact.ParseLevel = FactProvenanceMetadata.StructuredParseLevel;
                fact.Details = "password_state=" + (passwordState ?? "") + "; description=" + (description ?? "") +
                    "; shell=" + (shell ?? "") + "; source=" + (sourcePath ?? "");

                if (isGroup)
                {
                    AddEntity(fact, "Group", name);
                    AddEntity(fact, "GroupId", id);
                    foreach (string member in (members ?? "").Split(','))
                        AddEntity(fact, "User", member);
                }
                else
                {
                    AddEntity(fact, "User", name);
                    AddEntity(fact, "UserId", id);
                    AddEntity(fact, "GroupId", primaryGroupId);
                    AddEntity(fact, "HomeDirectory", home);
                    AddEntity(fact, "LoginShell", shell);
                }
                AddEntity(fact, "Path", sourcePath);
                facts.Add(fact);
            }
            return facts;
        }

        private static void AddEntity(Fact fact, string type, string value)
        {
            if (fact != null && !string.IsNullOrWhiteSpace(value))
                fact.AddEntity(type, value.Trim());
        }
    }
}
