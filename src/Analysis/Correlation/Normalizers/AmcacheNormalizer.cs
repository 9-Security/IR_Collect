using System;
using System.Collections.Generic;
using IR_Collect;

namespace IR_Collect.Analysis.Correlation.Normalizers
{
    public static class AmcacheNormalizer
    {
        public const string SourceName = "Amcache";

        public static List<Fact> ToFacts(string programsCsvPath, string filesCsvPath)
        {
            var list = new List<Fact>();
            var seenParserNotes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            list.AddRange(ToProgramFacts(programsCsvPath, seenParserNotes));
            list.AddRange(ToFileFacts(filesCsvPath, seenParserNotes));
            return list;
        }

        private static IEnumerable<Fact> ToProgramFacts(string csvPath, HashSet<string> seenParserNotes)
        {
            var rows = CorrelationCsvHelper.ReadCsv(csvPath);
            for (int i = 0; i < rows.Count; i++)
            {
                var row = rows[i];
                string name = CorrelationCsvHelper.Get(row, "ProgramName");
                string publisher = CorrelationCsvHelper.Get(row, "Publisher");
                string version = CorrelationCsvHelper.Get(row, "Version");
                string product = CorrelationCsvHelper.Get(row, "ProductName");
                string installDate = CorrelationCsvHelper.Get(row, "InstallDate");
                string programId = CorrelationCsvHelper.Get(row, "ProgramId");
                string parserNote = CorrelationCsvHelper.Get(row, "ParserNote");
                string rawRef = ArtifactNames.AmcacheProgramsCsv + ":" + (i + 2);

                if (IsNoteOnlyProgramRow(name, publisher, version, product, installDate, programId, parserNote))
                {
                    if (TryMarkParserNote(seenParserNotes, parserNote))
                        yield return CreateParserNoteFact("program_note_" + i.ToString(), ArtifactNames.AmcacheProgramsCsv, rawRef, parserNote);
                    continue;
                }

                if (IsEmpty(name, publisher, version, product, programId))
                    continue;

                DateTime time = CorrelationCsvHelper.ParseDateTime(installDate, DateTime.MinValue);
                string action = FactTimeMetadata.HasUsableTime(time) ? "Installed" : "FirstObserved";
                var fact = new Fact(SourceName + "_program_" + i.ToString(), time, SourceName, action);
                FactTimeMetadata.Apply(
                    fact,
                    FactTimeMetadata.HasUsableTime(time) ? FactTimeMetadata.MetadataTimeKind : FactTimeMetadata.UnknownTimeKind,
                    FactTimeMetadata.HasUsableTime(time) ? FactTimeMetadata.MediumConfidence : FactTimeMetadata.LowConfidence);
                fact.SourceFile = ArtifactNames.AmcacheProgramsCsv;
                fact.RawRef = rawRef;
                fact.ParseLevel = FactProvenanceMetadata.RegistryValueParseLevel;
                fact.Details = BuildProgramDetails(name, publisher, version, product, programId);

                AddEntity(fact, "Publisher", publisher);
                AddEntity(fact, "ProductName", product);
                AddEntity(fact, "ProgramName", name);
                AddEntity(fact, "ProgramId", programId);

                if (!string.IsNullOrWhiteSpace(parserNote))
                    fact.ParserNote = parserNote;
                if (!FactTimeMetadata.HasUsableTime(time))
                    fact.FallbackUsed = true;

                yield return fact;
            }
        }

        private static IEnumerable<Fact> ToFileFacts(string csvPath, HashSet<string> seenParserNotes)
        {
            var rows = CorrelationCsvHelper.ReadCsv(csvPath);
            for (int i = 0; i < rows.Count; i++)
            {
                var row = rows[i];
                string path = CorrelationCsvHelper.Get(row, "Path");
                string fileName = CorrelationCsvHelper.Get(row, "FileName");
                string hash = CorrelationCsvHelper.Get(row, "Hash");
                string product = CorrelationCsvHelper.Get(row, "ProductName");
                string publisher = CorrelationCsvHelper.Get(row, "Publisher");
                string programId = CorrelationCsvHelper.Get(row, "ProgramId");
                string firstObserved = CorrelationCsvHelper.Get(row, "FirstObservedTime");
                string executed = CorrelationCsvHelper.Get(row, "ExecutedTime");
                string parserNote = CorrelationCsvHelper.Get(row, "ParserNote");
                string rawRef = ArtifactNames.AmcacheFilesCsv + ":" + (i + 2);

                if (IsNoteOnlyFileRow(path, fileName, hash, product, publisher, programId, firstObserved, executed, parserNote))
                {
                    if (TryMarkParserNote(seenParserNotes, parserNote))
                        yield return CreateParserNoteFact("file_note_" + i.ToString(), ArtifactNames.AmcacheFilesCsv, rawRef, parserNote);
                    continue;
                }

                if (IsEmpty(path, fileName, hash, programId, product, publisher))
                    continue;

                DateTime execTime = CorrelationCsvHelper.ParseDateTime(executed, DateTime.MinValue);
                DateTime firstSeenTime = CorrelationCsvHelper.ParseDateTime(firstObserved, DateTime.MinValue);

                if (FactTimeMetadata.HasUsableTime(execTime))
                {
                    var executedFact = CreateFileFact(i, "Executed", execTime, path, fileName, hash, product, publisher, programId, rawRef, parserNote);
                    yield return executedFact;
                }
                if (FactTimeMetadata.HasUsableTime(firstSeenTime))
                {
                    var firstFact = CreateFileFact(i, "FirstObserved", firstSeenTime, path, fileName, hash, product, publisher, programId, rawRef, parserNote);
                    yield return firstFact;
                }
                if (!FactTimeMetadata.HasUsableTime(execTime) && !FactTimeMetadata.HasUsableTime(firstSeenTime))
                {
                    var partial = CreateFileFact(i, "FirstObserved", DateTime.MinValue, path, fileName, hash, product, publisher, programId, rawRef, parserNote);
                    partial.FallbackUsed = true;
                    if (string.IsNullOrWhiteSpace(partial.ParserNote))
                        partial.ParserNote = "Amcache file row has no stable timestamp for executed/first-observed semantics.";
                    yield return partial;
                }
            }
        }

        private static Fact CreateFileFact(
            int rowIndex,
            string action,
            DateTime time,
            string path,
            string fileName,
            string hash,
            string product,
            string publisher,
            string programId,
            string rawRef,
            string parserNote)
        {
            var fact = new Fact(SourceName + "_file_" + action + "_" + rowIndex.ToString(), time, SourceName, action);
            FactTimeMetadata.Apply(
                fact,
                FactTimeMetadata.HasUsableTime(time) ? FactTimeMetadata.MetadataTimeKind : FactTimeMetadata.UnknownTimeKind,
                FactTimeMetadata.HasUsableTime(time) ? FactTimeMetadata.MediumConfidence : FactTimeMetadata.LowConfidence);
            fact.SourceFile = ArtifactNames.AmcacheFilesCsv;
            fact.RawRef = rawRef;
            fact.ParseLevel = FactProvenanceMetadata.RegistryValueParseLevel;
            fact.Details = BuildFileDetails(path, fileName, hash, product, publisher, programId);
            AddEntity(fact, "Path", path);
            AddEntity(fact, "FileName", fileName);
            AddEntity(fact, "Hash", hash);
            AddEntity(fact, "Publisher", publisher);
            AddEntity(fact, "ProductName", product);
            AddEntity(fact, "ProgramId", programId);
            if (!string.IsNullOrWhiteSpace(parserNote))
                fact.ParserNote = parserNote;
            if (!FactTimeMetadata.HasUsableTime(time))
                fact.FallbackUsed = true;
            return fact;
        }

        private static string BuildProgramDetails(string name, string publisher, string version, string product, string programId)
        {
            return string.Format("Program={0}; Publisher={1}; Version={2}; Product={3}; ProgramId={4}",
                name ?? "", publisher ?? "", version ?? "", product ?? "", programId ?? "");
        }

        private static string BuildFileDetails(string path, string fileName, string hash, string product, string publisher, string programId)
        {
            return string.Format("Path={0}; File={1}; Hash={2}; Product={3}; Publisher={4}; ProgramId={5}",
                path ?? "", fileName ?? "", hash ?? "", product ?? "", publisher ?? "", programId ?? "");
        }

        private static Fact CreateParserNoteFact(string idSuffix, string sourceFile, string rawRef, string parserNote)
        {
            var fact = new Fact(SourceName + "_" + idSuffix, DateTime.MinValue, SourceName, "ParseNoteObserved");
            FactTimeMetadata.Apply(fact, FactTimeMetadata.UnknownTimeKind, FactTimeMetadata.LowConfidence);
            fact.SourceFile = sourceFile;
            fact.RawRef = rawRef;
            fact.ParseLevel = FactProvenanceMetadata.RawArtifactDerivedParseLevel;
            fact.FallbackUsed = true;
            fact.ParserNote = parserNote;
            fact.Details = parserNote;
            return fact;
        }

        private static bool IsNoteOnlyProgramRow(string name, string publisher, string version, string product, string installDate, string programId, string parserNote)
        {
            return IsEmpty(name, publisher, version, product, installDate, programId) && !string.IsNullOrWhiteSpace(parserNote);
        }

        private static bool IsNoteOnlyFileRow(string path, string fileName, string hash, string product, string publisher, string programId, string firstObserved, string executed, string parserNote)
        {
            return IsEmpty(path, fileName, hash, product, publisher, programId, firstObserved, executed) && !string.IsNullOrWhiteSpace(parserNote);
        }

        private static bool TryMarkParserNote(HashSet<string> seenParserNotes, string parserNote)
        {
            if (string.IsNullOrWhiteSpace(parserNote))
                return false;
            if (seenParserNotes == null)
                return true;
            return seenParserNotes.Add(parserNote.Trim());
        }

        private static void AddEntity(Fact fact, string type, string value)
        {
            if (fact == null || string.IsNullOrWhiteSpace(value))
                return;
            fact.AddEntity(type, value.Trim());
        }

        private static bool IsEmpty(params string[] values)
        {
            if (values == null) return true;
            foreach (string value in values)
            {
                if (!string.IsNullOrWhiteSpace(value))
                    return false;
            }
            return true;
        }
    }
}
