using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;
using IR_Collect.Analysis.Correlation;
using IR_Collect;

namespace IR_Collect.Analysis
{
    [DataContract]
    public class SummaryPayload
    {
        [DataMember(Name = "generated_at")]
        public string GeneratedAt { get; set; }
        [DataMember(Name = "export_schema")]
        public string ExportSchema { get; set; }
        [DataMember(Name = "analysis_mode")]
        public string AnalysisMode { get; set; }
        /// <summary>Case collection mode profile when recorded in collection_coverage.json (Standard, TriageFast, ForensicStrict).</summary>
        [DataMember(Name = "collection_mode_profile")]
        public string CollectionModeProfile { get; set; }
        [DataMember(Name = "host")]
        public string Host { get; set; }
        [DataMember(Name = "case_id")]
        public string CaseId { get; set; }
        [DataMember(Name = "artifacts_count")]
        public int ArtifactsCount { get; set; }
        [DataMember(Name = "mft_count")]
        public int MftCount { get; set; }
        [DataMember(Name = "mft_latest")]
        public string MftLatest { get; set; }
        [DataMember(Name = "counts")]
        public Dictionary<string, int> Counts { get; set; }
        [DataMember(Name = "event_highlights")]
        public List<string> EventHighlights { get; set; }
        [DataMember(Name = "load_warnings")]
        public List<string> LoadWarnings { get; set; }
        [DataMember(Name = "collection_coverage")]
        public CollectionCoverageReport CollectionCoverage { get; set; }
        [DataMember(Name = "fact_store_status")]
        public string FactStoreStatus { get; set; }
        [DataMember(Name = "fact_store_freshness_status")]
        public string FactStoreFreshnessStatus { get; set; }
        [DataMember(Name = "fact_store_freshness_detail")]
        public string FactStoreFreshnessDetail { get; set; }
        [DataMember(Name = "fact_count")]
        public int FactCount { get; set; }
        [DataMember(Name = "fact_source_counts")]
        public Dictionary<string, int> FactSourceCounts { get; set; }
        [DataMember(Name = "entity_type_counts")]
        public Dictionary<string, int> EntityTypeCounts { get; set; }
        [DataMember(Name = "parser_notes")]
        public List<string> ParserNotes { get; set; }
        [DataMember(Name = "fact_samples")]
        public List<Fact> FactSamples { get; set; }
        [DataMember(Name = "analyst_workflow")]
        public AnalystWorkflowState AnalystWorkflow { get; set; }
        [DataMember(Name = "guided_hunt")]
        public GuidedHuntResult GuidedHunt { get; set; }
        [DataMember(Name = "memory_acquisition")]
        public MemoryAcquisitionRecord MemoryAcquisition { get; set; }
        [DataMember(Name = "memory_analysis")]
        public MemoryAnalysisRecord MemoryAnalysis { get; set; }
    }

    public static class SummaryExport
    {
        /// <summary>Deep copy with safe fact times (used before AI redaction / serialization).</summary>
        public static SummaryPayload CloneForSerialization(SummaryPayload payload)
        {
            return ClonePayloadWithSafeFactTimes(payload);
        }

        public static string Serialize(SummaryPayload payload)
        {
            payload = ClonePayloadWithSafeFactTimes(payload);
            var serializer = new DataContractJsonSerializer(typeof(SummaryPayload));
            using (var ms = new MemoryStream())
            {
                serializer.WriteObject(ms, payload);
                return Encoding.UTF8.GetString(ms.ToArray());
            }
        }

        public static void SaveToFile(SummaryPayload payload, string path)
        {
            var json = Serialize(payload);
            File.WriteAllText(path, json, new UTF8Encoding(false));
        }

        private static SummaryPayload ClonePayloadWithSafeFactTimes(SummaryPayload payload)
        {
            if (payload == null)
                return null;

            var copy = new SummaryPayload();
            copy.GeneratedAt = payload.GeneratedAt;
            copy.ExportSchema = payload.ExportSchema;
            copy.AnalysisMode = payload.AnalysisMode;
            copy.CollectionModeProfile = payload.CollectionModeProfile;
            copy.Host = payload.Host;
            copy.CaseId = payload.CaseId;
            copy.ArtifactsCount = payload.ArtifactsCount;
            copy.MftCount = payload.MftCount;
            copy.MftLatest = payload.MftLatest;
            copy.Counts = payload.Counts;
            copy.EventHighlights = payload.EventHighlights;
            copy.LoadWarnings = payload.LoadWarnings;
            copy.CollectionCoverage = payload.CollectionCoverage;
            copy.FactStoreStatus = payload.FactStoreStatus;
            copy.FactStoreFreshnessStatus = payload.FactStoreFreshnessStatus;
            copy.FactStoreFreshnessDetail = payload.FactStoreFreshnessDetail;
            copy.FactCount = payload.FactCount;
            copy.FactSourceCounts = payload.FactSourceCounts;
            copy.EntityTypeCounts = payload.EntityTypeCounts;
            copy.ParserNotes = payload.ParserNotes;
            copy.AnalystWorkflow = payload.AnalystWorkflow;
            copy.GuidedHunt = payload.GuidedHunt;
            copy.MemoryAcquisition = payload.MemoryAcquisition;
            copy.MemoryAnalysis = payload.MemoryAnalysis;
            copy.FactSamples = CopyFactsWithSafeTimes(payload.FactSamples);
            return copy;
        }

        private static List<Fact> CopyFactsWithSafeTimes(IEnumerable<Fact> facts)
        {
            var safeFacts = new List<Fact>();
            if (facts == null)
                return safeFacts;

            DateTime safeEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            foreach (Fact fact in facts)
            {
                Fact copy = CopyFactWithSafeTime(fact, safeEpoch);
                if (copy != null)
                    safeFacts.Add(copy);
            }
            return safeFacts;
        }

        private static Fact CopyFactWithSafeTime(Fact fact, DateTime safeEpoch)
        {
            if (fact == null)
                return null;

            FactTimeMetadata.ApplyDefaultsIfMissing(fact);
            DateTime safeTime = FactStorePersistence.NormalizeFactTimeForJson(fact.Time, safeEpoch);
            var copy = new Fact(fact.Id, safeTime, fact.Source, fact.Action);
            copy.TimeKind = fact.TimeKind;
            copy.TimeConfidence = fact.TimeConfidence;
            copy.SourceFile = fact.SourceFile;
            copy.CollectionStep = fact.CollectionStep;
            copy.CollectionStatus = fact.CollectionStatus;
            copy.CollectionPrivilege = fact.CollectionPrivilege;
            copy.ParseLevel = fact.ParseLevel;
            copy.FallbackUsed = fact.FallbackUsed;
            copy.ParserNote = fact.ParserNote;
            copy.Details = fact.Details;
            copy.RawRef = fact.RawRef;
            if (fact.EntityRefs != null)
            {
                copy.EntityRefs = new List<EntityRef>();
                foreach (EntityRef entity in fact.EntityRefs)
                    copy.EntityRefs.Add(new EntityRef(entity.Type, entity.Value));
            }
            return copy;
        }
    }
}
