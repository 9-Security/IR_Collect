using System;
using System.Collections.Generic;
using System.Runtime.Serialization;

namespace IR_Collect.Analysis.Correlation
{
    /// <summary>
    /// 實體參考：用於跨來源串接（同一 Path/Hash/User 在不同 LOG 的出現）
    /// </summary>
    [DataContract]
    public class EntityRef
    {
        [DataMember] public string Type { get; set; }
        [DataMember] public string Value { get; set; }

        public EntityRef() { }

        public EntityRef(string type, string value)
        {
            Type = type ?? "";
            Value = value ?? "";
        }

        /// <summary>產生索引用鍵，例如 "Path:c:\windows\system32\cmd.exe" </summary>
        public string ToEntityKey()
        {
            if (string.IsNullOrEmpty(Value)) return null;
            string norm = (Value ?? "").Trim().ToLowerInvariant();
            if (string.IsNullOrEmpty(norm)) return null;
            return (Type ?? "Unknown") + ":" + norm;
        }
    }

    /// <summary>
    /// 統一事實：單一可分析事件，來自任一本專案支援的來源（Process, MFT, EventLog, Autorun, ...）
    /// </summary>
    [DataContract]
    public class Fact
    {
        [DataMember] public string Id { get; set; }
        [DataMember] public DateTime Time { get; set; }
        [DataMember] public string TimeKind { get; set; }
        [DataMember] public string TimeConfidence { get; set; }
        [DataMember] public string Source { get; set; }
        [DataMember] public string Action { get; set; }
        [DataMember] public List<EntityRef> EntityRefs { get; set; }
        [DataMember] public string SourceFile { get; set; }
        [DataMember] public string CollectionStep { get; set; }
        [DataMember] public string CollectionStatus { get; set; }
        [DataMember] public string CollectionPrivilege { get; set; }
        [DataMember] public string ParseLevel { get; set; }
        [DataMember] public bool FallbackUsed { get; set; }
        [DataMember] public string ParserNote { get; set; }
        [DataMember] public string Details { get; set; }
        [DataMember] public string RawRef { get; set; }

        public Fact()
        {
            EntityRefs = new List<EntityRef>();
            TimeKind = FactTimeMetadata.UnknownTimeKind;
            TimeConfidence = FactTimeMetadata.UnknownConfidence;
            CollectionStatus = "unknown";
            CollectionPrivilege = "unknown";
            ParseLevel = FactProvenanceMetadata.UnknownParseLevel;
        }

        public Fact(string id, DateTime time, string source, string action)
            : this()
        {
            Id = id;
            Time = time;
            Source = source ?? "";
            Action = action ?? "";
        }

        public void AddEntity(string type, string value)
        {
            if (string.IsNullOrEmpty(value)) return;
            EntityRefs.Add(new EntityRef(type, value));
        }
    }

    public static class FactProvenanceMetadata
    {
        public const string StructuredParseLevel = "Structured";
        public const string StructuredXmlParseLevel = "StructuredXml";
        public const string RegistryValueParseLevel = "RegistryValue";
        public const string MetadataDerivedParseLevel = "MetadataDerived";
        public const string SynthesizedParseLevel = "Synthesized";
        public const string RawArtifactDerivedParseLevel = "RawArtifactDerived";
        public const string UnknownParseLevel = "Unknown";

        public static string NormalizeParseLevel(string value)
        {
            switch ((value ?? "").Trim())
            {
                case StructuredParseLevel:
                    return StructuredParseLevel;
                case StructuredXmlParseLevel:
                    return StructuredXmlParseLevel;
                case RegistryValueParseLevel:
                    return RegistryValueParseLevel;
                case MetadataDerivedParseLevel:
                    return MetadataDerivedParseLevel;
                case SynthesizedParseLevel:
                    return SynthesizedParseLevel;
                case RawArtifactDerivedParseLevel:
                    return RawArtifactDerivedParseLevel;
                default:
                    return UnknownParseLevel;
            }
        }
    }

    public static class FactTimeMetadata
    {
        public const string EventTimeKind = "EventTime";
        public const string MetadataTimeKind = "MetadataTime";
        public const string ObservedTimeKind = "ObservedTime";
        public const string UnknownTimeKind = "UnknownTime";

        public const string HighConfidence = "High";
        public const string MediumConfidence = "Medium";
        public const string LowConfidence = "Low";
        public const string UnknownConfidence = "Unknown";

        public static bool HasUsableTime(DateTime time)
        {
            return time.Year > 1980 && time != DateTime.MinValue && time != DateTime.MaxValue;
        }

        public static void Apply(Fact fact, string timeKind, string timeConfidence)
        {
            if (fact == null) return;
            fact.TimeKind = NormalizeTimeKind(timeKind);
            fact.TimeConfidence = NormalizeTimeConfidence(timeConfidence);
        }

        public static void ApplyDefaultsIfMissing(Fact fact)
        {
            if (fact == null) return;
            if (string.IsNullOrWhiteSpace(fact.TimeKind))
                fact.TimeKind = InferTimeKind(fact.Source, fact.Time);
            else
                fact.TimeKind = NormalizeTimeKind(fact.TimeKind);

            if (string.IsNullOrWhiteSpace(fact.TimeConfidence))
                fact.TimeConfidence = InferTimeConfidence(fact.Source, fact.Time);
            else
                fact.TimeConfidence = NormalizeTimeConfidence(fact.TimeConfidence);
        }

        public static string InferTimeKind(string source, DateTime time)
        {
            string normalized = NormalizeSource(source);
            bool hasTime = HasUsableTime(time);

            if (normalized.StartsWith("eventlog", StringComparison.OrdinalIgnoreCase))
                return hasTime ? EventTimeKind : UnknownTimeKind;

            switch (normalized)
            {
                case "process":
                    return hasTime ? EventTimeKind : UnknownTimeKind;
                case "mft":
                case "prefetch":
                case "jumplist":
                case "jump_list":
                case "userassist":
                    return hasTime ? MetadataTimeKind : UnknownTimeKind;
                case "recentfiles":
                    return hasTime ? MetadataTimeKind : UnknownTimeKind;
                case "autorun":
                case "scheduledtask":
                case "runmru":
                case "recentdocs":
                    return hasTime ? ObservedTimeKind : UnknownTimeKind;
                default:
                    return hasTime ? ObservedTimeKind : UnknownTimeKind;
            }
        }

        public static string InferTimeConfidence(string source, DateTime time)
        {
            string normalized = NormalizeSource(source);
            bool hasTime = HasUsableTime(time);

            if (!hasTime) return LowConfidence;
            if (normalized.StartsWith("eventlog", StringComparison.OrdinalIgnoreCase))
                return HighConfidence;

            switch (normalized)
            {
                case "process":
                    return HighConfidence;
                case "mft":
                case "prefetch":
                case "jumplist":
                case "jump_list":
                case "userassist":
                    return MediumConfidence;
                case "recentfiles":
                    return LowConfidence;
                case "autorun":
                case "scheduledtask":
                case "runmru":
                case "recentdocs":
                    return LowConfidence;
                default:
                    return MediumConfidence;
            }
        }

        public static string NormalizeTimeKind(string value)
        {
            switch ((value ?? "").Trim())
            {
                case EventTimeKind:
                    return EventTimeKind;
                case MetadataTimeKind:
                    return MetadataTimeKind;
                case ObservedTimeKind:
                    return ObservedTimeKind;
                case UnknownTimeKind:
                    return UnknownTimeKind;
                default:
                    return UnknownTimeKind;
            }
        }

        public static string NormalizeTimeConfidence(string value)
        {
            switch ((value ?? "").Trim())
            {
                case HighConfidence:
                    return HighConfidence;
                case MediumConfidence:
                    return MediumConfidence;
                case LowConfidence:
                    return LowConfidence;
                case UnknownConfidence:
                    return UnknownConfidence;
                default:
                    return UnknownConfidence;
            }
        }

        private static string NormalizeSource(string source)
        {
            return (source ?? "").Trim().ToLowerInvariant();
        }
    }
}
