using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using IR_Collect.Analysis;

namespace IR_Collect.Analysis.Correlation
{
    public static class DiffBuilder
    {
        public const int DefaultMaxChanges = 50000;
        private const int MaxFactReferencesPerSide = 20;

        private sealed class FactBucket
        {
            public string Category;
            public string EntityKey;
            public string DisplayValue;
            public List<Fact> Facts = new List<Fact>();
            public HashSet<string> StateSignatures = new HashSet<string>(StringComparer.Ordinal);
            public HashSet<string> Sources = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }

        public static DiffReport Build(CaseData baseline, CaseData target)
        {
            return Build(baseline, target, DefaultMaxChanges);
        }

        public static DiffReport Build(CaseData baseline, CaseData target, int maxChanges)
        {
            if (baseline == null) throw new ArgumentNullException("baseline");
            if (target == null) throw new ArgumentNullException("target");
            if (baseline.FactStore == null || baseline.FactStore.Facts == null)
                throw new InvalidOperationException("Baseline Fact Store is not ready.");
            if (target.FactStore == null || target.FactStore.Facts == null)
                throw new InvalidOperationException("Target Fact Store is not ready.");
            if (maxChanges <= 0) maxChanges = DefaultMaxChanges;

            Dictionary<string, FactBucket> baselineBuckets = BuildBuckets(baseline.FactStore.Facts);
            Dictionary<string, FactBucket> targetBuckets = BuildBuckets(target.FactStore.Facts);
            HashSet<string> baselineSources = BuildSourceSet(baseline.FactStore.Facts);
            HashSet<string> targetSources = BuildSourceSet(target.FactStore.Facts);
            var keys = new HashSet<string>(baselineBuckets.Keys, StringComparer.OrdinalIgnoreCase);
            keys.UnionWith(targetBuckets.Keys);

            var changes = new List<DiffChange>();
            foreach (string key in keys)
            {
                FactBucket before;
                FactBucket after;
                baselineBuckets.TryGetValue(key, out before);
                targetBuckets.TryGetValue(key, out after);
                if (before != null && after != null && before.StateSignatures.SetEquals(after.StateSignatures))
                    continue;

                string changeType = before == null ? "Added" : (after == null ? "Removed" : "Modified");
                FactBucket identity = after ?? before;
                var change = new DiffChange
                {
                    Category = identity.Category,
                    ChangeType = changeType,
                    EntityKey = identity.EntityKey,
                    DisplayValue = identity.DisplayValue,
                    BaselineFactCount = before != null ? before.Facts.Count : 0,
                    TargetFactCount = after != null ? after.Facts.Count : 0,
                    Confidence = ResolveConfidence(changeType, before, after, baselineSources, targetSources)
                };

                change.SourceNames = UnionSources(before, after);
                change.BaselineFactRefs = BuildFactReferences(before);
                change.TargetFactRefs = BuildFactReferences(after);
                AddNotes(change, before, after, baselineSources, targetSources);
                changes.Add(change);
            }

            changes = changes
                .OrderBy(x => ChangeTypeRank(x.ChangeType))
                .ThenBy(x => CategoryRank(x.Category))
                .ThenBy(x => x.DisplayValue ?? "", StringComparer.OrdinalIgnoreCase)
                .ThenBy(x => x.EntityKey ?? "", StringComparer.OrdinalIgnoreCase)
                .ToList();

            var report = new DiffReport
            {
                DiffSchema = "diff_v1",
                GeneratedAt = DateTime.UtcNow.ToString("o"),
                ToolName = BuildInfo.ToolName,
                ToolVersion = BuildInfo.Version,
                AnalysisMode = "facts_only",
                BaselineRef = CreateCaseReference(baseline),
                TargetRef = CreateCaseReference(target),
                ChangeCount = changes.Count,
                ChangesTruncated = changes.Count > maxChanges,
                MaxChanges = maxChanges,
                Changes = changes.Take(maxChanges).ToList()
            };
            return report;
        }

        private static Dictionary<string, FactBucket> BuildBuckets(IEnumerable<Fact> facts)
        {
            var buckets = new Dictionary<string, FactBucket>(StringComparer.OrdinalIgnoreCase);
            foreach (Fact fact in facts ?? Enumerable.Empty<Fact>())
            {
                if (fact == null) continue;
                string category = Classify(fact);
                EntityRef identity = SelectIdentity(fact, category);
                string entityKey;
                string displayValue;
                if (identity != null && !string.IsNullOrWhiteSpace(identity.Value))
                {
                    entityKey = (identity.Type ?? "Unknown") + ":" + Normalize(identity.Value);
                    displayValue = identity.Value.Trim();
                }
                else
                {
                    string fingerprintSource = Normalize(fact.Source) + "|" + Normalize(fact.Action) + "|" + Normalize(fact.Details);
                    entityKey = "FactFingerprint:" + Hash(fingerprintSource).Substring(0, 24);
                    displayValue = !string.IsNullOrWhiteSpace(fact.Details)
                        ? Limit(fact.Details.Trim(), 240)
                        : ((fact.Source ?? "(unknown)") + " / " + (fact.Action ?? "(unknown)"));
                }

                string bucketKey = category + "|" + entityKey;
                FactBucket bucket;
                if (!buckets.TryGetValue(bucketKey, out bucket))
                {
                    bucket = new FactBucket
                    {
                        Category = category,
                        EntityKey = entityKey,
                        DisplayValue = displayValue
                    };
                    buckets[bucketKey] = bucket;
                }
                bucket.Facts.Add(fact);
                bucket.StateSignatures.Add(BuildStateSignature(fact));
                if (!string.IsNullOrWhiteSpace(fact.Source)) bucket.Sources.Add(fact.Source.Trim());
            }
            return buckets;
        }

        private static string Classify(Fact fact)
        {
            string source = Normalize(fact != null ? fact.Source : "");
            if (source == "process" || source == "prefetch" || source == "userassist" ||
                source == "bamdam" || source == "bam/dam")
                return "Process";
            if (source.Contains("autorun") || source.Contains("service") || source.Contains("scheduledtask") ||
                source.Contains("persistence") || source.Contains("wmipersistence") || source.Contains("bitsjob"))
                return "Persistence";
            if (source.Contains("network") || source.Contains("srum") || source.Contains("serverconnection") ||
                source.Contains("networkresource") || HasEntity(fact, "RemoteIP", "RemoteAddress", "IP", "TargetServer", "ShareName"))
                return "Network";
            if (source.Contains("account") || source.Contains("logon") || source.Contains("login") ||
                HasEntity(fact, "SID", "User", "TargetUser", "GroupName", "Account"))
            {
                if (!HasEntity(fact, "Path", "Hash", "RemoteIP", "RemoteAddress", "IP"))
                    return "Identity";
            }
            if (source == "mft" || source.Contains("amcache") || source.Contains("shimcache") ||
                source.Contains("usn") || source.Contains("recentfile") || source.Contains("jumplist") ||
                source.Contains("shellbags") || source.Contains("uacevidence") ||
                HasEntity(fact, "Path", "Hash"))
                return "File";
            return "Fact";
        }

        private static EntityRef SelectIdentity(Fact fact, string category)
        {
            string[] preferred;
            switch (category)
            {
                case "Process":
                    preferred = new string[] { "Path", "CommandLine", "Hash", "ProcessName" };
                    break;
                case "Persistence":
                    preferred = new string[] { "RegistryKey", "ServiceName", "TaskName", "PersistenceName", "Hash", "Path", "CommandLine" };
                    break;
                case "File":
                    preferred = new string[] { "Path", "Hash", "FileName" };
                    break;
                case "Identity":
                    preferred = new string[] { "User", "SID", "TargetUser", "Account", "GroupName" };
                    break;
                case "Network":
                    preferred = new string[] { "RemoteIP", "RemoteAddress", "IP", "TargetServer", "RemoteName", "ShareName", "URL" };
                    break;
                default:
                    preferred = new string[0];
                    break;
            }

            foreach (string type in preferred)
            {
                EntityRef match = (fact.EntityRefs ?? new List<EntityRef>())
                    .FirstOrDefault(x => x != null && !string.IsNullOrWhiteSpace(x.Value) &&
                        string.Equals(x.Type, type, StringComparison.OrdinalIgnoreCase));
                if (match != null) return match;
            }
            return (fact.EntityRefs ?? new List<EntityRef>())
                .Where(x => x != null && !string.IsNullOrWhiteSpace(x.Value))
                .OrderBy(x => x.Type ?? "", StringComparer.OrdinalIgnoreCase)
                .ThenBy(x => x.Value ?? "", StringComparer.OrdinalIgnoreCase)
                .FirstOrDefault();
        }

        private static string BuildStateSignature(Fact fact)
        {
            var entities = (fact.EntityRefs ?? new List<EntityRef>())
                .Where(x => x != null && !string.IsNullOrWhiteSpace(x.Value))
                .Select(x => Normalize(x.Type) + ":" + Normalize(x.Value))
                .Distinct(StringComparer.Ordinal)
                .OrderBy(x => x, StringComparer.Ordinal)
                .ToArray();
            string state = Normalize(fact.Source) + "|" + Normalize(fact.Action) + "|" +
                string.Join("|", entities) + "|" + Normalize(fact.Details);
            return Hash(state);
        }

        private static List<DiffFactReference> BuildFactReferences(FactBucket bucket)
        {
            if (bucket == null) return new List<DiffFactReference>();
            return bucket.Facts
                .OrderBy(x => x.Source ?? "", StringComparer.OrdinalIgnoreCase)
                .ThenBy(x => x.RawRef ?? "", StringComparer.OrdinalIgnoreCase)
                .ThenBy(x => x.Id ?? "", StringComparer.OrdinalIgnoreCase)
                .Take(MaxFactReferencesPerSide)
                .Select(x => new DiffFactReference
                {
                    Id = x.Id ?? "",
                    Source = x.Source ?? "",
                    Action = x.Action ?? "",
                    SourceFile = x.SourceFile ?? "",
                    RawRef = x.RawRef ?? "",
                    CollectionStep = x.CollectionStep ?? "",
                    CollectionStatus = x.CollectionStatus ?? "",
                    CollectionPrivilege = x.CollectionPrivilege ?? "",
                    ParseLevel = x.ParseLevel ?? "",
                    FallbackUsed = x.FallbackUsed,
                    ParserNote = x.ParserNote ?? ""
                }).ToList();
        }

        private static List<string> UnionSources(FactBucket before, FactBucket after)
        {
            var sources = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (before != null) sources.UnionWith(before.Sources);
            if (after != null) sources.UnionWith(after.Sources);
            return sources.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList();
        }

        private static HashSet<string> BuildSourceSet(IEnumerable<Fact> facts)
        {
            return new HashSet<string>((facts ?? Enumerable.Empty<Fact>())
                .Where(x => x != null && !string.IsNullOrWhiteSpace(x.Source))
                .Select(x => x.Source.Trim()), StringComparer.OrdinalIgnoreCase);
        }

        private static string ResolveConfidence(
            string changeType,
            FactBucket before,
            FactBucket after,
            HashSet<string> baselineSources,
            HashSet<string> targetSources)
        {
            if (string.Equals(changeType, "Modified", StringComparison.Ordinal))
            {
                if (before != null && after != null && before.Sources.SetEquals(after.Sources))
                    return "High";
                if (before != null && after != null && before.Sources.Overlaps(after.Sources))
                    return "Medium";
                return "Low";
            }
            FactBucket observed = after ?? before;
            HashSet<string> opposite = after != null ? baselineSources : targetSources;
            return observed != null && observed.Sources.All(x => opposite.Contains(x)) ? "Medium" : "Low";
        }

        private static void AddNotes(
            DiffChange change,
            FactBucket before,
            FactBucket after,
            HashSet<string> baselineSources,
            HashSet<string> targetSources)
        {
            if (string.Equals(change.ChangeType, "Modified", StringComparison.Ordinal))
            {
                change.Notes.Add("The same normalized entity key was observed in both cases with different action, details, source, or entity state.");
                if (before != null && after != null && !before.Sources.SetEquals(after.Sources))
                    change.Notes.Add("Contributing source sets differ between the cases; review collection and parser coverage before treating this as a state change.");
                return;
            }

            change.Notes.Add(string.Equals(change.ChangeType, "Added", StringComparison.Ordinal)
                ? "Observed in the target and not observed in the baseline under the same normalized entity key."
                : "Observed in the baseline and not observed in the target under the same normalized entity key.");
            change.Notes.Add("Not observed does not prove absence; collection and parser coverage must be reviewed.");

            FactBucket observed = after ?? before;
            HashSet<string> opposite = after != null ? baselineSources : targetSources;
            if (observed != null && observed.Sources.Any(x => !opposite.Contains(x)))
                change.Notes.Add("At least one contributing source was not represented in the opposite Fact Store; this change has low confidence.");
        }

        private static DiffCaseReference CreateCaseReference(CaseData c)
        {
            return new DiffCaseReference
            {
                Host = c.Hostname ?? "",
                CaseId = c.CaseID ?? "",
                FactCount = c.FactStore != null ? c.FactStore.Count : 0,
                EvidenceDigest = c.EvidenceDigest ?? "",
                SourceFormat = c.SourceFormat ?? "",
                SourceEvidenceSha256 = c.SourceEvidenceSha256 ?? "",
                CollectionCoverageStatus = c.CollectionCoverage != null
                    ? (c.CollectionCoverage.OverallStatus ?? "")
                    : "",
                FactStoreFreshnessStatus = c.FactStoreFreshnessStatus ?? "",
                FactStoreBuildMode = c.FactStoreBuildMode ?? ""
            };
        }

        private static bool HasEntity(Fact fact, params string[] types)
        {
            if (fact == null || fact.EntityRefs == null) return false;
            return fact.EntityRefs.Any(entity => entity != null && !string.IsNullOrWhiteSpace(entity.Value) &&
                types.Any(type => string.Equals(type, entity.Type, StringComparison.OrdinalIgnoreCase)));
        }

        private static int ChangeTypeRank(string value)
        {
            if (string.Equals(value, "Added", StringComparison.Ordinal)) return 0;
            if (string.Equals(value, "Modified", StringComparison.Ordinal)) return 1;
            return 2;
        }

        private static int CategoryRank(string value)
        {
            if (string.Equals(value, "Process", StringComparison.Ordinal)) return 0;
            if (string.Equals(value, "Persistence", StringComparison.Ordinal)) return 1;
            if (string.Equals(value, "File", StringComparison.Ordinal)) return 2;
            if (string.Equals(value, "Identity", StringComparison.Ordinal)) return 3;
            if (string.Equals(value, "Network", StringComparison.Ordinal)) return 4;
            return 5;
        }

        private static string Normalize(string value)
        {
            if (string.IsNullOrWhiteSpace(value)) return "";
            var builder = new StringBuilder(value.Length);
            bool whitespace = false;
            foreach (char c in value.Trim())
            {
                if (char.IsWhiteSpace(c))
                {
                    if (!whitespace) builder.Append(' ');
                    whitespace = true;
                }
                else
                {
                    builder.Append(char.ToLowerInvariant(c));
                    whitespace = false;
                }
            }
            return builder.ToString();
        }

        private static string Hash(string value)
        {
            using (SHA256 sha = SHA256.Create())
            {
                byte[] bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(value ?? ""));
                var builder = new StringBuilder(bytes.Length * 2);
                foreach (byte b in bytes) builder.Append(b.ToString("x2"));
                return builder.ToString();
            }
        }

        private static string Limit(string value, int max)
        {
            if (string.IsNullOrEmpty(value) || value.Length <= max) return value ?? "";
            return value.Substring(0, max - 3) + "...";
        }
    }
}
