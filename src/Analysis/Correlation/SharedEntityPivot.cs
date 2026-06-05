using System;
using System.Collections.Generic;
using System.Linq;
using IR_Collect.Analysis;

namespace IR_Collect.Analysis.Correlation
{
    public sealed class SharedEntityPivotOptions
    {
        public string SourcePrefixFilter { get; set; }
        public string TimeConfidenceFilter { get; set; }
        public string HostFilter { get; set; }
        public bool UseFromTime { get; set; }
        public DateTime FromTime { get; set; }
        public bool UseToTime { get; set; }
        public DateTime ToTime { get; set; }
        public int MaxResults { get; set; }
        public int BucketMinutes { get; set; }

        public SharedEntityPivotOptions()
        {
            MaxResults = 250;
            BucketMinutes = 30;
        }
    }

    public sealed class SharedEntityPivotItem
    {
        public string EntityType { get; set; }
        public string NormalizedValue { get; set; }
        public string DisplayValue { get; set; }
        public int FactCount { get; set; }
        public List<string> Hosts { get; set; }
        public List<string> Sources { get; set; }
        public DateTime FirstSeen { get; set; }
        public DateTime LastSeen { get; set; }

        public SharedEntityPivotItem()
        {
            Hosts = new List<string>();
            Sources = new List<string>();
            FirstSeen = DateTime.MinValue;
            LastSeen = DateTime.MinValue;
        }
    }

    public sealed class SharedEntityPivotResult
    {
        public List<SharedEntityPivotItem> Items { get; set; }
        public int ReadyHosts { get; set; }
        public int SkippedHosts { get; set; }
        public int TotalSharedEntities { get; set; }

        public SharedEntityPivotResult()
        {
            Items = new List<SharedEntityPivotItem>();
        }
    }

    public sealed class SharedEntityFactHit
    {
        public string Hostname { get; set; }
        public CaseData CaseData { get; set; }
        public Fact Fact { get; set; }
    }

    public sealed class RelatedEntityPivotItem
    {
        public string RelatedType { get; set; }
        public string NormalizedValue { get; set; }
        public string DisplayValue { get; set; }
        public int FactCount { get; set; }
        public List<string> Hosts { get; set; }
        public List<string> Sources { get; set; }
        public DateTime FirstSeen { get; set; }
        public DateTime LastSeen { get; set; }

        public RelatedEntityPivotItem()
        {
            Hosts = new List<string>();
            Sources = new List<string>();
            FirstSeen = DateTime.MinValue;
            LastSeen = DateTime.MinValue;
        }
    }

    public sealed class TemporalSharedEntityPivotItem
    {
        public string EntityType { get; set; }
        public string NormalizedValue { get; set; }
        public string DisplayValue { get; set; }
        public int FactCount { get; set; }
        public List<string> Hosts { get; set; }
        public List<string> Sources { get; set; }
        public DateTime BucketStart { get; set; }
        public DateTime BucketEnd { get; set; }
        public DateTime FirstSeen { get; set; }
        public DateTime LastSeen { get; set; }

        public TemporalSharedEntityPivotItem()
        {
            Hosts = new List<string>();
            Sources = new List<string>();
            BucketStart = DateTime.MinValue;
            BucketEnd = DateTime.MinValue;
            FirstSeen = DateTime.MinValue;
            LastSeen = DateTime.MinValue;
        }
    }

    internal sealed class SharedEntityPivotAccumulator
    {
        public string EntityType { get; set; }
        public string NormalizedValue { get; set; }
        public string DisplayValue { get; set; }
        public int FactCount { get; set; }
        public HashSet<string> Hosts { get; private set; }
        public HashSet<string> Sources { get; private set; }
        public DateTime FirstSeen { get; set; }
        public DateTime LastSeen { get; set; }

        public SharedEntityPivotAccumulator()
        {
            Hosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            Sources = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            FirstSeen = DateTime.MaxValue;
            LastSeen = DateTime.MinValue;
        }
    }

    internal sealed class RelatedEntityPivotAccumulator
    {
        public string RelatedType { get; set; }
        public string NormalizedValue { get; set; }
        public string DisplayValue { get; set; }
        public int FactCount { get; set; }
        public HashSet<string> Hosts { get; private set; }
        public HashSet<string> Sources { get; private set; }
        public DateTime FirstSeen { get; set; }
        public DateTime LastSeen { get; set; }

        public RelatedEntityPivotAccumulator()
        {
            Hosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            Sources = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            FirstSeen = DateTime.MaxValue;
            LastSeen = DateTime.MinValue;
        }
    }

    internal sealed class TemporalSharedEntityPivotAccumulator
    {
        public string EntityType { get; set; }
        public string NormalizedValue { get; set; }
        public string DisplayValue { get; set; }
        public int FactCount { get; set; }
        public HashSet<string> Hosts { get; private set; }
        public HashSet<string> Sources { get; private set; }
        public DateTime BucketStart { get; set; }
        public DateTime BucketEnd { get; set; }
        public DateTime FirstSeen { get; set; }
        public DateTime LastSeen { get; set; }

        public TemporalSharedEntityPivotAccumulator()
        {
            Hosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            Sources = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            BucketStart = DateTime.MinValue;
            BucketEnd = DateTime.MinValue;
            FirstSeen = DateTime.MaxValue;
            LastSeen = DateTime.MinValue;
        }
    }

    public static class SharedEntityPivotBuilder
    {
        public static SharedEntityPivotResult Build(IEnumerable<CaseData> cases, string entityType, string filter, int maxResults)
        {
            var options = new SharedEntityPivotOptions();
            options.MaxResults = maxResults > 0 ? maxResults : 250;
            return Build(cases, entityType, filter, options);
        }

        public static SharedEntityPivotResult Build(IEnumerable<CaseData> cases, string entityType, string filter, SharedEntityPivotOptions options)
        {
            var result = new SharedEntityPivotResult();
            var rows = new Dictionary<string, SharedEntityPivotAccumulator>(StringComparer.OrdinalIgnoreCase);
            string requestedType = string.IsNullOrWhiteSpace(entityType) ? "Path" : entityType.Trim();
            string requestedFilter = string.IsNullOrWhiteSpace(filter) ? "" : filter.Trim();
            int take = options != null && options.MaxResults > 0 ? options.MaxResults : 250;

            if (cases == null)
                return result;

            foreach (CaseData c in cases)
            {
                if (c == null)
                    continue;
                if (c.FactStoreBuilding)
                {
                    result.SkippedHosts++;
                    continue;
                }
                if (!CaseMatchesOptions(c, options))
                    continue;
                if (c.FactStore == null || c.FactStore.EntityIndex == null || c.FactStore.EntityIndex.Count == 0)
                    continue;

                result.ReadyHosts++;
                string host = string.IsNullOrWhiteSpace(c.Hostname) ? "host" : c.Hostname;
                foreach (KeyValuePair<string, HashSet<Fact>> kvp in c.FactStore.EntityIndex)
                {
                    string normalizedValue;
                    if (!TryMatchEntityKey(kvp.Key, requestedType, out normalizedValue))
                        continue;

                    string displayValue = ResolveEntityDisplayValue(kvp.Value, kvp.Key, normalizedValue);
                    string filterTarget = !string.IsNullOrWhiteSpace(displayValue) ? displayValue : normalizedValue;
                    if (!EntityMatchesFilter(filterTarget, requestedFilter))
                        continue;

                    List<Fact> matchingFacts = FilterFacts(kvp.Value, options);
                    if (matchingFacts.Count == 0)
                        continue;

                    SharedEntityPivotAccumulator row;
                    if (!rows.TryGetValue(kvp.Key, out row))
                    {
                        row = new SharedEntityPivotAccumulator();
                        row.EntityType = requestedType;
                        row.NormalizedValue = normalizedValue ?? "";
                        row.DisplayValue = !string.IsNullOrWhiteSpace(displayValue) ? displayValue : (normalizedValue ?? "");
                        rows[kvp.Key] = row;
                    }
                    else
                    {
                        row.DisplayValue = ChooseBetterDisplayValue(row.DisplayValue, displayValue);
                    }

                    row.Hosts.Add(host);
                    UpdateAccumulator(row, matchingFacts);
                }
            }

            List<SharedEntityPivotAccumulator> sharedRows = rows.Values
                .Where(r => r != null && r.Hosts.Count > 1)
                .OrderByDescending(r => r.Hosts.Count)
                .ThenByDescending(r => r.FactCount)
                .ThenBy(r => r.DisplayValue ?? "", StringComparer.OrdinalIgnoreCase)
                .ToList();

            result.TotalSharedEntities = sharedRows.Count;
            result.Items = sharedRows.Take(take).Select(ToItem).ToList();
            return result;
        }

        public static List<SharedEntityFactHit> BuildFactHits(IEnumerable<CaseData> cases, string entityType, string entityValue)
        {
            return BuildFactHits(cases, entityType, entityValue, null);
        }

        public static List<SharedEntityFactHit> BuildFactHits(IEnumerable<CaseData> cases, string entityType, string entityValue, SharedEntityPivotOptions options)
        {
            var hits = new List<SharedEntityFactHit>();
            string requestedType = string.IsNullOrWhiteSpace(entityType) ? "Path" : entityType.Trim();
            string requestedValue = string.IsNullOrWhiteSpace(entityValue) ? "" : entityValue.Trim();

            if (cases == null || string.IsNullOrEmpty(requestedValue))
                return hits;

            foreach (CaseData c in cases)
            {
                if (c == null || c.FactStoreBuilding || !CaseMatchesOptions(c, options) || c.FactStore == null)
                    continue;

                string host = string.IsNullOrWhiteSpace(c.Hostname) ? "host" : c.Hostname;
                foreach (Fact fact in c.FactStore.GetByEntity(requestedType, requestedValue))
                {
                    if (!FactMatchesOptions(fact, options))
                        continue;

                    hits.Add(new SharedEntityFactHit
                    {
                        Hostname = host,
                        CaseData = c,
                        Fact = fact
                    });
                }
            }

            return hits
                .OrderBy(h => h.Hostname ?? "", StringComparer.OrdinalIgnoreCase)
                .ThenByDescending(h => h.Fact != null && FactTimeMetadata.HasUsableTime(h.Fact.Time))
                .ThenByDescending(h => h.Fact != null ? h.Fact.Time : DateTime.MinValue)
                .ThenBy(h => h.Fact != null ? (h.Fact.Source ?? "") : "", StringComparer.OrdinalIgnoreCase)
                .ThenBy(h => h.Fact != null ? (h.Fact.Action ?? "") : "", StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        public static List<RelatedEntityPivotItem> BuildRelatedEntities(IEnumerable<CaseData> cases, string seedEntityType, string seedEntityValue, SharedEntityPivotOptions options)
        {
            var rows = new Dictionary<string, RelatedEntityPivotAccumulator>(StringComparer.OrdinalIgnoreCase);
            string requestedType = string.IsNullOrWhiteSpace(seedEntityType) ? "Path" : seedEntityType.Trim();
            string requestedValue = string.IsNullOrWhiteSpace(seedEntityValue) ? "" : seedEntityValue.Trim();
            int take = options != null && options.MaxResults > 0 ? options.MaxResults : 250;
            string seedKey = requestedType + ":" + requestedValue.ToLowerInvariant();

            if (cases == null || string.IsNullOrEmpty(requestedValue))
                return new List<RelatedEntityPivotItem>();

            foreach (CaseData c in cases)
            {
                if (c == null || c.FactStoreBuilding || !CaseMatchesOptions(c, options) || c.FactStore == null)
                    continue;

                string host = string.IsNullOrWhiteSpace(c.Hostname) ? "host" : c.Hostname;
                foreach (Fact fact in c.FactStore.GetByEntity(requestedType, requestedValue))
                {
                    if (!FactMatchesOptions(fact, options) || fact == null || fact.EntityRefs == null)
                        continue;

                    var seenInFact = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    foreach (EntityRef entity in fact.EntityRefs)
                    {
                        if (entity == null || string.IsNullOrWhiteSpace(entity.Value))
                            continue;

                        string key = entity.ToEntityKey();
                        if (string.IsNullOrWhiteSpace(key) || string.Equals(key, seedKey, StringComparison.OrdinalIgnoreCase))
                            continue;
                        if (!seenInFact.Add(key))
                            continue;

                        string normalizedValue = ExtractValueFromEntityKey(key);
                        RelatedEntityPivotAccumulator row;
                        if (!rows.TryGetValue(key, out row))
                        {
                            row = new RelatedEntityPivotAccumulator();
                            row.RelatedType = string.IsNullOrWhiteSpace(entity.Type) ? "Entity" : entity.Type.Trim();
                            row.NormalizedValue = normalizedValue ?? "";
                            row.DisplayValue = EventLogSafeValue(entity.Value);
                            rows[key] = row;
                        }
                        else
                        {
                            row.DisplayValue = ChooseBetterDisplayValue(row.DisplayValue, entity.Value);
                        }

                        row.Hosts.Add(host);
                        UpdateAccumulator(row, fact);
                    }
                }
            }

            return rows.Values
                .Where(r => r != null)
                .OrderByDescending(r => r.Hosts.Count)
                .ThenByDescending(r => r.FactCount)
                .ThenBy(r => r.RelatedType ?? "", StringComparer.OrdinalIgnoreCase)
                .ThenBy(r => r.DisplayValue ?? "", StringComparer.OrdinalIgnoreCase)
                .Take(take)
                .Select(ToRelatedItem)
                .ToList();
        }

        public static List<TemporalSharedEntityPivotItem> BuildTemporalCorrelations(IEnumerable<CaseData> cases, string entityType, string filter, SharedEntityPivotOptions options)
        {
            var rows = new Dictionary<string, TemporalSharedEntityPivotAccumulator>(StringComparer.OrdinalIgnoreCase);
            string requestedType = string.IsNullOrWhiteSpace(entityType) ? "Path" : entityType.Trim();
            string requestedFilter = string.IsNullOrWhiteSpace(filter) ? "" : filter.Trim();
            int take = options != null && options.MaxResults > 0 ? options.MaxResults : 250;
            int bucketMinutes = options != null && options.BucketMinutes > 0 ? options.BucketMinutes : 30;

            if (cases == null)
                return new List<TemporalSharedEntityPivotItem>();

            foreach (CaseData c in cases)
            {
                if (c == null || c.FactStoreBuilding || !CaseMatchesOptions(c, options) || c.FactStore == null || c.FactStore.EntityIndex == null)
                    continue;

                string host = string.IsNullOrWhiteSpace(c.Hostname) ? "host" : c.Hostname;
                foreach (KeyValuePair<string, HashSet<Fact>> kvp in c.FactStore.EntityIndex)
                {
                    string normalizedValue;
                    if (!TryMatchEntityKey(kvp.Key, requestedType, out normalizedValue))
                        continue;

                    string displayValue = ResolveEntityDisplayValue(kvp.Value, kvp.Key, normalizedValue);
                    string filterTarget = !string.IsNullOrWhiteSpace(displayValue) ? displayValue : normalizedValue;
                    if (!EntityMatchesFilter(filterTarget, requestedFilter))
                        continue;

                    var byBucket = new Dictionary<DateTime, List<Fact>>();
                    foreach (Fact fact in FilterFacts(kvp.Value, options))
                    {
                        if (!FactTimeMetadata.HasUsableTime(fact.Time))
                            continue;

                        DateTime bucketStart = GetBucketStart(fact.Time, bucketMinutes);
                        List<Fact> list;
                        if (!byBucket.TryGetValue(bucketStart, out list))
                        {
                            list = new List<Fact>();
                            byBucket[bucketStart] = list;
                        }
                        list.Add(fact);
                    }

                    foreach (KeyValuePair<DateTime, List<Fact>> bucket in byBucket)
                    {
                        if (bucket.Value == null || bucket.Value.Count == 0)
                            continue;

                        string rowKey = kvp.Key + "|" + bucket.Key.Ticks.ToString();
                        TemporalSharedEntityPivotAccumulator row;
                        if (!rows.TryGetValue(rowKey, out row))
                        {
                            row = new TemporalSharedEntityPivotAccumulator();
                            row.EntityType = requestedType;
                            row.NormalizedValue = normalizedValue ?? "";
                            row.DisplayValue = !string.IsNullOrWhiteSpace(displayValue) ? displayValue : (normalizedValue ?? "");
                            row.BucketStart = bucket.Key;
                            row.BucketEnd = bucket.Key.AddMinutes(bucketMinutes);
                            rows[rowKey] = row;
                        }
                        else
                        {
                            row.DisplayValue = ChooseBetterDisplayValue(row.DisplayValue, displayValue);
                        }

                        row.Hosts.Add(host);
                        UpdateAccumulator(row, bucket.Value);
                    }
                }
            }

            return rows.Values
                .Where(r => r != null && r.Hosts.Count > 1)
                .OrderByDescending(r => r.Hosts.Count)
                .ThenByDescending(r => r.FactCount)
                .ThenByDescending(r => r.BucketStart)
                .ThenBy(r => r.DisplayValue ?? "", StringComparer.OrdinalIgnoreCase)
                .Take(take)
                .Select(ToTemporalItem)
                .ToList();
        }

        private static SharedEntityPivotItem ToItem(SharedEntityPivotAccumulator row)
        {
            var item = new SharedEntityPivotItem();
            item.EntityType = row.EntityType ?? "";
            item.NormalizedValue = row.NormalizedValue ?? "";
            item.DisplayValue = !string.IsNullOrWhiteSpace(row.DisplayValue) ? row.DisplayValue : (row.NormalizedValue ?? "");
            item.FactCount = row.FactCount;
            item.Hosts = row.Hosts.OrderBy(v => v, StringComparer.OrdinalIgnoreCase).ToList();
            item.Sources = row.Sources.OrderBy(v => v, StringComparer.OrdinalIgnoreCase).ToList();
            item.FirstSeen = FactTimeMetadata.HasUsableTime(row.FirstSeen) ? row.FirstSeen : DateTime.MinValue;
            item.LastSeen = FactTimeMetadata.HasUsableTime(row.LastSeen) ? row.LastSeen : DateTime.MinValue;
            return item;
        }

        private static RelatedEntityPivotItem ToRelatedItem(RelatedEntityPivotAccumulator row)
        {
            var item = new RelatedEntityPivotItem();
            item.RelatedType = row.RelatedType ?? "";
            item.NormalizedValue = row.NormalizedValue ?? "";
            item.DisplayValue = !string.IsNullOrWhiteSpace(row.DisplayValue) ? row.DisplayValue : (row.NormalizedValue ?? "");
            item.FactCount = row.FactCount;
            item.Hosts = row.Hosts.OrderBy(v => v, StringComparer.OrdinalIgnoreCase).ToList();
            item.Sources = row.Sources.OrderBy(v => v, StringComparer.OrdinalIgnoreCase).ToList();
            item.FirstSeen = FactTimeMetadata.HasUsableTime(row.FirstSeen) ? row.FirstSeen : DateTime.MinValue;
            item.LastSeen = FactTimeMetadata.HasUsableTime(row.LastSeen) ? row.LastSeen : DateTime.MinValue;
            return item;
        }

        private static TemporalSharedEntityPivotItem ToTemporalItem(TemporalSharedEntityPivotAccumulator row)
        {
            var item = new TemporalSharedEntityPivotItem();
            item.EntityType = row.EntityType ?? "";
            item.NormalizedValue = row.NormalizedValue ?? "";
            item.DisplayValue = !string.IsNullOrWhiteSpace(row.DisplayValue) ? row.DisplayValue : (row.NormalizedValue ?? "");
            item.FactCount = row.FactCount;
            item.Hosts = row.Hosts.OrderBy(v => v, StringComparer.OrdinalIgnoreCase).ToList();
            item.Sources = row.Sources.OrderBy(v => v, StringComparer.OrdinalIgnoreCase).ToList();
            item.BucketStart = row.BucketStart;
            item.BucketEnd = row.BucketEnd;
            item.FirstSeen = FactTimeMetadata.HasUsableTime(row.FirstSeen) ? row.FirstSeen : DateTime.MinValue;
            item.LastSeen = FactTimeMetadata.HasUsableTime(row.LastSeen) ? row.LastSeen : DateTime.MinValue;
            return item;
        }

        private static void UpdateAccumulator(SharedEntityPivotAccumulator row, IEnumerable<Fact> facts)
        {
            foreach (Fact fact in facts)
                UpdateAccumulator(row, fact);
        }

        private static void UpdateAccumulator(SharedEntityPivotAccumulator row, Fact fact)
        {
            if (row == null || fact == null)
                return;

            row.FactCount++;
            if (!string.IsNullOrWhiteSpace(fact.Source))
                row.Sources.Add(fact.Source);
            if (FactTimeMetadata.HasUsableTime(fact.Time))
            {
                if (fact.Time < row.FirstSeen) row.FirstSeen = fact.Time;
                if (fact.Time > row.LastSeen) row.LastSeen = fact.Time;
            }
        }

        private static void UpdateAccumulator(RelatedEntityPivotAccumulator row, Fact fact)
        {
            if (row == null || fact == null)
                return;

            row.FactCount++;
            if (!string.IsNullOrWhiteSpace(fact.Source))
                row.Sources.Add(fact.Source);
            if (FactTimeMetadata.HasUsableTime(fact.Time))
            {
                if (fact.Time < row.FirstSeen) row.FirstSeen = fact.Time;
                if (fact.Time > row.LastSeen) row.LastSeen = fact.Time;
            }
        }

        private static void UpdateAccumulator(TemporalSharedEntityPivotAccumulator row, IEnumerable<Fact> facts)
        {
            foreach (Fact fact in facts)
            {
                if (row == null || fact == null)
                    continue;

                row.FactCount++;
                if (!string.IsNullOrWhiteSpace(fact.Source))
                    row.Sources.Add(fact.Source);
                if (FactTimeMetadata.HasUsableTime(fact.Time))
                {
                    if (fact.Time < row.FirstSeen) row.FirstSeen = fact.Time;
                    if (fact.Time > row.LastSeen) row.LastSeen = fact.Time;
                }
            }
        }

        private static bool TryMatchEntityKey(string entityKey, string entityType, out string normalizedValue)
        {
            normalizedValue = null;
            if (string.IsNullOrWhiteSpace(entityKey))
                return false;

            int sep = entityKey.IndexOf(':');
            if (sep <= 0 || sep >= entityKey.Length - 1)
                return false;

            string keyType = entityKey.Substring(0, sep);
            if (!string.Equals(keyType, entityType ?? "Path", StringComparison.OrdinalIgnoreCase))
                return false;

            normalizedValue = entityKey.Substring(sep + 1);
            return !string.IsNullOrWhiteSpace(normalizedValue);
        }

        private static string ResolveEntityDisplayValue(HashSet<Fact> facts, string entityKey, string fallback)
        {
            if (facts != null)
            {
                foreach (Fact fact in facts)
                {
                    if (fact == null || fact.EntityRefs == null)
                        continue;

                    foreach (EntityRef entity in fact.EntityRefs)
                    {
                        if (entity == null || string.IsNullOrWhiteSpace(entity.Value))
                            continue;
                        string key = entity.ToEntityKey();
                        if (string.Equals(key, entityKey, StringComparison.OrdinalIgnoreCase))
                            return EventLogSafeValue(entity.Value);
                    }
                }
            }

            return fallback ?? "";
        }

        private static bool EntityMatchesFilter(string value, string filter)
        {
            return string.IsNullOrEmpty(filter) || (value ?? "").IndexOf(filter, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static List<Fact> FilterFacts(IEnumerable<Fact> facts, SharedEntityPivotOptions options)
        {
            if (facts == null)
                return new List<Fact>();

            return facts.Where(f => FactMatchesOptions(f, options)).ToList();
        }

        private static bool CaseMatchesOptions(CaseData c, SharedEntityPivotOptions options)
        {
            if (c == null)
                return false;
            if (options == null || string.IsNullOrWhiteSpace(options.HostFilter))
                return true;

            string host = c.Hostname ?? "host";
            return host.IndexOf(options.HostFilter.Trim(), StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static bool FactMatchesOptions(Fact fact, SharedEntityPivotOptions options)
        {
            if (fact == null)
                return false;
            if (options == null)
                return true;

            FactTimeMetadata.ApplyDefaultsIfMissing(fact);

            string sourceFilter = options.SourcePrefixFilter != null ? options.SourcePrefixFilter.Trim() : "";
            if (!string.IsNullOrWhiteSpace(sourceFilter))
            {
                string source = fact.Source ?? "";
                if (!source.StartsWith(sourceFilter, StringComparison.OrdinalIgnoreCase))
                    return false;
            }

            string confidenceFilter = options.TimeConfidenceFilter != null ? options.TimeConfidenceFilter.Trim() : "";
            if (!string.IsNullOrWhiteSpace(confidenceFilter) &&
                !string.Equals(fact.TimeConfidence ?? "", confidenceFilter, StringComparison.OrdinalIgnoreCase))
                return false;

            if (options.UseFromTime || options.UseToTime)
            {
                if (!FactTimeMetadata.HasUsableTime(fact.Time))
                    return false;
                // Compare on a single UTC basis so UTC-kind facts (MFT/ShellBags) and local-kind
                // facts (EventLog/Process/Activity) are not mismatched by the host's UTC offset.
                DateTime ftUtc = FactStore.ToComparableUtc(fact.Time);
                if (options.UseFromTime && ftUtc < FactStore.ToComparableUtc(options.FromTime))
                    return false;
                if (options.UseToTime && ftUtc > FactStore.ToComparableUtc(options.ToTime))
                    return false;
            }

            return true;
        }

        private static DateTime GetBucketStart(DateTime time, int bucketMinutes)
        {
            if (bucketMinutes <= 0) bucketMinutes = 30;
            // Bucket on a single UTC basis so facts from different sources at the same instant
            // share a bucket regardless of each fact's DateTimeKind.
            DateTime t = FactStore.ToComparableUtc(time);
            int bucketMinute = (t.Minute / bucketMinutes) * bucketMinutes;
            return new DateTime(t.Year, t.Month, t.Day, t.Hour, bucketMinute, 0, DateTimeKind.Utc);
        }

        private static string ChooseBetterDisplayValue(string existingValue, string candidateValue)
        {
            string existing = EventLogSafeValue(existingValue);
            string candidate = EventLogSafeValue(candidateValue);
            if (string.IsNullOrWhiteSpace(existing))
                return candidate;
            if (candidate.Length > existing.Length)
                return candidate;
            return existing;
        }

        private static string ExtractValueFromEntityKey(string key)
        {
            if (string.IsNullOrWhiteSpace(key))
                return "";
            int sep = key.IndexOf(':');
            if (sep < 0 || sep >= key.Length - 1)
                return "";
            return key.Substring(sep + 1);
        }

        private static string EventLogSafeValue(string value)
        {
            return string.IsNullOrWhiteSpace(value) ? "" : value.Trim();
        }
    }
}
