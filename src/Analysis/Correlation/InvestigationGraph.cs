using System;
using System.Collections.Generic;
using System.Linq;
using IR_Collect.Analysis;

namespace IR_Collect.Analysis.Correlation
{
    public sealed class InvestigationGraphEdge
    {
        public string SeedType { get; set; }
        public string SeedValue { get; set; }
        public string RelatedType { get; set; }
        public string NormalizedValue { get; set; }
        public string DisplayValue { get; set; }
        public int FactCount { get; set; }
        public List<string> Hosts { get; set; }
        public List<string> Sources { get; set; }
        public List<string> Actions { get; set; }
        public DateTime FirstSeen { get; set; }
        public DateTime LastSeen { get; set; }

        public InvestigationGraphEdge()
        {
            Hosts = new List<string>();
            Sources = new List<string>();
            Actions = new List<string>();
        }
    }

    internal sealed class InvestigationGraphAccumulator
    {
        public string SeedType { get; set; }
        public string SeedValue { get; set; }
        public string RelatedType { get; set; }
        public string NormalizedValue { get; set; }
        public string DisplayValue { get; set; }
        public int FactCount { get; set; }
        public HashSet<string> Hosts { get; private set; }
        public HashSet<string> Sources { get; private set; }
        public HashSet<string> Actions { get; private set; }
        public DateTime FirstSeen { get; set; }
        public DateTime LastSeen { get; set; }

        public InvestigationGraphAccumulator()
        {
            Hosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            Sources = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            Actions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            FirstSeen = DateTime.MaxValue;
            LastSeen = DateTime.MinValue;
        }
    }

    public static class InvestigationGraphBuilder
    {
        public static List<InvestigationGraphEdge> Build(IEnumerable<CaseData> cases, string seedType, string seedValue, SharedEntityPivotOptions options)
        {
            var results = new Dictionary<string, InvestigationGraphAccumulator>(StringComparer.OrdinalIgnoreCase);
            string normalizedSeedType = string.IsNullOrWhiteSpace(seedType) ? "Path" : seedType.Trim();
            string normalizedSeedValue = string.IsNullOrWhiteSpace(seedValue) ? "" : seedValue.Trim();
            if (cases == null || string.IsNullOrWhiteSpace(normalizedSeedValue))
                return new List<InvestigationGraphEdge>();

            string seedKey = normalizedSeedType + ":" + normalizedSeedValue.ToLowerInvariant();
            int take = options != null && options.MaxResults > 0 ? options.MaxResults : 250;
            List<SharedEntityFactHit> hits = SharedEntityPivotBuilder.BuildFactHits(cases, normalizedSeedType, normalizedSeedValue, options);
            foreach (SharedEntityFactHit hit in hits)
            {
                Fact fact = hit != null ? hit.Fact : null;
                if (fact == null || fact.EntityRefs == null)
                    continue;

                var seenInFact = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (EntityRef entity in fact.EntityRefs)
                {
                    if (entity == null || string.IsNullOrWhiteSpace(entity.Value))
                        continue;

                    string entityKey = entity.ToEntityKey();
                    if (string.IsNullOrWhiteSpace(entityKey) || string.Equals(entityKey, seedKey, StringComparison.OrdinalIgnoreCase))
                        continue;
                    if (!seenInFact.Add(entityKey))
                        continue;

                    InvestigationGraphAccumulator row;
                    if (!results.TryGetValue(entityKey, out row))
                    {
                        row = new InvestigationGraphAccumulator();
                        row.SeedType = normalizedSeedType;
                        row.SeedValue = normalizedSeedValue;
                        row.RelatedType = string.IsNullOrWhiteSpace(entity.Type) ? "Entity" : entity.Type.Trim();
                        row.NormalizedValue = ExtractEntityValue(entityKey);
                        row.DisplayValue = entity.Value.Trim();
                        results[entityKey] = row;
                    }

                    row.FactCount++;
                    row.Hosts.Add(hit.Hostname ?? "host");
                    if (!string.IsNullOrWhiteSpace(fact.Source))
                        row.Sources.Add(fact.Source);
                    if (!string.IsNullOrWhiteSpace(fact.Action))
                        row.Actions.Add(fact.Action);
                    if (FactTimeMetadata.HasUsableTime(fact.Time))
                    {
                        if (fact.Time < row.FirstSeen) row.FirstSeen = fact.Time;
                        if (fact.Time > row.LastSeen) row.LastSeen = fact.Time;
                    }
                }
            }

            return results.Values
                .OrderByDescending(v => v.Hosts.Count)
                .ThenByDescending(v => v.FactCount)
                .ThenBy(v => v.RelatedType ?? "", StringComparer.OrdinalIgnoreCase)
                .ThenBy(v => v.DisplayValue ?? "", StringComparer.OrdinalIgnoreCase)
                .Take(take)
                .Select(ToEdge)
                .ToList();
        }

        public static List<SharedEntityFactHit> BuildEdgeFactHits(IEnumerable<CaseData> cases, InvestigationGraphEdge edge, SharedEntityPivotOptions options, bool restrictToEdgeHosts)
        {
            if (edge == null)
                return new List<SharedEntityFactHit>();

            var hits = SharedEntityPivotBuilder.BuildFactHits(cases, edge.RelatedType, edge.NormalizedValue, options);
            if (!restrictToEdgeHosts || edge.Hosts == null || edge.Hosts.Count == 0)
                return hits;

            var scopedHosts = new HashSet<string>(edge.Hosts.Where(v => !string.IsNullOrWhiteSpace(v)), StringComparer.OrdinalIgnoreCase);
            return hits.Where(h => h != null && scopedHosts.Contains(h.Hostname ?? "")).ToList();
        }

        private static InvestigationGraphEdge ToEdge(InvestigationGraphAccumulator row)
        {
            var edge = new InvestigationGraphEdge();
            edge.SeedType = row.SeedType ?? "";
            edge.SeedValue = row.SeedValue ?? "";
            edge.RelatedType = row.RelatedType ?? "";
            edge.NormalizedValue = row.NormalizedValue ?? "";
            edge.DisplayValue = row.DisplayValue ?? edge.NormalizedValue;
            edge.FactCount = row.FactCount;
            edge.Hosts = row.Hosts.OrderBy(v => v, StringComparer.OrdinalIgnoreCase).ToList();
            edge.Sources = row.Sources.OrderBy(v => v, StringComparer.OrdinalIgnoreCase).ToList();
            edge.Actions = row.Actions.OrderBy(v => v, StringComparer.OrdinalIgnoreCase).ToList();
            edge.FirstSeen = FactTimeMetadata.HasUsableTime(row.FirstSeen) ? row.FirstSeen : DateTime.MinValue;
            edge.LastSeen = FactTimeMetadata.HasUsableTime(row.LastSeen) ? row.LastSeen : DateTime.MinValue;
            return edge;
        }

        private static string ExtractEntityValue(string entityKey)
        {
            if (string.IsNullOrWhiteSpace(entityKey))
                return "";
            int idx = entityKey.IndexOf(':');
            return idx >= 0 && idx < entityKey.Length - 1 ? entityKey.Substring(idx + 1) : entityKey;
        }
    }
}
