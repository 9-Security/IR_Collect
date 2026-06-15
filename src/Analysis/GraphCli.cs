using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;
using IR_Collect.Analysis.Correlation;

namespace IR_Collect.Analysis
{
    // Phase 3.2b: serializable multi-hop investigation graph (schema "graph_v1"). Times are ISO-8601.

    [DataContract]
    public class GraphNodeDto
    {
        [DataMember(Name = "type")] public string Type { get; set; }
        [DataMember(Name = "value")] public string Value { get; set; }
        [DataMember(Name = "depth")] public int Depth { get; set; }
        [DataMember(Name = "host_count")] public int HostCount { get; set; }
        [DataMember(Name = "hosts")] public List<string> Hosts { get; set; }
    }

    [DataContract]
    public class GraphEdgeDto
    {
        [DataMember(Name = "from_type")] public string FromType { get; set; }
        [DataMember(Name = "from_value")] public string FromValue { get; set; }
        [DataMember(Name = "to_type")] public string ToType { get; set; }
        [DataMember(Name = "to_value")] public string ToValue { get; set; }
        [DataMember(Name = "fact_count")] public int FactCount { get; set; }
        [DataMember(Name = "host_count")] public int HostCount { get; set; }
        [DataMember(Name = "hosts")] public List<string> Hosts { get; set; }
        [DataMember(Name = "sources")] public List<string> Sources { get; set; }
        [DataMember(Name = "actions")] public List<string> Actions { get; set; }
        [DataMember(Name = "first_seen")] public string FirstSeen { get; set; }
        [DataMember(Name = "last_seen")] public string LastSeen { get; set; }
        [DataMember(Name = "depth")] public int Depth { get; set; }
    }

    [DataContract]
    public class GraphReport
    {
        [DataMember(Name = "generated_at")] public string GeneratedAt { get; set; }
        [DataMember(Name = "export_schema")] public string ExportSchema { get; set; }
        [DataMember(Name = "seed_type")] public string SeedType { get; set; }
        [DataMember(Name = "seed_value")] public string SeedValue { get; set; }
        [DataMember(Name = "max_depth")] public int MaxDepth { get; set; }
        [DataMember(Name = "per_hop_fanout")] public int PerHopFanout { get; set; }
        [DataMember(Name = "host_count")] public int HostCount { get; set; }
        [DataMember(Name = "hosts")] public List<CorrelationHostInfo> Hosts { get; set; }
        [DataMember(Name = "node_count")] public int NodeCount { get; set; }
        [DataMember(Name = "edge_count")] public int EdgeCount { get; set; }
        [DataMember(Name = "nodes")] public List<GraphNodeDto> Nodes { get; set; }
        [DataMember(Name = "edges")] public List<GraphEdgeDto> Edges { get; set; }

        public GraphReport()
        {
            Hosts = new List<CorrelationHostInfo>();
            Nodes = new List<GraphNodeDto>();
            Edges = new List<GraphEdgeDto>();
        }
    }

    /// <summary>
    /// Phase 3.2b - headless multi-hop investigation graph. InvestigationGraphBuilder.Build is single-hop
    /// (seed -> co-occurring entities); this BFS-expands across hops up to maxDepth over one or more
    /// already-collected folders, deduping nodes/edges and bounding the fan-out, then serializes a
    /// "graph_v1" JSON. Answers "what is connected to this indicator, across these machines, N hops out".
    /// </summary>
    public static class GraphCli
    {
        // Per-hop fan-out is deliberately tighter than the pivot default (250) so a multi-hop walk cannot
        // explode; the overall walk is also capped by NodeCap/EdgeCap below.
        private const int DefaultFanout = 40;
        private const int NodeCap = 600;
        private const int EdgeCap = 3000;

        public static int Run(string seedType, string seedValue, int maxDepth, string outFile, IList<string> folders, TextWriter console)
        {
            if (string.IsNullOrWhiteSpace(seedType) || string.IsNullOrWhiteSpace(seedValue))
            {
                console.WriteLine("[!] -graph needs <seedType> <seedValue>.");
                return 2;
            }
            if (folders == null || folders.Count < 1)
            {
                console.WriteLine("[!] -graph needs at least one artifact folder.");
                return 2;
            }
            if (maxDepth < 1) maxDepth = 1;

            var cases = new List<CaseData>();
            foreach (string folder in folders)
            {
                try
                {
                    CaseData c = CaseManager.LoadCaseFromFolder(folder);
                    c.FactStore = FactStore.BuildFromCase(c);
                    cases.Add(c);
                    console.WriteLine("[+] Loaded " + (string.IsNullOrEmpty(c.Hostname) ? folder : c.Hostname) + ": "
                        + (c.FactStore != null ? c.FactStore.Count : 0) + " facts.");
                }
                catch (Exception ex)
                {
                    console.WriteLine("[!] Skipped " + folder + ": " + ex.Message);
                }
            }
            if (cases.Count < 1)
            {
                console.WriteLine("[!] No loadable folders.");
                return 2;
            }

            GraphReport report = BuildGraph(cases, seedType, seedValue, maxDepth, null);

            string outPath = outFile;
            if (string.IsNullOrEmpty(outPath))
                outPath = Path.Combine(Directory.GetCurrentDirectory(), "ir_graph.json");
            try { File.WriteAllText(outPath, Serialize(report), new UTF8Encoding(false)); }
            catch (Exception ex)
            {
                console.WriteLine("[!] Could not write " + outPath + ": " + ex.Message);
                outPath = "(not written)";
            }

            console.WriteLine("[+] Graph from " + seedType + ":" + seedValue + " (depth " + maxDepth + ", "
                + report.HostCount + " host(s)): " + report.NodeCount + " node(s), " + report.EdgeCount + " edge(s).");
            console.WriteLine("[+] Graph JSON: " + outPath);
            return 0;
        }

        /// <summary>
        /// BFS multi-hop expansion from the seed across all cases. Exposed for unit tests.
        /// </summary>
        public static GraphReport BuildGraph(IEnumerable<CaseData> cases, string seedType, string seedValue, int maxDepth, SharedEntityPivotOptions options)
        {
            var caseList = new List<CaseData>();
            foreach (CaseData c in cases) if (c != null) caseList.Add(c);
            if (maxDepth < 1) maxDepth = 1;

            if (options == null)
                options = new SharedEntityPivotOptions { MaxResults = DefaultFanout };
            else if (options.MaxResults <= 0)
                options.MaxResults = DefaultFanout;

            var report = new GraphReport();
            report.GeneratedAt = DateTime.UtcNow.ToString("o");
            report.ExportSchema = "graph_v1";
            report.SeedType = seedType;
            report.SeedValue = seedValue;
            report.MaxDepth = maxDepth;
            report.PerHopFanout = options.MaxResults;
            report.HostCount = caseList.Count;
            foreach (CaseData c in caseList)
                report.Hosts.Add(new CorrelationHostInfo { Host = c.Hostname, CaseId = c.CaseID, FactCount = c.FactStore != null ? c.FactStore.Count : 0 });

            var nodes = new Dictionary<string, GraphNodeDto>(StringComparer.OrdinalIgnoreCase);
            var edges = new Dictionary<string, GraphEdgeDto>(StringComparer.OrdinalIgnoreCase);
            var expanded = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            string seedKey = NodeKey(seedType, seedValue);
            nodes[seedKey] = new GraphNodeDto { Type = seedType, Value = seedValue, Depth = 0, Hosts = new List<string>(), HostCount = 0 };

            // (type, value, depth) BFS frontier.
            var queue = new Queue<string[]>();
            queue.Enqueue(new[] { seedType, seedValue, "0" });

            while (queue.Count > 0 && nodes.Count < NodeCap && edges.Count < EdgeCap)
            {
                string[] cur = queue.Dequeue();
                string curType = cur[0], curValue = cur[1];
                int depth = int.Parse(cur[2]);
                string curKey = NodeKey(curType, curValue);
                if (!expanded.Add(curKey)) continue;     // already expanded
                if (depth >= maxDepth) continue;          // leaf at max depth - keep node, don't expand

                List<InvestigationGraphEdge> hop = InvestigationGraphBuilder.Build(caseList, curType, curValue, options);
                foreach (InvestigationGraphEdge e in hop)
                {
                    if (edges.Count >= EdgeCap) break;
                    string toKey = e.RelatedType + ":" + (e.NormalizedValue ?? "");
                    if (!nodes.ContainsKey(toKey))
                    {
                        nodes[toKey] = new GraphNodeDto
                        {
                            Type = e.RelatedType,
                            Value = e.DisplayValue,
                            Depth = depth + 1,
                            Hosts = e.Hosts != null ? new List<string>(e.Hosts) : new List<string>(),
                            HostCount = e.Hosts != null ? e.Hosts.Count : 0
                        };
                    }

                    string edgeKey = curKey + "=>" + toKey;
                    if (!edges.ContainsKey(edgeKey))
                    {
                        edges[edgeKey] = new GraphEdgeDto
                        {
                            FromType = curType,
                            FromValue = curValue,
                            ToType = e.RelatedType,
                            ToValue = e.DisplayValue,
                            FactCount = e.FactCount,
                            HostCount = e.Hosts != null ? e.Hosts.Count : 0,
                            Hosts = e.Hosts != null ? new List<string>(e.Hosts) : new List<string>(),
                            Sources = e.Sources != null ? new List<string>(e.Sources) : new List<string>(),
                            Actions = e.Actions != null ? new List<string>(e.Actions) : new List<string>(),
                            FirstSeen = CorrelationExport.Iso(e.FirstSeen),
                            LastSeen = CorrelationExport.Iso(e.LastSeen),
                            Depth = depth + 1
                        };
                    }

                    if (depth + 1 < maxDepth && !expanded.Contains(toKey))
                        queue.Enqueue(new[] { e.RelatedType, e.DisplayValue, (depth + 1).ToString() });
                }
            }

            report.Nodes = nodes.Values.OrderBy(n => n.Depth).ThenByDescending(n => n.HostCount)
                .ThenBy(n => n.Type ?? "", StringComparer.OrdinalIgnoreCase).ToList();
            report.Edges = edges.Values.OrderBy(e => e.Depth).ThenByDescending(e => e.HostCount)
                .ThenByDescending(e => e.FactCount).ToList();
            report.NodeCount = report.Nodes.Count;
            report.EdgeCount = report.Edges.Count;
            return report;
        }

        private static string NodeKey(string type, string value)
        {
            return (type ?? "") + ":" + (value ?? "").ToLowerInvariant();
        }

        public static string Serialize(GraphReport report)
        {
            var serializer = new DataContractJsonSerializer(typeof(GraphReport));
            using (var ms = new MemoryStream())
            {
                serializer.WriteObject(ms, report);
                return Encoding.UTF8.GetString(ms.ToArray());
            }
        }
    }
}
