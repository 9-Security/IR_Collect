using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using IR_Collect.Analysis.Correlation;

namespace IR_Collect.Analysis
{
    /// <summary>
    /// Phase 3.2 - headless multi-host correlation. Loads two or more folders of already-collected
    /// artifacts (each via the Phase 3.1 LoadCaseFromFolder front door), builds each one's FactStore,
    /// and runs the existing cross-host correlation engine (SharedEntityPivotBuilder +
    /// BuildTemporalCorrelations) over the whole set, emitting a "correlation_v1" JSON. No GUI, no live
    /// host. This is what makes "the same indicator showed up on these N machines" answerable from a CLI.
    /// </summary>
    public static class CorrelationCli
    {
        // Entity types worth pivoting across hosts by default. These are the EntityRef.Type values the
        // normalizers emit that most often constitute a cross-host indicator.
        private static readonly string[] DefaultEntityTypes = { "Path", "Hash", "User", "IP", "AppId" };

        public static int Run(IList<string> folders, string outFile, SharedEntityPivotOptions options, TextWriter console)
        {
            if (folders == null || folders.Count < 2)
            {
                console.WriteLine("[!] -correlate needs at least two artifact folders.");
                return 2;
            }

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
            if (cases.Count < 2)
            {
                console.WriteLine("[!] Need at least two loadable folders to correlate (loaded " + cases.Count + ").");
                return 2;
            }

            CorrelationReport report = BuildReport(cases, DefaultEntityTypes, options);

            string outPath = outFile;
            if (string.IsNullOrEmpty(outPath))
                outPath = Path.Combine(Directory.GetCurrentDirectory(), "ir_correlation.json");
            try { CorrelationExport.SaveToFile(report, outPath); }
            catch (Exception ex)
            {
                console.WriteLine("[!] Could not write " + outPath + ": " + ex.Message);
                outPath = "(not written)";
            }

            console.WriteLine("[+] Correlated " + report.HostCount + " host(s): "
                + report.SharedEntities.Count + " shared entit(ies), "
                + report.TemporalCorrelations.Count + " temporal correlation(s).");
            console.WriteLine("[+] Correlation JSON: " + outPath);
            return 0;
        }

        /// <summary>
        /// Build the correlation_v1 report from a set of cases whose FactStores are already built.
        /// Exposed for unit tests (no folder/CLI plumbing).
        /// </summary>
        public static CorrelationReport BuildReport(IEnumerable<CaseData> cases, IEnumerable<string> entityTypes, SharedEntityPivotOptions options)
        {
            options = options ?? new SharedEntityPivotOptions();
            var caseList = new List<CaseData>();
            foreach (CaseData c in cases) if (c != null) caseList.Add(c);

            var types = new List<string>();
            foreach (string t in (entityTypes ?? DefaultEntityTypes))
                if (!string.IsNullOrWhiteSpace(t) && !types.Contains(t, StringComparer.OrdinalIgnoreCase))
                    types.Add(t.Trim());

            var report = new CorrelationReport();
            report.GeneratedAt = DateTime.UtcNow.ToString("o");
            report.ExportSchema = "correlation_v1";
            report.ToolName = BuildInfo.ToolName;
            report.ToolVersion = BuildInfo.Version;
            report.HostCount = caseList.Count;
            report.BucketMinutes = options.BucketMinutes;
            report.EntityTypes = types;

            foreach (CaseData c in caseList)
            {
                report.Hosts.Add(new CorrelationHostInfo
                {
                    Host = c.Hostname,
                    CaseId = c.CaseID,
                    FactCount = c.FactStore != null ? c.FactStore.Count : 0,
                    EvidenceDigest = c.EvidenceDigest,
                    EvidenceFileCount = c.EvidenceFiles != null ? c.EvidenceFiles.Count : 0
                });
            }

            bool readySet = false;
            foreach (string type in types)
            {
                SharedEntityPivotResult pivot = SharedEntityPivotBuilder.Build(caseList, type, "", options);
                if (!readySet) { report.ReadyHosts = pivot.ReadyHosts; report.SkippedHosts = pivot.SkippedHosts; readySet = true; }
                foreach (SharedEntityPivotItem item in pivot.Items)
                {
                    report.SharedEntities.Add(new SharedEntityDto
                    {
                        EntityType = item.EntityType,
                        Value = item.DisplayValue,
                        FactCount = item.FactCount,
                        HostCount = item.Hosts != null ? item.Hosts.Count : 0,
                        Hosts = item.Hosts != null ? new List<string>(item.Hosts) : new List<string>(),
                        Sources = item.Sources != null ? new List<string>(item.Sources) : new List<string>(),
                        FirstSeen = CorrelationExport.Iso(item.FirstSeen),
                        LastSeen = CorrelationExport.Iso(item.LastSeen)
                    });
                }

                foreach (TemporalSharedEntityPivotItem t in SharedEntityPivotBuilder.BuildTemporalCorrelations(caseList, type, "", options))
                {
                    report.TemporalCorrelations.Add(new TemporalCorrelationDto
                    {
                        EntityType = t.EntityType,
                        Value = t.DisplayValue,
                        FactCount = t.FactCount,
                        HostCount = t.Hosts != null ? t.Hosts.Count : 0,
                        Hosts = t.Hosts != null ? new List<string>(t.Hosts) : new List<string>(),
                        BucketStart = CorrelationExport.Iso(t.BucketStart),
                        BucketEnd = CorrelationExport.Iso(t.BucketEnd)
                    });
                }
            }

            // Strongest cross-host signal first (most hosts, then most facts).
            report.SharedEntities = report.SharedEntities
                .OrderByDescending(s => s.HostCount).ThenByDescending(s => s.FactCount)
                .ThenBy(s => s.Value ?? "", StringComparer.OrdinalIgnoreCase).ToList();
            return report;
        }
    }
}
