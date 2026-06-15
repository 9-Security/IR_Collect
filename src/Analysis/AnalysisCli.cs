using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using IR_Collect.Analysis.Correlation;

namespace IR_Collect.Analysis
{
    /// <summary>
    /// Phase 3.1 - the "analysis layer" front door. Ingests a folder of already-collected artifacts
    /// (another tool's triage output, or an unzipped IR_Collect case), runs the SAME facts-only
    /// correlation pipeline a loaded case uses (FactStore.BuildFromCase + GuidedHunt), and emits a
    /// summary_v3 JSON. No live host, no GUI. This is what turns IR_Collect from "a collector that also
    /// analyzes" into "an analyzer you can point at anyone's collection".
    /// </summary>
    public static class AnalysisCli
    {
        /// <param name="folderArg">A folder path, or "-" to read the folder path from stdin.</param>
        /// <param name="outFile">Optional output JSON path; defaults to &lt;folder&gt;\ir_analysis.json.</param>
        public static int Run(string folderArg, string outFile, TextWriter console)
        {
            string folder = folderArg;
            if (folder == "-")
            {
                // Read the folder path from stdin (standard input).
                try { folder = (Console.In.ReadLine() ?? "").Trim(); } catch { folder = ""; }
            }
            if (string.IsNullOrWhiteSpace(folder))
            {
                console.WriteLine("[!] -analyze needs a folder path (or '-' to read it from stdin).");
                return 2;
            }

            CaseData c;
            try { c = CaseManager.LoadCaseFromFolder(folder); }
            catch (Exception ex)
            {
                console.WriteLine("[!] Could not load folder: " + ex.Message);
                return 1;
            }

            try
            {
                FactStore store = FactStore.BuildFromCase(c);
                c.FactStore = store;
            }
            catch (Exception ex)
            {
                console.WriteLine("[!] Analysis failed while building facts: " + ex.Message);
                return 1;
            }

            SummaryPayload payload = BuildHeadlessSummary(c);
            string json = SummaryExport.Serialize(payload);

            string outPath = outFile;
            if (string.IsNullOrEmpty(outPath))
                outPath = Path.Combine(c.ExtractPath ?? folder, "ir_analysis.json");
            try
            {
                File.WriteAllText(outPath, json, new UTF8Encoding(false));
            }
            catch (Exception ex)
            {
                console.WriteLine("[!] Could not write " + outPath + ": " + ex.Message);
                outPath = "(not written)";
            }

            int guidedMatches = (payload.GuidedHunt != null && payload.GuidedHunt.RuleMatches != null)
                ? payload.GuidedHunt.RuleMatches.Count : 0;
            // Concise human-facing summary (reliable even when winexe stdout piping is flaky).
            console.WriteLine("[+] Analyzed " + (string.IsNullOrEmpty(c.Hostname) ? "host" : c.Hostname) + ": "
                + payload.FactCount + " facts across " + payload.FactSourceCounts.Count + " source(s) from "
                + payload.ArtifactsCount + " artifact file(s); " + guidedMatches + " guided-hunt match(es).");
            console.WriteLine("[+] Summary JSON: " + outPath);
            return 0;
        }

        /// <summary>
        /// Build the summary_v3 payload headlessly (no GUI helpers) from a CaseData whose FactStore has
        /// already been built. Mirrors the schema MainForm.BuildSummaryPayload emits for the GUI export.
        /// </summary>
        public static SummaryPayload BuildHeadlessSummary(CaseData c)
        {
            var p = new SummaryPayload();
            p.GeneratedAt = DateTime.UtcNow.ToString("o");
            p.ExportSchema = "summary_v3";
            p.AnalysisMode = "facts_only";
            p.Host = c.Hostname;
            p.CaseId = c.CaseID;
            p.ArtifactsCount = c.Artifacts != null ? c.Artifacts.Count : 0;
            p.MftCount = c.MftEntries != null ? c.MftEntries.Count : 0;

            List<Fact> facts = (c.FactStore != null && c.FactStore.Facts != null) ? c.FactStore.Facts : new List<Fact>();
            p.FactCount = facts.Count;
            p.FactSourceCounts = new Dictionary<string, int>();
            p.EntityTypeCounts = new Dictionary<string, int>();
            var notes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (Fact f in facts)
            {
                if (f == null) continue;
                string src = string.IsNullOrEmpty(f.Source) ? "(unknown)" : f.Source;
                int n; p.FactSourceCounts.TryGetValue(src, out n); p.FactSourceCounts[src] = n + 1;
                if (f.EntityRefs != null)
                {
                    foreach (EntityRef e in f.EntityRefs)
                    {
                        if (e == null || string.IsNullOrEmpty(e.Type)) continue;
                        int m; p.EntityTypeCounts.TryGetValue(e.Type, out m); p.EntityTypeCounts[e.Type] = m + 1;
                    }
                }
                if (f.FallbackUsed && !string.IsNullOrWhiteSpace(f.ParserNote))
                    notes.Add((string.IsNullOrEmpty(f.Source) ? "" : f.Source + ": ") + f.ParserNote);
            }
            p.ParserNotes = notes.ToList();
            p.FactSamples = facts.Take(100).ToList();
            p.LoadWarnings = c.LoadWarnings != null ? new List<string>(c.LoadWarnings) : new List<string>();
            p.CollectionCoverage = c.CollectionCoverage;
            p.MemoryAcquisition = c.MemoryAcquisitionMeta;
            p.MemoryAnalysis = c.MemoryAnalysisMeta;
            p.AnalystWorkflow = c.AnalystWorkflow ?? new AnalystWorkflowState();
            if (c.CollectionCoverage != null && !string.IsNullOrWhiteSpace(c.CollectionCoverage.CollectionModeProfile))
                p.CollectionModeProfile = CollectionModeProfileHelper.Normalize(c.CollectionCoverage.CollectionModeProfile);
            else
                p.CollectionModeProfile = "";
            try { p.GuidedHunt = GuidedHuntPack.Evaluate(c); } catch { p.GuidedHunt = null; }
            return p;
        }
    }
}
