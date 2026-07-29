using System;
using System.IO;
using IR_Collect.Analysis.Correlation;

namespace IR_Collect.Analysis
{
    public static class DiffCli
    {
        public static int Run(string baselinePath, string targetPath, string outFile, TextWriter console)
        {
            if (string.IsNullOrWhiteSpace(baselinePath) || string.IsNullOrWhiteSpace(targetPath))
            {
                console.WriteLine("[!] -diff needs a baseline and target evidence folder/archive.");
                return 2;
            }

            CaseData baseline;
            CaseData target;
            try
            {
                baseline = CaseManager.LoadCaseFromPath(baselinePath);
                FactStoreBuildResult build = FactStoreBuildCoordinator.BuildConfigured(baseline);
                baseline.FactStore = build.Store;
                console.WriteLine("[+] Baseline " + DisplayName(baseline, baselinePath) + ": " + baseline.FactStore.Count +
                    " facts (" + build.BuildMode + ").");
            }
            catch (Exception ex)
            {
                console.WriteLine("[!] Could not load baseline: " + ex.Message);
                return 1;
            }

            try
            {
                target = CaseManager.LoadCaseFromPath(targetPath);
                FactStoreBuildResult build = FactStoreBuildCoordinator.BuildConfigured(target);
                target.FactStore = build.Store;
                console.WriteLine("[+] Target " + DisplayName(target, targetPath) + ": " + target.FactStore.Count +
                    " facts (" + build.BuildMode + ").");
            }
            catch (Exception ex)
            {
                console.WriteLine("[!] Could not load target: " + ex.Message);
                return 1;
            }

            DiffReport report;
            try
            {
                report = DiffBuilder.Build(baseline, target);
            }
            catch (Exception ex)
            {
                console.WriteLine("[!] Diff failed: " + ex.Message);
                return 1;
            }

            string output = string.IsNullOrWhiteSpace(outFile)
                ? Path.Combine(Directory.GetCurrentDirectory(), "ir_diff.json")
                : outFile;
            try
            {
                DiffExport.SaveToFile(report, output);
            }
            catch (Exception ex)
            {
                console.WriteLine("[!] Could not write " + output + ": " + ex.Message);
                return 1;
            }

            int added = report.Changes.FindAll(x => string.Equals(x.ChangeType, "Added", StringComparison.Ordinal)).Count;
            int removed = report.Changes.FindAll(x => string.Equals(x.ChangeType, "Removed", StringComparison.Ordinal)).Count;
            int modified = report.Changes.FindAll(x => string.Equals(x.ChangeType, "Modified", StringComparison.Ordinal)).Count;
            console.WriteLine("[+] Diff: " + report.ChangeCount + " change(s) (added " + added +
                ", modified " + modified + ", removed " + removed + ").");
            if (report.ChangesTruncated)
                console.WriteLine("[!] Output was capped at " + report.MaxChanges + " changes.");
            console.WriteLine("[+] Diff JSON: " + output);
            return 0;
        }

        private static string DisplayName(CaseData c, string fallback)
        {
            if (c != null && !string.IsNullOrWhiteSpace(c.Hostname)) return c.Hostname;
            return fallback ?? "case";
        }
    }
}
