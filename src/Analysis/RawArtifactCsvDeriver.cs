using System;
using System.Collections.Generic;
using System.IO;
using IR_Collect.Collectors;
using IR_Collect.Utils;

namespace IR_Collect.Analysis
{
    /// <summary>
    /// Phase 3.1b: when an ingested folder contains RAW hive/ESE files (Amcache.hve / SYSTEM / SRUDB.dat)
    /// but not the derived CSVs the normalizers read, parse them offline with IR_Collect's own validated
    /// parsers and write the canonical collector CSVs alongside (via the shared ExecutionArtifactCsvWriter,
    /// so the format cannot drift). This is what lets `-analyze` produce Amcache/ShimCache/SRUM facts from
    /// a foreign triage package. Existing CSVs are never overwritten. Best-effort: a parser that falls back
    /// (Amcache/ShimCache need 'reg load' = admin) writes nothing and records a warning so the caller can
    /// re-run elevated. SRUM uses the native ESE reader and needs no elevation.
    /// </summary>
    public static class RawArtifactCsvDeriver
    {
        public static void DeriveInto(string folder, List<string> warnings)
        {
            if (string.IsNullOrEmpty(folder) || !Directory.Exists(folder)) return;
            try { DeriveSrum(folder, warnings); } catch (Exception ex) { Warn(warnings, "SRUM derive failed: " + ex.Message); }
            try { DeriveAmcache(folder, warnings); } catch (Exception ex) { Warn(warnings, "Amcache derive failed: " + ex.Message); }
            try { DeriveShimCache(folder, warnings); } catch (Exception ex) { Warn(warnings, "ShimCache derive failed: " + ex.Message); }
        }

        private static void DeriveSrum(string folder, List<string> warnings)
        {
            string appCsv = Path.Combine(folder, ArtifactNames.SrumAppUsageCsv);
            string netCsv = Path.Combine(folder, ArtifactNames.SrumNetworkUsageCsv);
            if (File.Exists(appCsv) || File.Exists(netCsv)) return; // collector CSVs already present
            string db = FindFirst(folder, "SRUDB.dat");
            if (db == null) return;
            SrumExportResult export = SrumExporter.Export(db);
            if (export == null || (export.AppRows.Count == 0 && export.NetworkRows.Count == 0))
            {
                Warn(warnings, "SRUDB.dat present but no SRUM rows parsed" + NoteSuffix(export != null ? export.ParserNotes : null));
                return;
            }
            ExecutionArtifactCsvWriter.WriteSrumCsvs(export, netCsv, appCsv);
        }

        private static void DeriveAmcache(string folder, List<string> warnings)
        {
            string progCsv = Path.Combine(folder, ArtifactNames.AmcacheProgramsCsv);
            string fileCsv = Path.Combine(folder, ArtifactNames.AmcacheFilesCsv);
            if (File.Exists(progCsv) || File.Exists(fileCsv)) return;
            string hive = FindFirst(folder, "Amcache.hve");
            if (hive == null) return;
            AmcacheParseResult parsed = AmcacheParser.ParseHive(hive);
            if (parsed == null || (parsed.Files.Count == 0 && parsed.Programs.Count == 0))
            {
                Warn(warnings, "Amcache.hve present but no rows parsed (Amcache uses 'reg load' = elevation; re-run -analyze elevated for Amcache facts)" + NoteSuffix(parsed != null ? parsed.ParserNotes : null));
                return;
            }
            ExecutionArtifactCsvWriter.WriteAmcacheCsvs(parsed, progCsv, fileCsv);
        }

        private static void DeriveShimCache(string folder, List<string> warnings)
        {
            string entriesCsv = Path.Combine(folder, ArtifactNames.ShimCacheEntriesCsv);
            if (File.Exists(entriesCsv)) return;
            string sys = FindFirst(folder, "SYSTEM");
            if (sys == null) return;
            ShimCacheParseResult parsed = ShimCacheParser.ParseFromHiveFile(sys);
            if (parsed == null || parsed.Entries.Count == 0)
            {
                Warn(warnings, "SYSTEM hive present but no ShimCache entries parsed (ShimCache uses 'reg load' = elevation; re-run -analyze elevated for ShimCache facts)" + NoteSuffix(parsed != null ? parsed.ParserNotes : null));
                return;
            }
            ExecutionArtifactCsvWriter.WriteShimCacheEntriesCsv(parsed, entriesCsv);
        }

        // Find a file by exact name (case-insensitive) anywhere under root; null if absent.
        private static string FindFirst(string root, string fileName)
        {
            try
            {
                foreach (string f in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
                    if (string.Equals(Path.GetFileName(f), fileName, StringComparison.OrdinalIgnoreCase))
                        return f;
            }
            catch { }
            return null;
        }

        private static string NoteSuffix(List<string> notes)
        {
            if (notes == null || notes.Count == 0) return ".";
            return ": " + notes[0];
        }

        private static void Warn(List<string> warnings, string msg)
        {
            if (warnings != null) warnings.Add("Raw-artifact derive: " + msg);
        }
    }
}
