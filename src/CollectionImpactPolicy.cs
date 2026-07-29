using System;
using System.Collections.Generic;
using System.IO;

namespace IR_Collect
{
    public sealed class CollectionRunContext
    {
        public string CollectionModeProfile { get; set; }
        public string OutputTargetClass { get; set; }
        public string OutputTargetPath { get; set; }
        public bool OperatorAcknowledgedRisks { get; set; }
        public List<string> RestrictedSteps { get; set; }
        public List<string> SkippedByProfile { get; set; }

        public CollectionRunContext()
        {
            CollectionModeProfile = CollectionModeProfileHelper.Standard;
            OutputTargetClass = CollectionImpactPolicy.OutputUnknown;
            OutputTargetPath = "";
            RestrictedSteps = new List<string>();
            SkippedByProfile = new List<string>();
        }
    }

    /// <summary>
    /// Central policy for live-response impact controls. It does not claim zero-footprint behavior;
    /// it classifies the output target and records which optional high-impact actions were restricted.
    /// </summary>
    public static class CollectionImpactPolicy
    {
        public const string OutputSystemDisk = "system_disk";
        public const string OutputRemovable = "removable";
        public const string OutputNetwork = "network";
        public const string OutputUnknown = "unknown";

        public const string MemoryAcquisitionStep = "Memory acquisition";
        public const string MemoryAnalysisStep = "Memory analysis handoff";
        public const string DeepScanStep = "Deep Scan (manual live action)";

        public static CollectionRunContext Create(
            ConfigManager cfg,
            string outputDirectory,
            bool operatorAcknowledgedRisks)
        {
            string profile = CollectionModeProfileHelper.GetActive(cfg);
            return CreateForValues(
                profile,
                outputDirectory,
                operatorAcknowledgedRisks,
                GetBool(cfg, "ForensicStrictSkipMemoryHandoff", true),
                GetBool(cfg, "ForensicStrictSkipDeepScan", true),
                GetBool(cfg, "MemoryAcquireEnabled", false),
                GetBool(cfg, "MemoryAnalyzeEnabled", false));
        }

        internal static CollectionRunContext CreateForValues(
            string profile,
            string outputDirectory,
            bool operatorAcknowledgedRisks,
            bool skipMemoryHandoff,
            bool skipDeepScan,
            bool memoryAcquisitionEnabled,
            bool memoryAnalysisEnabled)
        {
            var context = new CollectionRunContext();
            context.CollectionModeProfile = CollectionModeProfileHelper.Normalize(profile);
            context.OutputTargetPath = ResolveOutputPath(outputDirectory);
            context.OutputTargetClass = ClassifyOutputTarget(context.OutputTargetPath);
            context.OperatorAcknowledgedRisks = operatorAcknowledgedRisks;

            if (!CollectionModeProfileHelper.IsForensicStrict(context.CollectionModeProfile))
                return context;

            if (skipMemoryHandoff)
            {
                context.RestrictedSteps.Add(MemoryAcquisitionStep);
                context.RestrictedSteps.Add(MemoryAnalysisStep);
                if (memoryAcquisitionEnabled)
                    context.SkippedByProfile.Add(MemoryAcquisitionStep);
                if (memoryAnalysisEnabled)
                    context.SkippedByProfile.Add(MemoryAnalysisStep);
            }

            if (skipDeepScan)
                context.RestrictedSteps.Add(DeepScanStep);

            return context;
        }

        public static string ClassifyOutputTarget(string outputPath)
        {
            if (string.IsNullOrWhiteSpace(outputPath))
                return OutputUnknown;

            string full;
            try { full = Path.GetFullPath(outputPath); }
            catch { return OutputUnknown; }

            if (full.StartsWith(@"\\", StringComparison.Ordinal))
                return OutputNetwork;

            string root;
            try { root = Path.GetPathRoot(full); }
            catch { return OutputUnknown; }
            if (string.IsNullOrEmpty(root))
                return OutputUnknown;

            string systemRoot = "";
            try { systemRoot = Path.GetPathRoot(Environment.SystemDirectory); }
            catch { }
            if (!string.IsNullOrEmpty(systemRoot) &&
                string.Equals(
                    systemRoot.TrimEnd('\\', '/'),
                    root.TrimEnd('\\', '/'),
                    StringComparison.OrdinalIgnoreCase))
                return OutputSystemDisk;

            try
            {
                var drive = new DriveInfo(root);
                if (drive.DriveType == DriveType.Removable)
                    return OutputRemovable;
                if (drive.DriveType == DriveType.Network)
                    return OutputNetwork;
            }
            catch { }

            return OutputUnknown;
        }

        public static bool RequiresOperatorAcknowledgment(CollectionRunContext context)
        {
            return context != null &&
                CollectionModeProfileHelper.IsForensicStrict(context.CollectionModeProfile);
        }

        public static bool ShouldWarnOnSystemDisk(ConfigManager cfg, CollectionRunContext context)
        {
            return RequiresOperatorAcknowledgment(context) &&
                GetBool(cfg, "WarnOnSystemDiskOutput", true) &&
                string.Equals(context.OutputTargetClass, OutputSystemDisk, StringComparison.Ordinal);
        }

        public static bool RequiresNonRemovableAcknowledgment(ConfigManager cfg, CollectionRunContext context)
        {
            return RequiresOperatorAcknowledgment(context) &&
                GetBool(cfg, "RequireRemovableMediaConfirmation", true) &&
                !string.Equals(context.OutputTargetClass, OutputRemovable, StringComparison.Ordinal);
        }

        public static bool RequiresSecondConfirmation(ConfigManager cfg, CollectionRunContext context)
        {
            return RequiresOperatorAcknowledgment(context) &&
                GetBool(cfg, "ForensicStrictRequireSecondConfirmation", true);
        }

        public static bool ShouldSkipMemoryAcquisition(ConfigManager cfg)
        {
            return CollectionModeProfileHelper.IsForensicStrict(CollectionModeProfileHelper.GetActive(cfg)) &&
                GetBool(cfg, "ForensicStrictSkipMemoryHandoff", true) &&
                GetBool(cfg, "MemoryAcquireEnabled", false);
        }

        public static bool ShouldSkipMemoryAnalysis(ConfigManager cfg)
        {
            return CollectionModeProfileHelper.IsForensicStrict(CollectionModeProfileHelper.GetActive(cfg)) &&
                GetBool(cfg, "ForensicStrictSkipMemoryHandoff", true) &&
                GetBool(cfg, "MemoryAnalyzeEnabled", false);
        }

        public static bool IsDeepScanRestricted(ConfigManager cfg)
        {
            return CollectionModeProfileHelper.IsForensicStrict(CollectionModeProfileHelper.GetActive(cfg)) &&
                GetBool(cfg, "ForensicStrictSkipDeepScan", true);
        }

        private static bool GetBool(ConfigManager cfg, string key, bool defaultValue)
        {
            if (cfg == null)
                return defaultValue;
            string value = cfg.Get(key);
            if (string.IsNullOrWhiteSpace(value))
                return defaultValue;
            return value != "0" && !string.Equals(value, "false", StringComparison.OrdinalIgnoreCase);
        }

        private static string ResolveOutputPath(string outputDirectory)
        {
            if (string.IsNullOrWhiteSpace(outputDirectory))
                return "";
            try { return Path.GetFullPath(outputDirectory); }
            catch { return outputDirectory; }
        }
    }
}
