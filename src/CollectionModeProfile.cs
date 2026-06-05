using System;
using System.Collections.Generic;

namespace IR_Collect
{
    /// <summary>Collection mode profiles (WP-E): configurable live-response posture labels and ForensicStrict outbound limits.</summary>
    public static class CollectionModeProfileHelper
    {
        public const string Standard = "Standard";
        public const string TriageFast = "TriageFast";
        public const string ForensicStrict = "ForensicStrict";

        /// <summary>Normalize config value to Standard, TriageFast, or ForensicStrict.</summary>
        public static string Normalize(string raw)
        {
            if (string.IsNullOrWhiteSpace(raw))
                return Standard;

            string t = raw.Trim();
            if (string.Equals(t, TriageFast, StringComparison.OrdinalIgnoreCase))
                return TriageFast;
            if (string.Equals(t, ForensicStrict, StringComparison.OrdinalIgnoreCase))
                return ForensicStrict;
            return Standard;
        }

        public static string GetActive(ConfigManager cfg)
        {
            if (cfg == null)
                return Standard;
            return Normalize(cfg.Get("CollectionModeProfile"));
        }

        public static bool IsForensicStrict(string normalizedProfile)
        {
            return string.Equals(normalizedProfile, ForensicStrict, StringComparison.Ordinal);
        }

        public static bool IsTriageFast(string normalizedProfile)
        {
            return string.Equals(normalizedProfile, TriageFast, StringComparison.Ordinal);
        }

        /// <summary>ForensicStrict blocks outbound ZIP upload after Local Collect regardless of allowlists.</summary>
        public static bool BlocksOutboundZipUpload(ConfigManager cfg)
        {
            return IsForensicStrict(GetActive(cfg));
        }

        /// <summary>
        /// Gate for ZIP upload after Local Collect: when <paramref name="collectionRunProfileRaw"/> is non-null, use the profile recorded for
        /// this collection run (empty or whitespace normalizes to Standard). When null, use current Settings (import/manual paths).
        /// </summary>
        public static bool BlocksOutboundZipUploadForLocalCollectRun(string collectionRunProfileRaw, ConfigManager cfg)
        {
            if (collectionRunProfileRaw != null)
                return IsForensicStrict(Normalize(collectionRunProfileRaw));
            return BlocksOutboundZipUpload(cfg);
        }

        /// <summary>
        /// Dashboard line for loaded cases' recorded profiles (from collection_coverage). Each entry is null when that case has no recorded profile.
        /// Leading newline included when non-empty. Does not include Settings profile.
        /// </summary>
        public static string FormatDashboardLoadedCollectionProfilesLine(IList<string> perCaseRecordedProfileOrNull)
        {
            if (perCaseRecordedProfileOrNull == null || perCaseRecordedProfileOrNull.Count == 0)
                return "";

            int unlabeled = 0;
            var distinct = new HashSet<string>(StringComparer.Ordinal);
            foreach (string entry in perCaseRecordedProfileOrNull)
            {
                if (string.IsNullOrWhiteSpace(entry))
                {
                    unlabeled++;
                    continue;
                }
                distinct.Add(Normalize(entry));
            }

            if (distinct.Count == 0)
                return "\nLoaded case collection profiles: (not recorded in collection_coverage.json for one or more loaded cases)";

            var sorted = new List<string>(distinct);
            sorted.Sort(StringComparer.Ordinal);

            if (distinct.Count == 1 && unlabeled == 0)
                return "\nLoaded case collection profiles: " + sorted[0];

            if (distinct.Count == 1 && unlabeled > 0)
                return "\nLoaded case collection profiles: " + sorted[0] + " (other loaded host(s) lack recorded profile in collection_coverage.json)";

            string mix = string.Join(", ", sorted.ToArray());
            string suffix = unlabeled > 0 ? "; some loaded host(s) lack recorded profile in collection_coverage.json" : "";
            return "\nLoaded case collection profiles: Mixed (" + mix + ")" + suffix;
        }

        /// <summary>ForensicStrict blocks in-app AI Analyze (including clipboard staging intended for network handoff).</summary>
        public static bool BlocksAiAnalyze(ConfigManager cfg)
        {
            return IsForensicStrict(GetActive(cfg));
        }
    }
}
