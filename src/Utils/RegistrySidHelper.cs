using System;
using System.IO;
using System.Text.RegularExpressions;

namespace IR_Collect.Utils
{
    public static class RegistrySidHelper
    {
        private static readonly Regex ValidSid = new Regex(@"^S-1-\d+(-\d+)+$", RegexOptions.CultureInvariant);

        public static bool IsValidLoadedUserSid(string sid)
        {
            if (string.IsNullOrWhiteSpace(sid)) return false;
            return ValidSid.IsMatch(sid.Trim());
        }

        /// <summary>Whether registry user-hive collection should run for this SID (format + length gate).</summary>
        public static bool ShouldCollectRegistryForLoadedUserSid(string sid)
        {
            if (!IsValidLoadedUserSid(sid)) return false;
            return sid.Trim().Length > 10;
        }

        /// <summary>Returns a filename token derived from a validated SID (not for registry paths).</summary>
        public static string SidToFileToken(string sid)
        {
            string s = (sid ?? "").Trim();
            return s.Replace("\\", "_").Replace(":", "_");
        }

        public static bool EnsurePathUnderDirectory(string parentDir, string candidatePath)
        {
            if (string.IsNullOrEmpty(parentDir) || string.IsNullOrEmpty(candidatePath)) return false;
            try
            {
                string root = Path.GetFullPath(parentDir);
                if (!root.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal))
                    root += Path.DirectorySeparatorChar;
                string full = Path.GetFullPath(candidatePath);
                return full.StartsWith(root, StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return false;
            }
        }
    }
}
