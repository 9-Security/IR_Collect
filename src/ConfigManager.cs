using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Linq;

namespace IR_Collect
{
    public class ConfigManager
    {
        private readonly string defaultConfigPath;
        private string configPath;
        public Dictionary<string, string> Settings { get; private set; }

        public ConfigManager()
        {
            defaultConfigPath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory ?? "", "config.ini");
            configPath = defaultConfigPath;
            Settings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            // Defaults
            Settings["VirusTotalApiKey"] = "";
            Settings["AiApiKey"] = "";
            Settings["AiApiEndpoint"] = "";
            Settings["AiEndpointAllowlist"] = "";
            Settings["AiExportRedactionProfile"] = "Basic";
            Settings["UploadApiKey"] = "";
            Settings["UploadEndpoint"] = "";
            Settings["UploadEndpointAllowlist"] = "";
            Settings["EventLogDays"] = "0";
            Settings["EventLogMaxEvents"] = "10000";
            Settings["MftMaxEntries"] = "100000";
            Settings["PostCollectDelaySeconds"] = "3";
            Settings["DeleteOutputDirAfterZip"] = "1";
            Settings["FactStoreWriteSqlite"] = "0";
            Settings["FactStoreAutoBuild"] = "1";
            Settings["CollectionModeProfile"] = "Standard";
            Settings["ShowCollectionCompleteMessage"] = "1";
            Settings["MemoryAcquireEnabled"] = "0";
            Settings["MemoryAcquireToolPath"] = "";
            Settings["MemoryAcquireToolArgs"] = "";
            Settings["MemoryAcquireArgsPreset"] = "custom";
            Settings["MemoryAcquireOutputName"] = "memory.raw";
            Settings["MemoryAcquireTimeoutSec"] = "3600";
            Settings["MemoryAcquireRequiresAdmin"] = "0";
            Settings["MemoryAcquireSkipIfNotElevated"] = "1";
            Settings["MemoryAcquireValidationMode"] = "exists_only";
            Settings["MemoryAcquireMinFileBytes"] = "1048576";
            Settings["MemoryAnalyzeEnabled"] = "0";
            Settings["MemoryAnalyzeToolPath"] = "";
            Settings["MemoryAnalyzeToolArgs"] = "";
            Settings["MemoryAnalyzeArgsPreset"] = "dual_quoted";
            Settings["MemoryAnalyzeOutputDirName"] = ArtifactNames.MemoryAnalysisFolder;
            Settings["MemoryAnalyzeTimeoutSec"] = "3600";
            Settings["MemoryAnalyzeValidationMode"] = "directory_has_files";
            Settings["MemoryAnalyzeRequiredPatterns"] = "";
            Settings["GuidedHuntEnabled"] = "1";
            Load();
        }

        public void Load()
        {
            if (!File.Exists(configPath)) return;
            try
            {
                var lines = File.ReadAllLines(configPath, Encoding.UTF8);
                foreach (var line in lines)
                {
                    if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#")) continue;
                    var parts = line.Split(new char[] { '=' }, 2);
                    if (parts.Length == 2)
                    {
                        Settings[parts[0].Trim()] = parts[1].Trim();
                    }
                }
            }
            catch (Exception ex)
            {
                IR_Collect.Utils.Logger.Warning("ConfigManager.Load: " + ex.Message);
            }
        }

        public void Save()
        {
            try
            {
                StringBuilder sb = new StringBuilder();
                foreach (var kvp in Settings)
                {
                    sb.AppendLine(string.Format("{0}={1}", kvp.Key, kvp.Value));
                }
                File.WriteAllText(configPath, sb.ToString(), new System.Text.UTF8Encoding(false));
                // config.ini holds API keys / endpoints in cleartext. Restrict it to the current user
                // so it is not world-readable at its predictable location next to the exe.
                TryRestrictAclToCurrentUser(configPath);
            }
            catch (Exception ex)
            {
                IR_Collect.Utils.Logger.Warning("ConfigManager.Save: " + ex.Message);
            }
        }

        /// <summary>
        /// Best-effort: lock a file's ACL down to the current user only (disable inheritance, drop
        /// other explicit rules, grant current user FullControl). Protects cleartext secrets in
        /// config.ini at rest. Degrades gracefully — removable media (FAT/exFAT) and any non-NTFS or
        /// permission failure are logged and ignored, never breaking config persistence.
        /// </summary>
        internal static void TryRestrictAclToCurrentUser(string path)
        {
            try
            {
                if (string.IsNullOrEmpty(path) || !File.Exists(path)) return;
                var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                if (identity == null || identity.User == null) return;

                var fi = new FileInfo(path);
                System.Security.AccessControl.FileSecurity sec = fi.GetAccessControl();
                // Stop inheriting parent-directory rules and do not copy them in.
                sec.SetAccessRuleProtection(true, false);
                // Remove any pre-existing explicit rules so only the current user remains.
                var existing = sec.GetAccessRules(true, false, typeof(System.Security.Principal.SecurityIdentifier));
                foreach (System.Security.AccessControl.FileSystemAccessRule r in existing)
                    sec.RemoveAccessRule(r);
                sec.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                    identity.User,
                    System.Security.AccessControl.FileSystemRights.FullControl,
                    System.Security.AccessControl.AccessControlType.Allow));
                fi.SetAccessControl(sec);
            }
            catch (Exception ex)
            {
                IR_Collect.Utils.Logger.Warning("ConfigManager: could not harden config ACL (best-effort, e.g. FAT/removable media): " + ex.Message);
            }
        }

        public string Get(string key)
        {
            if (string.IsNullOrEmpty(key)) return "";
            return Settings.ContainsKey(key) ? Settings[key] : "";
        }

        public void Set(string key, string value)
        {
            Settings[key] = value;
        }

        // Import functionality
        public void Import(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return;
            try
            {
                string ext = Path.GetExtension(path);
                if (string.IsNullOrEmpty(ext) || !ext.Equals(".ini", StringComparison.OrdinalIgnoreCase))
                {
                    IR_Collect.Utils.Logger.Warning("ConfigManager.Import: expected .ini file, got: " + path);
                    return;
                }
                string dir = Path.GetDirectoryName(path);
                if (!string.IsNullOrEmpty(dir) && !IsPathSafeForExport(Path.GetFullPath(dir)))
                {
                    IR_Collect.Utils.Logger.Warning("ConfigManager.Import: path is under system directory, import refused.");
                    return;
                }
                var lines = File.ReadAllLines(path, Encoding.UTF8);
                foreach (var line in lines)
                {
                    if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#")) continue;
                    var parts = line.Split(new char[] { '=' }, 2);
                    if (parts.Length == 2) Settings[parts[0].Trim()] = parts[1].Trim();
                }
                configPath = defaultConfigPath;
                Save();
            }
            catch (Exception ex)
            {
                IR_Collect.Utils.Logger.Warning("ConfigManager.Import: " + ex.Message);
            }
        }

        /// <summary>Returns true if export succeeded; false if path is unsafe (system dir) or an error occurred.</summary>
        public bool Export(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return false;
            try
            {
                string fullPath = Path.GetFullPath(path);
                if (!IsPathSafeForExport(fullPath))
                {
                    IR_Collect.Utils.Logger.Warning("ConfigManager.Export: path is under system directory, export refused.");
                    return false;
                }
                Save();
                File.Copy(configPath, path, true);
                return true;
            }
            catch (Exception ex)
            {
                IR_Collect.Utils.Logger.Warning("ConfigManager.Export: " + ex.Message);
                return false;
            }
        }

        /// <summary>Refuse export to system/Windows/Program Files to prevent overwriting critical files.</summary>
        private static bool IsPathSafeForExport(string fullPath)
        {
            if (string.IsNullOrEmpty(fullPath)) return false;
            string sysDir = Environment.SystemDirectory ?? "";
            string sysRoot = Path.GetPathRoot(sysDir) ?? "";
            string progFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            string progFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            fullPath = fullPath.TrimEnd(Path.DirectorySeparatorChar, '/', '\\');
            StringComparison cmp = StringComparison.OrdinalIgnoreCase;
            if (!string.IsNullOrEmpty(sysDir) && fullPath.StartsWith(sysDir.TrimEnd(Path.DirectorySeparatorChar, '/', '\\') + Path.DirectorySeparatorChar, cmp)) return false;
            if (!string.IsNullOrEmpty(winDir) && fullPath.StartsWith(winDir.TrimEnd(Path.DirectorySeparatorChar, '/', '\\') + Path.DirectorySeparatorChar, cmp)) return false;
            if (!string.IsNullOrEmpty(progFiles) && fullPath.StartsWith(progFiles.TrimEnd(Path.DirectorySeparatorChar, '/', '\\') + Path.DirectorySeparatorChar, cmp)) return false;
            if (!string.IsNullOrEmpty(progFilesX86) && fullPath.StartsWith(progFilesX86.TrimEnd(Path.DirectorySeparatorChar, '/', '\\') + Path.DirectorySeparatorChar, cmp)) return false;
            return true;
        }
    }
}
