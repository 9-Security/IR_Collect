using System;
using System.Reflection;

namespace IR_Collect
{
    /// <summary>
    /// Single source of truth for tool identity (name + version) used to stamp every machine-readable
    /// output for court-admissibility / reproducibility. Version is read once from the executing
    /// assembly (canonical: AssemblyInfo.cs AssemblyVersion) so there is no second place to update.
    /// </summary>
    public static class BuildInfo
    {
        public const string ToolName = "9SEC Evidence Workbench";
        public const string ExecutableBaseName = "9SEC_EvidW";
        public const string ExecutableName = ExecutableBaseName + ".exe";
        public const string ReviewExecutableName = ExecutableBaseName + "_review.exe";
        public const string SelfTestResultFileName = ExecutableBaseName + "_TestResult.txt";

        private static string _version;
        private static readonly object _sync = new object();

        /// <summary>Major.Minor.Build of the running assembly (e.g. "0.22.2"). "0.0.0" if unavailable.</summary>
        public static string Version
        {
            get
            {
                if (_version == null)
                {
                    lock (_sync)
                    {
                        if (_version == null)
                        {
                            string v = "0.0.0";
                            try
                            {
                                Version asm = Assembly.GetExecutingAssembly().GetName().Version;
                                if (asm != null)
                                    v = asm.Major + "." + asm.Minor + "." + asm.Build;
                            }
                            catch { }
                            _version = v;
                        }
                    }
                }
                return _version;
            }
        }

        /// <summary>"9SEC Evidence Workbench 0.22.2" - the canonical tool-identity string for output headers/CLI.</summary>
        public static string ToolIdentity
        {
            get { return ToolName + " " + Version; }
        }
    }
}
