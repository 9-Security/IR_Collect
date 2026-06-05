using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;
using IR_Collect.Utils;

namespace IR_Collect.Collectors
{
    public static class ExecutionArtifactCollector
    {
        public static void Collect(string outputDir)
        {
            Console.WriteLine("[*] Collecting Execution / Persistence Extension Artifacts...");
            string executionDir = Path.Combine(outputDir, ArtifactNames.ExecutionArtifactsFolder);
            Directory.CreateDirectory(executionDir);

            var failed = new List<string>();
            if (!CollectBamDam(outputDir)) failed.Add("BAM/DAM");
            if (!CollectBitsJobs(outputDir)) failed.Add("BITS Jobs");
            if (!CollectWmiPersistence(outputDir)) failed.Add("WMI Persistence");
            if (!CollectShimCache(outputDir)) failed.Add("ShimCache");
            if (!CollectShimCacheEntries(outputDir)) failed.Add("ShimCache Entries");
            if (!CollectAmcache(executionDir)) failed.Add("Amcache");
            if (!CollectAmcacheStructured(executionDir, outputDir)) failed.Add("Amcache Structured");
            if (!CollectSrum(executionDir)) failed.Add("SRUM");
            if (!CollectSrumStructured(executionDir, outputDir)) failed.Add("SRUM Structured");

            if (failed.Count > 0)
                throw new InvalidOperationException("Execution artifact collection incomplete: " + string.Join(", ", failed.ToArray()));
        }

        private static bool CollectBamDam(string outputDir)
        {
            string outFile = Path.Combine(outputDir, ArtifactNames.BamDamCsv);
            try
            {
                using (var sw = new StreamWriter(outFile, false, new UTF8Encoding(false)))
                {
                    sw.WriteLine("Source,User,RegistryPath,ValueName,Path,LastExecutionTime,DataLength,Details");
                    WriteBamDamBranch(sw, "BAM", @"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings");
                    WriteBamDamBranch(sw, "DAM", @"SYSTEM\CurrentControlSet\Services\dam\State\UserSettings");
                }
                Console.WriteLine("    + BAM/DAM collected.");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("    ! Error collecting BAM/DAM: " + ex.Message);
                Logger.Warning("ExecutionArtifactCollector.BAMDAM: " + ex.Message);
                return false;
            }
        }

        private static void WriteBamDamBranch(StreamWriter sw, string sourceName, string registryPath)
        {
            using (RegistryKey root = Registry.LocalMachine.OpenSubKey(registryPath))
            {
                if (root == null)
                    return;

                foreach (string sid in root.GetSubKeyNames())
                {
                    using (RegistryKey userKey = root.OpenSubKey(sid))
                    {
                        if (userKey == null)
                            continue;

                        string user = ResolveUserFromSid(sid);
                        foreach (string valueName in userKey.GetValueNames())
                        {
                            try
                            {
                                object rawValue = userKey.GetValue(valueName);
                                byte[] data = rawValue as byte[];
                                DateTime lastExec = TryParseBamFileTime(data);
                                string details = data != null && data.Length > 0 ? ("BinaryLength=" + data.Length.ToString(CultureInfo.InvariantCulture)) : "No binary payload";
                                sw.WriteLine(string.Join(",", new string[]
                                {
                                    CsvUtils.EscapeField(sourceName),
                                    CsvUtils.EscapeField(user),
                                    CsvUtils.EscapeField(@"HKLM\" + registryPath + "\\" + sid),
                                    CsvUtils.EscapeField(valueName),
                                    CsvUtils.EscapeField(valueName),
                                    CsvUtils.EscapeField(lastExec.Year > 1980 ? lastExec.ToString("yyyy-MM-dd HH:mm:ss") : ""),
                                    CsvUtils.EscapeField(data != null ? data.Length.ToString(CultureInfo.InvariantCulture) : "0"),
                                    CsvUtils.EscapeField(details)
                                }));
                            }
                            catch (Exception ex)
                            {
                                Logger.Warning("ExecutionArtifactCollector.BAMDAM row: " + ex.Message);
                            }
                        }
                    }
                }
            }
        }

        private static bool CollectBitsJobs(string outputDir)
        {
            string outFile = Path.Combine(outputDir, ArtifactNames.BitsJobsCsv);
            try
            {
                string script =
                    "& { " +
                    "if (Get-Command Get-BitsTransfer -ErrorAction SilentlyContinue) { " +
                    "Get-BitsTransfer -AllUsers | Select-Object DisplayName,OwnerAccount,JobState,Priority,CreationTime,ModificationTime,TransferType," +
                    "@{Name='RemoteName';Expression={ if ($_.FileList) { ($_.FileList | ForEach-Object { $_.RemoteName }) -join '; ' } else { '' } }}," +
                    "@{Name='LocalName';Expression={ if ($_.FileList) { ($_.FileList | ForEach-Object { $_.LocalName }) -join '; ' } else { '' } }}," +
                    "Description | ConvertTo-Csv -NoTypeInformation } }";

                ProcessStartInfo psi = new ProcessStartInfo("powershell.exe", "-NoProfile -Command \"" + script.Replace("\"", "\\\"") + "\"");
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.StandardOutputEncoding = Encoding.UTF8;
                psi.StandardErrorEncoding = Encoding.UTF8;

                string output;
                string error;
                using (Process p = Process.Start(psi))
                {
                    output = p.StandardOutput.ReadToEnd();
                    error = p.StandardError.ReadToEnd();
                    p.WaitForExit();
                    if (p.ExitCode != 0)
                        throw new InvalidOperationException(string.IsNullOrWhiteSpace(error) ? ("powershell exit code " + p.ExitCode) : error.Trim());
                }

                if (string.IsNullOrWhiteSpace(output))
                    output = "DisplayName,OwnerAccount,JobState,Priority,CreationTime,ModificationTime,TransferType,RemoteName,LocalName,Description\r\n";

                File.WriteAllText(outFile, output, new UTF8Encoding(false));
                Console.WriteLine("    + BITS jobs collected.");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("    ! Error collecting BITS jobs: " + ex.Message);
                Logger.Warning("ExecutionArtifactCollector.BITS: " + ex.Message);
                return false;
            }
        }

        private static bool CollectWmiPersistence(string outputDir)
        {
            string outFile = Path.Combine(outputDir, ArtifactNames.WmiPersistenceCsv);
            try
            {
                using (var sw = new StreamWriter(outFile, false, new UTF8Encoding(false)))
                {
                    sw.WriteLine("Class,Name,Filter,Consumer,Query,Path,Details");
                    WriteWmiRows(sw, "__EventFilter", new string[] { "Name", "Query", "EventNamespace", "QueryLanguage" });
                    WriteWmiRows(sw, "CommandLineEventConsumer", new string[] { "Name", "ExecutablePath", "CommandLineTemplate", "WorkingDirectory" });
                    WriteWmiRows(sw, "ActiveScriptEventConsumer", new string[] { "Name", "ScriptingEngine", "ScriptText" });
                    WriteWmiRows(sw, "LogFileEventConsumer", new string[] { "Name", "Filename", "Text" });
                    WriteWmiRows(sw, "NTEventLogEventConsumer", new string[] { "Name", "Category", "EventType", "SourceName" });
                    WriteWmiBindingRows(sw);
                }
                Console.WriteLine("    + WMI persistence collected.");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("    ! Error collecting WMI persistence: " + ex.Message);
                Logger.Warning("ExecutionArtifactCollector.WMI: " + ex.Message);
                return false;
            }
        }

        private static void WriteWmiRows(StreamWriter sw, string className, string[] propertyNames)
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher(@"root\subscription", "SELECT * FROM " + className))
                using (ManagementObjectCollection rows = searcher.Get())
                {
                    foreach (ManagementBaseObject row in rows)
                    {
                        string name = SafeWmiValue(row, "Name");
                        string filter = "";
                        string consumer = "";
                        string query = SafeWmiValue(row, "Query");
                        string path = SafeWmiValue(row, "ExecutablePath", "Filename");
                        string details = BuildWmiDetails(row, propertyNames);

                        sw.WriteLine(string.Join(",", new string[]
                        {
                            CsvUtils.EscapeField(className),
                            CsvUtils.EscapeField(name),
                            CsvUtils.EscapeField(filter),
                            CsvUtils.EscapeField(consumer),
                            CsvUtils.EscapeField(query),
                            CsvUtils.EscapeField(path),
                            CsvUtils.EscapeField(details)
                        }));
                    }
                }
            }
            catch (ManagementException ex)
            {
                Logger.Warning("ExecutionArtifactCollector.WMI query " + className + ": " + ex.Message);
            }
        }

        private static void WriteWmiBindingRows(StreamWriter sw)
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher(@"root\subscription", "SELECT * FROM __FilterToConsumerBinding"))
                using (ManagementObjectCollection rows = searcher.Get())
                {
                    foreach (ManagementBaseObject row in rows)
                    {
                        string filter = SafeWmiValue(row, "Filter");
                        string consumer = SafeWmiValue(row, "Consumer");
                        string details = BuildWmiDetails(row, new string[] { "CreatorSID", "DeliverSynchronously", "MaintainSecurityContext", "SlowDownProviders" });
                        sw.WriteLine(string.Join(",", new string[]
                        {
                            CsvUtils.EscapeField("__FilterToConsumerBinding"),
                            CsvUtils.EscapeField(""),
                            CsvUtils.EscapeField(filter),
                            CsvUtils.EscapeField(consumer),
                            CsvUtils.EscapeField(""),
                            CsvUtils.EscapeField(""),
                            CsvUtils.EscapeField(details)
                        }));
                    }
                }
            }
            catch (ManagementException ex)
            {
                Logger.Warning("ExecutionArtifactCollector.WMI bindings: " + ex.Message);
            }
        }

        private static bool CollectShimCache(string outputDir)
        {
            string outFile = Path.Combine(outputDir, ArtifactNames.ShimCacheCsv);
            try
            {
                using (var sw = new StreamWriter(outFile, false, new UTF8Encoding(false)))
                {
                    sw.WriteLine("RegistryPath,ValueName,ValueType,DataLength,Sha256Prefix,Details");
                    const string registryPath = @"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache";
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(registryPath))
                    {
                        if (key != null)
                        {
                            foreach (string valueName in key.GetValueNames())
                            {
                                object value = key.GetValue(valueName);
                                RegistryValueKind kind = key.GetValueKind(valueName);
                                byte[] data = value as byte[];
                                string hashPrefix = data != null && data.Length > 0 ? ComputeSha256Prefix(data) : "";
                                sw.WriteLine(string.Join(",", new string[]
                                {
                                    CsvUtils.EscapeField(@"HKLM\" + registryPath),
                                    CsvUtils.EscapeField(valueName),
                                    CsvUtils.EscapeField(kind.ToString()),
                                    CsvUtils.EscapeField(data != null ? data.Length.ToString(CultureInfo.InvariantCulture) : "0"),
                                    CsvUtils.EscapeField(hashPrefix),
                                    CsvUtils.EscapeField("Raw shimcache registry value; parse offline against SYSTEM hive for entry-level reconstruction.")
                                }));
                            }
                        }
                    }
                }
                Console.WriteLine("    + ShimCache metadata collected.");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("    ! Error collecting ShimCache metadata: " + ex.Message);
                Logger.Warning("ExecutionArtifactCollector.ShimCache: " + ex.Message);
                return false;
            }
        }

        private static bool CollectShimCacheEntries(string outputDir)
        {
            string outFile = Path.Combine(outputDir, ArtifactNames.ShimCacheEntriesCsv);
            try
            {
                ShimCacheParseResult parsed = ShimCacheParser.ParseFromLiveRegistry();
                using (var sw = new StreamWriter(outFile, false, new UTF8Encoding(false)))
                {
                    sw.WriteLine("RegistryPath,ValueName,EntryIndex,Path,FileName,LastModifiedTime,DataHashPrefix,ParserNote");
                    foreach (ShimCacheEntryRecord row in parsed.Entries)
                    {
                        sw.WriteLine(string.Join(",", new string[]
                        {
                            CsvUtils.EscapeField(row.RegistryPath),
                            CsvUtils.EscapeField(row.ValueName),
                            CsvUtils.EscapeField(row.EntryIndex.ToString(CultureInfo.InvariantCulture)),
                            CsvUtils.EscapeField(row.Path),
                            CsvUtils.EscapeField(row.FileName),
                            CsvUtils.EscapeField(row.LastModifiedTime),
                            CsvUtils.EscapeField(row.DataHashPrefix),
                            CsvUtils.EscapeField(row.ParserNote)
                        }));
                    }
                    foreach (string note in parsed.ParserNotes)
                    {
                        sw.WriteLine(string.Join(",", new string[]
                        {
                            CsvUtils.EscapeField(@"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"),
                            CsvUtils.EscapeField(""),
                            CsvUtils.EscapeField("0"),
                            CsvUtils.EscapeField(""),
                            CsvUtils.EscapeField(""),
                            CsvUtils.EscapeField(""),
                            CsvUtils.EscapeField(""),
                            CsvUtils.EscapeField(note)
                        }));
                    }
                }
                Console.WriteLine("    + ShimCache entry-level CSV exported.");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("    ! Error exporting ShimCache entries: " + ex.Message);
                Logger.Warning("ExecutionArtifactCollector.ShimCacheEntries: " + ex.Message);
                return false;
            }
        }

        private static bool CollectAmcache(string executionDir)
        {
            string src = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "AppCompat", "Programs", "Amcache.hve");
            string dest = Path.Combine(executionDir, "Amcache.hve");
            try
            {
                if (!File.Exists(src))
                    throw new FileNotFoundException("Amcache.hve not found.", src);

                File.Copy(src, dest, true);
                Console.WriteLine("    + Amcache hive copied.");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("    ! Error collecting Amcache hive: " + ex.Message);
                Logger.Warning("ExecutionArtifactCollector.Amcache: " + ex.Message);
                return false;
            }
        }

        private static bool CollectAmcacheStructured(string executionDir, string outputDir)
        {
            string hivePath = Path.Combine(executionDir, "Amcache.hve");
            string programsCsv = Path.Combine(outputDir, ArtifactNames.AmcacheProgramsCsv);
            string filesCsv = Path.Combine(outputDir, ArtifactNames.AmcacheFilesCsv);
            try
            {
                AmcacheParseResult parsed = AmcacheParser.ParseHive(hivePath);

                using (var sw = new StreamWriter(programsCsv, false, new UTF8Encoding(false)))
                {
                    sw.WriteLine("RegistryKey,ProgramName,Publisher,Version,ProductName,InstallDate,UninstallString,ProgramId,ParserNote");
                    foreach (AmcacheProgramRecord row in parsed.Programs)
                    {
                        sw.WriteLine(string.Join(",", new string[]
                        {
                            CsvUtils.EscapeField(row.RegistryKey),
                            CsvUtils.EscapeField(row.ProgramName),
                            CsvUtils.EscapeField(row.Publisher),
                            CsvUtils.EscapeField(row.Version),
                            CsvUtils.EscapeField(row.ProductName),
                            CsvUtils.EscapeField(row.InstallDate),
                            CsvUtils.EscapeField(row.UninstallString),
                            CsvUtils.EscapeField(row.ProgramId),
                            CsvUtils.EscapeField(row.ParserNote)
                        }));
                    }
                    foreach (string note in parsed.ParserNotes)
                    {
                        sw.WriteLine(string.Join(",", new string[]
                        {
                            CsvUtils.EscapeField(""),
                            CsvUtils.EscapeField(""),
                            CsvUtils.EscapeField(""),
                            CsvUtils.EscapeField(""),
                            CsvUtils.EscapeField(""),
                            CsvUtils.EscapeField(""),
                            CsvUtils.EscapeField(""),
                            CsvUtils.EscapeField(""),
                            CsvUtils.EscapeField(note)
                        }));
                    }
                }

                using (var sw = new StreamWriter(filesCsv, false, new UTF8Encoding(false)))
                {
                    sw.WriteLine("RegistryKey,Path,FileName,Hash,ProductName,Publisher,ProgramId,FirstObservedTime,ExecutedTime,ParserNote");
                    foreach (AmcacheFileRecord row in parsed.Files)
                    {
                        sw.WriteLine(string.Join(",", new string[]
                        {
                            CsvUtils.EscapeField(row.RegistryKey),
                            CsvUtils.EscapeField(row.Path),
                            CsvUtils.EscapeField(row.FileName),
                            CsvUtils.EscapeField(row.Hash),
                            CsvUtils.EscapeField(row.ProductName),
                            CsvUtils.EscapeField(row.Publisher),
                            CsvUtils.EscapeField(row.ProgramId),
                            CsvUtils.EscapeField(row.FirstObservedTime),
                            CsvUtils.EscapeField(row.ExecutedTime),
                            CsvUtils.EscapeField(row.ParserNote)
                        }));
                    }
                }

                Console.WriteLine("    + Amcache structured CSV exported.");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("    ! Error exporting Amcache structured CSV: " + ex.Message);
                Logger.Warning("ExecutionArtifactCollector.AmcacheStructured: " + ex.Message);
                return false;
            }
        }

        private static bool CollectSrum(string executionDir)
        {
            string srcDb = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "sru", "SRUDB.dat");
            string destDb = Path.Combine(executionDir, "SRUDB.dat");
            try
            {
                if (!File.Exists(srcDb))
                    throw new FileNotFoundException("SRUDB.dat not found.", srcDb);

                if (!TryCopyLockedFileWithEsentutl(srcDb, destDb))
                    File.Copy(srcDb, destDb, true);

                CopyIfExists(Path.Combine(Path.GetDirectoryName(srcDb) ?? "", "SRUDB.log"), Path.Combine(executionDir, "SRUDB.log"));
                CopyIfExists(Path.Combine(Path.GetDirectoryName(srcDb) ?? "", "SRUDB.jrs"), Path.Combine(executionDir, "SRUDB.jrs"));
                Console.WriteLine("    + SRUM database copied.");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("    ! Error collecting SRUM database: " + ex.Message);
                Logger.Warning("ExecutionArtifactCollector.SRUM: " + ex.Message);
                return false;
            }
        }

        private static bool CollectSrumStructured(string executionDir, string outputDir)
        {
            string dbPath = Path.Combine(executionDir, "SRUDB.dat");
            string networkCsv = Path.Combine(outputDir, ArtifactNames.SrumNetworkUsageCsv);
            string appCsv = Path.Combine(outputDir, ArtifactNames.SrumAppUsageCsv);
            try
            {
                SrumExportResult export = SrumExporter.Export(dbPath);
                using (var sw = new StreamWriter(networkCsv, false, new UTF8Encoding(false)))
                {
                    sw.WriteLine("Timestamp,AppId,Path,User,RemoteIP,Interface,BytesSent,BytesReceived,ParserNote");
                    foreach (SrumNetworkRecord row in export.NetworkRows)
                    {
                        sw.WriteLine(string.Join(",", new string[]
                        {
                            CsvUtils.EscapeField(row.Timestamp),
                            CsvUtils.EscapeField(row.AppId),
                            CsvUtils.EscapeField(row.Path),
                            CsvUtils.EscapeField(row.User),
                            CsvUtils.EscapeField(row.RemoteIP),
                            CsvUtils.EscapeField(row.InterfaceName),
                            CsvUtils.EscapeField(row.BytesSent),
                            CsvUtils.EscapeField(row.BytesReceived),
                            CsvUtils.EscapeField(row.ParserNote)
                        }));
                    }
                    foreach (string note in export.ParserNotes)
                    {
                        sw.WriteLine(string.Join(",", new string[]
                        {
                            CsvUtils.EscapeField(""),
                            CsvUtils.EscapeField(""),
                            CsvUtils.EscapeField(""),
                            CsvUtils.EscapeField(""),
                            CsvUtils.EscapeField(""),
                            CsvUtils.EscapeField(""),
                            CsvUtils.EscapeField(""),
                            CsvUtils.EscapeField(""),
                            CsvUtils.EscapeField(note)
                        }));
                    }
                }

                using (var sw = new StreamWriter(appCsv, false, new UTF8Encoding(false)))
                {
                    sw.WriteLine("Timestamp,AppId,Path,User,ForegroundCycleTime,BackgroundCycleTime,ParserNote");
                    foreach (SrumAppRecord row in export.AppRows)
                    {
                        sw.WriteLine(string.Join(",", new string[]
                        {
                            CsvUtils.EscapeField(row.Timestamp),
                            CsvUtils.EscapeField(row.AppId),
                            CsvUtils.EscapeField(row.Path),
                            CsvUtils.EscapeField(row.User),
                            CsvUtils.EscapeField(row.ForegroundCycleTime),
                            CsvUtils.EscapeField(row.BackgroundCycleTime),
                            CsvUtils.EscapeField(row.ParserNote)
                        }));
                    }
                    foreach (string note in export.ParserNotes)
                    {
                        sw.WriteLine(string.Join(",", new string[]
                        {
                            CsvUtils.EscapeField(""),
                            CsvUtils.EscapeField(""),
                            CsvUtils.EscapeField(""),
                            CsvUtils.EscapeField(""),
                            CsvUtils.EscapeField(""),
                            CsvUtils.EscapeField(""),
                            CsvUtils.EscapeField(note)
                        }));
                    }
                }
                Console.WriteLine("    + SRUM structured CSV exported.");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("    ! Error exporting SRUM structured CSV: " + ex.Message);
                Logger.Warning("ExecutionArtifactCollector.SrumStructured: " + ex.Message);
                return false;
            }
        }

        private static bool TryCopyLockedFileWithEsentutl(string srcPath, string destPath)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("esentutl.exe", "/y \"" + srcPath + "\" /d \"" + destPath + "\" /o");
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                using (Process p = Process.Start(psi))
                {
                    string stdErr = p.StandardError.ReadToEnd();
                    p.StandardOutput.ReadToEnd();
                    p.WaitForExit();
                    if (p.ExitCode == 0 && File.Exists(destPath))
                        return true;
                    if (!string.IsNullOrWhiteSpace(stdErr))
                        Logger.Warning("ExecutionArtifactCollector.esentutl: " + stdErr.Trim());
                }
            }
            catch (Exception ex)
            {
                Logger.Warning("ExecutionArtifactCollector.esentutl copy: " + ex.Message);
            }
            return false;
        }

        private static void CopyIfExists(string srcPath, string destPath)
        {
            try
            {
                if (!File.Exists(srcPath))
                    return;
                File.Copy(srcPath, destPath, true);
            }
            catch (Exception ex)
            {
                Logger.Warning("ExecutionArtifactCollector.CopyIfExists: " + ex.Message);
            }
        }

        private static DateTime TryParseBamFileTime(byte[] data)
        {
            if (data == null || data.Length < 8)
                return DateTime.MinValue;

            foreach (int offset in new int[] { 0, 8 })
            {
                if (data.Length < offset + 8)
                    continue;
                try
                {
                    long fileTime = BitConverter.ToInt64(data, offset);
                    if (fileTime <= 0)
                        continue;
                    DateTime dt = DateTime.FromFileTimeUtc(fileTime).ToLocalTime();
                    if (dt.Year >= 2000 && dt.Year <= 2100)
                        return dt;
                }
                catch { }
            }

            return DateTime.MinValue;
        }

        private static string ResolveUserFromSid(string sid)
        {
            try
            {
                using (RegistryKey prof = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\" + sid))
                {
                    if (prof == null)
                        return sid;
                    string path = prof.GetValue("ProfileImagePath") as string;
                    return string.IsNullOrWhiteSpace(path) ? sid : Path.GetFileName(path);
                }
            }
            catch
            {
                return sid;
            }
        }

        private static string SafeWmiValue(ManagementBaseObject row, params string[] propertyNames)
        {
            if (row == null || propertyNames == null)
                return "";

            foreach (string propertyName in propertyNames)
            {
                try
                {
                    object value = row[propertyName];
                    if (value == null)
                        continue;
                    string text = value.ToString();
                    if (!string.IsNullOrWhiteSpace(text))
                        return EventLogDataHelper.SanitizeSingleLine(text);
                }
                catch { }
            }
            return "";
        }

        private static string BuildWmiDetails(ManagementBaseObject row, string[] propertyNames)
        {
            var parts = new List<string>();
            if (propertyNames != null)
            {
                foreach (string propertyName in propertyNames)
                {
                    string value = SafeWmiValue(row, propertyName);
                    if (string.IsNullOrWhiteSpace(value))
                        continue;
                    if (value.Length > 400)
                        value = value.Substring(0, 397) + "...";
                    parts.Add(propertyName + "=" + value);
                }
            }
            return string.Join("; ", parts.ToArray());
        }

        private static string ComputeSha256Prefix(byte[] data)
        {
            if (data == null || data.Length == 0)
                return "";
            using (SHA256 sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(data);
                return BitConverter.ToString(hash).Replace("-", "").Substring(0, 16);
            }
        }
    }
}
