using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Net.NetworkInformation;
using System.Text;

namespace IR_Collect.Collectors
{
    public static class SystemCollector
    {
        private sealed class ProcessWmiInfo
        {
            public string CommandLine;
            public int PPID;
            public int SessionId;
            public int ThreadCount;
            public ulong WorkingSetSize;
            public string User;
        }

        private sealed class ProcessBinaryMetadata
        {
            public string Hash;
            public string SignatureStatus;
            public string Signer;
        }

        public static void Collect(string outputDir)
        {
            Console.WriteLine("[*] Collecting System Information...");
            var failedParts = new List<string>();
            if (!CollectProcesses(outputDir)) failedParts.Add("Processes");
            if (!CollectNetwork(outputDir)) failedParts.Add("Network");
            if (!CollectSystemInfo(outputDir)) failedParts.Add("SystemInfo");
            if (failedParts.Count > 0)
                throw new InvalidOperationException("System collection incomplete: " + string.Join(", ", failedParts.ToArray()));
        }

        private static bool CollectProcesses(string outputDir)
        {
            try
            {
                string outFile = Path.Combine(outputDir, ArtifactNames.ProcessListCsv);
                using (StreamWriter sw = new StreamWriter(outFile, false, new System.Text.UTF8Encoding(false)))
                {
                    sw.WriteLine("PID,Name,Path,CommandLine,StartTime,User,SHA256,SignatureStatus,Signer,PPID,SessionId,ThreadCount,WorkingSetSize");
                    var wmiInfo = GetProcessWmiInfo();
                    var binaryCache = new Dictionary<string, ProcessBinaryMetadata>(StringComparer.OrdinalIgnoreCase);

                    foreach (Process p in Process.GetProcesses())
                    {
                        try
                        {
                            string path = "";
                            string startTime = "";
                            string cmdLine = "";
                            string hash = "";
                            string sigStatus = "";
                            string signer = "";
                            int ppid = 0;
                            int sessionId = 0;
                            int threadCount = 0;
                            ulong workingSet = 0;
                            string user = "";

                            try { path = p.MainModule.FileName; } catch { }
                            try { startTime = p.StartTime.ToString("yyyy-MM-dd HH:mm:ss"); } catch { }

                            ProcessWmiInfo info;
                            if (wmiInfo != null && wmiInfo.TryGetValue(p.Id, out info))
                            {
                                cmdLine = info.CommandLine ?? "";
                                ppid = info.PPID;
                                sessionId = info.SessionId;
                                threadCount = info.ThreadCount;
                                workingSet = info.WorkingSetSize;
                                user = info.User ?? "";
                            }

                            if (!string.IsNullOrEmpty(path) && File.Exists(path))
                            {
                                ProcessBinaryMetadata metadata = GetProcessBinaryMetadata(path, binaryCache);
                                hash = metadata.Hash;
                                sigStatus = metadata.SignatureStatus;
                                signer = metadata.Signer;
                            }

                            sw.WriteLine(string.Format("{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12}",
                                p.Id,
                                IR_Collect.Utils.CsvUtils.EscapeField(p.ProcessName),
                                IR_Collect.Utils.CsvUtils.EscapeField(path),
                                IR_Collect.Utils.CsvUtils.EscapeField(cmdLine),
                                startTime,
                                IR_Collect.Utils.CsvUtils.EscapeField(user),
                                hash,
                                IR_Collect.Utils.CsvUtils.EscapeField(sigStatus),
                                IR_Collect.Utils.CsvUtils.EscapeField(signer),
                                ppid,
                                sessionId,
                                threadCount,
                                workingSet
                            ));
                        }
                        catch (Exception ex)
                        {
                            IR_Collect.Utils.Logger.Warning("Process list skip PID " + p.Id + ": " + ex.Message);
                        }
                        finally
                        {
                            try { p.Dispose(); } catch { }
                        }
                    }
                }
                Console.WriteLine("    + Processes collected (with Hashes, PPID, User, SessionId, ThreadCount, WorkingSetSize).");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("    ! Error collecting processes: " + ex.Message);
                IR_Collect.Utils.Logger.Error("CollectProcesses", ex);
                return false;
            }
        }

        private static bool CollectNetwork(string outputDir)
        {
            int collected = 0;
            if (TryCollectNetworkArtifact("network connections", "netstat", "-ano", Path.Combine(outputDir, "network_connections.txt"))) collected++;
            if (TryCollectNetworkArtifact("ARP table", "arp", "-a", Path.Combine(outputDir, "arp_table.txt"))) collected++;
            if (TryCollectNetworkArtifact("DNS cache", "ipconfig", "/displaydns", Path.Combine(outputDir, "dns_cache.txt"))) collected++;
            if (TryCollectNetworkArtifact("network configuration", "ipconfig", "/all", Path.Combine(outputDir, "network_config.txt"))) collected++;
            if (CollectLogonSessions(outputDir)) collected++;
            if (CollectNetworkResources(outputDir)) collected++;
            if (CollectServerConnections(outputDir)) collected++;
            if (CollectStoredCredentials(outputDir)) collected++;
            if (CollectKerberosTickets(outputDir)) collected++;

            if (collected > 0)
                Console.WriteLine("    + Network / identity artifacts collected: " + collected + "/9.");
            else
                Console.WriteLine("    ! Error collecting network: no network / identity artifacts collected.");
            return collected > 0;
        }

        private static bool CollectSystemInfo(string outputDir)
        {
             try
            {
                string outFile = Path.Combine(outputDir, ArtifactNames.SystemInfoFullTxt);
                IR_Collect.Collector.CommandHelper.RunToFile("systeminfo", "", outFile);
                Console.WriteLine("    + SystemInfo collected.");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("    ! Error collecting systeminfo: " + ex.Message);
                IR_Collect.Utils.Logger.Warning("CollectSystemInfo: " + ex.Message);
                return false;
            }
        }

        private static bool TryCollectNetworkArtifact(string description, string fileName, string args, string outputFile)
        {
            try
            {
                IR_Collect.Collector.CommandHelper.RunToFile(fileName, args, outputFile);
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("    ! Error collecting " + description + ": " + ex.Message);
                IR_Collect.Utils.Logger.Warning("CollectNetwork " + description + ": " + ex.Message);
                return false;
            }
        }

        private static bool CollectLogonSessions(string outputDir)
        {
            string outFile = Path.Combine(outputDir, ArtifactNames.LogonSessionsCsv);
            try
            {
                using (var sw = new StreamWriter(outFile, false, new UTF8Encoding(false)))
                {
                    sw.WriteLine("ObservedAtUtc,StartTime,LogonId,User,Domain,Sid,LogonType,LogonTypeName,AuthenticationPackage,LogonProcessName");
                    string observedAt = DateTime.UtcNow.ToString("o");
                    using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_LogonSession"))
                    using (ManagementObjectCollection rows = searcher.Get())
                    {
                        foreach (ManagementObject row in rows)
                        {
                            try
                            {
                                string logonId = SafeWmiValue(row, "LogonId");
                                string startTime = ConvertManagementDateTime(SafeWmiValue(row, "StartTime"));
                                string logonType = SafeWmiValue(row, "LogonType");
                                string authPackage = SafeWmiValue(row, "AuthenticationPackage");
                                string logonProcess = SafeWmiValue(row, "LogonProcessName");
                                string logonTypeName = GetLogonTypeName(logonType);

                                var accounts = GetAssociatedAccountsForLogonSession(logonId);
                                if (accounts.Count == 0)
                                {
                                    WriteLogonSessionRow(sw, observedAt, startTime, logonId, "", "", "", logonType, logonTypeName, authPackage, logonProcess);
                                }
                                else
                                {
                                    foreach (AssociatedAccount account in accounts)
                                    {
                                        string user = string.IsNullOrWhiteSpace(account.Name) ? "" : (string.IsNullOrWhiteSpace(account.Domain) ? account.Name : (account.Domain + "\\" + account.Name));
                                        WriteLogonSessionRow(sw, observedAt, startTime, logonId, user, account.Domain, account.Sid, logonType, logonTypeName, authPackage, logonProcess);
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                IR_Collect.Utils.Logger.Warning("CollectLogonSessions row: " + ex.Message);
                            }
                            finally
                            {
                                try { row.Dispose(); } catch { }
                            }
                        }
                    }
                }
                Console.WriteLine("    + Logon sessions collected.");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("    ! Error collecting logon sessions: " + ex.Message);
                IR_Collect.Utils.Logger.Warning("CollectLogonSessions: " + ex.Message);
                return false;
            }
        }

        private static void WriteLogonSessionRow(StreamWriter sw, string observedAt, string startTime, string logonId, string user, string domain, string sid, string logonType, string logonTypeName, string authPackage, string logonProcess)
        {
            sw.WriteLine(string.Join(",", new string[]
            {
                IR_Collect.Utils.CsvUtils.EscapeField(observedAt),
                IR_Collect.Utils.CsvUtils.EscapeField(startTime),
                IR_Collect.Utils.CsvUtils.EscapeField(logonId),
                IR_Collect.Utils.CsvUtils.EscapeField(user),
                IR_Collect.Utils.CsvUtils.EscapeField(domain),
                IR_Collect.Utils.CsvUtils.EscapeField(sid),
                IR_Collect.Utils.CsvUtils.EscapeField(logonType),
                IR_Collect.Utils.CsvUtils.EscapeField(logonTypeName),
                IR_Collect.Utils.CsvUtils.EscapeField(authPackage),
                IR_Collect.Utils.CsvUtils.EscapeField(logonProcess)
            }));
        }

        private static bool CollectNetworkResources(string outputDir)
        {
            string outFile = Path.Combine(outputDir, ArtifactNames.NetworkResourcesCsv);
            try
            {
                using (var sw = new StreamWriter(outFile, false, new UTF8Encoding(false)))
                {
                    sw.WriteLine("ObservedAtUtc,LocalName,RemoteName,UserName,ConnectionState,ConnectionType,DisplayType,ProviderName,Persistent,Status,Comment");
                    string observedAt = DateTime.UtcNow.ToString("o");
                    using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_NetworkConnection"))
                    using (ManagementObjectCollection rows = searcher.Get())
                    {
                        foreach (ManagementObject row in rows)
                        {
                            try
                            {
                                sw.WriteLine(string.Join(",", new string[]
                                {
                                    IR_Collect.Utils.CsvUtils.EscapeField(observedAt),
                                    IR_Collect.Utils.CsvUtils.EscapeField(SafeWmiValue(row, "LocalName")),
                                    IR_Collect.Utils.CsvUtils.EscapeField(SafeWmiValue(row, "RemoteName")),
                                    IR_Collect.Utils.CsvUtils.EscapeField(SafeWmiValue(row, "UserName")),
                                    IR_Collect.Utils.CsvUtils.EscapeField(SafeWmiValue(row, "ConnectionState")),
                                    IR_Collect.Utils.CsvUtils.EscapeField(SafeWmiValue(row, "ConnectionType")),
                                    IR_Collect.Utils.CsvUtils.EscapeField(SafeWmiValue(row, "DisplayType")),
                                    IR_Collect.Utils.CsvUtils.EscapeField(SafeWmiValue(row, "ProviderName")),
                                    IR_Collect.Utils.CsvUtils.EscapeField(SafeWmiValue(row, "Persistent")),
                                    IR_Collect.Utils.CsvUtils.EscapeField(SafeWmiValue(row, "Status")),
                                    IR_Collect.Utils.CsvUtils.EscapeField(SafeWmiValue(row, "Comment"))
                                }));
                            }
                            catch (Exception ex)
                            {
                                IR_Collect.Utils.Logger.Warning("CollectNetworkResources row: " + ex.Message);
                            }
                            finally
                            {
                                try { row.Dispose(); } catch { }
                            }
                        }
                    }
                }
                Console.WriteLine("    + Network resource connections collected.");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("    ! Error collecting network resources: " + ex.Message);
                IR_Collect.Utils.Logger.Warning("CollectNetworkResources: " + ex.Message);
                return false;
            }
        }

        private static bool CollectServerConnections(string outputDir)
        {
            string outFile = Path.Combine(outputDir, ArtifactNames.ServerConnectionsCsv);
            try
            {
                using (var sw = new StreamWriter(outFile, false, new UTF8Encoding(false)))
                {
                    sw.WriteLine("ObservedAtUtc,ComputerName,UserName,ShareName,ActiveTimeSec,IdleTimeSec,ConnectionId,NumberOfFiles,NumberOfUsers");
                    string observedAt = DateTime.UtcNow.ToString("o");
                    using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ServerConnection"))
                    using (ManagementObjectCollection rows = searcher.Get())
                    {
                        foreach (ManagementObject row in rows)
                        {
                            try
                            {
                                sw.WriteLine(string.Join(",", new string[]
                                {
                                    IR_Collect.Utils.CsvUtils.EscapeField(observedAt),
                                    IR_Collect.Utils.CsvUtils.EscapeField(SafeWmiValue(row, "ComputerName")),
                                    IR_Collect.Utils.CsvUtils.EscapeField(SafeWmiValue(row, "UserName")),
                                    IR_Collect.Utils.CsvUtils.EscapeField(SafeWmiValue(row, "ShareName")),
                                    IR_Collect.Utils.CsvUtils.EscapeField(SafeWmiValue(row, "ActiveTime")),
                                    IR_Collect.Utils.CsvUtils.EscapeField(SafeWmiValue(row, "IdleTime")),
                                    IR_Collect.Utils.CsvUtils.EscapeField(SafeWmiValue(row, "ConnectionID")),
                                    IR_Collect.Utils.CsvUtils.EscapeField(SafeWmiValue(row, "NumberOfFiles")),
                                    IR_Collect.Utils.CsvUtils.EscapeField(SafeWmiValue(row, "NumberOfUsers"))
                                }));
                            }
                            catch (Exception ex)
                            {
                                IR_Collect.Utils.Logger.Warning("CollectServerConnections row: " + ex.Message);
                            }
                            finally
                            {
                                try { row.Dispose(); } catch { }
                            }
                        }
                    }
                }
                Console.WriteLine("    + Incoming server connections collected.");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("    ! Error collecting server connections: " + ex.Message);
                IR_Collect.Utils.Logger.Warning("CollectServerConnections: " + ex.Message);
                return false;
            }
        }

        private static bool CollectStoredCredentials(string outputDir)
        {
            string outFile = Path.Combine(outputDir, ArtifactNames.StoredCredentialsTxt);
            try
            {
                string output = IR_Collect.Collector.CommandHelper.Run("cmdkey", "/list");
                File.WriteAllText(outFile,
                    "ObservedAtUtc: " + DateTime.UtcNow.ToString("o") + Environment.NewLine + output,
                    new UTF8Encoding(false));
                Console.WriteLine("    + Stored credentials collected.");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("    ! Error collecting stored credentials: " + ex.Message);
                IR_Collect.Utils.Logger.Warning("CollectStoredCredentials: " + ex.Message);
                return false;
            }
        }

        private static bool CollectKerberosTickets(string outputDir)
        {
            string outFile = Path.Combine(outputDir, ArtifactNames.KerberosTicketsTxt);
            try
            {
                string output = IR_Collect.Collector.CommandHelper.Run("klist", "");
                File.WriteAllText(outFile,
                    "ObservedAtUtc: " + DateTime.UtcNow.ToString("o") + Environment.NewLine + output,
                    new UTF8Encoding(false));
                Console.WriteLine("    + Kerberos tickets collected.");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("    ! Error collecting Kerberos tickets: " + ex.Message);
                IR_Collect.Utils.Logger.Warning("CollectKerberosTickets: " + ex.Message);
                return false;
            }
        }


        private static string ComputeSha256(string file)
        {
            try
            {
                using (var sha256 = System.Security.Cryptography.SHA256.Create())
                {
                    FileInfo fi = new FileInfo(file);
                    // 50MB limit to improve speed
                    if (fi.Length > 50 * 1024 * 1024) return "[Skipped-LargeFile]";

                    using (var stream = File.OpenRead(file))
                    {
                        var hash = sha256.ComputeHash(stream);
                        return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                    }
                }
            }
            catch 
            {
                return "";
            }
        }

        private static ProcessBinaryMetadata GetProcessBinaryMetadata(string path, Dictionary<string, ProcessBinaryMetadata> cache)
        {
            if (cache == null) cache = new Dictionary<string, ProcessBinaryMetadata>(StringComparer.OrdinalIgnoreCase);

            ProcessBinaryMetadata metadata;
            if (cache.TryGetValue(path, out metadata))
                return metadata;

            metadata = new ProcessBinaryMetadata();
            metadata.Hash = ComputeSha256(path);
            string signer;
            metadata.SignatureStatus = IR_Collect.SignatureHelper.GetSignatureStatus(path, out signer);
            metadata.Signer = signer ?? "";
            cache[path] = metadata;
            return metadata;
        }


        private static Dictionary<int, ProcessWmiInfo> GetProcessWmiInfo()
        {
            var results = new Dictionary<int, ProcessWmiInfo>();
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT ProcessId, CommandLine, ParentProcessId, SessionId, ThreadCount, WorkingSetSize FROM Win32_Process"))
                {
                    foreach (ManagementBaseObject baseObj in searcher.Get())
                    {
                        ManagementObject obj = baseObj as ManagementObject;
                        if (obj == null) continue;
                        try
                        {
                            object pidObj = obj["ProcessId"];
                            if (pidObj == null) continue;
                            int pid = Convert.ToInt32(pidObj);
                            string cmd = obj["CommandLine"] != null ? obj["CommandLine"].ToString() : "";
                            int ppid = 0;
                            if (obj["ParentProcessId"] != null)
                                try { ppid = Convert.ToInt32(obj["ParentProcessId"]); } catch { }
                            int sessionId = 0;
                            if (obj["SessionId"] != null)
                                try { sessionId = Convert.ToInt32(obj["SessionId"]); } catch { }
                            int threadCount = 0;
                            if (obj["ThreadCount"] != null)
                                try { threadCount = Convert.ToInt32(obj["ThreadCount"]); } catch { }
                            ulong workingSet = 0;
                            if (obj["WorkingSetSize"] != null)
                                try { workingSet = Convert.ToUInt64(obj["WorkingSetSize"]); } catch { }
                            string user = "";
                            try
                            {
                                ManagementBaseObject outParams = obj.InvokeMethod("GetOwner", null, null) as ManagementBaseObject;
                                using (outParams)
                                {
                                    if (outParams != null && outParams["User"] != null)
                                    {
                                        string domain = outParams["Domain"] != null ? outParams["Domain"].ToString() : "";
                                        string u = outParams["User"].ToString();
                                        user = string.IsNullOrEmpty(domain) ? u : (domain + "\\" + u);
                                    }
                                }
                            }
                            catch { }
                            results[pid] = new ProcessWmiInfo
                            {
                                CommandLine = cmd,
                                PPID = ppid,
                                SessionId = sessionId,
                                ThreadCount = threadCount,
                                WorkingSetSize = workingSet,
                                User = user
                            };
                        }
                        catch { }
                        finally
                        {
                            try { if (obj != null) obj.Dispose(); } catch { }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("    ! Error fetching process WMI: " + ex.Message);
                IR_Collect.Utils.Logger.Warning("GetProcessWmiInfo: " + ex.Message);
            }
            return results;
        }

        private sealed class AssociatedAccount
        {
            public string Domain;
            public string Name;
            public string Sid;
        }

        private static List<AssociatedAccount> GetAssociatedAccountsForLogonSession(string logonId)
        {
            var results = new List<AssociatedAccount>();
            if (string.IsNullOrWhiteSpace(logonId))
                return results;

            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                string query = string.Format("ASSOCIATORS OF {{Win32_LogonSession.LogonId=\"{0}\"}} WHERE AssocClass=Win32_LoggedOnUser Role=Dependent", logonId.Replace("\"", ""));
                using (var searcher = new ManagementObjectSearcher(query))
                using (ManagementObjectCollection accounts = searcher.Get())
                {
                    foreach (ManagementObject account in accounts)
                    {
                        try
                        {
                            string domain = SafeWmiValue(account, "Domain");
                            string name = SafeWmiValue(account, "Name");
                            string sid = SafeWmiValue(account, "SID");
                            string key = (domain ?? "") + "\\" + (name ?? "") + "|" + (sid ?? "");
                            if (!seen.Add(key))
                                continue;
                            results.Add(new AssociatedAccount { Domain = domain, Name = name, Sid = sid });
                        }
                        catch (Exception ex)
                        {
                            IR_Collect.Utils.Logger.Warning("GetAssociatedAccountsForLogonSession row: " + ex.Message);
                        }
                        finally
                        {
                            try { account.Dispose(); } catch { }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                IR_Collect.Utils.Logger.Warning("GetAssociatedAccountsForLogonSession " + logonId + ": " + ex.Message);
            }
            return results;
        }

        private static string SafeWmiValue(ManagementBaseObject row, params string[] propertyNames)
        {
            if (row == null || propertyNames == null)
                return "";

            foreach (string propertyName in propertyNames)
            {
                if (string.IsNullOrWhiteSpace(propertyName))
                    continue;
                try
                {
                    object value = row[propertyName];
                    if (value != null)
                        return value.ToString();
                }
                catch
                {
                }
            }

            return "";
        }

        private static string ConvertManagementDateTime(string raw)
        {
            if (string.IsNullOrWhiteSpace(raw))
                return "";
            try
            {
                DateTime dt = ManagementDateTimeConverter.ToDateTime(raw);
                return dt.ToString("o");
            }
            catch
            {
                return raw.Trim();
            }
        }

        private static string GetLogonTypeName(string logonType)
        {
            switch ((logonType ?? "").Trim())
            {
                case "2": return "Interactive";
                case "3": return "Network";
                case "4": return "Batch";
                case "5": return "Service";
                case "7": return "Unlock";
                case "8": return "NetworkCleartext";
                case "9": return "NewCredentials";
                case "10": return "RemoteInteractive";
                case "11": return "CachedInteractive";
                default: return "";
            }
        }
    }
}
