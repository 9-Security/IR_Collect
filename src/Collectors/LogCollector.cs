using System;
using System.IO;
using System.Diagnostics;
using System.Text;
using System.Collections.Generic;
using IR_Collect;
using IR_Collect.Utils;

namespace IR_Collect.Collectors
{
    public static class LogCollector
    {
        public static void Collect(string outputDir)
        {
            Console.WriteLine("[*] Collecting Event Logs...");
            string logsDir = Path.Combine(outputDir, "EventLogs");
            Directory.CreateDirectory(logsDir);

            int eventLogDays = EventLogFilteredCsvExporter.GetConfiguredDaysBack();
            int maxEvents = EventLogFilteredCsvExporter.GetConfiguredMaxEvents();
            int filteredDays = EventLogFilteredCsvExporter.NormalizeConfiguredDaysBack(eventLogDays);

            string[] logs = {
                "System", "Security", "Application",
                "Microsoft-Windows-PowerShell/Operational",
                "Microsoft-Windows-TaskScheduler/Operational",
                "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
                "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
                "Microsoft-Windows-Windows Defender/Operational",
                "Microsoft-Windows-SmbClient/Operational"
            };

            int exported = 0, failed = 0;
            foreach (string log in logs)
            {
                string safeName = log.Replace("/", "_").Replace("%4", "_").Replace("Microsoft-Windows-", "");
                string outFile = Path.Combine(logsDir, safeName + ".evtx");
                bool ok = TryExportEventLog(log, outFile, safeName);
                if (!ok)
                {
                    System.Threading.Thread.Sleep(1000);
                    ok = TryExportEventLog(log, outFile, safeName);
                }
                if (ok) exported++; else failed++;
            }
            if (failed > 0)
            {
                Console.WriteLine("    Event logs: {0} exported, {1} failed (check logs/ir_collect.log).", exported, failed);
                throw new InvalidOperationException(string.Format("Event log export incomplete: {0} failed.", failed));
            }

            int filteredSuccessCount = TryCollectFiltered(logsDir, logs, filteredDays, maxEvents);
            if (filteredSuccessCount <= 0)
            {
                Console.WriteLine("    Filtered event CSV export unavailable; full EVTX exports were preserved.");
                Logger.Warning("EventLog filtered export unavailable. Full EVTX exports were preserved.");
            }
            else if (filteredSuccessCount < logs.Length)
            {
                Console.WriteLine("    Filtered event CSV: {0}/{1} exported; EVTX exports remain complete.", filteredSuccessCount, logs.Length);
                Logger.Warning("EventLog filtered export incomplete: " + filteredSuccessCount + "/" + logs.Length + " logs.");
            }
        }

        private static bool TryExportEventLog(string logName, string outFile, string safeName)
        {
            try
            {
                Console.WriteLine("    Exporting " + safeName + "...");
                string arg = "epl " + IR_Collect.Collector.CommandHelper.EscapeArgForCmd(logName) + " " + IR_Collect.Collector.CommandHelper.EscapeArgForCmd(outFile);
                ProcessStartInfo psi = new ProcessStartInfo("wevtutil", arg);
                psi.WindowStyle = ProcessWindowStyle.Hidden;
                psi.CreateNoWindow = true;
                psi.UseShellExecute = false;
                using (Process p = Process.Start(psi))
                {
                    p.WaitForExit();
                    if (p.ExitCode != 0)
                    {
                        Logger.Warning("EventLog export " + logName + " exited with code " + p.ExitCode);
                        return false;
                    }
                }
                if (File.Exists(outFile) && new FileInfo(outFile).Length > 0) return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("    ! Failed to export " + logName + ": " + ex.Message);
                Logger.Error("EventLog export " + logName, ex);
            }
            return false;
        }

        private static void CollectFiltered(string logsDir, string[] logNames, int daysBack, int maxPerLog)
        {
            int filteredSuccessCount = TryCollectFiltered(logsDir, logNames, daysBack, maxPerLog);
            if (ShouldFallbackToFullExport(filteredSuccessCount))
            {
                // Filtered mode failed; fall back to full .evtx export
                Logger.Warning("CollectFiltered: filtered mode failed, falling back to full evtx export.");
                int exported = 0, failed = 0;
                foreach (string log in logNames)
                {
                    string safeName = log.Replace("/", "_").Replace("%4", "_").Replace("Microsoft-Windows-", "");
                    string outFile = Path.Combine(logsDir, safeName + ".evtx");
                    bool ok = TryExportEventLog(log, outFile, safeName);
                    if (!ok)
                    {
                        System.Threading.Thread.Sleep(1000);
                        ok = TryExportEventLog(log, outFile, safeName);
                    }
                    if (ok) exported++; else failed++;
                }
                if (failed > 0)
                {
                    Console.WriteLine("    Fallback evtx: {0} exported, {1} failed.", exported, failed);
                    throw new InvalidOperationException(string.Format("Fallback event log export incomplete: {0} failed.", failed));
                }
            }
            else if (filteredSuccessCount < logNames.Length)
            {
                Console.WriteLine("    Filtered event logs: {0}/{1} exported.", filteredSuccessCount, logNames.Length);
                throw new InvalidOperationException(string.Format("Filtered event log export incomplete: {0}/{1} exported.", filteredSuccessCount, logNames.Length));
            }
        }

        internal static bool ShouldFallbackToFullExport(int filteredSuccessCount)
        {
            return filteredSuccessCount <= 0;
        }

        private static int TryCollectFiltered(string logsDir, string[] logNames, int daysBack, int maxPerLog)
        {
            try
            {
                int successCount = 0;

                foreach (string logName in logNames)
                {
                    try
                    {
                        Console.WriteLine("    Filtered export " + logName + " (last " + daysBack + " days, max " + maxPerLog + ")...");
                        int count;
                        string windowDescription;
                        string error;
                        string safeName = logName.Replace("/", "_").Replace("%4", "_").Replace("Microsoft-Windows-", "");
                        string csvPath = Path.Combine(logsDir, safeName + ArtifactNames.EventLogFilteredSuffix);
                        if (!EventLogFilteredCsvExporter.TryExportFromLiveLog(logName, csvPath, daysBack, maxPerLog, out count, out windowDescription, out error))
                        {
                            throw new InvalidOperationException(error ?? "unknown error");
                        }
                        Logger.Info("EventLog filtered " + logName + ": " + count + " events (" + (windowDescription ?? "") + ")");
                        successCount++;
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("    ! Filtered " + logName + ": " + ex.Message);
                        Logger.Error("EventLog filtered " + logName, ex);
                    }
                }
                return successCount;
            }
            catch (Exception ex)
            {
                Console.WriteLine("    ! EventLog filtered mode failed: " + ex.Message);
                Logger.Error("EventLog filtered mode", ex);
                return 0;
            }
        }

    }
}
