using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Text;

namespace IR_Collect.Utils
{
    internal static class EventLogFilteredCsvExporter
    {
        public const int DefaultFilteredEventLogDays = 7;
        public const int DefaultFilteredEventLogMaxEvents = 10000;

        public static int GetConfiguredDaysBack()
        {
            try
            {
                var cfg = new IR_Collect.ConfigManager();
                int days;
                if (int.TryParse(cfg.Get("EventLogDays"), out days) && days >= 0)
                    return days;
            }
            catch (Exception ex)
            {
                Logger.Warning("EventLogFilteredCsvExporter.GetConfiguredDaysBack: " + ex.Message);
            }

            return 0;
        }

        public static int GetConfiguredMaxEvents()
        {
            try
            {
                var cfg = new IR_Collect.ConfigManager();
                int maxEvents;
                if (int.TryParse(cfg.Get("EventLogMaxEvents"), out maxEvents) && maxEvents > 0)
                    return NormalizeMaxEvents(maxEvents);
            }
            catch (Exception ex)
            {
                Logger.Warning("EventLogFilteredCsvExporter.GetConfiguredMaxEvents: " + ex.Message);
            }

            return DefaultFilteredEventLogMaxEvents;
        }

        public const int DefaultFilteredEventLogFormatBudgetSeconds = 90;

        // Per-log budget (seconds) for the EXPENSIVE human-readable formatting. FormatDescription /
        // LevelDisplayName / TaskDisplayName each load the publisher's resource templates and dominate
        // runtime on big logs (e.g. Security, observed 8-13 min). Past the budget we keep EVERY event and
        // the full structured EventData (what the normalizers consume); only the display strings degrade
        // to cheap numeric/structured equivalents. 0 = always format (no budget). No events are dropped.
        public static int GetConfiguredFormatBudgetSeconds()
        {
            try
            {
                var cfg = new IR_Collect.ConfigManager();
                int sec;
                if (int.TryParse(cfg.Get("EventLogMessageFormatBudgetSeconds"), out sec) && sec >= 0)
                    return sec;
            }
            catch (Exception ex)
            {
                Logger.Warning("EventLogFilteredCsvExporter.GetConfiguredFormatBudgetSeconds: " + ex.Message);
            }
            return DefaultFilteredEventLogFormatBudgetSeconds;
        }

        public static int NormalizeConfiguredDaysBack(int configuredDaysBack)
        {
            return configuredDaysBack > 0 ? configuredDaysBack : DefaultFilteredEventLogDays;
        }

        public static int NormalizeMaxEvents(int maxPerLog)
        {
            if (maxPerLog <= 0) return DefaultFilteredEventLogMaxEvents;
            return Math.Min(maxPerLog, 100000);
        }

        public static bool TryExportFromLiveLog(string logName, string csvPath, int daysBack, int maxPerLog, out int count, out string windowDescription, out string error)
        {
            count = 0;
            error = null;
            windowDescription = null;

            try
            {
                int normalizedDays = NormalizeConfiguredDaysBack(daysBack);
                int normalizedMax = NormalizeMaxEvents(maxPerLog);
                DateTime endUtc = DateTime.UtcNow;
                DateTime startUtc = endUtc.AddDays(-normalizedDays);
                string xpath = BuildTimeRangeXPath(startUtc, endUtc);
                var query = new EventLogQuery(logName, PathType.LogName, xpath);
                windowDescription = "last " + normalizedDays + " day(s) anchored to current time";
                return TryExportFromQuery(query, csvPath, normalizedMax, out count, out error);
            }
            catch (Exception ex)
            {
                error = ex.Message;
                Logger.Error("EventLog filtered live export " + (logName ?? ""), ex);
                return false;
            }
        }

        public static bool TryExportFromEvtxFile(string evtxPath, string csvPath, int daysBack, int maxPerLog, out int count, out string windowDescription, out string error)
        {
            count = 0;
            error = null;
            windowDescription = null;

            if (string.IsNullOrWhiteSpace(evtxPath) || !File.Exists(evtxPath))
            {
                error = "EVTX file not found.";
                return false;
            }

            try
            {
                int normalizedDays = NormalizeConfiguredDaysBack(daysBack);
                int normalizedMax = NormalizeMaxEvents(maxPerLog);
                DateTime newestEventUtc;
                DateTime? startUtc = null;
                DateTime? endUtc = null;

                if (TryGetNewestEventUtc(evtxPath, out newestEventUtc))
                {
                    startUtc = newestEventUtc.AddDays(-normalizedDays);
                    endUtc = newestEventUtc;
                    windowDescription = "last " + normalizedDays + " day(s) anchored to newest event in EVTX";
                }
                else
                {
                    windowDescription = "all available events (EVTX timestamps unavailable)";
                }

                using (var reader = new EventLogReader(evtxPath, PathType.FilePath))
                {
                    return TryExportFromReader(reader, csvPath, normalizedMax, startUtc, endUtc, out count, out error);
                }
            }
            catch (Exception ex)
            {
                error = ex.Message;
                Logger.Error("EventLog filtered EVTX export " + evtxPath, ex);
                return false;
            }
        }

        private static bool TryGetNewestEventUtc(string evtxPath, out DateTime newestEventUtc)
        {
            newestEventUtc = DateTime.MinValue;
            using (var reader = new EventLogReader(evtxPath, PathType.FilePath))
            {
                EventRecord record;
                while ((record = reader.ReadEvent()) != null)
                {
                    try
                    {
                        if (record.TimeCreated.HasValue)
                        {
                            DateTime timeUtc = record.TimeCreated.Value.ToUniversalTime();
                            if (timeUtc > newestEventUtc)
                                newestEventUtc = timeUtc;
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.Warning("TryGetNewestEventUtc " + evtxPath + ": " + ex.Message);
                    }
                    finally
                    {
                        record.Dispose();
                    }
                }
            }

            return newestEventUtc > DateTime.MinValue;
        }

        private static bool TryExportFromQuery(EventLogQuery query, string csvPath, int maxPerLog, out int count, out string error)
        {
            using (var reader = new EventLogReader(query))
            {
                return TryExportFromReader(reader, csvPath, maxPerLog, null, null, out count, out error);
            }
        }

        private static bool TryExportFromReader(EventLogReader reader, string csvPath, int maxPerLog, DateTime? startUtc, DateTime? endUtc, out int count, out string error)
        {
            count = 0;
            error = null;
            string csvDir = Path.GetDirectoryName(csvPath);
            if (!string.IsNullOrEmpty(csvDir) && !Directory.Exists(csvDir))
                Directory.CreateDirectory(csvDir);

            try
            {
                using (var sw = new StreamWriter(csvPath, false, new UTF8Encoding(false)))
                {
                    sw.WriteLine("TimeCreated,EventId,LevelDisplayName,ProviderName,Computer,UserId,TaskDisplayName,Message," + EventLogDataHelper.EventDataColumn);

                    int budgetSec = GetConfiguredFormatBudgetSeconds();
                    DateTime formatDeadline = budgetSec > 0 ? DateTime.UtcNow.AddSeconds(budgetSec) : DateTime.MaxValue;
                    int degraded = 0;

                    EventRecord record;
                    while (count < maxPerLog && (record = reader.ReadEvent()) != null)
                    {
                        try
                        {
                            if (!ShouldIncludeRecord(record, startUtc, endUtc))
                                continue;
                            // Past the budget, skip the expensive publisher-template formatting but KEEP
                            // the event and its full structured EventData (no forensic loss).
                            bool degrade = DateTime.UtcNow >= formatDeadline;
                            WriteRecord(sw, record, degrade);
                            if (degrade) degraded++;
                            count++;
                        }
                        catch (Exception ex)
                        {
                            Logger.Warning("EventLogFilteredCsvExporter.WriteRecord: " + ex.Message);
                        }
                        finally
                        {
                            record.Dispose();
                        }
                    }

                    if (degraded > 0)
                        Console.WriteLine(string.Format("      ({0}s format budget exceeded: {1}/{2} events kept with fast formatting; all events + structured EventData retained, message/level/task display degraded)", budgetSec, degraded, count));
                }

                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                TryDeleteIncompleteCsv(csvPath);
                return false;
            }
        }

        private static bool ShouldIncludeRecord(EventRecord record, DateTime? startUtc, DateTime? endUtc)
        {
            if (!startUtc.HasValue || !endUtc.HasValue)
                return true;
            if (record == null || !record.TimeCreated.HasValue)
                return false;

            DateTime eventUtc = record.TimeCreated.Value.ToUniversalTime();
            return eventUtc >= startUtc.Value && eventUtc <= endUtc.Value;
        }

        private static void WriteRecord(StreamWriter sw, EventRecord record)
        {
            WriteRecord(sw, record, false);
        }

        /// <param name="degrade">When true, skip the expensive publisher-template lookups
        /// (FormatDescription / LevelDisplayName / TaskDisplayName) and use cheap numeric/structured
        /// equivalents. The structured EventData column is unaffected, so normalizers are unchanged.</param>
        private static void WriteRecord(StreamWriter sw, EventRecord record, bool degrade)
        {
            string xml = "";
            try { xml = record.ToXml(); }
            catch { xml = ""; }

            Dictionary<string, string> eventData = EventLogDataHelper.ExtractEventDataFromXml(xml);
            string flattenedEventData = EventLogDataHelper.FlattenEventData(eventData, 48, 220, 2400);
            string time = SafeGetString(delegate { return record.TimeCreated.HasValue ? record.TimeCreated.Value.ToString("yyyy-MM-dd HH:mm:ss") : ""; });
            string eventId = SafeGetString(delegate { return record.Id.ToString(); });
            string level = degrade
                ? SafeGetString(delegate { return record.Level.HasValue ? record.Level.Value.ToString() : ""; })
                : SafeGetString(delegate { return record.LevelDisplayName ?? ""; });
            string provider = SafeGetString(delegate { return record.ProviderName ?? ""; });
            string computer = SafeGetString(delegate { return record.MachineName ?? ""; });
            string userId = SafeGetString(delegate { return record.UserId != null ? record.UserId.Value : ""; });
            string taskDisplay = degrade
                ? SafeGetString(delegate { return record.Task.HasValue ? record.Task.Value.ToString() : ""; })
                : SafeGetString(delegate { return record.TaskDisplayName ?? (record.Task.HasValue ? record.Task.Value.ToString() : ""); });
            string message = degrade
                ? (flattenedEventData.Length > 500 ? flattenedEventData.Substring(0, 497) + "..." : flattenedEventData)
                : BuildFilteredEventMessage(record, flattenedEventData, xml);

            sw.WriteLine(string.Join(",",
                Csv(time),
                Csv(eventId),
                Csv(level),
                Csv(provider),
                Csv(computer),
                Csv(userId),
                Csv(taskDisplay),
                Csv(message),
                Csv(flattenedEventData)));
        }

        private static string BuildTimeRangeXPath(DateTime startUtc, DateTime endUtc)
        {
            string startStr = startUtc.ToString("yyyy-MM-ddTHH:mm:ssZ");
            string endStr = endUtc.ToString("yyyy-MM-ddTHH:mm:ssZ");
            return string.Format("*[System[TimeCreated[@SystemTime>='{0}' and @SystemTime<='{1}']]]", startStr, endStr);
        }

        private static string BuildFilteredEventMessage(EventRecord record, string flattenedEventData, string xml)
        {
            string message = "";
            try { message = record.FormatDescription() ?? ""; }
            catch { message = ""; }

            message = EventLogDataHelper.SanitizeSingleLine(message);

            if (string.IsNullOrWhiteSpace(message) && !string.IsNullOrWhiteSpace(flattenedEventData))
                message = flattenedEventData;

            if (string.IsNullOrWhiteSpace(message) && !string.IsNullOrWhiteSpace(xml))
                message = EventLogDataHelper.SanitizeSingleLine(xml);

            if (message.Length > 500)
                message = message.Substring(0, 497) + "...";

            return message;
        }

        private static void TryDeleteIncompleteCsv(string csvPath)
        {
            try
            {
                if (!string.IsNullOrEmpty(csvPath) && File.Exists(csvPath))
                    File.Delete(csvPath);
            }
            catch (Exception ex)
            {
                Logger.Warning("TryDeleteIncompleteCsv " + (csvPath ?? "") + ": " + ex.Message);
            }
        }

        private static string Csv(string value)
        {
            string text = value ?? "";
            return "\"" + text.Replace("\"", "\"\"") + "\"";
        }

        private static string SafeGetString(Func<string> getter)
        {
            try
            {
                return getter() ?? "";
            }
            catch
            {
                return "";
            }
        }
    }
}
