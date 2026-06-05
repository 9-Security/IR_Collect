using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using IR_Collect.Analysis.Correlation;
using IR_Collect.Analysis.Correlation.Normalizers;

namespace IR_Collect
{
    /// <summary>Timeline Analysis 分頁：全方位時間軸，整合 Process / MFT / EventLog / Activity（Registry/JumpList/Prefetch/Recent 等），支援來源與時間篩選、CSV/JSON 匯出。</summary>
    partial class MainForm
    {
        /// <summary>統一時間軸事件 DTO。</summary>
        public class TimelineEvent
        {
            public DateTime Time { get; set; }
            public string TimeKind { get; set; }
            public string TimeConfidence { get; set; }
            public string Source { get; set; }
            public string Type { get; set; }
            public string Description { get; set; }
            public List<EntityRef> EntityRefs { get; set; }
        }

        private class EventDetailView
        {
            public string Description { get; set; }
            public string Parsed { get; set; }
            public string Xml { get; set; }
        }

        private List<TimelineEvent> BuildTimelineEvents(IR_Collect.Analysis.CaseData c)
        {
            var events = new List<TimelineEvent>();

            // 1. Process Start Times
            string procPath = ResolveArtifactPathFlexible(c, ArtifactNames.ProcessListCsv);
            if (File.Exists(procPath))
            {
                try { AddTimelineEventsFromFacts(events, ProcessNormalizer.ToFacts(procPath), 450); }
                catch (Exception ex) { IR_Collect.Utils.Logger.Warning("Timeline process list parse: " + ex.Message); }
            }

            // 1b. Live-observed logon sessions
            string logonSessionsPath = ResolveArtifactPathFlexible(c, ArtifactNames.LogonSessionsCsv);
            if (!string.IsNullOrEmpty(logonSessionsPath) && File.Exists(logonSessionsPath))
            {
                try
                {
                    AddTimelineEventsFromFacts(events, LogonSessionNormalizer.ToFacts(logonSessionsPath), 450);
                }
                catch (Exception ex) { Utils.Logger.Warning("BuildTimelineEvents.LogonSession: " + (ex.Message ?? "")); }
            }

            // 1c. Live-observed network resource connections
            string networkResourcesPath = ResolveArtifactPathFlexible(c, ArtifactNames.NetworkResourcesCsv);
            if (!string.IsNullOrEmpty(networkResourcesPath) && File.Exists(networkResourcesPath))
            {
                try
                {
                    AddTimelineEventsFromFacts(events, NetworkResourceNormalizer.ToFacts(networkResourcesPath), 450);
                }
                catch (Exception ex) { Utils.Logger.Warning("BuildTimelineEvents.NetworkResource: " + (ex.Message ?? "")); }
            }

            // 1d. Live-observed incoming server connections
            string serverConnectionsPath = ResolveArtifactPathFlexible(c, ArtifactNames.ServerConnectionsCsv);
            if (!string.IsNullOrEmpty(serverConnectionsPath) && File.Exists(serverConnectionsPath))
            {
                try
                {
                    AddTimelineEventsFromFacts(events, ServerConnectionNormalizer.ToFacts(serverConnectionsPath), 450);
                }
                catch (Exception ex) { Utils.Logger.Warning("BuildTimelineEvents.ServerConnection: " + (ex.Message ?? "")); }
            }

            string storedCredentialsPath = ResolveArtifactPathFlexible(c, ArtifactNames.StoredCredentialsTxt);
            if (!string.IsNullOrEmpty(storedCredentialsPath) && File.Exists(storedCredentialsPath))
            {
                try
                {
                    AddTimelineEventsFromFacts(events, StoredCredentialNormalizer.ToFacts(storedCredentialsPath), 450);
                }
                catch (Exception ex) { Utils.Logger.Warning("BuildTimelineEvents.StoredCredential: " + (ex.Message ?? "")); }
            }

            string kerberosTicketsPath = ResolveArtifactPathFlexible(c, ArtifactNames.KerberosTicketsTxt);
            if (!string.IsNullOrEmpty(kerberosTicketsPath) && File.Exists(kerberosTicketsPath))
            {
                try
                {
                    AddTimelineEventsFromFacts(events, KerberosTicketCacheNormalizer.ToFacts(kerberosTicketsPath), 450);
                }
                catch (Exception ex) { Utils.Logger.Warning("BuildTimelineEvents.KerberosTicketCache: " + (ex.Message ?? "")); }
            }

            // 1e. Memory acquisition / handoff orchestration metadata
            string memoryAcquisitionPath = ResolveArtifactPathFlexible(c, ArtifactNames.MemoryAcquisitionJson);
            if (!string.IsNullOrEmpty(memoryAcquisitionPath) && File.Exists(memoryAcquisitionPath))
            {
                try
                {
                    AddTimelineEventsFromFacts(events, MemoryAcquisitionNormalizer.ToFacts(memoryAcquisitionPath), 450);
                }
                catch (Exception ex) { Utils.Logger.Warning("BuildTimelineEvents.MemoryAcquisition: " + (ex.Message ?? "")); }
            }

            string memoryAnalysisPath = ResolveArtifactPathFlexible(c, ArtifactNames.MemoryAnalysisJson);
            if (!string.IsNullOrEmpty(memoryAnalysisPath) && File.Exists(memoryAnalysisPath))
            {
                try
                {
                    AddTimelineEventsFromFacts(events, MemoryAnalysisNormalizer.ToFacts(memoryAnalysisPath), 450);
                }
                catch (Exception ex) { Utils.Logger.Warning("BuildTimelineEvents.MemoryAnalysis: " + (ex.Message ?? "")); }
            }

            // 2. MFT Events (Created / Modified)
            if (c.MftEntries != null)
            {
                foreach(var m in c.MftEntries)
                {
                    DateTime created  = (m.StdCreated.Year  > 1980) ? m.StdCreated  : m.FnCreated;
                    DateTime modified = (m.StdModified.Year > 1980) ? m.StdModified : m.FnModified;
                    string desc = string.IsNullOrEmpty(m.FullPath) ? m.FileName : m.FullPath;
                    string entityType = string.IsNullOrEmpty(m.FullPath) ? "FileName" : "Path";

                    if (created.Year > 1980)
                        events.Add(new TimelineEvent {
                            Time = created,
                            TimeKind = FactTimeMetadata.MetadataTimeKind,
                            TimeConfidence = FactTimeMetadata.MediumConfidence,
                            Source = "MFT",
                            Type = "File Created",
                            Description = desc,
                            EntityRefs = CloneTimelineEntityRefs(new[] { new EntityRef(entityType, desc) })
                        });
                    if (modified.Year > 1980)
                        events.Add(new TimelineEvent {
                            Time = modified,
                            TimeKind = FactTimeMetadata.MetadataTimeKind,
                            TimeConfidence = FactTimeMetadata.MediumConfidence,
                            Source = "MFT",
                            Type = "File Modified",
                            Description = desc,
                            EntityRefs = CloneTimelineEntityRefs(new[] { new EntityRef(entityType, desc) })
                        });
                }
            }

            // 3. EventLog from *_filtered.csv
            foreach (var logFile in GetFilteredEventLogCsvPaths(c))
            {
                try
                {
                    AddTimelineEventsFromFacts(events, EventLogNormalizer.ToFacts(logFile.Item2, logFile.Item1), 300);
                }
                catch (Exception ex) { IR_Collect.Utils.Logger.Warning("Timeline EventLog CSV: " + ex.Message); }
            }

            // 4. USN Journal
            string usnPath = ResolveArtifactPathFlexible(c, ArtifactNames.UsnJournalCsv);
            if (!string.IsNullOrEmpty(usnPath) && File.Exists(usnPath))
            {
                try
                {
                    AddTimelineEventsFromFacts(events, UsnNormalizer.ToFacts(usnPath, 50000), 450);
                }
                catch (Exception ex) { Utils.Logger.Warning("BuildTimelineEvents.USN: " + (ex.Message ?? "")); }
            }

            // 5. BAM / DAM
            string bamDamPath = ResolveArtifactPathFlexible(c, ArtifactNames.BamDamCsv);
            if (!string.IsNullOrEmpty(bamDamPath) && File.Exists(bamDamPath))
            {
                try
                {
                    AddTimelineEventsFromFacts(events, BamDamNormalizer.ToFacts(bamDamPath), 450);
                }
                catch (Exception ex) { Utils.Logger.Warning("BuildTimelineEvents.BAMDAM: " + (ex.Message ?? "")); }
            }

            // 6. BITS Jobs
            string bitsPath = ResolveArtifactPathFlexible(c, ArtifactNames.BitsJobsCsv);
            if (!string.IsNullOrEmpty(bitsPath) && File.Exists(bitsPath))
            {
                try
                {
                    AddTimelineEventsFromFacts(events, BitsJobNormalizer.ToFacts(bitsPath), 450);
                }
                catch (Exception ex) { Utils.Logger.Warning("BuildTimelineEvents.BITS: " + (ex.Message ?? "")); }
            }

            // Jump List rows in the unified timeline come only from activity_timeline.csv (ActivityTimelineBuilder
            // already ingests jump_lists.csv with Source=JumpList). JumpListNormalizer facts remain in Fact Store /
            // Entity search / full_log_v3 — do not add jump_lists.csv a second time here (WP-D dedupe).

            // 7. Activity Timeline (Registry / JumpList / Prefetch / RecentFiles / Process 等)
            string activityPath = ResolveArtifactPathFlexible(c, ArtifactNames.ActivityTimelineCsv);
            if (!string.IsNullOrEmpty(activityPath) && File.Exists(activityPath))
            {
                long maxBytes = 100L * 1024 * 1024;
                int activityLimit = 50000;
                try
                {
                    if (new FileInfo(activityPath).Length <= maxBytes)
                        AddTimelineEventsFromFacts(events, ActivityTimelineNormalizer.ToFacts(activityPath).Take(activityLimit).ToList(), 450);
                }
                catch (Exception ex) { Utils.Logger.Warning("BuildTimelineEvents.Activity: " + (ex.Message ?? "")); }
            }

            // 8. Amcache (program/file observed and execution hints)
            string amcacheProgramsPath = ResolveArtifactPathFlexible(c, ArtifactNames.AmcacheProgramsCsv);
            string amcacheFilesPath = ResolveArtifactPathFlexible(c, ArtifactNames.AmcacheFilesCsv);
            if ((!string.IsNullOrEmpty(amcacheProgramsPath) && File.Exists(amcacheProgramsPath)) ||
                (!string.IsNullOrEmpty(amcacheFilesPath) && File.Exists(amcacheFilesPath)))
            {
                try
                {
                    AddTimelineEventsFromFacts(events, AmcacheNormalizer.ToFacts(amcacheProgramsPath, amcacheFilesPath), 450);
                }
                catch (Exception ex) { Utils.Logger.Warning("BuildTimelineEvents.Amcache: " + (ex.Message ?? "")); }
            }

            // 9. ShimCache entry-level reconstruction
            string shimcacheEntriesPath = ResolveArtifactPathFlexible(c, ArtifactNames.ShimCacheEntriesCsv);
            if (!string.IsNullOrEmpty(shimcacheEntriesPath) && File.Exists(shimcacheEntriesPath))
            {
                try
                {
                    AddTimelineEventsFromFacts(events, ShimCacheEntryNormalizer.ToFacts(shimcacheEntriesPath), 450);
                }
                catch (Exception ex) { Utils.Logger.Warning("BuildTimelineEvents.ShimCacheEntries: " + (ex.Message ?? "")); }
            }

            // 10. SRUM network usage
            string srumNetworkPath = ResolveArtifactPathFlexible(c, ArtifactNames.SrumNetworkUsageCsv);
            if (!string.IsNullOrEmpty(srumNetworkPath) && File.Exists(srumNetworkPath))
            {
                try
                {
                    AddTimelineEventsFromFacts(events, SrumNetworkNormalizer.ToFacts(srumNetworkPath), 450);
                }
                catch (Exception ex) { Utils.Logger.Warning("BuildTimelineEvents.SrumNetwork: " + (ex.Message ?? "")); }
            }

            // 11. SRUM app usage
            string srumAppPath = ResolveArtifactPathFlexible(c, ArtifactNames.SrumAppUsageCsv);
            if (!string.IsNullOrEmpty(srumAppPath) && File.Exists(srumAppPath))
            {
                try
                {
                    AddTimelineEventsFromFacts(events, SrumAppNormalizer.ToFacts(srumAppPath), 450);
                }
                catch (Exception ex) { Utils.Logger.Warning("BuildTimelineEvents.SrumApp: " + (ex.Message ?? "")); }
            }

            // 12. WMI persistence facts carry unknown time by design and are not added to the timeline.

            // 13. ShellBags (structured CSV / FolderBrowsed facts; time is source .reg file UTC mtime when available)
            string shellBagsPath = ResolveArtifactPathFlexible(c, ArtifactNames.ShellBagsCsv);
            if (!string.IsNullOrEmpty(shellBagsPath) && File.Exists(shellBagsPath))
            {
                try
                {
                    AddTimelineEventsFromFacts(events, ShellBagsNormalizer.ToFacts(shellBagsPath), 450);
                }
                catch (Exception ex) { Utils.Logger.Warning("BuildTimelineEvents.ShellBags: " + (ex.Message ?? "")); }
            }

            events.Sort((x, y) => y.Time.CompareTo(x.Time));
            return events;
        }

        private void AddTimelineEventsFromFacts(List<TimelineEvent> events, IEnumerable<Fact> facts, int maxDescriptionLength)
        {
            if (events == null || facts == null)
                return;

            foreach (Fact fact in facts)
            {
                if (fact == null || fact.Time.Year < 1980)
                    continue;

                events.Add(new TimelineEvent
                {
                    Time = fact.Time,
                    TimeKind = fact.TimeKind,
                    TimeConfidence = fact.TimeConfidence,
                    Source = fact.Source,
                    Type = fact.Action,
                    Description = BuildTimelineDescriptionFromFact(fact, maxDescriptionLength),
                    EntityRefs = CloneTimelineEntityRefs(fact.EntityRefs)
                });
            }
        }

        private string BuildTimelineDescriptionFromFact(Fact fact, int maxDescriptionLength)
        {
            string desc = fact != null ? (fact.Details ?? "") : "";
            if (string.IsNullOrWhiteSpace(desc))
                desc = BuildEntitySummary(fact != null ? fact.EntityRefs : null);
            if (string.IsNullOrWhiteSpace(desc))
                desc = fact != null ? (fact.Action ?? "") : "";
            if (maxDescriptionLength > 0 && desc.Length > maxDescriptionLength)
                desc = desc.Substring(0, maxDescriptionLength - 3) + "...";
            return desc;
        }

        private static List<EntityRef> CloneTimelineEntityRefs(IEnumerable<EntityRef> refs)
        {
            var clone = new List<EntityRef>();
            if (refs == null)
                return clone;

            foreach (EntityRef entity in refs)
            {
                if (entity == null || string.IsNullOrWhiteSpace(entity.Value))
                    continue;
                clone.Add(new EntityRef(entity.Type, entity.Value));
            }

            return clone;
        }

        internal static DateTime NormalizeTimelinePickerToMinute(DateTime value)
        {
            return new DateTime(value.Year, value.Month, value.Day, value.Hour, value.Minute, 0, value.Kind);
        }

        internal static DateTime NormalizeTimelineFilterStart(DateTime value)
        {
            return NormalizeTimelinePickerToMinute(value);
        }

        internal static DateTime NormalizeTimelineFilterEnd(DateTime value)
        {
            return NormalizeTimelinePickerToMinute(value).AddMinutes(1).AddTicks(-1);
        }

        internal static bool TimelineEventMatchesGraphFocus(TimelineEvent evt, string relatedType, string normalizedValue, string displayNeedle)
        {
            if (evt == null)
                return false;

            if (!string.IsNullOrWhiteSpace(relatedType) && !string.IsNullOrWhiteSpace(normalizedValue))
            {
                string expectedKey = relatedType.Trim() + ":" + normalizedValue.Trim().ToLowerInvariant();
                if (evt.EntityRefs != null)
                {
                    foreach (EntityRef entity in evt.EntityRefs)
                    {
                        if (entity == null)
                            continue;
                        if (string.Equals(entity.ToEntityKey(), expectedKey, StringComparison.OrdinalIgnoreCase))
                            return true;
                    }
                }
            }

            string needle = !string.IsNullOrWhiteSpace(displayNeedle)
                ? displayNeedle.Trim()
                : ((normalizedValue ?? "").Trim());
            if (string.IsNullOrWhiteSpace(needle))
                return false;

            string blob = ((evt.Description ?? "") + " " + (evt.Type ?? "")).Trim();
            return blob.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private List<Tuple<string, string>> GetFilteredEventLogCsvPaths(IR_Collect.Analysis.CaseData c)
        {
            var result = new List<Tuple<string, string>>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            if (c == null) return result;

            if (c.Artifacts != null)
            {
                foreach (var kvp in c.Artifacts)
                {
                    if (!ArtifactNames.IsEventLogFilteredCsv(kvp.Key)) continue;
                    if (kvp.Key.IndexOf("EventLogs", StringComparison.OrdinalIgnoreCase) < 0) continue;
                    AddFilteredEventLogCsvPath(result, seen, kvp.Value);
                }
            }

            string eventLogsDir = Path.Combine(c.ExtractPath ?? "", "EventLogs");
            if (Directory.Exists(eventLogsDir))
            {
                foreach (string path in Directory.GetFiles(eventLogsDir, ArtifactNames.EventLogFilteredGlob))
                    AddFilteredEventLogCsvPath(result, seen, path);
            }

            return result;
        }

        private void AddFilteredEventLogCsvPath(List<Tuple<string, string>> result, HashSet<string> seen, string path)
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return;

            string fullPath;
            try { fullPath = Path.GetFullPath(path); }
            catch { return; }

            if (!seen.Add(fullPath)) return;

            string logLabel = ArtifactNames.GetEventLogLabelFromFileName(Path.GetFileName(fullPath));
            result.Add(Tuple.Create(logLabel, fullPath));
        }

        private TabPage CreateTimelineTab(IR_Collect.Analysis.CaseData c)
        {
            var allEvents = BuildTimelineEvents(c);
            if (allEvents.Count == 0) return null;

            var displayEvents = new List<TimelineEvent>(allEvents);
            var sources = allEvents.Select(e => e.Source).Where(s => !string.IsNullOrEmpty(s)).Distinct().OrderBy(s => s).ToList();

            string graphRelatedType;
            string graphNormalizedValue;
            string graphTrail;
            string graphNeedle;
            bool graphHasWindow;
            DateTime graphWFrom;
            DateTime graphWTo;
            bool graphHandoff = TryConsumeTimelineGraphHandoff(c, out graphRelatedType, out graphNormalizedValue, out graphNeedle, out graphTrail, out graphHasWindow, out graphWFrom, out graphWTo);
            bool timelineGraphFocusActive = graphHandoff;
            string timelineGraphNeedle = graphNeedle ?? "";

            TabPage p = new TabPage("Timeline Analysis");
            p.ToolTipText = "Unified: Process + MFT + EventLog + Activity (Registry/JumpList/Prefetch/Recent)";

            Panel graphContextPanel = null;
            Button btnTimelineGraphClearFocus = null;
            if (graphHandoff)
            {
                graphContextPanel = new Panel();
                graphContextPanel.Dock = DockStyle.Top;
                graphContextPanel.Height = 52;
                graphContextPanel.BackColor = Color.FromArgb(255, 248, 220);
                var lblGraphTimelineContext = new Label();
                lblGraphTimelineContext.AutoSize = true;
                lblGraphTimelineContext.MaximumSize = new Size(820, 0);
                lblGraphTimelineContext.Left = 8;
                lblGraphTimelineContext.Top = 6;
                string entityLine = string.IsNullOrEmpty(timelineGraphNeedle) ? "(entity)" : timelineGraphNeedle;
                string typePrefix = string.IsNullOrEmpty(graphRelatedType) ? "Entity" : graphRelatedType;
                lblGraphTimelineContext.Text = "From investigation graph — " + typePrefix + " = \"" + entityLine + "\" (Description/Type contains this text; adjust filters as needed)" +
                    (string.IsNullOrEmpty(graphTrail) ? "" : "\r\n" + graphTrail);
                lblGraphTimelineContext.Text = "From investigation graph - " + typePrefix + " = \"" + entityLine + "\" (structured entity match first; text fallback only when no entity ref is available)" +
                    (string.IsNullOrEmpty(graphTrail) ? "" : "\r\n" + graphTrail);
                btnTimelineGraphClearFocus = new Button();
                btnTimelineGraphClearFocus.Text = "Show full timeline";
                btnTimelineGraphClearFocus.AutoSize = true;
                btnTimelineGraphClearFocus.Left = 840;
                btnTimelineGraphClearFocus.Top = 12;
                graphContextPanel.Controls.Add(lblGraphTimelineContext);
                graphContextPanel.Controls.Add(btnTimelineGraphClearFocus);
            }

            var filterPanel = new Panel();
            filterPanel.Dock = DockStyle.Top;
            filterPanel.Height = 38;
            filterPanel.BackColor = Color.WhiteSmoke;
            // 標籤與控制項：間隔 4–6px，MaximumSize 略小於欄寬防裁切（一次到位）
            var lblSource = new Label { Text = "Source:", AutoSize = true, Left = 8, Top = 10, MaximumSize = new Size(58, 0) };
            var comboSource = new ComboBox { Left = 70, Top = 6, Width = 128, DropDownStyle = ComboBoxStyle.DropDownList };
            comboSource.Items.Add("(All)");
            foreach (var s in sources) comboSource.Items.Add(s);
            comboSource.SelectedIndex = 0;
            var lblFrom = new Label { Text = "From:", AutoSize = true, Left = 204, Top = 10, MaximumSize = new Size(50, 0) };
            var dtFrom = new DateTimePicker { Left = 256, Top = 5, Width = 152, Format = DateTimePickerFormat.Custom, CustomFormat = "yyyy-MM-dd HH:mm", MinDate = new DateTime(1980, 1, 1), MaxDate = new DateTime(2100, 12, 31) };
            dtFrom.Value = NormalizeTimelinePickerToMinute(DateTime.Now.AddDays(-30));
            var lblTo = new Label { Text = "To:", AutoSize = true, Left = 414, Top = 10 };
            var dtTo = new DateTimePicker { Left = 444, Top = 5, Width = 152, Format = DateTimePickerFormat.Custom, CustomFormat = "yyyy-MM-dd HH:mm", MinDate = new DateTime(1980, 1, 1), MaxDate = new DateTime(2100, 12, 31) };
            dtTo.Value = NormalizeTimelinePickerToMinute(DateTime.Now.AddDays(1));
            if (graphHandoff && graphHasWindow)
            {
                DateTime wf = graphWFrom < dtFrom.MinDate ? dtFrom.MinDate : (graphWFrom > dtFrom.MaxDate ? dtFrom.MaxDate : graphWFrom);
                DateTime wt = graphWTo < dtTo.MinDate ? dtTo.MinDate : (graphWTo > dtTo.MaxDate ? dtTo.MaxDate : graphWTo);
                dtFrom.Value = wf;
                dtTo.Value = wt;
            }
            var btnFilterApply = new Button { Text = "Apply", Left = 620, Top = 5, Width = 72, Height = 26 };
            var btnFilterReset = new Button { Text = "Reset", Left = 698, Top = 5, Width = 72, Height = 26 };
            filterPanel.Controls.AddRange(new Control[] { lblSource, comboSource, lblFrom, dtFrom, lblTo, dtTo, btnFilterApply, btnFilterReset });

            var topPanel = new FlowLayoutPanel();
            topPanel.Height = 42;
            topPanel.Dock = DockStyle.Top;
            topPanel.FlowDirection = FlowDirection.LeftToRight;
            topPanel.WrapContents = false;
            topPanel.Padding = new Padding(8, 6, 8, 4);

            const int exportBtnHeight = 28;
            Button btnExportCsv  = new Button { Text = "CSV",  Size = new Size(72, exportBtnHeight), FlatStyle = FlatStyle.Flat, BackColor = Color.SteelBlue, ForeColor = Color.White, Margin = new Padding(0, 2, 8, 2) };
            Button btnExportJson = new Button { Text = "JSON", Size = new Size(72, exportBtnHeight), FlatStyle = FlatStyle.Flat, BackColor = Color.DarkCyan,  ForeColor = Color.White, Margin = new Padding(0, 2, 0, 2) };

            btnExportCsv.Click += (s, ev) =>
            {
                using (var dlg = new SaveFileDialog { Filter = "CSV|*.csv", FileName = "timeline_" + (c.Hostname ?? "case") + ".csv" })
                    if (dlg.ShowDialog() == DialogResult.OK)
                    {
                        try
                        {
                            var sb = new StringBuilder();
                            sb.AppendLine("Timestamp,TimeType,TimeConfidence,Source,Type,Description");
                            // Analyst-facing export: neutralize spreadsheet formula injection (this file is
                            // opened in Excel and is never re-ingested by the tool).
                            foreach (var e in displayEvents)
                                sb.AppendLine(string.Join(",",
                                    IR_Collect.Utils.CsvUtils.EscapeFieldForExport(e.Time.ToString("yyyy-MM-dd HH:mm:ss")),
                                    IR_Collect.Utils.CsvUtils.EscapeFieldForExport(FormatTimelineTimeKind(e)),
                                    IR_Collect.Utils.CsvUtils.EscapeFieldForExport(e.TimeConfidence),
                                    IR_Collect.Utils.CsvUtils.EscapeFieldForExport(e.Source),
                                    IR_Collect.Utils.CsvUtils.EscapeFieldForExport(e.Type),
                                    IR_Collect.Utils.CsvUtils.EscapeFieldForExport(e.Description)));
                            File.WriteAllText(dlg.FileName, sb.ToString(), new System.Text.UTF8Encoding(false));
                            MessageBox.Show("Exported " + displayEvents.Count + " rows to " + dlg.FileName, "Timeline Export", MessageBoxButtons.OK);
                        }
                        catch (Exception ex) { MessageBox.Show("Export failed: " + ex.Message, "Timeline Export", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
                    }
            };

            btnExportJson.Click += (s, ev) =>
            {
                using (var dlg = new SaveFileDialog { Filter = "JSON|*.json", FileName = "timeline_" + (c.Hostname ?? "case") + ".json" })
                    if (dlg.ShowDialog() == DialogResult.OK)
                    {
                        try
                        {
                            var sb = new StringBuilder();
                            sb.Append("[\r\n");
                            for (int i = 0; i < displayEvents.Count; i++)
                            {
                                var e = displayEvents[i];
                                sb.Append(string.Format(
                                    "  {{\"timestamp\":\"{0}\",\"time_type\":\"{1}\",\"time_confidence\":\"{2}\",\"source\":\"{3}\",\"type\":\"{4}\",\"description\":\"{5}\"}}",
                                    e.Time.ToString("yyyy-MM-dd HH:mm:ss"),
                                    EscapeJson(FormatTimelineTimeKind(e)),
                                    EscapeJson(e.TimeConfidence),
                                    EscapeJson(e.Source),
                                    EscapeJson(e.Type),
                                    EscapeJson(e.Description)));
                                sb.Append(i < displayEvents.Count - 1 ? ",\r\n" : "\r\n");
                            }
                            sb.Append("]");
                            File.WriteAllText(dlg.FileName, sb.ToString(), new System.Text.UTF8Encoding(false));
                            MessageBox.Show("Exported " + displayEvents.Count + " rows to " + dlg.FileName, "Timeline Export", MessageBoxButtons.OK);
                        }
                        catch (Exception ex) { MessageBox.Show("Export failed: " + ex.Message, "Timeline Export", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
                    }
            };

            topPanel.Controls.Add(btnExportCsv);
            topPanel.Controls.Add(btnExportJson);

            DataGridView grid = CreateGrid();
            grid.Dock = DockStyle.Fill;
            grid.VirtualMode = true;
            grid.Columns.Add("Time",   "Timestamp");
            grid.Columns.Add("TimeType", "Time Type");
            grid.Columns.Add("TimeConfidence", "Confidence");
            grid.Columns.Add("Source", "Source");
            grid.Columns.Add("Type",   "Type");
            grid.Columns.Add("Desc",   "Description");
            grid.Columns[0].Width = 140;
            grid.Columns[1].Width = 110;
            grid.Columns[2].Width = 90;
            grid.Columns[3].Width = 100;
            grid.Columns[4].Width = 100;
            grid.Columns[5].AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;

            int timelinePageStart = 0;
            int timelinePage = 1;
            int timelinePageSize = 150;
            int timelineTotal = displayEvents.Count;
            bool timelinePaging = timelineTotal > PagingThresholdDefault;
            Action updateLabels = null;

            Action refreshTimelineGrid = () =>
            {
                if (timelinePaging)
                {
                    int totalPages = (timelineTotal + timelinePageSize - 1) / timelinePageSize;
                    if (timelinePage < 1) timelinePage = 1;
                    if (timelinePage > totalPages) timelinePage = totalPages;
                    timelinePageStart = (timelinePage - 1) * timelinePageSize;
                    grid.RowCount = Math.Min(timelinePageSize, timelineTotal - timelinePageStart);
                }
                else
                {
                    timelinePageStart = 0;
                    grid.RowCount = timelineTotal;
                }
            };

            grid.CellValueNeeded += (s, e) => {
                int realIndex = timelinePageStart + e.RowIndex;
                if (realIndex < displayEvents.Count)
                {
                    var evt = displayEvents[realIndex];
                    switch (e.ColumnIndex)
                    {
                        case 0: e.Value = evt.Time.ToString("yyyy-MM-dd HH:mm:ss"); break;
                        case 1: e.Value = FormatTimelineTimeKind(evt); break;
                        case 2: e.Value = evt.TimeConfidence; break;
                        case 3: e.Value = evt.Source; break;
                        case 4: e.Value = evt.Type; break;
                        case 5: e.Value = evt.Description; break;
                    }
                }
            };

            grid.CellFormatting += (s, e) => {
                int realIndex = timelinePageStart + e.RowIndex;
                if (realIndex < displayEvents.Count) {
                    var evt = displayEvents[realIndex];
                    if      (evt.Source == "Process") e.CellStyle.BackColor = Color.FromArgb(255, 240, 240);
                    else if (evt.Source != null && evt.Source.StartsWith("EventLog", StringComparison.OrdinalIgnoreCase))
                             e.CellStyle.BackColor = Color.FromArgb(240, 248, 255);
                    else if (evt.Source == "MFT") e.CellStyle.ForeColor = Color.DarkGray;
                    else if (evt.Source == "UserAssist" || evt.Source == "JumpList" || evt.Source == "Prefetch" || evt.Source == "RecentFiles" || evt.Source == "Autorun" || evt.Source == "Registry" || evt.Source == "ActivityTimeline" || evt.Source == "Activity")
                             e.CellStyle.BackColor = Color.FromArgb(248, 252, 248);
                    if (timelineGraphFocusActive && (!string.IsNullOrWhiteSpace(graphNormalizedValue) || !string.IsNullOrWhiteSpace(timelineGraphNeedle)))
                    {
                        if (TimelineEventMatchesGraphFocus(evt, graphRelatedType, graphNormalizedValue, timelineGraphNeedle))
                            e.CellStyle.BackColor = Color.FromArgb(255, 250, 205);
                    }
                }
            };

            Panel timelinePagingBar = null;
            if (timelinePaging)
            {
                timelinePagingBar = new Panel() { Dock = DockStyle.Bottom, Height = 36, BackColor = Color.WhiteSmoke };
                var lblPerPage = new Label() { Text = "Per page:", AutoSize = true, Location = new Point(8, 8), MaximumSize = new Size(72, 0) };
                var comboPageSize = new ComboBox() { Width = 52, DropDownStyle = ComboBoxStyle.DropDownList, Location = new Point(84, 6) };
                foreach (int opt in PagingPageSizeOptions) comboPageSize.Items.Add(opt.ToString());
                comboPageSize.SelectedIndex = 0;
                var lblPage = new Label() { AutoSize = true, Text = "Page 1 of 1", Location = new Point(146, 8) };
                var btnPrev = new Button() { Text = "Prev", Width = 44, Height = 24, Location = new Point(246, 6) };
                var btnNext = new Button() { Text = "Next", Width = 44, Height = 24, Location = new Point(294, 6) };
                var lblGoto = new Label() { Text = "Go to:", AutoSize = true, Location = new Point(346, 8) };
                var txtPage = new TextBox() { Width = 40, Height = 22, Location = new Point(394, 6) };
                var btnGo = new Button() { Text = "Go", Width = 36, Height = 24, Location = new Point(438, 6) };

                updateLabels = () =>
                {
                    int totalPages = (timelineTotal + timelinePageSize - 1) / timelinePageSize;
                    lblPage.Text = "Page " + timelinePage + " of " + totalPages;
                    btnPrev.Enabled = timelinePage > 1;
                    btnNext.Enabled = timelinePage < totalPages;
                };

                comboPageSize.SelectedIndexChanged += (s, e) =>
                {
                    if (comboPageSize.SelectedIndex >= 0 && comboPageSize.SelectedIndex < PagingPageSizeOptions.Length)
                    {
                        timelinePageSize = PagingPageSizeOptions[comboPageSize.SelectedIndex];
                        timelinePage = 1;
                        refreshTimelineGrid();
                        updateLabels();
                    }
                };
                btnPrev.Click += (s, e) => { timelinePage--; refreshTimelineGrid(); updateLabels(); };
                btnNext.Click += (s, e) => { timelinePage++; refreshTimelineGrid(); updateLabels(); };
                btnGo.Click += (s, e) =>
                {
                    int pageNum;
                    if (int.TryParse(txtPage.Text, out pageNum) && pageNum >= 1)
                    {
                        int totalPages = (timelineTotal + timelinePageSize - 1) / timelinePageSize;
                        if (pageNum > totalPages) pageNum = totalPages;
                        timelinePage = pageNum;
                        refreshTimelineGrid();
                        updateLabels();
                    }
                };

                timelinePagingBar.Controls.Add(lblPerPage);
                timelinePagingBar.Controls.Add(comboPageSize);
                timelinePagingBar.Controls.Add(lblPage);
                timelinePagingBar.Controls.Add(btnPrev);
                timelinePagingBar.Controls.Add(btnNext);
                timelinePagingBar.Controls.Add(lblGoto);
                timelinePagingBar.Controls.Add(txtPage);
                timelinePagingBar.Controls.Add(btnGo);
                updateLabels();
            }

            Action applyTimelineFilter = () =>
            {
                string srcFilter = comboSource.SelectedIndex <= 0 ? null : (comboSource.SelectedItem == null ? null : comboSource.SelectedItem.ToString());
                DateTime from = NormalizeTimelineFilterStart(dtFrom.Value);
                DateTime to = NormalizeTimelineFilterEnd(dtTo.Value);
                displayEvents.Clear();
                displayEvents.AddRange(allEvents.Where(e =>
                {
                    if (e.Time.Year < 1980) return false;
                    if (e.Time < from || e.Time > to) return false;
                    if (!string.IsNullOrEmpty(srcFilter) && !string.Equals(e.Source, srcFilter, StringComparison.OrdinalIgnoreCase)) return false;
                    if (timelineGraphFocusActive && (!string.IsNullOrWhiteSpace(graphNormalizedValue) || !string.IsNullOrWhiteSpace(timelineGraphNeedle)))
                    {
                        if (!TimelineEventMatchesGraphFocus(e, graphRelatedType, graphNormalizedValue, timelineGraphNeedle)) return false;
                    }
                    return true;
                }));
                timelineTotal = displayEvents.Count;
                refreshTimelineGrid();
                if (updateLabels != null) updateLabels();
            };
            btnFilterApply.Click += (s, ev) =>
            {
                if (dtFrom.Value > dtTo.Value) { var swap = dtFrom.Value; dtFrom.Value = dtTo.Value; dtTo.Value = swap; MessageBox.Show("From was after To; swapped.", "Timeline Filter", MessageBoxButtons.OK, MessageBoxIcon.Information); }
                if (dtFrom.Value < dtFrom.MinDate || dtFrom.Value > dtFrom.MaxDate) { MessageBox.Show("From date out of range (1980–2100).", "Timeline Filter", MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
                if (dtTo.Value < dtTo.MinDate || dtTo.Value > dtTo.MaxDate) { MessageBox.Show("To date out of range (1980–2100).", "Timeline Filter", MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
                applyTimelineFilter();
            };
            btnFilterReset.Click += (s, ev) =>
            {
                timelineGraphFocusActive = false;
                timelineGraphNeedle = "";
                if (graphContextPanel != null)
                    graphContextPanel.Visible = false;
                comboSource.SelectedIndex = 0;
                dtFrom.Value = NormalizeTimelinePickerToMinute(DateTime.Now.AddDays(-30));
                dtTo.Value = NormalizeTimelinePickerToMinute(DateTime.Now.AddDays(1));
                displayEvents.Clear();
                displayEvents.AddRange(allEvents);
                timelineTotal = displayEvents.Count;
                refreshTimelineGrid();
                if (updateLabels != null) updateLabels();
            };

            if (btnTimelineGraphClearFocus != null)
            {
                btnTimelineGraphClearFocus.Click += (s, ev) =>
                {
                    timelineGraphFocusActive = false;
                    timelineGraphNeedle = "";
                    if (graphContextPanel != null)
                        graphContextPanel.Visible = false;
                    comboSource.SelectedIndex = 0;
                    dtFrom.Value = NormalizeTimelinePickerToMinute(DateTime.Now.AddDays(-30));
                    dtTo.Value = NormalizeTimelinePickerToMinute(DateTime.Now.AddDays(1));
                    displayEvents.Clear();
                    displayEvents.AddRange(allEvents);
                    timelineTotal = displayEvents.Count;
                    refreshTimelineGrid();
                    if (updateLabels != null) updateLabels();
                };
            }

            if (graphHandoff)
                applyTimelineFilter();
            else
                refreshTimelineGrid();

            p.Controls.Add(grid);
            if (timelinePagingBar != null)
                p.Controls.Add(timelinePagingBar);
            p.Controls.Add(topPanel);
            p.Controls.Add(filterPanel);
            if (graphContextPanel != null)
                p.Controls.Add(graphContextPanel);
            return p;
        }

        private string FormatTimelineTimeKind(TimelineEvent evt)
        {
            string value = evt != null ? (evt.TimeKind ?? "") : "";
            switch (value)
            {
                case FactTimeMetadata.EventTimeKind:
                    return "Event";
                case FactTimeMetadata.MetadataTimeKind:
                    return "Metadata";
                case FactTimeMetadata.ObservedTimeKind:
                    return "Observed";
                default:
                    return "Unknown";
            }
        }

#if INCLUDE_TESTS
        /// <summary>Regression hook: invokes the same unified timeline assembly as the Timeline Analysis tab (<see cref="BuildTimelineEvents"/>).</summary>
        internal List<TimelineEvent> BuildTimelineEventsForSelfTest(IR_Collect.Analysis.CaseData c)
        {
            return BuildTimelineEvents(c);
        }
#endif
    }
}
