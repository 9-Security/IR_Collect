using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.Xml.Linq;
using System.Diagnostics.Eventing.Reader;
using System.Text.RegularExpressions;
using IR_Collect.Utils;

namespace IR_Collect
{
    partial class MainForm
    {
        private IR_Collect.Analysis.Correlation.SharedEntityPivotResult _lastSharedEntityPivotResult;
        private IR_Collect.Analysis.Correlation.SharedEntityPivotItem _currentSharedEntityDrilldownItem;
        private string _lastSharedEntityPivotFilter;
        private IR_Collect.Analysis.CaseData _factsNavigationCase;
        private string _factsNavigationEntityType;
        private string _factsNavigationEntityValue;
        private string _factsNavigationPreferredRawRef;
        private IR_Collect.Analysis.Correlation.InvestigationWorkspaceState _investigationWorkspace;
        private List<IR_Collect.Analysis.Correlation.InvestigationGraphEdge> _currentInvestigationGraphEdges;

        private IR_Collect.Analysis.CaseData _timelineGraphHandoffCase;
        private string _timelineGraphHandoffRelatedType;
        private string _timelineGraphHandoffNormalizedValue;
        private string _timelineGraphHandoffNeedle;
        private string _timelineGraphHandoffTrail;
        private bool _timelineGraphHandoffHasWindow;
        private DateTime _timelineGraphHandoffWindowFrom;
        private DateTime _timelineGraphHandoffWindowTo;

        private void RunCorrelation()
        {
            if (treeHosts.Nodes.Count == 0)
            {
                MessageBox.Show("No host loaded. Please import a case first.", "Find Common Artifacts", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            listCorrelation.Items.Clear();
            listCorrelation.Columns.Clear();
            listCorrelation.Columns.Add("File/Artifact", 400);
            listCorrelation.Columns.Add("Count", 100);
            listCorrelation.Columns.Add("Hosts", -2); // -2 = 填滿右側剩餘寬度
            var common = IR_Collect.Analysis.CaseManager.FindCommonFiles();
            foreach(var kvp in common)
            {
                ListViewItem item = new ListViewItem(kvp.Key);
                item.SubItems.Add(kvp.Value.Count.ToString());
                item.SubItems.Add(string.Join(", ", kvp.Value));
                listCorrelation.Items.Add(item);
            }
            
            MessageBox.Show(string.Format("Found {0} files that appear on multiple hosts.", common.Count));
        }

        private void RunSharedEntityPivot()
        {
            if (treeHosts.Nodes.Count == 0)
            {
                MessageBox.Show("No host loaded. Please import a case first.", "Find Shared Entities", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            string entityType = (comboEntityType != null && comboEntityType.SelectedItem != null) ? comboEntityType.SelectedItem.ToString() : "Path";
            string filter = txtEntityValue != null ? (txtEntityValue.Text ?? "").Trim() : "";
            var summaryData = IR_Collect.Analysis.Correlation.SharedEntityPivotBuilder.Build(CollectLoadedCases(), entityType, filter, GetCorrelationOptions(250));
            _lastSharedEntityPivotResult = summaryData;
            _lastSharedEntityPivotFilter = filter;
            if (menuSharedEntityPivotBack != null) menuSharedEntityPivotBack.Enabled = true;

            if (summaryData.ReadyHosts == 0)
            {
                string noDataMessage = "No Fact Store data is ready. Load cases with facts first.";
                if (summaryData.SkippedHosts > 0)
                    noDataMessage += string.Format("\n\nSkipped {0} host(s) that are still building Fact Store.", summaryData.SkippedHosts);
                MessageBox.Show(noDataMessage, "Find Shared Entities", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            RenderSharedEntityPivotResult(summaryData);

            var results = summaryData.Items;

            if (results.Count == 0)
            {
                string noHitsMessage = string.Format("No shared {0} entities were found across the loaded hosts.", entityType);
                if (!string.IsNullOrEmpty(filter))
                    noHitsMessage += string.Format("\n\nFilter: \"{0}\"", filter);
                noHitsMessage += "\n\nOnly entities observed on multiple hosts are shown in this pivot.";
                if (summaryData.SkippedHosts > 0)
                    noHitsMessage += string.Format("\nSkipped {0} host(s) that are still building Fact Store.", summaryData.SkippedHosts);
                MessageBox.Show(noHitsMessage, "Find Shared Entities", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            var summary = new StringBuilder();
            summary.AppendFormat("Found {0} shared {1} entities across {2} ready host(s).", summaryData.TotalSharedEntities, entityType, summaryData.ReadyHosts);
            if (!string.IsNullOrEmpty(filter))
                summary.AppendFormat("\nFilter: \"{0}\".", filter);
            if (summaryData.TotalSharedEntities > results.Count)
                summary.AppendFormat("\nShowing top {0} results.", results.Count);
            if (summaryData.SkippedHosts > 0)
                summary.AppendFormat("\nSkipped {0} host(s) that are still building Fact Store.", summaryData.SkippedHosts);
            AppendCorrelationFilterSummary(summary, entityType, filter);
            summary.Append("\n\nDouble-click a row to drill into matching facts by host.");
            MessageBox.Show(summary.ToString(), "Find Shared Entities", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void RunRestoreLastSharedEntityPivot()
        {
            if (_lastSharedEntityPivotResult == null)
            {
                MessageBox.Show("No previous shared-entity pivot is available yet.", "Back To Last Shared Pivot", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            RenderSharedEntityPivotResult(_lastSharedEntityPivotResult);
        }

        private void RenderSharedEntityPivotResult(IR_Collect.Analysis.Correlation.SharedEntityPivotResult summaryData)
        {
            _currentSharedEntityDrilldownItem = null;
            var results = summaryData != null && summaryData.Items != null
                ? summaryData.Items
                : new List<IR_Collect.Analysis.Correlation.SharedEntityPivotItem>();

            listCorrelation.Items.Clear();
            listCorrelation.Columns.Clear();
            listCorrelation.Columns.Add("Entity", 320);
            listCorrelation.Columns.Add("Hosts", 60);
            listCorrelation.Columns.Add("Facts", 70);
            listCorrelation.Columns.Add("Sources", 180);
            listCorrelation.Columns.Add("First Seen", 140);
            listCorrelation.Columns.Add("Last Seen", 140);
            listCorrelation.Columns.Add("Hostnames", -2);

            foreach (var row in results)
            {
                var item = new ListViewItem(row.DisplayValue ?? row.NormalizedValue ?? "");
                item.SubItems.Add((row.Hosts != null ? row.Hosts.Count : 0).ToString());
                item.SubItems.Add(row.FactCount.ToString());
                item.SubItems.Add(FormatSharedValueList(row.Sources, 4));
                item.SubItems.Add(FormatPivotTime(row.FirstSeen));
                item.SubItems.Add(FormatPivotTime(row.LastSeen));
                item.SubItems.Add(FormatSharedValueList(row.Hosts, 8));
                item.Tag = row;
                listCorrelation.Items.Add(item);
            }
        }

        private void ListCorrelation_ItemActivate(object sender, EventArgs e)
        {
            if (listCorrelation == null || listCorrelation.SelectedItems == null || listCorrelation.SelectedItems.Count <= 0)
                return;

            var selected = listCorrelation.SelectedItems[0];
            var pivotItem = selected.Tag as IR_Collect.Analysis.Correlation.SharedEntityPivotItem;
            if (pivotItem != null)
            {
                RunSharedEntityPivotDrilldown(pivotItem);
                return;
            }

            var factHit = selected.Tag as IR_Collect.Analysis.Correlation.SharedEntityFactHit;
            if (factHit != null)
            {
                NavigateToHostFact(factHit);
                return;
            }

            var relatedItem = selected.Tag as IR_Collect.Analysis.Correlation.RelatedEntityPivotItem;
            if (relatedItem != null)
            {
                ActivateRelatedEntityItem(relatedItem);
                return;
            }

            var graphItem = selected.Tag as IR_Collect.Analysis.Correlation.InvestigationGraphEdge;
            if (graphItem != null)
            {
                ActivateInvestigationGraphEdge(graphItem);
                return;
            }

            var temporalItem = selected.Tag as IR_Collect.Analysis.Correlation.TemporalSharedEntityPivotItem;
            if (temporalItem != null)
                RunTemporalSharedEntityDrilldown(temporalItem);
        }

        private void ListCorrelation_SelectedIndexChanged(object sender, EventArgs e)
        {
            EnsureInvestigationWorkspace();
            var edge = GetSelectedInvestigationGraphEdge();
            if (edge != null)
                _investigationWorkspace.SetSelectedEdge(edge);
            else
                _investigationWorkspace.ClearSelectedEdge();
            RefreshInvestigationWorkspaceUi();
        }

        private void RunSharedEntityPivotDrilldown(IR_Collect.Analysis.Correlation.SharedEntityPivotItem pivotItem)
        {
            if (pivotItem == null)
                return;

            _currentSharedEntityDrilldownItem = pivotItem;
            var hits = IR_Collect.Analysis.Correlation.SharedEntityPivotBuilder.BuildFactHits(CollectLoadedCases(), pivotItem.EntityType, pivotItem.NormalizedValue, GetCorrelationOptions(500));
            listCorrelation.Items.Clear();
            listCorrelation.Columns.Clear();
            listCorrelation.Columns.Add("Host", 120);
            listCorrelation.Columns.Add("Time", 160);
            listCorrelation.Columns.Add("Time Meta", 110);
            listCorrelation.Columns.Add("Source", 120);
            listCorrelation.Columns.Add("Action", 100);
            listCorrelation.Columns.Add("Details", 360);
            listCorrelation.Columns.Add("RawRef", -2);

            foreach (var hit in hits)
            {
                var fact = hit != null ? hit.Fact : null;
                if (fact == null)
                    continue;

                var item = new ListViewItem(hit.Hostname ?? "host");
                item.SubItems.Add(FormatFactTime(fact.Time));
                item.SubItems.Add(FormatFactTimeMetadata(fact));
                item.SubItems.Add(fact.Source ?? "");
                item.SubItems.Add(fact.Action ?? "");
                item.SubItems.Add(BuildFactPreview(fact));
                item.SubItems.Add(CollapseSingleLine(fact.RawRef));
                item.Tag = hit;
                listCorrelation.Items.Add(item);
            }

            string value = !string.IsNullOrWhiteSpace(pivotItem.DisplayValue) ? pivotItem.DisplayValue : (pivotItem.NormalizedValue ?? "");
            string message = string.Format("Showing {0} fact(s) for shared {1} = \"{2}\".", hits.Count, pivotItem.EntityType ?? "Entity", value);
            if (!string.IsNullOrWhiteSpace(_lastSharedEntityPivotFilter))
                message += string.Format("\nOriginal filter: \"{0}\".", _lastSharedEntityPivotFilter);
            message += "\n\nDouble-click a fact row to jump into that host's focused Facts tab.";
            message += "\nUse Correlation -> Back To Last Shared Pivot to return.";
            MessageBox.Show(message, "Shared Entity Drilldown", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void RunRelatedEntityPivot()
        {
            if (treeHosts.Nodes.Count == 0)
            {
                MessageBox.Show("No host loaded. Please import a case first.", "Find Related Entities", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            string seedType;
            string seedValue;
            string seedDisplay;
            if (!TryResolveSeedEntity(out seedType, out seedValue, out seedDisplay))
            {
                MessageBox.Show("Enter an entity value first, or drill into a shared entity before asking for related entities.", "Find Related Entities", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            var results = IR_Collect.Analysis.Correlation.SharedEntityPivotBuilder.BuildRelatedEntities(CollectLoadedCases(), seedType, seedValue, GetCorrelationOptions(250));
            listCorrelation.Items.Clear();
            listCorrelation.Columns.Clear();
            listCorrelation.Columns.Add("Type", 120);
            listCorrelation.Columns.Add("Related Entity", 320);
            listCorrelation.Columns.Add("Hosts", 60);
            listCorrelation.Columns.Add("Facts", 70);
            listCorrelation.Columns.Add("Sources", 180);
            listCorrelation.Columns.Add("First Seen", 140);
            listCorrelation.Columns.Add("Last Seen", -2);

            foreach (var row in results)
            {
                var item = new ListViewItem(row.RelatedType ?? "");
                item.SubItems.Add(row.DisplayValue ?? row.NormalizedValue ?? "");
                item.SubItems.Add((row.Hosts != null ? row.Hosts.Count : 0).ToString());
                item.SubItems.Add(row.FactCount.ToString());
                item.SubItems.Add(FormatSharedValueList(row.Sources, 4));
                item.SubItems.Add(FormatPivotTime(row.FirstSeen));
                item.SubItems.Add(FormatPivotTime(row.LastSeen));
                item.Tag = row;
                listCorrelation.Items.Add(item);
            }

            if (results.Count == 0)
            {
                MessageBox.Show(string.Format("No related entities were found for {0} = \"{1}\" under the current filters.", seedType, seedDisplay), "Find Related Entities", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            var summary = new StringBuilder();
            summary.AppendFormat("Found {0} related entities for {1} = \"{2}\".", results.Count, seedType, seedDisplay);
            AppendCorrelationFilterSummary(summary, seedType, seedDisplay);
            summary.Append("\n\nDouble-click a related entity row to run Entity Search on it.");
            MessageBox.Show(summary.ToString(), "Find Related Entities", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void RunInvestigationGraph()
        {
            if (treeHosts.Nodes.Count == 0)
            {
                MessageBox.Show("No host loaded. Please import a case first.", "Build Investigation Graph", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            string seedType;
            string seedValue;
            string seedDisplay;
            if (!TryResolveSeedEntity(out seedType, out seedValue, out seedDisplay))
            {
                MessageBox.Show("Enter an entity value first, or drill into a shared entity before building an investigation graph.", "Build Investigation Graph", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            EnsureInvestigationWorkspace();
            _investigationWorkspace.Filters = BuildWorkspaceFiltersFromUi();
            _investigationWorkspace.HostScopeMode = GetSelectedWorkspaceHostScopeMode();
            _investigationWorkspace.StartOrAppendSeed(seedType, seedValue, seedDisplay);
            _investigationWorkspace.ResultMode = IR_Collect.Analysis.Correlation.InvestigationWorkspaceResultMode.InvestigationGraph;
            _investigationWorkspace.ClearSelectedEdge();

            var options = GetCorrelationOptions(300);
            var scopedCases = GetWorkspaceScopedCases(CollectLoadedCases());
            var results = IR_Collect.Analysis.Correlation.InvestigationGraphBuilder.Build(scopedCases, seedType, seedValue, options);
            _currentInvestigationGraphEdges = results;
            listCorrelation.Items.Clear();
            listCorrelation.Columns.Clear();
            listCorrelation.Columns.Add("Related Type", 120);
            listCorrelation.Columns.Add("Related Entity", 300);
            listCorrelation.Columns.Add("Hosts", 60);
            listCorrelation.Columns.Add("Facts", 70);
            listCorrelation.Columns.Add("Sources", 170);
            listCorrelation.Columns.Add("Actions", 160);
            listCorrelation.Columns.Add("First Seen", 140);
            listCorrelation.Columns.Add("Last Seen", -2);

            foreach (var row in results)
            {
                var item = new ListViewItem(row.RelatedType ?? "");
                item.SubItems.Add(row.DisplayValue ?? row.NormalizedValue ?? "");
                item.SubItems.Add((row.Hosts != null ? row.Hosts.Count : 0).ToString());
                item.SubItems.Add(row.FactCount.ToString());
                item.SubItems.Add(FormatSharedValueList(row.Sources, 4));
                item.SubItems.Add(FormatSharedValueList(row.Actions, 4));
                item.SubItems.Add(FormatPivotTime(row.FirstSeen));
                item.SubItems.Add(FormatPivotTime(row.LastSeen));
                item.Tag = row;
                listCorrelation.Items.Add(item);
            }
            RefreshInvestigationWorkspaceUi();

            if (results.Count == 0)
            {
                MessageBox.Show(string.Format("No graph edges were found for {0} = \"{1}\" under the current filters.", seedType, seedDisplay), "Build Investigation Graph", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            var summary = new StringBuilder();
            summary.AppendFormat("Built graph-style pivot with {0} edge(s) for {1} = \"{2}\".", results.Count, seedType, seedDisplay);
            AppendCorrelationFilterSummary(summary, seedType, seedDisplay);
            summary.Append("\n\nUse Expand From Selected Edge / Back / Forward / Reset To Original Seed for multi-step investigation navigation.");
            MessageBox.Show(summary.ToString(), "Build Investigation Graph", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void RunTemporalSharedEntityCorrelation()
        {
            if (treeHosts.Nodes.Count == 0)
            {
                MessageBox.Show("No host loaded. Please import a case first.", "Time-Window Entity Correlation", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            string entityType = (comboEntityType != null && comboEntityType.SelectedItem != null) ? comboEntityType.SelectedItem.ToString() : "Path";
            string filter = txtEntityValue != null ? (txtEntityValue.Text ?? "").Trim() : "";
            var options = GetCorrelationOptions(250);
            var results = IR_Collect.Analysis.Correlation.SharedEntityPivotBuilder.BuildTemporalCorrelations(CollectLoadedCases(), entityType, filter, options);

            listCorrelation.Items.Clear();
            listCorrelation.Columns.Clear();
            listCorrelation.Columns.Add("Entity", 280);
            listCorrelation.Columns.Add("Window", 170);
            listCorrelation.Columns.Add("Hosts", 60);
            listCorrelation.Columns.Add("Facts", 70);
            listCorrelation.Columns.Add("Sources", 160);
            listCorrelation.Columns.Add("First Seen", 140);
            listCorrelation.Columns.Add("Last Seen", -2);

            foreach (var row in results)
            {
                var item = new ListViewItem(row.DisplayValue ?? row.NormalizedValue ?? "");
                item.SubItems.Add(FormatTemporalWindow(row.BucketStart, row.BucketEnd));
                item.SubItems.Add((row.Hosts != null ? row.Hosts.Count : 0).ToString());
                item.SubItems.Add(row.FactCount.ToString());
                item.SubItems.Add(FormatSharedValueList(row.Sources, 4));
                item.SubItems.Add(FormatPivotTime(row.FirstSeen));
                item.SubItems.Add(FormatPivotTime(row.LastSeen));
                item.Tag = row;
                listCorrelation.Items.Add(item);
            }

            if (results.Count == 0)
            {
                MessageBox.Show("No time-window shared-entity correlations were found under the current filters.", "Time-Window Entity Correlation", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            var summary = new StringBuilder();
            summary.AppendFormat("Found {0} shared-entity time-window hit(s).", results.Count);
            AppendCorrelationFilterSummary(summary, entityType, filter);
            summary.AppendFormat("\nWindow size: {0}.", FormatCorrelationWindowLabel(GetCorrelationWindowMinutes()));
            summary.Append("\n\nDouble-click a row to drill into the matching host facts for that window.");
            MessageBox.Show(summary.ToString(), "Time-Window Entity Correlation", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void RunTemporalSharedEntityDrilldown(IR_Collect.Analysis.Correlation.TemporalSharedEntityPivotItem pivotItem)
        {
            if (pivotItem == null)
                return;

            var options = GetCorrelationOptions(500);
            options.UseFromTime = true;
            options.FromTime = pivotItem.BucketStart;
            options.UseToTime = true;
            options.ToTime = pivotItem.BucketEnd;

            var sharedItem = new IR_Collect.Analysis.Correlation.SharedEntityPivotItem();
            sharedItem.EntityType = pivotItem.EntityType;
            sharedItem.NormalizedValue = pivotItem.NormalizedValue;
            sharedItem.DisplayValue = pivotItem.DisplayValue;
            RunSharedEntityPivotDrilldown(sharedItem, options, true, FormatTemporalWindow(pivotItem.BucketStart, pivotItem.BucketEnd));
        }

        private void RunSharedEntityPivotDrilldown(IR_Collect.Analysis.Correlation.SharedEntityPivotItem pivotItem, IR_Collect.Analysis.Correlation.SharedEntityPivotOptions options, bool useCustomMessage, string customWindowLabel)
        {
            if (pivotItem == null)
                return;

            _currentSharedEntityDrilldownItem = pivotItem;
            var hits = IR_Collect.Analysis.Correlation.SharedEntityPivotBuilder.BuildFactHits(CollectLoadedCases(), pivotItem.EntityType, pivotItem.NormalizedValue, options);
            listCorrelation.Items.Clear();
            listCorrelation.Columns.Clear();
            listCorrelation.Columns.Add("Host", 120);
            listCorrelation.Columns.Add("Time", 160);
            listCorrelation.Columns.Add("Time Meta", 110);
            listCorrelation.Columns.Add("Source", 120);
            listCorrelation.Columns.Add("Action", 100);
            listCorrelation.Columns.Add("Details", 360);
            listCorrelation.Columns.Add("RawRef", -2);

            foreach (var hit in hits)
            {
                var fact = hit != null ? hit.Fact : null;
                if (fact == null)
                    continue;

                var item = new ListViewItem(hit.Hostname ?? "host");
                item.SubItems.Add(FormatFactTime(fact.Time));
                item.SubItems.Add(FormatFactTimeMetadata(fact));
                item.SubItems.Add(fact.Source ?? "");
                item.SubItems.Add(fact.Action ?? "");
                item.SubItems.Add(BuildFactPreview(fact));
                item.SubItems.Add(CollapseSingleLine(fact.RawRef));
                item.Tag = hit;
                listCorrelation.Items.Add(item);
            }

            string value = !string.IsNullOrWhiteSpace(pivotItem.DisplayValue) ? pivotItem.DisplayValue : (pivotItem.NormalizedValue ?? "");
            string message = string.Format("Showing {0} fact(s) for shared {1} = \"{2}\".", hits.Count, pivotItem.EntityType ?? "Entity", value);
            if (!string.IsNullOrWhiteSpace(_lastSharedEntityPivotFilter))
                message += string.Format("\nOriginal filter: \"{0}\".", _lastSharedEntityPivotFilter);
            if (useCustomMessage && !string.IsNullOrWhiteSpace(customWindowLabel))
                message += string.Format("\nTime window: {0}.", customWindowLabel);
            message += "\n\nDouble-click a fact row to jump into that host's focused Facts tab.";
            message += "\nUse Correlation -> Back To Last Shared Pivot to return.";
            MessageBox.Show(message, useCustomMessage ? "Time-Window Entity Drilldown" : "Shared Entity Drilldown", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private List<IR_Collect.Analysis.CaseData> CollectLoadedCases()
        {
            var cases = new List<IR_Collect.Analysis.CaseData>();
            if (treeHosts == null)
                return cases;

            foreach (TreeNode node in treeHosts.Nodes)
            {
                var caseData = node.Tag as IR_Collect.Analysis.CaseData;
                if (caseData != null)
                    cases.Add(caseData);
            }
            return cases;
        }

        private IR_Collect.Analysis.Correlation.SharedEntityPivotOptions GetCorrelationOptions(int maxResults)
        {
            var options = new IR_Collect.Analysis.Correlation.SharedEntityPivotOptions();
            options.MaxResults = maxResults > 0 ? maxResults : 250;
            options.SourcePrefixFilter = GetSelectedCorrelationSourceFilter();
            options.TimeConfidenceFilter = GetSelectedCorrelationConfidenceFilter();
            options.HostFilter = txtCorrelationHostFilter != null ? (txtCorrelationHostFilter.Text ?? "").Trim() : "";
            options.BucketMinutes = GetCorrelationWindowMinutes();
            if (dtCorrelationFrom != null && dtCorrelationFrom.Checked)
            {
                options.UseFromTime = true;
                options.FromTime = dtCorrelationFrom.Value;
            }
            if (dtCorrelationTo != null && dtCorrelationTo.Checked)
            {
                options.UseToTime = true;
                options.ToTime = dtCorrelationTo.Value;
            }
            if (options.UseFromTime && options.UseToTime && options.FromTime > options.ToTime)
            {
                DateTime tmp = options.FromTime;
                options.FromTime = options.ToTime;
                options.ToTime = tmp;
            }
            return options;
        }

        private string GetSelectedCorrelationSourceFilter()
        {
            string value = comboCorrelationSource != null && comboCorrelationSource.SelectedItem != null ? comboCorrelationSource.SelectedItem.ToString() : "";
            return string.Equals(value, "(All)", StringComparison.OrdinalIgnoreCase) ? "" : value;
        }

        private string GetSelectedCorrelationConfidenceFilter()
        {
            string value = comboCorrelationConfidence != null && comboCorrelationConfidence.SelectedItem != null ? comboCorrelationConfidence.SelectedItem.ToString() : "";
            return string.Equals(value, "(All)", StringComparison.OrdinalIgnoreCase) ? "" : value;
        }

        private int GetCorrelationWindowMinutes()
        {
            string label = comboCorrelationWindow != null && comboCorrelationWindow.SelectedItem != null ? comboCorrelationWindow.SelectedItem.ToString() : "30m";
            int minutes;
            if (int.TryParse((label ?? "").Replace("m", ""), out minutes) && minutes > 0)
                return minutes;
            return 30;
        }

        private string FormatCorrelationWindowLabel(int minutes)
        {
            return minutes.ToString() + "m";
        }

        private string FormatTemporalWindow(DateTime start, DateTime end)
        {
            if (!IR_Collect.Analysis.Correlation.FactTimeMetadata.HasUsableTime(start))
                return "";
            string endText = IR_Collect.Analysis.Correlation.FactTimeMetadata.HasUsableTime(end)
                ? end.ToString("HH:mm")
                : "";
            return start.ToString("yyyy-MM-dd HH:mm") + (string.IsNullOrEmpty(endText) ? "" : (" - " + endText));
        }

        private void AppendCorrelationFilterSummary(StringBuilder summary, string entityType, string filter)
        {
            if (summary == null)
                return;

            string sourceFilter = GetSelectedCorrelationSourceFilter();
            string confidenceFilter = GetSelectedCorrelationConfidenceFilter();
            string hostFilter = txtCorrelationHostFilter != null ? (txtCorrelationHostFilter.Text ?? "").Trim() : "";
            bool hasFrom = dtCorrelationFrom != null && dtCorrelationFrom.Checked;
            bool hasTo = dtCorrelationTo != null && dtCorrelationTo.Checked;

            if (!string.IsNullOrWhiteSpace(entityType))
                summary.AppendFormat("\nEntity type: {0}.", entityType);
            if (!string.IsNullOrWhiteSpace(filter))
                summary.AppendFormat("\nEntity filter: \"{0}\".", filter);
            if (!string.IsNullOrWhiteSpace(sourceFilter))
                summary.AppendFormat("\nSource filter: {0}.", sourceFilter);
            if (!string.IsNullOrWhiteSpace(confidenceFilter))
                summary.AppendFormat("\nConfidence filter: {0}.", confidenceFilter);
            if (!string.IsNullOrWhiteSpace(hostFilter))
                summary.AppendFormat("\nHost filter: \"{0}\".", hostFilter);
            if (hasFrom || hasTo)
            {
                string fromText = hasFrom ? dtCorrelationFrom.Value.ToString("yyyy-MM-dd HH:mm") : "(open)";
                string toText = hasTo ? dtCorrelationTo.Value.ToString("yyyy-MM-dd HH:mm") : "(open)";
                summary.AppendFormat("\nTime range: {0} to {1}.", fromText, toText);
            }
        }

        private bool TryResolveSeedEntity(out string seedType, out string seedValue, out string seedDisplay)
        {
            seedType = comboEntityType != null && comboEntityType.SelectedItem != null ? comboEntityType.SelectedItem.ToString() : "Path";
            seedValue = txtEntityValue != null ? (txtEntityValue.Text ?? "").Trim() : "";
            seedDisplay = seedValue;
            if (!string.IsNullOrWhiteSpace(seedValue))
                return true;

            if (_currentSharedEntityDrilldownItem != null)
            {
                seedType = _currentSharedEntityDrilldownItem.EntityType ?? "Path";
                seedValue = _currentSharedEntityDrilldownItem.NormalizedValue ?? "";
                seedDisplay = !string.IsNullOrWhiteSpace(_currentSharedEntityDrilldownItem.DisplayValue)
                    ? _currentSharedEntityDrilldownItem.DisplayValue
                    : seedValue;
                return !string.IsNullOrWhiteSpace(seedValue);
            }

            return false;
        }

        private void ActivateRelatedEntityItem(IR_Collect.Analysis.Correlation.RelatedEntityPivotItem item)
        {
            if (item == null)
                return;

            if (comboEntityType != null)
            {
                for (int i = 0; i < comboEntityType.Items.Count; i++)
                {
                    if (string.Equals(comboEntityType.Items[i].ToString(), item.RelatedType ?? "", StringComparison.OrdinalIgnoreCase))
                    {
                        comboEntityType.SelectedIndex = i;
                        break;
                    }
                }
            }
            if (txtEntityValue != null)
                txtEntityValue.Text = !string.IsNullOrWhiteSpace(item.DisplayValue) ? item.DisplayValue : (item.NormalizedValue ?? "");
            RunEntitySearch();
        }

        private void ActivateInvestigationGraphEdge(IR_Collect.Analysis.Correlation.InvestigationGraphEdge item)
        {
            if (item == null)
                return;

            EnsureInvestigationWorkspace();
            _investigationWorkspace.SetSelectedEdge(item);
            RefreshInvestigationWorkspaceUi();
            RunInvestigationWorkspaceOpenSelectedEdgeFacts();
        }

        private void NavigateToHostFact(IR_Collect.Analysis.Correlation.SharedEntityFactHit hit)
        {
            if (hit == null || hit.CaseData == null)
                return;

            string entityType = _currentSharedEntityDrilldownItem != null ? (_currentSharedEntityDrilldownItem.EntityType ?? "Path") : "Path";
            string entityValue = _currentSharedEntityDrilldownItem != null ? (_currentSharedEntityDrilldownItem.NormalizedValue ?? "") : "";
            SetFactsNavigationFocus(hit.CaseData, entityType, entityValue, hit.Fact != null ? hit.Fact.RawRef : "");

            TreeNode node = FindHostNode(hit.CaseData);
            if (node == null)
                return;

            bool alreadySelected = object.ReferenceEquals(treeHosts.SelectedNode, node);
            treeHosts.SelectedNode = node;
            if (alreadySelected)
                BuildHostTabs(hit.CaseData);
            if (dashboardPanel != null) dashboardPanel.Visible = false;
            if (rightContentPanel != null) rightContentPanel.Visible = true;
            SelectTopLevelHostTab("Facts");
        }

        private TreeNode FindHostNode(IR_Collect.Analysis.CaseData c)
        {
            if (treeHosts == null || c == null)
                return null;

            foreach (TreeNode node in treeHosts.Nodes)
            {
                if (object.ReferenceEquals(node.Tag, c))
                    return node;
            }
            return null;
        }

        private void SelectTopLevelHostTab(string tabText)
        {
            if (hostTabs == null || string.IsNullOrWhiteSpace(tabText))
                return;

            foreach (TabPage page in hostTabs.TabPages)
            {
                if (string.Equals(page.Text, tabText, StringComparison.OrdinalIgnoreCase))
                {
                    hostTabs.SelectedTab = page;
                    return;
                }
            }
        }

        private void SetFactsNavigationFocus(IR_Collect.Analysis.CaseData c, string entityType, string entityValue, string preferredRawRef)
        {
            _factsNavigationCase = c;
            _factsNavigationEntityType = entityType ?? "";
            _factsNavigationEntityValue = entityValue ?? "";
            _factsNavigationPreferredRawRef = preferredRawRef ?? "";
        }

        private bool TryGetFactsNavigationFocus(IR_Collect.Analysis.CaseData c, out string entityType, out string entityValue, out string preferredRawRef)
        {
            entityType = "";
            entityValue = "";
            preferredRawRef = "";
            if (c == null || !object.ReferenceEquals(_factsNavigationCase, c))
                return false;
            if (string.IsNullOrWhiteSpace(_factsNavigationEntityType) || string.IsNullOrWhiteSpace(_factsNavigationEntityValue))
                return false;

            entityType = _factsNavigationEntityType;
            entityValue = _factsNavigationEntityValue;
            preferredRawRef = _factsNavigationPreferredRawRef ?? "";
            return true;
        }

        private void ClearFactsNavigationFocus(IR_Collect.Analysis.CaseData c)
        {
            if (c != null && !object.ReferenceEquals(_factsNavigationCase, c))
                return;

            _factsNavigationCase = null;
            _factsNavigationEntityType = "";
            _factsNavigationEntityValue = "";
            _factsNavigationPreferredRawRef = "";
        }

        private void EnsureInvestigationWorkspace()
        {
            if (_investigationWorkspace == null)
                _investigationWorkspace = new IR_Collect.Analysis.Correlation.InvestigationWorkspaceState();
            if (_currentInvestigationGraphEdges == null)
                _currentInvestigationGraphEdges = new List<IR_Collect.Analysis.Correlation.InvestigationGraphEdge>();
        }

        private IR_Collect.Analysis.Correlation.InvestigationWorkspaceFilters BuildWorkspaceFiltersFromUi()
        {
            var filters = new IR_Collect.Analysis.Correlation.InvestigationWorkspaceFilters();
            filters.SourcePrefixFilter = GetSelectedCorrelationSourceFilter();
            filters.TimeConfidenceFilter = GetSelectedCorrelationConfidenceFilter();
            filters.HostFilterText = txtCorrelationHostFilter != null ? (txtCorrelationHostFilter.Text ?? "").Trim() : "";
            filters.BucketMinutes = GetCorrelationWindowMinutes();
            if (dtCorrelationFrom != null && dtCorrelationFrom.Checked)
            {
                filters.UseFromTime = true;
                filters.FromTime = dtCorrelationFrom.Value;
            }
            if (dtCorrelationTo != null && dtCorrelationTo.Checked)
            {
                filters.UseToTime = true;
                filters.ToTime = dtCorrelationTo.Value;
            }
            if (filters.UseFromTime && filters.UseToTime && filters.FromTime > filters.ToTime)
            {
                DateTime t = filters.FromTime;
                filters.FromTime = filters.ToTime;
                filters.ToTime = t;
            }
            return filters;
        }

        private void InvalidateInvestigationWorkspaceEdgeIfStale()
        {
            EnsureInvestigationWorkspace();
            if (string.IsNullOrWhiteSpace(_investigationWorkspace.SelectedEdgeType) || string.IsNullOrWhiteSpace(_investigationWorkspace.SelectedEdgeValue))
                return;
            if (_currentInvestigationGraphEdges == null || _currentInvestigationGraphEdges.Count == 0)
            {
                _investigationWorkspace.ClearSelectedEdge();
                return;
            }
            bool found = false;
            foreach (var e in _currentInvestigationGraphEdges)
            {
                if (e != null &&
                    string.Equals(e.RelatedType, _investigationWorkspace.SelectedEdgeType, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(e.NormalizedValue, _investigationWorkspace.SelectedEdgeValue, StringComparison.OrdinalIgnoreCase))
                {
                    found = true;
                    break;
                }
            }
            if (!found)
                _investigationWorkspace.ClearSelectedEdge();
        }

        private void ApplyWorkspaceFiltersToUi(IR_Collect.Analysis.Correlation.InvestigationWorkspaceFilters f)
        {
            if (f == null)
                return;

            if (comboCorrelationSource != null && comboCorrelationSource.Items.Count > 0)
            {
                string wantSrc = string.IsNullOrWhiteSpace(f.SourcePrefixFilter) ? "(All)" : f.SourcePrefixFilter.Trim();
                comboCorrelationSource.SelectedIndex = 0;
                for (int i = 0; i < comboCorrelationSource.Items.Count; i++)
                {
                    if (string.Equals(comboCorrelationSource.Items[i].ToString(), wantSrc, StringComparison.OrdinalIgnoreCase))
                    {
                        comboCorrelationSource.SelectedIndex = i;
                        break;
                    }
                }
            }

            if (comboCorrelationConfidence != null && comboCorrelationConfidence.Items.Count > 0)
            {
                string wantConf = string.IsNullOrWhiteSpace(f.TimeConfidenceFilter) ? "(All)" : f.TimeConfidenceFilter.Trim();
                comboCorrelationConfidence.SelectedIndex = 0;
                for (int i = 0; i < comboCorrelationConfidence.Items.Count; i++)
                {
                    if (string.Equals(comboCorrelationConfidence.Items[i].ToString(), wantConf, StringComparison.OrdinalIgnoreCase))
                    {
                        comboCorrelationConfidence.SelectedIndex = i;
                        break;
                    }
                }
            }

            if (txtCorrelationHostFilter != null)
                txtCorrelationHostFilter.Text = f.HostFilterText ?? "";

            if (comboCorrelationWindow != null && comboCorrelationWindow.Items.Count > 0 && f.BucketMinutes > 0)
            {
                string wantWin = f.BucketMinutes.ToString() + "m";
                for (int i = 0; i < comboCorrelationWindow.Items.Count; i++)
                {
                    if (string.Equals(comboCorrelationWindow.Items[i].ToString(), wantWin, StringComparison.OrdinalIgnoreCase))
                    {
                        comboCorrelationWindow.SelectedIndex = i;
                        break;
                    }
                }
            }

            if (dtCorrelationFrom != null)
            {
                dtCorrelationFrom.Checked = f.UseFromTime;
                if (f.UseFromTime)
                    dtCorrelationFrom.Value = f.FromTime;
            }
            if (dtCorrelationTo != null)
            {
                dtCorrelationTo.Checked = f.UseToTime;
                if (f.UseToTime)
                    dtCorrelationTo.Value = f.ToTime;
            }
        }

        private void ApplyWorkspaceHostScopeToUi(string scopeMode)
        {
            if (comboWorkspaceHostScope == null || comboWorkspaceHostScope.Items.Count == 0)
                return;
            string display = "All loaded hosts";
            if (string.Equals(scopeMode, IR_Collect.Analysis.Correlation.InvestigationWorkspaceHostScopeMode.CurrentEdgeHosts, StringComparison.OrdinalIgnoreCase))
                display = "Current edge hosts";
            else if (string.Equals(scopeMode, IR_Collect.Analysis.Correlation.InvestigationWorkspaceHostScopeMode.HostFilter, StringComparison.OrdinalIgnoreCase))
                display = "Host filter text";
            for (int i = 0; i < comboWorkspaceHostScope.Items.Count; i++)
            {
                if (string.Equals(comboWorkspaceHostScope.Items[i].ToString(), display, StringComparison.OrdinalIgnoreCase))
                {
                    comboWorkspaceHostScope.SelectedIndex = i;
                    return;
                }
            }
        }

        private void SetTimelineGraphHandoffFromInvestigation(IR_Collect.Analysis.CaseData c, IR_Collect.Analysis.Correlation.InvestigationGraphEdge graphEdge, string trailText)
        {
            ClearTimelineGraphHandoff();
            if (c == null || graphEdge == null)
                return;
            _timelineGraphHandoffCase = c;
            _timelineGraphHandoffRelatedType = (graphEdge.RelatedType ?? "").Trim();
            _timelineGraphHandoffNormalizedValue = (graphEdge.NormalizedValue ?? "").Trim();
            _timelineGraphHandoffNeedle = !string.IsNullOrWhiteSpace(graphEdge.DisplayValue)
                ? graphEdge.DisplayValue.Trim()
                : (graphEdge.NormalizedValue ?? "").Trim();
            _timelineGraphHandoffTrail = trailText ?? "";
            _timelineGraphHandoffHasWindow = false;
            if (IR_Collect.Analysis.Correlation.FactTimeMetadata.HasUsableTime(graphEdge.FirstSeen) &&
                IR_Collect.Analysis.Correlation.FactTimeMetadata.HasUsableTime(graphEdge.LastSeen))
            {
                _timelineGraphHandoffHasWindow = true;
                _timelineGraphHandoffWindowFrom = NormalizeTimelinePickerToMinute(graphEdge.FirstSeen);
                _timelineGraphHandoffWindowTo = NormalizeTimelinePickerToMinute(graphEdge.LastSeen);
            }
        }

        private void ClearTimelineGraphHandoff()
        {
            _timelineGraphHandoffCase = null;
            _timelineGraphHandoffRelatedType = "";
            _timelineGraphHandoffNormalizedValue = "";
            _timelineGraphHandoffNeedle = "";
            _timelineGraphHandoffTrail = "";
            _timelineGraphHandoffHasWindow = false;
        }

        private bool TryConsumeTimelineGraphHandoff(IR_Collect.Analysis.CaseData c, out string relatedType, out string normalizedValue, out string needle, out string trail, out bool hasWindow, out DateTime wFrom, out DateTime wTo)
        {
            relatedType = "";
            normalizedValue = "";
            needle = "";
            trail = "";
            hasWindow = false;
            wFrom = DateTime.MinValue;
            wTo = DateTime.MinValue;
            if (c == null || _timelineGraphHandoffCase == null || !object.ReferenceEquals(_timelineGraphHandoffCase, c))
                return false;
            relatedType = _timelineGraphHandoffRelatedType ?? "";
            normalizedValue = _timelineGraphHandoffNormalizedValue ?? "";
            needle = _timelineGraphHandoffNeedle ?? "";
            trail = _timelineGraphHandoffTrail ?? "";
            hasWindow = _timelineGraphHandoffHasWindow;
            wFrom = _timelineGraphHandoffWindowFrom;
            wTo = _timelineGraphHandoffWindowTo;
            ClearTimelineGraphHandoff();
            return true;
        }

        private List<IR_Collect.Analysis.CaseData> GetWorkspaceScopedCases(List<IR_Collect.Analysis.CaseData> allCases)
        {
            EnsureInvestigationWorkspace();
            if (allCases == null)
                return new List<IR_Collect.Analysis.CaseData>();

            InvalidateInvestigationWorkspaceEdgeIfStale();
            string scopeMode = GetSelectedWorkspaceHostScopeMode();
            _investigationWorkspace.HostScopeMode = scopeMode;
            if (string.Equals(scopeMode, IR_Collect.Analysis.Correlation.InvestigationWorkspaceHostScopeMode.CurrentEdgeHosts, StringComparison.OrdinalIgnoreCase))
            {
                var edgeHosts = _investigationWorkspace.SelectedEdgeHosts != null
                    ? new HashSet<string>(_investigationWorkspace.SelectedEdgeHosts, StringComparer.OrdinalIgnoreCase)
                    : new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                if (edgeHosts.Count == 0)
                    return allCases;
                return allCases.Where(c => c != null && edgeHosts.Contains(c.Hostname ?? "host")).ToList();
            }
            if (string.Equals(scopeMode, IR_Collect.Analysis.Correlation.InvestigationWorkspaceHostScopeMode.HostFilter, StringComparison.OrdinalIgnoreCase))
            {
                string hostFilter = txtCorrelationHostFilter != null ? (txtCorrelationHostFilter.Text ?? "").Trim() : "";
                if (string.IsNullOrWhiteSpace(hostFilter))
                    return allCases;
                return allCases.Where(c => c != null && (c.Hostname ?? "host").IndexOf(hostFilter, StringComparison.OrdinalIgnoreCase) >= 0).ToList();
            }
            return allCases;
        }

        private string GetSelectedWorkspaceHostScopeMode()
        {
            string value = comboWorkspaceHostScope != null && comboWorkspaceHostScope.SelectedItem != null
                ? comboWorkspaceHostScope.SelectedItem.ToString()
                : "All loaded hosts";
            if (string.Equals(value, "Current edge hosts", StringComparison.OrdinalIgnoreCase))
                return IR_Collect.Analysis.Correlation.InvestigationWorkspaceHostScopeMode.CurrentEdgeHosts;
            if (string.Equals(value, "Host filter text", StringComparison.OrdinalIgnoreCase))
                return IR_Collect.Analysis.Correlation.InvestigationWorkspaceHostScopeMode.HostFilter;
            return IR_Collect.Analysis.Correlation.InvestigationWorkspaceHostScopeMode.AllHosts;
        }

        private IR_Collect.Analysis.Correlation.InvestigationGraphEdge GetSelectedInvestigationGraphEdge()
        {
            if (listCorrelation == null || listCorrelation.SelectedItems == null || listCorrelation.SelectedItems.Count == 0)
                return null;
            var selected = listCorrelation.SelectedItems[0];
            return selected != null ? selected.Tag as IR_Collect.Analysis.Correlation.InvestigationGraphEdge : null;
        }

        private IR_Collect.Analysis.Correlation.InvestigationWorkspaceSeed ResolveCurrentWorkspaceSeed()
        {
            EnsureInvestigationWorkspace();
            var current = _investigationWorkspace.CurrentSeed;
            if (current != null)
                return current;

            string seedType;
            string seedValue;
            string seedDisplay;
            if (TryResolveSeedEntity(out seedType, out seedValue, out seedDisplay))
            {
                _investigationWorkspace.Filters = BuildWorkspaceFiltersFromUi();
                _investigationWorkspace.HostScopeMode = GetSelectedWorkspaceHostScopeMode();
                _investigationWorkspace.StartOrAppendSeed(seedType, seedValue, seedDisplay);
                return _investigationWorkspace.CurrentSeed;
            }
            return null;
        }

        private void RunInvestigationWorkspaceExpandFromSelectedEdge()
        {
            EnsureInvestigationWorkspace();
            var edge = GetSelectedInvestigationGraphEdge();
            if (edge == null)
            {
                MessageBox.Show("Select an investigation graph edge first.", "Expand From Selected Edge", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            _investigationWorkspace.Filters = BuildWorkspaceFiltersFromUi();
            _investigationWorkspace.HostScopeMode = GetSelectedWorkspaceHostScopeMode();
            _investigationWorkspace.SetSelectedEdge(edge);
            string seedDisplay = !string.IsNullOrWhiteSpace(edge.DisplayValue) ? edge.DisplayValue : (edge.NormalizedValue ?? "");
            _investigationWorkspace.StartOrAppendSeed(edge.RelatedType ?? "Entity", edge.NormalizedValue ?? "", seedDisplay);
            txtEntityValue.Text = seedDisplay;
            if (comboEntityType != null)
            {
                for (int i = 0; i < comboEntityType.Items.Count; i++)
                {
                    if (string.Equals(comboEntityType.Items[i].ToString(), edge.RelatedType ?? "", StringComparison.OrdinalIgnoreCase))
                    {
                        comboEntityType.SelectedIndex = i;
                        break;
                    }
                }
            }

            RunInvestigationGraphFromWorkspaceSeed();
        }

        private void RunInvestigationWorkspaceBack()
        {
            EnsureInvestigationWorkspace();
            if (!_investigationWorkspace.CanGoBack)
            {
                MessageBox.Show("No previous seed in the investigation trail.", "Back", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            _investigationWorkspace.GoBack();
            RunInvestigationGraphFromWorkspaceSeed();
        }

        private void RunInvestigationWorkspaceForward()
        {
            EnsureInvestigationWorkspace();
            if (!_investigationWorkspace.CanGoForward)
            {
                MessageBox.Show("No forward seed in the investigation trail.", "Forward", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            _investigationWorkspace.GoForward();
            RunInvestigationGraphFromWorkspaceSeed();
        }

        private void RunInvestigationWorkspaceResetToOriginalSeed()
        {
            EnsureInvestigationWorkspace();
            if (_investigationWorkspace.OriginalSeed == null)
            {
                MessageBox.Show("No original seed is available yet.", "Reset To Original Seed", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            _investigationWorkspace.ResetToOriginalSeed();
            RunInvestigationGraphFromWorkspaceSeed();
        }

        private void RunInvestigationWorkspacePinSelectedEdge()
        {
            EnsureInvestigationWorkspace();
            var edge = GetSelectedInvestigationGraphEdge();
            if (edge != null)
                _investigationWorkspace.SetSelectedEdge(edge);
            _investigationWorkspace.PinSelectedEdge();
            _investigationWorkspace.PinCurrentSeed();
            RefreshInvestigationWorkspaceUi();
        }

        private void RunInvestigationWorkspaceOpenSelectedEdgeFacts()
        {
            EnsureInvestigationWorkspace();
            var edge = GetSelectedInvestigationGraphEdge();
            if (edge != null)
                _investigationWorkspace.SetSelectedEdge(edge);
            string edgeType = _investigationWorkspace.SelectedEdgeType ?? "";
            string edgeValue = _investigationWorkspace.SelectedEdgeValue ?? "";
            if (string.IsNullOrWhiteSpace(edgeType) || string.IsNullOrWhiteSpace(edgeValue))
            {
                MessageBox.Show("Select an investigation graph edge first.", "Open Facts", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            var options = GetCorrelationOptions(500);
            var scopedCases = GetWorkspaceScopedCases(CollectLoadedCases());
            var graphEdge = edge ?? _currentInvestigationGraphEdges.FirstOrDefault(g =>
                g != null &&
                string.Equals(g.RelatedType, edgeType, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(g.NormalizedValue, edgeValue, StringComparison.OrdinalIgnoreCase));
            if (graphEdge == null)
                graphEdge = new IR_Collect.Analysis.Correlation.InvestigationGraphEdge { RelatedType = edgeType, NormalizedValue = edgeValue, DisplayValue = _investigationWorkspace.SelectedEdgeDisplay, Hosts = _investigationWorkspace.SelectedEdgeHosts };

            bool restrictToEdgeHosts = string.Equals(GetSelectedWorkspaceHostScopeMode(), IR_Collect.Analysis.Correlation.InvestigationWorkspaceHostScopeMode.CurrentEdgeHosts, StringComparison.OrdinalIgnoreCase);
            var hits = IR_Collect.Analysis.Correlation.InvestigationGraphBuilder.BuildEdgeFactHits(scopedCases, graphEdge, options, restrictToEdgeHosts);
            if (hits.Count == 0)
            {
                MessageBox.Show("No matching facts were found for the selected edge under current workspace filters.", "Open Facts", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            var targetHit = hits[0];
            SetFactsNavigationFocus(targetHit.CaseData, edgeType, edgeValue, targetHit.Fact != null ? targetHit.Fact.RawRef : "");
            TreeNode node = FindHostNode(targetHit.CaseData);
            if (node == null)
                return;
            bool alreadySelected = object.ReferenceEquals(treeHosts.SelectedNode, node);
            treeHosts.SelectedNode = node;
            if (alreadySelected)
                BuildHostTabs(targetHit.CaseData);
            if (dashboardPanel != null) dashboardPanel.Visible = false;
            if (rightContentPanel != null) rightContentPanel.Visible = true;
            SelectTopLevelHostTab("Facts");
        }

        private void RunInvestigationWorkspaceOpenSelectedEdgeTimeline()
        {
            EnsureInvestigationWorkspace();
            var edge = GetSelectedInvestigationGraphEdge();
            if (edge != null)
                _investigationWorkspace.SetSelectedEdge(edge);
            string edgeType = _investigationWorkspace.SelectedEdgeType ?? "";
            string edgeValue = _investigationWorkspace.SelectedEdgeValue ?? "";
            if (string.IsNullOrWhiteSpace(edgeType) || string.IsNullOrWhiteSpace(edgeValue))
            {
                MessageBox.Show("Select an investigation graph edge first.", "Open Timeline", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            var options = GetCorrelationOptions(500);
            var scopedCases = GetWorkspaceScopedCases(CollectLoadedCases());
            var graphEdge = edge ?? _currentInvestigationGraphEdges.FirstOrDefault(g =>
                g != null &&
                string.Equals(g.RelatedType, edgeType, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(g.NormalizedValue, edgeValue, StringComparison.OrdinalIgnoreCase));
            if (graphEdge == null)
                graphEdge = new IR_Collect.Analysis.Correlation.InvestigationGraphEdge
                {
                    RelatedType = edgeType,
                    NormalizedValue = edgeValue,
                    DisplayValue = _investigationWorkspace.SelectedEdgeDisplay,
                    Hosts = _investigationWorkspace.SelectedEdgeHosts
                };
            bool restrictToEdgeHosts = string.Equals(GetSelectedWorkspaceHostScopeMode(), IR_Collect.Analysis.Correlation.InvestigationWorkspaceHostScopeMode.CurrentEdgeHosts, StringComparison.OrdinalIgnoreCase);
            var hits = IR_Collect.Analysis.Correlation.InvestigationGraphBuilder.BuildEdgeFactHits(scopedCases, graphEdge, options, restrictToEdgeHosts);
            if (hits.Count == 0)
            {
                MessageBox.Show("No matching timeline context was found for the selected edge under current workspace filters.", "Open Timeline", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            var targetHit = hits[0];
            SetTimelineGraphHandoffFromInvestigation(targetHit.CaseData, graphEdge, _investigationWorkspace.BuildTrailText(6));
            TreeNode node = FindHostNode(targetHit.CaseData);
            if (node == null)
                return;
            bool alreadySelected = object.ReferenceEquals(treeHosts.SelectedNode, node);
            treeHosts.SelectedNode = node;
            if (alreadySelected)
                BuildHostTabs(targetHit.CaseData);
            if (dashboardPanel != null) dashboardPanel.Visible = false;
            if (rightContentPanel != null) rightContentPanel.Visible = true;
            SelectTopLevelHostTab("Timeline Analysis");
        }

        private void RunInvestigationGraphFromWorkspaceSeed()
        {
            EnsureInvestigationWorkspace();
            var seed = ResolveCurrentWorkspaceSeed();
            if (seed == null)
            {
                MessageBox.Show("No workspace seed is available. Set an entity seed first.", "Investigation Workspace", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            _investigationWorkspace.ClearSelectedEdge();

            if (seed.SnapshotFilters != null)
                ApplyWorkspaceFiltersToUi(seed.SnapshotFilters);
            else if (_investigationWorkspace.Filters != null)
                ApplyWorkspaceFiltersToUi(_investigationWorkspace.Filters);

            string scopeSnap = !string.IsNullOrWhiteSpace(seed.SnapshotHostScopeMode)
                ? seed.SnapshotHostScopeMode
                : (_investigationWorkspace.HostScopeMode ?? IR_Collect.Analysis.Correlation.InvestigationWorkspaceHostScopeMode.AllHosts);
            ApplyWorkspaceHostScopeToUi(scopeSnap);

            if (comboEntityType != null)
            {
                for (int i = 0; i < comboEntityType.Items.Count; i++)
                {
                    if (string.Equals(comboEntityType.Items[i].ToString(), seed.SeedType ?? "", StringComparison.OrdinalIgnoreCase))
                    {
                        comboEntityType.SelectedIndex = i;
                        break;
                    }
                }
            }
            if (txtEntityValue != null)
                txtEntityValue.Text = seed.SeedDisplay ?? seed.SeedValue ?? "";

            _investigationWorkspace.Filters = BuildWorkspaceFiltersFromUi();
            _investigationWorkspace.HostScopeMode = GetSelectedWorkspaceHostScopeMode();

            var scopedCases = GetWorkspaceScopedCases(CollectLoadedCases());
            var options = GetCorrelationOptions(300);
            var results = IR_Collect.Analysis.Correlation.InvestigationGraphBuilder.Build(scopedCases, seed.SeedType, seed.SeedValue, options);
            _currentInvestigationGraphEdges = results;
            _investigationWorkspace.ResultMode = IR_Collect.Analysis.Correlation.InvestigationWorkspaceResultMode.InvestigationGraph;
            _investigationWorkspace.HostScopeMode = GetSelectedWorkspaceHostScopeMode();
            _investigationWorkspace.Filters = BuildWorkspaceFiltersFromUi();

            listCorrelation.Items.Clear();
            listCorrelation.Columns.Clear();
            listCorrelation.Columns.Add("Related Type", 120);
            listCorrelation.Columns.Add("Related Entity", 300);
            listCorrelation.Columns.Add("Hosts", 60);
            listCorrelation.Columns.Add("Facts", 70);
            listCorrelation.Columns.Add("Sources", 170);
            listCorrelation.Columns.Add("Actions", 160);
            listCorrelation.Columns.Add("First Seen", 140);
            listCorrelation.Columns.Add("Last Seen", -2);

            foreach (var row in results)
            {
                var item = new ListViewItem(row.RelatedType ?? "");
                item.SubItems.Add(row.DisplayValue ?? row.NormalizedValue ?? "");
                item.SubItems.Add((row.Hosts != null ? row.Hosts.Count : 0).ToString());
                item.SubItems.Add(row.FactCount.ToString());
                item.SubItems.Add(FormatSharedValueList(row.Sources, 4));
                item.SubItems.Add(FormatSharedValueList(row.Actions, 4));
                item.SubItems.Add(FormatPivotTime(row.FirstSeen));
                item.SubItems.Add(FormatPivotTime(row.LastSeen));
                item.Tag = row;
                listCorrelation.Items.Add(item);
            }

            RefreshInvestigationWorkspaceUi();
        }

        private void RefreshInvestigationWorkspaceUi()
        {
            EnsureInvestigationWorkspace();
            InvalidateInvestigationWorkspaceEdgeIfStale();
            if (lblGraphWorkspaceTrail != null)
            {
                string scopeLabel = "all hosts";
                string scopeMode = GetSelectedWorkspaceHostScopeMode();
                if (string.Equals(scopeMode, IR_Collect.Analysis.Correlation.InvestigationWorkspaceHostScopeMode.CurrentEdgeHosts, StringComparison.OrdinalIgnoreCase))
                    scopeLabel = _investigationWorkspace.SelectedEdgeHosts != null && _investigationWorkspace.SelectedEdgeHosts.Count > 0
                        ? "edge hosts: " + string.Join(", ", _investigationWorkspace.SelectedEdgeHosts.Take(4).ToArray()) + (_investigationWorkspace.SelectedEdgeHosts.Count > 4 ? " +" + (_investigationWorkspace.SelectedEdgeHosts.Count - 4).ToString() : "")
                        : "edge hosts: (no valid edge — using all hosts)";
                else if (string.Equals(scopeMode, IR_Collect.Analysis.Correlation.InvestigationWorkspaceHostScopeMode.HostFilter, StringComparison.OrdinalIgnoreCase))
                    scopeLabel = "host filter: " + ((txtCorrelationHostFilter != null ? (txtCorrelationHostFilter.Text ?? "").Trim() : "") == "" ? "(empty)" : (txtCorrelationHostFilter.Text ?? "").Trim());
                lblGraphWorkspaceTrail.Text = _investigationWorkspace.BuildTrailText(6) + " | Scope: " + scopeLabel;
            }
            if (lblGraphWorkspacePinned != null)
            {
                if (_investigationWorkspace.PinnedEntities == null || _investigationWorkspace.PinnedEntities.Count == 0)
                    lblGraphWorkspacePinned.Text = "Pinned: (none)";
                else
                    lblGraphWorkspacePinned.Text = "Pinned: " + string.Join(" | ", _investigationWorkspace.PinnedEntities.Take(5).ToArray()) +
                        (_investigationWorkspace.PinnedEntities.Count > 5 ? " | +" + (_investigationWorkspace.PinnedEntities.Count - 5).ToString() + " more" : "");
            }

            if (btnGraphBack != null) btnGraphBack.Enabled = _investigationWorkspace.CanGoBack;
            if (btnGraphForward != null) btnGraphForward.Enabled = _investigationWorkspace.CanGoForward;
            if (btnGraphResetSeed != null) btnGraphResetSeed.Enabled = _investigationWorkspace.OriginalSeed != null;
            bool hasEdge = !string.IsNullOrWhiteSpace(_investigationWorkspace.SelectedEdgeType) && !string.IsNullOrWhiteSpace(_investigationWorkspace.SelectedEdgeValue);
            if (btnGraphExpandFromEdge != null) btnGraphExpandFromEdge.Enabled = hasEdge;
            if (btnGraphPin != null) btnGraphPin.Enabled = hasEdge || _investigationWorkspace.CurrentSeed != null;
            if (btnGraphOpenFacts != null) btnGraphOpenFacts.Enabled = hasEdge;
            if (btnGraphOpenTimeline != null) btnGraphOpenTimeline.Enabled = hasEdge;
        }

        private class ProcEvent
        {
            public string Host { get; set; }
            public DateTime Time { get; set; }
            public string Indicator { get; set; }
            public string Source { get; set; }
            public string Evidence { get; set; }
        }

        private IR_Collect.Analysis.CaseData GetSelectedCaseData()
        {
            return treeHosts != null && treeHosts.SelectedNode != null
                ? treeHosts.SelectedNode.Tag as IR_Collect.Analysis.CaseData
                : null;
        }

        private bool EnsureSelectedHostMaintenanceReady(string title, out IR_Collect.Analysis.CaseData c)
        {
            c = GetSelectedCaseData();
            if (c == null)
            {
                MessageBox.Show("Please select a host first.", title, MessageBoxButtons.OK, MessageBoxIcon.Information);
                return false;
            }
            if (_collectionInProgress)
            {
                MessageBox.Show("Local collection is still running. Please wait.", title, MessageBoxButtons.OK, MessageBoxIcon.Information);
                return false;
            }
            if (HasBackgroundViewLoadsInProgress())
            {
                MessageBox.Show("One or more background views are still loading. Please wait.", title, MessageBoxButtons.OK, MessageBoxIcon.Information);
                return false;
            }
            if (c.FactStoreBuilding)
            {
                MessageBox.Show("This host is still building Fact Store. Please wait.", title, MessageBoxButtons.OK, MessageBoxIcon.Information);
                return false;
            }
            return true;
        }

        private void RefreshSelectedHostAfterMaintenance(IR_Collect.Analysis.CaseData c)
        {
            UpdateSummary();
            if (c == null || treeHosts == null || treeHosts.SelectedNode == null)
                return;
            if (!object.ReferenceEquals(treeHosts.SelectedNode.Tag, c))
                return;

            BuildHostTabs(c);
            if (dashboardPanel != null) dashboardPanel.Visible = false;
            if (rightContentPanel != null) rightContentPanel.Visible = true;
        }

        private void RunRebuildSelectedEventLogs()
        {
            IR_Collect.Analysis.CaseData c;
            if (!EnsureSelectedHostMaintenanceReady("Rebuild Event Logs", out c))
                return;

            var worker = new System.ComponentModel.BackgroundWorker();
            worker.DoWork += (s, ev) =>
            {
                try
                {
                    var caseData = ev.Argument as IR_Collect.Analysis.CaseData;
                    var rebuild = IR_Collect.Analysis.CaseManager.RebuildFilteredEventLogs(caseData, true);
                    IR_Collect.Analysis.CaseManager.RefreshFactStoreFreshness(caseData);
                    ev.Result = Tuple.Create(caseData, rebuild, (string)null);
                }
                catch (Exception ex)
                {
                    ev.Result = Tuple.Create((IR_Collect.Analysis.CaseData)null, (IR_Collect.Analysis.CaseManager.EventLogRebuildResult)null, ex != null ? ex.Message : "Unknown error");
                }
            };
            worker.RunWorkerCompleted += (s, ev) =>
            {
                if (ev.Error != null)
                {
                    MessageBox.Show("Event Log rebuild failed: " + ev.Error.Message, "Rebuild Event Logs", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                var result = ev.Result as Tuple<IR_Collect.Analysis.CaseData, IR_Collect.Analysis.CaseManager.EventLogRebuildResult, string>;
                if (result == null)
                {
                    MessageBox.Show("Event Log rebuild failed.", "Rebuild Event Logs", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                if (!string.IsNullOrEmpty(result.Item3))
                {
                    MessageBox.Show("Event Log rebuild failed: " + result.Item3, "Rebuild Event Logs", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                var caseData = result.Item1;
                var rebuild = result.Item2 ?? new IR_Collect.Analysis.CaseManager.EventLogRebuildResult();
                RefreshSelectedHostAfterMaintenance(caseData);

                if (rebuild.TotalLogs <= 0)
                {
                    MessageBox.Show(rebuild.Detail ?? "No EVTX artifacts are available for this host.", "Rebuild Event Logs", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }

                var sb = new StringBuilder();
                sb.AppendFormat("Rebuilt {0}/{1} Event Log filtered CSV file(s).", rebuild.RebuiltLogs, rebuild.TotalLogs);
                if (rebuild.SkippedLogs > 0)
                    sb.AppendFormat("\nSkipped {0} existing log(s).", rebuild.SkippedLogs);
                if (rebuild.FailedLogs > 0)
                    sb.AppendFormat("\nFailed {0} log(s): {1}.", rebuild.FailedLogs, string.Join(", ", rebuild.FailedLabels.ToArray()));
                sb.AppendFormat("\nWindow: last {0} day(s), max {1} events per log.", rebuild.EffectiveDaysBack, rebuild.MaxEventsPerLog);
                if (caseData != null && caseData.FactStore != null && caseData.FactStore.Count > 0)
                    sb.Append("\n\nFact Store was not rebuilt. Rebuild Fact Store if you want Facts/export to reflect the new Event Log CSVs.");
                if (!string.IsNullOrWhiteSpace(rebuild.Detail))
                    sb.Append("\n\n" + rebuild.Detail);
                MessageBox.Show(sb.ToString(), "Rebuild Event Logs", MessageBoxButtons.OK, rebuild.FailedLogs > 0 ? MessageBoxIcon.Warning : MessageBoxIcon.Information);
            };
            worker.RunWorkerAsync(c);
        }

        private void RunRebuildSelectedFactStore()
        {
            IR_Collect.Analysis.CaseData c;
            if (!EnsureSelectedHostMaintenanceReady("Rebuild Fact Store", out c))
                return;

            c.FactStoreBuilding = true;
            RefreshSelectedHostAfterMaintenance(c);

            bool writeSqlite = config.Get("FactStoreWriteSqlite") == "1";
            var worker = new System.ComponentModel.BackgroundWorker();
            worker.DoWork += (s, ev) =>
            {
                var caseData = ev.Argument as IR_Collect.Analysis.CaseData;
                bool sqliteSaved = false;
                string error = null;
                IR_Collect.Analysis.Correlation.FactStore store = null;
                try
                {
                    _autoBuildFactStoreSemaphore.Wait();
                    store = IR_Collect.Analysis.Correlation.FactStore.BuildFromCase(caseData);
                    if (writeSqlite && store != null && store.Count > 0 && !string.IsNullOrEmpty(caseData.ExtractPath))
                    {
                        try
                        {
                            string dbPath = System.IO.Path.Combine(caseData.ExtractPath, ArtifactNames.FactStoreDb);
                            sqliteSaved = IR_Collect.Analysis.Correlation.FactStorePersistence.SaveToSqlite(store, dbPath);
                        }
                        catch (Exception ex)
                        {
                            Logger.Warning("FactStore SQLite save: " + ex.Message);
                        }
                    }
                }
                catch (Exception ex)
                {
                    error = ex != null ? ex.Message : "Unknown error";
                }
                finally
                {
                    try { _autoBuildFactStoreSemaphore.Release(); } catch { }
                }

                ev.Result = Tuple.Create(caseData, store, sqliteSaved, error);
            };
            worker.RunWorkerCompleted += (s, ev) =>
            {
                c.FactStoreBuilding = false;

                if (ev.Error != null)
                {
                    RefreshSelectedHostAfterMaintenance(c);
                    MessageBox.Show("Fact Store rebuild failed: " + ev.Error.Message, "Rebuild Fact Store", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                var result = ev.Result as Tuple<IR_Collect.Analysis.CaseData, IR_Collect.Analysis.Correlation.FactStore, bool, string>;
                if (result == null || result.Item1 == null)
                {
                    RefreshSelectedHostAfterMaintenance(c);
                    MessageBox.Show("Fact Store rebuild failed.", "Rebuild Fact Store", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                if (!string.IsNullOrEmpty(result.Item4))
                {
                    RefreshSelectedHostAfterMaintenance(c);
                    MessageBox.Show("Fact Store rebuild failed: " + result.Item4, "Rebuild Fact Store", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                var caseData = result.Item1;
                caseData.FactStore = result.Item2;
                IR_Collect.Analysis.CaseManager.RefreshFactStoreFreshness(caseData);
                RefreshSelectedHostAfterMaintenance(caseData);

                int count = caseData.FactStore != null ? caseData.FactStore.Count : 0;
                var sb = new StringBuilder();
                sb.AppendFormat("Rebuilt Fact Store for {0}: {1} fact(s).", caseData.Hostname ?? "host", count);
                if (result.Item3)
                    sb.Append("\nSQLite cache updated.");
                else if (writeSqlite)
                    sb.Append("\nSQLite cache was not updated.");
                if (!result.Item3 && string.Equals(caseData.FactStoreFreshnessStatus, "stale", StringComparison.OrdinalIgnoreCase))
                    sb.Append("\nOn-disk fact_store.db remains stale relative to current source artifacts.");
                MessageBox.Show(sb.ToString(), "Rebuild Fact Store", MessageBoxButtons.OK, MessageBoxIcon.Information);
            };
            worker.RunWorkerAsync(c);
        }

        private void RunBuildFactStore()
        {
            if (treeHosts.Nodes.Count == 0)
            {
                MessageBox.Show("No host loaded. Please import a case first.", "Build Fact Store", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            var cases = new List<IR_Collect.Analysis.CaseData>();
            foreach (TreeNode node in treeHosts.Nodes)
            {
                if (!(node.Tag is IR_Collect.Analysis.CaseData)) continue;
                var c = (IR_Collect.Analysis.CaseData)node.Tag;
                if (c.FactStoreBuilding)
                {
                    MessageBox.Show("One or more hosts are still building Fact Store. Please wait.", "Build Fact Store", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
                cases.Add(c);
            }
            if (cases.Count == 0) return;
            foreach (var c in cases) c.FactStoreBuilding = true;
            bool writeSqlite = config.Get("FactStoreWriteSqlite") == "1";
            if (btnExportFullLogJson != null) btnExportFullLogJson.Enabled = false;
            var worker = new System.ComponentModel.BackgroundWorker();
            worker.DoWork += (s, ev) =>
            {
                var state = (Tuple<List<IR_Collect.Analysis.CaseData>, bool>)ev.Argument;
                var list = state.Item1;
                bool sqlite = state.Item2;
                var built = new StringBuilder();
                int totalFacts = 0;
                try
                {
                    var builtStores = new List<Tuple<IR_Collect.Analysis.CaseData, IR_Collect.Analysis.Correlation.FactStore, bool>>();
                    foreach (var c in list)
                    {
                        var store = IR_Collect.Analysis.Correlation.FactStore.BuildFromCase(c);
                        int count = store != null ? store.Count : 0;
                        totalFacts += count;
                        if (built.Length > 0) built.AppendLine();
                        built.AppendFormat("{0}: {1} facts", c.Hostname ?? "host", count);
                        bool sqliteSaved = false;
                        if (sqlite && store != null && count > 0 && !string.IsNullOrEmpty(c.ExtractPath))
                        {
                            try
                            {
                                string dbPath = System.IO.Path.Combine(c.ExtractPath, ArtifactNames.FactStoreDb);
                                sqliteSaved = IR_Collect.Analysis.Correlation.FactStorePersistence.SaveToSqlite(store, dbPath);
                                if (sqliteSaved)
                                    built.Append(" [SQLite]");
                            }
                            catch (Exception ex)
                            {
                                Logger.Warning("FactStore SQLite save: " + ex.Message);
                            }
                        }
                        builtStores.Add(Tuple.Create(c, store, sqliteSaved));
                    }
                    ev.Result = Tuple.Create(built.ToString(), totalFacts, list.Count, (string)null, builtStores);
                }
                catch (Exception ex)
                {
                    ev.Result = Tuple.Create((string)null, 0, 0, ex != null ? ex.Message : "", (List<Tuple<IR_Collect.Analysis.CaseData, IR_Collect.Analysis.Correlation.FactStore, bool>>)null);
                }
            };
            worker.RunWorkerCompleted += (s, ev) =>
            {
                if (btnExportFullLogJson != null) btnExportFullLogJson.Enabled = true;
                foreach (var c in cases) c.FactStoreBuilding = false;
                if (ev.Error != null)
                {
                    MessageBox.Show("Error building Fact Store: " + ev.Error.Message, "Fact Store", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                var result = ev.Result as Tuple<string, int, int, string, List<Tuple<IR_Collect.Analysis.CaseData, IR_Collect.Analysis.Correlation.FactStore, bool>>>;
                if (result == null)
                {
                    MessageBox.Show("Fact Store build failed (internal error: no result).", "Fact Store", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                if (!string.IsNullOrEmpty(result.Item4))
                {
                    MessageBox.Show("Error building Fact Store: " + result.Item4, "Fact Store", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                        if (result.Item5 != null)
                        {
                            foreach (var item in result.Item5)
                            {
                                if (item == null || item.Item1 == null) continue;
                                item.Item1.FactStore = item.Item2;
                                IR_Collect.Analysis.CaseManager.RefreshFactStoreFreshness(item.Item1);
                            }
                        }
                UpdateSummary();
                MessageBox.Show(string.Format("Fact Store built for {0} host(s).\n\n{1}\n\nTotal: {2} facts.", result.Item3, result.Item1, result.Item2), "Fact Store", MessageBoxButtons.OK, MessageBoxIcon.Information);
            };
            worker.RunWorkerAsync(Tuple.Create(cases, writeSqlite));
        }

        /// <summary>移除所有已載入主機的資料（含解壓目錄與 Fact Store），並清空左側列表與右側分頁。</summary>
        private void RunClearAllHosts()
        {
            if (treeHosts.Nodes.Count == 0)
            {
                MessageBox.Show("No host loaded.", "Clear all hosts", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            if (_collectionInProgress)
            {
                MessageBox.Show("Local collection is still running. Please wait.", "Clear all hosts", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            if (HasBackgroundViewLoadsInProgress())
            {
                MessageBox.Show("One or more background views are still loading. Please wait.", "Clear all hosts", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            foreach (TreeNode node in treeHosts.Nodes)
            {
                var c = node.Tag as IR_Collect.Analysis.CaseData;
                if (c != null && c.FactStoreBuilding)
                {
                    MessageBox.Show("One or more hosts are still building Fact Store. Please wait.", "Clear all hosts", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
            }
            var result = MessageBox.Show("Remove all loaded hosts and their data (extract folders and Fact Store)? This cannot be undone.", "Clear all hosts", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
            if (result != DialogResult.Yes) return;

            int count = treeHosts.Nodes.Count;
            int cleanupFailures = IR_Collect.Analysis.CaseManager.CleanupAll();
            treeHosts.Nodes.Clear();
            treeHosts.SelectedNode = null;
            UpdateSummary();
            hostTabs.TabPages.Clear();
            if (listCorrelation != null) listCorrelation.Items.Clear();
            if (dashboardPanel != null) dashboardPanel.Visible = true;
            if (rightContentPanel != null) rightContentPanel.Visible = false;

            string message = cleanupFailures > 0
                ? string.Format("Removed {0} host(s). {1} extract folder(s) could not be deleted; see logs/ir_collect.log.", count, cleanupFailures)
                : string.Format("Removed {0} host(s). All data cleared.", count);
            MessageBox.Show(message, "Clear all hosts", MessageBoxButtons.OK, cleanupFailures > 0 ? MessageBoxIcon.Warning : MessageBoxIcon.Information);
        }

        private void RunExportFullLogJson()
        {
            if (treeHosts.Nodes.Count == 0)
            {
                MessageBox.Show("No host loaded. Please import a case first.", "Export full LOG JSON", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            var cases = new List<IR_Collect.Analysis.CaseData>();
            int skippedBuilding = 0;
            foreach (TreeNode node in treeHosts.Nodes)
            {
                if (!(node.Tag is IR_Collect.Analysis.CaseData)) continue;
                var c = (IR_Collect.Analysis.CaseData)node.Tag;
                if (c.FactStoreBuilding) { skippedBuilding++; continue; }
                if (c.FactStore != null && c.FactStore.Count > 0) cases.Add(c);
            }
            if (cases.Count == 0)
            {
                MessageBox.Show("No Fact Store data to export (or one or more hosts are still building). Load a case with a ready Fact Store first.", "Export full LOG JSON", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            using (var dlg = new SaveFileDialog() { Filter = "JSON|*.json|All|*.*", DefaultExt = "json", FileName = "full_log_facts.json" })
            {
                if (dlg.ShowDialog() != DialogResult.OK) return;
                try
                {
                    IR_Collect.Analysis.Correlation.FactStorePersistence.ExportFullLogJson(cases, dlg.FileName);
                    int total = 0; foreach (var c in cases) total += c.FactStore != null ? c.FactStore.Count : 0;
                    string message = string.Format("Exported {0} fact(s) from {1} host(s) to {2}.", total, cases.Count, dlg.FileName);
                    if (skippedBuilding > 0)
                        message += string.Format("\n\nSkipped {0} host(s) that are still building Fact Store.", skippedBuilding);
                    MessageBox.Show(message, "Export full LOG JSON", MessageBoxButtons.OK, skippedBuilding > 0 ? MessageBoxIcon.Warning : MessageBoxIcon.Information);
                }
                catch (Exception ex) { MessageBox.Show("Export failed: " + ex.Message, "Export full LOG JSON", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
            }
        }

        private void RunEntitySearch()
        {
            if (treeHosts.Nodes.Count == 0)
            {
                MessageBox.Show("No host loaded. Please import a case first.", "Entity Search", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            string type = (comboEntityType.SelectedItem != null) ? comboEntityType.SelectedItem.ToString() : "Path";
            string value = txtEntityValue != null ? (txtEntityValue.Text ?? "").Trim() : "";
            if (string.IsNullOrEmpty(value))
            {
                MessageBox.Show("Please enter a value to search (e.g. Path, User, Provider, EventId, RemoteIP, ServiceName).", "Entity Search", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            listCorrelation.Items.Clear();
            listCorrelation.Columns.Clear();
            listCorrelation.Columns.Add("Host", 120);
            listCorrelation.Columns.Add("Time", 160);
            listCorrelation.Columns.Add("Time Meta", 110);
            listCorrelation.Columns.Add("Source", 120);
            listCorrelation.Columns.Add("Action", 90);
            listCorrelation.Columns.Add("Details", 420);

            // Cap results so a broad entity (e.g. a common Path) on a large multi-host Fact Store
            // cannot freeze the UI / exhaust memory by adding hundreds of thousands of items to this
            // non-virtual ListView.
            const int MaxEntitySearchResults = 5000;
            int hitCount = 0;
            bool capped = false;
            listCorrelation.BeginUpdate();
            try
            {
                foreach (TreeNode node in treeHosts.Nodes)
                {
                    if (capped) break;
                    if (!(node.Tag is IR_Collect.Analysis.CaseData)) continue;
                    var c = (IR_Collect.Analysis.CaseData)node.Tag;
                    if (c.FactStoreBuilding || c.FactStore == null) continue;
                    var facts = c.FactStore.GetByEntity(type, value);
                    string host = c.Hostname ?? "host";
                    foreach (var f in facts)
                    {
                        if (hitCount >= MaxEntitySearchResults) { capped = true; break; }
                        var item = new ListViewItem(host);
                        item.SubItems.Add(FormatFactTime(f.Time));
                        item.SubItems.Add(FormatFactTimeMetadata(f));
                        item.SubItems.Add(f.Source ?? "");
                        item.SubItems.Add(f.Action ?? "");
                        item.SubItems.Add((f.Details != null && f.Details.Length > 200) ? f.Details.Substring(0, 197) + "..." : (f.Details ?? ""));
                        listCorrelation.Items.Add(item);
                        hitCount++;
                    }
                }
            }
            finally
            {
                listCorrelation.EndUpdate();
            }
            if (hitCount == 0)
                MessageBox.Show(string.Format("No facts found for {0} = \"{1}\". Build Fact Store first if you have not.", type, value), "Entity Search", MessageBoxButtons.OK, MessageBoxIcon.Information);
            else if (capped)
                MessageBox.Show(string.Format("Showing the first {0} matching fact(s); more matched. Narrow the value or pick a more specific entity type.", MaxEntitySearchResults), "Entity Search", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            else
                MessageBox.Show(string.Format("Found {0} fact(s).", hitCount), "Entity Search", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void RunTimelineCorrelation()
        {
            if (treeHosts.Nodes.Count == 0)
            {
                MessageBox.Show("No host loaded. Please import a case first.", "Find Timeline Correlation", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            listCorrelation.Items.Clear();
            EnsureCorrelationColumns("Indicator", "Count", "Hosts", "Window");
            var events = new List<ProcEvent>();
            foreach (TreeNode n in treeHosts.Nodes)
            {
                var c = n.Tag as IR_Collect.Analysis.CaseData;
                if (c == null) continue;
                events.AddRange(ReadProcessEvents(c));
                events.AddRange(ReadAutorunEvents(c));
                events.AddRange(ReadScheduledTaskEvents(c));
                events.AddRange(ReadMftEvents(c));
                events.AddRange(ReadEventLogEvents(c));
            }

            var grouped = new Dictionary<string, Dictionary<string, HashSet<string>>>();
            foreach (var e in events)
            {
                string bucket = GetTimeBucket(e.Time, 5);
                if (string.IsNullOrEmpty(bucket) || string.IsNullOrEmpty(e.Indicator)) continue;

                Dictionary<string, HashSet<string>> byBucket;
                if (!grouped.TryGetValue(e.Indicator, out byBucket))
                {
                    byBucket = new Dictionary<string, HashSet<string>>();
                    grouped[e.Indicator] = byBucket;
                }

                HashSet<string> hosts;
                if (!byBucket.TryGetValue(bucket, out hosts))
                {
                    hosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    byBucket[bucket] = hosts;
                }
                hosts.Add(e.Host ?? "host");
            }

            int hits = 0;
            foreach (var indicator in grouped.Keys.OrderBy(k => k))
            {
                foreach (var bucket in grouped[indicator].Keys.OrderBy(k => k))
                {
                    var hosts = grouped[indicator][bucket];
                    if (hosts.Count >= 2)
                    {
                        var item = new ListViewItem(indicator);
                        item.SubItems.Add(hosts.Count.ToString());
                        item.SubItems.Add(string.Join(", ", hosts));
                        item.SubItems.Add(bucket);
                        listCorrelation.Items.Add(item);
                        hits++;
                        if (hits >= 200) break;
                    }
                }
                if (hits >= 200) break;
            }

            MessageBox.Show(string.Format("Timeline correlation hits: {0}", hits));
        }

        private void EnsureCorrelationColumns(string col1, string col2, string col3, string col4)
        {
            listCorrelation.Columns.Clear();
            listCorrelation.Columns.Add(col1, 400);
            listCorrelation.Columns.Add(col2, 100);
            listCorrelation.Columns.Add(col3, 400);
            listCorrelation.Columns.Add(col4, -2); // -2 = 填滿右側剩餘寬度
        }

        private string FormatSharedValueList(IEnumerable<string> values, int maxCount)
        {
            if (values == null) return "";

            var list = values
                .Where(v => !string.IsNullOrWhiteSpace(v))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(v => v, StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (list.Count == 0) return "";
            if (list.Count <= maxCount) return string.Join(", ", list.ToArray());

            var shown = list.Take(maxCount).ToArray();
            return string.Join(", ", shown) + " +" + (list.Count - maxCount).ToString() + " more";
        }

        private string FormatPivotTime(DateTime time)
        {
            return IR_Collect.Analysis.Correlation.FactTimeMetadata.HasUsableTime(time)
                ? FormatFactTime(time)
                : "";
        }

        private string BuildFactPreview(IR_Collect.Analysis.Correlation.Fact fact)
        {
            if (fact == null) return "";

            string details = CollapseSingleLine(fact.Details);
            if (string.IsNullOrEmpty(details))
                details = BuildEntitySummary(fact.EntityRefs);
            if (details.Length > 220)
                details = details.Substring(0, 217) + "...";
            return details;
        }

        private const long MaxProcessListBytes = 50L * 1024 * 1024;
        private const long MaxScheduledTasksXmlBytes = 20L * 1024 * 1024;

        private List<ProcEvent> ReadProcessEvents(IR_Collect.Analysis.CaseData c)
        {
            var list = new List<ProcEvent>();
            try
            {
                string path = GetArtifactPath(c, ArtifactNames.ProcessListCsv);
                if (!File.Exists(path)) return list;
                if (new FileInfo(path).Length > MaxProcessListBytes) { Logger.Warning(ArtifactNames.ProcessListCsv + " too large: " + path); return list; }

                string[] lines = File.ReadAllLines(path, System.Text.Encoding.UTF8);
                for (int i = 1; i < lines.Length; i++)
                {
                    var parts = SplitCsvLine(lines[i]);
                    if (parts.Length < 5) continue;

                    DateTime dt;
                    if (!DateTime.TryParse(parts[4], out dt)) continue;

                    string name = parts[1];
                    string cmd = parts.Length > 3 ? parts[3] : "";
                    string indicator = NormalizeIndicator(name, cmd);
                    if (string.IsNullOrEmpty(indicator)) continue;

                    list.Add(new ProcEvent
                    {
                        Host = c.Hostname,
                        Time = dt,
                        Indicator = "process:" + indicator,
                        Source = "process",
                        Evidence = cmd
                    });
                }
            }
            catch (Exception ex) { Logger.Warning("ReadProcessEvents: " + (ex.Message ?? "")); }
            return list;
        }

        private List<ProcEvent> ReadAutorunEvents(IR_Collect.Analysis.CaseData c)
        {
            var list = new List<ProcEvent>();
            try
            {
                string path = GetArtifactPath(c, ArtifactNames.AutorunsRegistryCsv);
                if (!File.Exists(path)) return list;
                if (new FileInfo(path).Length > MaxProcessListBytes) { Logger.Warning(ArtifactNames.AutorunsRegistryCsv + " too large: " + path); return list; }

                string[] lines = File.ReadAllLines(path, System.Text.Encoding.UTF8);
                for (int i = 1; i < lines.Length; i++)
                {
                    var parts = SplitCsvLine(lines[i]);
                    if (parts.Length < 4) continue;

                    string value = parts[3];
                    if (string.IsNullOrEmpty(value)) continue;
                    string indicator = "autorun:" + NormalizeIndicator("", value);
                    list.Add(new ProcEvent
                    {
                        Host = c.Hostname,
                        Time = DateTime.MinValue,
                        Indicator = indicator,
                        Source = "autorun",
                        Evidence = value
                    });
                }
            }
            catch (Exception ex) { Logger.Warning("ReadAutorunEvents: " + (ex.Message ?? "")); }
            return list;
        }

        private List<ProcEvent> ReadScheduledTaskEvents(IR_Collect.Analysis.CaseData c)
        {
            var list = new List<ProcEvent>();
            try
            {
                string path = GetArtifactPath(c, ArtifactNames.ScheduledTasksXml);
                if (!File.Exists(path)) return list;
                if (new FileInfo(path).Length > MaxScheduledTasksXmlBytes) { Logger.Warning(ArtifactNames.ScheduledTasksXml + " too large: " + path); return list; }

                string content = File.ReadAllText(path, System.Text.Encoding.UTF8).Trim();
                content = Regex.Replace(content, @"<\?xml.*?\?>", "", RegexOptions.IgnoreCase);
                if (!content.StartsWith("<Tasks>", StringComparison.OrdinalIgnoreCase))
                    content = "<Tasks>" + content + "</Tasks>";

                var doc = XDocument.Parse(content);
                var tasks = doc.Descendants().Where(e => e.Name.LocalName == "Task");
                foreach (var task in tasks)
                {
                    var actions = task.Descendants().FirstOrDefault(e => e.Name.LocalName == "Actions");
                    if (actions == null) continue;
                    foreach (var act in actions.Elements())
                    {
                        if (act.Name.LocalName == "Exec")
                        {
                            string cmd = "";
                            string args = "";
                            var cmdNode = act.Elements().FirstOrDefault(e => e.Name.LocalName == "Command");
                            if (cmdNode != null) cmd = cmdNode.Value;
                            var argsNode = act.Elements().FirstOrDefault(e => e.Name.LocalName == "Arguments");
                            if (argsNode != null) args = argsNode.Value;

                            string indicator = "task:" + NormalizeIndicator(cmd, args);
                            if (string.IsNullOrEmpty(indicator)) continue;
                            list.Add(new ProcEvent
                            {
                                Host = c.Hostname,
                                Time = DateTime.MinValue,
                                Indicator = indicator,
                                Source = "task",
                                Evidence = cmd + " " + args
                            });
                        }
                    }
                }
            }
            catch (Exception ex) { Logger.Warning("ReadScheduledTaskEvents: " + (ex.Message ?? "")); }
            return list;
        }

        private List<ProcEvent> ReadMftEvents(IR_Collect.Analysis.CaseData c)
        {
            var list = new List<ProcEvent>();
            if (c.MftEntries == null) return list;
            int added = 0;
            foreach (var m in c.MftEntries)
            {
                DateTime created = (m.StdCreated.Year > 1980) ? m.StdCreated : m.FnCreated;
                DateTime modified = (m.StdModified.Year > 1980) ? m.StdModified : m.FnModified;
                string path = !string.IsNullOrEmpty(m.FullPath) ? m.FullPath : m.FileName;
                string indicator = "mft:" + NormalizeIndicator("", path);

                if (created.Year > 1980)
                {
                    list.Add(new ProcEvent { Host = c.Hostname, Time = created, Indicator = indicator, Source = "mft", Evidence = path });
                    added++;
                }
                if (modified.Year > 1980)
                {
                    list.Add(new ProcEvent { Host = c.Hostname, Time = modified, Indicator = indicator, Source = "mft", Evidence = path });
                    added++;
                }
                if (added >= 5000) break;
            }
            return list;
        }

        private List<ProcEvent> ReadEventLogEvents(IR_Collect.Analysis.CaseData c)
        {
            var list = new List<ProcEvent>();
            if (c.Artifacts == null) return list;
            try
            {
                var filteredLogs = GetFilteredEventLogCsvPaths(c);
                if (filteredLogs.Count > 0)
                {
                    foreach (var logFile in filteredLogs)
                    {
                        var rows = IR_Collect.Analysis.Correlation.CorrelationCsvHelper.ReadCsv(logFile.Item2);
                        int scanned = 0;
                        foreach (var row in rows)
                        {
                            string timeStr = IR_Collect.Analysis.Correlation.CorrelationCsvHelper.Get(row, "TimeCreated");
                            DateTime dt = IR_Collect.Analysis.Correlation.CorrelationCsvHelper.ParseDateTime(timeStr, DateTime.MinValue);
                            if (dt.Year < 1980) continue;
                            string eventId = IR_Collect.Analysis.Correlation.CorrelationCsvHelper.Get(row, "EventId");
                            string provider = IR_Collect.Analysis.Correlation.CorrelationCsvHelper.Get(row, "ProviderName");
                            string message = IR_Collect.Analysis.Correlation.CorrelationCsvHelper.Get(row, "Message");
                            string eventData = IR_Collect.Analysis.Correlation.CorrelationCsvHelper.Get(row, EventLogDataHelper.EventDataColumn);
                            string indicator = BuildFilteredEventIndicator(eventId, provider, message, eventData);
                            list.Add(new ProcEvent { Host = c.Hostname, Time = dt, Indicator = indicator, Source = "event", Evidence = "EventID " + (eventId ?? "") });
                            scanned++;
                            if (scanned >= 2000) break;
                        }
                    }
                }
            }
            catch (Exception ex) { Logger.Warning("ReadEventLogEvents: " + (ex.Message ?? "")); }
            return list;
        }

        private string BuildFilteredEventIndicator(string eventId, string provider, string message, string flattenedEventData)
        {
            string id = string.IsNullOrWhiteSpace(eventId) ? "unknown" : eventId.Trim();
            string baseId = "event:" + id;
            Dictionary<string, string> data = EventLogDataHelper.ParseFlattenedEventData(flattenedEventData);

            if (id == "4688")
            {
                string norm4688 = NormalizeIndicator(EventLogDataHelper.GetValue(data, "NewProcessName", "ProcessName", "Image"), EventLogDataHelper.GetValue(data, "CommandLine", "ProcessCommandLine"));
                if (!string.IsNullOrWhiteSpace(norm4688)) return baseId + ":" + norm4688;
            }
            if (id == "4624" || id == "4625")
            {
                string summary462x = BuildEventFieldSummary(
                    "User", EventLogDataHelper.GetValue(data, "TargetUserName", "SubjectUserName"),
                    "Type", EventLogDataHelper.GetValue(data, "LogonType"),
                    "IP", EventLogDataHelper.GetValue(data, "IpAddress", "ClientAddress", "SourceAddress", "RemoteAddress"));
                string norm462x = NormalizeIndicator("", summary462x);
                if (!string.IsNullOrWhiteSpace(norm462x)) return baseId + ":" + norm462x;
            }
            if (id == "4698")
            {
                string norm4698 = NormalizeIndicator(EventLogDataHelper.GetValue(data, "TaskName", "Task"), EventLogDataHelper.GetValue(data, "SubjectUserName", "User"));
                if (!string.IsNullOrWhiteSpace(norm4698)) return baseId + ":" + norm4698;
            }
            if (id == "7045")
            {
                string norm7045 = NormalizeIndicator(EventLogDataHelper.GetValue(data, "ServiceName"), EventLogDataHelper.GetValue(data, "ImagePath", "ServiceFileName"));
                if (!string.IsNullOrWhiteSpace(norm7045)) return baseId + ":" + norm7045;
            }
            if (id == "4104")
            {
                string norm4104 = NormalizeIndicator("", EventLogDataHelper.GetValue(data, "ScriptBlockText"));
                if (!string.IsNullOrWhiteSpace(norm4104)) return baseId + ":" + norm4104;
            }

            string norm = NormalizeIndicator(provider ?? "", !string.IsNullOrWhiteSpace(message) ? message : flattenedEventData ?? "");
            return string.IsNullOrEmpty(norm) ? baseId : (baseId + ":" + norm);
        }

        private string BuildEventIndicator(EventRecord record)
        {
            string baseId = "event:" + record.Id.ToString();
            try
            {
                var data = ExtractEventData(record);
                if (record.Id == 4688)
                {
                    string proc = GetEventField(data, "NewProcessName");
                    string cmd = GetEventField(data, "CommandLine");
                    return baseId + ":" + NormalizeIndicator(proc, cmd);
                }
                if (record.Id == 4624 || record.Id == 4625)
                {
                    string type = GetEventField(data, "LogonType");
                    string ip = GetEventField(data, "IpAddress");
                    return baseId + ":type" + type + ":ip" + ip;
                }
                if (record.Id == 7045)
                {
                    string svc = GetEventField(data, "ServiceName");
                    string img = GetEventField(data, "ImagePath");
                    return baseId + ":" + NormalizeIndicator(svc, img);
                }
                if (record.Id == 4104)
                {
                    string script = GetEventField(data, "ScriptBlockText");
                    return baseId + ":" + NormalizeIndicator("", script);
                }
            }
            catch (Exception ex) { Logger.Warning("BuildEventIndicator: " + (ex.Message ?? "")); }
            return baseId;
        }

        private Dictionary<string, string> ExtractEventData(EventRecord record)
        {
            try
            {
                return EventLogDataHelper.ExtractEventDataFromXml(record.ToXml());
            }
            catch (Exception ex) { Logger.Warning("ExtractEventData: " + (ex.Message ?? "")); }
            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }

        private string GetEventField(Dictionary<string, string> data, string key)
        {
            return EventLogDataHelper.GetValue(data, key);
        }

        private string NormalizeIndicator(string name, string cmd)
        {
            string baseVal = string.IsNullOrEmpty(cmd) ? name : cmd;
            if (string.IsNullOrEmpty(baseVal)) return "";
            baseVal = baseVal.Trim().ToLowerInvariant();
            if (baseVal.Length > 120) baseVal = baseVal.Substring(0, 120);
            return baseVal;
        }

        private string GetTimeBucket(DateTime dt, int minutes)
        {
            if (dt.Year < 1980) return "static";
            int bucketMin = (dt.Minute / minutes) * minutes;
            DateTime bucket = new DateTime(dt.Year, dt.Month, dt.Day, dt.Hour, bucketMin, 0);
            return bucket.ToString("yyyy-MM-dd HH:mm");
        }
    }
}
