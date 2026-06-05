using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Windows.Forms;
using IR_Collect.Utils;

namespace IR_Collect
{
    partial class MainForm
    {
        private volatile bool _collectionInProgress;
        private static readonly System.Threading.SemaphoreSlim _autoBuildFactStoreSemaphore = new System.Threading.SemaphoreSlim(1, 1);
        internal static bool ShouldAutoBuildFactStore(string autoBuildConfigValue, IR_Collect.Analysis.CaseData c)
        {
            return autoBuildConfigValue == "1" && (c == null || c.FactStore == null || c.FactStore.Count == 0);
        }
        internal static string BuildCollectionCompletionMessage(bool caseLoaded, bool loadAttempted, IR_Collect.Collector.CollectionResult collectionResult)
        {
            bool hasErrors = collectionResult != null && collectionResult.HasErrors;
            bool hasCoverageGaps = collectionResult != null && collectionResult.HasCoverageGaps;
            if (hasErrors)
            {
                string collectionMessage = "Collection completed with errors.";
                string failedSummary = collectionResult.BuildFailureSummary();
                if (!string.IsNullOrEmpty(failedSummary))
                    collectionMessage += "\n\nFailed steps: " + failedSummary;
                if (caseLoaded)
                    collectionMessage += "\n\nCase loaded into platform with partial results.";
                else if (loadAttempted)
                    collectionMessage += "\n\nThe ZIP was created, but the case did not load into the platform.";
                return collectionMessage;
            }
            if (hasCoverageGaps)
            {
                string collectionMessage = "Collection completed with coverage gaps.";
                if (collectionResult != null && collectionResult.CoverageReport != null)
                {
                    var report = collectionResult.CoverageReport;
                    collectionMessage += string.Format(
                        "\n\nCoverage: {0} (complete {1}, partial {2}, failed {3}, skipped {4}, missing {5}).",
                        string.IsNullOrWhiteSpace(report.OverallStatus) ? "unknown" : report.OverallStatus,
                        report.CompletedSteps,
                        report.PartialSteps,
                        report.FailedSteps,
                        report.SkippedSteps,
                        report.MissingSteps);
                }
                if (caseLoaded)
                    collectionMessage += "\n\nCase loaded into platform with partial results.";
                else if (loadAttempted)
                    collectionMessage += "\n\nThe ZIP was created, but the case did not load into the platform.";
                return collectionMessage;
            }
            if (caseLoaded) return "Collection Complete! Case loaded into platform.";
            if (loadAttempted) return "Collection complete, but the case did not load into the platform.";
            return "Collection Complete.";
        }

        /// <summary>Invoke on UI thread; no-op if form is disposed (avoids ObjectDisposedException from background threads).</summary>
        private void SafeInvoke(MethodInvoker action)
        {
            if (action == null) return;
            try
            {
                if (IsDisposed || !IsHandleCreated) return;
                if (InvokeRequired)
                    Invoke(action);
                else
                    action();
            }
            catch (ObjectDisposedException) { }
            catch (InvalidOperationException) { }
        }

        private void BtnCollect_Click(object sender, EventArgs e)
        {
            if (!IsAdmin())
            {
                var resp = MessageBox.Show("Need Admin rights for full collection (MFT). Elevate?", "Admin?", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
                if (resp == DialogResult.Yes) { TryRunElevated(); return; }
            }

            string evidenceId = PromptEvidenceId();
            if (evidenceId == "__CANCEL__") return;

            string profile = CollectionModeProfileHelper.GetActive(config);
            if (CollectionModeProfileHelper.IsTriageFast(profile))
            {
                MessageBox.Show(
                    "TriageFast profile is selected.\n\n" +
                    "- This mode is mainly a workflow label: Local Collect still uses the same collector scope as Standard unless you change other settings.\n" +
                    "- Live response can still perturb the host; this is not a footprint or tamper guarantee.\n\n" +
                    "Select OK to continue Local Collect.",
                    "Collection profile — TriageFast",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
            }
            if (CollectionModeProfileHelper.IsForensicStrict(profile))
            {
                string outName = IR_Collect.Collector.GetCollectionOutputDirectoryName(evidenceId);
                string outFull;
                try { outFull = Path.GetFullPath(outName); }
                catch { outFull = outName; }
                string msg =
                    "ForensicStrict profile — read before continuing:\n\n" +
                    "- Live-response collection can change the system (timestamps, caches, defensive memory use). This is not zero-footprint and not a complete low-impact forensic suite.\n\n" +
                    "- Output workspace on this system (before ZIP):\n" + outFull + "\n\n" +
                    "Writing on a compromised system disk can add risk; prefer an isolated output mount when practical.\n\n" +
                    "- After collection, outbound ZIP upload is blocked while this profile remains selected.\n" +
                    "- In-app AI Analyze is blocked while this profile remains selected.\n\n" +
                    "Continue Local Collect?";
                if (MessageBox.Show(msg, "ForensicStrict — live response", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes)
                    return;
            }

            lblCollectStatus.Text = "Collecting... Please wait.";
            progressCollect.Style = ProgressBarStyle.Marquee;
            progressCollect.MarqueeAnimationSpeed = 30;
            collectProgressPanel.Visible = true;
            btnCollect.Enabled = false;
            btnImport.Enabled = false;
            _collectionInProgress = true;
            Application.DoEvents();

            Action<string> onProgress = (msg) => SafeInvoke((MethodInvoker)(() => { if (lblCollectStatus != null && !lblCollectStatus.IsDisposed) lblCollectStatus.Text = msg; }));
            Action action = () => {
                try {
                    var collectionResult = IR_Collect.Collector.RunCollectionDetailed(evidenceId, onProgress);
                    string zipPath = collectionResult != null ? collectionResult.ZipPath : null;
                    string fullPath = null;
                    if (!string.IsNullOrEmpty(zipPath))
                    {
                        try { fullPath = Path.GetFullPath(zipPath); }
                        catch
                        {
                            fullPath = Path.IsPathRooted(zipPath) ? zipPath : Path.Combine(Environment.CurrentDirectory ?? "", zipPath);
                        }
                    }
                    string uploadTitle;
                    string localCollectRunProfileRaw = null;
                    if (collectionResult != null && collectionResult.CoverageReport != null)
                        localCollectRunProfileRaw = collectionResult.CoverageReport.CollectionModeProfile ?? "";
                    string uploadResult = TryUploadLocalCase(fullPath ?? zipPath, out uploadTitle, localCollectRunProfileRaw);
                    bool caseLoaded = false;
                    bool loadAttempted = !string.IsNullOrEmpty(fullPath) && File.Exists(fullPath);
                    var collectCompleteCfg = new ConfigManager();
                    bool showCompleteMsg = collectCompleteCfg.Get("ShowCollectionCompleteMessage") != "0";
                    SafeInvoke((MethodInvoker)delegate {
                        collectProgressPanel.Visible = false;
                        progressCollect.Style = ProgressBarStyle.Blocks;
                        btnCollect.Enabled = true;
                        btnImport.Enabled = true;
                        if (loadAttempted)
                            caseLoaded = LoadCase(fullPath);
                        string collectionMessage = BuildCollectionCompletionMessage(caseLoaded, loadAttempted, collectionResult);
                        MessageBoxIcon completionIcon = MessageBoxIcon.Information;
                        if (collectionResult != null && (collectionResult.HasErrors || collectionResult.HasCoverageGaps))
                        {
                            completionIcon = MessageBoxIcon.Warning;
                        }
                        else if (loadAttempted && !caseLoaded)
                        {
                            completionIcon = MessageBoxIcon.Warning;
                        }
                        if (showCompleteMsg)
                        {
                            if (!string.IsNullOrEmpty(uploadResult)) ShowTextDialog(uploadTitle, uploadResult);
                            if (!string.IsNullOrEmpty(uploadResult))
                            {
                                collectionMessage += "\n\nUpload: review the separate upload response dialog.";
                                if (!string.IsNullOrEmpty(uploadTitle) && uploadTitle.IndexOf("Error", StringComparison.OrdinalIgnoreCase) >= 0)
                                    completionIcon = MessageBoxIcon.Warning;
                            }
                            MessageBox.Show(collectionMessage, (collectionResult != null && (collectionResult.HasErrors || collectionResult.HasCoverageGaps)) || (loadAttempted && !caseLoaded) || (!string.IsNullOrEmpty(uploadTitle) && uploadTitle.IndexOf("Error", StringComparison.OrdinalIgnoreCase) >= 0) ? "Collection Warning" : "Collection Complete", MessageBoxButtons.OK, completionIcon);
                        }
                        else if (lblCollectStatus != null && !lblCollectStatus.IsDisposed)
                        {
                            lblCollectStatus.Text = collectionResult != null && collectionResult.HasErrors
                                ? "Collection completed with errors."
                                : (collectionResult != null && collectionResult.HasCoverageGaps
                                    ? "Collection completed with coverage gaps."
                                    : (caseLoaded ? "Collection complete. Case loaded." : (loadAttempted ? "Collection complete, but case load failed." : "Collection complete.")));
                            collectProgressPanel.Visible = true;
                            var t = new Timer { Interval = 2000 };
                            t.Tick += (__, ___) => { t.Stop(); t.Dispose(); collectProgressPanel.Visible = false; };
                            t.Start();
                        }
                        if (!showCompleteMsg && !string.IsNullOrEmpty(uploadResult)) ShowTextDialog(uploadTitle, uploadResult);
                    });
                } catch (Exception ex) {
                    SafeInvoke((MethodInvoker)delegate {
                        collectProgressPanel.Visible = false;
                        progressCollect.Style = ProgressBarStyle.Blocks;
                        btnCollect.Enabled = true;
                        btnImport.Enabled = true;
                        MessageBox.Show("Error: " + ex.Message);
                    });
                }
                finally
                {
                    _collectionInProgress = false;
                }
            };
            action.BeginInvoke(null, null);
        }

        private void BtnImport_Click(object sender, EventArgs e)
        {
            OpenFileDialog dlg = new OpenFileDialog();
            dlg.Filter = "ZIP Cases|*.zip";
            dlg.Multiselect = true;
            if (dlg.ShowDialog() == DialogResult.OK)
            {
                foreach(var f in dlg.FileNames) LoadCase(f);
            }
        }

        private void MainForm_DragDrop(object sender, DragEventArgs e)
        {
            if (e == null || e.Data == null || !e.Data.GetDataPresent(DataFormats.FileDrop)) return;
            try
            {
                string[] files = e.Data.GetData(DataFormats.FileDrop) as string[];
                if (files == null) return;
                foreach (string file in files)
                {
                    if (string.IsNullOrEmpty(file) || !file.EndsWith(".zip", StringComparison.OrdinalIgnoreCase)) continue;
                    string normalized;
                    try { normalized = System.IO.Path.GetFullPath(file); } catch { continue; }
                    if (normalized.IndexOf("..", StringComparison.Ordinal) >= 0) { IR_Collect.Utils.Logger.Warning("DragDrop: path contains '..' rejected: " + file); continue; }
                    LoadCase(normalized);
                }
            }
            catch (Exception ex) { Logger.Warning("DragDrop: " + ex.Message); }
        }

        private bool LoadCase(string path)
        {
            try {
                Cursor.Current = Cursors.WaitCursor;
                var c = IR_Collect.Analysis.CaseManager.LoadCase(path);

                TreeNode node = new TreeNode(c.Hostname);
                node.Tag = c;
                treeHosts.Nodes.Add(node);

                UpdateSummary();
                Cursor.Current = Cursors.Default;

                if (c.LoadWarnings != null && c.LoadWarnings.Count > 0)
                {
                    var warningText = new StringBuilder();
                    warningText.AppendLine("Case loaded with warnings:");
                    warningText.AppendLine();
                    foreach (string warning in c.LoadWarnings)
                        warningText.AppendLine("- " + warning);
                    MessageBox.Show(warningText.ToString().TrimEnd(), "Load Warnings", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }

                if (ShouldAutoBuildFactStore(config.Get("FactStoreAutoBuild"), c))
                {
                    c.FactStoreBuilding = true;
                    var worker = new System.ComponentModel.BackgroundWorker();
                    worker.DoWork += (_, __) =>
                    {
                        try
                        {
                            _autoBuildFactStoreSemaphore.Wait();
                            var store = IR_Collect.Analysis.Correlation.FactStore.BuildFromCase(c);
                            __.Result = new object[] { c, store };
                        }
                        catch (Exception ex) { Logger.Warning("Auto Build Fact Store: " + ex.Message); __.Result = null; }
                        finally
                        {
                            try { _autoBuildFactStoreSemaphore.Release(); } catch { }
                        }
                    };
                    worker.RunWorkerCompleted += (_, ev) =>
                    {
                        if (ev.Error != null)
                        {
                            c.FactStoreBuilding = false;
                            Logger.Warning("Auto Build Fact Store: " + ev.Error.Message);
                            MessageBox.Show("Fact Store auto-build failed: " + ev.Error.Message, "Fact Store Warning", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                            return;
                        }
                        var pair = ev.Result as object[];
                        if (pair == null || pair.Length < 2)
                        {
                            c.FactStoreBuilding = false;
                            MessageBox.Show("Fact Store auto-build failed. The case loaded, but Fact Store data was not built.", "Fact Store Warning", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                            return;
                        }
                        var caseData = pair[0] as IR_Collect.Analysis.CaseData;
                        var store = pair[1] as IR_Collect.Analysis.Correlation.FactStore;
                        if (caseData == null || store == null)
                        {
                            c.FactStoreBuilding = false;
                            MessageBox.Show("Fact Store auto-build finished without usable results (internal error). The case is loaded; rebuild Fact Store from the Analysis menu if needed.", "Fact Store Warning", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                            return;
                        }
                        if (!IR_Collect.Analysis.CaseManager.LoadedCases.Any(x => object.ReferenceEquals(x, caseData)))
                        {
                            c.FactStoreBuilding = false;
                            return;
                        }
                        caseData.FactStore = store;
                        caseData.FactStoreBuilding = false;
                        if (config.Get("FactStoreWriteSqlite") == "1" && store.Count > 0 && !string.IsNullOrEmpty(caseData.ExtractPath))
                        {
                            try { IR_Collect.Analysis.Correlation.FactStorePersistence.SaveToSqlite(store, System.IO.Path.Combine(caseData.ExtractPath, ArtifactNames.FactStoreDb)); }
                            catch (Exception ex) { Logger.Warning("FactStore SQLite save: " + ex.Message); }
                        }
                        IR_Collect.Analysis.CaseManager.RefreshFactStoreFreshness(caseData);
                        UpdateSummary();
                    };
                    worker.RunWorkerAsync();
                }
                else if (config.Get("FactStoreAutoBuild") == "1" && c.FactStore != null && c.FactStore.Count > 0)
                {
                    Logger.Info("Auto Build Fact Store skipped: bundled fact_store.db already loaded.");
                }
                return true;
            }
            catch (Exception ex) { MessageBox.Show("Load Failed: " + ex.Message); Cursor.Current = Cursors.Default; }
            return false;
        }

        private void UpdateSummary()
        {
            int cases = treeHosts.Nodes.Count;
            if (cases == 0)
            {
                lblDashSummary.Text = "";
                return;
            }
            int files = 0;
            var loadedCaseProfileSlots = new System.Collections.Generic.List<string>();
            foreach(TreeNode n in treeHosts.Nodes)
            {
                if (n.Tag is IR_Collect.Analysis.CaseData)
                {
                    var c = (IR_Collect.Analysis.CaseData)n.Tag;
                    var list = c.MftEntries;
                    files += (list != null ? list.Count : 0);
                    if (c.CollectionCoverage != null && !string.IsNullOrWhiteSpace(c.CollectionCoverage.CollectionModeProfile))
                        loadedCaseProfileSlots.Add(CollectionModeProfileHelper.Normalize(c.CollectionCoverage.CollectionModeProfile));
                    else
                        loadedCaseProfileSlots.Add(null);
                }
            }
            string loadedCasesProfilesLine = CollectionModeProfileHelper.FormatDashboardLoadedCollectionProfilesLine(loadedCaseProfileSlots);
            string settingsProfile = CollectionModeProfileHelper.GetActive(config);
            if (string.Equals(settingsProfile, CollectionModeProfileHelper.Standard, StringComparison.Ordinal))
                lblDashSummary.Text = string.Format("Total Cases: {0}\nTotal Files Indexed: {1:N0}{2}", cases, files, loadedCasesProfilesLine);
            else
                lblDashSummary.Text = string.Format(
                    "Settings collection profile (for new Local Collect runs): {0}\nTotal Cases: {1}\nTotal Files Indexed: {2:N0}{3}",
                    settingsProfile,
                    cases,
                    files,
                    loadedCasesProfilesLine);
        }

        private bool IsAdmin()
        {
            using (WindowsIdentity id = WindowsIdentity.GetCurrent())
                return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }

        private void TryRunElevated()
        {
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = Application.ExecutablePath;
            psi.UseShellExecute = true;
            psi.Verb = "runas";
            try { Process.Start(psi); Application.Exit(); }
            catch (Exception ex) { Logger.Warning("Restart as admin: " + ex.Message); }
        }
    }
}
