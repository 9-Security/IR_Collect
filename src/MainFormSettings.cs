using System;
using System.Collections.Generic;
using System.Drawing;
using System.Reflection;
using System.Windows.Forms;
using IR_Collect.Utils;

namespace IR_Collect
{
    partial class MainForm
    {
        private void ShowAboutDialog()
        {
            string version = IR_Collect.BuildInfo.Version;
            try
            {
                var asm = Assembly.GetExecutingAssembly();
                var v = asm.GetName().Version;
                if (v != null) version = string.Format("{0}.{1}.{2}", v.Major, v.Minor, v.Build);
            }
            catch { }

            Form dlg = new Form();
            dlg.Text = "About IR Analysis Platform";
            dlg.Size = new Size(480, 340);
            dlg.StartPosition = FormStartPosition.CenterParent;
            dlg.FormBorderStyle = FormBorderStyle.FixedDialog;
            dlg.MaximizeBox = false;
            dlg.MinimizeBox = false;
            dlg.BackColor = Color.FromArgb(30, 30, 30);

            // ── 標題區 ──────────────────────────────────────────────────────────
            var lblProduct = new Label
            {
                Text = "IR Analysis Platform",
                Font = new Font("Segoe UI", 15F, FontStyle.Bold),
                ForeColor = Color.White,
                Left = 20, Top = 20, Width = 430, Height = 30,
                AutoSize = false
            };

            var lblVersion = new Label
            {
                Text = "Version " + version + "  |  Windows DFIR Artifact Collector & Analyzer",
                Font = new Font("Segoe UI", 9F),
                ForeColor = Color.Silver,
                Left = 20, Top = 54, Width = 430, Height = 20,
                AutoSize = false
            };

            var divider = new Panel
            {
                Left = 20, Top = 80, Width = 430, Height = 1,
                BackColor = Color.FromArgb(70, 70, 70)
            };

            // ── 著作權資訊 ───────────────────────────────────────────────────────
            string year = DateTime.Now.Year.ToString();
            var copyright = string.Join(Environment.NewLine, new[]
            {
                "Copyright © " + year + "  nine-security Inc.",
                "All rights reserved.",
                "",
                "本軟體為 nine-security Inc. 之專有軟體，未經授權不得複製、",
                "散布、修改或以任何形式再發行。",
                "",
                "This software is proprietary to nine-security Inc.",
                "Unauthorized copying, distribution, or modification is",
                "strictly prohibited.",
                "",
                "For licensing inquiries, contact: nine-security Inc."
            });

            var lblCopyright = new Label
            {
                Text = copyright,
                Font = new Font("Segoe UI", 8.5F),
                ForeColor = Color.FromArgb(200, 200, 200),
                Left = 20, Top = 90, Width = 430, Height = 170,
                AutoSize = false
            };

            // ── 底部按鈕 ─────────────────────────────────────────────────────────
            var divider2 = new Panel
            {
                Left = 20, Top = 268, Width = 430, Height = 1,
                BackColor = Color.FromArgb(70, 70, 70)
            };

            var btnOk = new Button
            {
                Text = "OK",
                Left = 370, Top = 278, Width = 80, Height = 30,
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(0, 122, 204),
                ForeColor = Color.White,
                Font = new Font("Segoe UI", 9F),
                DialogResult = DialogResult.OK
            };
            btnOk.FlatAppearance.BorderSize = 0;

            dlg.Controls.Add(lblProduct);
            dlg.Controls.Add(lblVersion);
            dlg.Controls.Add(divider);
            dlg.Controls.Add(lblCopyright);
            dlg.Controls.Add(divider2);
            dlg.Controls.Add(btnOk);
            dlg.AcceptButton = btnOk;

            dlg.ShowDialog(this);
        }

        private static string EscapeJson(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            return s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\r", "\\r").Replace("\n", "\\n");
        }

        private void ShowSettingsDialog()
        {
            Form f = new Form();
            f.Text = "Settings";
            f.Size = new System.Drawing.Size(520, 1080);
            f.StartPosition = FormStartPosition.CenterParent;
            f.FormBorderStyle = FormBorderStyle.FixedDialog;
            f.MaximizeBox = false;
            f.MinimizeBox = false;
            f.AutoScroll = true;

            int y = 12;
            Label lProf = new Label()
            {
                Text = "Collection mode profile (live-response posture; ForensicStrict blocks outbound ZIP upload and AI Analyze):",
                Left = 20,
                Top = y,
                Width = 460,
                Height = 36
            };
            y += 40;
            ComboBox cbProfile = new ComboBox() { DropDownStyle = ComboBoxStyle.DropDownList, Left = 20, Top = y, Width = 260 };
            cbProfile.Items.AddRange(new object[] { CollectionModeProfileHelper.Standard, CollectionModeProfileHelper.TriageFast, CollectionModeProfileHelper.ForensicStrict });
            string profCur = CollectionModeProfileHelper.Normalize(config.Get("CollectionModeProfile"));
            if (string.Equals(profCur, CollectionModeProfileHelper.TriageFast, StringComparison.Ordinal)) cbProfile.SelectedIndex = 1;
            else if (string.Equals(profCur, CollectionModeProfileHelper.ForensicStrict, StringComparison.Ordinal)) cbProfile.SelectedIndex = 2;
            else cbProfile.SelectedIndex = 0;
            y += 28;
            Label lProfNote = new Label()
            {
                Text = "ForensicStrict adds stronger warnings and blocks outbound case ZIP upload and AI Analyze. It is not zero-footprint and not a complete low-impact forensic suite by itself.",
                Left = 20,
                Top = y,
                Width = 460,
                Height = 48
            };
            y += 52;

            Label l1 = new Label() { Text = "VirusTotal API Key (for future API use; Query VT opens browser):", Left = 20, Top = y, Width = 460 }; y += 22;
            TextBox t1 = new TextBox() { Left = 20, Top = y, Width = 460, Text = config.Get("VirusTotalApiKey"), UseSystemPasswordChar = true }; y += 28;

            Label l2 = new Label() { Text = "AI API Endpoint (URL):", Left = 20, Top = y, Width = 460 }; y += 22;
            TextBox t2Endpoint = new TextBox() { Left = 20, Top = y, Width = 460, Text = config.Get("AiApiEndpoint") }; y += 28;
            Label l2b = new Label() { Text = "AI API Key:", Left = 20, Top = y, Width = 460 }; y += 22;
            TextBox t2 = new TextBox() { Left = 20, Top = y, Width = 460, Text = config.Get("AiApiKey"), UseSystemPasswordChar = true }; y += 28;

            Label l2c = new Label()
            {
                Text = "AI endpoint allowlist (https/http URL prefixes; one per line or use | . Empty list blocks all AI POST):",
                Left = 20, Top = y, Width = 460, Height = 32
            };
            y += 34;
            TextBox tAiAllow = new TextBox()
            {
                Left = 20, Top = y, Width = 460, Height = 52,
                Multiline = true, ScrollBars = ScrollBars.Vertical,
                Text = AllowlistStorageToDisplay(config.Get("AiEndpointAllowlist"))
            };
            y += 56;
            Label l2d = new Label() { Text = "AI export redaction profile (AI Analyze outbound JSON only; not file export or ZIP upload):", Left = 20, Top = y, Width = 460, Height = 30 }; y += 32;
            ComboBox cbAiRedact = new ComboBox() { DropDownStyle = ComboBoxStyle.DropDownList, Left = 20, Top = y, Width = 200 };
            cbAiRedact.Items.AddRange(new object[] { "None", "Basic", "Strict" });
            string redactCur = IR_Collect.Analysis.SummaryPayloadAiRedactor.NormalizeProfile(config.Get("AiExportRedactionProfile"));
            if (redactCur == "None") cbAiRedact.SelectedIndex = 0;
            else if (redactCur == "Strict") cbAiRedact.SelectedIndex = 2;
            else cbAiRedact.SelectedIndex = 1;
            y += 28;

            Label l3a = new Label() { Text = "Upload Endpoint (URL, after Local Collect):", Left = 20, Top = y, Width = 460 }; y += 22;
            TextBox tUploadEndpoint = new TextBox() { Left = 20, Top = y, Width = 460, Text = config.Get("UploadEndpoint") }; y += 28;
            Label l3b = new Label() { Text = "Upload API Key:", Left = 20, Top = y, Width = 460 }; y += 22;
            TextBox tUploadKey = new TextBox() { Left = 20, Top = y, Width = 460, Text = config.Get("UploadApiKey"), UseSystemPasswordChar = true }; y += 28;

            Label l3c = new Label()
            {
                Text = "Upload endpoint allowlist (same rules as AI; empty list blocks all ZIP upload POST):",
                Left = 20, Top = y, Width = 460, Height = 30
            };
            y += 32;
            TextBox tUploadAllow = new TextBox()
            {
                Left = 20, Top = y, Width = 460, Height = 52,
                Multiline = true, ScrollBars = ScrollBars.Vertical,
                Text = AllowlistStorageToDisplay(config.Get("UploadEndpointAllowlist"))
            };
            y += 56;

            Label l4 = new Label() { Text = "MFT max entries (1000–500000):", Left = 20, Top = y, Width = 460 }; y += 22;
            TextBox t3 = new TextBox() { Left = 20, Top = y, Width = 120, Text = config.Get("MftMaxEntries") }; y += 28;
            Label l5 = new Label() { Text = "Post-collect delay (0–30 sec):", Left = 20, Top = y, Width = 460 }; y += 22;
            TextBox t4 = new TextBox() { Left = 20, Top = y, Width = 120, Text = config.Get("PostCollectDelaySeconds") }; y += 28;
            Label l6 = new Label() { Text = "Event log days (0 = default 7-day filtered CSV + full .evtx; >0 = custom filtered CSV window):", Left = 20, Top = y, Width = 460 }; y += 22;
            TextBox tEventLogDays = new TextBox() { Left = 20, Top = y, Width = 120, Text = config.Get("EventLogDays") }; y += 28;
            Label l7 = new Label() { Text = "Event log max events per log (1–100000):", Left = 20, Top = y, Width = 460 }; y += 22;
            TextBox tEventLogMax = new TextBox() { Left = 20, Top = y, Width = 120, Text = config.Get("EventLogMaxEvents") }; y += 28;

            CheckBox chkDeleteOutput = new CheckBox() { Text = "Delete output directory after creating ZIP", Left = 20, Top = y, Width = 460, Checked = config.Get("DeleteOutputDirAfterZip") != "0" }; y += 26;
            CheckBox chkSqlite = new CheckBox() { Text = "Write Fact Store to SQLite when building (Phase B3)", Left = 20, Top = y, Width = 460, Checked = config.Get("FactStoreWriteSqlite") == "1" }; y += 24;
            CheckBox chkAutoBuild = new CheckBox() { Text = "Auto Build Fact Store when case is loaded", Left = 20, Top = y, Width = 460, Checked = config.Get("FactStoreAutoBuild") == "1" }; y += 24;
            CheckBox chkShowComplete = new CheckBox() { Text = "Show \"Collection Complete\" message when Local Collect finishes", Left = 20, Top = y, Width = 460, Checked = config.Get("ShowCollectionCompleteMessage") != "0" }; y += 28;

            Label lMemHdr = new Label() { Text = "Memory acquisition (external tool only; collection orchestration, no in-app analysis):", Left = 20, Top = y, Width = 460, Height = 32 }; y += 34;
            CheckBox chkMemEn = new CheckBox() { Text = "Enable memory acquisition during Local Collect", Left = 20, Top = y, Width = 460, Checked = config.Get("MemoryAcquireEnabled") == "1" }; y += 26;
            Label lMemTool = new Label() { Text = "Tool path (.exe):", Left = 20, Top = y, Width = 460 }; y += 22;
            TextBox tMemTool = new TextBox() { Left = 20, Top = y, Width = 460, Text = config.Get("MemoryAcquireToolPath") }; y += 28;
            Label lMemPreset = new Label() { Text = "Arguments preset (Custom = full template below; Quoted/WinPMEM = core from preset, then append extras from the field below):", Left = 20, Top = y, Width = 460, Height = 36 }; y += 38;
            ComboBox cbMemPreset = new ComboBox() { DropDownStyle = ComboBoxStyle.DropDownList, Left = 20, Top = y, Width = 460 };
            cbMemPreset.Items.AddRange(new object[]
            {
                "Custom (use argument template below)",
                "Quoted output path only (\"{OutputPath}\")",
                "WinPMEM-style (-o \"{OutputPath}\")",
                "WinPMEM raw (--format raw -o \"{OutputPath}\")"
            });
            string memPreset = MemoryHandoffHelper.NormalizeAcquirePreset(config.Get("MemoryAcquireArgsPreset"));
            if (memPreset == MemoryHandoffHelper.AcquirePresetQuotedOutput) cbMemPreset.SelectedIndex = 1;
            else if (memPreset == MemoryHandoffHelper.AcquirePresetWinPmemO) cbMemPreset.SelectedIndex = 2;
            else if (memPreset == MemoryHandoffHelper.AcquirePresetWinPmemRaw) cbMemPreset.SelectedIndex = 3;
            else cbMemPreset.SelectedIndex = 0;
            y += 28;
            Label lMemArgs = new Label() { Text = "Argument template: Custom = entire command-line template; otherwise = extra flags appended after preset core (placeholders {OutputPath}, {OutputDir} still valid):", Left = 20, Top = y, Width = 460, Height = 36 }; y += 38;
            TextBox tMemArgs = new TextBox() { Left = 20, Top = y, Width = 460, Text = config.Get("MemoryAcquireToolArgs") }; y += 28;
            Label lMemOut = new Label() { Text = "Output file name under Memory\\\\ (e.g. memory.raw, memory.dmp):", Left = 20, Top = y, Width = 460 }; y += 22;
            TextBox tMemOut = new TextBox() { Left = 20, Top = y, Width = 200, Text = config.Get("MemoryAcquireOutputName") }; y += 28;
            Label lMemTo = new Label() { Text = "Timeout (seconds, 1–86400):", Left = 20, Top = y, Width = 460 }; y += 22;
            TextBox tMemTo = new TextBox() { Left = 20, Top = y, Width = 120, Text = config.Get("MemoryAcquireTimeoutSec") }; y += 28;
            Label lMemVal = new Label() { Text = "Output validation: Exists only = require the dump path on disk; Minimum size = require the dump path and a minimum byte threshold:", Left = 20, Top = y, Width = 460, Height = 36 }; y += 38;
            ComboBox cbMemValidation = new ComboBox() { DropDownStyle = ComboBoxStyle.DropDownList, Left = 20, Top = y, Width = 220 };
            cbMemValidation.Items.AddRange(new object[] { "Exists only", "Minimum size + exists" });
            string memValidationMode = MemoryHandoffHelper.NormalizeAcquireValidationMode(config.Get("MemoryAcquireValidationMode"));
            cbMemValidation.SelectedIndex = memValidationMode == MemoryHandoffHelper.AcquireValidationMinSize ? 1 : 0;
            Label lMemMin = new Label() { Text = "Minimum bytes:", Left = 258, Top = y + 4, Width = 150 };
            TextBox tMemMin = new TextBox() { Left = 258, Top = y + 22, Width = 140, Text = config.Get("MemoryAcquireMinFileBytes") }; y += 50;
            CheckBox chkMemReqAdm = new CheckBox() { Text = "Document: tool expects Administrator (recorded in memory_acquisition.json only)", Left = 20, Top = y, Width = 460, Checked = config.Get("MemoryAcquireRequiresAdmin") == "1" }; y += 26;
            CheckBox chkMemSkip = new CheckBox() { Text = "Skip acquisition when not elevated (recommended unless you always run elevated)", Left = 20, Top = y, Width = 460, Checked = config.Get("MemoryAcquireSkipIfNotElevated") != "0" }; y += 32;

            Label lMemAnaHdr = new Label() { Text = "Memory analysis handoff (external analyzer against collected dump; no in-app parsing/verdicts):", Left = 20, Top = y, Width = 460, Height = 32 }; y += 34;
            CheckBox chkMemAnaEn = new CheckBox() { Text = "Enable external memory analysis handoff after memory acquisition", Left = 20, Top = y, Width = 460, Checked = config.Get("MemoryAnalyzeEnabled") == "1" }; y += 26;
            Label lMemAnaTool = new Label() { Text = "Analyzer tool path (.exe):", Left = 20, Top = y, Width = 460 }; y += 22;
            TextBox tMemAnaTool = new TextBox() { Left = 20, Top = y, Width = 460, Text = config.Get("MemoryAnalyzeToolPath") }; y += 28;
            Label lMemAnaPreset = new Label() { Text = "Arguments preset (Custom = use template below; dual-quoted = input path and analysis output dir):", Left = 20, Top = y, Width = 460, Height = 30 }; y += 32;
            ComboBox cbMemAnaPreset = new ComboBox() { DropDownStyle = ComboBoxStyle.DropDownList, Left = 20, Top = y, Width = 460 };
            cbMemAnaPreset.Items.AddRange(new object[]
            {
                "Dual quoted: \"{InputPath}\" \"{OutputDir}\"",
                "Custom (use argument template below)",
                "Input/output flags: -i \"{InputPath}\" -o \"{OutputDir}\"",
                "Volatility3-style: -f \"{InputPath}\" --output-dir \"{OutputDir}\""
            });
            string anaPreset = MemoryHandoffHelper.NormalizeAnalyzePreset(config.Get("MemoryAnalyzeArgsPreset"));
            if (anaPreset == MemoryHandoffHelper.AnalyzePresetCustom) cbMemAnaPreset.SelectedIndex = 1;
            else if (anaPreset == MemoryHandoffHelper.AnalyzePresetInputOutputFlags) cbMemAnaPreset.SelectedIndex = 2;
            else if (anaPreset == MemoryHandoffHelper.AnalyzePresetVolatility3OutputDir) cbMemAnaPreset.SelectedIndex = 3;
            else cbMemAnaPreset.SelectedIndex = 0;
            y += 28;
            Label lMemAnaArgs = new Label() { Text = "Argument template (Custom preset; placeholders {InputPath}, {InputDir}, {OutputDir}, {CaseDir}):", Left = 20, Top = y, Width = 460, Height = 34 }; y += 36;
            TextBox tMemAnaArgs = new TextBox() { Left = 20, Top = y, Width = 460, Text = config.Get("MemoryAnalyzeToolArgs") }; y += 28;
            Label lMemAnaOut = new Label() { Text = "Output directory name under case root (e.g. MemoryAnalysis):", Left = 20, Top = y, Width = 460 }; y += 22;
            TextBox tMemAnaOut = new TextBox() { Left = 20, Top = y, Width = 200, Text = config.Get("MemoryAnalyzeOutputDirName") }; y += 28;
            Label lMemAnaTo = new Label() { Text = "Timeout (seconds, 1-86400):", Left = 20, Top = y, Width = 460 }; y += 22;
            TextBox tMemAnaTo = new TextBox() { Left = 20, Top = y, Width = 120, Text = config.Get("MemoryAnalyzeTimeoutSec") }; y += 28;
            Label lMemAnaVal = new Label() { Text = "Output validation: Any output files = require files under the analysis directory; Required file patterns = every listed glob must match (one per line or use |):", Left = 20, Top = y, Width = 460, Height = 36 }; y += 38;
            ComboBox cbMemAnaValidation = new ComboBox() { DropDownStyle = ComboBoxStyle.DropDownList, Left = 20, Top = y, Width = 220 };
            cbMemAnaValidation.Items.AddRange(new object[] { "Any output files", "Required file patterns" });
            string memAnaValidationMode = MemoryHandoffHelper.NormalizeAnalyzeValidationMode(config.Get("MemoryAnalyzeValidationMode"));
            cbMemAnaValidation.SelectedIndex = memAnaValidationMode == MemoryHandoffHelper.AnalyzeValidationRequiredPatterns ? 1 : 0; y += 28;
            TextBox tMemAnaPatterns = new TextBox() { Left = 20, Top = y, Width = 460, Height = 56, Multiline = true, ScrollBars = ScrollBars.Vertical, Text = string.Join(Environment.NewLine, MemoryHandoffHelper.ParsePatternList(config.Get("MemoryAnalyzeRequiredPatterns")).ToArray()) }; y += 60;
            CheckBox chkGuidedHunt = new CheckBox() { Text = "Enable Guided Hunt Pack overlay (ATT&CK-mapped explainable hunt leads over facts)", Left = 20, Top = y, Width = 460, Checked = config.Get("GuidedHuntEnabled") != "0" }; y += 32;

            Button btnSave = new Button() { Text = "Save", Left = 390, Top = y, Width = 100, Height = 32 };
            btnSave.DialogResult = DialogResult.OK;
            btnSave.Click += (s, e) => {
                config.Set("CollectionModeProfile", cbProfile.SelectedItem != null ? cbProfile.SelectedItem.ToString() : CollectionModeProfileHelper.Standard);
                config.Set("VirusTotalApiKey", t1.Text.Trim());
                config.Set("AiApiEndpoint", t2Endpoint.Text.Trim());
                config.Set("AiApiKey", t2.Text.Trim());
                config.Set("AiEndpointAllowlist", AllowlistDisplayToStorage(tAiAllow.Text));
                config.Set("AiExportRedactionProfile", cbAiRedact.SelectedItem != null ? cbAiRedact.SelectedItem.ToString() : "Basic");
                config.Set("UploadEndpoint", tUploadEndpoint.Text.Trim());
                config.Set("UploadApiKey", tUploadKey.Text.Trim());
                config.Set("UploadEndpointAllowlist", AllowlistDisplayToStorage(tUploadAllow.Text));
                int mftMax = 100000;
                int n;
                if (int.TryParse(t3.Text.Trim(), out n) && n > 0)
                    mftMax = Math.Min(Math.Max(n, 1000), 500000);
                config.Set("MftMaxEntries", mftMax.ToString());
                int delaySec = 3;
                if (int.TryParse(t4.Text.Trim(), out n) && n >= 0)
                    delaySec = Math.Min(n, 30);
                config.Set("PostCollectDelaySeconds", delaySec.ToString());
                int eventLogDays = 0;
                if (int.TryParse(tEventLogDays.Text.Trim(), out n) && n >= 0)
                    eventLogDays = n;
                config.Set("EventLogDays", eventLogDays.ToString());
                int eventLogMax = 10000;
                if (int.TryParse(tEventLogMax.Text.Trim(), out n) && n > 0)
                    eventLogMax = Math.Min(n, 100000);
                config.Set("EventLogMaxEvents", eventLogMax.ToString());
                config.Set("DeleteOutputDirAfterZip", chkDeleteOutput.Checked ? "1" : "0");
                config.Set("FactStoreWriteSqlite", chkSqlite.Checked ? "1" : "0");
                config.Set("FactStoreAutoBuild", chkAutoBuild.Checked ? "1" : "0");
                config.Set("ShowCollectionCompleteMessage", chkShowComplete.Checked ? "1" : "0");
                config.Set("MemoryAcquireEnabled", chkMemEn.Checked ? "1" : "0");
                config.Set("MemoryAcquireToolPath", tMemTool.Text.Trim());
                string acquirePreset = MemoryHandoffHelper.AcquirePresetCustom;
                if (cbMemPreset.SelectedIndex == 1) acquirePreset = MemoryHandoffHelper.AcquirePresetQuotedOutput;
                else if (cbMemPreset.SelectedIndex == 2) acquirePreset = MemoryHandoffHelper.AcquirePresetWinPmemO;
                else if (cbMemPreset.SelectedIndex == 3) acquirePreset = MemoryHandoffHelper.AcquirePresetWinPmemRaw;
                config.Set("MemoryAcquireArgsPreset", acquirePreset);
                config.Set("MemoryAcquireToolArgs", tMemArgs.Text.Trim());
                string outName = (tMemOut.Text ?? "").Trim();
                if (string.IsNullOrEmpty(outName)) outName = "memory.raw";
                config.Set("MemoryAcquireOutputName", outName);
                int memTimeout = 3600;
                if (int.TryParse(tMemTo.Text.Trim(), out n) && n > 0)
                    memTimeout = Math.Min(n, 86400);
                config.Set("MemoryAcquireTimeoutSec", memTimeout.ToString());
                config.Set("MemoryAcquireRequiresAdmin", chkMemReqAdm.Checked ? "1" : "0");
                config.Set("MemoryAcquireSkipIfNotElevated", chkMemSkip.Checked ? "1" : "0");
                config.Set("MemoryAcquireValidationMode", cbMemValidation.SelectedIndex == 1 ? MemoryHandoffHelper.AcquireValidationMinSize : MemoryHandoffHelper.AcquireValidationExistsOnly);
                long minBytes = 1048576L;
                long longValue;
                if (long.TryParse(tMemMin.Text.Trim(), out longValue) && longValue > 0)
                    minBytes = Math.Min(longValue, 1099511627776L);
                config.Set("MemoryAcquireMinFileBytes", minBytes.ToString());
                config.Set("MemoryAnalyzeEnabled", chkMemAnaEn.Checked ? "1" : "0");
                config.Set("MemoryAnalyzeToolPath", tMemAnaTool.Text.Trim());
                string analyzePreset = MemoryHandoffHelper.AnalyzePresetDualQuoted;
                if (cbMemAnaPreset.SelectedIndex == 1) analyzePreset = MemoryHandoffHelper.AnalyzePresetCustom;
                else if (cbMemAnaPreset.SelectedIndex == 2) analyzePreset = MemoryHandoffHelper.AnalyzePresetInputOutputFlags;
                else if (cbMemAnaPreset.SelectedIndex == 3) analyzePreset = MemoryHandoffHelper.AnalyzePresetVolatility3OutputDir;
                config.Set("MemoryAnalyzeArgsPreset", analyzePreset);
                config.Set("MemoryAnalyzeToolArgs", tMemAnaArgs.Text.Trim());
                string analysisOut = (tMemAnaOut.Text ?? "").Trim();
                if (string.IsNullOrEmpty(analysisOut)) analysisOut = ArtifactNames.MemoryAnalysisFolder;
                config.Set("MemoryAnalyzeOutputDirName", analysisOut);
                int memAnalysisTimeout = 3600;
                if (int.TryParse(tMemAnaTo.Text.Trim(), out n) && n > 0)
                    memAnalysisTimeout = Math.Min(n, 86400);
                config.Set("MemoryAnalyzeTimeoutSec", memAnalysisTimeout.ToString());
                config.Set("MemoryAnalyzeValidationMode", cbMemAnaValidation.SelectedIndex == 1 ? MemoryHandoffHelper.AnalyzeValidationRequiredPatterns : MemoryHandoffHelper.AnalyzeValidationDirectoryHasFiles);
                config.Set("MemoryAnalyzeRequiredPatterns", string.Join("|", MemoryHandoffHelper.ParsePatternList(tMemAnaPatterns.Text).ToArray()));
                config.Set("GuidedHuntEnabled", chkGuidedHunt.Checked ? "1" : "0");
                config.Save();
                f.Close();
            };

            f.Controls.Add(lProf); f.Controls.Add(cbProfile); f.Controls.Add(lProfNote);
            f.Controls.Add(l1); f.Controls.Add(t1);
            f.Controls.Add(l2); f.Controls.Add(t2Endpoint); f.Controls.Add(l2b); f.Controls.Add(t2);
            f.Controls.Add(l2c); f.Controls.Add(tAiAllow); f.Controls.Add(l2d); f.Controls.Add(cbAiRedact);
            f.Controls.Add(l3a); f.Controls.Add(tUploadEndpoint); f.Controls.Add(l3b); f.Controls.Add(tUploadKey);
            f.Controls.Add(l3c); f.Controls.Add(tUploadAllow);
            f.Controls.Add(l4); f.Controls.Add(t3);
            f.Controls.Add(l5); f.Controls.Add(t4);
            f.Controls.Add(l6); f.Controls.Add(tEventLogDays);
            f.Controls.Add(l7); f.Controls.Add(tEventLogMax);
            f.Controls.Add(chkDeleteOutput);
            f.Controls.Add(chkSqlite);
            f.Controls.Add(chkAutoBuild);
            f.Controls.Add(chkShowComplete);
            f.Controls.Add(lMemHdr);
            f.Controls.Add(chkMemEn);
            f.Controls.Add(lMemTool);
            f.Controls.Add(tMemTool);
            f.Controls.Add(lMemPreset);
            f.Controls.Add(cbMemPreset);
            f.Controls.Add(lMemArgs);
            f.Controls.Add(tMemArgs);
            f.Controls.Add(lMemOut);
            f.Controls.Add(tMemOut);
            f.Controls.Add(lMemTo);
            f.Controls.Add(tMemTo);
            f.Controls.Add(lMemVal);
            f.Controls.Add(cbMemValidation);
            f.Controls.Add(lMemMin);
            f.Controls.Add(tMemMin);
            f.Controls.Add(chkMemReqAdm);
            f.Controls.Add(chkMemSkip);
            f.Controls.Add(lMemAnaHdr);
            f.Controls.Add(chkMemAnaEn);
            f.Controls.Add(lMemAnaTool);
            f.Controls.Add(tMemAnaTool);
            f.Controls.Add(lMemAnaPreset);
            f.Controls.Add(cbMemAnaPreset);
            f.Controls.Add(lMemAnaArgs);
            f.Controls.Add(tMemAnaArgs);
            f.Controls.Add(lMemAnaOut);
            f.Controls.Add(tMemAnaOut);
            f.Controls.Add(lMemAnaTo);
            f.Controls.Add(tMemAnaTo);
            f.Controls.Add(lMemAnaVal);
            f.Controls.Add(cbMemAnaValidation);
            f.Controls.Add(tMemAnaPatterns);
            f.Controls.Add(chkGuidedHunt);
            f.Controls.Add(btnSave);
            f.AcceptButton = btnSave;

            f.ShowDialog(this);
        }

        private static string AllowlistStorageToDisplay(string stored)
        {
            if (string.IsNullOrEmpty(stored)) return "";
            List<string> entries = EndpointGovernance.ParseAllowlistEntries(stored);
            if (entries == null || entries.Count == 0) return "";
            return string.Join(Environment.NewLine, entries.ToArray());
        }

        private static string AllowlistDisplayToStorage(string text)
        {
            if (string.IsNullOrEmpty(text)) return "";
            var parts = new List<string>();
            foreach (string rawLine in text.Replace("\r\n", "\n").Split('\n'))
            {
                string line = (rawLine ?? "").Trim();
                if (string.IsNullOrEmpty(line)) continue;
                foreach (string chunk in line.Split(new char[] { '|' }, StringSplitOptions.None))
                {
                    string t = (chunk ?? "").Trim();
                    if (!string.IsNullOrEmpty(t)) parts.Add(t);
                }
            }
            return string.Join("|", parts.ToArray());
        }
    }
}
