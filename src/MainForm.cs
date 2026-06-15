using System;
using System.ComponentModel;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;
using System.IO;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Principal;
using System.Linq;
using System.Xml.Linq;
using System.Diagnostics.Eventing.Reader;
using System.Text;
using System.Net;
using IR_Collect.Utils;

namespace IR_Collect
{
    public partial class MainForm : Form
    {
        private int _backgroundLoadWorkerCount;

        // UI Components
        private Panel headerPanel;
        private Button btnCollect;
        private Button btnImport;
        private Label lblTitle;
        
        private SplitContainer mainSplit;
        private TreeView treeHosts;
        private ContextMenuStrip ctxHostMenu; // Host Context Menu
        
        // Dynamic Right Panel
        private TabControl hostTabs;
        private Panel dashboardPanel; 
        private Panel rightContentPanel; // Safe reference to right container 
        private Label lblDashSummary;
        private Button btnCorrelation;
        private ContextMenuStrip menuCorrelation;
        private ToolStripMenuItem menuSharedEntityPivotBack;
        private Button btnExportFullLogJson;
        private ComboBox comboEntityType;
        private TextBox txtEntityValue;
        private Button btnSearchEntity;
        private ComboBox comboCorrelationSource;
        private ComboBox comboCorrelationConfidence;
        private TextBox txtCorrelationHostFilter;
        private ComboBox comboCorrelationWindow;
        private ComboBox comboWorkspaceHostScope;
        private DateTimePicker dtCorrelationFrom;
        private DateTimePicker dtCorrelationTo;
        private Button btnGraphExpandFromEdge;
        private Button btnGraphBack;
        private Button btnGraphForward;
        private Button btnGraphResetSeed;
        private Button btnGraphPin;
        private Button btnGraphOpenFacts;
        private Button btnGraphOpenTimeline;
        private Label lblGraphWorkspaceTrail;
        private Label lblGraphWorkspacePinned;
        private ListView listCorrelation;

        // Shared Context Menu for Grids
        private ContextMenuStrip ctxGridMenu;

        // Local Collect progress (visible while collection runs)
        private Panel collectProgressPanel;
        private ProgressBar progressCollect;
        private Label lblCollectStatus;
        
        // Config
        private ConfigManager config;
        private ToolTip toolTipMain;

        // Fonts
        private Font uiFont = new Font("Segoe UI", 11F, FontStyle.Regular); // Increased Font
        private Font codeFont = new Font("Consolas", 10.5F);
        private Font navTabFont = new Font("Segoe UI", 10F, FontStyle.Regular);
        private Font navTabFontBold = new Font("Segoe UI", 10F, FontStyle.Bold);

        // Drag State
        private Point dragStartPoint = Point.Empty;
        private Button dragSourceBtn = null;

        private sealed class EventLogTabState
        {
            public string Path;
            public Guid LoadToken;
            public bool IsLoading;
            public bool IsLoaded;
        }

        private sealed class DeferredTabState
        {
            public Func<TabPage> Loader;
            public Func<object> DataLoader;
            public Func<object, TabPage> TabBuilder;
            public bool IsLoading;
            public bool IsLoaded;
        }

        private sealed class CsvTabData
        {
            public List<string> Headers;
            public List<string[]> Rows;
            public bool IsUsn;
        }

        public MainForm()
        {
            InitializeComponent();
        }

        private void InitializeComponent()
        {
            this.Text = "IR Analysis Platform";
            this.Size = new Size(1300, 850);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.Font = uiFont; // Apply base font
            
            this.config = new ConfigManager();

            this.FormClosing += MainForm_FormClosing;

            // --- Menu Strip ---
            MenuStrip menuStrip = new MenuStrip();
            menuStrip.Dock = DockStyle.Top;
            menuStrip.Font = new Font("Segoe UI", 9F);
            menuStrip.BackColor = Color.FromArgb(245, 245, 245);

            // File
            var menuFile = new ToolStripMenuItem("File");
            var itemOpen = new ToolStripMenuItem("Open Case...");
            itemOpen.ShortcutKeys = Keys.Control | Keys.O;
            itemOpen.ShortcutKeyDisplayString = "Ctrl+O";
            itemOpen.Click += (s, e) => BtnImport_Click(s, e);
            menuFile.DropDownItems.Add(itemOpen);
            menuFile.DropDownItems.Add("-");
            menuFile.DropDownItems.Add("Clear all hosts", null, (s, e) => RunClearAllHosts());
            menuFile.DropDownItems.Add("-");
            menuFile.DropDownItems.Add("Exit", null, (s, e) => Close());
            menuStrip.Items.Add(menuFile);

            // Advanced
            var menuAdv = new ToolStripMenuItem("Advanced");
            menuAdv.DropDownItems.Add("Settings...", null, (s,e) => ShowSettingsDialog());
            menuAdv.DropDownItems.Add("-");
            menuAdv.DropDownItems.Add("Rebuild Selected Host Event Logs", null, (s, e) => RunRebuildSelectedEventLogs());
            menuAdv.DropDownItems.Add("Rebuild Selected Host Fact Store", null, (s, e) => RunRebuildSelectedFactStore());
            menuAdv.DropDownItems.Add("-");
            menuAdv.DropDownItems.Add("Import Settings...", null, (s,e) => {
                OpenFileDialog ofd = new OpenFileDialog(); if(ofd.ShowDialog()==DialogResult.OK) { config.Import(ofd.FileName); MessageBox.Show("Settings Imported"); }
            });
            menuAdv.DropDownItems.Add("Export Settings...", null, (s,e) => {
                SaveFileDialog sfd = new SaveFileDialog(); sfd.FileName = "config.ini"; if(sfd.ShowDialog()==DialogResult.OK) { if (config.Export(sfd.FileName)) MessageBox.Show("Settings Exported"); else MessageBox.Show("Export refused: cannot save to system directory (e.g. Windows, Program Files). Choose a user folder or desktop.", "Export Settings", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
            });
            menuStrip.Items.Add(menuAdv);

            // Help
            var menuHelp = new ToolStripMenuItem("Help");
            menuHelp.DropDownItems.Add("About", null, (s, e) => ShowAboutDialog());
            menuStrip.Items.Add(menuHelp);

            // --- Context Menus ---
            

            // 1. Grid Context Menu (SHA256 Actions)
            this.ctxGridMenu = new ContextMenuStrip();
            var itemCopy = this.ctxGridMenu.Items.Add("Copy Value");
            itemCopy.Click += (s, e) => {
                DataGridViewCell c = ctxGridMenu.Tag as DataGridViewCell;
                if (c != null && c.Value != null) 
                    Clipboard.SetText(c.Value.ToString());
            };
            var itemVT = this.ctxGridMenu.Items.Add("Query VirusTotal");
            itemVT.Click += (s, e) => {
                 DataGridViewCell c = ctxGridMenu.Tag as DataGridViewCell;
                 if (c != null && c.Value != null) {
                     string hash = c.Value.ToString().Trim();
                     if (!IsValidVirusTotalHash(hash))
                     {
                         MessageBox.Show("Hash must be 32 (MD5) or 64 (SHA256) hexadecimal characters.", "VirusTotal", MessageBoxButtons.OK, MessageBoxIcon.Information);
                         return;
                     }
                     string url = "https://www.virustotal.com/gui/file/" + hash;
                     try { Process.Start(url); } catch (Exception ex) { Logger.Warning("VT open: " + ex.Message); }
                 }
            };
            
            // 2. Host Context Menu
            this.ctxHostMenu = new ContextMenuStrip();
            this.ctxHostMenu.Items.Add("Summary", null, (s,e) => {
                if (treeHosts.SelectedNode != null && treeHosts.SelectedNode.Tag is IR_Collect.Analysis.CaseData) {
                    IR_Collect.Analysis.CaseData c = (IR_Collect.Analysis.CaseData)treeHosts.SelectedNode.Tag;
                    int mftCount = (c.MftEntries != null) ? c.MftEntries.Count : 0;
                    MessageBox.Show(string.Format("Host: {0}\nCaseID: {1}\nMFT Records: {2:N0}", c.Hostname, c.CaseID, mftCount), "Host Summary");
                }
            });
            this.ctxHostMenu.Items.Add("-");
            this.ctxHostMenu.Items.Add("Rebuild Event Logs", null, (s, e) => RunRebuildSelectedEventLogs());
            this.ctxHostMenu.Items.Add("Rebuild Fact Store", null, (s, e) => RunRebuildSelectedFactStore());
            this.ctxHostMenu.Items.Add("-");
            this.ctxHostMenu.Items.Add("Clear Host Data", null, (s,e) => {
                if (treeHosts.SelectedNode != null) {
                   if (_collectionInProgress)
                   {
                       MessageBox.Show("Local collection is still running. Please wait.", "Clear Host Data", MessageBoxButtons.OK, MessageBoxIcon.Information);
                       return;
                   }
                   if (HasBackgroundViewLoadsInProgress())
                   {
                       MessageBox.Show("One or more background views are still loading. Please wait.", "Clear Host Data", MessageBoxButtons.OK, MessageBoxIcon.Information);
                       return;
                   }
                   var c = treeHosts.SelectedNode.Tag as IR_Collect.Analysis.CaseData;
                   if (c != null && c.FactStoreBuilding)
                   {
                       MessageBox.Show("This host is still building Fact Store. Please wait.", "Clear Host Data", MessageBoxButtons.OK, MessageBoxIcon.Information);
                       return;
                   }
                   if (c != null && !IR_Collect.Analysis.CaseManager.RemoveCase(c))
                   {
                       MessageBox.Show("Could not clear this host because its extracted files are still in use. Please close related views or retry.", "Clear Host Data", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                       return;
                   }
                   TreeNode nodeToRemove = treeHosts.SelectedNode;
                   treeHosts.Nodes.Remove(nodeToRemove);
                   UpdateSummary();
                   if (listCorrelation != null) listCorrelation.Items.Clear();
                   if (treeHosts.Nodes.Count == 0)
                   {
                       hostTabs.TabPages.Clear();
                       treeHosts.SelectedNode = null;
                       if (dashboardPanel != null) dashboardPanel.Visible = true;
                       if (rightContentPanel != null) rightContentPanel.Visible = false;
                   }
                   else if (treeHosts.SelectedNode == null)
                   {
                       treeHosts.SelectedNode = treeHosts.Nodes[0];
                   }
                   else if (treeHosts.SelectedNode.Tag is IR_Collect.Analysis.CaseData)
                   {
                       BuildHostTabs((IR_Collect.Analysis.CaseData)treeHosts.SelectedNode.Tag);
                   }
                }
            });

            // --- Header Panel ---
            this.headerPanel = new Panel();
            this.headerPanel.Dock = DockStyle.Top;
            this.headerPanel.Height = 70; // Taller header
            this.headerPanel.BackColor = Color.FromArgb(45, 45, 48); // Dark VS-like theme
            
            // Toggle Sidebar Button
            Button btnToggle = new Button();
            btnToggle.Text = "☰";
            btnToggle.Font = new Font("Segoe UI", 12F, FontStyle.Bold);
            btnToggle.Size = new Size(40, 40);
            btnToggle.Location = new Point(10, 15);
            btnToggle.FlatStyle = FlatStyle.Flat;
            btnToggle.FlatAppearance.BorderSize = 0;
            btnToggle.ForeColor = Color.White;
            btnToggle.Cursor = Cursors.Hand;
            btnToggle.Click += (s, e) => { this.mainSplit.Panel1Collapsed = !this.mainSplit.Panel1Collapsed; };
            this.headerPanel.Controls.Add(btnToggle);

            // Try to load Logo for Window Icon only (not Header)
            string logoPath = "LOGOS\\icon.png";
            if (!File.Exists(logoPath)) logoPath = "..\\LOGOS\\icon.png"; 
            
            if (File.Exists(logoPath))
            {
                try {
                    Bitmap bmp = new Bitmap(logoPath);
                    IntPtr hIcon = bmp.GetHicon();
                    this.Icon = Icon.FromHandle(hIcon);
                } catch (Exception ex) { Logger.Warning("Icon: " + ex.Message); }
            }

            this.lblTitle = new Label();
            this.lblTitle.Text = "IR COLLECTOR & ANALYZER";
            this.lblTitle.ForeColor = Color.White;
            this.lblTitle.Font = new Font("Segoe UI", 14F, FontStyle.Bold);
            this.lblTitle.Location = new Point(60, 20); // Moved right for toggle
            this.lblTitle.AutoSize = true;

            this.btnCollect = CreateStyledButton("Local Collect", 340, Color.FromArgb(0, 122, 204));
            this.btnCollect.Click += new EventHandler(this.BtnCollect_Click);

            this.btnImport = CreateStyledButton("Import Case(s)", 500, Color.FromArgb(28, 151, 234));
            this.btnImport.Click += new EventHandler(this.BtnImport_Click);

            this.headerPanel.Controls.Add(this.lblTitle);
            this.headerPanel.Controls.Add(this.btnCollect);
            this.headerPanel.Controls.Add(this.btnImport);

            this.toolTipMain = new ToolTip();
            this.toolTipMain.SetToolTip(this.btnCollect, "在本機執行證據收集，完成後自動載入案卷。建議以系統管理員執行以取得完整 MFT、Prefetch。");
            this.toolTipMain.SetToolTip(this.btnImport, "匯入已收集的 ZIP 案卷（可多選）。");

            // --- Main Layout ---
            this.mainSplit = new SplitContainer();
            this.mainSplit.Dock = DockStyle.Fill;
            this.mainSplit.FixedPanel = FixedPanel.Panel1;
            this.mainSplit.SplitterDistance = 300; // Wider to fit text
            this.mainSplit.IsSplitterFixed = false; // Allow resizing
            this.mainSplit.BackColor = Color.FromArgb(240, 240, 240);

            // Left Panel Controls
            // 1. Dashboard Button
            Button btnDashboard = new Button();
            btnDashboard.Text = " Global Dashboard";
            btnDashboard.Dock = DockStyle.Top;
            btnDashboard.TextAlign = ContentAlignment.MiddleLeft;
            btnDashboard.Height = 50;
            btnDashboard.Font = new Font("Segoe UI", 12F, FontStyle.Bold); 
            btnDashboard.ForeColor = Color.White;
            btnDashboard.BackColor = Color.FromArgb(0, 122, 204);
            btnDashboard.FlatStyle = FlatStyle.Flat;
            btnDashboard.FlatAppearance.BorderSize = 0;
            btnDashboard.Cursor = Cursors.Hand;
            btnDashboard.Click += (s, e) => {
                this.treeHosts.SelectedNode = null;
                this.dashboardPanel.Visible = true;
                if (this.rightContentPanel != null) this.rightContentPanel.Visible = false;
            };

            // 2. Separator/Header for List
            Label lblTreeHeader = new Label();
            lblTreeHeader.Text = " Hosts list";
            lblTreeHeader.Dock = DockStyle.Top;
            lblTreeHeader.TextAlign = ContentAlignment.MiddleLeft;
            lblTreeHeader.Height = 35;
            lblTreeHeader.BackColor = Color.FromArgb(220, 230, 240); // Distinct color
            lblTreeHeader.ForeColor = Color.FromArgb(0, 50, 100);
            lblTreeHeader.Font = new Font("Segoe UI", 10F, FontStyle.Bold);
            lblTreeHeader.Padding = new Padding(5, 0, 0, 0);
            
            // 3. TreeView Container
            Panel pnlTreeContainer = new Panel();
            pnlTreeContainer.Dock = DockStyle.Fill;
            pnlTreeContainer.Padding = new Padding(1);
            pnlTreeContainer.BackColor = Color.FromArgb(180, 180, 180);

            this.treeHosts = new TreeView();
            this.treeHosts.Dock = DockStyle.Fill;
            this.treeHosts.BorderStyle = BorderStyle.None;
            this.treeHosts.Font = new Font("Segoe UI", 11F);
            this.treeHosts.FullRowSelect = true;
            this.treeHosts.ShowLines = false;
            this.treeHosts.ShowPlusMinus = true;
            this.treeHosts.ShowRootLines = false;
            // Context Menu Bind
            this.treeHosts.ContextMenuStrip = this.ctxHostMenu;
            this.treeHosts.NodeMouseClick += (s, e) => {
                if (e.Button == MouseButtons.Right) this.treeHosts.SelectedNode = e.Node;
            };
            this.treeHosts.AfterSelect += new TreeViewEventHandler(this.TreeHosts_AfterSelect);

            pnlTreeContainer.Controls.Add(this.treeHosts);

            this.mainSplit.Panel1.Controls.Clear();
            this.mainSplit.Panel1.Controls.Add(pnlTreeContainer); // Fill
            this.mainSplit.Panel1.Controls.Add(lblTreeHeader);    // Top
            this.mainSplit.Panel1.Controls.Add(btnDashboard);     // Top


            // Right Panel (Initially Dashboard)
            this.dashboardPanel = CreateDashboardPanel();
            
            // Dynamic Tabs Container
            Panel rightContainer = new Panel();
            this.rightContentPanel = rightContainer;
            rightContainer.Dock = DockStyle.Fill;

            // Custom Tab Navigation (FlowLayout)
            FlowLayoutPanel tabNavPanel = new FlowLayoutPanel();
            tabNavPanel.Dock = DockStyle.Top;
            tabNavPanel.Height = 40;
            tabNavPanel.BackColor = Color.FromArgb(230, 230, 232); // Modern Light Gray
            tabNavPanel.Padding = new Padding(5, 5, 0, 0);
            tabNavPanel.Name = "tabNavPanel";

            this.hostTabs = new TabControl();
            this.hostTabs.Dock = DockStyle.Fill;
            this.hostTabs.Visible = false;
            SetDoubleBuffered(this.hostTabs);
            this.hostTabs.SelectedIndexChanged += (s, ev) =>
            {
                if (hostTabs != null) { hostTabs.SuspendLayout(); BeginInvoke((MethodInvoker)(() => { try { if (hostTabs != null && !hostTabs.IsDisposed) hostTabs.ResumeLayout(true); } catch { } })); }
            };
            // Hide Native Headers
            this.hostTabs.SizeMode = TabSizeMode.Fixed;
            this.hostTabs.ItemSize = new Size(0, 1);
            this.hostTabs.Appearance = TabAppearance.FlatButtons;

            rightContainer.Controls.Add(this.hostTabs);
            rightContainer.Controls.Add(tabNavPanel);

            this.mainSplit.Panel2.Controls.Add(this.dashboardPanel);
            this.mainSplit.Panel2.Controls.Add(rightContainer);

            this.Controls.Add(this.mainSplit);
            this.Controls.Add(this.headerPanel);
            this.Controls.Add(menuStrip);

            // Collect progress bar (bottom strip, hidden by default)
            this.collectProgressPanel = new Panel();
            this.collectProgressPanel.Dock = DockStyle.Bottom;
            this.collectProgressPanel.Height = 32;
            this.collectProgressPanel.BackColor = Color.FromArgb(0, 122, 204);
            this.collectProgressPanel.Visible = false;
            this.lblCollectStatus = new Label();
            this.lblCollectStatus.Text = "Collecting... Please wait.";
            this.lblCollectStatus.ForeColor = Color.White;
            this.lblCollectStatus.AutoSize = true;
            this.lblCollectStatus.Location = new Point(12, 8);
            this.lblCollectStatus.Font = new Font("Segoe UI", 9.5F);
            this.progressCollect = new ProgressBar();
            this.progressCollect.Style = ProgressBarStyle.Marquee;
            this.progressCollect.MarqueeAnimationSpeed = 30;
            this.progressCollect.Dock = DockStyle.Bottom;
            this.progressCollect.Height = 6;
            this.progressCollect.Visible = true;
            this.collectProgressPanel.Controls.Add(this.lblCollectStatus);
            this.collectProgressPanel.Controls.Add(this.progressCollect);
            this.Controls.Add(this.collectProgressPanel);

            // Drag Drop
            this.AllowDrop = true;
            this.DragEnter += (s, e) => { if (e.Data.GetDataPresent(DataFormats.FileDrop)) e.Effect = DragDropEffects.Copy; };
            this.DragDrop += new DragEventHandler(this.MainForm_DragDrop);
            
            // Default view logic
            this.dashboardPanel.Visible = true;
        }

        // Helper to update custom tab buttons with Drag & Drop Reordering
        private void UpdateTabNav(TabControl tabs)
        {
            var nav = (FlowLayoutPanel)tabs.Parent.Controls["tabNavPanel"];
            nav.AllowDrop = true;
            nav.Tag = tabs;
            ClearNavButtons(nav);
            tabs.Visible = true;

            // Wire up FlowPanel DnD
            nav.DragEnter -= Nav_DragEnter;
            nav.DragEnter += Nav_DragEnter;
            nav.DragDrop -= Nav_DragDropProxy;
            nav.DragDrop += Nav_DragDropProxy;

            foreach (TabPage page in tabs.TabPages)
            {
                Button btn = new Button();
                btn.Text = page.Text;
                btn.AutoSize = true;
                btn.FlatStyle = FlatStyle.Flat;
                btn.FlatAppearance.BorderSize = 0;
                btn.Font = navTabFont;
                btn.Cursor = Cursors.Hand;
                btn.Margin = new Padding(0, 0, 2, 0);
                btn.Tag = page; // Link back to page

                // Click Event
                btn.Click += (s, e) =>
                {
                    tabs.SelectedTab = page;
                    RefreshNavStyles(nav, btn);
                };

                // Drag Start
                // Drag Start Logic
                btn.MouseDown += (s, e) => {
                    if (e.Button == MouseButtons.Left)
                    {
                        dragStartPoint = e.Location;
                        dragSourceBtn = btn;
                    }
                };

                btn.MouseMove += (s, e) => {
                    if (e.Button == MouseButtons.Left && dragSourceBtn == btn)
                    {
                        // Check if moved far enough
                        if (Math.Abs(e.X - dragStartPoint.X) > SystemInformation.DragSize.Width ||
                            Math.Abs(e.Y - dragStartPoint.Y) > SystemInformation.DragSize.Height)
                        {
                            btn.DoDragDrop(btn, DragDropEffects.Move);
                            // Reset after drag returns (optional, or rely on MouseUp)
                            dragSourceBtn = null;
                        }
                    }
                };

                btn.MouseUp += (s, e) => {
                    dragSourceBtn = null;
                };

                if (page == tabs.SelectedTab)
                {
                    btn.BackColor = Color.White;
                    btn.ForeColor = Color.FromArgb(0, 122, 204);
                    btn.Font = navTabFontBold;
                }

                nav.Controls.Add(btn);
            }
        }

        private void ClearNavButtons(FlowLayoutPanel nav)
        {
            if (nav == null) return;
            while (nav.Controls.Count > 0)
            {
                Control control = nav.Controls[0];
                nav.Controls.RemoveAt(0);
                control.Dispose();
            }
        }

        private void RefreshNavStyles(FlowLayoutPanel nav, Button activeBtn)
        {
            foreach(Button b in nav.Controls)
            {
                b.BackColor = Color.Transparent;
                b.ForeColor = Color.Black;
                b.Font = navTabFont;
            }
            if (activeBtn != null)
            {
                activeBtn.BackColor = Color.White; // Active bg
                activeBtn.ForeColor = Color.FromArgb(0, 122, 204); // Active blue
                activeBtn.Font = navTabFontBold;
            }
        }

        // Custom Nav Drag Events
        private void Nav_DragEnter(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(typeof(Button))) e.Effect = DragDropEffects.Move;
        }

        private void Nav_DragDrop(object sender, DragEventArgs e, TabControl tabs)
        {
            Button draggedBtn = (Button)e.Data.GetData(typeof(Button));
            FlowLayoutPanel nav = (FlowLayoutPanel)sender;

            if (draggedBtn == null || nav == null || tabs == null) return;

            // Determine insertion index based on mouse X
            Point pt = nav.PointToClient(new Point(e.X, e.Y));
            Control target = nav.GetChildAtPoint(pt);

            int newIndex = -1;
            if (target != null) newIndex = nav.Controls.GetChildIndex(target);
            else newIndex = nav.Controls.Count - 1;

            if (newIndex < 0) newIndex = 0;

            // Reorder TabPages
            TabPage movedPage = (TabPage)draggedBtn.Tag;
            if (movedPage == null) return;
            tabs.TabPages.Remove(movedPage);

            // Adjust index for Tabs
            if (newIndex >= tabs.TabPages.Count) tabs.TabPages.Add(movedPage);
            else tabs.TabPages.Insert(newIndex, movedPage);

            tabs.SelectedTab = movedPage;
            UpdateTabNav(tabs); // Rebuild buttons
        }

        private void Nav_DragDropProxy(object sender, DragEventArgs e)
        {
            FlowLayoutPanel nav = sender as FlowLayoutPanel;
            TabControl tabs = nav != null ? nav.Tag as TabControl : null;
            if (nav == null || tabs == null || tabs.IsDisposed) return;
            Nav_DragDrop(sender, e, tabs);
        }

        // Native TabControl Drag Helpers
        private void EnableTabDragging(TabControl tc)
        {
            tc.AllowDrop = true;
            tc.MouseDown += (s, e) => {
                // Get tab under mouse
                for (int i = 0; i < tc.TabCount; i++) {
                    if (tc.GetTabRect(i).Contains(e.Location)) {
                        tc.DoDragDrop(tc.TabPages[i], DragDropEffects.Move);
                        return;
                    }
                }
            };
            tc.DragOver += (s, e) => {
                if (e.Data.GetDataPresent(typeof(TabPage))) e.Effect = DragDropEffects.Move;
            };
            tc.DragDrop += (s, e) => {
                if (e.Data.GetDataPresent(typeof(TabPage))) {
                    TabPage draggedTab = (TabPage)e.Data.GetData(typeof(TabPage));
                    TabControl parent = (TabControl)s;
                   
                    // Find target tab
                    Point pt = parent.PointToClient(new Point(e.X, e.Y));
                    TabPage targetTab = null;
                    int targetIndex = -1;

                    for (int i = 0; i < parent.TabCount; i++) {
                        if (parent.GetTabRect(i).Contains(pt)) {
                            targetTab = parent.TabPages[i];
                            targetIndex = i;
                            break;
                        }
                    }

                    if (targetIndex != -1 && draggedTab != targetTab) {
                        parent.TabPages.Remove(draggedTab);
                        parent.TabPages.Insert(targetIndex, draggedTab);
                        parent.SelectedTab = draggedTab;
                    }
                }
            };
        }

        private Panel CreateDashboardPanel()
        {
            Panel p = new Panel();
            p.Dock = DockStyle.Fill;
            p.BackColor = Color.White;

            Label title = new Label();
            title.Text = "Global Correlation & Overview";
            title.Font = new Font("Segoe UI", 18F, FontStyle.Regular); // Big title
            title.Location = new Point(25, 25);
            title.AutoSize = true;

            this.lblDashSummary = new Label();
            this.lblDashSummary.Text = "";
            this.lblDashSummary.Location = new Point(30, 72);
            this.lblDashSummary.AutoSize = true;
            this.lblDashSummary.Font = new Font("Segoe UI", 12F);
            this.lblDashSummary.MaximumSize = new Size(900, 0);

            // Dashboard 按鈕：同一列，兩顆圖示同大（50×50），緊貼 Entity search 上方、間隔縮小
            const int leftX = 30, row1Y = 140, gap = 10, iconBtnSize = 50;
            const int entityRowY = 202;
            const int filterRowY = 238;
            const int timeFilterRowY = 272;
            const int workspaceRowY = 304;
            const int workspaceInfoY = 336;
            const int listTopY = 384;

            this.menuCorrelation = new ContextMenuStrip();
            var itemCommon = this.menuCorrelation.Items.Add("Find Common Artifacts（跨主機共有）");
            itemCommon.Click += (s, e) => RunCorrelation();
            var itemEntityPivot = this.menuCorrelation.Items.Add("Find Shared Entities（跨主機實體）");
            itemEntityPivot.Click += (s, e) => RunSharedEntityPivot();
            this.menuSharedEntityPivotBack = new ToolStripMenuItem("Back To Last Shared Pivot（返回上一個 Pivot）");
            this.menuSharedEntityPivotBack.Enabled = false;
            this.menuSharedEntityPivotBack.Click += (s, e) => RunRestoreLastSharedEntityPivot();
            this.menuCorrelation.Items.Add(this.menuSharedEntityPivotBack);
            var itemRelated = this.menuCorrelation.Items.Add("Find Related Entities（實體關聯）");
            itemRelated.Click += (s, e) => RunRelatedEntityPivot();
            var itemGraph = this.menuCorrelation.Items.Add("Build Investigation Graph（跨主機圖譜表）");
            itemGraph.Click += (s, e) => RunInvestigationGraph();
            var itemTemporalEntity = this.menuCorrelation.Items.Add("Find Time-Window Entity Correlation（跨主機＋同實體＋同時段）");
            itemTemporalEntity.Click += (s, e) => RunTemporalSharedEntityCorrelation();
            var itemTimeline = this.menuCorrelation.Items.Add("Find Timeline Correlation（跨主機＋同時段）");
            itemTimeline.Click += (s, e) => RunTimelineCorrelation();

            this.btnCorrelation = new Button();
            this.btnCorrelation.Text = "";
            this.btnCorrelation.Size = new Size(iconBtnSize, iconBtnSize);
            this.btnCorrelation.Location = new Point(leftX, row1Y);
            this.btnCorrelation.BackColor = Color.SeaGreen;
            this.btnCorrelation.ForeColor = Color.White;
            this.btnCorrelation.FlatStyle = FlatStyle.Flat;
            this.btnCorrelation.Image = CreateCorrelationIconImage(iconBtnSize - 2);
            this.btnCorrelation.ImageAlign = ContentAlignment.MiddleCenter;
            this.btnCorrelation.Click += (s, e) => this.menuCorrelation.Show(this.btnCorrelation, new Point(0, this.btnCorrelation.Height));
            if (this.toolTipMain != null) this.toolTipMain.SetToolTip(this.btnCorrelation, "Correlation：跨主機關聯（共有 / 實體 Pivot / 實體關聯 / 同實體＋同時段 / 指標式同時段）");

            this.btnExportFullLogJson = new Button();
            this.btnExportFullLogJson.Text = "";
            this.btnExportFullLogJson.Size = new Size(iconBtnSize, iconBtnSize);
            this.btnExportFullLogJson.Location = new Point(leftX + iconBtnSize + gap, row1Y);
            this.btnExportFullLogJson.BackColor = Color.Teal;
            this.btnExportFullLogJson.ForeColor = Color.White;
            this.btnExportFullLogJson.FlatStyle = FlatStyle.Flat;
            this.btnExportFullLogJson.Image = CreateExportJsonIconImage(iconBtnSize - 2);
            this.btnExportFullLogJson.ImageAlign = ContentAlignment.MiddleCenter;
            this.btnExportFullLogJson.Click += (s, e) => RunExportFullLogJson();
            if (this.toolTipMain != null) this.toolTipMain.SetToolTip(this.btnExportFullLogJson, "Export full LOG JSON：將所有主機的 Fact Store 匯出為 full_log_v3 facts-only JSON 封裝（含 host 摘要、workflow、warnings、parser notes、provenance 與完整 facts）。");

            var lblEntity = new Label();
            lblEntity.Text = "Entity search:";
            lblEntity.Location = new Point(30, entityRowY + 4);
            lblEntity.AutoSize = true;
            lblEntity.Font = new Font("Segoe UI", 10F);

            this.comboEntityType = new ComboBox();
            this.comboEntityType.DropDownStyle = ComboBoxStyle.DropDownList;
            this.comboEntityType.Location = new Point(130, entityRowY);
            this.comboEntityType.Size = new Size(90, 24);
            this.comboEntityType.Font = new Font("Segoe UI", 10F);
            this.comboEntityType.Items.AddRange(new object[] { "Path", "FileName", "Hash", "User", "Sid", "SubjectUser", "TargetUser", "RegistryKey", "Provider", "EventId", "RemoteIP", "RemotePort", "RemoteName", "ServiceName", "TaskName", "ShareName", "ShareLocalPath", "Workstation", "TargetServer", "CredentialTarget", "LogonType", "LogonProcess", "AuthenticationPackage", "ProcessId", "ThreatName", "CommandLine", "Computer", "BitsJob", "WmiFilter", "WmiConsumer", "Query", "AppId", "Interface", "Publisher", "ProductName", "ProgramName", "ProgramId" });
            this.comboEntityType.SelectedIndex = 0;

            this.txtEntityValue = new TextBox();
            this.txtEntityValue.Location = new Point(230, entityRowY);
            this.txtEntityValue.Size = new Size(320, 24);
            this.txtEntityValue.Font = new Font("Segoe UI", 10F);

            this.btnSearchEntity = new Button();
            this.btnSearchEntity.Text = "Search";
            this.btnSearchEntity.Location = new Point(560, entityRowY - 2);
            this.btnSearchEntity.Size = new Size(90, 28);
            this.btnSearchEntity.BackColor = Color.Teal;
            this.btnSearchEntity.ForeColor = Color.White;
            this.btnSearchEntity.FlatStyle = FlatStyle.Flat;
            this.btnSearchEntity.Font = new Font("Segoe UI", 10F);
            this.btnSearchEntity.Click += (s, e) => RunEntitySearch();
            if (this.toolTipMain != null) this.toolTipMain.SetToolTip(this.btnSearchEntity, "依 Path / FileName / Hash / User / SubjectUser / TargetUser / RegistryKey / Provider / EventId / RemoteIP / RemotePort / RemoteName / ServiceName / TaskName / ShareName / ShareLocalPath / Workstation / TargetServer / LogonType / LogonProcess / AuthenticationPackage / ProcessId / ThreatName / CommandLine / Computer / BitsJob / WmiFilter / WmiConsumer / Query / AppId / Interface / Publisher / ProductName / ProgramName / ProgramId 搜尋 Fact Store（含 Phase 3 lateral movement 實體）。");

            var lblFilterSource = new Label();
            lblFilterSource.Text = "Source:";
            lblFilterSource.Location = new Point(30, filterRowY + 4);
            lblFilterSource.AutoSize = true;
            lblFilterSource.Font = new Font("Segoe UI", 10F);

            this.comboCorrelationSource = new ComboBox();
            this.comboCorrelationSource.DropDownStyle = ComboBoxStyle.DropDownList;
            this.comboCorrelationSource.Location = new Point(92, filterRowY);
            this.comboCorrelationSource.Size = new Size(110, 24);
            this.comboCorrelationSource.Font = new Font("Segoe UI", 10F);
            this.comboCorrelationSource.Items.AddRange(new object[] { "(All)", "Process", "EventLog", "MFT", "ActivityTimeline", "Autorun", "Service", "ScheduledTask", "StoredCredential", "KerberosTicketCache", "USN", "BAM", "DAM", "BITS", "JumpList", "WmiPersistence", "Amcache", "ShimCache", "ShellBags", "SRUMNetwork", "SRUMApp" });
            this.comboCorrelationSource.SelectedIndex = 0;

            var lblFilterConfidence = new Label();
            lblFilterConfidence.Text = "Confidence:";
            lblFilterConfidence.Location = new Point(214, filterRowY + 4);
            lblFilterConfidence.AutoSize = true;
            lblFilterConfidence.Font = new Font("Segoe UI", 10F);

            this.comboCorrelationConfidence = new ComboBox();
            this.comboCorrelationConfidence.DropDownStyle = ComboBoxStyle.DropDownList;
            this.comboCorrelationConfidence.Location = new Point(294, filterRowY);
            this.comboCorrelationConfidence.Size = new Size(90, 24);
            this.comboCorrelationConfidence.Font = new Font("Segoe UI", 10F);
            this.comboCorrelationConfidence.Items.AddRange(new object[] { "(All)", "High", "Medium", "Low", "Unknown" });
            this.comboCorrelationConfidence.SelectedIndex = 0;

            var lblFilterHost = new Label();
            lblFilterHost.Text = "Host:";
            lblFilterHost.Location = new Point(400, filterRowY + 4);
            lblFilterHost.AutoSize = true;
            lblFilterHost.Font = new Font("Segoe UI", 10F);

            this.txtCorrelationHostFilter = new TextBox();
            this.txtCorrelationHostFilter.Location = new Point(442, filterRowY);
            this.txtCorrelationHostFilter.Size = new Size(130, 24);
            this.txtCorrelationHostFilter.Font = new Font("Segoe UI", 10F);

            var lblFilterWindow = new Label();
            lblFilterWindow.Text = "Window:";
            lblFilterWindow.Location = new Point(588, filterRowY + 4);
            lblFilterWindow.AutoSize = true;
            lblFilterWindow.Font = new Font("Segoe UI", 10F);

            this.comboCorrelationWindow = new ComboBox();
            this.comboCorrelationWindow.DropDownStyle = ComboBoxStyle.DropDownList;
            this.comboCorrelationWindow.Location = new Point(652, filterRowY);
            this.comboCorrelationWindow.Size = new Size(86, 24);
            this.comboCorrelationWindow.Font = new Font("Segoe UI", 10F);
            this.comboCorrelationWindow.Items.AddRange(new object[] { "5m", "15m", "30m", "60m" });
            this.comboCorrelationWindow.SelectedIndex = 2;

            var lblWorkspaceHostScope = new Label();
            lblWorkspaceHostScope.Text = "Graph host scope:";
            lblWorkspaceHostScope.Location = new Point(756, filterRowY + 4);
            lblWorkspaceHostScope.AutoSize = true;
            lblWorkspaceHostScope.Font = new Font("Segoe UI", 10F);

            this.comboWorkspaceHostScope = new ComboBox();
            this.comboWorkspaceHostScope.DropDownStyle = ComboBoxStyle.DropDownList;
            this.comboWorkspaceHostScope.Location = new Point(874, filterRowY);
            this.comboWorkspaceHostScope.Size = new Size(160, 24);
            this.comboWorkspaceHostScope.Font = new Font("Segoe UI", 10F);
            this.comboWorkspaceHostScope.Items.AddRange(new object[] { "All loaded hosts", "Current edge hosts", "Host filter text" });
            this.comboWorkspaceHostScope.SelectedIndex = 0;
            this.comboWorkspaceHostScope.SelectedIndexChanged += (s, e) => RefreshInvestigationWorkspaceUi();

            var lblFilterFrom = new Label();
            lblFilterFrom.Text = "From:";
            lblFilterFrom.Location = new Point(30, timeFilterRowY + 4);
            lblFilterFrom.AutoSize = true;
            lblFilterFrom.Font = new Font("Segoe UI", 10F);

            this.dtCorrelationFrom = new DateTimePicker();
            this.dtCorrelationFrom.Location = new Point(82, timeFilterRowY);
            this.dtCorrelationFrom.Size = new Size(182, 24);
            this.dtCorrelationFrom.Font = new Font("Segoe UI", 10F);
            this.dtCorrelationFrom.Format = DateTimePickerFormat.Custom;
            this.dtCorrelationFrom.CustomFormat = "yyyy-MM-dd HH:mm";
            this.dtCorrelationFrom.ShowCheckBox = true;
            this.dtCorrelationFrom.Checked = false;
            this.dtCorrelationFrom.MinDate = new DateTime(1980, 1, 1);
            this.dtCorrelationFrom.MaxDate = new DateTime(2100, 12, 31);

            var lblFilterTo = new Label();
            lblFilterTo.Text = "To:";
            lblFilterTo.Location = new Point(284, timeFilterRowY + 4);
            lblFilterTo.AutoSize = true;
            lblFilterTo.Font = new Font("Segoe UI", 10F);

            this.dtCorrelationTo = new DateTimePicker();
            this.dtCorrelationTo.Location = new Point(320, timeFilterRowY);
            this.dtCorrelationTo.Size = new Size(182, 24);
            this.dtCorrelationTo.Font = new Font("Segoe UI", 10F);
            this.dtCorrelationTo.Format = DateTimePickerFormat.Custom;
            this.dtCorrelationTo.CustomFormat = "yyyy-MM-dd HH:mm";
            this.dtCorrelationTo.ShowCheckBox = true;
            this.dtCorrelationTo.Checked = false;
            this.dtCorrelationTo.MinDate = new DateTime(1980, 1, 1);
            this.dtCorrelationTo.MaxDate = new DateTime(2100, 12, 31);

            this.btnGraphExpandFromEdge = new Button();
            this.btnGraphExpandFromEdge.Text = "Expand From Selected Edge";
            this.btnGraphExpandFromEdge.Location = new Point(30, workspaceRowY);
            this.btnGraphExpandFromEdge.Size = new Size(185, 28);
            this.btnGraphExpandFromEdge.BackColor = Color.SeaGreen;
            this.btnGraphExpandFromEdge.ForeColor = Color.White;
            this.btnGraphExpandFromEdge.FlatStyle = FlatStyle.Flat;
            this.btnGraphExpandFromEdge.Font = new Font("Segoe UI", 9F);
            this.btnGraphExpandFromEdge.Click += (s, e) => RunInvestigationWorkspaceExpandFromSelectedEdge();

            this.btnGraphBack = new Button();
            this.btnGraphBack.Text = "Back";
            this.btnGraphBack.Location = new Point(225, workspaceRowY);
            this.btnGraphBack.Size = new Size(72, 28);
            this.btnGraphBack.BackColor = Color.DimGray;
            this.btnGraphBack.ForeColor = Color.White;
            this.btnGraphBack.FlatStyle = FlatStyle.Flat;
            this.btnGraphBack.Font = new Font("Segoe UI", 9F);
            this.btnGraphBack.Click += (s, e) => RunInvestigationWorkspaceBack();

            this.btnGraphForward = new Button();
            this.btnGraphForward.Text = "Forward";
            this.btnGraphForward.Location = new Point(304, workspaceRowY);
            this.btnGraphForward.Size = new Size(76, 28);
            this.btnGraphForward.BackColor = Color.DimGray;
            this.btnGraphForward.ForeColor = Color.White;
            this.btnGraphForward.FlatStyle = FlatStyle.Flat;
            this.btnGraphForward.Font = new Font("Segoe UI", 9F);
            this.btnGraphForward.Click += (s, e) => RunInvestigationWorkspaceForward();

            this.btnGraphResetSeed = new Button();
            this.btnGraphResetSeed.Text = "Reset To Original Seed";
            this.btnGraphResetSeed.Location = new Point(388, workspaceRowY);
            this.btnGraphResetSeed.Size = new Size(175, 28);
            this.btnGraphResetSeed.BackColor = Color.DimGray;
            this.btnGraphResetSeed.ForeColor = Color.White;
            this.btnGraphResetSeed.FlatStyle = FlatStyle.Flat;
            this.btnGraphResetSeed.Font = new Font("Segoe UI", 9F);
            this.btnGraphResetSeed.Click += (s, e) => RunInvestigationWorkspaceResetToOriginalSeed();

            this.btnGraphPin = new Button();
            this.btnGraphPin.Text = "Pin Edge";
            this.btnGraphPin.Location = new Point(570, workspaceRowY);
            this.btnGraphPin.Size = new Size(85, 28);
            this.btnGraphPin.BackColor = Color.Teal;
            this.btnGraphPin.ForeColor = Color.White;
            this.btnGraphPin.FlatStyle = FlatStyle.Flat;
            this.btnGraphPin.Font = new Font("Segoe UI", 9F);
            this.btnGraphPin.Click += (s, e) => RunInvestigationWorkspacePinSelectedEdge();

            this.btnGraphOpenFacts = new Button();
            this.btnGraphOpenFacts.Text = "Open Facts";
            this.btnGraphOpenFacts.Location = new Point(662, workspaceRowY);
            this.btnGraphOpenFacts.Size = new Size(90, 28);
            this.btnGraphOpenFacts.BackColor = Color.DarkCyan;
            this.btnGraphOpenFacts.ForeColor = Color.White;
            this.btnGraphOpenFacts.FlatStyle = FlatStyle.Flat;
            this.btnGraphOpenFacts.Font = new Font("Segoe UI", 9F);
            this.btnGraphOpenFacts.Click += (s, e) => RunInvestigationWorkspaceOpenSelectedEdgeFacts();

            this.btnGraphOpenTimeline = new Button();
            this.btnGraphOpenTimeline.Text = "Open Timeline";
            this.btnGraphOpenTimeline.Location = new Point(758, workspaceRowY);
            this.btnGraphOpenTimeline.Size = new Size(108, 28);
            this.btnGraphOpenTimeline.BackColor = Color.DarkCyan;
            this.btnGraphOpenTimeline.ForeColor = Color.White;
            this.btnGraphOpenTimeline.FlatStyle = FlatStyle.Flat;
            this.btnGraphOpenTimeline.Font = new Font("Segoe UI", 9F);
            this.btnGraphOpenTimeline.Click += (s, e) => RunInvestigationWorkspaceOpenSelectedEdgeTimeline();

            this.lblGraphWorkspaceTrail = new Label();
            this.lblGraphWorkspaceTrail.Text = "Trail: (empty)";
            this.lblGraphWorkspaceTrail.Location = new Point(30, workspaceInfoY);
            this.lblGraphWorkspaceTrail.Size = new Size(980, 18);
            this.lblGraphWorkspaceTrail.Font = new Font("Segoe UI", 9F);

            this.lblGraphWorkspacePinned = new Label();
            this.lblGraphWorkspacePinned.Text = "Pinned: (none)";
            this.lblGraphWorkspacePinned.Location = new Point(30, workspaceInfoY + 18);
            this.lblGraphWorkspacePinned.Size = new Size(980, 18);
            this.lblGraphWorkspacePinned.Font = new Font("Segoe UI", 9F);

            if (this.toolTipMain != null)
            {
                this.toolTipMain.SetToolTip(this.comboCorrelationSource, "供 Shared Entities / Related Entities / Time-Window Entity Correlation 使用的來源前綴篩選。");
                this.toolTipMain.SetToolTip(this.comboCorrelationConfidence, "依 TimeConfidence 篩選關聯結果。");
                this.toolTipMain.SetToolTip(this.txtCorrelationHostFilter, "只分析主機名稱包含此文字的已載入主機。");
                this.toolTipMain.SetToolTip(this.comboCorrelationWindow, "供 Time-Window Entity Correlation 使用的時間桶大小。");
                this.toolTipMain.SetToolTip(this.comboWorkspaceHostScope, "Investigation Graph workspace 的 host 範圍：全部主機、目前 edge 涉及主機、或 Host filter 文字。");
                this.toolTipMain.SetToolTip(this.dtCorrelationFrom, "勾選後才會套用 From 時間。");
                this.toolTipMain.SetToolTip(this.dtCorrelationTo, "勾選後才會套用 To 時間。");
                this.toolTipMain.SetToolTip(this.btnGraphExpandFromEdge, "以選取 edge 的 related entity 當作下一層 seed，延續調查路徑。");
                this.toolTipMain.SetToolTip(this.btnGraphBack, "回到上一個 seed。");
                this.toolTipMain.SetToolTip(this.btnGraphForward, "前進到下一個 seed。");
                this.toolTipMain.SetToolTip(this.btnGraphResetSeed, "重設回最初 seed。");
                this.toolTipMain.SetToolTip(this.btnGraphPin, "釘選目前選取 edge。");
                this.toolTipMain.SetToolTip(this.btnGraphOpenFacts, "開啟選取 edge 的 matching facts（保留 workspace context）。");
                this.toolTipMain.SetToolTip(this.btnGraphOpenTimeline, "跳到選取 edge 的 host timeline context。");
            }

            this.listCorrelation = new ListView();
            this.listCorrelation.Location = new Point(30, listTopY);
            this.listCorrelation.Size = new Size(950, 415);
            this.listCorrelation.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
            this.listCorrelation.View = View.Details;
            this.listCorrelation.GridLines = true;
            this.listCorrelation.FullRowSelect = true;
            this.listCorrelation.Font = new Font("Segoe UI", 11F);
            this.listCorrelation.ItemActivate += new EventHandler(this.ListCorrelation_ItemActivate);
            this.listCorrelation.SelectedIndexChanged += new EventHandler(this.ListCorrelation_SelectedIndexChanged);
            this.listCorrelation.Columns.Add("File/Artifact", 400);
            this.listCorrelation.Columns.Add("Count", 100);
            this.listCorrelation.Columns.Add("Hosts", -2); // -2 = 填滿右側剩餘寬度

            const int marginRight = 24, marginBottom = 24;
            p.Resize += (s, ev) =>
            {
                if (p.Parent == null) return;
                int w = p.ClientSize.Width - 30 - marginRight;
                int h = p.ClientSize.Height - listTopY - marginBottom;
                if (w > 0 && h > 0)
                    this.listCorrelation.SetBounds(30, listTopY, w, h);
            };

            p.Controls.Add(title);
            p.Controls.Add(lblDashSummary);
            p.Controls.Add(this.btnCorrelation);
            p.Controls.Add(this.btnExportFullLogJson);
            p.Controls.Add(lblEntity);
            p.Controls.Add(comboEntityType);
            p.Controls.Add(txtEntityValue);
            p.Controls.Add(btnSearchEntity);
            p.Controls.Add(lblFilterSource);
            p.Controls.Add(comboCorrelationSource);
            p.Controls.Add(lblFilterConfidence);
            p.Controls.Add(comboCorrelationConfidence);
            p.Controls.Add(lblFilterHost);
            p.Controls.Add(txtCorrelationHostFilter);
            p.Controls.Add(lblFilterWindow);
            p.Controls.Add(comboCorrelationWindow);
            p.Controls.Add(lblWorkspaceHostScope);
            p.Controls.Add(comboWorkspaceHostScope);
            p.Controls.Add(lblFilterFrom);
            p.Controls.Add(dtCorrelationFrom);
            p.Controls.Add(lblFilterTo);
            p.Controls.Add(dtCorrelationTo);
            p.Controls.Add(this.btnGraphExpandFromEdge);
            p.Controls.Add(this.btnGraphBack);
            p.Controls.Add(this.btnGraphForward);
            p.Controls.Add(this.btnGraphResetSeed);
            p.Controls.Add(this.btnGraphPin);
            p.Controls.Add(this.btnGraphOpenFacts);
            p.Controls.Add(this.btnGraphOpenTimeline);
            p.Controls.Add(this.lblGraphWorkspaceTrail);
            p.Controls.Add(this.lblGraphWorkspacePinned);
            p.Controls.Add(listCorrelation);
            RefreshInvestigationWorkspaceUi();
            return p;
        }

        private Button CreateStyledButton(string text, int x, Color backColor)
        {
            Button btn = new Button();
            btn.Text = text;
            btn.Location = new Point(x, 20);
            btn.Size = new Size(140, 36); // Bigger button
            btn.BackColor = backColor;
            btn.ForeColor = Color.White;
            btn.FlatStyle = FlatStyle.Flat;
            btn.FlatAppearance.BorderSize = 0;
            btn.Font = new Font("Segoe UI", 10F, FontStyle.Bold);
            return btn;
        }

        /// <summary>Draw a simple correlation/link icon (two nodes connected) for the Dashboard button.</summary>
        private static Bitmap CreateCorrelationIconImage(int sizePx)
        {
            var bmp = new Bitmap(sizePx, sizePx);
            using (var g = Graphics.FromImage(bmp))
            {
                g.Clear(Color.Transparent);
                g.SmoothingMode = SmoothingMode.AntiAlias;
                float penW = Math.Max(2f, sizePx / 16f);
                using (var pen = new Pen(Color.White, penW))
                {
                    float r = sizePx * 0.22f;
                    float cx1 = sizePx * 0.3f;
                    float cx2 = sizePx * 0.7f;
                    float cy = sizePx * 0.5f;
                    g.DrawEllipse(pen, cx1 - r, cy - r, r * 2, r * 2);
                    g.DrawEllipse(pen, cx2 - r, cy - r, r * 2, r * 2);
                    g.DrawLine(pen, cx1 + r, cy, cx2 - r, cy);
                }
            }
            return bmp;
        }

        /// <summary>Draw an export/download document icon for the Export full LOG JSON button.</summary>
        private static Bitmap CreateExportJsonIconImage(int sizePx)
        {
            var bmp = new Bitmap(sizePx, sizePx);
            using (var g = Graphics.FromImage(bmp))
            {
                g.Clear(Color.Transparent);
                g.SmoothingMode = SmoothingMode.AntiAlias;
                float penW = Math.Max(2f, sizePx / 16f);
                using (var pen = new Pen(Color.White, penW))
                {
                    float cx = sizePx * 0.5f;
                    float cy = sizePx * 0.4f;
                    float w = sizePx * 0.5f;
                    float h = sizePx * 0.45f;
                    g.DrawRectangle(pen, cx - w / 2, cy - h / 2, w, h);
                    float arrowY = cy + h / 2 + sizePx * 0.08f;
                    float arrowW = sizePx * 0.2f;
                    g.DrawLine(pen, cx - arrowW, arrowY - arrowW, cx, arrowY);
                    g.DrawLine(pen, cx, arrowY, cx + arrowW, arrowY - arrowW);
                    g.DrawLine(pen, cx, arrowY, cx, arrowY + sizePx * 0.12f);
                }
            }
            return bmp;
        }

        private void TreeHosts_AfterSelect(object sender, TreeViewEventArgs e)
        {
            if (e.Node == null) return;
            if (this.rightContentPanel == null) return;
            var rightContainer = this.rightContentPanel; 
            
            if (e.Node.Tag is IR_Collect.Analysis.CaseData)
            {
                var caseData = (IR_Collect.Analysis.CaseData)e.Node.Tag;
                BuildHostTabs(caseData);
                this.dashboardPanel.Visible = false;
                rightContainer.Visible = true;
            }
        }

        private void BuildHostTabs(IR_Collect.Analysis.CaseData c)
        {
            hostTabs.TabPages.Clear();
            hostTabs.Tag = c; // Save context

            // 0. Summary
            var summaryTab = CreateSummaryTab(c);
            if (summaryTab != null) hostTabs.TabPages.Add(summaryTab);

            // Facts
            var factsTab = CreateFactsTab(c);
            if (factsTab != null) hostTabs.TabPages.Add(factsTab);

            // 0. Timeline Analysis (Unified: Process + MFT + EventLog + Activity)
            bool hasTimelineData = (c.MftEntries != null && c.MftEntries.Count > 0) ||
                ResolveArtifactPathFlexible(c, ArtifactNames.ProcessListCsv) != null ||
                ResolveArtifactPathFlexible(c, ArtifactNames.LogonSessionsCsv) != null ||
                ResolveArtifactPathFlexible(c, ArtifactNames.NetworkResourcesCsv) != null ||
                ResolveArtifactPathFlexible(c, ArtifactNames.ServerConnectionsCsv) != null ||
                ResolveArtifactPathFlexible(c, ArtifactNames.StoredCredentialsTxt) != null ||
                ResolveArtifactPathFlexible(c, ArtifactNames.KerberosTicketsTxt) != null ||
                ResolveArtifactPathFlexible(c, ArtifactNames.ActivityTimelineCsv) != null ||
                ResolveArtifactPathFlexible(c, ArtifactNames.BamDamCsv) != null ||
                ResolveArtifactPathFlexible(c, ArtifactNames.BitsJobsCsv) != null ||
                ResolveArtifactPathFlexible(c, ArtifactNames.AmcacheProgramsCsv) != null ||
                ResolveArtifactPathFlexible(c, ArtifactNames.AmcacheFilesCsv) != null ||
                ResolveArtifactPathFlexible(c, ArtifactNames.ShimCacheEntriesCsv) != null ||
                ResolveArtifactPathFlexible(c, ArtifactNames.SrumNetworkUsageCsv) != null ||
                ResolveArtifactPathFlexible(c, ArtifactNames.SrumAppUsageCsv) != null ||
                ResolveArtifactPathFlexible(c, ArtifactNames.WmiPersistenceCsv) != null ||
                ResolveArtifactPathFlexible(c, ArtifactNames.UsnJournalCsv) != null ||
                ResolveArtifactPathFlexible(c, ArtifactNames.ShellBagsCsv) != null ||
                c.Artifacts.Keys.Any(k => ArtifactNames.IsEventLogFilteredCsv(k));
            var timelineTab = hasTimelineData ? CreateDeferredTab("Timeline Analysis", () => CreateTimelineTab(c)) : null;
            if (timelineTab != null) hostTabs.TabPages.Add(timelineTab);

            // 1. Basic Info
            TabPage pageBasic = new TabPage("Basic Info");
            TabControl subBasic = CreateSubTabControl();
            AddTabIfExists(subBasic, CreateSystemInfoTab(c));
            AddTabIfExists(subBasic, ResolveArtifactPathFlexible(c, ArtifactNames.ProcessListCsv) != null ? CreateDeferredTab("Processes", () => LoadCsvDataForTab(c, "Processes", ArtifactNames.ProcessListCsv), data => BuildCsvTabFromData("Processes", data as CsvTabData)) : null);
            AddTabIfExists(subBasic, ResolveArtifactPathFlexible(c, ArtifactNames.LogonSessionsCsv) != null ? CreateDeferredTab("Logon Sessions", () => LoadCsvDataForTab(c, "Logon Sessions", ArtifactNames.LogonSessionsCsv), data => BuildCsvTabFromData("Logon Sessions", data as CsvTabData)) : null);
            AddTabIfExists(subBasic, ResolveArtifactPathFlexible(c, ArtifactNames.NetworkResourcesCsv) != null ? CreateDeferredTab("Network Resources", () => LoadCsvDataForTab(c, "Network Resources", ArtifactNames.NetworkResourcesCsv), data => BuildCsvTabFromData("Network Resources", data as CsvTabData)) : null);
            AddTabIfExists(subBasic, ResolveArtifactPathFlexible(c, ArtifactNames.ServerConnectionsCsv) != null ? CreateDeferredTab("Server Connections", () => LoadCsvDataForTab(c, "Server Connections", ArtifactNames.ServerConnectionsCsv), data => BuildCsvTabFromData("Server Connections", data as CsvTabData)) : null);
            AddTabIfExists(subBasic, ResolveArtifactPathFlexible(c, ArtifactNames.StoredCredentialsTxt) != null ? CreateDeferredTab("Stored Credentials", () => CreateTextTab(c, "Stored Credentials", ArtifactNames.StoredCredentialsTxt)) : null);
            AddTabIfExists(subBasic, ResolveArtifactPathFlexible(c, ArtifactNames.KerberosTicketsTxt) != null ? CreateDeferredTab("Kerberos Tickets", () => CreateTextTab(c, "Kerberos Tickets", ArtifactNames.KerberosTicketsTxt)) : null);
            AddTabIfExists(subBasic, CreateIpConfigTab(c));
            AddTabIfExists(subBasic, CreateConnectionsTab(c));
            AddTabIfExists(subBasic, CreateArpTab(c));
            AddTabIfExists(subBasic, CreateDnsTab(c));
            if (subBasic.TabCount > 0) { pageBasic.Controls.Add(subBasic); hostTabs.TabPages.Add(pageBasic); }

            // 2. Persistence
            TabPage pagePersist = new TabPage("Persistence");
            TabControl subPersist = CreateSubTabControl();
            AddTabIfExists(subPersist, ResolveArtifactPathFlexible(c, ArtifactNames.ServicesCsv) != null ? CreateDeferredTab("Services", () => LoadCsvDataForTab(c, "Services", ArtifactNames.ServicesCsv), data => BuildCsvTabFromData("Services", data as CsvTabData)) : null);
            AddTabIfExists(subPersist, ResolveArtifactPathFlexible(c, ArtifactNames.AutorunsRegistryCsv) != null ? CreateDeferredTab("Autoruns", () => LoadCsvDataForTab(c, "Autoruns", ArtifactNames.AutorunsRegistryCsv), data => BuildCsvTabFromData("Autoruns", data as CsvTabData)) : null);
            AddTabIfExists(subPersist, ResolveArtifactPathFlexible(c, ArtifactNames.BamDamCsv) != null ? CreateDeferredTab("BAM / DAM", () => LoadCsvDataForTab(c, "BAM / DAM", ArtifactNames.BamDamCsv), data => BuildCsvTabFromData("BAM / DAM", data as CsvTabData)) : null);
            AddTabIfExists(subPersist, ResolveArtifactPathFlexible(c, ArtifactNames.BitsJobsCsv) != null ? CreateDeferredTab("BITS Jobs", () => LoadCsvDataForTab(c, "BITS Jobs", ArtifactNames.BitsJobsCsv), data => BuildCsvTabFromData("BITS Jobs", data as CsvTabData)) : null);
            AddTabIfExists(subPersist, ResolveArtifactPathFlexible(c, ArtifactNames.WmiPersistenceCsv) != null ? CreateDeferredTab("WMI Persistence", () => LoadCsvDataForTab(c, "WMI Persistence", ArtifactNames.WmiPersistenceCsv), data => BuildCsvTabFromData("WMI Persistence", data as CsvTabData)) : null);
            AddTabIfExists(subPersist, ResolveArtifactPathFlexible(c, ArtifactNames.InstalledSoftwareCsv) != null ? CreateDeferredTab("Software", () => LoadCsvDataForTab(c, "Software", ArtifactNames.InstalledSoftwareCsv), data => BuildCsvTabFromData("Software", data as CsvTabData)) : null);
            // Tasks (Special)
            var taskTab = ResolveArtifactPathFlexible(c, ArtifactNames.ScheduledTasksXml) != null ? CreateDeferredTab("Scheduled Tasks (XML)", () => CreateScheduledTaskTab(c)) : null;
            if (taskTab != null) subPersist.TabPages.Add(taskTab);
            if (subPersist.TabCount > 0) { pagePersist.Controls.Add(subPersist); hostTabs.TabPages.Add(pagePersist); }

            // 3. Logs & Artifacts
            TabPage pageLogs = new TabPage("Logs & Artifacts");
            TabControl subLogs = CreateSubTabControl();
            var evtTab = CreateEventLogTab(c);
            if (evtTab != null) subLogs.TabPages.Add(evtTab);
            AddTabIfExists(subLogs, ResolveArtifactPathFlexible(c, ArtifactNames.UsnJournalCsv) != null ? CreateDeferredTab("USN Journal", () => LoadCsvDataForTab(c, "USN Journal", ArtifactNames.UsnJournalCsv), data => BuildCsvTabFromData("USN Journal", data as CsvTabData)) : null);
            AddTabIfExists(subLogs, ResolveArtifactPathFlexible(c, ArtifactNames.ShellBagsCsv) != null ? CreateDeferredTab("ShellBags (parsed)", () => LoadCsvDataForTab(c, "ShellBags (parsed)", ArtifactNames.ShellBagsCsv), data => BuildCsvTabFromData("ShellBags (parsed)", data as CsvTabData)) : null);
            AddTabIfExists(subLogs, ResolveArtifactPathFlexible(c, ArtifactNames.ShimCacheCsv) != null ? CreateDeferredTab("ShimCache", () => LoadCsvDataForTab(c, "ShimCache", ArtifactNames.ShimCacheCsv), data => BuildCsvTabFromData("ShimCache", data as CsvTabData)) : null);
            AddTabIfExists(subLogs, ResolveArtifactPathFlexible(c, ArtifactNames.ShimCacheEntriesCsv) != null ? CreateDeferredTab("ShimCache Entries", () => LoadCsvDataForTab(c, "ShimCache Entries", ArtifactNames.ShimCacheEntriesCsv), data => BuildCsvTabFromData("ShimCache Entries", data as CsvTabData)) : null);
            AddTabIfExists(subLogs, ResolveArtifactPathFlexible(c, ArtifactNames.AmcacheProgramsCsv) != null ? CreateDeferredTab("Amcache Programs", () => LoadCsvDataForTab(c, "Amcache Programs", ArtifactNames.AmcacheProgramsCsv), data => BuildCsvTabFromData("Amcache Programs", data as CsvTabData)) : null);
            AddTabIfExists(subLogs, ResolveArtifactPathFlexible(c, ArtifactNames.AmcacheFilesCsv) != null ? CreateDeferredTab("Amcache Files", () => LoadCsvDataForTab(c, "Amcache Files", ArtifactNames.AmcacheFilesCsv), data => BuildCsvTabFromData("Amcache Files", data as CsvTabData)) : null);
            AddTabIfExists(subLogs, ResolveArtifactPathFlexible(c, ArtifactNames.SrumNetworkUsageCsv) != null ? CreateDeferredTab("SRUM Network Usage", () => LoadCsvDataForTab(c, "SRUM Network Usage", ArtifactNames.SrumNetworkUsageCsv), data => BuildCsvTabFromData("SRUM Network Usage", data as CsvTabData)) : null);
            AddTabIfExists(subLogs, ResolveArtifactPathFlexible(c, ArtifactNames.SrumAppUsageCsv) != null ? CreateDeferredTab("SRUM App Usage", () => LoadCsvDataForTab(c, "SRUM App Usage", ArtifactNames.SrumAppUsageCsv), data => BuildCsvTabFromData("SRUM App Usage", data as CsvTabData)) : null);
            AddTabIfExists(subLogs, GetArtifactSubFolderPath(c, "Registry") != null ? CreateDeferredTab("Registry exports", () => CreateFileListTab(c, "Registry exports", "Registry")) : null);
            AddTabIfExists(subLogs, GetArtifactSubFolderPath(c, ArtifactNames.ExecutionArtifactsFolder) != null ? CreateDeferredTab("Execution Artifacts (Raw)", () => CreateFileListTab(c, "Execution Artifacts (Raw)", ArtifactNames.ExecutionArtifactsFolder)) : null);
            AddTabIfExists(subLogs, GetArtifactSubFolderPath(c, ArtifactNames.MemoryFolder) != null ? CreateDeferredTab("Memory (Raw dump)", () => CreateFileListTab(c, "Memory (Raw dump)", ArtifactNames.MemoryFolder)) : null);
            AddTabIfExists(subLogs, ResolveArtifactPathFlexible(c, ArtifactNames.MemoryAcquisitionJson) != null ? CreateDeferredTab("Memory acquisition (meta)", () => CreateTextTab(c, "Memory acquisition (meta)", ArtifactNames.MemoryAcquisitionJson)) : null);
            AddTabIfExists(subLogs, GetArtifactSubFolderPath(c, ArtifactNames.MemoryAnalysisFolder) != null ? CreateDeferredTab("Memory analysis output", () => CreateFileListTab(c, "Memory analysis output", ArtifactNames.MemoryAnalysisFolder)) : null);
            AddTabIfExists(subLogs, ResolveArtifactPathFlexible(c, ArtifactNames.MemoryAnalysisJson) != null ? CreateDeferredTab("Memory analysis (meta)", () => CreateTextTab(c, "Memory analysis (meta)", ArtifactNames.MemoryAnalysisJson)) : null);

            // MFT (Special - Virtual Mode)
            TabPage mftPage = new TabPage("MFT View");
            DataGridView mftGrid = CreateGrid();
            mftGrid.VirtualMode = true;
            mftGrid.Columns.Add("Id", "Record ID");
            mftGrid.Columns.Add("Name", "File Name");
            mftGrid.Columns.Add("Path", "Full Path");
            mftGrid.Columns.Add("Size", "Size");
            mftGrid.Columns.Add("StdCreated", "Std Created");
            mftGrid.Columns.Add("StdModified", "Std Modified");
            mftGrid.Columns.Add("StdMftModified", "Std MFT Modified");
            mftGrid.Columns.Add("StdAccessed", "Std Accessed");
            mftGrid.Columns.Add("FnCreated", "FN Created");
            mftGrid.Columns.Add("FnModified", "FN Modified");
            mftGrid.Columns.Add("FnMftModified", "FN MFT Modified");
            mftGrid.Columns.Add("FnAccessed", "FN Accessed");
            mftGrid.Columns[2].Width = 400; // Full path width
            mftGrid.Columns[mftGrid.Columns.Count - 1].AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;

            // Filter UI：標籤簡短不重疊、欄寬一次到位，Apply/Reset 可見；視窗窄時可橫向捲動
            Panel mftFilterPanel = new Panel();
            mftFilterPanel.Dock = DockStyle.Top;
            mftFilterPanel.Height = 40;
            mftFilterPanel.BackColor = Color.WhiteSmoke;
            mftFilterPanel.AutoScroll = true;
            mftFilterPanel.MinimumSize = new Size(0, 40);

            var mftTable = new TableLayoutPanel();
            mftTable.Dock = DockStyle.Fill;
            mftTable.Padding = new Padding(6, 6, 6, 4);
            mftTable.ColumnCount = 10;
            mftTable.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 50));   // Path 標籤（完整顯示 "Path:"）
            mftTable.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 220));  // Path 輸入
            mftTable.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 6));
            mftTable.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 72));   // Min size 標籤
            mftTable.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 80));   // Min 輸入
            mftTable.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 80));   // Max size 標籤（完整顯示 "Max size:"）
            mftTable.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 80));   // Max 輸入
            mftTable.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 6));
            mftTable.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 60));   // Apply
            mftTable.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 60));   // Reset
            mftTable.RowCount = 1;
            mftTable.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));
            mftTable.MinimumSize = new Size(774, 28);  // 保持完整寬度，窄視窗時由 panel AutoScroll 捲動

            Label lblPath = new Label() { Text = "Path:", AutoSize = true, Anchor = AnchorStyles.Left, MaximumSize = new Size(48, 0) };
            TextBox txtPath = new TextBox() { Dock = DockStyle.Fill, MinimumSize = new Size(180, 0) };
            Label lblMin = new Label() { Text = "Min size:", AutoSize = true, Anchor = AnchorStyles.Left, MaximumSize = new Size(70, 0) };
            TextBox txtMin = new TextBox() { Dock = DockStyle.Fill, MinimumSize = new Size(60, 0) };
            Label lblMax = new Label() { Text = "Max size:", AutoSize = true, Anchor = AnchorStyles.Left, MaximumSize = new Size(78, 0) };
            TextBox txtMax = new TextBox() { Dock = DockStyle.Fill, MinimumSize = new Size(60, 0) };
            Button btnApply = new Button() { Text = "Apply", Width = 58, Height = 26 };
            Button btnReset = new Button() { Text = "Reset", Width = 58, Height = 26 };

            mftTable.Controls.Add(lblPath, 0, 0);
            mftTable.Controls.Add(txtPath, 1, 0);
            mftTable.Controls.Add(lblMin, 3, 0);
            mftTable.Controls.Add(txtMin, 4, 0);
            mftTable.Controls.Add(lblMax, 5, 0);
            mftTable.Controls.Add(txtMax, 6, 0);
            mftTable.Controls.Add(btnApply, 8, 0);
            mftTable.Controls.Add(btnReset, 9, 0);
            mftFilterPanel.Controls.Add(mftTable);

            // Restrict Min/Max to digits only (防呆)
            KeyPressEventHandler restrictNumeric = (s, k) => {
                if (!char.IsControl(k.KeyChar) && !char.IsDigit(k.KeyChar)) k.Handled = true;
            };
            txtMin.KeyPress += restrictNumeric;
            txtMax.KeyPress += restrictNumeric;

            List<IR_Collect.MFT.MftParser.MftEntry> mftView =
                (c.MftEntries != null) ? new List<IR_Collect.MFT.MftParser.MftEntry>(c.MftEntries) :
                new List<IR_Collect.MFT.MftParser.MftEntry>();

            mftGrid.CellValueNeeded += (s, e) => {
                if (mftView != null && e.RowIndex < mftView.Count) {
                    var entry = mftView[e.RowIndex];
                    switch (e.ColumnIndex) {
                        case 0: e.Value = entry.RecordNumber; break;
                        case 1: e.Value = entry.FileName; break;
                        case 2: e.Value = entry.FullPath; break;
                        case 3: e.Value = entry.Size; break;
                        case 4: e.Value = entry.StdCreated; break;
                        case 5: e.Value = entry.StdModified; break;
                        case 6: e.Value = entry.StdMftModified; break;
                        case 7: e.Value = entry.StdAccessed; break;
                        case 8: e.Value = entry.FnCreated; break;
                        case 9: e.Value = entry.FnModified; break;
                        case 10: e.Value = entry.FnMftModified; break;
                        case 11: e.Value = entry.FnAccessed; break;
                    }
                }
            };

            Action applyFilter = () =>
            {
                string pathFilter = txtPath.Text.Trim();
                string minStr = txtMin.Text.Trim();
                string maxStr = txtMax.Text.Trim();

                long minSize = 0;
                long maxSize = long.MaxValue;
                if (!string.IsNullOrEmpty(minStr))
                {
                    if (!long.TryParse(minStr, out minSize) || minSize < 0)
                    {
                        MessageBox.Show("Min size must be a non-negative number (bytes).", "MFT Filter", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        return;
                    }
                }
                if (!string.IsNullOrEmpty(maxStr))
                {
                    if (!long.TryParse(maxStr, out maxSize) || maxSize < 0)
                    {
                        MessageBox.Show("Max size must be a non-negative number (bytes).", "MFT Filter", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        return;
                    }
                }
                if (minSize > maxSize)
                {
                    MessageBox.Show("Min size must be less than or equal to Max size.", "MFT Filter", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                IEnumerable<IR_Collect.MFT.MftParser.MftEntry> query = c.MftEntries ?? new List<IR_Collect.MFT.MftParser.MftEntry>();

                if (!string.IsNullOrEmpty(pathFilter))
                {
                    query = query.Where(x =>
                        (!string.IsNullOrEmpty(x.FullPath) && x.FullPath.IndexOf(pathFilter, StringComparison.OrdinalIgnoreCase) >= 0) ||
                        (!string.IsNullOrEmpty(x.FileName) && x.FileName.IndexOf(pathFilter, StringComparison.OrdinalIgnoreCase) >= 0)
                    );
                }

                query = query.Where(x => x.Size >= minSize && x.Size <= maxSize);

                mftView = query.ToList();
                mftGrid.RowCount = mftView.Count;
                mftGrid.Invalidate();
                mftGrid.Refresh();
            };

            btnApply.Click += (s, e) => applyFilter();
            btnReset.Click += (s, e) => {
                txtPath.Text = "";
                txtMin.Text = "";
                txtMax.Text = "";
                mftView = (c.MftEntries != null) ? new List<IR_Collect.MFT.MftParser.MftEntry>(c.MftEntries) :
                    new List<IR_Collect.MFT.MftParser.MftEntry>();
                mftGrid.RowCount = mftView.Count;
                mftGrid.Invalidate();
                mftGrid.Refresh();
            };

            mftGrid.RowCount = mftView.Count;

            // Show hint when no MFT data (e.g. MFT collection failed or case has no MFT)
            Label mftEmptyHint = new Label();
            mftEmptyHint.AutoSize = false;
            mftEmptyHint.Dock = DockStyle.Fill;
            mftEmptyHint.TextAlign = ContentAlignment.MiddleCenter;
            mftEmptyHint.ForeColor = Color.Gray;
            mftEmptyHint.Font = new Font(mftEmptyHint.Font.FontFamily, 10);
            mftEmptyHint.Text = "此案卷沒有 MFT 資料。\r\n\r\n可能原因：\r\n• 尚未執行「Local Collect」或未匯入含 MFT 的案卷\r\n• 請以「系統管理員」執行 Local Collect 以收集 MFT\r\n• 若已用管理員收集仍為空，可能是 MFT 讀取失敗（防毒/磁碟鎖定），請查看 logs\\ir_collect.log";
            mftEmptyHint.Visible = (c.MftEntries == null || c.MftEntries.Count == 0);
            mftPage.Controls.Add(mftGrid);
            mftPage.Controls.Add(mftEmptyHint);
            mftPage.Controls.Add(mftFilterPanel);
            subLogs.TabPages.Add(mftPage);

            var browserTab = CreateBrowserFilesTab(c);
            if (browserTab != null) subLogs.TabPages.Add(browserTab);



            if (subLogs.TabCount > 0) { pageLogs.Controls.Add(subLogs); hostTabs.TabPages.Add(pageLogs); }

            // 4. File Activity
            TabPage pageFiles = new TabPage("File Activity");
            TabControl subFiles = CreateSubTabControl();
            AddTabIfExists(subFiles, ResolveArtifactPathFlexible(c, ArtifactNames.RecentFilesCsv) != null ? CreateDeferredTab("Recent Files", () => LoadCsvDataForTab(c, "Recent Files", ArtifactNames.RecentFilesCsv), data => BuildCsvTabFromData("Recent Files", data as CsvTabData)) : null);
            AddTabIfExists(subFiles, ResolveArtifactPathFlexible(c, ArtifactNames.Filesystem7DaysCsv) != null ? CreateDeferredTab("Recent Mod (7d)", () => LoadCsvDataForTab(c, "Recent Mod (7d)", ArtifactNames.Filesystem7DaysCsv), data => BuildCsvTabFromData("Recent Mod (7d)", data as CsvTabData)) : null);
            AddTabIfExists(subFiles, ResolveArtifactPathFlexible(c, ArtifactNames.JumpListsCsv) != null ? CreateDeferredTab("Jump Lists", () => LoadCsvDataForTab(c, "Jump Lists", ArtifactNames.JumpListsCsv), data => BuildCsvTabFromData("Jump Lists", data as CsvTabData)) : null);
            AddTabIfExists(subFiles, GetArtifactSubFolderPath(c, "JumpLists") != null ? CreateDeferredTab("Jump Lists (Raw)", () => CreateFileListTab(c, "Jump Lists (Raw)", "JumpLists")) : null);
            AddTabIfExists(subFiles, GetArtifactSubFolderPath(c, "LnkFiles") != null ? CreateDeferredTab("Lnk Files (Dump)", () => CreateFileListTab(c, "Lnk Files (Dump)", "LnkFiles")) : null);
            AddTabIfExists(subFiles, GetArtifactSubFolderPath(c, "Prefetch") != null ? CreateDeferredTab("Prefetch (Dump)", () => CreateFileListTab(c, "Prefetch (Dump)", "Prefetch")) : null);
            
            if (subFiles.TabCount > 0) { pageFiles.Controls.Add(subFiles); hostTabs.TabPages.Add(pageFiles); }

            // 5. Integrity Check
            TabPage pageIntegrity = new TabPage("Integrity Check");
            TabControl subIntegrity = CreateSubTabControl();
            var subFileCheck = ResolveArtifactPathFlexible(c, ArtifactNames.FileIntegrityCsv) != null ? CreateDeferredTab("File Check", () => CreateFileCheckTab(c, "File Check", ArtifactNames.FileIntegrityCsv)) : null;
            if (subFileCheck != null) subIntegrity.TabPages.Add(subFileCheck);
            if (subIntegrity.TabCount > 0) { pageIntegrity.Controls.Add(subIntegrity); hostTabs.TabPages.Add(pageIntegrity); }

            // Re-generate the custom nav bar
            UpdateTabNav(hostTabs);
        }

        private TabPage CreateSummaryTab(IR_Collect.Analysis.CaseData c)
        {
            TabPage p = new TabPage("Summary");

            var topPanel = new FlowLayoutPanel();
            topPanel.Dock = DockStyle.Top;
            topPanel.Height = 50;
            topPanel.Padding = new Padding(8, 6, 8, 4);
            topPanel.BackColor = Color.WhiteSmoke;
            topPanel.FlowDirection = FlowDirection.LeftToRight;
            topPanel.WrapContents = true;
            topPanel.AutoSize = false;

            Button btnExport = new Button();
            btnExport.Text = "Export Summary JSON";
            btnExport.Size = new Size(200, 28);
            btnExport.BackColor = Color.SteelBlue;
            btnExport.ForeColor = Color.White;
            btnExport.FlatStyle = FlatStyle.Flat;
            btnExport.Margin = new Padding(0, 0, 10, 0);

            Button btnAnalyze = new Button();
            btnAnalyze.Text = "AI Analyze";
            btnAnalyze.Size = new Size(140, 28);
            btnAnalyze.BackColor = Color.MediumSeaGreen;
            btnAnalyze.ForeColor = Color.White;
            btnAnalyze.FlatStyle = FlatStyle.Flat;
            btnAnalyze.Margin = new Padding(0, 0, 10, 0);

            Button btnExportHtml = new Button();
            btnExportHtml.Text = "Export HTML Report";
            btnExportHtml.Size = new Size(180, 28);
            btnExportHtml.BackColor = Color.DarkSlateGray;
            btnExportHtml.ForeColor = Color.White;
            btnExportHtml.FlatStyle = FlatStyle.Flat;
            btnExportHtml.Margin = new Padding(0, 0, 0, 0);

            TextBox txt = new TextBox();
            txt.Multiline = true;
            txt.Dock = DockStyle.Fill;
            txt.ScrollBars = ScrollBars.Vertical;
            txt.Font = codeFont;
            txt.ReadOnly = true;
            txt.MaxLength = 0;

            GroupBox workflowBox = new GroupBox();
            workflowBox.Text = "Analyst Workflow";
            workflowBox.Dock = DockStyle.Bottom;
            workflowBox.Height = 236;
            workflowBox.Padding = new Padding(10, 22, 10, 10);

            CheckBox chkBookmarked = new CheckBox();
            chkBookmarked.Text = "Bookmarked";
            chkBookmarked.Left = 14;
            chkBookmarked.Top = 28;
            chkBookmarked.Width = 110;

            Label lblPriority = new Label();
            lblPriority.Text = "Priority:";
            lblPriority.Left = 140;
            lblPriority.Top = 31;
            lblPriority.AutoSize = true;

            ComboBox comboPriority = new ComboBox();
            comboPriority.Left = 198;
            comboPriority.Top = 27;
            comboPriority.Width = 120;
            comboPriority.DropDownStyle = ComboBoxStyle.DropDownList;
            comboPriority.Items.AddRange(new object[] { "(unset)", "Low", "Medium", "High", "Critical" });

            Label lblTags = new Label();
            lblTags.Text = "Tags:";
            lblTags.Left = 338;
            lblTags.Top = 31;
            lblTags.AutoSize = true;

            TextBox txtTags = new TextBox();
            txtTags.Left = 382;
            txtTags.Top = 27;
            txtTags.Width = 260;

            Label lblHypothesis = new Label();
            lblHypothesis.Text = "Hypothesis:";
            lblHypothesis.Left = 14;
            lblHypothesis.Top = 64;
            lblHypothesis.AutoSize = true;

            TextBox txtHypothesis = new TextBox();
            txtHypothesis.Left = 92;
            txtHypothesis.Top = 60;
            txtHypothesis.Width = 550;
            txtHypothesis.Height = 56;
            txtHypothesis.Multiline = true;
            txtHypothesis.ScrollBars = ScrollBars.Vertical;

            Label lblNotes = new Label();
            lblNotes.Text = "Notes:";
            lblNotes.Left = 14;
            lblNotes.Top = 126;
            lblNotes.AutoSize = true;

            TextBox txtNotes = new TextBox();
            txtNotes.Left = 92;
            txtNotes.Top = 122;
            txtNotes.Width = 550;
            txtNotes.Height = 64;
            txtNotes.Multiline = true;
            txtNotes.ScrollBars = ScrollBars.Vertical;

            Button btnSaveWorkflow = new Button();
            btnSaveWorkflow.Text = "Save Workflow";
            btnSaveWorkflow.Left = 92;
            btnSaveWorkflow.Top = 192;
            btnSaveWorkflow.Width = 120;
            btnSaveWorkflow.Height = 28;

            Button btnReloadWorkflow = new Button();
            btnReloadWorkflow.Text = "Reload";
            btnReloadWorkflow.Left = 220;
            btnReloadWorkflow.Top = 192;
            btnReloadWorkflow.Width = 90;
            btnReloadWorkflow.Height = 28;

            Label lblWorkflowPath = new Label();
            lblWorkflowPath.Left = 322;
            lblWorkflowPath.Top = 198;
            lblWorkflowPath.Width = 560;
            lblWorkflowPath.Height = 24;
            lblWorkflowPath.Text = "Sidecar: " + (c.AnalystWorkflowPath ?? "(unavailable)");

            Action loadWorkflowControls = () =>
            {
                var workflow = c.AnalystWorkflow ?? new IR_Collect.Analysis.AnalystWorkflowState();
                chkBookmarked.Checked = workflow.Bookmarked;
                string priority = string.IsNullOrWhiteSpace(workflow.Priority) ? "(unset)" : workflow.Priority;
                int idx = comboPriority.Items.IndexOf(priority);
                comboPriority.SelectedIndex = idx >= 0 ? idx : 0;
                txtTags.Text = workflow.Tags != null ? string.Join(", ", workflow.Tags.ToArray()) : "";
                txtHypothesis.Text = workflow.Hypothesis ?? "";
                txtNotes.Text = workflow.Notes ?? "";
                lblWorkflowPath.Text = "Sidecar: " + (c.AnalystWorkflowPath ?? "(unavailable)");
            };

            loadWorkflowControls();

            var sb = new StringBuilder();
            sb.AppendLine("Host: " + (string.IsNullOrEmpty(c.Hostname) ? "(unknown)" : c.Hostname));
            sb.AppendLine("CaseID: " + (string.IsNullOrEmpty(c.CaseID) ? "(unknown)" : c.CaseID));
            sb.AppendLine("Artifacts: " + c.Artifacts.Count.ToString("N0"));

            // MFT stats
            int mftCount = (c.MftEntries != null) ? c.MftEntries.Count : 0;
            sb.AppendLine("MFT Records: " + mftCount.ToString("N0"));
            var latestMft = GetLatestMftTime(c.MftEntries);
            if (latestMft.Year > 1980)
                sb.AppendLine("Latest MFT Activity: " + latestMft.ToString("yyyy-MM-dd HH:mm:ss"));

            // CSV counts
            AppendCount(sb, "Processes", CountCsvRows(GetArtifactPath(c, ArtifactNames.ProcessListCsv)));
            AppendCount(sb, "Logon Sessions", CountCsvRows(GetArtifactPath(c, ArtifactNames.LogonSessionsCsv)));
            AppendCount(sb, "Network Resources", CountCsvRows(GetArtifactPath(c, ArtifactNames.NetworkResourcesCsv)));
            AppendCount(sb, "Server Connections", CountCsvRows(GetArtifactPath(c, ArtifactNames.ServerConnectionsCsv)));
            AppendCount(sb, "Services", CountCsvRows(GetArtifactPath(c, ArtifactNames.ServicesCsv)));
            AppendCount(sb, "Autoruns", CountCsvRows(GetArtifactPath(c, ArtifactNames.AutorunsRegistryCsv)));
            AppendCount(sb, "BAM / DAM", CountCsvRows(GetArtifactPath(c, ArtifactNames.BamDamCsv)));
            AppendCount(sb, "BITS Jobs", CountCsvRows(GetArtifactPath(c, ArtifactNames.BitsJobsCsv)));
            AppendCount(sb, "WMI Persistence", CountCsvRows(GetArtifactPath(c, ArtifactNames.WmiPersistenceCsv)));
            AppendCount(sb, "ShimCache Rows", CountCsvRows(GetArtifactPath(c, ArtifactNames.ShimCacheCsv)));
            AppendCount(sb, "ShimCache Entries", CountCsvRows(GetArtifactPath(c, ArtifactNames.ShimCacheEntriesCsv)));
            AppendCount(sb, "Amcache Programs", CountCsvRows(GetArtifactPath(c, ArtifactNames.AmcacheProgramsCsv)));
            AppendCount(sb, "Amcache Files", CountCsvRows(GetArtifactPath(c, ArtifactNames.AmcacheFilesCsv)));
            AppendCount(sb, "SRUM Network Usage", CountCsvRows(GetArtifactPath(c, ArtifactNames.SrumNetworkUsageCsv)));
            AppendCount(sb, "SRUM App Usage", CountCsvRows(GetArtifactPath(c, ArtifactNames.SrumAppUsageCsv)));
            AppendCount(sb, "Installed Software", CountCsvRows(GetArtifactPath(c, ArtifactNames.InstalledSoftwareCsv)));
            AppendCount(sb, "Recent Files", CountCsvRows(GetArtifactPath(c, ArtifactNames.RecentFilesCsv)));
            AppendCount(sb, "Registry Activity", CountCsvRows(GetArtifactPath(c, ArtifactNames.ActivityTimelineCsv)));
            AppendCount(sb, "USN Journal", CountCsvRows(GetArtifactPath(c, ArtifactNames.UsnJournalCsv)));
            AppendCount(sb, "ShellBags (parsed)", CountCsvRows(GetArtifactPath(c, ArtifactNames.ShellBagsCsv)));

            // Scheduled Tasks (XML)
            AppendCount(sb, "Scheduled Tasks", CountXmlTasks(GetArtifactPath(c, ArtifactNames.ScheduledTasksXml)));

            // Event logs & browser artifacts
            AppendCount(sb, "Event Logs", CountAvailableEventLogs(c));
            AppendCount(sb, "BrowsingHistoryView", CountBrowserArtifacts(c));

            sb.AppendLine();
            sb.AppendLine("Collection Coverage:");
            if (c.CollectionCoverage == null || c.CollectionCoverage.Steps == null || c.CollectionCoverage.Steps.Count == 0)
            {
                sb.AppendLine("- No collection_coverage.json available.");
            }
            else
            {
                if (!string.IsNullOrWhiteSpace(c.CollectionCoverage.CollectionModeProfile))
                    sb.AppendLine("- Collection mode profile: " + CollectionModeProfileHelper.Normalize(c.CollectionCoverage.CollectionModeProfile));
                sb.AppendLine("- Overall: " + FormatCollectionCoverageStatus(c.CollectionCoverage));
                sb.AppendLine("- Collector: " + FormatCollectionRuntime(c.CollectionCoverage));
                foreach (var line in BuildCollectionCoverageSummaryLines(c.CollectionCoverage, c.CollectionCoverage.Steps.Count))
                    sb.AppendLine("- " + line);
            }

            sb.AppendLine();
            sb.AppendLine("Memory acquisition:");
            AppendMemorySummaryLines(
                sb,
                GetCollectionCoverageStep(c.CollectionCoverage, "Memory acquisition"),
                c.MemoryAcquisitionMeta != null ? c.MemoryAcquisitionMeta.BuildSummaryLine() : null,
                "memory_acquisition.json");

            sb.AppendLine();
            sb.AppendLine("Memory analysis handoff:");
            AppendMemorySummaryLines(
                sb,
                GetCollectionCoverageStep(c.CollectionCoverage, "Memory analysis handoff"),
                c.MemoryAnalysisMeta != null ? c.MemoryAnalysisMeta.BuildSummaryLine() : null,
                "memory_analysis.json");

            if (c.MemoryAcquisitionMeta != null || c.MemoryAnalysisMeta != null)
            {
                sb.AppendLine();
                sb.AppendLine("Memory handoff note:");
                sb.AppendLine("- " + MemoryHandoffHelper.CoverageVsSidecarGuidance);
            }

            sb.AppendLine();
            sb.AppendLine("Fact Store Cache:");
            sb.AppendLine("- Status: " + GetFactStoreStatus(c));
            sb.AppendLine("- Freshness: " + FormatFactStoreFreshnessStatus(c));
            if (!string.IsNullOrWhiteSpace(c.FactStoreFreshnessDetail))
                sb.AppendLine("- Detail: " + c.FactStoreFreshnessDetail);

            sb.AppendLine();
            sb.AppendLine("Analyst Workflow:");
            foreach (var line in BuildAnalystWorkflowSummaryLines(c))
                sb.AppendLine("- " + line);

            sb.AppendLine();
            sb.AppendLine("Guided Hunt:");
            foreach (var line in BuildGuidedHuntSummaryLines(c))
                sb.AppendLine("- " + line);

            sb.AppendLine();
            sb.AppendLine("Event Log Highlights (sampled):");
            var highlights = GetEventLogHighlights(c);
            if (highlights.Count == 0)
            {
                sb.AppendLine("- None found or logs missing");
            }
            else
            {
                foreach (var h in highlights) sb.AppendLine("- " + h);
            }
            sb.AppendLine("Note: Highlights are sampled (max 5000 records per log).");

            sb.AppendLine();
            sb.AppendLine("Parser Notes:");
            var parserNotes = BuildSummaryParserNotes(c);
            if (parserNotes.Count == 0)
            {
                sb.AppendLine("- None.");
            }
            else
            {
                foreach (var note in parserNotes) sb.AppendLine("- " + note);
            }

            sb.AppendLine();
            sb.AppendLine("Observed Facts:");
            if (c.FactStoreBuilding && (c.FactStore == null || c.FactStore.Count == 0))
            {
                sb.AppendLine("- Fact Store is still building.");
            }
            else if (c.FactStore == null || c.FactStore.Count == 0)
            {
                sb.AppendLine("- Fact Store not built or no facts available.");
            }
            else
            {
                sb.AppendLine("- Total facts: " + c.FactStore.Count.ToString("N0"));
                foreach (var fact in GetFactSamples(c, 8))
                    sb.AppendLine("- " + FormatFactSummaryLine(fact));
            }

            sb.AppendLine();
            sb.AppendLine("Analysis Note:");
            sb.AppendLine("- Observed facts remain primary. Guided Hunt, when enabled, adds explainable ATT&CK-mapped leads without changing the underlying facts.");
            sb.AppendLine("- Time Type / Confidence show whether a timestamp comes from an event, metadata, observation, or remains unknown.");
            sb.AppendLine("- Review observed facts directly, or export JSON for analyst/AI-assisted interpretation.");
            sb.AppendLine("- Fact provenance carries collection step/status, parse level, fallback usage, and collection privilege context.");

            txt.Text = sb.ToString();
            topPanel.Controls.Add(btnExport);
            topPanel.Controls.Add(btnAnalyze);
            topPanel.Controls.Add(btnExportHtml);
            p.Controls.Add(txt);
            workflowBox.Controls.Add(chkBookmarked);
            workflowBox.Controls.Add(lblPriority);
            workflowBox.Controls.Add(comboPriority);
            workflowBox.Controls.Add(lblTags);
            workflowBox.Controls.Add(txtTags);
            workflowBox.Controls.Add(lblHypothesis);
            workflowBox.Controls.Add(txtHypothesis);
            workflowBox.Controls.Add(lblNotes);
            workflowBox.Controls.Add(txtNotes);
            workflowBox.Controls.Add(btnSaveWorkflow);
            workflowBox.Controls.Add(btnReloadWorkflow);
            workflowBox.Controls.Add(lblWorkflowPath);
            p.Controls.Add(workflowBox);
            p.Controls.Add(topPanel);

            btnExport.Click += (s, e) =>
            {
                try
                {
                    var payload = BuildSummaryPayload(c);
                    SaveFileDialog sfd = new SaveFileDialog();
                    sfd.Filter = "JSON Files|*.json";
                    sfd.FileName = string.Format("{0}_summary.json", c.Hostname);
                    if (sfd.ShowDialog() == DialogResult.OK)
                    {
                        IR_Collect.Analysis.SummaryExport.SaveToFile(payload, sfd.FileName);
                        MessageBox.Show("Summary JSON saved.");
                    }
                }
                catch (Exception ex) { MessageBox.Show("Export failed: " + ex.Message, "Summary JSON", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
            };

            btnExportHtml.Click += (s, e) =>
            {
                SaveFileDialog sfd = new SaveFileDialog();
                sfd.Filter = "HTML Files|*.html";
                sfd.FileName = string.Format("{0}_report.html", c.Hostname ?? "case");
                if (sfd.ShowDialog() == DialogResult.OK)
                {
                    try
                    {
                        string html = BuildHtmlReport(c);
                        File.WriteAllText(sfd.FileName, html, new System.Text.UTF8Encoding(false));
                        MessageBox.Show("HTML report saved.");
                    }
                    catch (Exception ex) { MessageBox.Show("Export failed: " + ex.Message, "HTML Report", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
                }
            };

            btnAnalyze.Click += (s, e) =>
            {
                try
                {
                    if (CollectionModeProfileHelper.BlocksAiAnalyze(config))
                    {
                        MessageBox.Show(
                            "AI Analyze is disabled while collection mode profile is ForensicStrict.\n\n" +
                            "Use Summary JSON export (or other offline review steps) instead. Change profile under Advanced → Settings if outbound AI is explicitly approved for this workstation.",
                            "AI Analyze blocked",
                            MessageBoxButtons.OK,
                            MessageBoxIcon.Warning);
                        return;
                    }

                    string endpoint = (config.Get("AiApiEndpoint") ?? "").Trim();
                    string apiKey = config.Get("AiApiKey");
                    string profile = IR_Collect.Analysis.SummaryPayloadAiRedactor.NormalizeProfile(config.Get("AiExportRedactionProfile"));
                    var payload = BuildSummaryPayload(c);
                    var forAi = IR_Collect.Analysis.SummaryExport.CloneForSerialization(payload);
                    IR_Collect.Analysis.SummaryPayloadAiRedactor.Apply(forAi, profile);
                    string json = IR_Collect.Analysis.SummaryExport.Serialize(forAi);

                    if (string.IsNullOrEmpty(endpoint))
                    {
                        Clipboard.SetText(json);
                        ShowTextDialog("AI Input (copied to clipboard)", json);
                        MessageBox.Show("AI endpoint not set. JSON copied to clipboard (uses redaction profile: " + profile + ").", "AI Analyze", MessageBoxButtons.OK, MessageBoxIcon.Information);
                        return;
                    }

                    if (!IR_Collect.Utils.EndpointGovernance.IsEndpointAllowed(endpoint, config.Get("AiEndpointAllowlist")))
                    {
                        MessageBox.Show(
                            "AI request blocked: this endpoint is not allowed by the AI endpoint allowlist.\nConfigure prefixes under Advanced → Settings (empty allowlist blocks all outbound AI POST).",
                            "AI Analyze",
                            MessageBoxButtons.OK,
                            MessageBoxIcon.Warning);
                        return;
                    }

                    string confirmMsg = "Send AI request?\n\nEndpoint: " + endpoint + "\nRedaction profile: " + profile + "\n\nOnly this redacted JSON will be posted.";
                    if (MessageBox.Show(confirmMsg, "AI Outbound", MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2) != DialogResult.Yes)
                        return;

                    try
                    {
                        string response = SendAiRequest(endpoint, apiKey, json);
                        ShowTextDialog("AI Response", response);
                    }
                    catch (Exception ex)
                    {
                        ShowTextDialog("AI Error", ex.Message);
                    }
                }
                catch (Exception ex) { ShowTextDialog("AI Error", ex.Message); }
            };

            btnSaveWorkflow.Click += (s, e) =>
            {
                var workflow = c.AnalystWorkflow ?? new IR_Collect.Analysis.AnalystWorkflowState();
                workflow.Bookmarked = chkBookmarked.Checked;
                workflow.Priority = comboPriority.SelectedIndex <= 0 ? "" : (comboPriority.SelectedItem != null ? comboPriority.SelectedItem.ToString() : "");
                workflow.Tags = IR_Collect.Analysis.AnalystWorkflowStore.NormalizeTags(txtTags.Text);
                workflow.Hypothesis = txtHypothesis.Text ?? "";
                workflow.Notes = txtNotes.Text ?? "";
                c.AnalystWorkflow = workflow;
                if (string.IsNullOrWhiteSpace(c.AnalystWorkflowPath))
                    c.AnalystWorkflowPath = IR_Collect.Analysis.AnalystWorkflowStore.ResolvePath(c.SourceZip, c.ExtractPath);

                string error;
                if (!IR_Collect.Analysis.AnalystWorkflowStore.SaveToFile(workflow, c.AnalystWorkflowPath, out error))
                {
                    MessageBox.Show("Workflow save failed: " + error, "Analyst Workflow", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                BuildHostTabs(c);
                SelectTopLevelHostTab("Summary");
                MessageBox.Show("Workflow sidecar saved.", "Analyst Workflow", MessageBoxButtons.OK, MessageBoxIcon.Information);
            };

            btnReloadWorkflow.Click += (s, e) =>
            {
                try
                {
                    c.AnalystWorkflow = IR_Collect.Analysis.AnalystWorkflowStore.LoadFromFile(c.AnalystWorkflowPath);
                    loadWorkflowControls();
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Workflow reload failed: " + ex.Message, "Analyst Workflow", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            };

            return p;
        }

        private string GetFactStoreStatus(IR_Collect.Analysis.CaseData c)
        {
            if (c == null) return "not_built";
            if (c.FactStoreBuilding && (c.FactStore == null || c.FactStore.Count == 0)) return "building";
            if (c.FactStore == null) return "not_built";
            return c.FactStore.Count > 0 ? "ready" : "empty";
        }

        private string FormatFactStoreFreshnessStatus(IR_Collect.Analysis.CaseData c)
        {
            string status = c != null ? (c.FactStoreFreshnessStatus ?? "") : "";
            if (string.IsNullOrWhiteSpace(status)) status = "unknown";
            return status;
        }

        private string FormatCollectionCoverageStatus(CollectionCoverageReport report)
        {
            if (report == null) return "unknown";
            string overall = string.IsNullOrWhiteSpace(report.OverallStatus) ? "unknown" : report.OverallStatus;
            return string.Format("{0} (complete {1}, partial {2}, failed {3}, skipped {4}, missing {5})",
                overall,
                report.CompletedSteps,
                report.PartialSteps,
                report.FailedSteps,
                report.SkippedSteps,
                report.MissingSteps);
        }

        private string FormatCollectionRuntime(CollectionCoverageReport report)
        {
            if (report == null)
                return "unknown";

            var parts = new List<string>();
            if (!string.IsNullOrWhiteSpace(report.CollectorUser))
                parts.Add(report.CollectorUser);
            if (!string.IsNullOrWhiteSpace(report.CollectorPrivilegeState))
                parts.Add(report.CollectorPrivilegeState);
            if (!string.IsNullOrWhiteSpace(report.BackupPrivilegeStatus))
                parts.Add(report.BackupPrivilegeStatus);
            return parts.Count > 0 ? string.Join(" | ", parts.ToArray()) : "unknown";
        }

        private List<string> BuildCollectionCoverageSummaryLines(CollectionCoverageReport report, int maxCount)
        {
            var lines = new List<string>();
            if (report == null || report.Steps == null || report.Steps.Count == 0 || maxCount <= 0)
                return lines;

            foreach (var step in report.Steps.Take(maxCount))
            {
                if (step == null) continue;
                string detail = step.Detail ?? "";
                if (step.ArtifactsMissing != null && step.ArtifactsMissing.Count > 0)
                    detail = string.IsNullOrWhiteSpace(detail) ? ("missing: " + string.Join(", ", step.ArtifactsMissing.ToArray())) : (detail + "; missing: " + string.Join(", ", step.ArtifactsMissing.ToArray()));
                lines.Add((step.Step ?? "step") + " = " + (step.Status ?? "unknown") + (string.IsNullOrWhiteSpace(detail) ? "" : (" (" + detail + ")")));
            }

            return lines;
        }

        private CollectionCoverageStep GetCollectionCoverageStep(CollectionCoverageReport report, string stepName)
        {
            if (report == null || report.Steps == null || string.IsNullOrWhiteSpace(stepName))
                return null;

            return report.Steps.FirstOrDefault(step =>
                step != null &&
                string.Equals(step.Step, stepName, StringComparison.OrdinalIgnoreCase));
        }

        private string FormatCoverageStepSummary(CollectionCoverageStep step)
        {
            if (step == null)
                return "coverage unavailable";

            string detail = step.Detail ?? "";
            if (step.ArtifactsMissing != null && step.ArtifactsMissing.Count > 0)
                detail = string.IsNullOrWhiteSpace(detail)
                    ? ("missing: " + string.Join(", ", step.ArtifactsMissing.ToArray()))
                    : (detail + "; missing: " + string.Join(", ", step.ArtifactsMissing.ToArray()));
            return (step.Status ?? "unknown") + (string.IsNullOrWhiteSpace(detail) ? "" : (" (" + detail + ")"));
        }

        private void AppendMemorySummaryLines(StringBuilder sb, CollectionCoverageStep coverageStep, string sidecarSummary, string sidecarFileName)
        {
            if (sb == null)
                return;

            if (coverageStep != null)
                sb.AppendLine("- Coverage: " + FormatCoverageStepSummary(coverageStep));
            else
                sb.AppendLine("- Coverage: unavailable.");

            if (!string.IsNullOrWhiteSpace(sidecarSummary))
                sb.AppendLine("- Sidecar: " + sidecarSummary);
            else
                sb.AppendLine("- Sidecar: " + sidecarFileName + " not present in case.");
        }

        private List<string> BuildAnalystWorkflowSummaryLines(IR_Collect.Analysis.CaseData c)
        {
            var lines = new List<string>();
            var workflow = c != null ? c.AnalystWorkflow : null;
            if (workflow == null)
            {
                lines.Add("No workflow annotations saved.");
                return lines;
            }

            lines.Add("Bookmarked = " + (workflow.Bookmarked ? "yes" : "no"));
            lines.Add("Priority = " + (string.IsNullOrWhiteSpace(workflow.Priority) ? "(unset)" : workflow.Priority));
            lines.Add("Tags = " + (workflow.Tags != null && workflow.Tags.Count > 0 ? string.Join(", ", workflow.Tags.ToArray()) : "(none)"));
            lines.Add("Hypothesis = " + TrimPreviewText(workflow.Hypothesis, 180));
            lines.Add("Notes = " + TrimPreviewText(workflow.Notes, 180));
            if (!string.IsNullOrWhiteSpace(workflow.UpdatedAt))
                lines.Add("Updated = " + workflow.UpdatedAt);
            return lines;
        }

        private IR_Collect.Analysis.GuidedHuntResult GetGuidedHuntResult(IR_Collect.Analysis.CaseData c)
        {
            return IR_Collect.Analysis.GuidedHuntPack.Evaluate(c);
        }

        private List<string> BuildGuidedHuntSummaryLines(IR_Collect.Analysis.CaseData c)
        {
            var lines = new List<string>();
            var guidedHunt = GetGuidedHuntResult(c);
            if (guidedHunt == null)
            {
                lines.Add("Unavailable.");
                return lines;
            }

            lines.Add("Enabled = " + (guidedHunt.Enabled ? "yes" : "no"));
            lines.Add("Facts evaluated = " + guidedHunt.FactCountEvaluated.ToString("N0"));
            lines.Add("Rule matches = " + guidedHunt.RuleMatches.Count.ToString());
            lines.Add("Hypothesis templates = " + guidedHunt.HypothesisTemplates.Count.ToString());

            foreach (var match in guidedHunt.RuleMatches.Take(4))
            {
                lines.Add(string.Format(
                    "{0} [{1}] {2} -> {3} {4}: {5}",
                    match.Id ?? "",
                    match.Severity ?? "",
                    match.Title ?? "",
                    match.AttackTechniqueId ?? "",
                    match.AttackTechniqueName ?? "",
                    TrimPreviewText(match.Summary, 180)));
            }
            if (guidedHunt.RuleMatches.Count > 4)
                lines.Add("+" + (guidedHunt.RuleMatches.Count - 4).ToString() + " more rule match(es).");

            foreach (var hypothesis in guidedHunt.HypothesisTemplates.Take(3))
                lines.Add("Hypothesis template = " + TrimPreviewText(hypothesis.Title + ": " + hypothesis.Question, 180));
            if (guidedHunt.HypothesisTemplates.Count > 3)
                lines.Add("+" + (guidedHunt.HypothesisTemplates.Count - 3).ToString() + " more hypothesis template(s).");

            foreach (var note in guidedHunt.Notes.Take(2))
                lines.Add("Note = " + TrimPreviewText(note, 180));
            return lines;
        }

        private List<IR_Collect.Analysis.Correlation.Fact> GetFactSamples(IR_Collect.Analysis.CaseData c, int maxCount)
        {
            if (c == null || c.FactStore == null || c.FactStore.Facts == null || c.FactStore.Facts.Count == 0 || maxCount <= 0)
                return new List<IR_Collect.Analysis.Correlation.Fact>();

            return c.FactStore.Facts
                .OrderByDescending(f => f != null && f.Time.Year > 1980 ? f.Time : DateTime.MinValue)
                .ThenBy(f => f != null ? (f.Source ?? "") : "")
                .Take(maxCount)
                .ToList();
        }

        private string TrimPreviewText(string value, int maxLength)
        {
            string text = (value ?? "").Replace("\r", " ").Replace("\n", " ").Trim();
            if (string.IsNullOrWhiteSpace(text))
                return "(empty)";
            if (text.Length <= maxLength)
                return text;
            return text.Substring(0, Math.Max(0, maxLength - 3)) + "...";
        }

        private Dictionary<string, int> BuildFactSourceCounts(IR_Collect.Analysis.CaseData c)
        {
            var result = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            if (c == null || c.FactStore == null || c.FactStore.Facts == null) return result;

            foreach (var fact in c.FactStore.Facts)
            {
                string key = fact != null ? (fact.Source ?? "") : "";
                if (string.IsNullOrWhiteSpace(key)) key = "Unknown";
                int count;
                result[key] = result.TryGetValue(key, out count) ? (count + 1) : 1;
            }

            return result;
        }

        private Dictionary<string, int> BuildEntityTypeCounts(IR_Collect.Analysis.CaseData c)
        {
            var result = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            if (c == null || c.FactStore == null || c.FactStore.Facts == null) return result;

            foreach (var fact in c.FactStore.Facts)
            {
                if (fact == null || fact.EntityRefs == null) continue;
                foreach (var entity in fact.EntityRefs)
                {
                    string key = entity != null ? (entity.Type ?? "") : "";
                    if (string.IsNullOrWhiteSpace(key)) key = "Unknown";
                    int count;
                    result[key] = result.TryGetValue(key, out count) ? (count + 1) : 1;
                }
            }

            return result;
        }

        private List<string> BuildSummaryParserNotes(IR_Collect.Analysis.CaseData c)
        {
            var notes = new List<string>();
            notes.Add("This export preserves observed facts only. Optional Guided Hunt output, when enabled, remains a separate explainable overlay and does not modify the underlying facts.");
            notes.Add("TimeKind and TimeConfidence describe whether a timestamp comes from an event record, metadata, observation, or remains unknown.");
            notes.Add("RawRef points back to the original artifact row or record when available; SourceFile identifies the originating artifact file when known.");
            notes.Add("CollectionStep, CollectionStatus, CollectionPrivilege, ParseLevel, and FallbackUsed provide fact-level provenance for review and downstream automation.");

            bool hasFilteredEventLogs = c != null && GetFilteredEventLogCsvPaths(c).Count > 0;
            if (hasFilteredEventLogs)
                notes.Add("Filtered Event Log CSVs include structured EventData columns; EventLog facts may expose User, Path, CommandLine, RemoteIP, ServiceName, TaskName, ThreatName, and Computer entities.");

            if (c != null && c.CollectionCoverage != null)
                notes.Add("Collection coverage records which major artifact groups were present, partial, failed, or missing at collection time.");

            var guidedHunt = GetGuidedHuntResult(c);
            if (guidedHunt != null && guidedHunt.Enabled)
                notes.Add("Guided Hunt Pack adds ATT&CK-mapped, explainable hunt leads and hypothesis templates on top of facts without emitting a verdict.");

            if (c != null && c.CollectionCoverage != null && !string.IsNullOrWhiteSpace(c.CollectionCoverage.CollectionModeProfile))
                notes.Add("Collection mode profile (from collection_coverage.json): " + CollectionModeProfileHelper.Normalize(c.CollectionCoverage.CollectionModeProfile) + ".");

            bool hasParserNotes = c != null && c.FactStore != null && c.FactStore.Facts != null &&
                c.FactStore.Facts.Any(f => f != null && !string.IsNullOrWhiteSpace(f.ParserNote));
            if (hasParserNotes)
                notes.Add("ParserNote is set only when a fact needed extra parsing context, such as message-derived paths or USN rows without full paths.");
            notes.AddRange(IR_Collect.Analysis.ParserNoteSummaryBuilder.BuildFactParserNoteLines(
                c != null && c.FactStore != null ? c.FactStore.Facts : null,
                10));

            bool hasExecutionStructuredFacts = c != null && c.FactStore != null && c.FactStore.Facts != null &&
                c.FactStore.Facts.Any(f => f != null &&
                    (string.Equals(f.Source, "Amcache", StringComparison.OrdinalIgnoreCase) ||
                     string.Equals(f.Source, "ShimCache", StringComparison.OrdinalIgnoreCase) ||
                     string.Equals(f.Source, "SRUMNetwork", StringComparison.OrdinalIgnoreCase) ||
                     string.Equals(f.Source, "SRUMApp", StringComparison.OrdinalIgnoreCase)));
            if (hasExecutionStructuredFacts)
                notes.Add("Amcache/ShimCache/SRUM parsers are schema-sensitive across Windows versions; parser notes indicate partial field recovery or fallback rows when columns are unavailable.");

            bool hasShellBagsFacts = c != null && c.FactStore != null && c.FactStore.Facts != null &&
                c.FactStore.Facts.Any(f => f != null && string.Equals(f.Source, "ShellBags", StringComparison.OrdinalIgnoreCase));
            if (hasShellBagsFacts)
                notes.Add("ShellBags facts recover folder path segments from exported BagMRU/Bags registry data; they describe folder browsing artifacts, not execution. Fact time (when present) is the UTC last-write time of the source ShellBags_*.reg file, not the original registry key last-write time.");

            bool hasAutorunFacts = c != null && c.FactStore != null && c.FactStore.Facts != null &&
                c.FactStore.Facts.Any(f => f != null && string.Equals(f.Source, "Autorun", StringComparison.OrdinalIgnoreCase));
            if (hasAutorunFacts)
                notes.Add("Autorun facts represent persistence entries observed at collection time; some registry values may remain raw command strings when no executable path could be normalized.");

            bool hasServiceFacts = c != null && c.FactStore != null && c.FactStore.Facts != null &&
                c.FactStore.Facts.Any(f => f != null && string.Equals(f.Source, "Service", StringComparison.OrdinalIgnoreCase));
            if (hasServiceFacts)
                notes.Add("Service facts describe service configuration observed at collection time; they do not prove install time, start time, or execution without corroborating artifacts.");

            bool hasStoredCredentialFacts = c != null && c.FactStore != null && c.FactStore.Facts != null &&
                c.FactStore.Facts.Any(f => f != null && string.Equals(f.Source, "StoredCredential", StringComparison.OrdinalIgnoreCase));
            if (hasStoredCredentialFacts)
                notes.Add("StoredCredential facts represent credentials currently listed by cmdkey at collection time; target-server parsing is heuristic because cmdkey output is text-formatted.");

            bool hasKerberosTicketFacts = c != null && c.FactStore != null && c.FactStore.Facts != null &&
                c.FactStore.Facts.Any(f => f != null && string.Equals(f.Source, "KerberosTicketCache", StringComparison.OrdinalIgnoreCase));
            if (hasKerberosTicketFacts)
                notes.Add("KerberosTicketCache facts represent cached tickets observed by klist; timeline uses ticket Start Time when parseable, otherwise ObservedAtUtc.");

            bool hasScheduledTaskFacts = c != null && c.FactStore != null && c.FactStore.Facts != null &&
                c.FactStore.Facts.Any(f => f != null && string.Equals(f.Source, "ScheduledTask", StringComparison.OrdinalIgnoreCase));
            if (hasScheduledTaskFacts)
                notes.Add("ScheduledTask facts describe task definitions, not task execution times; corroborate with Event Logs for runtime activity.");

            bool hasMftFacts = c != null && c.FactStore != null && c.FactStore.Facts != null &&
                c.FactStore.Facts.Any(f => f != null && string.Equals(f.Source, "MFT", StringComparison.OrdinalIgnoreCase));
            if (hasMftFacts)
                notes.Add("MFT facts are file-system metadata observations, not direct execution events.");

            if (c != null && string.Equals(c.FactStoreFreshnessStatus, "stale", StringComparison.OrdinalIgnoreCase))
                notes.Add("fact_store.db is older than one or more currently loaded source artifacts; rebuild Fact Store to refresh cached facts.");

            if (c != null && c.AnalystWorkflow != null && (c.AnalystWorkflow.Bookmarked || !string.IsNullOrWhiteSpace(c.AnalystWorkflow.Priority) || (c.AnalystWorkflow.Tags != null && c.AnalystWorkflow.Tags.Count > 0)))
                notes.Add("Analyst workflow annotations are stored in a sidecar JSON so bookmarks, tags, notes, and hypotheses can be preserved without modifying the original evidence ZIP.");

            if (c != null && (c.MemoryAcquisitionMeta != null || c.MemoryAnalysisMeta != null))
                notes.Add(MemoryHandoffHelper.CoverageVsSidecarGuidance);

            return notes;
        }

        private void AppendAmcacheParserNoteSummary(IR_Collect.Analysis.CaseData c, List<string> notes)
        {
            if (notes == null || c == null || c.FactStore == null || c.FactStore.Facts == null)
                return;

            var amcacheNotes = c.FactStore.Facts
                .Where(f => f != null &&
                            string.Equals(f.Source, "Amcache", StringComparison.OrdinalIgnoreCase) &&
                            !string.IsNullOrWhiteSpace(f.ParserNote))
                .Select(f => (f.ParserNote ?? "").Trim())
                .Where(v => !string.IsNullOrWhiteSpace(v))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(v => v, StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (amcacheNotes.Count == 0)
                return;

            notes.Add(string.Format("Amcache parser/fallback notes: {0} unique note(s).", amcacheNotes.Count));
            int maxInline = 6;
            foreach (string note in amcacheNotes.Take(maxInline))
                notes.Add("Amcache note: " + note);
            if (amcacheNotes.Count > maxInline)
                notes.Add("Amcache note: +" + (amcacheNotes.Count - maxInline).ToString() + " more (see Facts tab for full list).");
        }

        private string BuildHtmlReport(IR_Collect.Analysis.CaseData c)
        {
            var sb = new StringBuilder();
            sb.AppendLine("<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>IR Report - " + EscapeHtml(c.Hostname ?? "Case") + "</title>");
            sb.AppendLine("<style>body{font-family:Segoe UI,sans-serif;margin:24px;background:#f8f9fa;} h1{color:#333;} h2{margin-top:24px;color:#555;} table{border-collapse:collapse;margin:8px 0;} th,td{border:1px solid #ccc;padding:6px 10px;text-align:left;} th{background:#e0e0e0;} .high{color:#c00;} .medium{color:#a60;} .low{color:#666;} ul{margin:4px 0;}</style></head><body>");
            sb.AppendLine("<h1>IR Collect Report</h1>");
            sb.AppendLine("<p><b>Host:</b> " + EscapeHtml(c.Hostname ?? "") + " &nbsp;|&nbsp; <b>Case ID:</b> " + EscapeHtml(c.CaseID ?? "") + " &nbsp;|&nbsp; <b>Generated:</b> " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "</p>");

            sb.AppendLine("<h2>Artifact counts</h2><table><tr><th>Artifact</th><th>Count</th></tr>");
            sb.AppendLine("<tr><td>Artifacts (files)</td><td>" + GetExtractedArtifactFileCount(c) + "</td></tr>");
            sb.AppendLine("<tr><td>MFT records</td><td>" + ((c.MftEntries != null) ? c.MftEntries.Count.ToString("N0") : "0") + "</td></tr>");
            AppendHtmlCountRow(sb, "Processes", CountCsvRows(GetArtifactPath(c, ArtifactNames.ProcessListCsv)));
            AppendHtmlCountRow(sb, "Logon sessions", CountCsvRows(GetArtifactPath(c, ArtifactNames.LogonSessionsCsv)));
            AppendHtmlCountRow(sb, "Network resources", CountCsvRows(GetArtifactPath(c, ArtifactNames.NetworkResourcesCsv)));
            AppendHtmlCountRow(sb, "Server connections", CountCsvRows(GetArtifactPath(c, ArtifactNames.ServerConnectionsCsv)));
            AppendHtmlCountRow(sb, "Services", CountCsvRows(GetArtifactPath(c, ArtifactNames.ServicesCsv)));
            AppendHtmlCountRow(sb, "Autoruns", CountCsvRows(GetArtifactPath(c, ArtifactNames.AutorunsRegistryCsv)));
            AppendHtmlCountRow(sb, "BAM / DAM", CountCsvRows(GetArtifactPath(c, ArtifactNames.BamDamCsv)));
            AppendHtmlCountRow(sb, "BITS jobs", CountCsvRows(GetArtifactPath(c, ArtifactNames.BitsJobsCsv)));
            AppendHtmlCountRow(sb, "WMI persistence", CountCsvRows(GetArtifactPath(c, ArtifactNames.WmiPersistenceCsv)));
            AppendHtmlCountRow(sb, "ShimCache entries", CountCsvRows(GetArtifactPath(c, ArtifactNames.ShimCacheEntriesCsv)));
            AppendHtmlCountRow(sb, "Amcache programs", CountCsvRows(GetArtifactPath(c, ArtifactNames.AmcacheProgramsCsv)));
            AppendHtmlCountRow(sb, "Amcache files", CountCsvRows(GetArtifactPath(c, ArtifactNames.AmcacheFilesCsv)));
            AppendHtmlCountRow(sb, "SRUM network usage", CountCsvRows(GetArtifactPath(c, ArtifactNames.SrumNetworkUsageCsv)));
            AppendHtmlCountRow(sb, "SRUM app usage", CountCsvRows(GetArtifactPath(c, ArtifactNames.SrumAppUsageCsv)));
            AppendHtmlCountRow(sb, "Scheduled tasks", CountXmlTasks(GetArtifactPath(c, ArtifactNames.ScheduledTasksXml)));
            AppendHtmlCountRow(sb, "USN journal", CountCsvRows(GetArtifactPath(c, ArtifactNames.UsnJournalCsv)));
            AppendHtmlCountRow(sb, "ShellBags (parsed)", CountCsvRows(GetArtifactPath(c, ArtifactNames.ShellBagsCsv)));
            sb.AppendLine("<tr><td>Event logs</td><td>" + CountAvailableEventLogs(c) + "</td></tr>");
            sb.AppendLine("</table>");

            sb.AppendLine("<h2>Collection coverage</h2>");
            if (c.CollectionCoverage == null || c.CollectionCoverage.Steps == null || c.CollectionCoverage.Steps.Count == 0)
            {
                sb.AppendLine("<p>No collection_coverage.json available.</p>");
            }
            else
            {
                if (!string.IsNullOrWhiteSpace(c.CollectionCoverage.CollectionModeProfile))
                    sb.AppendLine("<p><b>Collection mode profile:</b> " + EscapeHtml(CollectionModeProfileHelper.Normalize(c.CollectionCoverage.CollectionModeProfile)) + "</p>");
                sb.AppendLine("<p><b>Overall:</b> " + EscapeHtml(FormatCollectionCoverageStatus(c.CollectionCoverage)) + "</p>");
                sb.AppendLine("<p><b>Collector:</b> " + EscapeHtml(FormatCollectionRuntime(c.CollectionCoverage)) + "</p>");
                sb.AppendLine("<table><tr><th>Step</th><th>Status</th><th>Detail</th><th>Present</th><th>Missing</th></tr>");
                foreach (var step in c.CollectionCoverage.Steps)
                {
                    if (step == null) continue;
                    sb.AppendLine("<tr><td>" + EscapeHtml(step.Step ?? "") + "</td><td>" + EscapeHtml(step.Status ?? "") + "</td><td>" + EscapeHtml(step.Detail ?? "") + "</td><td>" + EscapeHtml(step.ArtifactsPresent != null ? string.Join(", ", step.ArtifactsPresent.ToArray()) : "") + "</td><td>" + EscapeHtml(step.ArtifactsMissing != null ? string.Join(", ", step.ArtifactsMissing.ToArray()) : "") + "</td></tr>");
                }
                sb.AppendLine("</table>");
            }

            sb.AppendLine("<h2>Memory acquisition</h2>");
            var memoryAcquisitionCoverage = GetCollectionCoverageStep(c.CollectionCoverage, "Memory acquisition");
            if (memoryAcquisitionCoverage != null)
                sb.AppendLine("<p><b>Coverage:</b> " + EscapeHtml(FormatCoverageStepSummary(memoryAcquisitionCoverage)) + "</p>");
            if (c.MemoryAcquisitionMeta == null)
                sb.AppendLine("<p>No <code>memory_acquisition.json</code> in this case (not collected or legacy package). Distinguish from skipped or failed steps in <code>collection_coverage.json</code> when present.</p>");
            else
            {
                var mr = c.MemoryAcquisitionMeta;
                sb.AppendLine("<p><b>Sidecar:</b> " + EscapeHtml(mr.BuildSummaryLine() ?? "") + "</p>");
                sb.AppendLine("<p><b>Status:</b> " + EscapeHtml(mr.Status ?? "") + " &nbsp;|&nbsp; <b>Detail:</b> " + EscapeHtml(mr.Detail ?? "") + "</p>");
                if (!string.IsNullOrEmpty(mr.OutputRelativePath))
                    sb.AppendLine("<p><b>Output:</b> " + EscapeHtml(mr.OutputRelativePath) + " &nbsp;|&nbsp; <b>Size:</b> " + mr.OutputFileSizeBytes.ToString("N0") + " bytes</p>");
                if (!string.IsNullOrEmpty(mr.OutputSha256))
                    sb.AppendLine("<p><b>SHA256:</b> " + EscapeHtml(mr.OutputSha256) + "</p>");
                sb.AppendLine("<p><b>Tool:</b> " + EscapeHtml(mr.ToolPath ?? "") + " &nbsp;|&nbsp; <b>Exit code:</b> " + mr.ExitCode.ToString() + " &nbsp;|&nbsp; <b>Collector elevated:</b> " + (mr.CollectorWasAdmin ? "yes" : "no") + "</p>");
                sb.AppendLine("<p>Collection-only metadata; dump contents are not analyzed in-app.</p>");
            }

            sb.AppendLine("<h2>Memory analysis handoff</h2>");
            var memoryAnalysisCoverage = GetCollectionCoverageStep(c.CollectionCoverage, "Memory analysis handoff");
            if (memoryAnalysisCoverage != null)
                sb.AppendLine("<p><b>Coverage:</b> " + EscapeHtml(FormatCoverageStepSummary(memoryAnalysisCoverage)) + "</p>");
            if (c.MemoryAnalysisMeta == null)
                sb.AppendLine("<p>No <code>memory_analysis.json</code> in this case (not analyzed or legacy package).</p>");
            else
            {
                var ar = c.MemoryAnalysisMeta;
                sb.AppendLine("<p><b>Sidecar:</b> " + EscapeHtml(ar.BuildSummaryLine() ?? "") + "</p>");
                sb.AppendLine("<p><b>Status:</b> " + EscapeHtml(ar.Status ?? "") + " &nbsp;|&nbsp; <b>Detail:</b> " + EscapeHtml(ar.Detail ?? "") + "</p>");
                if (!string.IsNullOrEmpty(ar.InputRelativePath))
                    sb.AppendLine("<p><b>Input dump:</b> " + EscapeHtml(ar.InputRelativePath) + "</p>");
                if (!string.IsNullOrEmpty(ar.OutputDirectoryRelativePath))
                    sb.AppendLine("<p><b>Output directory:</b> " + EscapeHtml(ar.OutputDirectoryRelativePath) + " &nbsp;|&nbsp; <b>Files:</b> " + ar.OutputFileCount.ToString("N0") + " &nbsp;|&nbsp; <b>Total bytes:</b> " + ar.OutputTotalBytes.ToString("N0") + "</p>");
                sb.AppendLine("<p><b>Tool:</b> " + EscapeHtml(ar.ToolPath ?? "") + " &nbsp;|&nbsp; <b>Exit code:</b> " + ar.ExitCode.ToString() + " &nbsp;|&nbsp; <b>Collector elevated:</b> " + (ar.CollectorWasAdmin ? "yes" : "no") + "</p>");
                sb.AppendLine("<p>Handoff metadata only; any generated files under <code>MemoryAnalysis</code> remain external-tool outputs and are not interpreted as in-app verdicts.</p>");
            }

            if (c.MemoryAcquisitionMeta != null || c.MemoryAnalysisMeta != null)
                sb.AppendLine("<p><em>" + EscapeHtml(MemoryHandoffHelper.CoverageVsSidecarGuidance) + "</em></p>");

            sb.AppendLine("<h2>Fact Store cache</h2>");
            sb.AppendLine("<p><b>Status:</b> " + EscapeHtml(GetFactStoreStatus(c)) + " &nbsp;|&nbsp; <b>Freshness:</b> " + EscapeHtml(FormatFactStoreFreshnessStatus(c)) + "</p>");
            if (!string.IsNullOrWhiteSpace(c.FactStoreFreshnessDetail))
                sb.AppendLine("<p>" + EscapeHtml(c.FactStoreFreshnessDetail) + "</p>");

            sb.AppendLine("<h2>Analyst workflow</h2><ul>");
            foreach (var line in BuildAnalystWorkflowSummaryLines(c)) sb.AppendLine("<li>" + EscapeHtml(line) + "</li>");
            sb.AppendLine("</ul>");

            var guidedHunt = GetGuidedHuntResult(c);
            sb.AppendLine("<h2>Guided Hunt</h2><ul>");
            foreach (var line in BuildGuidedHuntSummaryLines(c)) sb.AppendLine("<li>" + EscapeHtml(line) + "</li>");
            if (guidedHunt != null && guidedHunt.Enabled && guidedHunt.RuleMatches != null && guidedHunt.RuleMatches.Count > 0)
            {
                foreach (var match in guidedHunt.RuleMatches.Take(4))
                {
                    sb.AppendLine("<li><b>" + EscapeHtml(match.Id ?? "") + "</b> [" + EscapeHtml(match.Severity ?? "") + "] " +
                        EscapeHtml(match.Title ?? "") + " -> " +
                        EscapeHtml(match.AttackTechniqueId ?? "") + " " +
                        EscapeHtml(match.AttackTechniqueName ?? "") + "<br/>" +
                        EscapeHtml(match.Summary ?? "") + "</li>");
                }
            }
            sb.AppendLine("</ul>");

            var highlights = GetEventLogHighlights(c);
            sb.AppendLine("<h2>Event log highlights (sampled)</h2>");
            if (highlights.Count == 0) sb.AppendLine("<p>None or logs missing.</p>");
            else { sb.AppendLine("<ul>"); foreach (var h in highlights) sb.AppendLine("<li>" + EscapeHtml(h) + "</li>"); sb.AppendLine("</ul>"); }

            if (c.LoadWarnings != null && c.LoadWarnings.Count > 0)
            {
                sb.AppendLine("<h2>Load warnings</h2><ul>");
                foreach (var warning in c.LoadWarnings) sb.AppendLine("<li>" + EscapeHtml(warning) + "</li>");
                sb.AppendLine("</ul>");
            }

            sb.AppendLine("<h2>Analysis note</h2>");
                sb.AppendLine("<p>This report preserves observed facts and sampled artifacts only. Optional Guided Hunt output remains an explainable overlay and does not alter the underlying Fact Store.</p>");
                sb.AppendLine("<p>Time Type / Confidence indicate whether a timestamp comes from an event record, metadata, observation, or remains unknown.</p>");
            var parserNotes = BuildSummaryParserNotes(c);
            if (parserNotes.Count > 0)
            {
                sb.AppendLine("<h2>Parser notes</h2><ul>");
                foreach (var note in parserNotes) sb.AppendLine("<li>" + EscapeHtml(note) + "</li>");
                sb.AppendLine("</ul>");
            }

            sb.AppendLine("<h2>Observed facts</h2>");
            if (c.FactStoreBuilding && (c.FactStore == null || c.FactStore.Count == 0))
            {
                sb.AppendLine("<p>Fact Store is still building.</p>");
            }
            else if (c.FactStore == null || c.FactStore.Count == 0)
            {
                sb.AppendLine("<p>Fact Store not built or no facts available.</p>");
            }
            else
            {
                sb.AppendLine("<p><b>Total facts:</b> " + c.FactStore.Count.ToString("N0") + "</p>");
                sb.AppendLine("<table><tr><th>Time</th><th>Time Type</th><th>Confidence</th><th>Source</th><th>Action</th><th>Entities</th><th>Details</th><th>SourceFile</th><th>Provenance</th><th>RawRef</th><th>ParserNote</th></tr>");
                foreach (var fact in GetFactSamples(c, 100))
                {
                    sb.AppendLine("<tr><td>" + EscapeHtml(FormatFactTime(fact.Time)) + "</td><td>" + EscapeHtml(FormatFactTimeType(fact)) + "</td><td>" + EscapeHtml(FormatFactTimeConfidence(fact)) + "</td><td>" + EscapeHtml(fact.Source ?? "") + "</td><td>" + EscapeHtml(fact.Action ?? "") + "</td><td>" + EscapeHtml(BuildEntitySummary(fact.EntityRefs)) + "</td><td>" + EscapeHtml(fact.Details ?? "") + "</td><td>" + EscapeHtml(fact.SourceFile ?? "") + "</td><td>" + EscapeHtml(IR_Collect.Analysis.Correlation.FactProvenanceHelper.BuildSummary(fact)) + "</td><td>" + EscapeHtml(fact.RawRef ?? "") + "</td><td>" + EscapeHtml(fact.ParserNote ?? "") + "</td></tr>");
                }
                sb.AppendLine("</table>");
            }

            sb.AppendLine("</body></html>");
            return sb.ToString();
        }

        private static string EscapeHtml(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            return s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;");
        }

        /// <summary>Only allow 32 (MD5) or 64 (SHA256) hex chars for VirusTotal URL to prevent injection.</summary>
        private static bool IsValidVirusTotalHash(string hash)
        {
            if (string.IsNullOrEmpty(hash)) return false;
            if (hash.Length != 32 && hash.Length != 64) return false;
            for (int i = 0; i < hash.Length; i++)
            {
                char c = hash[i];
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return false;
            }
            return true;
        }

        private IR_Collect.Analysis.SummaryPayload BuildSummaryPayload(IR_Collect.Analysis.CaseData c)
        {
            var payload = new IR_Collect.Analysis.SummaryPayload();
            payload.GeneratedAt = DateTime.UtcNow.ToString("o");
            payload.ExportSchema = "summary_v3";
            payload.ToolName = IR_Collect.BuildInfo.ToolName;
            payload.ToolVersion = IR_Collect.BuildInfo.Version;
            payload.AnalysisMode = "facts_only";
            payload.Host = c.Hostname;
            payload.CaseId = c.CaseID;
            payload.ArtifactsCount = GetExtractedArtifactFileCount(c);
            payload.MftCount = (c.MftEntries != null) ? c.MftEntries.Count : 0;
            var latest = GetLatestMftTime(c.MftEntries);
            payload.MftLatest = latest.Year > 1980 ? latest.ToString("o") : "";

            payload.Counts = new Dictionary<string, int>();
            payload.Counts["processes"] = NormalizeArtifactCountForExport(CountCsvRows(GetArtifactPath(c, ArtifactNames.ProcessListCsv)));
            payload.Counts["logon_sessions"] = NormalizeArtifactCountForExport(CountCsvRows(GetArtifactPath(c, ArtifactNames.LogonSessionsCsv)));
            payload.Counts["network_resources"] = NormalizeArtifactCountForExport(CountCsvRows(GetArtifactPath(c, ArtifactNames.NetworkResourcesCsv)));
            payload.Counts["server_connections"] = NormalizeArtifactCountForExport(CountCsvRows(GetArtifactPath(c, ArtifactNames.ServerConnectionsCsv)));
            payload.Counts["services"] = NormalizeArtifactCountForExport(CountCsvRows(GetArtifactPath(c, ArtifactNames.ServicesCsv)));
            payload.Counts["autoruns"] = NormalizeArtifactCountForExport(CountCsvRows(GetArtifactPath(c, ArtifactNames.AutorunsRegistryCsv)));
            payload.Counts["bam_dam"] = NormalizeArtifactCountForExport(CountCsvRows(GetArtifactPath(c, ArtifactNames.BamDamCsv)));
            payload.Counts["bits_jobs"] = NormalizeArtifactCountForExport(CountCsvRows(GetArtifactPath(c, ArtifactNames.BitsJobsCsv)));
            payload.Counts["wmi_persistence"] = NormalizeArtifactCountForExport(CountCsvRows(GetArtifactPath(c, ArtifactNames.WmiPersistenceCsv)));
            payload.Counts["shimcache_rows"] = NormalizeArtifactCountForExport(CountCsvRows(GetArtifactPath(c, ArtifactNames.ShimCacheCsv)));
            payload.Counts["shimcache_entries"] = NormalizeArtifactCountForExport(CountCsvRows(GetArtifactPath(c, ArtifactNames.ShimCacheEntriesCsv)));
            payload.Counts["amcache_programs"] = NormalizeArtifactCountForExport(CountCsvRows(GetArtifactPath(c, ArtifactNames.AmcacheProgramsCsv)));
            payload.Counts["amcache_files"] = NormalizeArtifactCountForExport(CountCsvRows(GetArtifactPath(c, ArtifactNames.AmcacheFilesCsv)));
            payload.Counts["srum_network_usage"] = NormalizeArtifactCountForExport(CountCsvRows(GetArtifactPath(c, ArtifactNames.SrumNetworkUsageCsv)));
            payload.Counts["srum_app_usage"] = NormalizeArtifactCountForExport(CountCsvRows(GetArtifactPath(c, ArtifactNames.SrumAppUsageCsv)));
            payload.Counts["installed_software"] = NormalizeArtifactCountForExport(CountCsvRows(GetArtifactPath(c, ArtifactNames.InstalledSoftwareCsv)));
            payload.Counts["recent_files"] = NormalizeArtifactCountForExport(CountCsvRows(GetArtifactPath(c, ArtifactNames.RecentFilesCsv)));
            payload.Counts["usn_journal"] = NormalizeArtifactCountForExport(CountCsvRows(GetArtifactPath(c, ArtifactNames.UsnJournalCsv)));
            payload.Counts["shellbags"] = NormalizeArtifactCountForExport(CountCsvRows(GetArtifactPath(c, ArtifactNames.ShellBagsCsv)));
            payload.Counts["scheduled_tasks"] = NormalizeArtifactCountForExport(CountXmlTasks(GetArtifactPath(c, ArtifactNames.ScheduledTasksXml)));
            payload.Counts["event_logs"] = CountAvailableEventLogs(c);
            payload.Counts["browser_artifacts"] = CountBrowserArtifacts(c);

            payload.EventHighlights = GetEventLogHighlights(c);
            payload.LoadWarnings = c.LoadWarnings != null ? new List<string>(c.LoadWarnings) : new List<string>();
            payload.CollectionCoverage = c.CollectionCoverage;
            payload.FactStoreStatus = GetFactStoreStatus(c);
            payload.FactStoreFreshnessStatus = c.FactStoreFreshnessStatus ?? "";
            payload.FactStoreFreshnessDetail = c.FactStoreFreshnessDetail ?? "";
            payload.FactCount = c.FactStore != null ? c.FactStore.Count : 0;
            payload.FactSourceCounts = BuildFactSourceCounts(c);
            payload.EntityTypeCounts = BuildEntityTypeCounts(c);
            payload.ParserNotes = BuildSummaryParserNotes(c);
            payload.FactSamples = GetFactSamples(c, 100);
            payload.AnalystWorkflow = c.AnalystWorkflow ?? new IR_Collect.Analysis.AnalystWorkflowState();
            payload.GuidedHunt = GetGuidedHuntResult(c);
            payload.MemoryAcquisition = c.MemoryAcquisitionMeta;
            payload.MemoryAnalysis = c.MemoryAnalysisMeta;
            if (c.CollectionCoverage != null && !string.IsNullOrWhiteSpace(c.CollectionCoverage.CollectionModeProfile))
                payload.CollectionModeProfile = CollectionModeProfileHelper.Normalize(c.CollectionCoverage.CollectionModeProfile);
            else
                payload.CollectionModeProfile = "";
            return payload;
        }

        private string SendAiRequest(string endpoint, string apiKey, string summaryJson)
        {
            var request = (System.Net.HttpWebRequest)System.Net.WebRequest.Create(endpoint);
            request.Method = "POST";
            request.ContentType = "application/json";
            if (!string.IsNullOrEmpty(apiKey))
            {
                request.Headers["Authorization"] = "Bearer " + apiKey;
                request.Headers["x-api-key"] = apiKey;
            }

            string payload = "{\"input\":" + summaryJson + "}";
            byte[] bytes = Encoding.UTF8.GetBytes(payload);
            using (var stream = request.GetRequestStream())
            {
                stream.Write(bytes, 0, bytes.Length);
            }

            return ReadResponseBodyOrThrow(request);
        }

        /// <summary>
        /// Read an HTTP response body, disposing it even on error. On a WebException the protocol error
        /// response holds a live connection that the using-pattern would otherwise leak on repeated
        /// failures (e.g. a bad endpoint); dispose it and surface the server's error body.
        /// </summary>
        private static string ReadResponseBodyOrThrow(System.Net.WebRequest request)
        {
            try
            {
                using (var response = (System.Net.HttpWebResponse)request.GetResponse())
                using (var reader = new StreamReader(response.GetResponseStream()))
                {
                    return reader.ReadToEnd();
                }
            }
            catch (System.Net.WebException wex)
            {
                var http = wex.Response as System.Net.HttpWebResponse;
                if (http != null)
                {
                    string body = "";
                    try
                    {
                        using (http)
                        using (var s = http.GetResponseStream())
                        {
                            if (s != null)
                                using (var er = new StreamReader(s)) body = er.ReadToEnd();
                        }
                    }
                    catch { try { http.Close(); } catch { } }
                    throw new Exception("HTTP " + (int)http.StatusCode + ": " + (string.IsNullOrEmpty(body) ? wex.Message : body));
                }
                throw;
            }
        }

        /// <param name="localCollectRunProfileRaw">
        /// When non-null, ForensicStrict upload blocking follows this Local Collect run's recorded profile (from collection_coverage), not current Settings.
        /// Pass null for non-run upload attempts (use Settings). When coverage exists but field absent, pass empty string (treated as Standard for this run).
        /// </param>
        private string TryUploadLocalCase(string zipPath, out string title, string localCollectRunProfileRaw = null)
        {
            title = "Upload Transport Result";
            if (string.IsNullOrEmpty(zipPath) || !File.Exists(zipPath))
            {
                return "Zip file not found: " + zipPath;
            }

            if (CollectionModeProfileHelper.BlocksOutboundZipUploadForLocalCollectRun(localCollectRunProfileRaw, config))
            {
                title = "Upload blocked";
                var sbBlock = new StringBuilder();
                string sha256Block = GetZipSha256(zipPath);
                if (!string.IsNullOrEmpty(sha256Block)) sbBlock.AppendLine("SHA256: " + sha256Block);
                if (localCollectRunProfileRaw != null)
                    sbBlock.AppendLine("ZIP upload blocked: this Local Collect run was recorded with ForensicStrict (collection_mode_profile on this collected package). Outbound case ZIP transport is disabled for this ZIP regardless of the current Advanced → Settings profile.");
                else
                    sbBlock.AppendLine("ZIP upload blocked: the current Advanced → Settings collection mode profile is ForensicStrict (outbound case transport disabled). Change profile under Advanced → Settings to permit allowlist-based upload checks.");
                return sbBlock.ToString().Trim();
            }

            string endpoint = config.Get("UploadEndpoint");
            string apiKey = config.Get("UploadApiKey");
            StringBuilder sb = new StringBuilder();
            if (string.IsNullOrEmpty(endpoint))
            {
                string sha256Local = GetZipSha256(zipPath);
                if (!string.IsNullOrEmpty(sha256Local)) sb.AppendLine("SHA256: " + sha256Local);
                sb.AppendLine("Upload: skipped (endpoint not set).");
                return sb.ToString().Trim();
            }

            if (!IR_Collect.Utils.EndpointGovernance.IsEndpointAllowed(endpoint.Trim(), config.Get("UploadEndpointAllowlist")))
            {
                string sha256Block = GetZipSha256(zipPath);
                if (!string.IsNullOrEmpty(sha256Block)) sb.AppendLine("SHA256: " + sha256Block);
                sb.AppendLine("Upload blocked: endpoint not on Upload allowlist (Advanced → Settings). Empty allowlist blocks all upload POST.");
                title = "Upload Error";
                return sb.ToString().Trim();
            }

            try
            {
                string sha256 = GetZipSha256(zipPath);
                if (!string.IsNullOrEmpty(sha256)) sb.AppendLine("SHA256: " + sha256);
                string response = UploadCase(endpoint, apiKey, zipPath, sha256);
                if (LooksLikeUploadFailure(response))
                    throw new InvalidOperationException("Upload endpoint returned an error response: " + response);
                if (!string.IsNullOrEmpty(response))
                {
                    if (sb.Length > 0) sb.AppendLine();
                    sb.AppendLine("Upload request completed. Review server response:");
                    sb.AppendLine(response);
                }
                return sb.ToString().Trim();
            }
            catch (Exception ex)
            {
                title = "Upload Error";
                if (sb.Length > 0) sb.AppendLine();
                sb.AppendLine(ex.Message);
                return sb.ToString().Trim();
            }
        }

        private string UploadCase(string endpoint, string apiKey, string zipPath, string sha256)
        {
            string boundary = "----IRCollectBoundary" + DateTime.Now.Ticks;
            var request = (HttpWebRequest)WebRequest.Create(endpoint);
            request.Method = "POST";
            request.ContentType = "multipart/form-data; boundary=" + boundary;
            request.SendChunked = true;

            if (!string.IsNullOrEmpty(apiKey))
            {
                request.Headers["Authorization"] = "Bearer " + apiKey;
                request.Headers["x-api-key"] = apiKey;
            }

            string evidenceId = Path.GetFileNameWithoutExtension(zipPath);
            string fileName = Path.GetFileName(zipPath);
            string header1 = "--" + boundary + "\r\n" +
                             "Content-Disposition: form-data; name=\"evidence_id\"\r\n\r\n" +
                             evidenceId + "\r\n";
            string headerSha = "";
            if (!string.IsNullOrEmpty(sha256))
            {
                headerSha = "--" + boundary + "\r\n" +
                            "Content-Disposition: form-data; name=\"sha256\"\r\n\r\n" +
                            sha256 + "\r\n";
            }
            string header2 = "--" + boundary + "\r\n" +
                             "Content-Disposition: form-data; name=\"file\"; filename=\"" + fileName + "\"\r\n" +
                             "Content-Type: application/zip\r\n\r\n";
            string footer = "\r\n--" + boundary + "--\r\n";

            using (var reqStream = request.GetRequestStream())
            {
                WriteString(reqStream, header1);
                if (!string.IsNullOrEmpty(headerSha)) WriteString(reqStream, headerSha);
                WriteString(reqStream, header2);
                using (var fs = new FileStream(zipPath, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    byte[] buffer = new byte[81920];
                    int read;
                    while ((read = fs.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        reqStream.Write(buffer, 0, read);
                    }
                }
                WriteString(reqStream, footer);
            }

            return ReadResponseBodyOrThrow(request);
        }

        private void WriteString(Stream stream, string value)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(value);
            stream.Write(bytes, 0, bytes.Length);
        }

        private string GetZipSha256(string zipPath)
        {
            if (string.IsNullOrEmpty(zipPath))
                throw new ArgumentException("zipPath is null or empty.", "zipPath");
            if (!File.Exists(zipPath))
                throw new FileNotFoundException("Zip file not found.", zipPath);

            string actualHash;
            using (var sha = System.Security.Cryptography.SHA256.Create())
            using (var fs = new FileStream(zipPath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                byte[] hash = sha.ComputeHash(fs);
                actualHash = BitConverter.ToString(hash).Replace("-", "");
            }

            string shaPath = zipPath + ".sha256";
            if (File.Exists(shaPath))
            {
                string recordedHash = File.ReadAllText(shaPath).Trim();
                if (string.IsNullOrEmpty(recordedHash) || recordedHash.Length != 64 || !recordedHash.All(IsHexChar))
                    throw new InvalidDataException("Invalid SHA256 sidecar: " + shaPath);
                if (!string.Equals(recordedHash, actualHash, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("SHA256 sidecar does not match zip contents: " + shaPath);
            }

            return actualHash;
        }

        internal static bool LooksLikeUploadFailure(string response)
        {
            if (string.IsNullOrWhiteSpace(response)) return false;
            return System.Text.RegularExpressions.Regex.IsMatch(response, "\"(?:success|ok)\"\\s*:\\s*false", System.Text.RegularExpressions.RegexOptions.IgnoreCase) ||
                   System.Text.RegularExpressions.Regex.IsMatch(response, "\"status\"\\s*:\\s*\"(?:error|failed|rejected)\"", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        }

        private static bool IsHexChar(char c)
        {
            return (c >= '0' && c <= '9') ||
                   (c >= 'a' && c <= 'f') ||
                   (c >= 'A' && c <= 'F');
        }

        private string PromptEvidenceId()
        {
            Form f = new Form();
            f.Text = "Evidence ID";
            f.Size = new Size(420, 180);
            f.StartPosition = FormStartPosition.CenterParent;
            f.FormBorderStyle = FormBorderStyle.FixedDialog;
            f.MaximizeBox = false;
            f.MinimizeBox = false;

            Label l1 = new Label() { Text = "Evidence ID (optional):", Left = 12, Top = 15, Width = 360 };
            Label l2 = new Label() { Text = "Auto format: AA-YYYYMMDDHHmm", Left = 12, Top = 40, Width = 360 };
            TextBox t1 = new TextBox() { Left = 12, Top = 65, Width = 380 };

            Button btnOk = new Button() { Text = "OK", Left = 212, Top = 100, Width = 80 };
            Button btnCancel = new Button() { Text = "Cancel", Left = 302, Top = 100, Width = 80 };

            string result = "";
            btnOk.Click += (s, e) => { result = t1.Text.Trim(); f.DialogResult = DialogResult.OK; f.Close(); };
            btnCancel.Click += (s, e) => { result = "__CANCEL__"; f.DialogResult = DialogResult.Cancel; f.Close(); };

            f.Controls.Add(l1); f.Controls.Add(l2); f.Controls.Add(t1);
            f.Controls.Add(btnOk); f.Controls.Add(btnCancel);
            f.AcceptButton = btnOk;
            f.CancelButton = btnCancel;

            f.ShowDialog(this);
            return result;
        }

        private void ShowTextDialog(string title, string text)
        {
            Form f = new Form();
            f.Text = title;
            f.Size = new Size(800, 600);
            f.StartPosition = FormStartPosition.CenterParent;

            TextBox txt = new TextBox();
            txt.Multiline = true;
            txt.Dock = DockStyle.Fill;
            txt.ScrollBars = ScrollBars.Both;
            txt.ReadOnly = true;
            txt.Font = codeFont;
            txt.Text = text;

            Button btnCopy = new Button();
            btnCopy.Text = "Copy";
            btnCopy.Width = 80;
            btnCopy.Height = 30;
            btnCopy.Location = new Point(10, 10);
            btnCopy.Click += (s, e) => Clipboard.SetText(text);

            Panel top = new Panel();
            top.Dock = DockStyle.Top;
            top.Height = 40;
            top.Controls.Add(btnCopy);

            f.Controls.Add(txt);
            f.Controls.Add(top);
            f.ShowDialog(this);
        }

        private TabPage CreateFactsTab(IR_Collect.Analysis.CaseData c)
        {
            TabPage p = new TabPage("Facts");

            var info = new Label();
            info.Dock = DockStyle.Top;
            info.Height = 40;
            info.Padding = new Padding(10, 10, 10, 0);
            info.TextAlign = ContentAlignment.MiddleLeft;

            if (c.FactStoreBuilding && (c.FactStore == null || c.FactStore.Count == 0))
            {
                info.Text = "Fact Store is still building. Observed facts will appear when the build completes.";
                p.Controls.Add(info);
                return p;
            }

            if (c.FactStore == null || c.FactStore.Facts == null || c.FactStore.Facts.Count == 0)
            {
                info.Text = "No observed facts are available. Build Fact Store or load a case that includes fact_store.db.";
                p.Controls.Add(info);
                return p;
            }

            string focusEntityType;
            string focusEntityValue;
            string focusPreferredRawRef;
            bool hasFocus = TryGetFactsNavigationFocus(c, out focusEntityType, out focusEntityValue, out focusPreferredRawRef);

            IEnumerable<IR_Collect.Analysis.Correlation.Fact> factQuery = c.FactStore.Facts;
            int totalFactsForView = c.FactStore.Count;
            if (hasFocus)
            {
                factQuery = factQuery.Where(f => FactHasEntity(f, focusEntityType, focusEntityValue));
                totalFactsForView = factQuery.Count();
            }

            const int maxDisplayFacts = 50000;
            var orderedFacts = factQuery
                .OrderByDescending(f => hasFocus && !string.IsNullOrWhiteSpace(focusPreferredRawRef) && string.Equals(f != null ? (f.RawRef ?? "") : "", focusPreferredRawRef, StringComparison.OrdinalIgnoreCase))
                .ThenByDescending(f => f != null && f.Time.Year > 1980 ? f.Time : DateTime.MinValue)
                .ThenBy(f => f != null ? (f.Source ?? "") : "")
                .Take(maxDisplayFacts)
                .ToList();

            if (hasFocus)
            {
                info.Text = totalFactsForView > maxDisplayFacts
                    ? string.Format("Focused on {0} = \"{1}\". Showing {2:N0} of {3:N0} matching facts for this host.", focusEntityType, focusEntityValue, orderedFacts.Count, totalFactsForView)
                    : string.Format("Focused on {0} = \"{1}\". Showing {2:N0} matching facts for this host.", focusEntityType, focusEntityValue, orderedFacts.Count);
            }
            else
            {
                info.Text = c.FactStore.Count > maxDisplayFacts
                    ? string.Format("Showing latest {0:N0} of {1:N0} observed facts.", orderedFacts.Count, c.FactStore.Count)
                    : string.Format("Showing {0:N0} observed facts.", orderedFacts.Count);
            }

            DataGridView grid = CreateGrid();
            grid.Columns.Add("Time", "Time");
            grid.Columns.Add("TimeType", "Time Type");
            grid.Columns.Add("TimeConfidence", "Confidence");
            grid.Columns.Add("Source", "Source");
            grid.Columns.Add("Action", "Action");
            grid.Columns.Add("Entities", "Entities");
            grid.Columns.Add("Details", "Details");
            grid.Columns.Add("Artifact", "Artifact");
            grid.Columns.Add("Provenance", "Provenance");
            grid.Columns.Add("RawRef", "RawRef");
            grid.Columns[0].Width = 140;
            grid.Columns[1].Width = 110;
            grid.Columns[2].Width = 90;
            grid.Columns[3].Width = 130;
            grid.Columns[4].Width = 110;
            grid.Columns[5].Width = 280;
            grid.Columns[6].Width = 300;
            grid.Columns[7].Width = 150;
            grid.Columns[8].AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;
            grid.Columns[9].Width = 220;
            foreach (DataGridViewColumn col in grid.Columns)
                col.SortMode = DataGridViewColumnSortMode.NotSortable;

            var rows = new List<string[]>(orderedFacts.Count);
            foreach (var fact in orderedFacts)
            {
                rows.Add(new string[]
                {
                    FormatFactTime(fact.Time),
                    FormatFactTimeType(fact),
                    FormatFactTimeConfidence(fact),
                    fact.Source ?? "",
                    fact.Action ?? "",
                    BuildEntitySummary(fact.EntityRefs),
                    fact.Details ?? "",
                    fact.SourceFile ?? "",
                    IR_Collect.Analysis.Correlation.FactProvenanceHelper.BuildSummary(fact),
                    fact.RawRef ?? ""
                });
            }

            var contentPanel = new Panel() { Dock = DockStyle.Fill };
            Panel pagingBarPanel;
            var setDataAndRefresh = CreatePagingBar(contentPanel, grid, 8, PagingThresholdDefault, out pagingBarPanel);
            contentPanel.Controls.Add(grid);
            contentPanel.Controls.Add(pagingBarPanel);

            p.Controls.Add(contentPanel);
            p.Controls.Add(info);
            if (hasFocus)
            {
                var focusPanel = new Panel();
                focusPanel.Dock = DockStyle.Top;
                focusPanel.Height = 34;
                focusPanel.BackColor = Color.AliceBlue;

                var focusLabel = new Label();
                focusLabel.Text = string.Format("Navigation focus from cross-host drilldown: {0} = \"{1}\"", focusEntityType, focusEntityValue);
                focusLabel.AutoSize = true;
                focusLabel.Left = 10;
                focusLabel.Top = 9;

                var btnShowAllFacts = new Button();
                btnShowAllFacts.Text = "Show All Facts";
                btnShowAllFacts.Width = 110;
                btnShowAllFacts.Height = 24;
                btnShowAllFacts.Left = 620;
                btnShowAllFacts.Top = 5;
                btnShowAllFacts.Click += (s, e) =>
                {
                    ClearFactsNavigationFocus(c);
                    BuildHostTabs(c);
                    SelectTopLevelHostTab("Facts");
                };

                focusPanel.Controls.Add(focusLabel);
                focusPanel.Controls.Add(btnShowAllFacts);
                p.Controls.Add(focusPanel);
            }
            setDataAndRefresh(rows, null);
            return p;
        }

        private bool FactHasEntity(IR_Collect.Analysis.Correlation.Fact fact, string type, string value)
        {
            if (fact == null || fact.EntityRefs == null || string.IsNullOrWhiteSpace(type) || string.IsNullOrWhiteSpace(value))
                return false;

            string key = type.Trim() + ":" + value.Trim().ToLowerInvariant();
            foreach (var entity in fact.EntityRefs)
            {
                if (entity == null) continue;
                if (string.Equals(entity.ToEntityKey(), key, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        private string FormatFactTime(DateTime time)
        {
            return time.Year > 1980 ? time.ToString("yyyy-MM-dd HH:mm:ss") : "";
        }

        private string FormatFactTimeType(IR_Collect.Analysis.Correlation.Fact fact)
        {
            IR_Collect.Analysis.Correlation.FactTimeMetadata.ApplyDefaultsIfMissing(fact);
            string value = fact != null ? (fact.TimeKind ?? "") : "";
            switch (value)
            {
                case IR_Collect.Analysis.Correlation.FactTimeMetadata.EventTimeKind:
                    return "Event";
                case IR_Collect.Analysis.Correlation.FactTimeMetadata.MetadataTimeKind:
                    return "Metadata";
                case IR_Collect.Analysis.Correlation.FactTimeMetadata.ObservedTimeKind:
                    return "Observed";
                default:
                    return "Unknown";
            }
        }

        private string FormatFactTimeConfidence(IR_Collect.Analysis.Correlation.Fact fact)
        {
            IR_Collect.Analysis.Correlation.FactTimeMetadata.ApplyDefaultsIfMissing(fact);
            return fact != null && !string.IsNullOrWhiteSpace(fact.TimeConfidence) ? fact.TimeConfidence : IR_Collect.Analysis.Correlation.FactTimeMetadata.UnknownConfidence;
        }

        private string FormatFactTimeMetadata(IR_Collect.Analysis.Correlation.Fact fact)
        {
            return FormatFactTimeType(fact) + "/" + FormatFactTimeConfidence(fact);
        }

        private string BuildEntitySummary(IList<IR_Collect.Analysis.Correlation.EntityRef> refs)
        {
            if (refs == null || refs.Count == 0) return "";

            var all = refs
                .Where(er => er != null && !string.IsNullOrWhiteSpace(er.Value))
                .Select(er => (string.IsNullOrWhiteSpace(er.Type) ? "Entity" : er.Type.Trim()) + "=" + CollapseSingleLine(er.Value))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (all.Count == 0) return "";

            int shown = Math.Min(all.Count, 5);
            string summary = string.Join(" | ", all.Take(shown).ToArray());
            if (all.Count > shown)
                summary += " | +" + (all.Count - shown).ToString() + " more";
            return summary;
        }

        private string FormatFactSummaryLine(IR_Collect.Analysis.Correlation.Fact fact)
        {
            if (fact == null) return "";
            string time = FormatFactTime(fact.Time);
            string prefix = string.IsNullOrEmpty(time) ? (fact.Source ?? "") : (time + " " + (fact.Source ?? ""));
            string timeMetadata = FormatFactTimeMetadata(fact);
            if (!string.IsNullOrEmpty(timeMetadata))
                prefix = string.IsNullOrEmpty(prefix) ? timeMetadata : (prefix + " (" + timeMetadata + ")");
            string details = CollapseSingleLine(fact.Details);
            if (details.Length > 120) details = details.Substring(0, 117) + "...";
            if (string.IsNullOrEmpty(details))
                return prefix + " [" + (fact.Action ?? "") + "]";
            return prefix + " [" + (fact.Action ?? "") + "] " + details;
        }

        private string CollapseSingleLine(string value)
        {
            if (string.IsNullOrEmpty(value)) return "";
            string s = value.Replace("\r", " ").Replace("\n", " ").Trim();
            while (s.Contains("  ")) s = s.Replace("  ", " ");
            return s;
        }

        private void AppendCount(StringBuilder sb, string label, int count)
        {
            if (count >= 0)
                sb.AppendLine(label + ": " + count.ToString("N0"));
            else
                sb.AppendLine(label + ": (not found)");
        }

        private string FormatArtifactCountDisplay(int count)
        {
            return count >= 0 ? count.ToString("N0") : "(not found)";
        }

        private int NormalizeArtifactCountForExport(int count)
        {
            return count >= 0 ? count : 0;
        }

        private void AppendHtmlCountRow(StringBuilder sb, string label, int count)
        {
            if (sb == null)
                return;

            sb.AppendLine("<tr><td>" + EscapeHtml(label ?? "") + "</td><td>" + EscapeHtml(FormatArtifactCountDisplay(count)) + "</td></tr>");
        }

        private string GetArtifactPath(IR_Collect.Analysis.CaseData c, string fileName)
        {
            return IR_Collect.Analysis.CaseManager.ResolveArtifactPath(c, fileName);
        }

        private string ResolveArtifactPathFlexible(IR_Collect.Analysis.CaseData c, string fileName)
        {
            return GetArtifactPath(c, fileName);
        }

        private string GetArtifactSubFolderPath(IR_Collect.Analysis.CaseData c, string subFolder)
        {
            if (c == null || string.IsNullOrEmpty(subFolder)) return null;
            string rootDir = GetCaseRootPath(c);
            if (string.IsNullOrEmpty(rootDir)) return null;
            string targetDir = Path.Combine(rootDir, subFolder);
            return Directory.Exists(targetDir) ? targetDir : null;
        }

        private string GetCaseRootPath(IR_Collect.Analysis.CaseData c)
        {
            if (c == null) return null;
            if (!string.IsNullOrEmpty(c.ExtractPath) && Directory.Exists(c.ExtractPath))
                return c.ExtractPath;
            if (c.Artifacts != null && c.Artifacts.Count > 0)
            {
                string firstPath = c.Artifacts.FirstOrDefault().Value;
                if (!string.IsNullOrEmpty(firstPath))
                    return Path.GetDirectoryName(firstPath);
            }
            return null;
        }

        private int CountCsvRows(string path)
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return -1;
            try
            {
                int count = 0;
                using (StreamReader sr = new StreamReader(path, System.Text.Encoding.UTF8))
                {
                    string line;
                    bool header = true;
                    while ((line = sr.ReadLine()) != null)
                    {
                        if (header) { header = false; continue; }
                        if (!string.IsNullOrWhiteSpace(line)) count++;
                    }
                }
                return count;
            }
            catch (Exception ex) { IR_Collect.Utils.Logger.Warning("CountCsvRows: " + (ex != null ? ex.Message : "")); return -1; }
        }

        private int CountXmlTasks(string path)
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return -1;
            try
            {
                var doc = XDocument.Load(path);
                return doc.Descendants().Count(x => x.Name.LocalName == "Task");
            }
            catch (Exception ex) { IR_Collect.Utils.Logger.Warning("CountXmlTasks: " + (ex != null ? ex.Message : "")); return -1; }
        }

        private int CountFiles(string rootDir, string pattern)
        {
            if (string.IsNullOrEmpty(rootDir) || !Directory.Exists(rootDir)) return -1;
            const int MaxCountFiles = 50000;
            try
            {
                int n = 0;
                foreach (string _ in Directory.EnumerateFiles(rootDir, pattern, SearchOption.AllDirectories))
                {
                    if (++n >= MaxCountFiles) { Logger.Warning("CountFiles: capped at " + MaxCountFiles + " for " + rootDir); return MaxCountFiles; }
                }
                return n;
            }
            catch (Exception ex) { Logger.Warning("CountFiles: " + (ex.Message ?? "")); return -1; }
        }

        private int CountArtifactsByExtension(IR_Collect.Analysis.CaseData c, string extension)
        {
            if (c == null || c.Artifacts == null || string.IsNullOrEmpty(extension)) return -1;
            try
            {
                return c.Artifacts.Keys.Count(k => k.EndsWith(extension, StringComparison.OrdinalIgnoreCase));
            }
            catch { return -1; }
        }

        private int CountAvailableEventLogs(IR_Collect.Analysis.CaseData c)
        {
            if (c == null) return -1;
            try
            {
                var labels = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var kvp in GetEvtxEventLogFiles(c))
                {
                    string label = Path.GetFileNameWithoutExtension(kvp.Key);
                    if (!string.IsNullOrEmpty(label)) labels.Add(label);
                }
                foreach (var kvp in GetFilteredEventLogCsvPaths(c))
                {
                    if (!string.IsNullOrEmpty(kvp.Item1)) labels.Add(kvp.Item1);
                }
                return labels.Count;
            }
            catch { return -1; }
        }

        private int CountBrowserArtifacts(IR_Collect.Analysis.CaseData c)
        {
            try
            {
                return c.Artifacts.Keys.Count(k => ArtifactNames.IsBrowserHistoryMainArtifact(Path.GetFileName(k)));
            }
            catch { return -1; }
        }

        private IEnumerable<KeyValuePair<string, string>> GetEvtxEventLogFiles(IR_Collect.Analysis.CaseData c, bool highlightsOnly = false)
        {
            if (c == null || c.Artifacts == null) yield break;
            foreach (var kvp in c.Artifacts.Where(x => x.Key.EndsWith(".evtx", StringComparison.OrdinalIgnoreCase)))
            {
                if (!highlightsOnly ||
                    kvp.Key.IndexOf("Security", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    kvp.Key.IndexOf("System", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    kvp.Key.IndexOf("PowerShell", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    yield return kvp;
                }
            }
        }

        private bool HasFactStoreBuildInProgress()
        {
            if (treeHosts == null) return false;
            foreach (TreeNode node in treeHosts.Nodes)
            {
                var c = node.Tag as IR_Collect.Analysis.CaseData;
                if (c != null && c.FactStoreBuilding) return true;
            }
            return false;
        }

        private void BeginBackgroundViewLoad()
        {
            System.Threading.Interlocked.Increment(ref _backgroundLoadWorkerCount);
        }

        private void EndBackgroundViewLoad()
        {
            System.Threading.Interlocked.Decrement(ref _backgroundLoadWorkerCount);
        }

        private bool HasBackgroundViewLoadsInProgress()
        {
            return System.Threading.Interlocked.CompareExchange(ref _backgroundLoadWorkerCount, 0, 0) > 0;
        }

        private void MainForm_FormClosing(object sender, FormClosingEventArgs e)
        {
            if (e != null && _collectionInProgress)
            {
                MessageBox.Show("Local collection is still running. Please wait for it to finish before closing.", "Close", MessageBoxButtons.OK, MessageBoxIcon.Information);
                e.Cancel = true;
                return;
            }
            if (e != null && HasBackgroundViewLoadsInProgress())
            {
                MessageBox.Show("One or more background views are still loading. Please wait.", "Close", MessageBoxButtons.OK, MessageBoxIcon.Information);
                e.Cancel = true;
                return;
            }
            if (e != null && HasFactStoreBuildInProgress())
            {
                MessageBox.Show("One or more hosts are still building Fact Store. Please wait.", "Close", MessageBoxButtons.OK, MessageBoxIcon.Information);
                e.Cancel = true;
                return;
            }
            if (treeHosts != null) treeHosts.Nodes.Clear();
            if (hostTabs != null) hostTabs.TabPages.Clear();
            if (dashboardPanel != null) dashboardPanel.Visible = true;
            if (rightContentPanel != null) rightContentPanel.Visible = false;
            int cleanupFailures = IR_Collect.Analysis.CaseManager.CleanupAll();
            if (cleanupFailures > 0)
            {
                MessageBox.Show("One or more extracted case directories could not be removed during shutdown. Check logs/ir_collect.log for details.", "Cleanup Warning", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private int GetExtractedArtifactFileCount(IR_Collect.Analysis.CaseData c)
        {
            try
            {
                if (c == null || string.IsNullOrEmpty(c.ExtractPath) || !Directory.Exists(c.ExtractPath))
                    return c != null && c.Artifacts != null ? c.Artifacts.Count : 0;
                return Directory.GetFiles(c.ExtractPath, "*", SearchOption.AllDirectories).Length;
            }
            catch
            {
                return c != null && c.Artifacts != null ? c.Artifacts.Count : 0;
            }
        }

        private DateTime GetLatestMftTime(List<IR_Collect.MFT.MftParser.MftEntry> entries)
        {
            if (entries == null || entries.Count == 0) return DateTime.MinValue;
            DateTime upperBound = DateTime.UtcNow.AddDays(1);
            DateTime latest = DateTime.MinValue;
            foreach (var e in entries)
            {
                if (e.StdCreated > latest && e.StdCreated < upperBound) latest = e.StdCreated;
                if (e.StdModified > latest && e.StdModified < upperBound) latest = e.StdModified;
                if (e.StdMftModified > latest && e.StdMftModified < upperBound) latest = e.StdMftModified;
                if (e.StdAccessed > latest && e.StdAccessed < upperBound) latest = e.StdAccessed;
                if (e.FnCreated > latest && e.FnCreated < upperBound) latest = e.FnCreated;
                if (e.FnModified > latest && e.FnModified < upperBound) latest = e.FnModified;
                if (e.FnMftModified > latest && e.FnMftModified < upperBound) latest = e.FnMftModified;
                if (e.FnAccessed > latest && e.FnAccessed < upperBound) latest = e.FnAccessed;
            }
            return latest;
        }

        private List<string> GetEventLogHighlights(IR_Collect.Analysis.CaseData c)
        {
            List<string> results = new List<string>();
            var idMap = new Dictionary<int, string>
            {
                { 4624, "Logon Success" },
                { 4625, "Logon Failure" },
                { 4648, "Explicit Credential Use" },
                { 4672, "Special Privileges" },
                { 4688, "Process Creation" },
                { 4697, "Service Installed (Security)" },
                { 4698, "Scheduled Task Created" },
                { 4702, "Scheduled Task Updated" },
                { 4768, "Kerberos TGT" },
                { 4769, "Kerberos Service Ticket" },
                { 4776, "NTLM Validation" },
                { 7045, "Service Installed (System)" },
                { 1102, "Log Cleared" },
                { 4719, "Audit Policy Changed" },
                { 4720, "User Created" },
                { 4722, "User Enabled" },
                { 4725, "User Disabled" },
                { 4732, "User Added to Local Group" },
                { 4104, "PowerShell ScriptBlock" },
                { 5140, "SMB Share Access" },
                { 5145, "SMB Share Object Access" },
                { 1149, "RDP Auth Success" }
            };

            var counts = new Dictionary<int, int>();
            var samples = new Dictionary<int, List<string>>();
            foreach (var id in idMap.Keys) counts[id] = 0;
            foreach (var id in idMap.Keys) samples[id] = new List<string>();

            var filteredLogs = GetFilteredEventLogCsvPaths(c);
            if (filteredLogs.Count > 0)
            {
                foreach (var logFile in filteredLogs)
                {
                    try
                    {
                        var rows = IR_Collect.Analysis.Correlation.CorrelationCsvHelper.ReadCsv(logFile.Item2);
                        int scanned = 0;
                        foreach (var row in rows)
                        {
                            string eventIdText = IR_Collect.Analysis.Correlation.CorrelationCsvHelper.Get(row, "EventId");
                            int id;
                            if (!int.TryParse(eventIdText, out id)) continue;
                            if (!counts.ContainsKey(id)) continue;
                            counts[id]++;
                            if (samples[id].Count < 3)
                            {
                                string sample = BuildFilteredEventSample(logFile.Item1, row);
                                if (!string.IsNullOrEmpty(sample)) samples[id].Add(sample);
                            }
                            scanned++;
                            if (scanned >= 5000) break;
                        }
                    }
                    catch { }
                }
            }
            else
            {
                bool hasEvtx = GetEvtxEventLogFiles(c, true).Any();
                if (hasEvtx)
                    results.Add("Event log highlights are unavailable for EVTX-only cases. Import filtered event CSVs to align highlights with Timeline / Fact Store / full LOG JSON.");
            }

            foreach (var kvp in idMap)
            {
                int count;
                if (counts.TryGetValue(kvp.Key, out count) && count > 0)
                {
                    string sampleText = (samples[kvp.Key].Count > 0) ? " | ex: " + string.Join(" ; ", samples[kvp.Key]) : "";
                    results.Add(string.Format("EventID {0} ({1}): {2}{3}", kvp.Key, kvp.Value, count, sampleText));
                }
            }

            return results;
        }

        private string BuildFilteredEventSample(string logLabel, Dictionary<string, string> row)
        {
            try
            {
                string eventId = IR_Collect.Analysis.Correlation.CorrelationCsvHelper.Get(row, "EventId");
                string time = IR_Collect.Analysis.Correlation.CorrelationCsvHelper.Get(row, "TimeCreated");
                string provider = IR_Collect.Analysis.Correlation.CorrelationCsvHelper.Get(row, "ProviderName");
                string message = IR_Collect.Analysis.Correlation.CorrelationCsvHelper.Get(row, "Message");
                string eventDataRaw = IR_Collect.Analysis.Correlation.CorrelationCsvHelper.Get(row, EventLogDataHelper.EventDataColumn);
                Dictionary<string, string> eventData = EventLogDataHelper.ParseFlattenedEventData(eventDataRaw);
                string prefix = string.IsNullOrEmpty(provider) ? logLabel : (logLabel + " / " + provider);
                string details = BuildStructuredEventSummary(eventId, eventData, message);
                return TrimEventSample(prefix, (time ?? "") + " | " + details);
            }
            catch
            {
                return "";
            }
        }

        private string BuildStructuredEventSummary(string eventId, IDictionary<string, string> data, string fallbackMessage)
        {
            string id = (eventId ?? "").Trim();
            if (id == "4688")
            {
                string summary = TrimEventSample(EventLogDataHelper.GetValue(data, "NewProcessName", "ProcessName", "Image"), EventLogDataHelper.GetValue(data, "CommandLine", "ProcessCommandLine"));
                if (!string.IsNullOrWhiteSpace(summary)) return summary;
            }
            if (id == "4624" || id == "4625")
            {
                string summary = BuildEventFieldSummary(
                    "User", EventLogDataHelper.GetValue(data, "TargetUserName", "SubjectUserName"),
                    "Type", EventLogDataHelper.GetValue(data, "LogonType"),
                    "IP", EventLogDataHelper.GetValue(data, "IpAddress", "ClientAddress", "SourceAddress", "RemoteAddress"));
                if (!string.IsNullOrWhiteSpace(summary)) return summary;
            }
            if (id == "4698")
            {
                string summary = TrimEventSample(EventLogDataHelper.GetValue(data, "TaskName", "Task"), EventLogDataHelper.GetValue(data, "SubjectUserName", "User"));
                if (!string.IsNullOrWhiteSpace(summary)) return summary;
            }
            if (id == "7045")
            {
                string summary = TrimEventSample(EventLogDataHelper.GetValue(data, "ServiceName"), EventLogDataHelper.GetValue(data, "ImagePath", "ServiceFileName"));
                if (!string.IsNullOrWhiteSpace(summary)) return summary;
            }
            if (id == "4104")
            {
                string summary = TrimEventSample(EventLogDataHelper.GetValue(data, "ScriptBlockText"), "");
                if (!string.IsNullOrWhiteSpace(summary)) return summary;
            }
            if (id == "5140")
            {
                string summary = BuildEventFieldSummary(
                    "Share", EventLogDataHelper.GetValue(data, "ShareName"),
                    "IP", EventLogDataHelper.GetValue(data, "IpAddress", "ClientAddress", "SourceAddress"),
                    null, null);
                if (!string.IsNullOrWhiteSpace(summary)) return summary;
            }

            string normalizedFallback = EventLogDataHelper.SanitizeSingleLine(fallbackMessage);
            if (!string.IsNullOrWhiteSpace(normalizedFallback))
                return normalizedFallback;

            return EventLogDataHelper.FlattenEventData(data, 8, 120, 240);
        }

        private string BuildEventFieldSummary(string label1, string value1, string label2, string value2, string label3, string value3)
        {
            var parts = new List<string>();
            AppendEventSummaryPart(parts, label1, value1);
            AppendEventSummaryPart(parts, label2, value2);
            AppendEventSummaryPart(parts, label3, value3);
            return parts.Count == 0 ? "" : string.Join(" ", parts.ToArray());
        }

        private void AppendEventSummaryPart(List<string> parts, string label, string value)
        {
            string normalizedValue = EventLogDataHelper.SanitizeSingleLine(value);
            if (string.IsNullOrWhiteSpace(label) || string.IsNullOrWhiteSpace(normalizedValue)) return;
            parts.Add(label + "=" + normalizedValue);
        }

        private string BuildEventSample(EventRecord record)
        {
            try
            {
                var data = ExtractEventData(record);
                if (record.Id == 4688)
                {
                    string proc = GetEventField(data, "NewProcessName");
                    string cmd = GetEventField(data, "CommandLine");
                    return TrimEventSample(proc, cmd);
                }
                if (record.Id == 4624 || record.Id == 4625)
                {
                    string type = GetEventField(data, "LogonType");
                    string ip = GetEventField(data, "IpAddress");
                    string user = GetEventField(data, "TargetUserName");
                    return "LogonType=" + type + " IP=" + ip + " User=" + user;
                }
                if (record.Id == 7045)
                {
                    string svc = GetEventField(data, "ServiceName");
                    string img = GetEventField(data, "ImagePath");
                    return TrimEventSample(svc, img);
                }
                if (record.Id == 4104)
                {
                    string text = GetEventField(data, "ScriptBlockText");
                    return TrimEventSample(text, "");
                }
            }
            catch { }
            return "";
        }

        private string TrimEventSample(string a, string b)
        {
            string s = (string.IsNullOrEmpty(b) ? a : (a + " | " + b));
            if (string.IsNullOrEmpty(s)) return "";
            s = s.Replace("\r", " ").Replace("\n", " ");
            if (s.Length > 120) s = s.Substring(0, 117) + "...";
            return s;
        }

        private static void SetDoubleBuffered(Control c)
        {
            try
            {
                typeof(Control).InvokeMember("DoubleBuffered",
                    System.Reflection.BindingFlags.SetProperty | System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic,
                    null, c, new object[] { true });
            }
            catch { }
        }

        private const int PagingThresholdDefault = 500;
        private static readonly int[] PagingPageSizeOptions = new int[] { 150, 200, 250, 300 };

        /// <summary>Add paging bar to container (Dock Top). When data.Count > threshold, show paging (default 150/200/250/300 per page). Returns action (list, optionalTags) to set data and refresh.</summary>
        private Action<List<string[]>, List<object>> CreatePagingBar(Control container, DataGridView grid, int colCount, int threshold, out Panel pagingBarPanel)
        {
            var pagingBar = new Panel() { Dock = DockStyle.Bottom, Height = 36, BackColor = Color.WhiteSmoke };
            var comboPageSize = new ComboBox() { Width = 52, DropDownStyle = ComboBoxStyle.DropDownList };
            foreach (int opt in PagingPageSizeOptions) comboPageSize.Items.Add(opt.ToString());
            comboPageSize.SelectedIndex = 0;
            var lblPage = new Label() { AutoSize = true, Text = "Page 1 of 1" };
            var btnPrev = new Button() { Text = "Prev", Width = 44, Height = 24 };
            var btnNext = new Button() { Text = "Next", Width = 44, Height = 24 };
            var lblGoto = new Label() { AutoSize = true, Text = "Go to:" };
            var txtPage = new TextBox() { Width = 40, Height = 22 };
            var btnGo = new Button() { Text = "Go", Width = 36, Height = 24 };

            List<string[]> data = new List<string[]>();
            List<object> rowTags = new List<object>();
            int page = 1;
            int pageSize = PagingPageSizeOptions[0];

            Action refreshGrid = () =>
            {
                if (grid.IsDisposed) return;
                grid.Rows.Clear();
                int total = data.Count;
                bool useTags = rowTags != null && rowTags.Count == total;
                if (total <= threshold)
                {
                    pagingBar.Visible = false;
                    for (int i = 0; i < total; i++)
                    {
                        var row = data[i];
                        if (row.Length != colCount)
                        {
                            var padded = new object[colCount];
                            for (int j = 0; j < colCount; j++) padded[j] = (j < row.Length) ? row[j] : "";
                            grid.Rows.Add(padded);
                        }
                        else
                            grid.Rows.Add(row);
                        if (useTags && i < rowTags.Count) grid.Rows[grid.Rows.Count - 1].Tag = rowTags[i];
                    }
                    return;
                }
                pagingBar.Visible = true;
                int totalPages = (total + pageSize - 1) / pageSize;
                if (page < 1) page = 1;
                if (page > totalPages) page = totalPages;
                int start = (page - 1) * pageSize;
                int end = Math.Min(start + pageSize, total);
                lblPage.Text = "Page " + page + " of " + totalPages;
                btnPrev.Enabled = page > 1;
                btnNext.Enabled = page < totalPages;
                for (int i = start; i < end; i++)
                {
                    var row = data[i];
                    if (row.Length != colCount)
                    {
                        var padded = new object[colCount];
                        for (int j = 0; j < colCount; j++) padded[j] = (j < row.Length) ? row[j] : "";
                        grid.Rows.Add(padded);
                    }
                    else
                        grid.Rows.Add(row);
                    if (useTags && i < rowTags.Count) grid.Rows[grid.Rows.Count - 1].Tag = rowTags[i];
                }
            };

            comboPageSize.SelectedIndexChanged += (s, e) =>
            {
                if (comboPageSize.SelectedIndex >= 0 && comboPageSize.SelectedIndex < PagingPageSizeOptions.Length)
                {
                    pageSize = PagingPageSizeOptions[comboPageSize.SelectedIndex];
                    page = 1;
                    refreshGrid();
                }
            };
            btnPrev.Click += (s, e) => { page--; refreshGrid(); };
            btnNext.Click += (s, e) => { page++; refreshGrid(); };
            btnGo.Click += (s, e) =>
            {
                int p;
                if (int.TryParse(txtPage.Text, out p) && p >= 1)
                {
                    int total = data.Count;
                    if (total > threshold)
                    {
                        int totalPages = (total + pageSize - 1) / pageSize;
                        if (p > totalPages) p = totalPages;
                        page = p;
                        refreshGrid();
                    }
                }
            };

            pagingBar.Controls.Add(new Label() { Text = "Per page:", AutoSize = true, Location = new Point(8, 8), MaximumSize = new Size(72, 0) });
            comboPageSize.Location = new Point(84, 6);
            pagingBar.Controls.Add(comboPageSize);
            lblPage.Location = new Point(146, 8);
            pagingBar.Controls.Add(lblPage);
            btnPrev.Location = new Point(246, 6);
            btnNext.Location = new Point(294, 6);
            pagingBar.Controls.Add(btnPrev);
            pagingBar.Controls.Add(btnNext);
            lblGoto.Location = new Point(346, 8);
            pagingBar.Controls.Add(lblGoto);
            txtPage.Location = new Point(394, 6);
            pagingBar.Controls.Add(txtPage);
            btnGo.Location = new Point(438, 6);
            pagingBar.Controls.Add(btnGo);
            pagingBar.Visible = false;

            pagingBarPanel = pagingBar;
            Action<List<string[]>, List<object>> setDataAndRefresh = (list, tags) =>
            {
                data = list ?? new List<string[]>();
                rowTags = (tags != null && tags.Count == data.Count) ? tags : null;
                page = 1;
                refreshGrid();
            };
            return setDataAndRefresh;
        }

        private TabControl CreateSubTabControl()
        {
            TabControl tc = new TabControl();
            tc.Dock = DockStyle.Fill;
            tc.Font = this.uiFont;
            SetDoubleBuffered(tc);
            tc.SelectedIndexChanged += (s, ev) =>
            {
                var tab = s as TabControl;
                if (tab != null) { tab.SuspendLayout(); BeginInvoke((MethodInvoker)(() => { try { if (!tab.IsDisposed) tab.ResumeLayout(true); } catch { } })); }
            };
            EnableTabDragging(tc);
            return tc;
        }

        private void AddTabIfExists(TabControl tc, TabPage p)
        {
            if (p != null) tc.TabPages.Add(p);
        }

        private TabPage CreateDeferredTab(string title, Func<TabPage> loader)
        {
            if (loader == null) return null;

            TabPage tab = new TabPage(title);
            tab.Tag = new DeferredTabState { Loader = loader };
            tab.Controls.Add(CreateDeferredMessageLabel("Open this tab to load content."));
            tab.Enter += DeferredTab_Enter;
            return tab;
        }

        private TabPage CreateDeferredTab(string title, Func<object> dataLoader, Func<object, TabPage> tabBuilder)
        {
            if (dataLoader == null || tabBuilder == null) return null;

            TabPage tab = new TabPage(title);
            tab.Tag = new DeferredTabState { DataLoader = dataLoader, TabBuilder = tabBuilder };
            tab.Controls.Add(CreateDeferredMessageLabel("Open this tab to load content."));
            tab.Enter += DeferredTab_Enter;
            return tab;
        }

        private Label CreateDeferredMessageLabel(string text)
        {
            Label label = new Label();
            label.Dock = DockStyle.Fill;
            label.TextAlign = ContentAlignment.MiddleCenter;
            label.ForeColor = Color.Gray;
            label.Text = text;
            return label;
        }

        private void DeferredTab_Enter(object sender, EventArgs e)
        {
            TabPage tab = sender as TabPage;
            DeferredTabState state = tab != null ? tab.Tag as DeferredTabState : null;
            if (tab == null || state == null || state.IsLoaded || state.IsLoading) return;

            state.IsLoading = true;
            tab.Controls.Clear();
            tab.Controls.Add(CreateDeferredMessageLabel("Loading..."));

            if (state.DataLoader != null && state.TabBuilder != null)
            {
                var worker = new BackgroundWorker();
                BeginBackgroundViewLoad();
                worker.DoWork += (s, ev) => { ev.Result = state.DataLoader(); };
                worker.RunWorkerCompleted += (s, ev) =>
                {
                    try
                    {
                        if (tab.IsDisposed) { state.IsLoading = false; return; }
                        TabPage loaded = ev.Error != null ? null : state.TabBuilder(ev.Result);
                        tab.Controls.Clear();
                        if (loaded == null)
                        {
                            tab.Controls.Add(CreateDeferredMessageLabel(ev.Error != null ? "Load failed: " + ev.Error.Message : "No data available. (檔案可能不存在、格式不符或權限不足)"));
                            if (ev.Error != null) Logger.Warning("DeferredTab load " + tab.Text + ": " + ev.Error.Message);
                        }
                        else
                        {
                            while (loaded.Controls.Count > 0)
                            {
                                Control ctrl = loaded.Controls[0];
                                loaded.Controls.RemoveAt(0);
                                tab.Controls.Add(ctrl);
                            }
                            loaded.Dispose();
                            state.IsLoaded = true;
                            SafeInvoke((MethodInvoker)(() =>
                            {
                                if (tab.IsDisposed) return;
                                tab.PerformLayout();
                                tab.Refresh();
                            }));
                        }
                    }
                    catch (Exception ex)
                    {
                        tab.Controls.Clear();
                        tab.Controls.Add(CreateDeferredMessageLabel("Load failed: " + ex.Message));
                        Logger.Warning("DeferredTab load " + tab.Text + ": " + ex.Message);
                    }
                    finally
                    {
                        EndBackgroundViewLoad();
                        state.IsLoading = false;
                    }
                };
                worker.RunWorkerAsync();
                return;
            }

            BeginInvoke((MethodInvoker)delegate
            {
                if (tab.IsDisposed) return;
                try
                {
                    TabPage loaded = state.Loader();
                    tab.Controls.Clear();
                    if (loaded == null)
                    {
                        tab.Controls.Add(CreateDeferredMessageLabel("No data available. (檔案可能不存在或格式不符)"));
                    }
                    else
                    {
                        while (loaded.Controls.Count > 0)
                        {
                            Control control = loaded.Controls[0];
                            loaded.Controls.RemoveAt(0);
                            tab.Controls.Add(control);
                        }
                        loaded.Dispose();
                        state.IsLoaded = true;
                        SafeInvoke((MethodInvoker)(() =>
                        {
                            if (tab.IsDisposed) return;
                            tab.PerformLayout();
                            tab.Refresh();
                        }));
                    }
                }
                catch (Exception ex)
                {
                    tab.Controls.Clear();
                    tab.Controls.Add(CreateDeferredMessageLabel("Load failed: " + ex.Message));
                    Logger.Warning("DeferredTab load " + tab.Text + ": " + ex.Message);
                }
                finally
                {
                    state.IsLoading = false;
                }
            });
        }

        // Modified Helpers to Return TabPage instead of adding valid void
        // I will keep the logic to check Existence inside Create... functions



        private TabPage CreateBrowserFilesTab(IR_Collect.Analysis.CaseData c)
        {
            var browserFiles = c.Artifacts.Where(x => ArtifactNames.IsBrowserHistoryMainArtifact(Path.GetFileName(x.Key))).ToList();
            if (browserFiles.Count == 0) return null;

            TabPage mainPage = new TabPage("BrowsingHistoryView");
            TabControl browserTabs = new TabControl();
            browserTabs.Dock = DockStyle.Fill;
            browserTabs.Font = this.uiFont;
            EnableTabDragging(browserTabs);

            // 1. Overview Tab
            TabPage overview = new TabPage("Files List");
            DataGridView grid = CreateGrid();
            grid.Columns.Add("File", "File Name");
            grid.Columns.Add("Size", "Size (KB)");
            grid.Columns.Add("Path", "Full Path");
            grid.Columns[grid.Columns.Count - 1].AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;

            foreach(var kvp in browserFiles)
            {
                long size = 0;
                try { size = new FileInfo(kvp.Value).Length / 1024; } catch {}
                grid.Rows.Add(kvp.Key, size.ToString("N0") + " KB", kvp.Value);
            }
            overview.Controls.Add(grid);
            browserTabs.TabPages.Add(overview);

            // 2. Individual File Tabs (Lazy Load)
            foreach(var kvp in browserFiles)
            {
                // Fix: kvp.Key might be a relative path (e.g. "Root/Chrome_History")
                // We want just the file name part for logic
                string fileName = Path.GetFileName(kvp.Key);
                
                // Shorten name for Tab Label
                string tabName = fileName;
                if (fileName.StartsWith("Chrome_", StringComparison.OrdinalIgnoreCase)) tabName = "Chrome";
                else if (fileName.StartsWith("Edge_", StringComparison.OrdinalIgnoreCase)) tabName = "Edge";
                else if (fileName.StartsWith("Firefox_", StringComparison.OrdinalIgnoreCase)) tabName = "Firefox";
                else if (fileName.StartsWith("Brave_", StringComparison.OrdinalIgnoreCase)) tabName = "Brave";
                else if (fileName.StartsWith("Opera_", StringComparison.OrdinalIgnoreCase)) tabName = "Opera";
                else if (fileName.StartsWith("OperaGX_", StringComparison.OrdinalIgnoreCase)) tabName = "OperaGX";
                else if (fileName.StartsWith("Vivaldi_", StringComparison.OrdinalIgnoreCase)) tabName = "Vivaldi";
                
                // If multiple of same browser, append hash or part of name to distinguish?
                // For now just substring if too long and not matched above
                if (tabName.Length > 15) tabName = tabName.Substring(0, 12) + "...";

                TabPage page = new TabPage(tabName);
                page.Tag = kvp.Value; // Store full path for loading
                browserTabs.TabPages.Add(page);
            }


            browserTabs.Selected += (s, e) => {
                if (e.TabPage.Controls.Count == 0 && e.TabPage.Tag != null)
                {
                   LoadBrowserHistoryTab(e.TabPage, e.TabPage.Tag.ToString());
                }
            };

            mainPage.Controls.Add(browserTabs);
            return mainPage;
        }

        private void LoadBrowserHistoryTab(TabPage p, string path)
        {
            try 
            {
                DataGridView grid = CreateGrid();
                var fromSqlite = IR_Collect.Analysis.Correlation.FactStorePersistence.TryGetChromeHistory(path, 5000);
                if (fromSqlite == null && (path.IndexOf("places.sqlite", StringComparison.OrdinalIgnoreCase) >= 0 || path.IndexOf("Firefox", StringComparison.OrdinalIgnoreCase) >= 0))
                    fromSqlite = IR_Collect.Analysis.Correlation.FactStorePersistence.TryGetFirefoxHistory(path, 5000);
                if (fromSqlite != null && fromSqlite.Count > 0)
                {
                    grid.Columns.Add("URL", "Visited URL (Extracted)");
                    grid.Columns.Add("Last visit", "Last Visit");
                    grid.Columns[0].AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;
                    grid.Columns[1].Width = 160;
                    foreach (var t in fromSqlite)
                    {
                        string timeStr = t.Item2.Year > 1980 ? t.Item2.ToString("yyyy-MM-dd HH:mm:ss") : "";
                        grid.Rows.Add(t.Item1, timeStr);
                    }
                }
                else
                {
                    grid.Columns.Add("Status", "Browser History Status");
                    grid.Columns[0].AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;
                    string status = "No parsed browser history rows were available.";
                    if (IsSqliteBrowserHistoryArtifact(path))
                        status = "SQLite browser history requires System.Data.SQLite.dll for reliable parsing. Raw URL scraping is disabled to avoid false evidence.";
                    grid.Rows.Add(status);
                }

                p.Controls.Add(grid);
            }
            catch (Exception ex)
            {
                Label lbl = new Label();
                lbl.Text = "Error parsing history: " + ex.Message;
                lbl.AutoSize = true;
                lbl.ForeColor = Color.Red;
                lbl.Location = new Point(10, 10);
                p.Controls.Add(lbl);
            }
        }

        internal static bool IsSqliteBrowserHistoryArtifact(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            string fileName = Path.GetFileName(path);
            if (string.IsNullOrEmpty(fileName)) return false;
            return fileName.EndsWith(".sqlite", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(fileName, "History", StringComparison.OrdinalIgnoreCase) ||
                   fileName.EndsWith("_History", StringComparison.OrdinalIgnoreCase);
        }

        private TabPage CreateFileListTab(IR_Collect.Analysis.CaseData c, string title, string subFolder)
        {
            string rootDir = GetCaseRootPath(c);
            if (string.IsNullOrEmpty(rootDir)) return null;
            string targetDir = Path.Combine(rootDir, subFolder);
            if (!Directory.Exists(targetDir)) return null;

            TabPage p = new TabPage(title);
            DataGridView grid = CreateGrid();
            grid.Columns.Add("File", "File Name");
            grid.Columns.Add("Size", "Size (KB)");
            grid.Columns.Add("Date", "Date Modified");
            grid.Columns[grid.Columns.Count - 1].AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;
            
            p.Controls.Add(grid);

            // Populate Async or Sync? Sync is fine for a few hundred files
            try 
            {
                var files = Directory.GetFiles(targetDir);
                foreach(var f in files)
                {
                    FileInfo fi = new FileInfo(f);
                    grid.Rows.Add(fi.Name, (fi.Length / 1024).ToString("N0") + " KB", fi.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss"));
                }
            } catch {}

            return p;
        }

        private bool HasArtifact(IR_Collect.Analysis.CaseData c, string key)
        {
            return c.Artifacts.ContainsKey(key);
        }

        private TabPage CreateTextTab(IR_Collect.Analysis.CaseData c, string title, string fileName)
        {
            string path = GetArtifactPath(c, fileName);
            // simplified check: system_info_basic vs full
            if (path == null && fileName == ArtifactNames.SystemInfoFullTxt)
                path = GetArtifactPath(c, ArtifactNames.SystemInfoBasicTxt);

            if (path != null && File.Exists(path))
            {
                TabPage p = new TabPage(title);
                TextBox txt = new TextBox();
                txt.Multiline = true;
                txt.Dock = DockStyle.Fill;
                txt.ScrollBars = ScrollBars.Both;
                txt.Font = codeFont; // Use Code Font
                txt.ReadOnly = true;
                txt.MaxLength = 0; // limit only by memory
                try {
                    // Prefer UTF-8 (our artifact output), fallback to default if invalid
                    try { txt.Text = File.ReadAllText(path, System.Text.Encoding.UTF8).Replace("\n", "\r\n"); }
                    catch { txt.Text = File.ReadAllText(path, Encoding.Default).Replace("\n", "\r\n"); }
                } catch { txt.Text = "Error reading file."; }
                
                p.Controls.Add(txt);
                return p;
            }
            return null;
        }

        private TabPage CreateCsvTab(IR_Collect.Analysis.CaseData c, string title, string fileName)
        {
            string path = ResolveArtifactPathFlexible(c, fileName);
            if (path != null && File.Exists(path))
            {
                if (string.Equals(fileName, ArtifactNames.UsnJournalCsv, StringComparison.OrdinalIgnoreCase))
                    return CreateUsnJournalTab(path);
                TabPage p = new TabPage(title);
                DataGridView grid = CreateGrid();
                FillGridFromCsv(grid, path);
                foreach (DataGridViewColumn col in grid.Columns)
                    col.SortMode = DataGridViewColumnSortMode.NotSortable;
                p.Controls.Add(grid);
                return p;
            }
            return null;
        }

        private object LoadCsvDataForTab(IR_Collect.Analysis.CaseData c, string title, string fileName)
        {
            string path = ResolveArtifactPathFlexible(c, fileName);
            if (path == null || !File.Exists(path)) return null;
            bool isUsn = string.Equals(fileName, ArtifactNames.UsnJournalCsv, StringComparison.OrdinalIgnoreCase);
            if (isUsn)
            {
                List<string> headers;
                List<string[]> allRows;
                if (!TryLoadUsnJournalData(path, out headers, out allRows)) return null;
                return new CsvTabData { Headers = headers, Rows = allRows, IsUsn = true };
            }
            return LoadNormalCsvData(path);
        }

        private CsvTabData LoadNormalCsvData(string csvPath)
        {
            try
            {
                long maxBytes = 100L * 1024 * 1024;
                if (new FileInfo(csvPath).Length > maxBytes)
                {
                    Logger.Warning("CSV file too large to load: " + csvPath);
                    return null;
                }
                string[] lines;
                try { lines = File.ReadAllLines(csvPath, System.Text.Encoding.UTF8); }
                catch { lines = File.ReadAllLines(csvPath, Encoding.Default); }
                var validLines = lines.Where(l => !string.IsNullOrWhiteSpace(l.Trim())).ToList();
                if (validLines.Count == 0) return null;
                string headerLine = validLines[0];
                var headers = SplitCsvLine(headerLine).Select(h => h.Trim()).ToList();
                int colCount = headers.Count;
                var rows = new List<string[]>();
                for (int i = 1; i < validLines.Count; i++)
                {
                    string line = validLines[i];
                    if (line.Trim() == headerLine.Trim()) continue;
                    var parts = SplitCsvLine(line);
                    if (parts.Length == 0) continue;
                    if (parts.Length != colCount)
                    {
                        var padded = new string[colCount];
                        for (int j = 0; j < colCount; j++) padded[j] = (j < parts.Length) ? parts[j] : "";
                        rows.Add(padded);
                    }
                    else
                        rows.Add(parts);
                }
                return new CsvTabData { Headers = headers, Rows = rows, IsUsn = false };
            }
            catch (Exception ex) { Logger.Warning("LoadNormalCsvData: " + (ex.Message ?? "")); return null; }
        }

        private TabPage BuildCsvTabFromData(string title, CsvTabData data)
        {
            if (data == null || data.Headers == null || data.Rows == null) return null;
            if (data.IsUsn) return BuildUsnJournalTabFromData(data);
            TabPage p = new TabPage(title);
            DataGridView grid = CreateGrid();
            foreach (var h in data.Headers) grid.Columns.Add(h, h);
            if (grid.Columns.Count > 0)
                grid.Columns[grid.Columns.Count - 1].AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;
            foreach (DataGridViewColumn col in grid.Columns)
                col.SortMode = DataGridViewColumnSortMode.NotSortable;
            var contentPanel = new Panel() { Dock = DockStyle.Fill };
            Panel pagingBarPanel;
            var setDataAndRefresh = CreatePagingBar(contentPanel, grid, data.Headers.Count, PagingThresholdDefault, out pagingBarPanel);
            contentPanel.Controls.Add(grid);
            contentPanel.Controls.Add(pagingBarPanel);
            p.Controls.Add(contentPanel);
            setDataAndRefresh(data.Rows, null);
            return p;
        }

        /// <summary>USN Journal tab with exclude filter: "+" add condition, "-" remove, Apply filters rows (exclude when any cell matches any condition).</summary>
        private TabPage CreateUsnJournalTab(string csvPath)
        {
            List<string> headers;
            List<string[]> allRows;
            if (!TryLoadUsnJournalData(csvPath, out headers, out allRows))
                return null;
            return BuildUsnJournalTabFromData(new CsvTabData { Headers = headers, Rows = allRows, IsUsn = true });
        }

        private TabPage BuildUsnJournalTabFromData(CsvTabData data)
        {
            if (data == null || data.Headers == null || data.Rows == null) return null;
            List<string> headers = data.Headers;
            List<string[]> allRows = data.Rows;

            TabPage p = new TabPage("USN Journal");
            DataGridView grid = CreateGrid();
            foreach (var h in headers) grid.Columns.Add(h.Trim(), h.Trim());
            if (grid.Columns.Count > 0)
                grid.Columns[grid.Columns.Count - 1].AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;
            foreach (DataGridViewColumn col in grid.Columns)
                col.SortMode = DataGridViewColumnSortMode.NotSortable;

            // Filter: resizable by splitter; height only as needed (Dock Top), no extra space.
            Panel filterPanel = new Panel();
            filterPanel.BackColor = Color.WhiteSmoke;
            filterPanel.AutoScroll = true;
            filterPanel.MinimumSize = new Size(120, 36);

            var mainFlowVertical = new FlowLayoutPanel()
            {
                FlowDirection = FlowDirection.TopDown,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                Dock = DockStyle.Top,
                Padding = new Padding(6, 4, 8, 4),
                WrapContents = false,
                MinimumSize = new Size(100, 32)
            };

            var pnlConditionRows = new FlowLayoutPanel()
            {
                FlowDirection = FlowDirection.TopDown,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                Margin = new Padding(0, 0, 0, 4),
                WrapContents = false
            };

            var conditionRows = new List<Tuple<FlowLayoutPanel, TextBox, ComboBox>>();
            Action updateFilterHeight = null;
            var btnAdd = new Button() { Text = "+", Size = new Size(28, 24), Margin = new Padding(0, 0, 8, 0), BackColor = Color.LightGreen };
            var btnReset = new Button() { Text = "Reset", Size = new Size(60, 24), MinimumSize = new Size(60, 24), Margin = new Padding(0, 0, 0, 0) };

            Action<List<string[]>, List<object>> setDataAndRefresh = null;
            Action applyFilter = () =>
            {
                var conditions = new List<Tuple<string, bool>>();
                foreach (var row in conditionRows)
                {
                    string v = row.Item2 != null && row.Item2.Text != null ? row.Item2.Text.Trim() : "";
                    if (string.IsNullOrEmpty(v)) continue;
                    bool isExclude = (row.Item3 == null || row.Item3.SelectedItem == null) ? true : (row.Item3.SelectedItem.ToString() == "Exclude");
                    conditions.Add(Tuple.Create(v, isExclude));
                }
                var filtered = new List<string[]>(allRows);
                foreach (var cond in conditions)
                {
                    string kw = cond.Item1;
                    bool isExclude = cond.Item2;
                    if (isExclude)
                        filtered = filtered.Where(r => !r.Any(c => c != null && c.IndexOf(kw, StringComparison.OrdinalIgnoreCase) >= 0)).ToList();
                    else
                        filtered = filtered.Where(r => r.Any(c => c != null && c.IndexOf(kw, StringComparison.OrdinalIgnoreCase) >= 0)).ToList();
                }
                if (setDataAndRefresh != null) setDataAndRefresh(filtered, null);
            };

            Action addConditionRow = () =>
            {
                if (conditionRows.Count > 0)
                {
                    var lastRow = conditionRows[conditionRows.Count - 1].Item1;
                    lastRow.Controls.Remove(btnAdd);
                    lastRow.Controls.Remove(btnReset);
                    var btnMinus = new Button() { Text = "-", Width = 26, Height = 24, Margin = new Padding(0, 0, 0, 0), BackColor = Color.LightCoral };
                    var lastTuple = conditionRows[conditionRows.Count - 1];
                    btnMinus.Tag = lastTuple;
                    btnMinus.Click += (s, ev) =>
                    {
                        var t = ((Button)s).Tag as Tuple<FlowLayoutPanel, TextBox, ComboBox>;
                        if (t == null) return;
                        bool wasLast = t.Item1.Controls.Contains(btnAdd);
                        pnlConditionRows.Controls.Remove(t.Item1);
                        conditionRows.Remove(t);
                        if (wasLast && conditionRows.Count > 0)
                        {
                            var newLast = conditionRows[conditionRows.Count - 1].Item1;
                            if (newLast.Controls.Count > 0 && newLast.Controls[newLast.Controls.Count - 1] is Button)
                                newLast.Controls.RemoveAt(newLast.Controls.Count - 1);
                            newLast.Controls.Add(btnAdd);
                            newLast.Controls.Add(btnReset);
                        }
                        applyFilter();
                        if (updateFilterHeight != null) updateFilterHeight();
                    };
                    lastRow.Controls.Add(btnMinus);
                }

                var rowFlow = new FlowLayoutPanel()
                {
                    FlowDirection = FlowDirection.LeftToRight,
                    AutoSize = true,
                    Margin = new Padding(0, 0, 0, 4),
                    WrapContents = false
                };
                var lblContains = new Label() { Text = "Contains", AutoSize = true, Margin = new Padding(0, 4, 4, 0) };
                var txt = new TextBox() { Width = 160, Height = 22, Margin = new Padding(0, 2, 8, 0) };
                var lblThen = new Label() { Text = "then", AutoSize = true, Margin = new Padding(0, 4, 4, 0) };
                var comboMode = new ComboBox() { Width = 84, Height = 22, DropDownStyle = ComboBoxStyle.DropDownList, Margin = new Padding(0, 2, 8, 0), IntegralHeight = true };
                comboMode.Items.AddRange(new object[] { "Exclude", "Include" });
                comboMode.SelectedIndex = 0;
                comboMode.SelectedIndexChanged += (s, ev) => applyFilter();
                rowFlow.Controls.Add(lblContains);
                rowFlow.Controls.Add(txt);
                rowFlow.Controls.Add(lblThen);
                rowFlow.Controls.Add(comboMode);
                rowFlow.Controls.Add(btnAdd);
                rowFlow.Controls.Add(btnReset);
                txt.TextChanged += (s, ev) => applyFilter();
                conditionRows.Add(Tuple.Create(rowFlow, txt, comboMode));
                pnlConditionRows.Controls.Add(rowFlow);
                applyFilter();
                if (updateFilterHeight != null) updateFilterHeight();
            };

            btnAdd.Click += (s, e) => addConditionRow();
            btnReset.Click += (s, e) =>
            {
                foreach (var row in conditionRows)
                {
                    if (row.Item2 != null) row.Item2.Text = "";
                    if (row.Item3 != null && row.Item3.Items.Count > 0) row.Item3.SelectedIndex = 0;
                }
                applyFilter();
            };

            var rowFlow0 = new FlowLayoutPanel()
            {
                FlowDirection = FlowDirection.LeftToRight,
                AutoSize = true,
                Margin = new Padding(0, 0, 0, 4),
                WrapContents = false
            };
            var lblContains0 = new Label() { Text = "Contains", AutoSize = true, Margin = new Padding(0, 4, 4, 0) };
            var txt0 = new TextBox() { Width = 160, Height = 22, Margin = new Padding(0, 2, 8, 0) };
            var lblThen0 = new Label() { Text = "then", AutoSize = true, Margin = new Padding(0, 4, 4, 0) };
            var comboMode0 = new ComboBox() { Width = 84, Height = 22, DropDownStyle = ComboBoxStyle.DropDownList, Margin = new Padding(0, 2, 8, 0), IntegralHeight = true };
            comboMode0.Items.AddRange(new object[] { "Exclude", "Include" });
            comboMode0.SelectedIndex = 0;
            comboMode0.SelectedIndexChanged += (s, ev) => applyFilter();
            rowFlow0.Controls.Add(lblContains0);
            rowFlow0.Controls.Add(txt0);
            rowFlow0.Controls.Add(lblThen0);
            rowFlow0.Controls.Add(comboMode0);
            rowFlow0.Controls.Add(btnAdd);
            rowFlow0.Controls.Add(btnReset);
            txt0.TextChanged += (s, ev) => applyFilter();
            conditionRows.Add(Tuple.Create(rowFlow0, txt0, comboMode0));
            pnlConditionRows.Controls.Add(rowFlow0);
            mainFlowVertical.Controls.Add(pnlConditionRows);
            filterPanel.Controls.Add(mainFlowVertical);

            var split = new SplitContainer();
            split.Dock = DockStyle.Fill;
            split.Orientation = Orientation.Horizontal;
            split.Panel1MinSize = 36;
            split.Panel2MinSize = 80;
            updateFilterHeight = () =>
            {
                int rowCount = conditionRows.Count;
                int h = 12 + Math.Min(12, rowCount) * 30;
                if (h > 280) h = 280;
                if (split.Height > h + 80 && split.SplitterDistance != h) split.SplitterDistance = h;
            };
            split.Panel1.Controls.Add(filterPanel);
            split.SplitterDistance = 48;
            updateFilterHeight();
            Panel pagingBarPanel;
            setDataAndRefresh = CreatePagingBar(split.Panel2, grid, headers.Count, PagingThresholdDefault, out pagingBarPanel);
            split.Panel2.Controls.Add(grid);
            split.Panel2.Controls.Add(pagingBarPanel);
            filterPanel.Dock = DockStyle.Fill;

            p.Controls.Add(split);
            applyFilter();
            return p;
        }

        /// <summary>Load USN journal CSV; returns headers and all data rows. Returns false if file too large or parse failed.</summary>
        private bool TryLoadUsnJournalData(string csvPath, out List<string> headers, out List<string[]> allRows)
        {
            headers = new List<string>();
            allRows = new List<string[]>();
            try
            {
                long maxBytes = 100L * 1024 * 1024;
                if (new FileInfo(csvPath).Length > maxBytes)
                {
                    Logger.Warning("USN journal file too large to load: " + csvPath);
                    return false;
                }
                string[] lines;
                try { lines = File.ReadAllLines(csvPath, System.Text.Encoding.UTF8); }
                catch { lines = File.ReadAllLines(csvPath, Encoding.Default); }
                var validLines = lines.Where(l => !string.IsNullOrWhiteSpace(l.Trim())).ToList();
                if (validLines.Count == 0) return false;
                int headerIndex = -1;
                for (int i = 0; i < validLines.Count; i++)
                {
                    string line = validLines[i];
                    if (line.IndexOf("Usn", StringComparison.OrdinalIgnoreCase) >= 0 && line.IndexOf("File name", StringComparison.OrdinalIgnoreCase) >= 0 && line.IndexOf("Reason", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        headerIndex = i;
                        break;
                    }
                }
                if (headerIndex < 0) return false;
                var headerParts = SplitCsvLine(validLines[headerIndex]);
                foreach (var h in headerParts) headers.Add(h.Trim());
                int colCount = headers.Count;
                for (int i = headerIndex + 1; i < validLines.Count; i++)
                {
                    var parts = SplitCsvLine(validLines[i]);
                    if (parts.Length == 0) continue;
                    if (parts.Length != colCount)
                    {
                        var padded = new string[colCount];
                        for (int j = 0; j < colCount; j++) padded[j] = (j < parts.Length) ? parts[j] : "";
                        allRows.Add(padded);
                    }
                    else
                        allRows.Add(parts);
                }
                return true;
            }
            catch (Exception ex) { Logger.Warning("TryLoadUsnJournalData: " + (ex.Message ?? "")); return false; }
        }

        private static string EscapeCsvForExport(string s)
        {
            if (s == null) return "";
            if (s.IndexOf('"') >= 0 || s.IndexOf(',') >= 0 || s.IndexOf('\n') >= 0)
                return "\"" + s.Replace("\"", "\"\"") + "\"";
            return s;
        }

        private TabPage CreateFileCheckTab(IR_Collect.Analysis.CaseData c, string title, string fileName)
        {
            string path = GetArtifactPath(c, fileName);
            
            TabPage p = new TabPage(title);
            
            // Layout
            // Use Docking
            
            Panel topPanel = new Panel();
            topPanel.Dock = DockStyle.Top;
            topPanel.Height = 50;
            topPanel.BackColor = Color.WhiteSmoke;

            Button btnScan = new Button();
            btnScan.Text = "Deep Scan Local System32 (Live)";
            btnScan.Width = 250;
            btnScan.Location = new Point(10, 10);
            btnScan.BackColor = Color.Firebrick;
            btnScan.ForeColor = Color.White;
            btnScan.FlatStyle = FlatStyle.Flat;
            btnScan.Font = new Font("Segoe UI", 9F, FontStyle.Bold);

            topPanel.Controls.Add(btnScan);

            // Split Container for Baseline vs Deep Scan
            SplitContainer split = new SplitContainer();
            split.Dock = DockStyle.Fill;
            split.Orientation = Orientation.Horizontal;
            split.SplitterDistance = 300; // Top is Baseline

            // 1. Baseline Grid
            DataGridView baselineGrid = CreateGrid();
            if (!string.IsNullOrEmpty(path) && File.Exists(path))
            {
                FillGridFromCsv(baselineGrid, path);
            }
            else
            {
               baselineGrid.Columns.Add("FileName", "FileName");
               baselineGrid.Columns.Add("Path", "Path");
               baselineGrid.Columns.Add("SHA256", "SHA256");
               baselineGrid.Columns.Add("SignatureStatus", "SignatureStatus");
               baselineGrid.Columns.Add("Signer", "Signer");
               baselineGrid.Columns.Add("Status", "Status");
               baselineGrid.Columns[baselineGrid.Columns.Count - 1].AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;
            }
            
            GroupBox grpBaseline = new GroupBox();
            grpBaseline.Text = "Baseline Check (Collected Artifact)";
            grpBaseline.Dock = DockStyle.Fill;
            grpBaseline.Controls.Add(baselineGrid);
            split.Panel1.Controls.Add(grpBaseline);

            // 2. Deep Scan Grid
            DataGridView scanGrid = CreateGrid();
            scanGrid.Columns.Add("FileName", "FileName");
            scanGrid.Columns.Add("Path", "Path");
            scanGrid.Columns.Add("SHA256", "SHA256");
            scanGrid.Columns.Add("Status", "Status");
            scanGrid.Columns[scanGrid.Columns.Count - 1].AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;

            GroupBox grpScan = new GroupBox();
            grpScan.Text = "Deep Scan Results (Live System)";
            grpScan.Dock = DockStyle.Fill;
            grpScan.Controls.Add(scanGrid);
            split.Panel2.Controls.Add(grpScan);

            // Button Logic
            btnScan.Click += (s, e) => {
                var confirm = MessageBox.Show(
                    "This will scan ALL .exe and .dll files in C:\\Windows\\System32 on THIS machine.\n" +
                    "It may take a few minutes.\n\nContinue?", 
                    "Deep Scan Warning", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);

                if (confirm == DialogResult.Yes)
                {
                    btnScan.Enabled = false;
                    btnScan.Text = "Scanning...";
                    scanGrid.Rows.Clear(); 
                    
                    // Run async
                    Action scan = () => {
                        try {
                           string sys32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
                           var exes = Directory.GetFiles(sys32, "*.exe", SearchOption.TopDirectoryOnly); 
                           var dlls = Directory.GetFiles(sys32, "*.dll", SearchOption.TopDirectoryOnly);
                           
                           List<string[]> results = new List<string[]>();
                           
                           foreach(var f in exes) ProcessFile(f, results);
                           foreach(var f in dlls) ProcessFile(f, results);

                           SafeInvoke((MethodInvoker)delegate {
                               foreach(var r in results) scanGrid.Rows.Add(r);
                               btnScan.Text = "Deep Scan Complete";
                               btnScan.Enabled = true;
                           });

                        } catch (Exception ex) {
                             SafeInvoke((MethodInvoker)delegate {
                                MessageBox.Show("Error: " + ex.Message);
                                btnScan.Text = "Deep Scan Local System32 (Live)";
                                btnScan.Enabled = true;
                             });
                        }
                    };
                    scan.BeginInvoke(null, null);
                }
            };

            p.Controls.Add(split);   // Fill
            p.Controls.Add(topPanel); // Top
            return p;
        }

        private void ProcessFile(string file, List<string[]> list)
        {
            try {
                using (var sha256 = System.Security.Cryptography.SHA256.Create())
                using (var stream = File.OpenRead(file))
                {
                    var hash = sha256.ComputeHash(stream);
                    string hStr = BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                    list.Add(new string[] { Path.GetFileName(file), file, hStr, "Live Scan" });
                }
            } catch (Exception ex) { Logger.Warning("ProcessFile: " + (ex != null ? ex.Message : "")); }
        }

        private TabPage CreateEventLogTab(IR_Collect.Analysis.CaseData c)
        {
            var evtxFiles = GetEvtxEventLogFiles(c).ToList();
            var filteredLogs = GetFilteredEventLogCsvPaths(c);
            if (evtxFiles.Count == 0 && filteredLogs.Count == 0) return null;

            TabPage mainPage = new TabPage("Event Logs");
            TabControl eventTabs = new TabControl();
            eventTabs.Dock = DockStyle.Fill;
            eventTabs.Font = this.uiFont;
            EnableTabDragging(eventTabs);

            // 1. Overview Tab
            TabPage overview = new TabPage("Files List");
            DataGridView grid = CreateGrid();
            grid.Columns.Add("LogFile", "Log File Name");
            grid.Columns.Add("Type", "Type");
            grid.Columns.Add("Size", "Size (KB)");
            grid.Columns.Add("Path", "Full Path");
            grid.Columns[grid.Columns.Count - 1].AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;

            foreach(var kvp in evtxFiles)
            {
                long size = 0;
                try { size = new FileInfo(kvp.Value).Length / 1024; } catch {}
                grid.Rows.Add(kvp.Key, ".evtx", size.ToString("N0") + " KB", kvp.Value);
            }
            foreach (var logFile in filteredLogs)
            {
                long size = 0;
                try { size = new FileInfo(logFile.Item2).Length / 1024; } catch {}
                grid.Rows.Add(logFile.Item1 + ArtifactNames.EventLogFilteredSuffix, "Filtered CSV", size.ToString("N0") + " KB", logFile.Item2);
            }
            overview.Controls.Add(grid);
            eventTabs.TabPages.Add(overview);

            // 2. Individual Log Tabs (Lazy Load)
            foreach(var kvp in evtxFiles)
            {
                string name = Path.GetFileNameWithoutExtension(kvp.Key).Replace("Microsoft-Windows-", ""); 
                if (name.Length > 20) name = name.Substring(0, 17) + "..."; // Shorten name for tab

                TabPage logPage = new TabPage(name);
                logPage.Tag = new EventLogTabState { Path = kvp.Value };
                eventTabs.TabPages.Add(logPage);
            }
            foreach (var logFile in filteredLogs)
            {
                string title = logFile.Item1;
                string path = logFile.Item2;
                var csvTab = CreateDeferredTab(title, () => LoadNormalCsvData(path), data => BuildCsvTabFromData(title, data as CsvTabData));
                if (csvTab != null) eventTabs.TabPages.Add(csvTab);
            }

            // Lazy Loader (async to avoid UI "Not Responding")
            eventTabs.Selected += (s, e) => {
                EventLogTabState state = e.TabPage.Tag as EventLogTabState;
                if (state != null && !state.IsLoading && !state.IsLoaded && e.TabPage.Controls.Count == 0)
                {
                   state.IsLoading = true;
                   state.LoadToken = Guid.NewGuid();
                   LoadEventLogTabAsync(e.TabPage, state);
                }
            };

            mainPage.Controls.Add(eventTabs);
            return mainPage;
        }

                private const long MaxEvtxFileBytes = 50L * 1024 * 1024;

                private void LoadEventLogTabAsync(TabPage p, EventLogTabState state)
        {
            if (p == null || state == null || string.IsNullOrEmpty(state.Path))
            {
                if (state != null) state.IsLoading = false;
                return;
            }
            try
            {
                if (new FileInfo(state.Path).Length > MaxEvtxFileBytes)
                {
                    var lbl = new Label { Text = "Event log file too large (>50 MB). Skipped.", AutoSize = true, Location = new Point(12, 12) };
                    p.Controls.Add(lbl);
                    state.IsLoading = false;
                    return;
                }
            }
            catch { state.IsLoading = false; }

            var loadingLabel = new Label
            {
                Text = "Loading event log...",
                AutoSize = true,
                Font = new Font("Segoe UI", 11F),
                Location = new Point(12, 12)
            };
            p.Controls.Add(loadingLabel);

            var worker = new BackgroundWorker();
            BeginBackgroundViewLoad();
            worker.DoWork += (s, ev) =>
            {
                var allRows = new List<string[]>();
                var allDetails = new List<EventDetailView>();
                using (var reader = new EventLogReader(state.Path, PathType.FilePath))
                {
                    EventRecord record;
                    int count = 0;
                    var tempRecords = new List<EventRecord>();
                    while ((record = reader.ReadEvent()) != null)
                    {
                        tempRecords.Add(record);
                        count++;
                        if (count > 2000) break;
                    }
                    tempRecords.Reverse();
                    foreach (var r in tempRecords)
                    {
                        try
                        {
                            string type = r.LevelDisplayName ?? (r.Level.HasValue ? r.Level.ToString() : "Info");
                            if (string.IsNullOrEmpty(type)) type = "Info";
                            DateTime? dt = r.TimeCreated;
                            string date = dt.HasValue ? dt.Value.ToString("yyyy/M/d") : "";
                            string time = dt.HasValue ? dt.Value.ToString("HH:mm:ss") : "";
                            string id = r.Id.ToString();
                            string source = r.ProviderName;
                            string cat = r.TaskDisplayName ?? (r.Task.HasValue ? r.Task.ToString() : "");
                            string user = "N/A";
                            if (r.UserId != null) user = r.UserId.Value;
                            string comp = r.MachineName;
                            string desc = "";
                            try { desc = r.FormatDescription(); } catch { }
                            if (string.IsNullOrEmpty(desc)) desc = "(No description)";
                            var data = ExtractEventData(r);
                            var parsedSb = new StringBuilder();
                            foreach (var kv in data)
                                parsedSb.AppendLine(kv.Key + ": " + (kv.Value.Length > 500 ? kv.Value.Substring(0, 497) + "..." : kv.Value));
                            string parsedStr = parsedSb.Length > 0 ? parsedSb.ToString().Trim() : "(No parsed data)";
                            string xmlStr = "";
                            try { xmlStr = r.ToXml(); } catch { xmlStr = "(Unable to get XML)"; }
                            allRows.Add(new string[] { type, date, time, id, source, cat, user, comp });
                            allDetails.Add(new EventDetailView { Description = desc, Parsed = parsedStr, Xml = xmlStr });
                        }
                        catch { }
                        finally { r.Dispose(); }
                    }
                }
                ev.Result = Tuple.Create(state.LoadToken, state.Path, allRows, allDetails);
            };
            worker.RunWorkerCompleted += (s, ev) =>
            {
                try
                {
                    SafeInvoke((MethodInvoker)delegate
                    {
                        EventLogTabState currentState = p.Tag as EventLogTabState;
                        if (currentState == null) return;

                        currentState.IsLoading = false;

                        if (p.IsDisposed || p.Parent == null || currentState.LoadToken != state.LoadToken)
                        {
                            loadingLabel.Dispose();
                            return;
                        }

                        if (p.Controls.Contains(loadingLabel))
                            p.Controls.Remove(loadingLabel);
                        loadingLabel.Dispose();

                        if (ev.Error != null)
                        {
                            var lbl = new Label { Text = "Error loading: " + ev.Error.Message, AutoSize = true, Location = new Point(12, 12) };
                            p.Controls.Add(lbl);
                            return;
                        }

                        var result = ev.Result as Tuple<Guid, string, List<string[]>, List<EventDetailView>>;
                        if (result == null || result.Item3 == null)
                        {
                            var lbl = new Label { Text = "Error reading log.", AutoSize = true, Location = new Point(12, 12) };
                            p.Controls.Add(lbl);
                            return;
                        }

                        currentState.IsLoaded = true;
                        PopulateEventLogTabContent(p, result.Item2, result.Item3, result.Item4);
                    });
                }
                finally
                {
                    EndBackgroundViewLoad();
                }
            };
            worker.RunWorkerAsync();
        }

        private void PopulateEventLogTabContent(TabPage p, string path, List<string[]> allRows, List<EventDetailView> allDetails)
        {
            // Layout: 可拉伸的線在「資訊區(表格)」與「Per page」之間。SplitContainer Panel1=表格, Panel2=Per page + Event detail
            SplitContainer split = new SplitContainer();
            split.Dock = DockStyle.Fill;
            split.Orientation = Orientation.Horizontal;
            split.SplitterDistance = 400;
            split.Panel1MinSize = 100;
            split.Panel2MinSize = 80;

            DataGridView grid = CreateGrid();
            Panel filterPanel = new Panel();
            filterPanel.Dock = DockStyle.Top;
            filterPanel.Height = 36;
            filterPanel.BackColor = Color.WhiteSmoke;

            // 標籤不遮輸入框：MaximumSize 限制寬度，輸入框 Left 留約 6px 間隔
            Label lblId = new Label() { Text = "Event ID:", Left = 8, Top = 9, AutoSize = true, MaximumSize = new Size(68, 0) };
            TextBox txtId = new TextBox() { Left = 82, Top = 6, Width = 70 };
            Label lblSource = new Label() { Text = "Source:", Left = 160, Top = 9, AutoSize = true, MaximumSize = new Size(52, 0) };
            TextBox txtSource = new TextBox() { Left = 218, Top = 6, Width = 140 };
            Label lblUser = new Label() { Text = "User:", Left = 364, Top = 9, AutoSize = true, MaximumSize = new Size(40, 0) };
            TextBox txtUser = new TextBox() { Left = 410, Top = 6, Width = 120 };
            Label lblContains = new Label() { Text = "Contains:", Left = 538, Top = 9, AutoSize = true, MaximumSize = new Size(62, 0) };
            TextBox txtContains = new TextBox() { Left = 608, Top = 6, Width = 150 };
            Button btnApply = new Button() { Text = "Apply", Left = 768, Top = 5, Width = 60, Height = 24 };
            Button btnReset = new Button() { Text = "Reset", Left = 833, Top = 5, Width = 60, Height = 24 };

            filterPanel.Controls.Add(lblId);
            filterPanel.Controls.Add(txtId);
            filterPanel.Controls.Add(lblSource);
            filterPanel.Controls.Add(txtSource);
            filterPanel.Controls.Add(lblUser);
            filterPanel.Controls.Add(txtUser);
            filterPanel.Controls.Add(lblContains);
            filterPanel.Controls.Add(txtContains);
            filterPanel.Controls.Add(btnApply);
            filterPanel.Controls.Add(btnReset);
            grid.Columns.Add("Type", "Type");
            grid.Columns.Add("Date", "Date");
            grid.Columns.Add("Time", "Time");
            grid.Columns.Add("EventID", "Event ID");
            grid.Columns.Add("Source", "Source");
            grid.Columns.Add("Category", "Category");
            grid.Columns.Add("User", "User");
            grid.Columns.Add("Computer", "Computer");

            grid.Columns[0].Width = 80;
            grid.Columns[1].Width = 90;
            grid.Columns[2].Width = 90;
            grid.Columns[3].Width = 70;
            grid.Columns[4].Width = 150;
            grid.Columns[5].Width = 100;
            grid.Columns[6].Width = 100;
            grid.Columns[7].AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;

            int viewIndex = 0;
            string[] viewOptions = new string[] { "Description", "Parsed fields", "Raw XML" };
            Label lblView = new Label() { Text = "View:", Left = 8, Top = 10, AutoSize = true, MaximumSize = new Size(42, 0) };
            Panel detailHeader = new Panel();
            detailHeader.Height = 36;
            detailHeader.Dock = DockStyle.Top;
            detailHeader.Controls.Add(lblView);

            RichTextBox txtDesc = new RichTextBox();
            txtDesc.Dock = DockStyle.Fill;
            txtDesc.ReadOnly = true;
            txtDesc.BackColor = Color.White;
            txtDesc.Font = new Font("Segoe UI", 10F);
            txtDesc.BorderStyle = BorderStyle.None;
            txtDesc.Padding = new Padding(10);
            txtDesc.ScrollBars = RichTextBoxScrollBars.Vertical;

            GroupBox grpDesc = new GroupBox();
            grpDesc.Text = "Event detail";
            grpDesc.Dock = DockStyle.Fill;
            grpDesc.Padding = new Padding(8);
            grpDesc.Controls.Add(detailHeader);
            grpDesc.Controls.Add(txtDesc);

            Action<List<string[]>, List<object>> setDataAndRefreshEventLog = null;
            Action applyFilter = () =>
                {
                    string idFilter = txtId.Text.Trim();
                    string sourceFilter = txtSource.Text.Trim();
                    string userFilter = txtUser.Text.Trim();
                    string containsFilter = txtContains.Text.Trim();

                    var filteredRows = new List<string[]>();
                    var filteredDetails = new List<EventDetailView>();
                    for (int i = 0; i < allRows.Count; i++)
                    {
                        var r = allRows[i];
                        string id = r.Length > 3 ? r[3] : "";
                        string source = r.Length > 4 ? r[4] : "";
                        string user = r.Length > 6 ? r[6] : "";

                        if (!string.IsNullOrEmpty(idFilter) && id.IndexOf(idFilter, StringComparison.OrdinalIgnoreCase) < 0) continue;
                        if (!string.IsNullOrEmpty(sourceFilter) && source.IndexOf(sourceFilter, StringComparison.OrdinalIgnoreCase) < 0) continue;
                        if (!string.IsNullOrEmpty(userFilter) && user.IndexOf(userFilter, StringComparison.OrdinalIgnoreCase) < 0) continue;
                        if (!string.IsNullOrEmpty(containsFilter) && (allDetails[i].Description + allDetails[i].Parsed + allDetails[i].Xml).IndexOf(containsFilter, StringComparison.OrdinalIgnoreCase) < 0) continue;

                        filteredRows.Add(r);
                        filteredDetails.Add(allDetails[i]);
                    }
                    var detailsAsObjects = new List<object>(filteredDetails.Count);
                    foreach (var d in filteredDetails) detailsAsObjects.Add(d);
                    if (setDataAndRefreshEventLog != null) setDataAndRefreshEventLog(filteredRows, detailsAsObjects);
                };

            // Panel2 = Per page（上）+ Event detail（下）；分頁列放在上方以便分隔線在「表格」與「Per page」之間
            Panel bottomPanel = new Panel() { Dock = DockStyle.Fill };
            Panel eventLogPagingPanel;
            setDataAndRefreshEventLog = CreatePagingBar(bottomPanel, grid, 8, PagingThresholdDefault, out eventLogPagingPanel);
            eventLogPagingPanel.Dock = DockStyle.Top;  // Per page 在 Panel2 頂部，分隔線即為「資訊區｜Per page」
            bottomPanel.Controls.Add(grpDesc);        // Event detail 填滿其餘
            split.Panel1.Controls.Add(grid);           // Panel1 = 僅表格（可拉伸高度）
            split.Panel1.Controls.Add(filterPanel);
            split.Panel2.Controls.Add(bottomPanel);    // Panel2 = Per page + Event detail

                Action updateDetail = () =>
                {
                    if (grid.SelectedRows.Count > 0)
                    {
                        var row = grid.SelectedRows[0];
                        var v = row.Tag as EventDetailView;
                        if (v != null)
                        {
                            if (viewIndex == 1) txtDesc.Text = v.Parsed;
                            else if (viewIndex == 2) txtDesc.Text = v.Xml;
                            else txtDesc.Text = v.Description;
                        }
                    }
                };

                Button btnView = new Button();
                btnView.Text = viewOptions[0];
                btnView.FlatStyle = FlatStyle.System;
                btnView.Location = new Point(56, 6);
                btnView.Size = new Size(140, 24);
                btnView.TextAlign = ContentAlignment.MiddleLeft;
                var viewDropDown = new ToolStripDropDown();
                viewDropDown.LayoutStyle = ToolStripLayoutStyle.VerticalStackWithOverflow;
                for (int i = 0; i < viewOptions.Length; i++)
                {
                    string opt = viewOptions[i];
                    var item = new ToolStripMenuItem(opt);
                    int idx = i;
                    item.Click += (s, ev) => {
                        viewIndex = idx;
                        btnView.Text = opt;
                        updateDetail();
                        viewDropDown.Close();
                    };
                    viewDropDown.Items.Add(item);
                }
                btnView.Click += (s, e) => { viewDropDown.Show(btnView, new Point(0, btnView.Height)); };
                detailHeader.Controls.Add(btnView);

                btnApply.Click += (s, e) => applyFilter();
                btnReset.Click += (s, e) => {
                    txtId.Text = "";
                    txtSource.Text = "";
                    txtUser.Text = "";
                    txtContains.Text = "";
                    applyFilter();
                };

                applyFilter();

                grid.SelectionChanged += (s, e) => updateDetail();

                p.Controls.Add(split);
        }

        private string GetEventDetailsFromXml(string xml)
        {
            try
            {
                XDocument doc = XDocument.Parse(xml);
                XNamespace ns = doc.Root.GetDefaultNamespace();
                
                // Look for EventData -> Data
                var dataItems = doc.Descendants(ns + "Data").Select(x => 
                    new { 
                        Name = x.Attribute("Name") != null ? x.Attribute("Name").Value : "", 
                        Value = x.Value.Trim() 
                    }).Where(x => !string.IsNullOrEmpty(x.Value)).ToList();

                if (dataItems.Any())
                {
                    return string.Join(", ", dataItems.Select(x => 
                        string.IsNullOrEmpty(x.Name) ? x.Value : string.Format("{0}: {1}", x.Name, x.Value)
                    ));
                }
                
                // Fallback: Try UserData (common in some system events)
                // UserData usually has a custom sub-element
                var userData = doc.Descendants(ns + "UserData").FirstOrDefault();
                if (userData != null && userData.HasElements)
                {
                     // Get all leaf elements
                     var leaves = userData.Descendants().Where(e => !e.HasElements);
                     return string.Join(", ", leaves.Select(x => string.Format("{0}: {1}", x.Name.LocalName, x.Value)));
                }

                return "";
            }
            catch
            {
                return "";
            }
        }


        private TabPage CreateScheduledTaskTab(IR_Collect.Analysis.CaseData c)
        {
            string fileName = ArtifactNames.ScheduledTasksXml;
            string path = ResolveArtifactPathFlexible(c, fileName);
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return null;
            const long MaxScheduledTasksXmlBytes = 20L * 1024 * 1024;
            if (new FileInfo(path).Length > MaxScheduledTasksXmlBytes) { IR_Collect.Utils.Logger.Warning("Scheduled Tasks XML too large: " + path); return null; }

            try
            {
                // Handles concatenated XMLs from schtasks query (UTF-8)
                string content = File.ReadAllText(path, System.Text.Encoding.UTF8).Trim();
                // Strip <?xml ...?> headers if any remain
                content = System.Text.RegularExpressions.Regex.Replace(content, @"<\?xml.*?\?>", "", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                
                // Only wrap if not already wrapped in <Tasks>
                string wrapped = content;
                if (!content.StartsWith("<Tasks>", StringComparison.OrdinalIgnoreCase))
                {
                    wrapped = "<Tasks>" + content + "</Tasks>";
                }

                XDocument doc = XDocument.Parse(wrapped);
                
                TabPage p = new TabPage("Scheduled Tasks (XML)");
                DataGridView grid = CreateGrid();
                grid.Columns.Add("Path", "Task Path");
                grid.Columns.Add("Enabled", "Enabled");
                grid.Columns.Add("Command", "Command");
                grid.Columns.Add("Arguments", "Arguments");
                grid.Columns.Add("Triggers", "Triggers");
                grid.Columns.Add("RunAs", "Run As");
                grid.Columns[grid.Columns.Count - 1].AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;

                var tasks = doc.Descendants().Where(e => e.Name.LocalName == "Task");
                foreach (var task in tasks)
                {
                    var uriNode = task.Descendants().FirstOrDefault(e => e.Name.LocalName == "URI");
                    string uri = uriNode != null ? uriNode.Value : "";
                    
                    string enabled = "True";
                    var settings = task.Descendants().FirstOrDefault(e => e.Name.LocalName == "Settings");
                    if (settings != null)
                    {
                        var en = settings.Descendants().FirstOrDefault(e => e.Name.LocalName == "Enabled");
                        if (en != null) enabled = en.Value;
                    }

                    List<string> cmdList = new List<string>();
                    List<string> argList = new List<string>();

                    var actions = task.Descendants().FirstOrDefault(e => e.Name.LocalName == "Actions");
                    if (actions != null)
                    {
                        foreach(var act in actions.Elements())
                        {
                            if (act.Name.LocalName == "Exec")
                            {
                                var cmdNode = act.Elements().FirstOrDefault(e => e.Name.LocalName == "Command");
                                string cmd = cmdNode != null ? cmdNode.Value : "";
                                cmdList.Add(cmd);

                                var argsNode = act.Elements().FirstOrDefault(e => e.Name.LocalName == "Arguments");
                                string args = argsNode != null ? argsNode.Value : "";
                                argList.Add(args);
                            }
                            else if (act.Name.LocalName == "ComHandler")
                            {
                                var clsNode = act.Elements().FirstOrDefault(e => e.Name.LocalName == "ClassId");
                                string cls = clsNode != null ? clsNode.Value : "";
                                cmdList.Add("COM: " + cls);
                                argList.Add("");
                            }
                            else
                            {
                                cmdList.Add(act.Name.LocalName);
                                argList.Add("");
                            }
                        }
                    }
                    string cmdStr = string.Join(Environment.NewLine, cmdList);
                    string argStr = string.Join(Environment.NewLine, argList);

                    List<string> triggersList = new List<string>();
                    var triggers = task.Descendants().FirstOrDefault(e => e.Name.LocalName == "Triggers");
                    if (triggers != null)
                    {
                        foreach(var t in triggers.Elements()) triggersList.Add(t.Name.LocalName);
                    }
                    string triggerStr = string.Join(", ", triggersList);

                    string runAs = "";
                    var princ = task.Descendants().FirstOrDefault(e => e.Name.LocalName == "Principal");
                    if (princ != null)
                    {
                        var uid = princ.Elements().FirstOrDefault(e => e.Name.LocalName == "UserId");
                        var gid = princ.Elements().FirstOrDefault(e => e.Name.LocalName == "GroupId");
                        
                        if (uid != null) runAs = uid.Value;
                        else if (gid != null) runAs = gid.Value;
                    }

                    grid.Rows.Add(uri, enabled, cmdStr, argStr, triggerStr, runAs);
                }

                p.Controls.Add(grid);
                return p;
            }
            catch
            {
                return null;
            }
        }

        private DataGridView CreateGrid()
        {
            DataGridView g = new DataGridView();
            g.Dock = DockStyle.Fill;
            g.ReadOnly = true;
            g.AllowUserToAddRows = false;
            SetDoubleBuffered(g);
            // Allow manual resizing
            g.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.None; 
            g.AllowUserToResizeColumns = true;
            g.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
            g.RowHeadersVisible = false;
            g.Font = this.uiFont; // Use larger font
            g.ColumnHeadersHeight = 35;
            
            // Context Menu Bind
            g.CellMouseDown += (s, e) => {
                if (e.Button == MouseButtons.Right && e.RowIndex >= 0 && e.ColumnIndex >= 0) {
                    g.CurrentCell = g[e.ColumnIndex, e.RowIndex];
                    object cellVal = g.CurrentCell.Value;
                    string val = (cellVal != null) ? cellVal.ToString() : "";
                    
                    if (this.ctxGridMenu != null)
                    {
                        // Update VT state
                        bool isHash = !string.IsNullOrEmpty(val) && System.Text.RegularExpressions.Regex.IsMatch(val, "^[a-fA-F0-9]{32,64}$"); 
                        if (this.ctxGridMenu.Items.Count > 1) this.ctxGridMenu.Items[1].Enabled = isHash;
                        this.ctxGridMenu.Tag = g.CurrentCell;
                        this.ctxGridMenu.Show(Cursor.Position);
                    }
                }
            };
            return g;
        }




        private void FillGridFromCsv(DataGridView grid, string csvPath)
        {
            try 
            {
                // Prefer UTF-8 (our output); WMIC CSVs may be UCS-2, fallback to default
                string[] lines;
                try { lines = File.ReadAllLines(csvPath, System.Text.Encoding.UTF8); }
                catch { lines = File.ReadAllLines(csvPath, Encoding.Default); }

                // Filter out completely empty lines first
                var validLines = lines.Where(l => !string.IsNullOrWhiteSpace(l.Trim())).ToList();

                if (validLines.Count == 0) return;

                // Detect Header
                // If header contains "Node" (from WMIC), it's the header.
                // The first valid line might be the header.
                string headerLine = validLines[0];
                var headers = SplitCsvLine(headerLine);
                
                // If strictly WMIC format, sometimes Node is the first column.
                // Let's create columns
                foreach(var h in headers) grid.Columns.Add(h, h);
                if (grid.Columns.Count > 0)
                    grid.Columns[grid.Columns.Count - 1].AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;

                int colCount = grid.Columns.Count;
                for(int i=1; i<validLines.Count; i++)
                {
                    string line = validLines[i];
                    if (line.Trim() == headerLine.Trim()) continue;
                    var parts = SplitCsvLine(line);
                    if (parts.Length == 0) continue;
                    if (parts.Length != colCount)
                    {
                        var padded = new object[colCount];
                        for (int j = 0; j < colCount; j++) padded[j] = (j < parts.Length) ? parts[j] : "";
                        grid.Rows.Add(padded);
                    }
                    else
                        grid.Rows.Add(parts);
                }
            }
            catch
            {
                // Just swallow UI errors in list for now or log
                // MessageBox.Show("Error parsing CSV " + Path.GetFileName(csvPath) + ": " + ex.Message);
            }
        }

        /// <summary>統一使用 CsvUtils.SplitLine（RFC 4180，含 "" 跳脫）。</summary>
        private string[] SplitCsvLine(string line)
        {
            return CsvUtils.SplitLine(line ?? "");
        }

    }
}
