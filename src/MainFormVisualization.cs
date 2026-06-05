using System;
using System.IO;
using System.Windows.Forms;
using System.Drawing;
using IR_Collect.Utils;

namespace IR_Collect
{
    /// <summary>網路與系統資訊視覺化分頁（System Info / IP Config / Connections / ARP / DNS）。</summary>
    partial class MainForm
    {
        private const long MaxTxtFileBytes = 5L * 1024 * 1024; // 5MB for visualization txt files

        private TabPage CreateSystemInfoTab(IR_Collect.Analysis.CaseData c)
        {
            try {
                string path = GetArtifactPath(c, ArtifactNames.SystemInfoFullTxt);
                if (!File.Exists(path)) return null;
                if (new FileInfo(path).Length > MaxTxtFileBytes) { Logger.Warning("System info file too large: " + path); return null; }

                TabPage p = new TabPage("System Info");
                DataGridView grid = CreateGrid();
                grid.Columns.Add("Property", "Property");
                grid.Columns.Add("Value", "Value");
                grid.Columns[0].Width = 250;
                grid.Columns[1].AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;

                string[] lines = File.ReadAllLines(path, System.Text.Encoding.UTF8);
                foreach(var line in lines)
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    int idx = line.IndexOf(':');
                    if (idx > 0)
                    {
                        string key = line.Substring(0, idx).Trim();
                        string val = line.Substring(idx + 1).Trim();
                        grid.Rows.Add(key, val);
                    }
                    else if (line.StartsWith("   ") && grid.Rows.Count > 0)
                    {
                        var lastRow = grid.Rows[grid.Rows.Count - 1];
                        lastRow.Cells[1].Value += ", " + line.Trim();
                    }
                }
                p.Controls.Add(grid);
                return p;
            } catch (Exception ex) { Logger.Warning("CreateSystemInfoTab: " + (ex.Message ?? "")); return null; }
        }

        private TabPage CreateIpConfigTab(IR_Collect.Analysis.CaseData c)
        {
            try {
                string path = GetArtifactPath(c, "network_config.txt");
                if (!File.Exists(path)) return null;
                if (new FileInfo(path).Length > MaxTxtFileBytes) { Logger.Warning("Network config file too large: " + path); return null; }

                TabPage p = new TabPage("IP Config");
                TreeView tv = new TreeView();
                tv.Dock = DockStyle.Fill;
                tv.Font = this.uiFont;
                tv.ShowLines = true;
                tv.ShowPlusMinus = true;
                tv.BorderStyle = BorderStyle.None;

                string[] lines = File.ReadAllLines(path, System.Text.Encoding.UTF8);
                TreeNode currentAdapter = null;

                foreach(var line in lines)
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    if (line.StartsWith("   ") || line.StartsWith("\t"))
                    {
                        if (currentAdapter != null)
                        {
                            var trimmed = line.Trim();
                            if (trimmed.Contains(":"))
                            {
                                var parts = trimmed.Split(new char[]{':'}, 2);
                                currentAdapter.Nodes.Add(parts[0].Trim() + ": " + parts[1].Trim());
                            }
                            else currentAdapter.Nodes.Add(trimmed);
                        }
                    }
                    else if (!line.StartsWith(" "))
                    {
                        if (line.Contains("Configuration")) continue;
                        string adapterName = line.Trim().TrimEnd(':');
                        currentAdapter = new TreeNode(adapterName);
                        tv.Nodes.Add(currentAdapter);
                    }
                }
                tv.ExpandAll();
                p.Controls.Add(tv);
                return p;
            } catch (Exception ex) { Logger.Warning("CreateIpConfigTab: " + (ex.Message ?? "")); return null; }
        }

        private TabPage CreateConnectionsTab(IR_Collect.Analysis.CaseData c)
        {
            try {
                string path = GetArtifactPath(c, "network_connections.txt");
                if (!File.Exists(path)) return null;
                if (new FileInfo(path).Length > MaxTxtFileBytes) { Logger.Warning("Connections file too large: " + path); return null; }

                TabPage p = new TabPage("Connections");
                DataGridView grid = CreateGrid();
                grid.Columns.Add("Proto", "Proto");
                grid.Columns.Add("Local", "Local Address");
                grid.Columns.Add("Foreign", "Foreign Address");
                grid.Columns.Add("State", "State");
                grid.Columns.Add("PID", "PID");
                grid.Columns[0].Width = 70;
                grid.Columns[1].Width = 150;
                grid.Columns[2].Width = 150;
                grid.Columns[3].Width = 120;
                grid.Columns[4].AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;

                string[] lines = File.ReadAllLines(path, System.Text.Encoding.UTF8);
                foreach(var line in lines)
                {
                    var parts = line.Trim().Split(new char[]{' '}, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 4)
                    {
                        if (parts[0] == "TCP" || parts[0] == "UDP")
                        {
                            string proto = parts[0];
                            string loc   = parts[1];
                            string rem   = parts[2];
                            string state = (parts.Length > 4) ? parts[3] : "";
                            string pid   = (parts.Length > 4) ? parts[4] : parts[3];
                            if (proto == "UDP") { state = ""; pid = parts[3]; }
                            grid.Rows.Add(proto, loc, rem, state, pid);
                        }
                    }
                }
                p.Controls.Add(grid);
                return p;
            } catch (Exception ex) { Logger.Warning("CreateConnectionsTab: " + (ex.Message ?? "")); return null; }
        }

        private TabPage CreateArpTab(IR_Collect.Analysis.CaseData c)
        {
            try {
                string path = GetArtifactPath(c, "arp_table.txt");
                if (!File.Exists(path)) return null;
                if (new FileInfo(path).Length > MaxTxtFileBytes) { Logger.Warning("ARP file too large: " + path); return null; }

                TabPage p = new TabPage("ARP");
                DataGridView grid = CreateGrid();
                grid.Columns.Add("IP", "Internet Address");
                grid.Columns.Add("MAC", "Physical Address");
                grid.Columns.Add("Type", "Type");
                grid.Columns[0].Width = 150;
                grid.Columns[1].Width = 180;
                grid.Columns[2].AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;

                string[] lines = File.ReadAllLines(path, System.Text.Encoding.UTF8);
                foreach(var line in lines)
                {
                    var l = line.Trim();
                    if (string.IsNullOrEmpty(l) || l.StartsWith("Interface") || l.StartsWith("Internet")) continue;
                    var parts = l.Split(new char[]{' '}, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 3 && parts[0].Contains("."))
                        grid.Rows.Add(parts[0], parts[1], parts[2]);
                }
                p.Controls.Add(grid);
                return p;
            } catch (Exception ex) { Logger.Warning("CreateArpTab: " + (ex.Message ?? "")); return null; }
        }

        private string GetVal(string line)
        {
            int idx = line.IndexOf(':');
            return (idx >= 0) ? line.Substring(idx + 1).Trim() : "";
        }

        private TabPage CreateDnsTab(IR_Collect.Analysis.CaseData c)
        {
            try {
                string path = GetArtifactPath(c, "dns_cache.txt");
                if (!File.Exists(path)) return null;
                if (new FileInfo(path).Length > MaxTxtFileBytes) { Logger.Warning("DNS cache file too large: " + path); return null; }

                TabPage p = new TabPage("DNS Cache");
                DataGridView grid = CreateGrid();
                grid.Columns.Add("Name", "Record Name");
                grid.Columns.Add("Type", "Type");
                grid.Columns.Add("Data", "Data/IP");
                grid.Columns[0].Width = 250;
                grid.Columns[2].AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;

                string[] lines = File.ReadAllLines(path, System.Text.Encoding.UTF8);
                string name = "", type = "", data = "";
                bool readingRecord = false;

                foreach(var line in lines)
                {
                    var l = line.Trim();
                    if (l.StartsWith("Record Name")) {
                        if (readingRecord && !string.IsNullOrEmpty(name)) grid.Rows.Add(name, type, data);
                        name = GetVal(l); type = ""; data = ""; readingRecord = true;
                    }
                    else if (l.StartsWith("Record Type")) type = GetVal(l);
                    else if (l.StartsWith("A (Host) Record") || l.StartsWith("CNAME") || l.StartsWith("PTR"))
                    {
                        string v = GetVal(l);
                        if (!string.IsNullOrEmpty(data)) data += ", " + v; else data = v;
                    }
                }
                if (readingRecord && !string.IsNullOrEmpty(name)) grid.Rows.Add(name, type, data);
                p.Controls.Add(grid);
                return p;
            } catch (Exception ex) { Logger.Warning("CreateDnsTab: " + (ex.Message ?? "")); return null; }
        }
    }
}
