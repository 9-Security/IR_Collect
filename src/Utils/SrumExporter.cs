using System;
using System.Collections.Generic;
using System.Data;
using System.Data.OleDb;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Text;

namespace IR_Collect.Utils
{
    public sealed class SrumNetworkRecord
    {
        public string Timestamp { get; set; }
        public string AppId { get; set; }
        public string Path { get; set; }
        public string User { get; set; }
        public string RemoteIP { get; set; }
        public string InterfaceName { get; set; }
        public string BytesSent { get; set; }
        public string BytesReceived { get; set; }
        public string ParserNote { get; set; }
    }

    public sealed class SrumAppRecord
    {
        public string Timestamp { get; set; }
        public string AppId { get; set; }
        public string Path { get; set; }
        public string User { get; set; }
        public string ForegroundCycleTime { get; set; }
        public string BackgroundCycleTime { get; set; }
        public string ParserNote { get; set; }
    }

    public sealed class SrumExportResult
    {
        public List<SrumNetworkRecord> NetworkRows { get; private set; }
        public List<SrumAppRecord> AppRows { get; private set; }
        public List<string> ParserNotes { get; private set; }
        public bool FallbackUsed { get; set; }

        public SrumExportResult()
        {
            NetworkRows = new List<SrumNetworkRecord>();
            AppRows = new List<SrumAppRecord>();
            ParserNotes = new List<string>();
        }
    }

    public static class SrumExporter
    {
        private static readonly string[] ProviderCandidates = new[]
        {
            "Provider=Microsoft.ACE.OLEDB.16.0;Data Source={0};Persist Security Info=False;",
            "Provider=Microsoft.ACE.OLEDB.12.0;Data Source={0};Persist Security Info=False;",
            "Provider=Microsoft.Jet.OLEDB.4.0;Data Source={0};Extended Properties=Esent;"
        };

        private static readonly string[] IdMapTableCandidates = new[]
        {
            "SruDbIdMapTable",
            "{DD6636C4-8929-4683-974E-22C046A43763}"
        };

        private static readonly string[] NetworkTableCandidates = new[]
        {
            "{973F5D5C-1D90-4944-BE8E-24B94231A174}"
        };

        private static readonly string[] AppTableCandidates = new[]
        {
            "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}"
        };

        public static SrumExportResult Export(string dbPath)
        {
            var result = new SrumExportResult();
            if (string.IsNullOrWhiteSpace(dbPath) || !File.Exists(dbPath))
            {
                result.FallbackUsed = true;
                result.ParserNotes.Add("SRUDB.dat not found; wrote header-only CSV.");
                return result;
            }

            OleDbConnection conn = null;
            string providerName = "";
            try
            {
                conn = OpenConnection(dbPath, out providerName);
                if (conn == null)
                {
                    result.FallbackUsed = true;
                    result.ParserNotes.Add("No available OLE DB provider could open SRUDB.dat on this host.");
                    return result;
                }

                var tableMap = LoadTableMap(conn);
                var idMap = LoadIdMap(conn, tableMap, result);
                string networkTable = ResolveTableName(tableMap, NetworkTableCandidates);
                string appTable = ResolveTableName(tableMap, AppTableCandidates);

                if (string.IsNullOrWhiteSpace(networkTable))
                {
                    result.FallbackUsed = true;
                    result.ParserNotes.Add("SRUM network usage table not found in this database schema.");
                }
                else
                {
                    ExtractNetworkRows(conn, networkTable, idMap, result);
                }

                if (string.IsNullOrWhiteSpace(appTable))
                {
                    result.FallbackUsed = true;
                    result.ParserNotes.Add("SRUM app usage table not found in this database schema.");
                }
                else
                {
                    ExtractAppRows(conn, appTable, idMap, result);
                }

                if (result.NetworkRows.Count == 0 && result.AppRows.Count == 0)
                {
                    result.FallbackUsed = true;
                    result.ParserNotes.Add("SRUM parse completed with provider '" + providerName + "' but extracted no structured rows.");
                }
            }
            catch (Exception ex)
            {
                result.FallbackUsed = true;
                result.ParserNotes.Add("SRUM export exception: " + Shorten(ex.Message, 220));
            }
            finally
            {
                if (conn != null)
                {
                    try { conn.Close(); }
                    catch { }
                    conn.Dispose();
                }
            }
            return result;
        }

        private static OleDbConnection OpenConnection(string dbPath, out string providerName)
        {
            providerName = "";
            foreach (string template in ProviderCandidates)
            {
                string connStr = string.Format(template, dbPath);
                OleDbConnection conn = null;
                try
                {
                    conn = new OleDbConnection(connStr);
                    conn.Open();
                    providerName = template.Split(';')[0];
                    return conn;
                }
                catch (Exception ex)
                {
                    if (conn != null) conn.Dispose();
                    Logger.Warning("SrumExporter provider failed: " + ex.Message);
                }
            }
            return null;
        }

        private static Dictionary<string, string> LoadTableMap(OleDbConnection conn)
        {
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            DataTable schema = conn.GetOleDbSchemaTable(OleDbSchemaGuid.Tables, null);
            if (schema == null) return map;
            foreach (DataRow row in schema.Rows)
            {
                string tableType = SafeText(row["TABLE_TYPE"]);
                if (!string.Equals(tableType, "TABLE", StringComparison.OrdinalIgnoreCase))
                    continue;
                string tableName = SafeText(row["TABLE_NAME"]);
                if (string.IsNullOrWhiteSpace(tableName))
                    continue;
                string normalized = NormalizeGuidLikeName(tableName);
                if (!map.ContainsKey(normalized))
                    map[normalized] = tableName;
            }
            return map;
        }

        private static Dictionary<long, string> LoadIdMap(OleDbConnection conn, Dictionary<string, string> tableMap, SrumExportResult result)
        {
            var idMap = new Dictionary<long, string>();
            string idMapTable = ResolveTableName(tableMap, IdMapTableCandidates);
            if (string.IsNullOrWhiteSpace(idMapTable))
            {
                result.FallbackUsed = true;
                result.ParserNotes.Add("SRUM IdMap table not found; AppId/User mapping may stay numeric.");
                return idMap;
            }

            string sql = "SELECT * FROM [" + idMapTable + "]";
            using (var cmd = new OleDbCommand(sql, conn))
            using (var reader = cmd.ExecuteReader())
            {
                if (reader == null) return idMap;
                while (reader.Read())
                {
                    long id = TryGetInt64(reader, "IdIndex", "Id");
                    if (id <= 0) continue;
                    object blobObj = TryGet(reader, "IdBlob", "Blob", "Data");
                    string decoded = DecodeIdBlob(blobObj);
                    if (string.IsNullOrWhiteSpace(decoded))
                        decoded = SafeText(TryGet(reader, "IdValue", "Value"));
                    if (!string.IsNullOrWhiteSpace(decoded))
                        idMap[id] = decoded;
                }
            }
            return idMap;
        }

        private static void ExtractNetworkRows(OleDbConnection conn, string tableName, Dictionary<long, string> idMap, SrumExportResult result)
        {
            string sql = "SELECT * FROM [" + tableName + "]";
            using (var cmd = new OleDbCommand(sql, conn))
            using (var reader = cmd.ExecuteReader())
            {
                if (reader == null) return;
                while (reader.Read())
                {
                    string appId = ResolveMappedId(TryGet(reader, "AppId", "ApplicationId"), idMap);
                    string user = ResolveMappedId(TryGet(reader, "UserId", "UserSID"), idMap);
                    string iface = ResolveMappedId(TryGet(reader, "InterfaceLuid", "InterfaceId", "L2ProfileId"), idMap);
                    string remoteIp = SafeText(TryGet(reader, "RemoteAddress", "RemoteIP", "DestinationIp", "DestIp"));
                    string path = GuessPath(appId);
                    string ts = ParseSrumTime(TryGet(reader, "TimeStamp", "Timestamp", "ConnectStartTime", "StartTime"));

                    result.NetworkRows.Add(new SrumNetworkRecord
                    {
                        Timestamp = ts,
                        AppId = appId,
                        Path = path,
                        User = user,
                        RemoteIP = remoteIp,
                        InterfaceName = iface,
                        BytesSent = SafeText(TryGet(reader, "BytesSent", "OutgoingBytes", "SentBytes")),
                        BytesReceived = SafeText(TryGet(reader, "BytesRecvd", "BytesReceived", "IncomingBytes", "RecvBytes")),
                        ParserNote = "SRUM network row parsed from core table; available columns vary by Windows build."
                    });
                }
            }
        }

        private static void ExtractAppRows(OleDbConnection conn, string tableName, Dictionary<long, string> idMap, SrumExportResult result)
        {
            string sql = "SELECT * FROM [" + tableName + "]";
            using (var cmd = new OleDbCommand(sql, conn))
            using (var reader = cmd.ExecuteReader())
            {
                if (reader == null) return;
                while (reader.Read())
                {
                    string appId = ResolveMappedId(TryGet(reader, "AppId", "ApplicationId"), idMap);
                    string user = ResolveMappedId(TryGet(reader, "UserId", "UserSID"), idMap);
                    string ts = ParseSrumTime(TryGet(reader, "TimeStamp", "Timestamp", "EndTime", "StartTime"));
                    string path = GuessPath(appId);

                    result.AppRows.Add(new SrumAppRecord
                    {
                        Timestamp = ts,
                        AppId = appId,
                        Path = path,
                        User = user,
                        ForegroundCycleTime = SafeText(TryGet(reader, "ForegroundCycleTime", "ForegroundContextSwitches")),
                        BackgroundCycleTime = SafeText(TryGet(reader, "BackgroundCycleTime", "BackgroundContextSwitches")),
                        ParserNote = "SRUM app row parsed from core table; column set and counters vary across versions."
                    });
                }
            }
        }

        private static string ResolveTableName(Dictionary<string, string> tableMap, IEnumerable<string> candidates)
        {
            if (tableMap == null || candidates == null) return "";
            foreach (string candidate in candidates)
            {
                if (string.IsNullOrWhiteSpace(candidate)) continue;
                string normalized = NormalizeGuidLikeName(candidate);
                string actual;
                if (tableMap.TryGetValue(normalized, out actual))
                    return actual;
            }
            return "";
        }

        private static string NormalizeGuidLikeName(string name)
        {
            if (string.IsNullOrWhiteSpace(name)) return "";
            string n = name.Trim().Trim('[', ']', '{', '}');
            return "{" + n.ToUpperInvariant() + "}";
        }

        private static object TryGet(IDataRecord r, params string[] names)
        {
            if (r == null || names == null) return null;
            for (int i = 0; i < names.Length; i++)
            {
                string target = names[i];
                if (string.IsNullOrWhiteSpace(target)) continue;
                for (int c = 0; c < r.FieldCount; c++)
                {
                    if (string.Equals(r.GetName(c), target, StringComparison.OrdinalIgnoreCase))
                    {
                        object v = r.GetValue(c);
                        return v == DBNull.Value ? null : v;
                    }
                }
            }
            return null;
        }

        private static long TryGetInt64(IDataRecord r, params string[] names)
        {
            object v = TryGet(r, names);
            if (v == null) return 0;
            try
            {
                if (v is long) return (long)v;
                if (v is int) return (int)v;
                if (v is short) return (short)v;
                long parsed;
                return long.TryParse(v.ToString(), out parsed) ? parsed : 0;
            }
            catch
            {
                return 0;
            }
        }

        private static string ResolveMappedId(object raw, Dictionary<long, string> idMap)
        {
            if (raw == null) return "";
            string text = SafeText(raw);
            long id;
            if (long.TryParse(text, out id) && idMap != null)
            {
                string mapped;
                if (idMap.TryGetValue(id, out mapped) && !string.IsNullOrWhiteSpace(mapped))
                    return mapped;
            }
            return text;
        }

        internal static string DecodeIdBlob(object blobObj)
        {
            byte[] data = blobObj as byte[];
            if (data == null || data.Length == 0) return "";

            try
            {
                // A SECURITY_IDENTIFIER blob is: revision(0x01) | subAuthCount(0..15) | 6-byte authority
                // | 4*count sub-authorities, so length == 8 + 4*count. Requiring the revision byte and
                // exact length stops UTF-16 AppId text (whose 2nd byte is often 0x00) being mis-decoded
                // into a bogus SID string.
                if (data.Length >= 8 && data[0] == 0x01 && data[1] <= 15 && data.Length == 8 + 4 * data[1])
                {
                    var sid = new SecurityIdentifier(data, 0);
                    return sid.ToString();
                }
            }
            catch { }

            try
            {
                string utf16 = Encoding.Unicode.GetString(data).Trim('\0', ' ', '\t', '\r', '\n');
                if (!string.IsNullOrWhiteSpace(utf16) && utf16.IndexOf('\uFFFD') < 0)
                    return utf16;
            }
            catch { }

            try
            {
                string utf8 = Encoding.UTF8.GetString(data).Trim('\0', ' ', '\t', '\r', '\n');
                if (!string.IsNullOrWhiteSpace(utf8) && utf8.IndexOf('\uFFFD') < 0)
                    return utf8;
            }
            catch { }

            return BitConverter.ToString(data).Replace("-", "");
        }

        private static string GuessPath(string appId)
        {
            if (string.IsNullOrWhiteSpace(appId))
                return "";
            string trimmed = appId.Trim();
            if (trimmed.IndexOf(":\\", StringComparison.OrdinalIgnoreCase) > 0 || trimmed.StartsWith(@"\\", StringComparison.OrdinalIgnoreCase))
                return trimmed;
            return "";
        }

        private static string ParseSrumTime(object raw)
        {
            if (raw == null) return "";
            try
            {
                if (raw is DateTime)
                {
                    DateTime dt = (DateTime)raw;
                    return dt.Year > 1980 ? dt.ToString("yyyy-MM-dd HH:mm:ss") : "";
                }
                string text = SafeText(raw);
                DateTime parsed;
                if (DateTime.TryParse(text, out parsed) && parsed.Year > 1980)
                    return parsed.ToString("yyyy-MM-dd HH:mm:ss");
                long n;
                if (long.TryParse(text, out n))
                {
                    if (n > 116444736000000000 && n < 200000000000000000)
                        return DateTime.FromFileTimeUtc(n).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
                    if (n > 0 && n < 4102444800)
                        return new DateTime(1970, 1, 1).AddSeconds(n).ToString("yyyy-MM-dd HH:mm:ss");
                }
            }
            catch { }
            return "";
        }

        private static string SafeText(object value)
        {
            if (value == null || value == DBNull.Value)
                return "";
            return EventLogDataHelper.SanitizeSingleLine(Convert.ToString(value) ?? "");
        }

        private static string Shorten(string text, int maxLen)
        {
            if (string.IsNullOrWhiteSpace(text) || maxLen <= 0)
                return "";
            if (text.Length <= maxLen)
                return text;
            return text.Substring(0, maxLen - 3) + "...";
        }
    }
}
