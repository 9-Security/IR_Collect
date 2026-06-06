using System;
using System.Collections.Generic;
using System.IO;
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

            try
            {
                using (var ese = new EseReader(dbPath))
                {
                    List<string> tables = ese.GetTableNames();
                    string idMapTable = ResolveTableName(tables, IdMapTableCandidates);
                    string networkTable = ResolveTableName(tables, NetworkTableCandidates);
                    string appTable = ResolveTableName(tables, AppTableCandidates);

                    Dictionary<long, string> idMap = LoadIdMap(ese, idMapTable, result);

                    if (string.IsNullOrWhiteSpace(networkTable))
                    {
                        result.FallbackUsed = true;
                        result.ParserNotes.Add("SRUM network usage table not found in this database schema.");
                    }
                    else
                    {
                        ExtractNetworkRows(ese, networkTable, idMap, result);
                    }

                    if (string.IsNullOrWhiteSpace(appTable))
                    {
                        result.FallbackUsed = true;
                        result.ParserNotes.Add("SRUM app usage table not found in this database schema.");
                    }
                    else
                    {
                        ExtractAppRows(ese, appTable, idMap, result);
                    }

                    if (result.NetworkRows.Count == 0 && result.AppRows.Count == 0)
                    {
                        result.FallbackUsed = true;
                        result.ParserNotes.Add("SRUM ESE parse opened the database but extracted no structured rows.");
                    }
                }
            }
            catch (Exception ex)
            {
                result.FallbackUsed = true;
                result.ParserNotes.Add("SRUM ESE export exception: " + Shorten(ex.Message, 220));
            }
            return result;
        }

        private static Dictionary<long, string> LoadIdMap(EseReader ese, string idMapTable, SrumExportResult result)
        {
            var idMap = new Dictionary<long, string>();
            if (string.IsNullOrWhiteSpace(idMapTable))
            {
                result.FallbackUsed = true;
                result.ParserNotes.Add("SRUM IdMap table not found; AppId/User mapping may stay numeric.");
                return idMap;
            }
            foreach (var row in ese.ReadRows(idMapTable, new[] { "IdType", "IdIndex", "IdBlob" }))
            {
                long id = AsInt64(Pick(row, "IdIndex", "Id"));
                if (id <= 0) continue;
                object blobObj = Pick(row, "IdBlob", "Blob", "Data");
                string decoded = DecodeIdBlob(blobObj);
                if (!string.IsNullOrWhiteSpace(decoded))
                    idMap[id] = decoded;
            }
            return idMap;
        }

        private static void ExtractNetworkRows(EseReader ese, string tableName, Dictionary<long, string> idMap, SrumExportResult result)
        {
            string[] cols = { "AppId", "UserId", "InterfaceLuid", "L2ProfileId", "TimeStamp",
                "BytesSent", "BytesRecvd", "RemoteAddress" };
            foreach (var row in ese.ReadRows(tableName, cols))
            {
                string appId = ResolveMappedId(Pick(row, "AppId", "ApplicationId"), idMap);
                string user = ResolveMappedId(Pick(row, "UserId", "UserSID"), idMap);
                string iface = ResolveMappedId(Pick(row, "InterfaceLuid", "InterfaceId", "L2ProfileId"), idMap);
                result.NetworkRows.Add(new SrumNetworkRecord
                {
                    Timestamp = ParseSrumTime(Pick(row, "TimeStamp", "Timestamp")),
                    AppId = appId,
                    Path = GuessPath(appId),
                    User = user,
                    RemoteIP = SafeText(Pick(row, "RemoteAddress", "RemoteIP")),
                    InterfaceName = iface,
                    BytesSent = SafeText(Pick(row, "BytesSent", "OutgoingBytes")),
                    BytesReceived = SafeText(Pick(row, "BytesRecvd", "BytesReceived")),
                    ParserNote = "SRUM network row parsed from ESE; column set varies by Windows build."
                });
            }
        }

        private static void ExtractAppRows(EseReader ese, string tableName, Dictionary<long, string> idMap, SrumExportResult result)
        {
            string[] cols = { "AppId", "UserId", "TimeStamp", "ForegroundCycleTime", "BackgroundCycleTime" };
            foreach (var row in ese.ReadRows(tableName, cols))
            {
                string appId = ResolveMappedId(Pick(row, "AppId", "ApplicationId"), idMap);
                string user = ResolveMappedId(Pick(row, "UserId", "UserSID"), idMap);
                result.AppRows.Add(new SrumAppRecord
                {
                    Timestamp = ParseSrumTime(Pick(row, "TimeStamp", "Timestamp")),
                    AppId = appId,
                    Path = GuessPath(appId),
                    User = user,
                    ForegroundCycleTime = SafeText(Pick(row, "ForegroundCycleTime")),
                    BackgroundCycleTime = SafeText(Pick(row, "BackgroundCycleTime")),
                    ParserNote = "SRUM app row parsed from ESE; column set and counters vary across versions."
                });
            }
        }

        // Match a SRUM table GUID candidate (with or without braces) to the actual ESE table name.
        private static string ResolveTableName(List<string> tableNames, IEnumerable<string> candidates)
        {
            if (tableNames == null || candidates == null) return "";
            var byNorm = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (string t in tableNames)
            {
                string norm = NormalizeGuidLikeName(t);
                if (!byNorm.ContainsKey(norm)) byNorm[norm] = t;
            }
            foreach (string candidate in candidates)
            {
                if (string.IsNullOrWhiteSpace(candidate)) continue;
                string actual;
                if (byNorm.TryGetValue(NormalizeGuidLikeName(candidate), out actual))
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

        private static object Pick(Dictionary<string, object> row, params string[] names)
        {
            if (row == null || names == null) return null;
            foreach (string n in names)
            {
                object v;
                if (!string.IsNullOrEmpty(n) && row.TryGetValue(n, out v) && v != null) return v;
            }
            return null;
        }

        private static long AsInt64(object v)
        {
            if (v == null) return 0;
            if (v is long) return (long)v;
            if (v is int) return (int)v;
            long parsed;
            return long.TryParse(Convert.ToString(v), out parsed) ? parsed : 0;
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
