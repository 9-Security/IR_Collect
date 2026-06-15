using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace IR_Collect.Utils
{
    /// <summary>
    /// Minimal read-only reader for ESE ("JET Blue" / esent) databases such as SRUDB.dat, via P/Invoke
    /// into esent.dll (a Windows system DLL, so no external dependency). Opens a database read-only with
    /// recovery off (works on a copied/dirty file), enumerates table names, and reads rows of the columns
    /// you ask for as a name->value dictionary. Built for Phase 2.3 to replace the OLE DB/ACE path, which
    /// cannot read ESE at all.
    /// </summary>
    internal sealed class EseReader : IDisposable
    {
        // JET handle widths: instance/session/table are pointer-sized; dbid/columnid are 32-bit.
        private IntPtr _instance = IntPtr.Zero;
        private IntPtr _sesid = IntPtr.Zero;
        private uint _dbid;
        private bool _attached;
        private bool _inited;
        private readonly string _dbPath;
        private readonly string _tempPath;

        // --- JET constants ---
        private const uint JET_paramSystemPath = 0;
        private const uint JET_paramTempPath = 1;
        private const uint JET_paramLogFilePath = 2;
        private const uint JET_paramBaseName = 3;
        private const uint JET_paramRecovery = 34;
        private const uint JET_paramMaxTemporaryTables = 40;
        private const uint JET_paramDatabasePageSize = 64;
        private const uint JET_paramCreatePathIfNotExist = 100;

        private const uint JET_bitDbReadOnly = 0x00000001;
        private const int JET_MoveFirst = unchecked((int)0x80000000);
        private const int JET_MoveNext = 1;

        private const uint JET_DbInfoPageSize = 17;
        private const uint JET_objtypTable = 1;
        private const uint JET_ObjInfoListNoStats = 2;

        private const int JET_errSuccess = 0;
        private const int JET_errNoCurrentRecord = -1603;
        private const int JET_errColumnNotFound = -1004;
        private const int JET_wrnBufferTruncated = 1006;
        private const int JET_wrnColumnNull = 1004;

        // JET_coltyp
        private const uint coltypBit = 1, coltypUnsignedByte = 2, coltypShort = 3, coltypLong = 4,
            coltypCurrency = 5, coltypIEEESingle = 6, coltypIEEEDouble = 7, coltypDateTime = 8,
            coltypBinary = 9, coltypText = 10, coltypLongBinary = 11, coltypLongText = 12,
            coltypUnsignedLong = 14, coltypLongLong = 15, coltypGUID = 16, coltypUnsignedShort = 17;

        internal EseReader(string dbPath)
        {
            _dbPath = dbPath;
            _tempPath = System.IO.Path.Combine(System.IO.Path.GetTempPath(),
                "IRCol_ESE_" + Guid.NewGuid().ToString("N"));
            System.IO.Directory.CreateDirectory(_tempPath);
            Open();
        }

        private static void Check(int err, string where)
        {
            if (err < 0) throw new InvalidOperationException("ESE " + where + " failed: JET_err " + err);
        }

        private void Open()
        {
            int pageSize = 0;
            // Page size must be set before init or attach can fail with a mismatch; read it from the file.
            NativeMethods.JetGetDatabaseFileInfoW(_dbPath, out pageSize, sizeof(int), JET_DbInfoPageSize);
            if (pageSize <= 0) pageSize = 8192;

            Check(NativeMethods.JetCreateInstanceW(out _instance, "IRCol_" + Guid.NewGuid().ToString("N")), "JetCreateInstance");

            // Recovery off + private temp/log paths so a copied SRUDB.dat opens without its logs and
            // without touching the original directory.
            SetParam(JET_paramRecovery, IntPtr.Zero, "Off");
            SetParam(JET_paramDatabasePageSize, (IntPtr)pageSize, null);
            SetParam(JET_paramMaxTemporaryTables, (IntPtr)1, null);
            SetParam(JET_paramTempPath, IntPtr.Zero, _tempPath + System.IO.Path.DirectorySeparatorChar);
            SetParam(JET_paramSystemPath, IntPtr.Zero, _tempPath + System.IO.Path.DirectorySeparatorChar);
            SetParam(JET_paramLogFilePath, IntPtr.Zero, _tempPath + System.IO.Path.DirectorySeparatorChar);
            SetParam(JET_paramCreatePathIfNotExist, (IntPtr)1, null);

            Check(NativeMethods.JetInit(ref _instance), "JetInit");
            _inited = true;
            Check(NativeMethods.JetBeginSessionW(_instance, out _sesid, null, null), "JetBeginSession");
            Check(NativeMethods.JetAttachDatabaseW(_sesid, _dbPath, JET_bitDbReadOnly), "JetAttachDatabase");
            _attached = true;
            Check(NativeMethods.JetOpenDatabaseW(_sesid, _dbPath, null, out _dbid, JET_bitDbReadOnly), "JetOpenDatabase");
        }

        private void SetParam(uint paramid, IntPtr lParam, string sz)
        {
            Check(NativeMethods.JetSetSystemParameterW(ref _instance, IntPtr.Zero, paramid, lParam, sz), "JetSetSystemParameter(" + paramid + ")");
        }

        /// <summary>All user table names in the database.</summary>
        internal List<string> GetTableNames()
        {
            var names = new List<string>();
            var list = new JET_OBJECTLIST();
            list.cbStruct = (uint)Marshal.SizeOf(typeof(JET_OBJECTLIST));
            int err = NativeMethods.JetGetObjectInfoW(_sesid, _dbid, JET_objtypTable, null, null,
                ref list, list.cbStruct, JET_ObjInfoListNoStats);
            if (err < 0) return names;
            IntPtr tbl = list.tableid;
            try
            {
                int move = NativeMethods.JetMove(_sesid, tbl, JET_MoveFirst, 0);
                while (move == JET_errSuccess)
                {
                    string n = RetrieveString(tbl, list.columnidobjectname);
                    if (!string.IsNullOrEmpty(n)) names.Add(n);
                    move = NativeMethods.JetMove(_sesid, tbl, JET_MoveNext, 0);
                }
            }
            finally
            {
                NativeMethods.JetCloseTable(_sesid, tbl);
            }
            return names;
        }

        /// <summary>
        /// Read every row of <paramref name="tableName"/>, returning the requested columns (by name,
        /// case-insensitive) as a dictionary per row. Unknown columns are simply absent.
        /// </summary>
        internal List<Dictionary<string, object>> ReadRows(string tableName, IEnumerable<string> wantColumns)
        {
            var rows = new List<Dictionary<string, object>>();
            IntPtr tableid;
            int oerr = NativeMethods.JetOpenTableW(_sesid, _dbid, tableName, IntPtr.Zero, 0, JET_bitDbReadOnly, out tableid);
            if (oerr < 0) return rows;
            try
            {
                // Resolve columnid + type for each wanted column once.
                var cols = new List<ColRef>();
                foreach (string want in wantColumns)
                {
                    var def = new JET_COLUMNDEF();
                    def.cbStruct = (uint)Marshal.SizeOf(typeof(JET_COLUMNDEF));
                    int cerr = NativeMethods.JetGetTableColumnInfoW(_sesid, tableid, want, ref def,
                        def.cbStruct, 0 /* JET_ColInfo */);
                    if (cerr == JET_errColumnNotFound || cerr < 0) continue;
                    cols.Add(new ColRef { Name = want, Columnid = def.columnid, Coltyp = def.coltyp, Cp = def.cp });
                }
                if (cols.Count == 0) return rows;

                int move = NativeMethods.JetMove(_sesid, tableid, JET_MoveFirst, 0);
                while (move == JET_errSuccess)
                {
                    var row = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
                    foreach (var c in cols)
                    {
                        object val = RetrieveColumn(tableid, c);
                        if (val != null) row[c.Name] = val;
                    }
                    rows.Add(row);
                    move = NativeMethods.JetMove(_sesid, tableid, JET_MoveNext, 0);
                }
            }
            finally
            {
                NativeMethods.JetCloseTable(_sesid, tableid);
            }
            return rows;
        }

        private sealed class ColRef
        {
            public string Name;
            public uint Columnid;
            public uint Coltyp;
            public ushort Cp;
        }

        private object RetrieveColumn(IntPtr tableid, ColRef c)
        {
            byte[] raw = RetrieveRaw(tableid, c.Columnid);
            if (raw == null) return null;
            switch (c.Coltyp)
            {
                case coltypBit:
                case coltypUnsignedByte:
                    return raw.Length >= 1 ? (long)raw[0] : 0L;
                case coltypShort:
                    return raw.Length >= 2 ? (long)BitConverter.ToInt16(raw, 0) : 0L;
                case coltypUnsignedShort:
                    return raw.Length >= 2 ? (long)BitConverter.ToUInt16(raw, 0) : 0L;
                case coltypLong:
                    return raw.Length >= 4 ? (long)BitConverter.ToInt32(raw, 0) : 0L;
                case coltypUnsignedLong:
                    return raw.Length >= 4 ? (long)BitConverter.ToUInt32(raw, 0) : 0L;
                case coltypLongLong:
                case coltypCurrency:
                    return raw.Length >= 8 ? BitConverter.ToInt64(raw, 0) : 0L;
                case coltypIEEESingle:
                    return raw.Length >= 4 ? (double)BitConverter.ToSingle(raw, 0) : 0.0;
                case coltypIEEEDouble:
                    return raw.Length >= 8 ? BitConverter.ToDouble(raw, 0) : 0.0;
                case coltypDateTime:
                    if (raw.Length >= 8)
                    {
                        double oa = BitConverter.ToDouble(raw, 0);
                        try { return DateTime.FromOADate(oa); } catch { return null; }
                    }
                    return null;
                case coltypText:
                case coltypLongText:
                    {
                        Encoding enc = c.Cp == 1200 ? Encoding.Unicode : Encoding.GetEncoding(c.Cp == 0 ? 1252 : c.Cp);
                        return enc.GetString(raw).TrimEnd('\0');
                    }
                case coltypGUID:
                    return raw.Length >= 16 ? new Guid(raw).ToString() : (object)raw;
                default:
                    return raw; // binary / unknown -> raw bytes (DecodeIdBlob handles SID/text blobs)
            }
        }

        private byte[] RetrieveRaw(IntPtr tableid, uint columnid)
        {
            uint cbActual;
            int err = NativeMethods.JetRetrieveColumn(_sesid, tableid, columnid, IntPtr.Zero, 0, out cbActual, 0, IntPtr.Zero);
            if (err == JET_wrnColumnNull) return null;
            if (cbActual == 0)
            {
                if (err < 0 && err != JET_wrnBufferTruncated) return null;
                return new byte[0];
            }
            IntPtr buf = Marshal.AllocHGlobal((int)cbActual);
            try
            {
                uint got;
                int e2 = NativeMethods.JetRetrieveColumn(_sesid, tableid, columnid, buf, cbActual, out got, 0, IntPtr.Zero);
                if (e2 < 0 && e2 != JET_wrnBufferTruncated) return null;
                int n = (int)Math.Min(got, cbActual);
                byte[] data = new byte[n];
                Marshal.Copy(buf, data, 0, n);
                return data;
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
        }

        private string RetrieveString(IntPtr tableid, uint columnid)
        {
            byte[] raw = RetrieveRaw(tableid, columnid);
            if (raw == null || raw.Length == 0) return "";
            // Object-name columns in the catalog temp table are Unicode text.
            return Encoding.Unicode.GetString(raw).TrimEnd('\0');
        }

        public void Dispose()
        {
            try { if (_attached) NativeMethods.JetDetachDatabaseW(_sesid, _dbPath); } catch { }
            try { if (_sesid != IntPtr.Zero) NativeMethods.JetEndSession(_sesid, 0); } catch { }
            try { if (_inited) NativeMethods.JetTerm(_instance); } catch { }
            try { if (System.IO.Directory.Exists(_tempPath)) System.IO.Directory.Delete(_tempPath, true); } catch { }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JET_COLUMNDEF
        {
            public uint cbStruct;
            public uint columnid;
            public uint coltyp;
            public ushort wCountry;
            public ushort langid;
            public ushort cp;
            public ushort wCollate;
            public uint cbMax;
            public uint grbit;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JET_OBJECTLIST
        {
            public uint cbStruct;
            public IntPtr tableid;
            public uint cRecord;
            public uint columnidcontainername;
            public uint columnidobjectname;
            public uint columnidobjtyp;
            public uint columnidDtCreate;
            public uint columnidDtUpdate;
            public uint columnidGrbit;
            public uint columnidFlags;
            public uint columnidcRecord;
            public uint columnidcPage;
        }

        private static class NativeMethods
        {
            private const string Esent = "esent.dll";

            [DllImport(Esent, CharSet = CharSet.Unicode, ExactSpelling = true)]
            public static extern int JetGetDatabaseFileInfoW(string szDatabaseName, out int pvResult, int cbMax, uint InfoLevel);

            [DllImport(Esent, CharSet = CharSet.Unicode, ExactSpelling = true)]
            public static extern int JetCreateInstanceW(out IntPtr instance, string szInstanceName);

            [DllImport(Esent, CharSet = CharSet.Unicode, ExactSpelling = true)]
            public static extern int JetSetSystemParameterW(ref IntPtr instance, IntPtr sesid, uint paramid, IntPtr lParam, string szParam);

            [DllImport(Esent, ExactSpelling = true)]
            public static extern int JetInit(ref IntPtr instance);

            [DllImport(Esent, CharSet = CharSet.Unicode, ExactSpelling = true)]
            public static extern int JetBeginSessionW(IntPtr instance, out IntPtr sesid, string szUserName, string szPassword);

            [DllImport(Esent, CharSet = CharSet.Unicode, ExactSpelling = true)]
            public static extern int JetAttachDatabaseW(IntPtr sesid, string szFilename, uint grbit);

            [DllImport(Esent, CharSet = CharSet.Unicode, ExactSpelling = true)]
            public static extern int JetOpenDatabaseW(IntPtr sesid, string szFilename, string szConnect, out uint dbid, uint grbit);

            [DllImport(Esent, CharSet = CharSet.Unicode, ExactSpelling = true)]
            public static extern int JetOpenTableW(IntPtr sesid, uint dbid, string szTableName, IntPtr pvParameters, uint cbParameters, uint grbit, out IntPtr tableid);

            [DllImport(Esent, CharSet = CharSet.Unicode, ExactSpelling = true)]
            public static extern int JetGetTableColumnInfoW(IntPtr sesid, IntPtr tableid, string szColumnName, ref JET_COLUMNDEF pvResult, uint cbMax, uint InfoLevel);

            [DllImport(Esent, CharSet = CharSet.Unicode, ExactSpelling = true)]
            public static extern int JetGetObjectInfoW(IntPtr sesid, uint dbid, uint objtyp, string szContainerName, string szObjectName, ref JET_OBJECTLIST pvResult, uint cbMax, uint InfoLevel);

            [DllImport(Esent, ExactSpelling = true)]
            public static extern int JetMove(IntPtr sesid, IntPtr tableid, int cRow, uint grbit);

            [DllImport(Esent, ExactSpelling = true)]
            public static extern int JetRetrieveColumn(IntPtr sesid, IntPtr tableid, uint columnid, IntPtr pvData, uint cbData, out uint cbActual, uint grbit, IntPtr pretinfo);

            [DllImport(Esent, ExactSpelling = true)]
            public static extern int JetCloseTable(IntPtr sesid, IntPtr tableid);

            [DllImport(Esent, CharSet = CharSet.Unicode, ExactSpelling = true)]
            public static extern int JetDetachDatabaseW(IntPtr sesid, string szFilename);

            [DllImport(Esent, ExactSpelling = true)]
            public static extern int JetEndSession(IntPtr sesid, uint grbit);

            [DllImport(Esent, ExactSpelling = true)]
            public static extern int JetTerm(IntPtr instance);
        }
    }
}
