using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using IR_Collect.Utils;

namespace IR_Collect.MFT
{
    public class MftParser
    {
        public class ParseResult
        {
            public List<MftEntry> Entries { get; set; }
            public int SkippedRecords { get; set; }

            public ParseResult()
            {
                Entries = new List<MftEntry>();
            }
        }

        public class MftEntry
        {
            public uint RecordNumber { get; set; }
            public bool InUse { get; set; }
            public bool IsDirectory { get; set; }
            public string FileName { get; set; }
            public string FullPath { get; set; }
            public long Size { get; set; }
            public ulong ParentRecordNumber { get; set; }

            // Standard Information timestamps
            public DateTime StdCreated { get; set; }
            public DateTime StdModified { get; set; }
            public DateTime StdMftModified { get; set; }
            public DateTime StdAccessed { get; set; }

            // File Name timestamps
            public DateTime FnCreated { get; set; }
            public DateTime FnModified { get; set; }
            public DateTime FnMftModified { get; set; }
            public DateTime FnAccessed { get; set; }

            // Convenience timestamps (prefer Standard, fallback to FileName)
            public DateTime Created { get; set; }
            public DateTime Modified { get; set; }
        }

        public static List<MftEntry> Parse(string mftFilePath, int limit = 100)
        {
            return ParseWithDiagnostics(mftFilePath, limit).Entries;
        }

        public static ParseResult ParseWithDiagnostics(string mftFilePath, int limit = 100)
        {
            ParseResult result = new ParseResult();
            if (!File.Exists(mftFilePath)) return result;

            using (FileStream fs = new FileStream(mftFilePath, FileMode.Open, FileAccess.Read))
            using (BinaryReader br = new BinaryReader(fs))
            {
                // MFT Records are usually 1024 bytes
                byte[] recordBuffer = new byte[1024];
                int recordSize = 1024;
                uint recordIndex = 0;

                while (fs.Position < fs.Length && result.Entries.Count < limit)
                {
                    int read = br.Read(recordBuffer, 0, recordSize);
                    if (read < recordSize) break;

                    // Basic Signature Check "FILE"
                    if (recordBuffer[0] == 0x46 && recordBuffer[1] == 0x49 && recordBuffer[2] == 0x4C && recordBuffer[3] == 0x45)
                    {
                        // NTFS stores an Update Sequence Number in the last 2 bytes of every 512-byte
                        // sector and the real bytes in the Update Sequence Array; restore them before
                        // reading attributes, or any field crossing a sector boundary is corrupted.
                        ApplyUsnFixup(recordBuffer, recordSize);
                        try
                        {
                            MftEntry entry = ParseRecord(recordBuffer, recordIndex);
                            if (entry != null) result.Entries.Add(entry);
                        }
                        catch (Exception ex)
                        {
                            result.SkippedRecords++;
                            Logger.Warning("MftParser: skip record " + recordIndex + ": " + ex.Message);
                        }
                    }
                    recordIndex++;
                }
            }

            // Build full paths after parsing
            BuildFullPaths(result.Entries);
            return result;
        }

        /// <summary>
        /// Apply the NTFS fixup (Update Sequence Array) to a record buffer in place. The record header
        /// holds the USA offset at 0x04 and the USA entry count at 0x06 (1 signature word + one word per
        /// sector). The signature word must currently occupy the last 2 bytes of each sector; those are
        /// overwritten with the corresponding USA word, restoring the original on-disk bytes.
        /// Returns true if a fixup was applied. internal for self-tests.
        /// </summary>
        internal static bool ApplyUsnFixup(byte[] data, int recordSize)
        {
            if (data == null || recordSize < 512 || data.Length < recordSize) return false;
            ushort usaOffset = BitConverter.ToUInt16(data, 0x04);
            ushort usaCount = BitConverter.ToUInt16(data, 0x06);
            if (usaCount < 2) return false;                                   // need signature + >=1 sector
            int sectors = usaCount - 1;
            if (sectors * 512 > recordSize) return false;                    // USA bigger than the record
            if (usaOffset < 0x2A || usaOffset + usaCount * 2 > recordSize) return false;
            for (int i = 1; i <= sectors; i++)
            {
                int sectorEnd = i * 512 - 2;                                 // last 2 bytes of sector i
                if (sectorEnd + 1 >= recordSize) break;
                int usaEntry = usaOffset + i * 2;
                data[sectorEnd] = data[usaEntry];
                data[sectorEnd + 1] = data[usaEntry + 1];
            }
            return true;
        }

        // Rank of a $FILE_NAME namespace byte (offset 0x41 of the attribute content) so the human-facing
        // Win32 long name wins over a DOS 8.3 short name: Win32&DOS(3) > Win32(1) > POSIX(0) > DOS(2).
        internal static int NamespaceRank(byte ns)
        {
            switch (ns)
            {
                case 3: return 3;   // Win32 & DOS (single combined name)
                case 1: return 2;   // Win32 (long name)
                case 0: return 1;   // POSIX
                case 2: return 0;   // DOS (8.3 short name)
                default: return 0;
            }
        }

        internal static MftEntry ParseRecord(byte[] data, uint index)
        {
            // Simple Parser logic
            // Offset 0x16: Flags (0x01 = InUse, 0x02 = Directory)
            ushort flags = BitConverter.ToUInt16(data, 0x16);
            bool inUse = (flags & 0x01) != 0;
            bool isDir = (flags & 0x02) != 0;

            // To find FileName, we need to walk attributes.
            // First Attribute Offset: 0x14
            ushort firstAttrOffset = BitConverter.ToUInt16(data, 0x14);
            
            string filename = "";
            int bestNameRank = -1;   // best $FILE_NAME namespace seen so far (prefer Win32 over DOS 8.3)
            ulong parentRef = 0;
            long fileSize = 0;

            DateTime stdCreated = DateTime.MinValue;
            DateTime stdModified = DateTime.MinValue;
            DateTime stdMftModified = DateTime.MinValue;
            DateTime stdAccessed = DateTime.MinValue;

            DateTime fnCreated = DateTime.MinValue;
            DateTime fnModified = DateTime.MinValue;
            DateTime fnMftModified = DateTime.MinValue;
            DateTime fnAccessed = DateTime.MinValue;

            int offset = firstAttrOffset;
            while (offset < data.Length - 8)
            {
                uint attrType = BitConverter.ToUInt32(data, offset);
                if (attrType == 0xFFFFFFFF) break; // End marker

                uint attrLen = BitConverter.ToUInt32(data, offset + 4);
                if (attrLen < 8 || offset + attrLen > data.Length) break; // prevent loop / overflow

                byte nonResident = data[offset + 8];
                if (attrType == 0x10 && nonResident == 0 && offset + 0x16 <= data.Length) // $STANDARD_INFORMATION
                {
                    ushort contentOffset = BitConverter.ToUInt16(data, offset + 0x14);
                    int attrContentStart = offset + contentOffset;
                    if (attrContentStart + 0x20 <= data.Length)
                    {
                        stdCreated = ConvertFileTime(BitConverter.ToInt64(data, attrContentStart + 0x00));
                        stdModified = ConvertFileTime(BitConverter.ToInt64(data, attrContentStart + 0x08));
                        stdMftModified = ConvertFileTime(BitConverter.ToInt64(data, attrContentStart + 0x10));
                        stdAccessed = ConvertFileTime(BitConverter.ToInt64(data, attrContentStart + 0x18));
                    }
                }

                // 0x30 = $FILE_NAME
                if (attrType == 0x30 && nonResident == 0 && offset + 22 <= data.Length)
                {
                    ushort contentOffset = BitConverter.ToUInt16(data, offset + 20);
                    int attrContentStart = offset + contentOffset;
                    if (attrContentStart + 66 > data.Length) { offset += (int)attrLen; continue; }
                    byte nameLen = data[attrContentStart + 64];
                    byte ns = data[attrContentStart + 65];
                    if (attrContentStart + 66 + (nameLen * 2) <= data.Length)
                    {
                        // Parent ref and the FN timestamps are identical across a record's $FILE_NAME
                        // namespaces, so capture them from any one.
                        parentRef = BitConverter.ToUInt64(data, attrContentStart);
                        fnCreated = ConvertFileTime(BitConverter.ToInt64(data, attrContentStart + 0x08));
                        fnModified = ConvertFileTime(BitConverter.ToInt64(data, attrContentStart + 0x10));
                        fnMftModified = ConvertFileTime(BitConverter.ToInt64(data, attrContentStart + 0x18));
                        fnAccessed = ConvertFileTime(BitConverter.ToInt64(data, attrContentStart + 0x20));
                        // But keep the name from the highest-ranked namespace (Win32 long name beats the
                        // DOS 8.3 short name) rather than letting the last attribute win.
                        // KNOWN LIMITATION: this only ranks among $FILE_NAME attributes present in the BASE
                        // record. Files with several long hardlink names (e.g. WinSxS .cat/.manifest) keep
                        // the long Win32 names in $ATTRIBUTE_LIST extension records that this parser does
                        // not follow, so only the short DOS name remains here. Tracked for Phase 2.3.
                        int rank = NamespaceRank(ns);
                        if (rank > bestNameRank)
                        {
                            filename = Encoding.Unicode.GetString(data, attrContentStart + 66, nameLen * 2);
                            bestNameRank = rank;
                        }
                    }
                }

                // 0x80 = $DATA (file size)
                if (attrType == 0x80)
                {
                    if (nonResident == 0)
                    {
                        if (offset + 0x14 <= data.Length)
                        {
                            uint contentSize = BitConverter.ToUInt32(data, offset + 0x10);
                            if (contentSize > fileSize) fileSize = contentSize;
                        }
                    }
                    else
                    {
                        if (offset + 0x38 <= data.Length)
                        {
                            long realSize = BitConverter.ToInt64(data, offset + 0x30);
                            if (realSize > fileSize) fileSize = realSize;
                        }
                    }
                }

                offset += (int)attrLen;
            }

            DateTime created = stdCreated.Year > 1980 ? stdCreated : fnCreated;
            DateTime modified = stdModified.Year > 1980 ? stdModified : fnModified;

            return new MftEntry
            {
                RecordNumber = index,
                InUse = inUse,
                IsDirectory = isDir,
                FileName = filename,
                Size = fileSize,
                ParentRecordNumber = parentRef & 0x0000FFFFFFFFFFFF,
                StdCreated = stdCreated,
                StdModified = stdModified,
                StdMftModified = stdMftModified,
                StdAccessed = stdAccessed,
                FnCreated = fnCreated,
                FnModified = fnModified,
                FnMftModified = fnMftModified,
                FnAccessed = fnAccessed,
                Created = created,
                Modified = modified
            };
        }

        private static DateTime ConvertFileTime(long fileTime)
        {
            try { return DateTime.FromFileTimeUtc(fileTime); } catch { return DateTime.MinValue; }
        }

        private static void BuildFullPaths(List<MftEntry> entries)
        {
            var map = new Dictionary<ulong, MftEntry>();
            foreach (var e in entries)
            {
                map[e.RecordNumber] = e;
            }

            var cache = new Dictionary<ulong, string>();
            foreach (var e in entries)
            {
                e.FullPath = ResolveFullPath(e, map, cache, 0);
            }
        }

        private static string ResolveFullPath(MftEntry entry, Dictionary<ulong, MftEntry> map, Dictionary<ulong, string> cache, int depth)
        {
            if (entry == null) return "";
            if (cache.ContainsKey(entry.RecordNumber)) return cache[entry.RecordNumber];
            if (depth > 64) return entry.FileName ?? "";

            // Root directory is typically record 5
            if (entry.RecordNumber == 5 || entry.ParentRecordNumber == entry.RecordNumber)
            {
                cache[entry.RecordNumber] = "\\";
                return "\\";
            }

            string name = string.IsNullOrEmpty(entry.FileName) ? "" : entry.FileName;
            string parentPath = "\\";

            MftEntry parent;
            if (map.TryGetValue(entry.ParentRecordNumber, out parent))
            {
                parentPath = ResolveFullPath(parent, map, cache, depth + 1);
            }

            if (string.IsNullOrEmpty(parentPath)) parentPath = "\\";
            if (parentPath == "\\") cache[entry.RecordNumber] = parentPath + name;
            else cache[entry.RecordNumber] = parentPath.TrimEnd('\\') + "\\" + name;
            return cache[entry.RecordNumber];
        }
    }
}
