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

            internal ulong BaseRecordNumber { get; set; }
            internal ushort RecordSequenceNumber { get; set; }
            internal ushort BaseRecordSequenceNumber { get; set; }
            internal int FileNameNamespaceRank { get; set; }
            internal List<ulong> FileNameExtensionRecordReferences { get; private set; }

            public MftEntry()
            {
                FileNameNamespaceRank = -1;
                FileNameExtensionRecordReferences = new List<ulong>();
            }
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

                MergeFileNameExtensionRecords(fs, result, recordSize);
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
            if (data == null || data.Length < 0x30) return null;
            // Simple Parser logic
            // Offset 0x16: Flags (0x01 = InUse, 0x02 = Directory)
            ushort flags = BitConverter.ToUInt16(data, 0x16);
            bool inUse = (flags & 0x01) != 0;
            bool isDir = (flags & 0x02) != 0;

            // To find FileName, we need to walk attributes.
            // First Attribute Offset: 0x14
            ushort firstAttrOffset = BitConverter.ToUInt16(data, 0x14);
            ushort recordSequenceNumber = BitConverter.ToUInt16(data, 0x10);
            ulong baseRecordReference = BitConverter.ToUInt64(data, 0x20);
            ulong baseRecordNumber = baseRecordReference & 0x0000FFFFFFFFFFFF;
            ushort baseRecordSequenceNumber = (ushort)(baseRecordReference >> 48);
            
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
            var fileNameExtensionReferences = new List<ulong>();

            int offset = firstAttrOffset;
            while (offset < data.Length - 8)
            {
                uint attrType = BitConverter.ToUInt32(data, offset);
                if (attrType == 0xFFFFFFFF) break; // End marker

                uint attrLen = BitConverter.ToUInt32(data, offset + 4);
                if (attrLen < 8 || offset + attrLen > data.Length) break; // prevent loop / overflow

                byte nonResident = data[offset + 8];
                if (attrType == 0x20 && nonResident == 0) // resident $ATTRIBUTE_LIST
                {
                    foreach (ulong recordReference in ParseAttributeListFileNameReferences(data, offset, attrLen))
                    {
                        ulong recordNumber = recordReference & 0x0000FFFFFFFFFFFF;
                        if (recordNumber != index && !fileNameExtensionReferences.Contains(recordReference))
                            fileNameExtensionReferences.Add(recordReference);
                        if (fileNameExtensionReferences.Count >= 64) break;
                    }
                }
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
                        // Keep the metadata paired with the selected name. Hard links can have different
                        // parents, so taking timestamps/parent from a lower-ranked DOS name would produce
                        // an internally inconsistent path.
                        int rank = NamespaceRank(ns);
                        if (rank > bestNameRank)
                        {
                            filename = Encoding.Unicode.GetString(data, attrContentStart + 66, nameLen * 2);
                            parentRef = BitConverter.ToUInt64(data, attrContentStart);
                            fnCreated = ConvertFileTime(BitConverter.ToInt64(data, attrContentStart + 0x08));
                            fnModified = ConvertFileTime(BitConverter.ToInt64(data, attrContentStart + 0x10));
                            fnMftModified = ConvertFileTime(BitConverter.ToInt64(data, attrContentStart + 0x18));
                            fnAccessed = ConvertFileTime(BitConverter.ToInt64(data, attrContentStart + 0x20));
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

            var entry = new MftEntry
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
                Modified = modified,
                BaseRecordNumber = baseRecordNumber,
                RecordSequenceNumber = recordSequenceNumber,
                BaseRecordSequenceNumber = baseRecordSequenceNumber,
                FileNameNamespaceRank = bestNameRank
            };
            entry.FileNameExtensionRecordReferences.AddRange(fileNameExtensionReferences);
            return entry;
        }

        internal static List<ulong> ParseAttributeListFileNameReferences(byte[] data, int attributeOffset, uint attributeLength)
        {
            var references = new List<ulong>();
            if (data == null || attributeOffset < 0 || attributeLength < 0x18 ||
                (long)attributeOffset + attributeLength > data.Length || attributeOffset + 0x16 > data.Length)
                return references;

            uint contentLength = BitConverter.ToUInt32(data, attributeOffset + 0x10);
            ushort contentOffset = BitConverter.ToUInt16(data, attributeOffset + 0x14);
            long contentStartLong = (long)attributeOffset + contentOffset;
            long contentEndLong = contentStartLong + contentLength;
            long attributeEnd = (long)attributeOffset + attributeLength;
            if (contentStartLong < attributeOffset || contentStartLong > attributeEnd ||
                contentEndLong < contentStartLong || contentEndLong > attributeEnd || contentEndLong > data.Length)
                return references;

            int position = (int)contentStartLong;
            int contentEnd = (int)contentEndLong;
            while (position + 0x1A <= contentEnd && references.Count < 64)
            {
                uint listedType = BitConverter.ToUInt32(data, position);
                ushort entryLength = BitConverter.ToUInt16(data, position + 4);
                if (entryLength < 0x1A || position + entryLength > contentEnd) break;
                if (listedType == 0x30)
                {
                    ulong recordReference = BitConverter.ToUInt64(data, position + 0x10);
                    if (!references.Contains(recordReference)) references.Add(recordReference);
                }
                position += entryLength;
            }
            return references;
        }

        private static void MergeFileNameExtensionRecords(FileStream fs, ParseResult result, int recordSize)
        {
            if (fs == null || result == null || result.Entries == null || recordSize <= 0) return;
            long recordCount = fs.Length / recordSize;
            var parsedExtensions = new Dictionary<ulong, MftEntry>();
            byte[] buffer = new byte[recordSize];

            foreach (MftEntry baseEntry in result.Entries)
            {
                if (baseEntry == null || baseEntry.BaseRecordNumber != 0 ||
                    baseEntry.FileNameExtensionRecordReferences == null) continue;

                foreach (ulong recordReference in baseEntry.FileNameExtensionRecordReferences)
                {
                    ulong reference = recordReference & 0x0000FFFFFFFFFFFF;
                    ushort expectedSequence = (ushort)(recordReference >> 48);
                    if (reference >= (ulong)recordCount) continue;
                    MftEntry extension;
                    if (!parsedExtensions.TryGetValue(reference, out extension))
                    {
                        try
                        {
                            fs.Position = checked((long)reference * recordSize);
                            int total = 0;
                            while (total < recordSize)
                            {
                                int read = fs.Read(buffer, total, recordSize - total);
                                if (read <= 0) break;
                                total += read;
                            }
                            if (total != recordSize || buffer[0] != 0x46 || buffer[1] != 0x49 ||
                                buffer[2] != 0x4C || buffer[3] != 0x45)
                            {
                                parsedExtensions[reference] = null;
                                continue;
                            }
                            ApplyUsnFixup(buffer, recordSize);
                            extension = ParseRecord(buffer, (uint)reference);
                            parsedExtensions[reference] = extension;
                        }
                        catch (Exception ex)
                        {
                            result.SkippedRecords++;
                            parsedExtensions[reference] = null;
                            Logger.Warning("MftParser: skip $ATTRIBUTE_LIST extension record " +
                                reference + ": " + ex.Message);
                            continue;
                        }
                    }

                    if (extension == null ||
                        (expectedSequence != 0 && extension.RecordSequenceNumber != expectedSequence) ||
                        extension.BaseRecordNumber != baseEntry.RecordNumber ||
                        (extension.BaseRecordSequenceNumber != 0 && baseEntry.RecordSequenceNumber != 0 &&
                         extension.BaseRecordSequenceNumber != baseEntry.RecordSequenceNumber) ||
                        extension.FileNameNamespaceRank <= baseEntry.FileNameNamespaceRank ||
                        string.IsNullOrEmpty(extension.FileName))
                        continue;

                    baseEntry.FileName = extension.FileName;
                    baseEntry.ParentRecordNumber = extension.ParentRecordNumber;
                    baseEntry.FnCreated = extension.FnCreated;
                    baseEntry.FnModified = extension.FnModified;
                    baseEntry.FnMftModified = extension.FnMftModified;
                    baseEntry.FnAccessed = extension.FnAccessed;
                    baseEntry.FileNameNamespaceRank = extension.FileNameNamespaceRank;
                    if (baseEntry.StdCreated.Year <= 1980) baseEntry.Created = extension.FnCreated;
                    if (baseEntry.StdModified.Year <= 1980) baseEntry.Modified = extension.FnModified;
                }
            }
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
