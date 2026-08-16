using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace IR_Collect.Collectors
{
    internal sealed class OleCompoundStream
    {
        public string Name { get; set; }
        public byte[] Data { get; set; }
    }

    internal sealed class OleCompoundFileResult
    {
        public OleCompoundFileResult()
        {
            Streams = new List<OleCompoundStream>();
            Warnings = new List<string>();
        }

        public bool IsCompoundFile { get; set; }
        public bool IsComplete { get; set; }
        public List<OleCompoundStream> Streams { get; private set; }
        public List<string> Warnings { get; private set; }
    }

    /// <summary>
    /// Bounded, read-only OLE Compound File reader for Jump List stream recovery. It intentionally
    /// exposes only stream names and bytes; higher-level DestList semantics remain out of scope.
    /// </summary>
    internal static class OleCompoundFileReader
    {
        private static readonly byte[] Signature =
        {
            0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1
        };

        public static OleCompoundFileResult Read(byte[] data)
        {
            var result = new OleCompoundFileResult();
            if (!HasSignature(data))
                return result;

            result.IsCompoundFile = true;
            try
            {
                new Reader(data, result).Parse();
            }
            catch (InvalidDataException ex)
            {
                AddWarning(result, ex.Message);
            }
            catch (Exception ex)
            {
                AddWarning(result, "CFB parser stopped safely: " + ex.GetType().Name + ".");
            }
            result.IsComplete = result.Warnings.Count == 0;
            return result;
        }

        private static bool HasSignature(byte[] data)
        {
            if (data == null || data.Length < Signature.Length)
                return false;
            for (int i = 0; i < Signature.Length; i++)
                if (data[i] != Signature[i])
                    return false;
            return true;
        }

        private static void AddWarning(OleCompoundFileResult result, string warning)
        {
            const int MaxWarnings = 16;
            if (result == null || result.Warnings.Count >= MaxWarnings)
                return;
            result.Warnings.Add(string.IsNullOrWhiteSpace(warning) ? "CFB parser reported incomplete input." : warning);
        }

        private sealed class Reader
        {
            private const uint FreeSector = 0xFFFFFFFFu;
            private const uint EndOfChain = 0xFFFFFFFEu;
            private const uint FatSector = 0xFFFFFFFDu;
            private const uint DifatSector = 0xFFFFFFFCu;
            private const int MaxDirectoryEntries = 4096;
            private const int MaxDirectoryBytes = MaxDirectoryEntries * 128;
            private const int MaxSingleStreamBytes = 8 * 1024 * 1024;
            private const int MaxAggregateStreamBytes = 16 * 1024 * 1024;

            private readonly byte[] data;
            private readonly OleCompoundFileResult result;
            private readonly List<uint> fat = new List<uint>();
            private int sectorSize;
            private int miniSectorSize;
            private int totalSectors;
            private uint miniStreamCutoff;

            public Reader(byte[] data, OleCompoundFileResult result)
            {
                this.data = data;
                this.result = result;
            }

            public void Parse()
            {
                if (data.Length < 512)
                    throw new InvalidDataException("CFB header is truncated.");

                ushort majorVersion = ReadUInt16(0x1A);
                ushort byteOrder = ReadUInt16(0x1C);
                ushort sectorShift = ReadUInt16(0x1E);
                ushort miniSectorShift = ReadUInt16(0x20);
                if (byteOrder != 0xFFFE)
                    throw new InvalidDataException("CFB byte order is unsupported.");
                if ((majorVersion != 3 && majorVersion != 4) ||
                    (majorVersion == 3 && sectorShift != 9) ||
                    (majorVersion == 4 && sectorShift != 12))
                    throw new InvalidDataException("CFB sector size or major version is invalid.");
                if (miniSectorShift != 6)
                    throw new InvalidDataException("CFB mini-sector size is unsupported.");

                sectorSize = 1 << sectorShift;
                miniSectorSize = 1 << miniSectorShift;
                if (data.Length < sectorSize)
                    throw new InvalidDataException("CFB header sector is truncated.");
                totalSectors = (data.Length - sectorSize) / sectorSize;
                if (totalSectors <= 0)
                    throw new InvalidDataException("CFB contains no sectors.");
                if ((data.Length - sectorSize) % sectorSize != 0)
                    Warn("CFB has a truncated trailing sector.");

                uint numberOfDirectorySectors = ReadUInt32(0x28);
                uint numberOfFatSectors = ReadUInt32(0x2C);
                uint firstDirectorySector = ReadUInt32(0x30);
                miniStreamCutoff = ReadUInt32(0x38);
                uint firstMiniFatSector = ReadUInt32(0x3C);
                uint numberOfMiniFatSectors = ReadUInt32(0x40);
                uint firstDifatSector = ReadUInt32(0x44);
                uint numberOfDifatSectors = ReadUInt32(0x48);

                if (numberOfFatSectors == 0 || numberOfFatSectors > (uint)totalSectors)
                    throw new InvalidDataException("CFB FAT sector count is invalid.");
                if (miniStreamCutoff > MaxAggregateStreamBytes)
                    throw new InvalidDataException("CFB mini-stream cutoff is unreasonable.");

                LoadFat(numberOfFatSectors, firstDifatSector, numberOfDifatSectors);

                long expectedDirectoryBytes = -1;
                if (majorVersion == 4 && numberOfDirectorySectors > 0)
                {
                    if (numberOfDirectorySectors > MaxDirectoryBytes / sectorSize)
                        Warn("CFB directory exceeds the supported entry limit and was truncated.");
                    expectedDirectoryBytes = Math.Min((long)numberOfDirectorySectors * sectorSize, MaxDirectoryBytes);
                }
                byte[] directoryBytes = ReadFatChain(firstDirectorySector, expectedDirectoryBytes,
                    MaxDirectoryBytes, "directory");
                if (directoryBytes.Length < 128)
                    throw new InvalidDataException("CFB directory stream is missing or truncated.");

                DirectoryEntry root;
                List<DirectoryEntry> streams;
                ParseDirectory(directoryBytes, majorVersion, out root, out streams);
                if (root == null)
                    throw new InvalidDataException("CFB root directory entry is missing.");

                List<uint> miniFat = LoadMiniFat(firstMiniFatSector, numberOfMiniFatSectors);
                byte[] rootMiniStream = new byte[0];
                if (root.StreamSize > 0)
                {
                    if (root.StreamSize > MaxAggregateStreamBytes)
                        Warn("CFB root mini stream exceeds the supported size limit.");
                    else
                        rootMiniStream = ReadFatChain(root.StartSector, (long)root.StreamSize,
                            MaxAggregateStreamBytes, "root mini stream");
                }

                int aggregateBytes = 0;
                for (int i = 0; i < streams.Count; i++)
                {
                    DirectoryEntry entry = streams[i];
                    if (entry.StreamSize > MaxSingleStreamBytes)
                    {
                        Warn("CFB stream '" + SafeName(entry.Name) + "' exceeds the supported size limit.");
                        continue;
                    }
                    if (aggregateBytes + (long)entry.StreamSize > MaxAggregateStreamBytes)
                    {
                        Warn("CFB aggregate stream output exceeds the supported size limit.");
                        break;
                    }

                    byte[] streamData;
                    if (entry.StreamSize == 0)
                        streamData = new byte[0];
                    else if (entry.StreamSize < miniStreamCutoff)
                        streamData = ReadMiniChain(entry.StartSector, (long)entry.StreamSize, miniFat,
                            rootMiniStream, "stream '" + SafeName(entry.Name) + "'");
                    else
                        streamData = ReadFatChain(entry.StartSector, (long)entry.StreamSize,
                            MaxSingleStreamBytes, "stream '" + SafeName(entry.Name) + "'");

                    aggregateBytes += streamData.Length;
                    result.Streams.Add(new OleCompoundStream { Name = entry.Name, Data = streamData });
                }
            }

            private void LoadFat(uint numberOfFatSectors, uint firstDifatSector, uint numberOfDifatSectors)
            {
                var fatSectorIds = new List<uint>();
                var seenFatSectors = new HashSet<uint>();
                for (int i = 0; i < 109 && fatSectorIds.Count < numberOfFatSectors; i++)
                    AddFatSectorId(ReadUInt32(0x4C + (i * 4)), fatSectorIds, seenFatSectors);

                uint difatSid = firstDifatSector;
                var seenDifatSectors = new HashSet<uint>();
                int difatEntriesPerSector = (sectorSize / 4) - 1;
                uint difatRead = 0;
                while (fatSectorIds.Count < numberOfFatSectors && difatRead < numberOfDifatSectors)
                {
                    if (!IsNormalSector(difatSid) || !seenDifatSectors.Add(difatSid))
                    {
                        Warn("CFB DIFAT chain is invalid or cyclic.");
                        break;
                    }
                    int offset = SectorOffset(difatSid);
                    for (int i = 0; i < difatEntriesPerSector && fatSectorIds.Count < numberOfFatSectors; i++)
                        AddFatSectorId(ReadUInt32(offset + (i * 4)), fatSectorIds, seenFatSectors);
                    difatSid = ReadUInt32(offset + sectorSize - 4);
                    difatRead++;
                }

                if (fatSectorIds.Count != numberOfFatSectors)
                    Warn("CFB FAT sector list is incomplete.");
                if (fatSectorIds.Count == 0)
                    throw new InvalidDataException("CFB FAT sector list is empty.");

                for (int i = 0; i < fatSectorIds.Count; i++)
                {
                    int offset = SectorOffset(fatSectorIds[i]);
                    for (int p = 0; p < sectorSize; p += 4)
                        fat.Add(ReadUInt32(offset + p));
                }
                if (fat.Count < totalSectors)
                    Warn("CFB FAT does not address every physical sector.");
            }

            private void AddFatSectorId(uint sid, List<uint> ids, HashSet<uint> seen)
            {
                if (sid == FreeSector)
                    return;
                if (!IsNormalSector(sid))
                {
                    Warn("CFB DIFAT contains an invalid FAT sector identifier.");
                    return;
                }
                if (!seen.Add(sid))
                {
                    Warn("CFB DIFAT contains a duplicate FAT sector identifier.");
                    return;
                }
                ids.Add(sid);
            }

            private List<uint> LoadMiniFat(uint firstMiniFatSector, uint numberOfMiniFatSectors)
            {
                var miniFat = new List<uint>();
                if (numberOfMiniFatSectors == 0)
                    return miniFat;
                long expected = (long)numberOfMiniFatSectors * sectorSize;
                if (expected > MaxDirectoryBytes)
                {
                    Warn("CFB mini FAT exceeds the supported size limit.");
                    expected = MaxDirectoryBytes;
                }
                byte[] bytes = ReadFatChain(firstMiniFatSector, expected, MaxDirectoryBytes, "mini FAT");
                for (int i = 0; i + 4 <= bytes.Length; i += 4)
                    miniFat.Add(ReadUInt32(bytes, i));
                return miniFat;
            }

            private void ParseDirectory(byte[] bytes, ushort majorVersion, out DirectoryEntry root,
                out List<DirectoryEntry> streams)
            {
                root = null;
                streams = new List<DirectoryEntry>();
                int count = Math.Min(bytes.Length / 128, MaxDirectoryEntries);
                for (int i = 0; i < count; i++)
                {
                    int offset = i * 128;
                    byte objectType = bytes[offset + 66];
                    if (objectType != 2 && objectType != 5)
                        continue;
                    ushort nameLength = ReadUInt16(bytes, offset + 64);
                    if (nameLength < 2 || nameLength > 64 || (nameLength & 1) != 0)
                    {
                        Warn("CFB directory entry has an invalid name length.");
                        continue;
                    }
                    string name = Encoding.Unicode.GetString(bytes, offset, nameLength - 2).TrimEnd('\0');
                    ulong size = ReadUInt64(bytes, offset + 120);
                    if (majorVersion == 3)
                        size &= 0xFFFFFFFFuL;
                    var entry = new DirectoryEntry
                    {
                        Name = name,
                        StartSector = ReadUInt32(bytes, offset + 116),
                        StreamSize = size
                    };
                    if (objectType == 5)
                    {
                        if (root == null)
                            root = entry;
                    }
                    else if (streams.Count < MaxDirectoryEntries)
                        streams.Add(entry);
                }
            }

            private byte[] ReadFatChain(uint startSector, long expectedBytes, int maxBytes, string label)
            {
                if (expectedBytes == 0)
                    return new byte[0];
                var output = new MemoryStream();
                var seen = new HashSet<uint>();
                uint sid = startSector;
                int maxSectors = Math.Min(totalSectors + 1, (maxBytes + sectorSize - 1) / sectorSize + 1);

                while (output.Length < maxBytes && seen.Count < maxSectors)
                {
                    if (sid == EndOfChain)
                        break;
                    if (!IsNormalSector(sid) || sid >= fat.Count)
                    {
                        Warn("CFB " + label + " chain references an invalid sector.");
                        break;
                    }
                    if (!seen.Add(sid))
                    {
                        Warn("CFB " + label + " chain is cyclic.");
                        break;
                    }

                    int offset = SectorOffset(sid);
                    int take = sectorSize;
                    if (expectedBytes >= 0)
                        take = (int)Math.Min(take, expectedBytes - output.Length);
                    take = (int)Math.Min(take, maxBytes - output.Length);
                    if (take <= 0)
                        break;
                    output.Write(data, offset, take);
                    if (expectedBytes >= 0 && output.Length >= expectedBytes)
                        break;
                    sid = fat[(int)sid];
                }

                if (expectedBytes >= 0 && output.Length < expectedBytes)
                    Warn("CFB " + label + " chain ended before the declared stream size.");
                if (output.Length >= maxBytes && (expectedBytes < 0 || output.Length < expectedBytes))
                    Warn("CFB " + label + " chain reached the supported size limit.");
                return output.ToArray();
            }

            private byte[] ReadMiniChain(uint startSector, long expectedBytes, List<uint> miniFat,
                byte[] rootMiniStream, string label)
            {
                if (expectedBytes == 0)
                    return new byte[0];
                var output = new MemoryStream();
                var seen = new HashSet<uint>();
                uint sid = startSector;
                int maxMiniSectors = Math.Min((MaxSingleStreamBytes + miniSectorSize - 1) / miniSectorSize + 1,
                    (rootMiniStream.Length + miniSectorSize - 1) / miniSectorSize + 1);

                while (output.Length < expectedBytes && seen.Count < maxMiniSectors)
                {
                    if (sid == EndOfChain)
                        break;
                    if (sid >= miniFat.Count || !seen.Add(sid))
                    {
                        Warn("CFB " + label + " mini-sector chain is invalid or cyclic.");
                        break;
                    }
                    long offset64 = (long)sid * miniSectorSize;
                    if (offset64 < 0 || offset64 >= rootMiniStream.Length)
                    {
                        Warn("CFB " + label + " references a mini-sector outside the root stream.");
                        break;
                    }
                    int offset = (int)offset64;
                    int take = (int)Math.Min(miniSectorSize, expectedBytes - output.Length);
                    take = Math.Min(take, rootMiniStream.Length - offset);
                    if (take <= 0)
                        break;
                    output.Write(rootMiniStream, offset, take);
                    sid = miniFat[(int)sid];
                }

                if (output.Length < expectedBytes)
                    Warn("CFB " + label + " mini-sector chain ended before the declared stream size.");
                return output.ToArray();
            }

            private bool IsNormalSector(uint sid)
            {
                return sid < (uint)totalSectors && sid != FatSector && sid != DifatSector;
            }

            private int SectorOffset(uint sid)
            {
                if (!IsNormalSector(sid))
                    throw new InvalidDataException("CFB sector identifier is outside the file.");
                long offset = ((long)sid + 1L) * sectorSize;
                if (offset < 0 || offset + sectorSize > data.Length)
                    throw new InvalidDataException("CFB sector extends beyond the file.");
                return (int)offset;
            }

            private ushort ReadUInt16(int offset)
            {
                return ReadUInt16(data, offset);
            }

            private uint ReadUInt32(int offset)
            {
                return ReadUInt32(data, offset);
            }

            private static ushort ReadUInt16(byte[] source, int offset)
            {
                if (source == null || offset < 0 || offset + 2 > source.Length)
                    throw new InvalidDataException("CFB integer read exceeds input bounds.");
                return (ushort)(source[offset] | (source[offset + 1] << 8));
            }

            private static uint ReadUInt32(byte[] source, int offset)
            {
                if (source == null || offset < 0 || offset + 4 > source.Length)
                    throw new InvalidDataException("CFB integer read exceeds input bounds.");
                return (uint)(source[offset] |
                    (source[offset + 1] << 8) |
                    (source[offset + 2] << 16) |
                    (source[offset + 3] << 24));
            }

            private static ulong ReadUInt64(byte[] source, int offset)
            {
                uint low = ReadUInt32(source, offset);
                uint high = ReadUInt32(source, offset + 4);
                return low | ((ulong)high << 32);
            }

            private void Warn(string warning)
            {
                AddWarning(result, warning);
            }

            private static string SafeName(string value)
            {
                if (string.IsNullOrEmpty(value))
                    return "<unnamed>";
                return value.Length <= 64 ? value : value.Substring(0, 64);
            }

            private sealed class DirectoryEntry
            {
                public string Name { get; set; }
                public uint StartSector { get; set; }
                public ulong StreamSize { get; set; }
            }
        }
    }
}
