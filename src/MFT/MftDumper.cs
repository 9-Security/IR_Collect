using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using IR_Collect;
using IR_Collect.Utils;
// using System.ComponentModel;

namespace IR_Collect.MFT
{
    public class MftDumper
    {
        public static string DumpMft(string driveLetter, string outputDir)
        {
            driveLetter = NormalizeDriveLetter(driveLetter);
            // Avoid setting console encoding when run from GUI (no console → invalid handle → exception)
            try { Console.OutputEncoding = System.Text.Encoding.UTF8; } catch { }
            string outFile = Path.Combine(outputDir, ArtifactNames.MftDumpBin);
            
            // Strategy 1: Direct File Access (simplest but often blocked)
            try 
            {
                string privStatus;
                NativeMethods.EnableBackupPrivilege(out privStatus);
                Console.WriteLine("    Privilege: " + privStatus);
                DumpByPath(driveLetter, outFile);
                return outFile;
            }
            catch (Exception ex)
            {
                Console.WriteLine("    ! Strategy 1 failed: " + FormatException(ex));
            }

            // Strategy 2: Raw Volume Access (Parsing Boot Sector)
            try
            {
                 Console.WriteLine("    Attempting Strategy 2: Raw Volume Parsing...");
                 string privStatus;
                 NativeMethods.EnableBackupPrivilege(out privStatus);
                 Console.WriteLine("    Privilege: " + privStatus);
                 DumpByRawVolume(driveLetter, outFile);
                 return outFile;
            }
            catch (Exception ex)
            {
                 throw new Exception("All MFT dump strategies failed. " + FormatException(ex));
            }
        }

        private static string FormatException(Exception ex)
        {
            return ex.Message;
        }

        /// <summary>Validates drive letter is single A-Z to prevent path traversal. Returns one uppercase letter.</summary>
        public static string NormalizeDriveLetter(string driveLetter)
        {
            if (string.IsNullOrWhiteSpace(driveLetter)) throw new ArgumentException("Drive letter is required.", "driveLetter");
            char c = driveLetter.Trim().ToUpperInvariant()[0];
            if (c < 'A' || c > 'Z') throw new ArgumentException("Drive letter must be A-Z.", "driveLetter");
            return c.ToString();
        }

        private static void DumpByPath(string driveLetter, string outFile)
        {
            // format: \\.\C:\$MFT (driveLetter already normalized to single A-Z)
            string mftPath = string.Format(@"\\.\{0}:\$MFT", driveLetter);
            
            using (var handle = NativeMethods.CreateFile(
                mftPath,
                NativeMethods.GENERIC_READ,
                NativeMethods.FILE_SHARE_READ | NativeMethods.FILE_SHARE_WRITE | NativeMethods.FILE_SHARE_DELETE,
                IntPtr.Zero,
                NativeMethods.OPEN_EXISTING,
                NativeMethods.FILE_ATTRIBUTE_NORMAL | NativeMethods.FILE_FLAG_BACKUP_SEMANTICS | NativeMethods.FILE_FLAG_SEQUENTIAL_SCAN, 
                IntPtr.Zero))
            {
                if (handle.IsInvalid) throw new Exception("Error code: " + Marshal.GetLastWin32Error());

                using (FileStream fs = new FileStream(handle, FileAccess.Read))
                using (FileStream outFs = new FileStream(outFile, FileMode.Create, FileAccess.Write))
                {
                    byte[] buffer = new byte[65536];
                    int bytesRead;
                    while ((bytesRead = fs.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        outFs.Write(buffer, 0, bytesRead);
                    }
                }
            }
        }

        private static void DumpByRawVolume(string driveLetter, string outFile)
        {
            // 1. Open Volume
             using (var rawDisk = new RawDiskReader(driveLetter))
             {
                 // 2. Read Boot Sector (0-512)
                 byte[] bootSector = new byte[512];
                 if (rawDisk.Read(bootSector, 0, 512) != 512) throw new Exception("Failed to read Boot Sector");

                 // 3. Parse NTFS Geometry
                 // 0x0B (11): Bytes Per Sector (2 bytes)
                 ushort bytesPerSector = BitConverter.ToUInt16(bootSector, 11);
                 // 0x0D (13): Sectors Per Cluster (1 byte)
                 byte sectorsPerCluster = bootSector[13];
                 // 0x30 (48): MFT LCN (8 bytes)
                 long mftLcn = BitConverter.ToInt64(bootSector, 48);

                 long clusterSize = bytesPerSector * sectorsPerCluster;
                 long mftOffset = mftLcn * clusterSize;

                 Console.WriteLine(string.Format("    Metadata: BPS={0}, SPC={1}, MFT LCN={2}, Offset={3}", 
                     bytesPerSector, sectorsPerCluster, mftLcn, mftOffset));

                 // 4. Read MFT record 0 to get $MFT $DATA run list
                 byte[] record0 = new byte[1024];
                 rawDisk.Seek(mftOffset);
                 int recRead = rawDisk.Read(record0, 0, record0.Length);
                 if (recRead < record0.Length)
                 {
                     throw new Exception("Failed to read MFT record 0 for run list.");
                 }

                 long realSize;
                 var runs = TryGetMftDataRuns(record0, out realSize);
                 if (runs == null || runs.Count == 0)
                 {
                     Console.WriteLine("    ! Run list not found, falling back to fixed chunk read.");
                     rawDisk.Seek(mftOffset);
                     using (FileStream outFs = new FileStream(outFile, FileMode.Create, FileAccess.Write))
                     {
                         long limit = 256 * 1024 * 1024; 
                         byte[] buffer = new byte[65536];
                         long total = 0;
                         
                         while (total < limit)
                         {
                             int read = rawDisk.Read(buffer, 0, buffer.Length);
                             if (read == 0) break;
                             outFs.Write(buffer, 0, read);
                             total += read;
                         }
                     }
                     Console.WriteLine("    Dumped first 256MB of MFT (Raw access).");
                     return;
                 }

                 Console.WriteLine("    Run list found. Dumping full MFT via data runs...");
                 using (FileStream outFs = new FileStream(outFile, FileMode.Create, FileAccess.Write))
                 {
                     byte[] buffer = new byte[65536];
                     long remaining = realSize > 0 ? realSize : long.MaxValue;

                     foreach (var run in runs)
                     {
                         long runBytes = run.LengthClusters * clusterSize;
                         if (runBytes <= 0) continue;
                         if (remaining <= 0) break;
                         if (runBytes > remaining) runBytes = remaining;

                         long runOffset = run.StartLcn * clusterSize;
                         rawDisk.Seek(runOffset);

                         long written = 0;
                         while (written < runBytes)
                         {
                             int toRead = (int)Math.Min(buffer.Length, runBytes - written);
                             int read = rawDisk.Read(buffer, 0, toRead);
                             if (read == 0) break;
                             outFs.Write(buffer, 0, read);
                             written += read;
                             remaining -= read;
                             if (remaining <= 0) break;
                         }
                     }
                 }
                 Console.WriteLine("    Dumped MFT using run list (Raw access).");
             }
        }

        internal class DataRun
        {
            public long StartLcn { get; set; }
            public long LengthClusters { get; set; }
        }

        private static List<DataRun> TryGetMftDataRuns(byte[] record, out long realSize)
        {
            realSize = 0;
            try
            {
                // Signature "FILE"
                if (record[0] != 0x46 || record[1] != 0x49 || record[2] != 0x4C || record[3] != 0x45)
                    return null;

                ushort firstAttrOffset = BitConverter.ToUInt16(record, 0x14);
                int offset = firstAttrOffset;

                while (offset < record.Length - 8)
                {
                    uint attrType = BitConverter.ToUInt32(record, offset);
                    if (attrType == 0xFFFFFFFF) break;

                    uint attrLen = BitConverter.ToUInt32(record, offset + 4);
                    if (attrLen == 0) break;

                    byte nonResident = record[offset + 8];

                    if (attrType == 0x80 && nonResident == 1)
                    {
                        ushort dataRunOffset = BitConverter.ToUInt16(record, offset + 0x20);
                        long fileSize = BitConverter.ToInt64(record, offset + 0x30);
                        realSize = fileSize;

                        int runStart = offset + dataRunOffset;
                        return ParseRunList(record, runStart, offset + (int)attrLen);
                    }

                    offset += (int)attrLen;
                }
            }
            catch (Exception ex) { Logger.Warning("MftDumper GetDataRunList: " + ex.Message); }
            return null;
        }

        internal static List<DataRun> ParseRunList(byte[] buffer, int start, int end)
        {
            var runs = new List<DataRun>();
            long currentLcn = 0;
            if (buffer == null || start < 0) return runs;
            int pos = start;
            // `end` is derived from an attacker-influenced attribute length; clamp it so a malformed
            // record cannot drive reads past the buffer.
            if (end > buffer.Length) end = buffer.Length;

            while (pos < end)
            {
                byte header = buffer[pos++];
                if (header == 0x00) break;

                int lenSize = header & 0x0F;
                int offSize = (header >> 4) & 0x0F;

                // Bounds-check the variable-length fields before reading. A truncated/malformed run
                // list must not throw IndexOutOfRange — the caller swallows that and silently falls
                // back to a fixed-size read, producing a TRUNCATED $MFT with no error surfaced.
                if (lenSize == 0) break;                  // length run must be >= 1 byte (0 only valid as terminator)
                if (pos + lenSize + offSize > end) break; // not enough bytes for this run

                long length = ReadUnsigned(buffer, pos, lenSize);
                pos += lenSize;
                long offset = ReadSigned(buffer, pos, offSize);
                pos += offSize;

                currentLcn += offset;
                if (length <= 0) break;                   // nonsensical run length => stop
                runs.Add(new DataRun { StartLcn = currentLcn, LengthClusters = length });
            }

            return runs;
        }

        private static long ReadUnsigned(byte[] buffer, int start, int size)
        {
            long val = 0;
            for (int i = 0; i < size; i++)
            {
                val |= ((long)buffer[start + i]) << (8 * i);
            }
            return val;
        }

        private static long ReadSigned(byte[] buffer, int start, int size)
        {
            long val = 0;
            for (int i = 0; i < size; i++)
            {
                val |= ((long)buffer[start + i]) << (8 * i);
            }
            // sign extend if highest bit of last byte is set
            if (size > 0 && (buffer[start + size - 1] & 0x80) != 0)
            {
                long mask = -1L << (size * 8);
                val |= mask;
            }
            return val;
        }
    }
}
