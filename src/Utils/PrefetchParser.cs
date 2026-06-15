using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace IR_Collect.Utils
{
    public sealed class PrefetchEntry
    {
        public string ExecutableName { get; set; }
        public int FormatVersion { get; set; }
        public int RunCount { get; set; }
        public string Hash { get; set; }
        public List<DateTime> LastRunTimesUtc { get; private set; }
        public string SourceFile { get; set; }
        public string ParserNote { get; set; }

        public PrefetchEntry() { LastRunTimesUtc = new List<DateTime>(); }
    }

    public sealed class PrefetchParseResult
    {
        public List<PrefetchEntry> Entries { get; private set; }
        public List<string> ParserNotes { get; private set; }
        public bool FallbackUsed { get; set; }

        public PrefetchParseResult()
        {
            Entries = new List<PrefetchEntry>();
            ParserNotes = new List<string>();
        }
    }

    /// <summary>
    /// Parses Windows Prefetch (.pf) execution-evidence files into entries (executable, run count, last
    /// run times). Win8+ .pf are MAM/Xpress-Huffman compressed; we decompress via ntdll RtlDecompressBufferEx
    /// then read the SCCA structure. Validated differentially against Eric Zimmerman's PECmd.
    /// </summary>
    public static class PrefetchParser
    {
        private const ushort COMPRESSION_FORMAT_XPRESS_HUFFMAN = 0x0004;

        [DllImport("ntdll.dll")]
        private static extern uint RtlGetCompressionWorkSpaceSize(ushort CompressionFormatAndEngine, out uint CompressBufferWorkSpaceSize, out uint CompressFragmentWorkSpaceSize);

        [DllImport("ntdll.dll")]
        private static extern uint RtlDecompressBufferEx(ushort CompressionFormat, byte[] UncompressedBuffer, uint UncompressedBufferSize, byte[] CompressedBuffer, uint CompressedBufferSize, out uint FinalUncompressedSize, IntPtr WorkSpace);

        public static PrefetchParseResult ParseDirectory(string prefetchDir)
        {
            var result = new PrefetchParseResult();
            if (string.IsNullOrEmpty(prefetchDir) || !Directory.Exists(prefetchDir))
            {
                result.FallbackUsed = true;
                result.ParserNotes.Add("Prefetch directory not found.");
                return result;
            }
            string[] files;
            try { files = Directory.GetFiles(prefetchDir, "*.pf"); }
            catch (Exception ex) { result.FallbackUsed = true; result.ParserNotes.Add("Prefetch enumerate failed: " + ex.Message); return result; }

            foreach (string f in files)
            {
                PrefetchEntry e = null;
                try { e = ParseFile(f); }
                catch (Exception ex) { result.ParserNotes.Add(Path.GetFileName(f) + ": " + ex.Message); }
                if (e != null) result.Entries.Add(e);
                else result.FallbackUsed = true;
            }
            if (result.Entries.Count == 0) result.FallbackUsed = true;
            return result;
        }

        public static PrefetchEntry ParseFile(string path)
        {
            byte[] raw = File.ReadAllBytes(path);
            byte[] data = raw;

            // Win8+ compressed container: "MAM\x04" + uint32 uncompressedSize + Xpress-Huffman data.
            if (raw.Length >= 8 && raw[0] == 0x4D && raw[1] == 0x41 && raw[2] == 0x4D && raw[3] == 0x04)
            {
                byte[] dec = DecompressMam(raw);
                if (dec == null) return null;
                data = dec;
            }

            // SCCA header: version @0x00, "SCCA" @0x04, exe name @0x10 (UTF-16), hash @0x4C.
            if (data.Length < 0x54) return null;
            int version = BitConverter.ToInt32(data, 0);
            if (!(data[4] == 0x53 && data[5] == 0x43 && data[6] == 0x43 && data[7] == 0x41)) return null; // "SCCA"

            var entry = new PrefetchEntry();
            entry.SourceFile = Path.GetFileName(path);
            entry.FormatVersion = version;
            entry.ExecutableName = ReadUtf16Z(data, 0x10, 60);
            entry.Hash = (data.Length >= 0x50) ? BitConverter.ToUInt32(data, 0x4C).ToString("X8") : "";

            // File Information section: last run times and run count offsets are version-specific.
            int runCountOffset;
            int lastRunOffset = 0x80;
            int lastRunCount;
            switch (version)
            {
                case 17: // WinXP
                    lastRunOffset = 0x78; lastRunCount = 1; runCountOffset = 0x90; break;
                case 23: // Vista/Win7
                    lastRunOffset = 0x80; lastRunCount = 1; runCountOffset = 0x98; break;
                case 26: // Win8.1
                    lastRunOffset = 0x80; lastRunCount = 8; runCountOffset = 0xD0; break;
                default: // 30 (Win10), 31 (Win11): run count at 0xC8 (validated vs PECmd on real v31)
                    lastRunOffset = 0x80; lastRunCount = 8; runCountOffset = 0xC8; break;
            }

            for (int i = 0; i < lastRunCount; i++)
            {
                int off = lastRunOffset + i * 8;
                if (off + 8 > data.Length) break;
                long ft = BitConverter.ToInt64(data, off);
                DateTime t = FileTimeToUtc(ft);
                if (t != DateTime.MinValue) entry.LastRunTimesUtc.Add(t);
            }

            if (runCountOffset + 4 <= data.Length)
            {
                int rc = BitConverter.ToInt32(data, runCountOffset);
                if (rc >= 0 && rc < 100000000) entry.RunCount = rc;
            }

            entry.ParserNote = "Prefetch v" + version + " (" + (data == raw ? "uncompressed" : "MAM/Xpress-Huffman") + ").";
            return entry;
        }

        private static byte[] DecompressMam(byte[] data)
        {
            try
            {
                uint uncompressedSize = BitConverter.ToUInt32(data, 4);
                if (uncompressedSize == 0 || uncompressedSize > 64 * 1024 * 1024) return null;
                int compLen = data.Length - 8;
                byte[] compressed = new byte[compLen];
                Array.Copy(data, 8, compressed, 0, compLen);

                uint wsCompress, wsFragment;
                if (RtlGetCompressionWorkSpaceSize(COMPRESSION_FORMAT_XPRESS_HUFFMAN, out wsCompress, out wsFragment) != 0)
                    return null;

                byte[] output = new byte[uncompressedSize];
                IntPtr ws = Marshal.AllocHGlobal((int)wsCompress);
                try
                {
                    uint finalSize;
                    uint r = RtlDecompressBufferEx(COMPRESSION_FORMAT_XPRESS_HUFFMAN, output, uncompressedSize, compressed, (uint)compLen, out finalSize, ws);
                    if (r != 0) return null;
                    if (finalSize < (uint)output.Length)
                    {
                        byte[] trimmed = new byte[finalSize];
                        Array.Copy(output, trimmed, (int)finalSize);
                        return trimmed;
                    }
                    return output;
                }
                finally { Marshal.FreeHGlobal(ws); }
            }
            catch { return null; }
        }

        private static string ReadUtf16Z(byte[] data, int offset, int maxBytes)
        {
            int end = Math.Min(offset + maxBytes, data.Length - 1);
            var sb = new StringBuilder();
            for (int i = offset; i + 1 < end + 1; i += 2)
            {
                char c = (char)(data[i] | (data[i + 1] << 8));
                if (c == '\0') break;
                sb.Append(c);
            }
            return sb.ToString();
        }

        private static DateTime FileTimeToUtc(long fileTime)
        {
            if (fileTime <= 0) return DateTime.MinValue;
            try
            {
                DateTime dt = DateTime.FromFileTimeUtc(fileTime);
                if (dt.Year < 1990 || dt.Year > 2200) return DateTime.MinValue;
                return dt;
            }
            catch { return DateTime.MinValue; }
        }
    }
}
