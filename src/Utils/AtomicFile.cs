using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace IR_Collect.Utils
{
    internal static class AtomicFile
    {
        private const int MoveFileReplaceExisting = 0x1;
        private const int MoveFileWriteThrough = 0x8;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool MoveFileEx(string existingFileName, string newFileName, int flags);

        public static void WriteAllText(string destination, string contents, Encoding encoding)
        {
            WriteText(destination, encoding, delegate(StreamWriter writer)
            {
                writer.Write(contents ?? "");
                return true;
            });
        }

        public static void WriteText(string destination, Encoding encoding, Action<StreamWriter> write)
        {
            if (write == null) throw new ArgumentNullException("write");
            WriteText(destination, encoding, delegate(StreamWriter writer)
            {
                write(writer);
                return true;
            });
        }

        public static bool WriteText(
            string destination,
            Encoding encoding,
            Func<StreamWriter, bool> writeAndShouldPublish)
        {
            if (string.IsNullOrWhiteSpace(destination))
                throw new ArgumentException("destination is null or empty.", "destination");
            if (encoding == null) throw new ArgumentNullException("encoding");
            if (writeAndShouldPublish == null) throw new ArgumentNullException("writeAndShouldPublish");

            destination = Path.GetFullPath(destination);
            string temp = CreateTempPath(destination);
            bool publish = false;
            try
            {
                using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                using (var writer = new StreamWriter(stream, encoding))
                    publish = writeAndShouldPublish(writer);

                if (!publish) return false;
                Commit(temp, destination);
                temp = null;
                return true;
            }
            finally
            {
                TryDelete(temp);
            }
        }

        public static string CreateTempPath(string destination)
        {
            if (string.IsNullOrWhiteSpace(destination))
                throw new ArgumentException("destination is null or empty.", "destination");

            destination = Path.GetFullPath(destination);
            string directory = Path.GetDirectoryName(destination);
            if (string.IsNullOrEmpty(directory))
                throw new IOException("Atomic output destination must have a parent directory.");
            Directory.CreateDirectory(directory);
            return Path.Combine(
                directory,
                "." + Path.GetFileName(destination) + ".partial-" + Guid.NewGuid().ToString("N") + ".tmp");
        }

        public static void Commit(string temp, string destination)
        {
            if (string.IsNullOrWhiteSpace(temp) || !File.Exists(temp))
                throw new FileNotFoundException("Atomic output staging file was not found.", temp);
            if (string.IsNullOrWhiteSpace(destination))
                throw new ArgumentException("destination is null or empty.", "destination");

            temp = Path.GetFullPath(temp);
            destination = Path.GetFullPath(destination);
            string tempDirectory = Path.GetDirectoryName(temp);
            string destinationDirectory = Path.GetDirectoryName(destination);
            if (!string.Equals(tempDirectory, destinationDirectory, StringComparison.OrdinalIgnoreCase))
                throw new IOException("Atomic output staging file must be in the destination directory.");

            if (!File.Exists(destination))
            {
                File.Move(temp, destination);
                return;
            }

            if (!MoveFileEx(temp, destination, MoveFileReplaceExisting | MoveFileWriteThrough))
                throw new IOException(
                    "Atomic output publication failed.",
                    new Win32Exception(Marshal.GetLastWin32Error()));
        }

        public static void TryDelete(string path)
        {
            if (string.IsNullOrEmpty(path)) return;
            try
            {
                if (File.Exists(path)) File.Delete(path);
            }
            catch (Exception ex)
            {
                Logger.Warning("AtomicFile staging cleanup: " + (ex.Message ?? ""));
            }
        }
    }
}
