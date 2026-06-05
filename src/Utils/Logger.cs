using System;
using System.IO;

namespace IR_Collect.Utils
{
    /// <summary>
    /// 集中式日誌：寫入 logs/ir_collect.log，支援 Info / Warning / Error。
    /// </summary>
    public static class Logger
    {
        private static readonly object _lock = new object();
        private static string _logDir;
        private static string _logPath;
        private static bool _initialized;

        private static void EnsureInit()
        {
            if (_initialized) return;
            lock (_lock)
            {
                if (_initialized) return;
                try
                {
                    string baseDir = AppDomain.CurrentDomain.BaseDirectory ?? "";
                    _logDir = Path.Combine(baseDir, "logs");
                    _logPath = Path.Combine(_logDir, "ir_collect.log");
                    _initialized = true;
                }
                catch
                {
                    _logPath = null;
                    _initialized = true;
                }
            }
        }

        public static void Info(string message)
        {
            Write("INFO", message, null);
        }

        public static void Warning(string message)
        {
            Write("WARN", message, null);
        }

        public static void Error(string message)
        {
            Write("ERROR", message, null);
        }

        public static void Error(string message, Exception ex)
        {
            string extra = (ex != null) ? (" | " + ex.Message) : "";
            Write("ERROR", message + extra, ex);
        }

        private static void Write(string level, string message, Exception ex)
        {
            EnsureInit();
            string line = string.Format("[{0:yyyy-MM-dd HH:mm:ss}] [{1}] {2}",
                DateTime.Now, level, message ?? "");
            if (ex != null && !string.IsNullOrEmpty(ex.StackTrace))
                line += Environment.NewLine + "  " + (ex.StackTrace ?? "").Replace(Environment.NewLine, Environment.NewLine + "  ");
            lock (_lock)
            {
                try
                {
                    if (!string.IsNullOrEmpty(_logDir) && !Directory.Exists(_logDir))
                        Directory.CreateDirectory(_logDir);
                    if (!string.IsNullOrEmpty(_logPath))
                        File.AppendAllText(_logPath, line + Environment.NewLine, new System.Text.UTF8Encoding(false));
                }
                catch { }
            }
#if DEBUG
            System.Diagnostics.Debug.WriteLine(line);
#endif
        }
    }
}
