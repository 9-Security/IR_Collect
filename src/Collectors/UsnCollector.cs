using System;
using System.IO;
using IR_Collect;

namespace IR_Collect.Collectors
{
    public static class UsnCollector
    {
        public static void Collect(string outputDir, string driveLetter)
        {
            Console.WriteLine("[*] Collecting USN Journal...");
            string outFile = Path.Combine(outputDir, ArtifactNames.UsnJournalCsv);
            driveLetter = (driveLetter ?? "").Trim().ToUpperInvariant();
            if (driveLetter.Length != 1 || driveLetter[0] < 'A' || driveLetter[0] > 'Z')
                throw new InvalidOperationException("UsnCollector: invalid drive letter '" + (driveLetter ?? "") + "'.");
            try
            {
                string args = string.Format("usn readjournal {0}: csv", driveLetter);
                IR_Collect.Collector.CommandHelper.RunToFile("fsutil", args, outFile);
                if (!File.Exists(outFile) || new FileInfo(outFile).Length <= 0)
                    throw new IOException("USN journal output was not created: " + outFile);
            }
            catch (Exception ex)
            {
                Console.WriteLine("USN Collection Error: " + ex.Message);
                IR_Collect.Utils.Logger.Warning("UsnCollector: " + ex.Message);
                throw;
            }
        }
    }
}
