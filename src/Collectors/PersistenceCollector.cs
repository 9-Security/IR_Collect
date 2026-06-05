using System;
using System.IO;
using System.Diagnostics;
using Microsoft.Win32;
using IR_Collect.Utils;

namespace IR_Collect.Collectors
{
    public static class PersistenceCollector
    {
        public static void Collect(string outputDir)
        {
            Console.WriteLine("[*] Collecting Persistence Artifacts...");
            var failed = new System.Collections.Generic.List<string>();
            if (!CollectAutoruns(outputDir)) failed.Add("Autoruns");
            if (!CollectServices(outputDir)) failed.Add("Services");
            if (!CollectScheduledTasks(outputDir)) failed.Add("Scheduled Tasks");
            if (failed.Count > 0)
                throw new InvalidOperationException("Persistence collection incomplete: " + string.Join(", ", failed.ToArray()));
        }

        private static bool CollectAutoruns(string outputDir)
        {
            try
            {
                string outFile = Path.Combine(outputDir, ArtifactNames.AutorunsRegistryCsv);
                bool hadDumpErrors = false;
                using (StreamWriter sw = new StreamWriter(outFile, false, new System.Text.UTF8Encoding(false)))
                {
                    sw.WriteLine("Hive,Path,Name,Value");
                    
                    // Run & RunOnce
                    string[] roots = { "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" };
                    foreach(var r in roots)
                    {
                        if (!DumpKey(Registry.LocalMachine, r, sw)) hadDumpErrors = true;
                        if (!DumpKey(Registry.CurrentUser, r, sw)) hadDumpErrors = true;
                    }
                    
                    // Winlogon
                    if (!DumpKey(Registry.LocalMachine, "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", sw)) hadDumpErrors = true;
                }
                Console.WriteLine("    + Autoruns collected.");
                if (hadDumpErrors)
                    throw new InvalidOperationException("One or more persistence registry keys could not be read.");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("    ! Error collecting autoruns: " + ex.Message);
                return false;
            }
        }

        private static bool DumpKey(RegistryKey root, string path, StreamWriter sw)
        {
             try
             {
                 using (RegistryKey key = root.OpenSubKey(path))
                 {
                     if (key != null)
                     {
                         foreach(string name in key.GetValueNames())
                         {
                             string val = key.GetValue(name, "").ToString();
                             sw.WriteLine(string.Format("{0},{1},{2},{3}", root.Name, path, IR_Collect.Utils.CsvUtils.EscapeField(name), IR_Collect.Utils.CsvUtils.EscapeField(val)));
                         }
                     }
                 }
                 return true;
             }
             catch (Exception ex) { Logger.Warning("PersistenceCollector: " + ex.Message); return false; }
        }

        private static bool CollectServices(string outputDir)
        {
            try
            {
                // wmic service get /format:csv
                string outFile = Path.Combine(outputDir, ArtifactNames.ServicesCsv);
                IR_Collect.Collector.CommandHelper.RunWmicToFile("service get Name,DisplayName,PathName,StartMode,State /format:csv", outFile);
                Console.WriteLine("    + Services collected.");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("    ! Error collecting services: " + ex.Message);
                return false;
            }
        }

        private static bool CollectScheduledTasks(string outputDir)
        {
            try
            {
                string outFile = Path.Combine(outputDir, ArtifactNames.ScheduledTasksXml);
                // Get raw output
                string output = IR_Collect.Collector.CommandHelper.Run("schtasks", "/query /xml");
                
                // Clean up XML: strip <?xml ...?> declarations (schtasks repeats them for every task)
                string clean = System.Text.RegularExpressions.Regex.Replace(output, @"<\?xml.*?\?>", "", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                
                // Wrap in root element
                string wrapped = "<Tasks>" + clean + "</Tasks>";

                // Write with UTF-8 (no BOM)
                File.WriteAllText(outFile, wrapped, new System.Text.UTF8Encoding(false));
                
                Console.WriteLine("    + Scheduled tasks collected (XML).");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("    ! Error collecting tasks: " + ex.Message);
                return false;
            }
        }

    }
}
