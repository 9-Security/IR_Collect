using System;
using System.IO;
using Microsoft.Win32;
using IR_Collect;
using IR_Collect.Utils;

namespace IR_Collect.Collectors
{
    public static class SoftwareCollector
    {
        public static void Collect(string outputDir)
        {
            Console.WriteLine("[*] Collecting Installed Software...");
            string outFile = Path.Combine(outputDir, ArtifactNames.InstalledSoftwareCsv);

            try
            {
                bool hadErrors = false;
                using (StreamWriter sw = new StreamWriter(outFile, false, new System.Text.UTF8Encoding(false)))
                {
                    sw.WriteLine("DisplayName,DisplayVersion,Publisher,InstallDate,UninstallString,SourceKey");

                    if (!CrawlUninstallKey(Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Uninstall", sw)) hadErrors = true;
                    if (!CrawlUninstallKey(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", sw)) hadErrors = true;
                    if (!CrawlUninstallKey(Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", sw)) hadErrors = true;
                }
                Console.WriteLine("    + Software inventory collected.");
                if (hadErrors)
                    throw new InvalidOperationException("One or more uninstall registry keys could not be read.");
            }
            catch (Exception ex)
            {
                Console.WriteLine("    ! Error collecting software: " + ex.Message);
                Logger.Warning("SoftwareCollector.Collect: " + ex.Message);
                throw;
            }
        }

        private static bool CrawlUninstallKey(RegistryKey root, string subKeyPath, StreamWriter sw)
        {
            bool ok = true;
            try
            {
                using (RegistryKey key = root.OpenSubKey(subKeyPath))
                {
                    if (key == null) return true;

                    foreach (string subKeyName in key.GetSubKeyNames())
                    {
                        try
                        {
                            using (RegistryKey subKey = key.OpenSubKey(subKeyName))
                            {
                                string name = GetString(subKey, "DisplayName");
                                if (string.IsNullOrEmpty(name)) continue;

                                string ver = GetString(subKey, "DisplayVersion");
                                string pub = GetString(subKey, "Publisher");
                                string date = GetString(subKey, "InstallDate");
                                string uninst = GetString(subKey, "UninstallString");

                                sw.WriteLine(string.Format("{0},{1},{2},{3},{4},{5}",
                                    CsvEscape(name),
                                    CsvEscape(ver),
                                    CsvEscape(pub),
                                    CsvEscape(date),
                                    CsvEscape(uninst),
                                    CsvEscape(root.Name + "\\" + subKeyPath + "\\" + subKeyName)
                                ));
                            }
                        }
                        catch (Exception ex)
                        {
                            Logger.Warning("SoftwareCollector.CrawlUninstallKey item: " + ex.Message);
                            ok = false;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Warning("SoftwareCollector.CrawlUninstallKey: " + ex.Message);
                ok = false;
            }
            return ok;
        }

        private static string GetString(RegistryKey key, string valName)
        {
            try
            {
                object o = key.GetValue(valName);
                if (o != null) return o.ToString();
            }
            catch (Exception ex) { Logger.Warning("SoftwareCollector GetString: " + ex.Message); }
            return "";
        }

        private static string CsvEscape(string field)
        {
            if (string.IsNullOrEmpty(field)) return "";
            if (field.Contains(",") || field.Contains("\"") || field.Contains("\n") || field.Contains("\r"))
                return "\"" + field.Replace("\"", "\"\"") + "\"";
            return field;
        }
    }
}
