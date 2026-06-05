using System;
using System.IO;
using IR_Collect.Utils;

namespace IR_Collect.Collectors
{
    public static class PrefetchCollector
    {
        public static void Collect(string outputDir)
        {
            Console.WriteLine("[*] Collecting Prefetch Files...");
            
            if (!IsAdministrator())
            {
                Console.WriteLine("    [!] SKIPPED: Accessing Prefetch requires Administrator privileges.");
                Logger.Info("Prefetch: SKIPPED (run as Administrator to collect Prefetch)");
                throw new InvalidOperationException("Prefetch requires Administrator privileges.");
            }

            string pfDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
            string destDir = Path.Combine(outputDir, "Prefetch");

            if (!Directory.Exists(pfDir))
            {
                Console.WriteLine("    [!] Prefetch directory not found at: " + pfDir);
                throw new DirectoryNotFoundException("Prefetch directory not found: " + pfDir);
            }

            try
            {
                if (!Directory.Exists(destDir)) Directory.CreateDirectory(destDir);

                string[] files = Directory.GetFiles(pfDir, "*.pf");
                int count = 0;
                int errors = 0;

                foreach (string file in files)
                {
                    try
                    {
                        string destFile = Path.Combine(destDir, Path.GetFileName(file));
                        File.Copy(file, destFile, true);
                        count++;
                    }
                    catch (Exception copyEx) 
                    { 
                        errors++;
                        // Detailed error for first failure
                        if (errors == 1) Console.WriteLine("    [!] Copy Error (Sample): " + copyEx.Message);
                    } 
                }
                Console.WriteLine("    + Collected {0} prefetch files. (Errors: {1})", count, errors);
                if (errors > 0)
                    throw new IOException("One or more prefetch files could not be copied.");
            }
            catch (UnauthorizedAccessException)
            {
                 Console.WriteLine("    [!] Access Denied to Prefetch directory!");
                 throw;
            }
            catch (Exception ex)
            {
                Console.WriteLine("    ! Error logging prefetch: " + ex.Message);
                throw;
            }
        }

        private static bool IsAdministrator()
        {
            using (var identity = System.Security.Principal.WindowsIdentity.GetCurrent())
            {
                var principal = new System.Security.Principal.WindowsPrincipal(identity);
                return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
        }
    }
}
