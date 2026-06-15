using System;
using System.Windows.Forms;
using System.Runtime.InteropServices;
#if INCLUDE_TESTS
using IR_Collect.Tests;
#endif

namespace IR_Collect
{
    static class Program
    {
        [DllImport("kernel32.dll")]
        static extern bool AttachConsole(int dwProcessId);
        private const int ATTACH_PARENT_PROCESS = -1;

        [DllImport("kernel32.dll")]
        static extern bool FreeConsole();

        [STAThread]
        static void Main(string[] args)
        {
            // Hybrid Mode Logic
            if (args.Length > 0)
            {
                // CLI Mode
                AttachConsole(ATTACH_PARENT_PROCESS);
                
                string mode = args[0].ToLower();
                if (mode == "-version" || mode == "--version")
                {
                    // Court-admissibility / reproducibility: report tool identity headlessly. The same
                    // tool_name/tool_version is stamped into every analysis JSON output.
                    Console.WriteLine(BuildInfo.ToolIdentity);
                    Console.WriteLine("output_schemas: summary_v3, correlation_v1, graph_v1, full_log_v3");
                    FreeConsole();
                    Environment.Exit(0);
                }
                else if (mode == "-h" || mode == "--help")
                {
                    Console.WriteLine("\nIR_Collect — Windows DFIR Artifact Collector & Analyzer");
                    Console.WriteLine("");
                    Console.WriteLine("Usage:");
                    Console.WriteLine("  IR_Collect.exe                 Launch GUI");
                    Console.WriteLine("  IR_Collect.exe -c [EvidenceID]  Run collection (CLI). Output: <EvidenceID>.zip in current directory.");
                    Console.WriteLine("  IR_Collect.exe -analyze <folder|-> [out.json]  Analyze an already-collected artifact folder -> summary JSON (no live host).");
                    Console.WriteLine("  IR_Collect.exe -correlate <out.json> <folderA> <folderB> [...]  Cross-host correlation over >=2 folders -> correlation JSON.");
                    Console.WriteLine("  IR_Collect.exe -graph <seedType> <seedValue> <maxDepth> <out.json> <folderA> [...]  Multi-hop investigation graph -> graph JSON.");
                    Console.WriteLine("  IR_Collect.exe -version         Print tool name + version + output schema versions");
                    Console.WriteLine("  IR_Collect.exe -h, --help       Show this help");
#if INCLUDE_TESTS
                    Console.WriteLine("  IR_Collect.exe -test            Run built-in self-tests (writes %TEMP%\\IR_Collect_TestResult.txt)");
                    Console.WriteLine("  IR_Collect.exe -make-fixtures [dir]  Regenerate the parser fixture corpus (default: tests\\fixtures)");
                    Console.WriteLine("  IR_Collect.exe -parse <kind> <file> [out]  Parse one artifact (lnk|jumplist); emit JSON (diff-validation harness)");
#endif
                    Console.WriteLine("");
                    Console.WriteLine("Examples:");
                    Console.WriteLine("  IR_Collect.exe -c              Collect with auto-generated ID");
                    Console.WriteLine("  IR_Collect.exe -c MyCase-001   Collect with ID MyCase-001");
                    Console.WriteLine("");
                }
                else if (mode == "-c" || mode == "--collect")
                {
                    Console.WriteLine("\n[+] Starting IR Collection in CLI Mode...");
                    string evidenceId = args.Length > 1 ? args[1] : null;
                    try
                    {
                        var cfgCli = new ConfigManager();
                        string cliProfile = CollectionModeProfileHelper.GetActive(cfgCli);
                        Console.WriteLine("[i] Collection mode profile: " + cliProfile);
                        if (CollectionModeProfileHelper.IsTriageFast(cliProfile))
                        {
                            Console.WriteLine("[i] TriageFast: live response still changes the host; outputs are labeled for faster triage workflows (not a footprint guarantee).");
                        }
                        if (CollectionModeProfileHelper.IsForensicStrict(cliProfile))
                        {
                            string outName = Collector.GetCollectionOutputDirectoryName(evidenceId);
                            string outFull;
                            try { outFull = System.IO.Path.GetFullPath(outName); }
                            catch { outFull = outName; }
                            Console.WriteLine("[!] ForensicStrict: live-response collection can perturb the system; this is not zero-footprint or a full low-impact forensic suite.");
                            Console.WriteLine("[!] Output workspace directory (before ZIP): " + outFull);
                            Console.WriteLine("[!] Prefer an isolated output volume when possible; writing on a suspect disk can be risky.");
                            Console.WriteLine("[!] Outbound ZIP upload and in-app AI Analyze are blocked while ForensicStrict is selected in Settings.");
                        }

                        var result = Collector.RunCollectionDetailed(evidenceId, null);
                        string zipPath = result != null ? result.ZipPath : null;
                        if (result != null && result.HasErrors)
                        {
                            Console.WriteLine("[!] Collection completed with errors.");
                            Console.WriteLine("[!] Failed steps: " + result.BuildFailureSummary());
                            if (!string.IsNullOrEmpty(zipPath)) Console.WriteLine("[+] Output: " + zipPath);
                            FreeConsole();
                            Environment.Exit(2);
                        }
                        if (result != null && result.HasCoverageGaps)
                        {
                            Console.WriteLine("[!] Collection completed with coverage gaps.");
                            if (result.CoverageReport != null)
                            {
                                Console.WriteLine(string.Format(
                                    "[!] Coverage: {0} (complete {1}, partial {2}, failed {3}, skipped {4}, missing {5})",
                                    string.IsNullOrWhiteSpace(result.CoverageReport.OverallStatus) ? "unknown" : result.CoverageReport.OverallStatus,
                                    result.CoverageReport.CompletedSteps,
                                    result.CoverageReport.PartialSteps,
                                    result.CoverageReport.FailedSteps,
                                    result.CoverageReport.SkippedSteps,
                                    result.CoverageReport.MissingSteps));
                            }
                            if (!string.IsNullOrEmpty(zipPath)) Console.WriteLine("[+] Output: " + zipPath);
                            FreeConsole();
                            Environment.Exit(0);
                        }
                        Console.WriteLine("[+] Collection Complete.");
                        if (!string.IsNullOrEmpty(zipPath)) Console.WriteLine("[+] Output: " + zipPath);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("[!] Collection failed: " + ex.Message);
                        if (ex.InnerException != null) Console.WriteLine("[!] Inner: " + ex.InnerException.Message);
                        FreeConsole();
                        Environment.Exit(1);
                    }
                }
                else if (mode == "-analyze")
                {
                    // -analyze <folder|-> [out.json]. Analysis-layer front door (Phase 3.1): ingest a folder
                    // of already-collected artifacts and emit a summary_v3 JSON. '-' reads the folder path
                    // from stdin. No live host is touched.
                    string folder = args.Length > 1 ? args[1] : null;
                    string outFile = args.Length > 2 ? args[2] : null;
                    int rc;
                    if (string.IsNullOrEmpty(folder))
                    {
                        Console.WriteLine("\n[!] Usage: IR_Collect.exe -analyze <folder|-> [out.json]");
                        rc = 2;
                    }
                    else
                    {
                        rc = IR_Collect.Analysis.AnalysisCli.Run(folder, outFile, Console.Out);
                    }
                    FreeConsole();
                    Environment.Exit(rc);
                }
                else if (mode == "-correlate")
                {
                    // -correlate <out.json> <folderA> <folderB> [...]. Phase 3.2: cross-host correlation
                    // over two or more already-collected folders. No live host is touched.
                    int rc;
                    if (args.Length < 4)
                    {
                        Console.WriteLine("\n[!] Usage: IR_Collect.exe -correlate <out.json> <folderA> <folderB> [...]");
                        rc = 2;
                    }
                    else
                    {
                        string outFile = args[1];
                        var folders = new System.Collections.Generic.List<string>();
                        for (int i = 2; i < args.Length; i++) folders.Add(args[i]);
                        rc = IR_Collect.Analysis.CorrelationCli.Run(folders, outFile, null, Console.Out);
                    }
                    FreeConsole();
                    Environment.Exit(rc);
                }
                else if (mode == "-graph")
                {
                    // -graph <seedType> <seedValue> <maxDepth> <out.json> <folderA> [...]. Phase 3.2b:
                    // multi-hop investigation graph expanded from a seed entity across >=1 folder(s).
                    int rc;
                    if (args.Length < 6)
                    {
                        Console.WriteLine("\n[!] Usage: IR_Collect.exe -graph <seedType> <seedValue> <maxDepth> <out.json> <folderA> [...]");
                        rc = 2;
                    }
                    else
                    {
                        string seedType = args[1];
                        string seedValue = args[2];
                        int maxDepth;
                        if (!int.TryParse(args[3], out maxDepth)) maxDepth = 2;
                        string outFile = args[4];
                        var folders = new System.Collections.Generic.List<string>();
                        for (int i = 5; i < args.Length; i++) folders.Add(args[i]);
                        rc = IR_Collect.Analysis.GraphCli.Run(seedType, seedValue, maxDepth, outFile, folders, Console.Out);
                    }
                    FreeConsole();
                    Environment.Exit(rc);
                }
#if INCLUDE_TESTS
                else if (mode == "-test" || mode == "--test")
                {
                    int testExit = IRCollectSelfTests.RunAndWriteResultFile();
                    FreeConsole();
                    Environment.Exit(testExit);
                }
                else if (mode == "-parse")
                {
                    // -parse <kind> <file> [outFile]. This is a winexe (GUI subsystem), so stdout is not
                    // reliably captured when piped; the optional outFile gives the harness a deterministic
                    // result sink (mirrors how -test also writes a result file).
                    string kind = args.Length > 1 ? args[1] : null;
                    string file = args.Length > 2 ? args[2] : null;
                    string outFile = args.Length > 3 ? args[3] : null;
                    int rc;
                    if (!string.IsNullOrEmpty(outFile))
                    {
                        using (var sw = new System.IO.StreamWriter(outFile, false, new System.Text.UTF8Encoding(false)))
                            rc = IR_Collect.Tests.ParserCli.Run(kind, file, sw);
                    }
                    else
                    {
                        rc = IR_Collect.Tests.ParserCli.Run(kind, file, Console.Out);
                    }
                    FreeConsole();
                    Environment.Exit(rc);
                }
                else if (mode == "-dump-mft")
                {
                    // -dump-mft <driveLetter> <outDir>. Raw-extract $MFT (needs admin). Used by the
                    // local-sample extractor so MFTECmd and our MftParser can diff the same $MFT file.
                    string drive = args.Length > 1 ? args[1] : "C";
                    string outDir = args.Length > 2 ? args[2] : ".";
                    try
                    {
                        System.IO.Directory.CreateDirectory(outDir);
                        string path = IR_Collect.MFT.MftDumper.DumpMft(drive, outDir);
                        Console.WriteLine("[+] $MFT dumped to: " + path);
                        FreeConsole();
                        Environment.Exit(0);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("[!] $MFT dump failed (run elevated?): " + ex.Message);
                        FreeConsole();
                        Environment.Exit(1);
                    }
                }
                else if (mode == "-make-fixtures")
                {
                    string outDir = args.Length > 1 ? args[1] : System.IO.Path.Combine("tests", "fixtures");
                    try
                    {
                        int n = IR_Collect.Tests.FixtureCorpus.WriteCorpus(outDir);
                        Console.WriteLine("[+] Wrote " + n + " fixture(s) + manifest.json + README.md to " + outDir);
                        FreeConsole();
                        Environment.Exit(0);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("[!] Fixture generation failed: " + ex.Message);
                        FreeConsole();
                        Environment.Exit(1);
                    }
                }
#endif
                else
                {
                    Console.WriteLine("\n[!] Unknown argument: " + args[0]);
                    Console.WriteLine("Use -h or --help for usage.");
                    FreeConsole();
                    Environment.Exit(1);
                }

                // Detach console before exiting so the command prompt returns
                FreeConsole(); 
            }
            else
            {
                // GUI Mode
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                Application.Run(new MainForm());
            }
        }
    }
}
