using System.Globalization;
using System.IO;
using System.Text;
using IR_Collect.Utils;

namespace IR_Collect.Collectors
{
    /// <summary>
    /// Shared writers that serialize a parsed Amcache / ShimCache / SRUM result to the canonical
    /// collector CSV format. Used both by ExecutionArtifactCollector (live collection) and by the
    /// Phase 3.1 RawArtifactCsvDeriver (analysis-layer folder ingest), so the two paths cannot drift
    /// in column layout - the normalizers parse exactly these headers.
    /// </summary>
    public static class ExecutionArtifactCsvWriter
    {
        public static void WriteShimCacheEntriesCsv(ShimCacheParseResult parsed, string outFile)
        {
            AtomicFile.WriteText(outFile, new UTF8Encoding(false), delegate(StreamWriter sw)
            {
                sw.WriteLine("RegistryPath,ValueName,EntryIndex,Path,FileName,LastModifiedTime,DataHashPrefix,ParserNote");
                foreach (ShimCacheEntryRecord row in parsed.Entries)
                {
                    sw.WriteLine(string.Join(",", new string[]
                    {
                        CsvUtils.EscapeField(row.RegistryPath),
                        CsvUtils.EscapeField(row.ValueName),
                        CsvUtils.EscapeField(row.EntryIndex.ToString(CultureInfo.InvariantCulture)),
                        CsvUtils.EscapeField(row.Path),
                        CsvUtils.EscapeField(row.FileName),
                        CsvUtils.EscapeField(row.LastModifiedTime),
                        CsvUtils.EscapeField(row.DataHashPrefix),
                        CsvUtils.EscapeField(row.ParserNote)
                    }));
                }
                foreach (string note in parsed.ParserNotes)
                {
                    sw.WriteLine(string.Join(",", new string[]
                    {
                        CsvUtils.EscapeField(@"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"),
                        CsvUtils.EscapeField(""),
                        CsvUtils.EscapeField("0"),
                        CsvUtils.EscapeField(""),
                        CsvUtils.EscapeField(""),
                        CsvUtils.EscapeField(""),
                        CsvUtils.EscapeField(""),
                        CsvUtils.EscapeField(note)
                    }));
                }
            });
        }

        public static void WriteAmcacheCsvs(AmcacheParseResult parsed, string programsCsv, string filesCsv)
        {
            AtomicFile.WriteText(programsCsv, new UTF8Encoding(false), delegate(StreamWriter sw)
            {
                sw.WriteLine("RegistryKey,ProgramName,Publisher,Version,ProductName,InstallDate,UninstallString,ProgramId,ParserNote");
                foreach (AmcacheProgramRecord row in parsed.Programs)
                {
                    sw.WriteLine(string.Join(",", new string[]
                    {
                        CsvUtils.EscapeField(row.RegistryKey),
                        CsvUtils.EscapeField(row.ProgramName),
                        CsvUtils.EscapeField(row.Publisher),
                        CsvUtils.EscapeField(row.Version),
                        CsvUtils.EscapeField(row.ProductName),
                        CsvUtils.EscapeField(row.InstallDate),
                        CsvUtils.EscapeField(row.UninstallString),
                        CsvUtils.EscapeField(row.ProgramId),
                        CsvUtils.EscapeField(row.ParserNote)
                    }));
                }
                foreach (string note in parsed.ParserNotes)
                {
                    sw.WriteLine(string.Join(",", new string[]
                    {
                        CsvUtils.EscapeField(""), CsvUtils.EscapeField(""), CsvUtils.EscapeField(""),
                        CsvUtils.EscapeField(""), CsvUtils.EscapeField(""), CsvUtils.EscapeField(""),
                        CsvUtils.EscapeField(""), CsvUtils.EscapeField(""), CsvUtils.EscapeField(note)
                    }));
                }
            });

            AtomicFile.WriteText(filesCsv, new UTF8Encoding(false), delegate(StreamWriter sw)
            {
                sw.WriteLine("RegistryKey,Path,FileName,Hash,ProductName,Publisher,ProgramId,FirstObservedTime,ExecutedTime,ParserNote");
                foreach (AmcacheFileRecord row in parsed.Files)
                {
                    sw.WriteLine(string.Join(",", new string[]
                    {
                        CsvUtils.EscapeField(row.RegistryKey),
                        CsvUtils.EscapeField(row.Path),
                        CsvUtils.EscapeField(row.FileName),
                        CsvUtils.EscapeField(row.Hash),
                        CsvUtils.EscapeField(row.ProductName),
                        CsvUtils.EscapeField(row.Publisher),
                        CsvUtils.EscapeField(row.ProgramId),
                        CsvUtils.EscapeField(row.FirstObservedTime),
                        CsvUtils.EscapeField(row.ExecutedTime),
                        CsvUtils.EscapeField(row.ParserNote)
                    }));
                }
            });
        }

        public static void WriteSrumCsvs(SrumExportResult export, string networkCsv, string appCsv)
        {
            AtomicFile.WriteText(networkCsv, new UTF8Encoding(false), delegate(StreamWriter sw)
            {
                sw.WriteLine("Timestamp,AppId,Path,User,RemoteIP,Interface,BytesSent,BytesReceived,ParserNote");
                foreach (SrumNetworkRecord row in export.NetworkRows)
                {
                    sw.WriteLine(string.Join(",", new string[]
                    {
                        CsvUtils.EscapeField(row.Timestamp),
                        CsvUtils.EscapeField(row.AppId),
                        CsvUtils.EscapeField(row.Path),
                        CsvUtils.EscapeField(row.User),
                        CsvUtils.EscapeField(row.RemoteIP),
                        CsvUtils.EscapeField(row.InterfaceName),
                        CsvUtils.EscapeField(row.BytesSent),
                        CsvUtils.EscapeField(row.BytesReceived),
                        CsvUtils.EscapeField(row.ParserNote)
                    }));
                }
                foreach (string note in export.ParserNotes)
                {
                    sw.WriteLine(string.Join(",", new string[]
                    {
                        CsvUtils.EscapeField(""), CsvUtils.EscapeField(""), CsvUtils.EscapeField(""),
                        CsvUtils.EscapeField(""), CsvUtils.EscapeField(""), CsvUtils.EscapeField(""),
                        CsvUtils.EscapeField(""), CsvUtils.EscapeField(""), CsvUtils.EscapeField(note)
                    }));
                }
            });

            AtomicFile.WriteText(appCsv, new UTF8Encoding(false), delegate(StreamWriter sw)
            {
                sw.WriteLine("Timestamp,AppId,Path,User,ForegroundCycleTime,BackgroundCycleTime,ParserNote");
                foreach (SrumAppRecord row in export.AppRows)
                {
                    sw.WriteLine(string.Join(",", new string[]
                    {
                        CsvUtils.EscapeField(row.Timestamp),
                        CsvUtils.EscapeField(row.AppId),
                        CsvUtils.EscapeField(row.Path),
                        CsvUtils.EscapeField(row.User),
                        CsvUtils.EscapeField(row.ForegroundCycleTime),
                        CsvUtils.EscapeField(row.BackgroundCycleTime),
                        CsvUtils.EscapeField(row.ParserNote)
                    }));
                }
                foreach (string note in export.ParserNotes)
                {
                    sw.WriteLine(string.Join(",", new string[]
                    {
                        CsvUtils.EscapeField(""), CsvUtils.EscapeField(""), CsvUtils.EscapeField(""),
                        CsvUtils.EscapeField(""), CsvUtils.EscapeField(""), CsvUtils.EscapeField(""),
                        CsvUtils.EscapeField(note)
                    }));
                }
            });
        }
    }
}
