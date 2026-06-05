using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Xml.Linq;
using IR_Collect;
using IR_Collect.Analysis.Correlation;
using IR_Collect.Utils;

namespace IR_Collect.Analysis.Correlation.Normalizers
{
    public static class ScheduledTaskNormalizer
    {
        public const string SourceName = "ScheduledTask";

        public static List<Correlation.Fact> ToFacts(string scheduledTasksXmlPath)
        {
            var list = new List<Correlation.Fact>();
            if (string.IsNullOrEmpty(scheduledTasksXmlPath) || !File.Exists(scheduledTasksXmlPath)) return list;
            try
            {
                string content = File.ReadAllText(scheduledTasksXmlPath, System.Text.Encoding.UTF8).Trim();
                content = System.Text.RegularExpressions.Regex.Replace(content, @"<\?xml.*?\?>", "", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                if (!content.StartsWith("<Tasks>", StringComparison.OrdinalIgnoreCase))
                    content = "<Tasks>" + content + "</Tasks>";

                XDocument doc = XDocument.Parse(content);
                var tasks = doc.Descendants().Where(el => el.Name.LocalName == "Task");
                int idx = 0;
                foreach (var task in tasks)
                {
                    string uri = "";
                    var uriNode = task.Descendants().FirstOrDefault(el => el.Name.LocalName == "URI");
                    if (uriNode != null) uri = uriNode.Value;

                    string runAs = "";
                    var princ = task.Descendants().FirstOrDefault(el => el.Name.LocalName == "Principal");
                    if (princ != null)
                    {
                        var uid = princ.Elements().FirstOrDefault(el => el.Name.LocalName == "UserId");
                        var gid = princ.Elements().FirstOrDefault(el => el.Name.LocalName == "GroupId");
                        if (uid != null) runAs = uid.Value;
                        else if (gid != null) runAs = gid.Value;
                    }

                    var actions = task.Descendants().FirstOrDefault(el => el.Name.LocalName == "Actions");
                    if (actions == null) continue;
                    foreach (var act in actions.Elements())
                    {
                        if (act.Name.LocalName != "Exec") continue;
                        string cmd = "";
                        string args = "";
                        var cmdNode = act.Elements().FirstOrDefault(el => el.Name.LocalName == "Command");
                        if (cmdNode != null) cmd = cmdNode.Value;
                        var argsNode = act.Elements().FirstOrDefault(el => el.Name.LocalName == "Arguments");
                        if (argsNode != null) args = argsNode.Value;

                        if (string.IsNullOrWhiteSpace(cmd)) continue;

                        string id = "ScheduledTask_" + idx++;
                        var fact = new Fact(id, DateTime.MinValue, SourceName, "Scheduled");
                        FactTimeMetadata.Apply(fact, FactTimeMetadata.InferTimeKind(SourceName, fact.Time), FactTimeMetadata.InferTimeConfidence(SourceName, fact.Time));
                        fact.SourceFile = ArtifactNames.ScheduledTasksXml;
                        fact.RawRef = ArtifactNames.ScheduledTasksXml + ": " + uri;
                        fact.ParseLevel = FactProvenanceMetadata.StructuredXmlParseLevel;
                        fact.Details = args.Length > 300 ? args.Substring(0, 297) + "..." : args;
                        if (string.IsNullOrWhiteSpace(uri))
                        {
                            fact.ParserNote = "Scheduled task URI was unavailable; this fact is linked by command path and any available user only.";
                            fact.FallbackUsed = true;
                        }

                        fact.AddEntity("Path", cmd.Trim());
                        if (!string.IsNullOrWhiteSpace(uri))
                            fact.AddEntity("TaskName", uri.Trim());
                        if (!string.IsNullOrWhiteSpace(runAs))
                            fact.AddEntity("User", runAs.Trim());
                        list.Add(fact);
                    }
                }
            }
            catch (Exception ex) { Logger.Warning("ScheduledTaskNormalizer: " + ex.Message); }
            return list;
        }
    }
}
