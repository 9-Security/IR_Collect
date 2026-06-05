using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;

namespace IR_Collect.Analysis
{
    [DataContract]
    public sealed class AnalystWorkflowState
    {
        [DataMember(Name = "bookmarked")]
        public bool Bookmarked { get; set; }

        [DataMember(Name = "priority")]
        public string Priority { get; set; }

        [DataMember(Name = "tags")]
        public List<string> Tags { get; set; }

        [DataMember(Name = "hypothesis")]
        public string Hypothesis { get; set; }

        [DataMember(Name = "notes")]
        public string Notes { get; set; }

        [DataMember(Name = "updated_at")]
        public string UpdatedAt { get; set; }

        public AnalystWorkflowState()
        {
            Priority = "";
            Tags = new List<string>();
            Hypothesis = "";
            Notes = "";
            UpdatedAt = "";
        }
    }

    public static class AnalystWorkflowStore
    {
        public static string ResolvePath(string sourceZipPath, string extractPath)
        {
            if (!string.IsNullOrWhiteSpace(sourceZipPath))
                return sourceZipPath + ArtifactNames.AnalystWorkflowJsonSuffix;
            if (!string.IsNullOrWhiteSpace(extractPath))
                return Path.Combine(extractPath, "analyst_workflow.json");
            return null;
        }

        public static AnalystWorkflowState LoadFromFile(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                return new AnalystWorkflowState();

            var serializer = new DataContractJsonSerializer(typeof(AnalystWorkflowState));
            using (var sr = new StreamReader(path, Encoding.UTF8, true))
            {
                string json = sr.ReadToEnd();
                if (!string.IsNullOrEmpty(json) && json[0] == '\uFEFF')
                    json = json.Substring(1);
                using (var ms = new MemoryStream(Encoding.UTF8.GetBytes(json ?? "")))
                {
                    var state = serializer.ReadObject(ms) as AnalystWorkflowState;
                    return state ?? new AnalystWorkflowState();
                }
            }
        }

        public static bool SaveToFile(AnalystWorkflowState state, string path, out string error)
        {
            error = "";
            if (state == null)
                state = new AnalystWorkflowState();
            if (string.IsNullOrWhiteSpace(path))
            {
                error = "Workflow sidecar path is unavailable.";
                return false;
            }

            try
            {
                string dir = Path.GetDirectoryName(path);
                if (!string.IsNullOrWhiteSpace(dir) && !Directory.Exists(dir))
                    Directory.CreateDirectory(dir);

                state.UpdatedAt = DateTime.UtcNow.ToString("o");
                var serializer = new DataContractJsonSerializer(typeof(AnalystWorkflowState));
                using (var ms = new MemoryStream())
                {
                    serializer.WriteObject(ms, state);
                    File.WriteAllText(path, Encoding.UTF8.GetString(ms.ToArray()), new UTF8Encoding(false));
                }
                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message ?? "unknown error";
                return false;
            }
        }

        public static List<string> NormalizeTags(string rawTags)
        {
            var tags = new List<string>();
            if (string.IsNullOrWhiteSpace(rawTags))
                return tags;

            string[] parts = rawTags.Split(new char[] { ',', ';', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string part in parts)
            {
                string tag = (part ?? "").Trim();
                if (string.IsNullOrWhiteSpace(tag) || !seen.Add(tag))
                    continue;
                tags.Add(tag);
            }
            return tags;
        }
    }
}
