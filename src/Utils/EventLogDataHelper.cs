using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml.Linq;

namespace IR_Collect.Utils
{
    internal static class EventLogDataHelper
    {
        public const string EventDataColumn = "EventData";

        public static Dictionary<string, string> ExtractEventDataFromXml(string xml)
        {
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (string.IsNullOrWhiteSpace(xml)) return map;

            try
            {
                XDocument doc = XDocument.Parse(xml);
                int unnamedIndex = 0;

                foreach (XElement dataElement in doc.Descendants().Where(e => string.Equals(e.Name.LocalName, "Data", StringComparison.OrdinalIgnoreCase)))
                {
                    string value = SanitizeSingleLine(dataElement.Value);
                    if (string.IsNullOrWhiteSpace(value)) continue;

                    XAttribute nameAttr = dataElement.Attribute("Name");
                    string key = nameAttr != null ? SanitizeSingleLine(nameAttr.Value) : "";
                    if (string.IsNullOrWhiteSpace(key))
                    {
                        unnamedIndex++;
                        key = "Data" + unnamedIndex.ToString();
                    }

                    if (!map.ContainsKey(key))
                        map[key] = value;
                }

                XElement userData = doc.Descendants().FirstOrDefault(e => string.Equals(e.Name.LocalName, "UserData", StringComparison.OrdinalIgnoreCase));
                if (userData != null)
                {
                    foreach (XElement leaf in userData.Descendants().Where(e => !e.HasElements))
                    {
                        string key = SanitizeSingleLine(leaf.Name.LocalName);
                        string value = SanitizeSingleLine(leaf.Value);
                        if (string.IsNullOrWhiteSpace(key) || string.IsNullOrWhiteSpace(value)) continue;
                        if (!map.ContainsKey(key))
                            map[key] = value;
                    }
                }
            }
            catch
            {
            }

            return map;
        }

        public static string FlattenEventData(IDictionary<string, string> data, int maxPairs, int maxValueLength, int maxChars)
        {
            if (data == null || data.Count == 0) return "";

            var parts = new List<string>();
            int count = 0;
            foreach (KeyValuePair<string, string> kv in data)
            {
                if (maxPairs > 0 && count >= maxPairs) break;
                string key = SanitizeSingleLine(kv.Key);
                string value = SanitizeSingleLine(kv.Value);
                if (string.IsNullOrWhiteSpace(key) || string.IsNullOrWhiteSpace(value)) continue;
                if (maxValueLength > 0 && value.Length > maxValueLength)
                    value = value.Substring(0, maxValueLength - 3) + "...";
                value = value.Replace("|", "/");
                parts.Add(key + "=" + value);
                count++;
            }

            string flattened = string.Join(" | ", parts.ToArray());
            if (maxChars > 0 && flattened.Length > maxChars)
                flattened = flattened.Substring(0, maxChars - 3) + "...";
            return flattened;
        }

        public static Dictionary<string, string> ParseFlattenedEventData(string flattened)
        {
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (string.IsNullOrWhiteSpace(flattened)) return map;

            string[] parts = flattened.Split(new string[] { " | " }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string part in parts)
            {
                int idx = part.IndexOf('=');
                if (idx <= 0) continue;
                string key = SanitizeSingleLine(part.Substring(0, idx));
                string value = SanitizeSingleLine(part.Substring(idx + 1));
                if (string.IsNullOrWhiteSpace(key) || string.IsNullOrWhiteSpace(value)) continue;
                if (!map.ContainsKey(key))
                    map[key] = value;
            }

            return map;
        }

        public static string GetValue(IDictionary<string, string> data, params string[] keys)
        {
            if (data == null || keys == null) return "";

            foreach (string key in keys)
            {
                if (string.IsNullOrWhiteSpace(key)) continue;

                string direct;
                if (TryGetValue(data, key, out direct) && !string.IsNullOrWhiteSpace(direct))
                    return direct.Trim();

                string normalizedKey = NormalizeKey(key);
                foreach (KeyValuePair<string, string> kv in data)
                {
                    if (NormalizeKey(kv.Key) == normalizedKey && !string.IsNullOrWhiteSpace(kv.Value))
                        return kv.Value.Trim();
                }
            }

            return "";
        }

        public static string SanitizeSingleLine(string value)
        {
            if (string.IsNullOrEmpty(value)) return "";
            return value.Replace("\r", " ").Replace("\n", " ").Replace("\t", " ").Trim();
        }

        private static bool TryGetValue(IDictionary<string, string> data, string key, out string value)
        {
            value = "";
            if (data == null || string.IsNullOrWhiteSpace(key)) return false;

            string found;
            if (data.TryGetValue(key, out found))
            {
                value = found ?? "";
                return true;
            }

            return false;
        }

        private static string NormalizeKey(string key)
        {
            if (string.IsNullOrWhiteSpace(key)) return "";

            var sb = new StringBuilder(key.Length);
            foreach (char ch in key)
            {
                if (char.IsLetterOrDigit(ch))
                    sb.Append(char.ToLowerInvariant(ch));
            }

            return sb.ToString();
        }
    }
}
