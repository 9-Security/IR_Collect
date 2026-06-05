using System;
using System.Collections.Generic;
using System.Linq;
using IR_Collect.Analysis.Correlation;

namespace IR_Collect.Analysis
{
    internal static class ParserNoteSummaryBuilder
    {
        internal static List<string> BuildFactParserNoteLines(IEnumerable<Fact> facts, int maxInlineNotes)
        {
            var lines = new List<string>();
            var factList = facts != null ? facts.Where(f => f != null).ToList() : new List<Fact>();
            if (factList.Count == 0)
                return lines;

            var uniqueNotes = new List<KeyValuePair<string, string>>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var sources = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (Fact fact in factList)
            {
                string note = (fact.ParserNote ?? "").Trim();
                if (string.IsNullOrWhiteSpace(note))
                    continue;

                string source = string.IsNullOrWhiteSpace(fact.Source) ? "Unknown" : fact.Source.Trim();
                string key = source + "\n" + note;
                if (!seen.Add(key))
                    continue;

                sources.Add(source);
                uniqueNotes.Add(new KeyValuePair<string, string>(source, note));
            }

            if (uniqueNotes.Count == 0)
                return lines;

            uniqueNotes = uniqueNotes
                .OrderBy(v => v.Key, StringComparer.OrdinalIgnoreCase)
                .ThenBy(v => v.Value, StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (maxInlineNotes <= 0)
                maxInlineNotes = 8;

            lines.Add(string.Format(
                "Parser/fallback notes: {0} unique note(s) across {1} source(s) are preserved independently of fact sampling.",
                uniqueNotes.Count,
                sources.Count));

            foreach (KeyValuePair<string, string> pair in uniqueNotes.Take(maxInlineNotes))
                lines.Add(pair.Key + " note: " + pair.Value);

            if (uniqueNotes.Count > maxInlineNotes)
                lines.Add("Parser note: +" + (uniqueNotes.Count - maxInlineNotes).ToString() + " more.");

            return lines;
        }
    }
}
