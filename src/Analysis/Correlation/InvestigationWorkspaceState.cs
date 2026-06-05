using System;
using System.Collections.Generic;
using System.Linq;

namespace IR_Collect.Analysis.Correlation
{
    public static class InvestigationWorkspaceHostScopeMode
    {
        public const string AllHosts = "all_hosts";
        public const string CurrentEdgeHosts = "edge_hosts";
        public const string HostFilter = "host_filter";
    }

    public static class InvestigationWorkspaceResultMode
    {
        public const string InvestigationGraph = "investigation_graph";
        public const string EdgeFacts = "edge_facts";
        public const string RelatedEntities = "related_entities";
        public const string SharedEntities = "shared_entities";
        public const string TemporalCorrelation = "temporal_correlation";
    }

    public sealed class InvestigationWorkspaceFilters
    {
        public string SourcePrefixFilter { get; set; }
        public string TimeConfidenceFilter { get; set; }
        public string HostFilterText { get; set; }
        public bool UseFromTime { get; set; }
        public DateTime FromTime { get; set; }
        public bool UseToTime { get; set; }
        public DateTime ToTime { get; set; }
        public int BucketMinutes { get; set; }

        public InvestigationWorkspaceFilters Clone()
        {
            return new InvestigationWorkspaceFilters
            {
                SourcePrefixFilter = SourcePrefixFilter,
                TimeConfidenceFilter = TimeConfidenceFilter,
                HostFilterText = HostFilterText,
                UseFromTime = UseFromTime,
                FromTime = FromTime,
                UseToTime = UseToTime,
                ToTime = ToTime,
                BucketMinutes = BucketMinutes
            };
        }
    }

    public sealed class InvestigationWorkspaceSeed
    {
        public string SeedType { get; set; }
        public string SeedValue { get; set; }
        public string SeedDisplay { get; set; }
        public DateTime AtUtc { get; set; }
        public InvestigationWorkspaceFilters SnapshotFilters { get; set; }
        public string SnapshotHostScopeMode { get; set; }
    }

    public sealed class InvestigationWorkspaceState
    {
        private readonly List<InvestigationWorkspaceSeed> _history;
        private int _historyIndex;

        public string SelectedEdgeType { get; set; }
        public string SelectedEdgeValue { get; set; }
        public string SelectedEdgeDisplay { get; set; }
        public List<string> SelectedEdgeHosts { get; set; }
        public string HostScopeMode { get; set; }
        public string ResultMode { get; set; }
        public InvestigationWorkspaceFilters Filters { get; set; }
        public List<string> PinnedEntities { get; set; }

        public InvestigationWorkspaceState()
        {
            _history = new List<InvestigationWorkspaceSeed>();
            _historyIndex = -1;
            SelectedEdgeHosts = new List<string>();
            HostScopeMode = InvestigationWorkspaceHostScopeMode.AllHosts;
            ResultMode = InvestigationWorkspaceResultMode.InvestigationGraph;
            Filters = new InvestigationWorkspaceFilters();
            PinnedEntities = new List<string>();
        }

        public IReadOnlyList<InvestigationWorkspaceSeed> History
        {
            get { return _history; }
        }

        public InvestigationWorkspaceSeed CurrentSeed
        {
            get
            {
                if (_historyIndex < 0 || _historyIndex >= _history.Count)
                    return null;
                return _history[_historyIndex];
            }
        }

        public InvestigationWorkspaceSeed OriginalSeed
        {
            get { return _history.Count > 0 ? _history[0] : null; }
        }

        public bool CanGoBack
        {
            get { return _historyIndex > 0; }
        }

        public bool CanGoForward
        {
            get { return _historyIndex >= 0 && _historyIndex < _history.Count - 1; }
        }

        public void StartOrAppendSeed(string seedType, string seedValue, string seedDisplay)
        {
            if (string.IsNullOrWhiteSpace(seedType) || string.IsNullOrWhiteSpace(seedValue))
                return;

            var normalizedType = seedType.Trim();
            var normalizedValue = seedValue.Trim();
            var display = string.IsNullOrWhiteSpace(seedDisplay) ? normalizedValue : seedDisplay.Trim();
            var current = CurrentSeed;
            if (current != null &&
                string.Equals(current.SeedType, normalizedType, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(current.SeedValue, normalizedValue, StringComparison.OrdinalIgnoreCase))
            {
                if (_historyIndex >= 0 && _historyIndex < _history.Count)
                {
                    var entry = _history[_historyIndex];
                    entry.SnapshotFilters = Filters != null ? Filters.Clone() : new InvestigationWorkspaceFilters();
                    entry.SnapshotHostScopeMode = string.IsNullOrWhiteSpace(HostScopeMode)
                        ? InvestigationWorkspaceHostScopeMode.AllHosts
                        : HostScopeMode;
                }
                return;
            }

            if (_historyIndex < _history.Count - 1)
                _history.RemoveRange(_historyIndex + 1, _history.Count - (_historyIndex + 1));

            _history.Add(new InvestigationWorkspaceSeed
            {
                SeedType = normalizedType,
                SeedValue = normalizedValue,
                SeedDisplay = display,
                AtUtc = DateTime.UtcNow,
                SnapshotFilters = Filters != null ? Filters.Clone() : new InvestigationWorkspaceFilters(),
                SnapshotHostScopeMode = string.IsNullOrWhiteSpace(HostScopeMode)
                    ? InvestigationWorkspaceHostScopeMode.AllHosts
                    : HostScopeMode
            });
            _historyIndex = _history.Count - 1;
        }

        public InvestigationWorkspaceSeed GoBack()
        {
            if (!CanGoBack)
                return CurrentSeed;
            _historyIndex--;
            return CurrentSeed;
        }

        public InvestigationWorkspaceSeed GoForward()
        {
            if (!CanGoForward)
                return CurrentSeed;
            _historyIndex++;
            return CurrentSeed;
        }

        public InvestigationWorkspaceSeed ResetToOriginalSeed()
        {
            if (_history.Count == 0)
                return null;
            _historyIndex = 0;
            return CurrentSeed;
        }

        public void ClearSelectedEdge()
        {
            SetSelectedEdge(null);
        }

        public void SetSelectedEdge(InvestigationGraphEdge edge)
        {
            if (edge == null)
            {
                SelectedEdgeType = "";
                SelectedEdgeValue = "";
                SelectedEdgeDisplay = "";
                SelectedEdgeHosts = new List<string>();
                return;
            }

            SelectedEdgeType = edge.RelatedType ?? "";
            SelectedEdgeValue = edge.NormalizedValue ?? "";
            SelectedEdgeDisplay = !string.IsNullOrWhiteSpace(edge.DisplayValue) ? edge.DisplayValue : (edge.NormalizedValue ?? "");
            SelectedEdgeHosts = edge.Hosts != null
                ? edge.Hosts.Where(v => !string.IsNullOrWhiteSpace(v)).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(v => v, StringComparer.OrdinalIgnoreCase).ToList()
                : new List<string>();
        }

        public void PinCurrentSeed()
        {
            var seed = CurrentSeed;
            if (seed == null)
                return;
            Pin(seed.SeedType, seed.SeedDisplay);
        }

        public void PinSelectedEdge()
        {
            if (string.IsNullOrWhiteSpace(SelectedEdgeType) || string.IsNullOrWhiteSpace(SelectedEdgeDisplay))
                return;
            Pin(SelectedEdgeType, SelectedEdgeDisplay);
        }

        private void Pin(string type, string value)
        {
            var pin = (type ?? "Entity") + ": " + (value ?? "");
            if (PinnedEntities.Any(v => string.Equals(v, pin, StringComparison.OrdinalIgnoreCase)))
                return;
            PinnedEntities.Add(pin);
        }

        public string BuildTrailText(int maxItems)
        {
            if (_history.Count == 0)
                return "Trail: (empty)";

            if (maxItems <= 0) maxItems = 6;
            var trail = _history.Select(s => (s.SeedType ?? "Entity") + "=" + (s.SeedDisplay ?? s.SeedValue ?? "")).ToList();
            if (trail.Count > maxItems)
                trail = trail.Skip(trail.Count - maxItems).ToList();
            return "Trail: " + string.Join(" -> ", trail.ToArray());
        }
    }
}
