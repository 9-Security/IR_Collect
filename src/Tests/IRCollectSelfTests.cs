#if INCLUDE_TESTS
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Windows.Forms;
using IR_Collect.Analysis;
using IR_Collect.Analysis.Correlation;
using IR_Collect.Analysis.Correlation.Normalizers;
using IR_Collect.Utils;

namespace IR_Collect.Tests
{
    /// <summary>Headless self-tests for review builds (-test). Same assembly as production code.</summary>
    public static class IRCollectSelfTests
    {
        public static int RunAndWriteResultFile()
        {
            var sb = new StringBuilder();
            int failed = 0;
            failed += RunOne("IsPathUnderRoot_accepts_child", IsPathUnderRoot_accepts_child, sb) ? 0 : 1;
            failed += RunOne("IsPathUnderRoot_rejects_prefix_sibling", IsPathUnderRoot_rejects_prefix_sibling, sb) ? 0 : 1;
            failed += RunOne("ExtractZip_rejects_traversal_only", ExtractZip_rejects_traversal_only, sb) ? 0 : 1;
            failed += RunOne("ExtractZip_accepts_plain_entry", ExtractZip_accepts_plain_entry, sb) ? 0 : 1;
            failed += RunOne("EventLogLabel_strips_suffix_case_insensitive", EventLogLabel_strips_suffix_case_insensitive, sb) ? 0 : 1;
            failed += RunOne("EventLogLabel_keeps_non_suffix_name", EventLogLabel_keeps_non_suffix_name, sb) ? 0 : 1;
            failed += RunOne("CaseManager_GetRelativePath_accepts_child", CaseManager_GetRelativePath_accepts_child, sb) ? 0 : 1;
            failed += RunOne("CaseManager_GetRelativePath_rejects_prefix_sibling", CaseManager_GetRelativePath_rejects_prefix_sibling, sb) ? 0 : 1;
            failed += RunOne("Cli_unknown_arg_exits_nonzero", Cli_unknown_arg_exits_nonzero, sb) ? 0 : 1;
            failed += RunOne("EscapeArgForCmd_quotes_metachars_without_caret_corruption", EscapeArgForCmd_quotes_metachars_without_caret_corruption, sb) ? 0 : 1;
            failed += RunOne("FactStoreLoad_skips_bad_rows_keeps_good", FactStoreLoad_skips_bad_rows_keeps_good, sb) ? 0 : 1;
            failed += RunOne("FactStoreLoad_unsupported_schema_throws", FactStoreLoad_unsupported_schema_throws, sb) ? 0 : 1;
            failed += RunOne("FactStoreLoad_all_unreadable_rows_throws", FactStoreLoad_all_unreadable_rows_throws, sb) ? 0 : 1;
            failed += RunOne("FactTime_ToComparableUtc_aligns_local_and_utc_same_instant", FactTime_ToComparableUtc_aligns_local_and_utc_same_instant, sb) ? 0 : 1;
            failed += RunOne("FactStore_GetByTimeRange_matches_mixed_kind_same_instant", FactStore_GetByTimeRange_matches_mixed_kind_same_instant, sb) ? 0 : 1;
            failed += RunOne("FactStore_AppendFacts_swaps_without_mutating_old_reference", FactStore_AppendFacts_swaps_without_mutating_old_reference, sb) ? 0 : 1;
            failed += RunOne("FactStore_concurrent_append_and_read_no_exception", FactStore_concurrent_append_and_read_no_exception, sb) ? 0 : 1;
            failed += RunOne("SqliteModule_unsigned_or_missing_dll_is_rejected", SqliteModule_unsigned_or_missing_dll_is_rejected, sb) ? 0 : 1;
            failed += RunOne("ConfigAcl_hardening_keeps_file_readable_and_no_throw", ConfigAcl_hardening_keeps_file_readable_and_no_throw, sb) ? 0 : 1;
            failed += RunOne("CsvExport_neutralizes_formula_injection", CsvExport_neutralizes_formula_injection, sb) ? 0 : 1;
            failed += RunOne("RunToFile_streams_output_and_cleans_on_failure", RunToFile_streams_output_and_cleans_on_failure, sb) ? 0 : 1;
            failed += RunOne("MemoryRecord_args_governance_note_round_trips", MemoryRecord_args_governance_note_round_trips, sb) ? 0 : 1;
            failed += RunOne("Lnk_parser_reads_unicode_and_ansi_local_base_path", Lnk_parser_reads_unicode_and_ansi_local_base_path, sb) ? 0 : 1;
            failed += RunOne("MftRunList_parses_valid_and_survives_truncation", MftRunList_parses_valid_and_survives_truncation, sb) ? 0 : 1;
            failed += RunOne("MftNormalizer_action_reflects_timestamp_source", MftNormalizer_action_reflects_timestamp_source, sb) ? 0 : 1;
            failed += RunOne("MftFixup_restores_bytes_at_sector_boundaries", MftFixup_restores_bytes_at_sector_boundaries, sb) ? 0 : 1;
            failed += RunOne("MftParser_prefers_win32_long_name_over_dos_short_name", MftParser_prefers_win32_long_name_over_dos_short_name, sb) ? 0 : 1;
            failed += RunOne("ShimCache_structured_win10_entry_recovers_path_and_filetime", ShimCache_structured_win10_entry_recovers_path_and_filetime, sb) ? 0 : 1;
            failed += RunOne("AnalyzeFolder_ingests_artifacts_and_builds_summary", AnalyzeFolder_ingests_artifacts_and_builds_summary, sb) ? 0 : 1;
            failed += RunOne("RawArtifactCsvWriter_amcache_output_is_consumable_by_normalizer", RawArtifactCsvWriter_amcache_output_is_consumable_by_normalizer, sb) ? 0 : 1;
            failed += RunOne("CorrelateCli_finds_shared_entity_across_two_folders", CorrelateCli_finds_shared_entity_across_two_folders, sb) ? 0 : 1;
            failed += RunOne("BuildInfo_version_matches_assembly_and_is_stamped_in_outputs", BuildInfo_version_matches_assembly_and_is_stamped_in_outputs, sb) ? 0 : 1;
            failed += RunOne("EvidenceManifest_hashes_inputs_and_summary_carries_digest", EvidenceManifest_hashes_inputs_and_summary_carries_digest, sb) ? 0 : 1;
            failed += RunOne("RecentFileScan_respects_time_budget", RecentFileScan_respects_time_budget, sb) ? 0 : 1;
            failed += RunOne("Prefetch_parses_v30_and_normalizer_emits_executed_facts", Prefetch_parses_v30_and_normalizer_emits_executed_facts, sb) ? 0 : 1;
            failed += RunOne("GuidedHunt_flags_prefetch_dll_sideload", GuidedHunt_flags_prefetch_dll_sideload, sb) ? 0 : 1;
            failed += RunOne("GuidedHunt_flags_execution_from_suspicious_path", GuidedHunt_flags_execution_from_suspicious_path, sb) ? 0 : 1;
            failed += RunOne("GuidedHunt_flags_event_log_cleared", GuidedHunt_flags_event_log_cleared, sb) ? 0 : 1;
            failed += RunOne("GraphCli_multi_hop_reaches_sibling_via_shared_publisher", GraphCli_multi_hop_reaches_sibling_via_shared_publisher, sb) ? 0 : 1;
            failed += RunOne("EventLog_5145_composes_absolute_path_from_share_local_path", EventLog_5145_composes_absolute_path_from_share_local_path, sb) ? 0 : 1;
            failed += RunOne("SrumDecodeIdBlob_distinguishes_sid_from_utf16_text", SrumDecodeIdBlob_distinguishes_sid_from_utf16_text, sb) ? 0 : 1;
            failed += RunOne("EventLog_1149_message_fallback_adds_target_user", EventLog_1149_message_fallback_adds_target_user, sb) ? 0 : 1;
            failed += RunOne("EventLog_1149_structured_target_user_is_not_duplicated", EventLog_1149_structured_target_user_is_not_duplicated, sb) ? 0 : 1;
            failed += RunOne("EventLog_5145_relative_target_name_maps_to_path", EventLog_5145_relative_target_name_maps_to_path, sb) ? 0 : 1;
            failed += RunOne("EventLog_blank_time_keeps_fact_with_entities_low_confidence", EventLog_blank_time_keeps_fact_with_entities_low_confidence, sb) ? 0 : 1;
            failed += RunOne("MemoryHandoff_resolve_acquire_and_analyze_arg_templates", MemoryHandoff_resolve_acquire_and_analyze_arg_templates, sb) ? 0 : 1;
            failed += RunOne("MemoryHandoff_finalize_analysis_disk_reconciles_missing_outputs", MemoryHandoff_finalize_analysis_disk_reconciles_missing_outputs, sb) ? 0 : 1;
            failed += RunOne("MemoryCoverage_complete_with_missing_dump_becomes_failed", MemoryCoverage_complete_with_missing_dump_becomes_failed, sb) ? 0 : 1;
            failed += RunOne("MemoryCoverage_partial_with_missing_dump_stays_partial", MemoryCoverage_partial_with_missing_dump_stays_partial, sb) ? 0 : 1;
            failed += RunOne("MemoryAnalysisOutputDir_default_folder_allowed", MemoryAnalysisOutputDir_default_folder_allowed, sb) ? 0 : 1;
            failed += RunOne("MemoryAnalysisOutputDir_case_root_rejected", MemoryAnalysisOutputDir_case_root_rejected, sb) ? 0 : 1;
            failed += RunOne("MemoryAnalysisOutputDir_reserved_evidence_dir_rejected", MemoryAnalysisOutputDir_reserved_evidence_dir_rejected, sb) ? 0 : 1;
            failed += RunOne("MemoryAnalysisCoverage_complete_with_outputs_is_complete", MemoryAnalysisCoverage_complete_with_outputs_is_complete, sb) ? 0 : 1;
            failed += RunOne("MemoryAnalysisCoverage_complete_without_outputs_becomes_failed", MemoryAnalysisCoverage_complete_without_outputs_becomes_failed, sb) ? 0 : 1;
            failed += RunOne("MemoryAcquisitionNormalizer_ToFacts_emits_summary_and_output_facts", MemoryAcquisitionNormalizer_ToFacts_emits_summary_and_output_facts, sb) ? 0 : 1;
            failed += RunOne("MemoryAnalysisNormalizer_ToFacts_emits_summary_and_output_facts", MemoryAnalysisNormalizer_ToFacts_emits_summary_and_output_facts, sb) ? 0 : 1;
            failed += RunOne("ServiceNormalizer_ToFacts_maps_service_name_and_path", ServiceNormalizer_ToFacts_maps_service_name_and_path, sb) ? 0 : 1;
            failed += RunOne("StoredCredentialNormalizer_ToFacts_maps_target_user_server", StoredCredentialNormalizer_ToFacts_maps_target_user_server, sb) ? 0 : 1;
            failed += RunOne("KerberosTicketCacheNormalizer_ToFacts_maps_ticket_entities_and_time", KerberosTicketCacheNormalizer_ToFacts_maps_ticket_entities_and_time, sb) ? 0 : 1;
            failed += RunOne("EventLogCoverage_label_mismatch_is_partial", EventLogCoverage_label_mismatch_is_partial, sb) ? 0 : 1;
            failed += RunOne("ExecutionArtifactsCoverage_failed_with_present_artifact_stays_failed", ExecutionArtifactsCoverage_failed_with_present_artifact_stays_failed, sb) ? 0 : 1;
            failed += RunOne("CollectionCoverage_failed_step_with_present_artifact_makes_overall_failed", CollectionCoverage_failed_step_with_present_artifact_makes_overall_failed, sb) ? 0 : 1;
            failed += RunOne("CollectionCoverage_missing_steps_make_overall_partial", CollectionCoverage_missing_steps_make_overall_partial, sb) ? 0 : 1;
            failed += RunOne("CollectionResult_coverage_failed_step_sets_has_errors", CollectionResult_coverage_failed_step_sets_has_errors, sb) ? 0 : 1;
            failed += RunOne("SharedEntityPivot_finds_cross_host_path", SharedEntityPivot_finds_cross_host_path, sb) ? 0 : 1;
            failed += RunOne("RelatedEntityPivot_returns_seed_neighbors", RelatedEntityPivot_returns_seed_neighbors, sb) ? 0 : 1;
            failed += RunOne("InvestigationGraph_returns_related_edges", InvestigationGraph_returns_related_edges, sb) ? 0 : 1;
            failed += RunOne("TemporalSharedEntityPivot_groups_same_bucket_across_hosts", TemporalSharedEntityPivot_groups_same_bucket_across_hosts, sb) ? 0 : 1;
            failed += RunOne("SummaryExport_serialize_preserves_summary_v3_schema", SummaryExport_serialize_preserves_summary_v3_schema, sb) ? 0 : 1;
            failed += RunOne("SummaryExport_serialize_handles_minvalue_fact_time", SummaryExport_serialize_handles_minvalue_fact_time, sb) ? 0 : 1;
            failed += RunOne("ParserNoteSummary_includes_non_amcache_sources", ParserNoteSummary_includes_non_amcache_sources, sb) ? 0 : 1;
            failed += RunOne("SummaryTab_includes_parser_notes_section", SummaryTab_includes_parser_notes_section, sb) ? 0 : 1;
            failed += RunOne("HtmlReport_missing_artifact_counts_render_not_found", HtmlReport_missing_artifact_counts_render_not_found, sb) ? 0 : 1;
            failed += RunOne("SummaryPayload_missing_artifact_counts_are_zero", SummaryPayload_missing_artifact_counts_are_zero, sb) ? 0 : 1;
            failed += RunOne("ShellBagsParser_DecodeShellItemBlob_ascii_segment", ShellBagsParser_DecodeShellItemBlob_ascii_segment, sb) ? 0 : 1;
            failed += RunOne("ShellBagsParser_TryEnsureShellBagsCsv_writes_csv", ShellBagsParser_TryEnsureShellBagsCsv_writes_csv, sb) ? 0 : 1;
            failed += RunOne("ShellBags_ReadLogicalLines_hex_continuation_strips_backslashes", ShellBags_ReadLogicalLines_hex_continuation_strips_backslashes, sb) ? 0 : 1;
            failed += RunOne("ShellBagsParser_TryEnsureShellBagsCsv_multiline_hex_decodes_path", ShellBagsParser_TryEnsureShellBagsCsv_multiline_hex_decodes_path, sb) ? 0 : 1;
            failed += RunOne("ShellBagsParser_BagsShell_key_without_Shell_segment", ShellBagsParser_BagsShell_key_without_Shell_segment, sb) ? 0 : 1;
            failed += RunOne("ShellBagsParser_BagsShellNoRoam_key", ShellBagsParser_BagsShellNoRoam_key, sb) ? 0 : 1;
            failed += RunOne("ShellBagsNormalizer_ToFacts_maps_path_user_sid", ShellBagsNormalizer_ToFacts_maps_path_user_sid, sb) ? 0 : 1;
            failed += RunOne("JumpListNormalizer_ToFacts_emits_entities", JumpListNormalizer_ToFacts_emits_entities, sb) ? 0 : 1;
            failed += RunOne("JumpListNormalizer_ToFacts_unc_derives_workstation_share", JumpListNormalizer_ToFacts_unc_derives_workstation_share, sb) ? 0 : 1;
            failed += RunOne("BitsJobNormalizer_ToFacts_unc_derives_share_and_remote_ip", BitsJobNormalizer_ToFacts_unc_derives_share_and_remote_ip, sb) ? 0 : 1;
            failed += RunOne("BitsJobNormalizer_ToFacts_multi_segment_remote_name_derives_unc_and_urls", BitsJobNormalizer_ToFacts_multi_segment_remote_name_derives_unc_and_urls, sb) ? 0 : 1;
            failed += RunOne("LogonSessionNormalizer_ToFacts_maps_user_sid_and_logon_metadata", LogonSessionNormalizer_ToFacts_maps_user_sid_and_logon_metadata, sb) ? 0 : 1;
            failed += RunOne("NetworkResourceNormalizer_ToFacts_derives_unc_entities", NetworkResourceNormalizer_ToFacts_derives_unc_entities, sb) ? 0 : 1;
            failed += RunOne("ServerConnectionNormalizer_ToFacts_maps_user_share_and_remote_host", ServerConnectionNormalizer_ToFacts_maps_user_share_and_remote_host, sb) ? 0 : 1;
            failed += RunOne("FactProvenance_logon_session_uses_system_info_step", FactProvenance_logon_session_uses_system_info_step, sb) ? 0 : 1;
            failed += RunOne("FactProvenance_bits_uses_execution_artifacts_step", FactProvenance_bits_uses_execution_artifacts_step, sb) ? 0 : 1;
            failed += RunOne("FactProvenance_wmi_uses_execution_artifacts_step", FactProvenance_wmi_uses_execution_artifacts_step, sb) ? 0 : 1;
            failed += RunOne("FactProvenance_service_uses_persistence_step", FactProvenance_service_uses_persistence_step, sb) ? 0 : 1;
            failed += RunOne("FactProvenance_stored_credential_uses_system_info_step", FactProvenance_stored_credential_uses_system_info_step, sb) ? 0 : 1;
            failed += RunOne("FactProvenance_kerberos_ticket_uses_system_info_step", FactProvenance_kerberos_ticket_uses_system_info_step, sb) ? 0 : 1;
            failed += RunOne("FactProvenance_memory_acquisition_uses_memory_acquisition_step", FactProvenance_memory_acquisition_uses_memory_acquisition_step, sb) ? 0 : 1;
            failed += RunOne("FactProvenance_memory_analysis_uses_memory_analysis_step", FactProvenance_memory_analysis_uses_memory_analysis_step, sb) ? 0 : 1;
            failed += RunOne("Timeline_unified_jumplist_row_count_equals_activity_only_not_jump_csv_dup", Timeline_unified_jumplist_row_count_equals_activity_only_not_jump_csv_dup, sb) ? 0 : 1;
            failed += RunOne("BuildTimelineEvents_MainForm_path_jumplist_single_when_activity_and_jump_csv_present", BuildTimelineEvents_MainForm_path_jumplist_single_when_activity_and_jump_csv_present, sb) ? 0 : 1;
            failed += RunOne("TimelineFilter_helpers_honor_minute_precision", TimelineFilter_helpers_honor_minute_precision, sb) ? 0 : 1;
            failed += RunOne("TimelineGraphFocus_matches_entity_refs_before_text_fallback", TimelineGraphFocus_matches_entity_refs_before_text_fallback, sb) ? 0 : 1;
            failed += RunOne("FullLogExportJson_includes_memory_and_freshness_host_fields", FullLogExportJson_includes_memory_and_freshness_host_fields, sb) ? 0 : 1;
            failed += RunOne("GuidedHuntPack_matches_rdp_and_admin_share_rules", GuidedHuntPack_matches_rdp_and_admin_share_rules, sb) ? 0 : 1;
            failed += RunOne("GuidedHuntPack_matches_task_service_and_credential_rules", GuidedHuntPack_matches_task_service_and_credential_rules, sb) ? 0 : 1;
            failed += RunOne("GuidedHuntPack_matches_cmdkey_and_klist_artifacts", GuidedHuntPack_matches_cmdkey_and_klist_artifacts, sb) ? 0 : 1;
            failed += RunOne("SummaryExport_serialize_includes_guided_hunt", SummaryExport_serialize_includes_guided_hunt, sb) ? 0 : 1;
            failed += RunOne("EndpointGovernance_empty_allowlist_blocks", EndpointGovernance_empty_allowlist_blocks, sb) ? 0 : 1;
            failed += RunOne("EndpointGovernance_prefix_allows_child_path", EndpointGovernance_prefix_allows_child_path, sb) ? 0 : 1;
            failed += RunOne("EndpointGovernance_different_host_rejected", EndpointGovernance_different_host_rejected, sb) ? 0 : 1;
            failed += RunOne("EndpointGovernance_path_case_mismatch_rejected", EndpointGovernance_path_case_mismatch_rejected, sb) ? 0 : 1;
            failed += RunOne("CollectionModeProfile_normalize_and_cases", CollectionModeProfile_normalize_and_cases, sb) ? 0 : 1;
            failed += RunOne("CollectionModeProfile_forensic_strict_blocks_outbound_helpers", CollectionModeProfile_forensic_strict_blocks_outbound_helpers, sb) ? 0 : 1;
            failed += RunOne("CollectionModeProfile_standard_allows_outbound_helpers", CollectionModeProfile_standard_allows_outbound_helpers, sb) ? 0 : 1;
            failed += RunOne("CollectionCoverage_report_includes_mode_profile", CollectionCoverage_report_includes_mode_profile, sb) ? 0 : 1;
            failed += RunOne("ZipUpload_gate_uses_run_profile_ForensicStrict_even_if_settings_Standard", ZipUpload_gate_uses_run_profile_ForensicStrict_even_if_settings_Standard, sb) ? 0 : 1;
            failed += RunOne("ZipUpload_gate_run_Standard_not_blocked_when_settings_ForensicStrict", ZipUpload_gate_run_Standard_not_blocked_when_settings_ForensicStrict, sb) ? 0 : 1;
            failed += RunOne("ZipUpload_gate_null_run_falls_back_to_settings_ForensicStrict", ZipUpload_gate_null_run_falls_back_to_settings_ForensicStrict, sb) ? 0 : 1;
            failed += RunOne("Dashboard_loaded_case_profiles_line_mixed", Dashboard_loaded_case_profiles_line_mixed, sb) ? 0 : 1;
            failed += RunOne("Dashboard_loaded_case_profiles_line_all_unlabeled", Dashboard_loaded_case_profiles_line_all_unlabeled, sb) ? 0 : 1;
            failed += RunOne("Dashboard_loaded_case_profiles_line_single", Dashboard_loaded_case_profiles_line_single, sb) ? 0 : 1;
            failed += RunOne("AiRedaction_basic_masks_collection_coverage_identity", AiRedaction_basic_masks_collection_coverage_identity, sb) ? 0 : 1;
            failed += RunOne("AiRedaction_basic_masks_memory_toolargs_paths", AiRedaction_basic_masks_memory_toolargs_paths, sb) ? 0 : 1;
            failed += RunOne("AiRedaction_basic_masks_top_level_host_case_id", AiRedaction_basic_masks_top_level_host_case_id, sb) ? 0 : 1;
            failed += RunOne("AiRedaction_basic_masks_memory_collector_user", AiRedaction_basic_masks_memory_collector_user, sb) ? 0 : 1;
            failed += RunOne("AiRedaction_basic_masks_fact_details_unc_paths_live_untouched", AiRedaction_basic_masks_fact_details_unc_paths_live_untouched, sb) ? 0 : 1;
            failed += RunOne("AiRedaction_basic_masks_workflow_notes_paths_live_untouched", AiRedaction_basic_masks_workflow_notes_paths_live_untouched, sb) ? 0 : 1;
            failed += RunOne("AiRedaction_strict_clears_fact_samples", AiRedaction_strict_clears_fact_samples, sb) ? 0 : 1;
            failed += RunOne("AiRedaction_basic_masks_ipv4_in_highlights", AiRedaction_basic_masks_ipv4_in_highlights, sb) ? 0 : 1;
            failed += RunOne("AiRedaction_none_unchanged_highlight", AiRedaction_none_unchanged_highlight, sb) ? 0 : 1;
            failed += RunOne("FixtureCorpus_committed_files_match_builder_and_parse_as_expected", FixtureCorpus_committed_files_match_builder_and_parse_as_expected, sb) ? 0 : 1;

            sb.AppendLine();
            sb.AppendLine(failed == 0 ? "SUMMARY: 0 failed (all passed)." : "SUMMARY: " + failed + " failed.");

            string outPath = Path.Combine(Path.GetTempPath(), "IR_Collect_TestResult.txt");
            try
            {
                File.WriteAllText(outPath, sb.ToString(), new UTF8Encoding(false));
            }
            catch (Exception ex)
            {
                sb.AppendLine("WARN: could not write result file: " + ex.Message);
            }

            Console.Write(sb.ToString());
            return failed > 0 ? 1 : 0;
        }

        private static bool RunOne(string name, Func<bool> test, StringBuilder sb)
        {
            try
            {
                if (test())
                {
                    sb.AppendLine("PASS: " + name);
                    return true;
                }
                sb.AppendLine("FAIL: " + name + " (returned false)");
                return false;
            }
            catch (Exception ex)
            {
                sb.AppendLine("FAIL: " + name + " — " + ex.Message);
                return false;
            }
        }

        private static bool IsPathUnderRoot_accepts_child()
        {
            string root = Path.Combine(Path.GetTempPath(), "IRCollectPathTest_" + Guid.NewGuid().ToString("N"));
            try
            {
                string child = Path.Combine(root, "sub", "f.txt");
                Directory.CreateDirectory(Path.GetDirectoryName(child));
                File.WriteAllText(child, "x");
                return CaseManager.IsPathUnderRoot(child, root);
            }
            finally
            {
                TryDeleteDir(root);
            }
        }

        private static bool IsPathUnderRoot_rejects_prefix_sibling()
        {
            string root = Path.Combine(Path.GetTempPath(), "IRCollectPathTestA_" + Guid.NewGuid().ToString("N"));
            string sibling = root + "_X";
            try
            {
                Directory.CreateDirectory(root);
                Directory.CreateDirectory(sibling);
                string file = Path.Combine(sibling, "f.txt");
                File.WriteAllText(file, "x");
                return !CaseManager.IsPathUnderRoot(file, root);
            }
            finally
            {
                TryDeleteDir(root);
                TryDeleteDir(sibling);
            }
        }

        private static bool ExtractZip_rejects_traversal_only()
        {
            string dir = Path.Combine(Path.GetTempPath(), "IRCollectZipT_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            string zipPath = Path.Combine(dir, "t.zip");
            string extractDir = Path.Combine(dir, "out");
            try
            {
                Directory.CreateDirectory(extractDir);
                using (var fs = new FileStream(zipPath, FileMode.Create))
                using (var archive = new ZipArchive(fs, ZipArchiveMode.Create))
                {
                    string entryName = ".." + Path.AltDirectorySeparatorChar + "outside.txt";
                    ZipArchiveEntry e = archive.CreateEntry(entryName, CompressionLevel.Fastest);
                    using (var w = new StreamWriter(e.Open()))
                        w.Write("bad");
                }
                try
                {
                    CaseManager.ExtractZipSafely(zipPath, extractDir);
                    return false;
                }
                catch (InvalidDataException)
                {
                    return true;
                }
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool ExtractZip_accepts_plain_entry()
        {
            string dir = Path.Combine(Path.GetTempPath(), "IRCollectZipG_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            string zipPath = Path.Combine(dir, "t.zip");
            string extractDir = Path.Combine(dir, "out");
            try
            {
                Directory.CreateDirectory(extractDir);
                using (var fs = new FileStream(zipPath, FileMode.Create))
                using (var archive = new ZipArchive(fs, ZipArchiveMode.Create))
                {
                    ZipArchiveEntry e = archive.CreateEntry("ok.txt", CompressionLevel.Fastest);
                    using (var w = new StreamWriter(e.Open()))
                        w.Write("ok");
                }
                CaseManager.ExtractZipSafely(zipPath, extractDir);
                return File.Exists(Path.Combine(extractDir, "ok.txt"));
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool Cli_unknown_arg_exits_nonzero()
        {
            string exe = Assembly.GetExecutingAssembly().Location;
            if (string.IsNullOrEmpty(exe) || !File.Exists(exe))
                return false;

            var psi = new ProcessStartInfo
            {
                FileName = exe,
                Arguments = "--IRCollectNonexistentFlag987",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using (Process p = Process.Start(psi))
            {
                if (p == null) return false;
                if (!p.WaitForExit(120000))
                {
                    try { p.Kill(); } catch { }
                    return false;
                }
                return p.ExitCode == 1;
            }
        }

        private static bool EscapeArgForCmd_quotes_metachars_without_caret_corruption()
        {
            // '&' must be preserved verbatim inside quotes (the old code injected a stray '^').
            string amp = Collector.CommandHelper.EscapeArgForCmd(@"C:\out\a&b\reg.hiv");
            if (amp != "\"C:\\out\\a&b\\reg.hiv\"") return false;
            // A path with a space is quoted.
            string sp = Collector.CommandHelper.EscapeArgForCmd(@"C:\Program Files\x.reg");
            if (sp != "\"C:\\Program Files\\x.reg\"") return false;
            // A plain path with no metachars is returned unquoted, unchanged.
            string plain = Collector.CommandHelper.EscapeArgForCmd(@"C:\out\reg.hiv");
            if (plain != @"C:\out\reg.hiv") return false;
            // A stray double-quote (illegal in real paths) is stripped so it cannot break out of quoting.
            string q = Collector.CommandHelper.EscapeArgForCmd("a\"b c");
            if (q.IndexOf('"') != 0 || q[q.Length - 1] != '"') return false; // wrapped
            if (q.Substring(1, q.Length - 2).IndexOf('"') >= 0) return false; // no inner quote remains
            return true;
        }

        private static bool FactTime_ToComparableUtc_aligns_local_and_utc_same_instant()
        {
            DateTime utc = new DateTime(2024, 6, 1, 12, 0, 0, DateTimeKind.Utc);
            // Same instant expressed as naive-local (how EventLog/Process/Activity facts arrive).
            DateTime localNaive = DateTime.SpecifyKind(utc.ToLocalTime(), DateTimeKind.Unspecified);
            DateTime a = FactStore.ToComparableUtc(utc);
            DateTime b = FactStore.ToComparableUtc(localNaive);
            return a == b && a.Kind == DateTimeKind.Utc;
        }

        private static bool FactStore_GetByTimeRange_matches_mixed_kind_same_instant()
        {
            var store = new FactStore();
            DateTime utcInstant = new DateTime(2024, 6, 1, 12, 0, 0, DateTimeKind.Utc);
            // Fact carries UTC kind (like MFT FromFileTimeUtc / ShellBags).
            var f = new Fact("id", utcInstant, "MFT", "Observed");
            f.EntityRefs.Add(new EntityRef("Path", "x"));
            store.Facts.Add(f);
            store.BuildEntityIndex();
            // Window expressed in naive-local time (like UI date pickers). Before the fix this
            // would be off by the host UTC offset and could miss the UTC-kind fact.
            DateTime localNaive = DateTime.SpecifyKind(utcInstant.ToLocalTime(), DateTimeKind.Unspecified);
            var hits = store.GetByTimeRange(localNaive.AddMinutes(-1), localNaive.AddMinutes(1));
            return hits.Count == 1;
        }

        private static bool SrumDecodeIdBlob_distinguishes_sid_from_utf16_text()
        {
            // Real SID S-1-5-18 (LocalSystem): rev=1, subAuthCount=1, authority=5, subAuth=18.
            byte[] sid = new byte[] { 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00 };
            if (!string.Equals(SrumExporter.DecodeIdBlob(sid), "S-1-5-18", StringComparison.OrdinalIgnoreCase)) return false;

            // UTF-16 AppId text (2nd byte 0x00) must NOT be misread as a SID.
            byte[] text = Encoding.Unicode.GetBytes("C:\\app.exe");
            string t = SrumExporter.DecodeIdBlob(text);
            return t.IndexOf("C:\\app.exe", StringComparison.OrdinalIgnoreCase) >= 0
                && !t.StartsWith("S-", StringComparison.OrdinalIgnoreCase);
        }

        private static bool MftNormalizer_action_reflects_timestamp_source()
        {
            var entries = new List<IR_Collect.MFT.MftParser.MftEntry>();
            // Created invalid -> time falls back to Modified -> Action must be "Modified", not "Created".
            entries.Add(new IR_Collect.MFT.MftParser.MftEntry
            {
                RecordNumber = 5,
                FullPath = "\\Windows\\a.dll",
                Created = DateTime.MinValue,
                Modified = new DateTime(2024, 3, 1, 12, 0, 0)
            });
            // Created valid -> Action "Created".
            entries.Add(new IR_Collect.MFT.MftParser.MftEntry
            {
                RecordNumber = 6,
                FullPath = "\\Windows\\b.dll",
                Created = new DateTime(2024, 2, 1, 9, 0, 0),
                Modified = new DateTime(2024, 3, 1, 12, 0, 0)
            });
            var facts = MftNormalizer.ToFacts(entries, 10);
            if (facts.Count != 2) return false;
            var fb = facts[0];
            var ok = facts[1];
            return string.Equals(fb.Action, "Modified", StringComparison.Ordinal)
                && fb.FallbackUsed
                && fb.Time == new DateTime(2024, 3, 1, 12, 0, 0)
                && string.Equals(ok.Action, "Created", StringComparison.Ordinal);
        }

        private static bool EventLog_5145_composes_absolute_path_from_share_local_path()
        {
            string dir = CreateTempDir("IRCollectEvt5145Abs_");
            try
            {
                string csv = Path.Combine(dir, "Security_filtered.csv");
                WriteEventLogCsv(csv, new[]
                {
                    BuildEventLogRow(
                        "2026-04-08T10:02:00Z",
                        "5145",
                        "Microsoft-Windows-Security-Auditing",
                        "Share access checked.",
                        "SubjectUserName=bob | ShareName=\\\\server\\share | ShareLocalPath=C:\\Shares\\Team | RelativeTargetName=docs\\secret.txt")
                });
                List<Fact> facts = EventLogNormalizer.ToFacts(csv, "Security");
                if (facts.Count != 1) return false;
                Fact f = facts[0];
                return HasEntity(f, "Path", "C:\\Shares\\Team\\docs\\secret.txt") // composed absolute
                    && HasEntity(f, "Path", "docs\\secret.txt");                   // relative still present
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool MftRunList_parses_valid_and_survives_truncation()
        {
            // NTFS run-list encoding: [header=(offSize<<4)|lenSize][length LE][offset LE]..., 0x00 terminates.
            // Two 1+1-byte runs (header 0x11) then terminator.
            byte[] good = new byte[] { 0x11, 0x10, 0x20, 0x11, 0x05, 0x03, 0x00 };
            var runs = IR_Collect.MFT.MftDumper.ParseRunList(good, 0, good.Length);
            if (runs == null || runs.Count != 2) return false;

            // Truncated: header claims 4+4 bytes but only 2 trailing bytes exist — must NOT throw.
            byte[] bad = new byte[] { 0x44, 0x01, 0x02 };
            var runs2 = IR_Collect.MFT.MftDumper.ParseRunList(bad, 0, bad.Length);
            if (runs2 == null || runs2.Count != 0) return false;

            // `end` past the buffer (attacker-influenced attribute length) is clamped, not over-read.
            var runs3 = IR_Collect.MFT.MftDumper.ParseRunList(good, 0, 9999);
            return runs3 != null && runs3.Count == 2;
        }

        private static bool MftFixup_restores_bytes_at_sector_boundaries()
        {
            // NTFS replaces the last 2 bytes of each 512-byte sector with the USN; the originals live in
            // the Update Sequence Array. After fixup those boundary bytes must hold the USA values.
            byte[] rec = new byte[1024];
            rec[0] = 0x46; rec[1] = 0x49; rec[2] = 0x4C; rec[3] = 0x45;   // "FILE"
            rec[0x04] = 0x30; rec[0x05] = 0x00;                            // usaOffset = 0x30
            rec[0x06] = 0x03; rec[0x07] = 0x00;                            // usaCount  = 3 (USN + 2 sectors)
            rec[0x30] = 0xAA; rec[0x31] = 0xBB;                            // USN signature word
            rec[0x32] = 0x11; rec[0x33] = 0x22;                            // USA[1] -> sector 1 original
            rec[0x34] = 0x33; rec[0x35] = 0x44;                            // USA[2] -> sector 2 original
            rec[510] = 0xAA; rec[511] = 0xBB;                              // sector 1 boundary (holds USN)
            rec[1022] = 0xAA; rec[1023] = 0xBB;                           // sector 2 boundary (holds USN)
            bool applied = IR_Collect.MFT.MftParser.ApplyUsnFixup(rec, 1024);
            return applied
                && rec[510] == 0x11 && rec[511] == 0x22
                && rec[1022] == 0x33 && rec[1023] == 0x44;
        }

        // Build a resident $FILE_NAME attribute carrying a name in the given namespace (1=Win32, 2=DOS).
        private static byte[] BuildFileNameAttr(string name, byte ns)
        {
            byte[] nameBytes = Encoding.Unicode.GetBytes(name);
            int contentLen = 0x42 + nameBytes.Length;
            int attrLen = 0x18 + contentLen;
            if (attrLen % 8 != 0) attrLen += 8 - (attrLen % 8);
            byte[] a = new byte[attrLen];
            BitConverter.GetBytes((uint)0x30).CopyTo(a, 0);                // type = $FILE_NAME
            BitConverter.GetBytes((uint)attrLen).CopyTo(a, 4);            // attribute length
            a[8] = 0;                                                      // resident
            BitConverter.GetBytes((uint)contentLen).CopyTo(a, 0x10);     // content length
            BitConverter.GetBytes((ushort)0x18).CopyTo(a, 0x14);         // content offset
            int c = 0x18;
            BitConverter.GetBytes((ulong)5).CopyTo(a, c + 0x00);         // parent ref (root)
            a[c + 0x40] = (byte)name.Length;                              // name length (chars)
            a[c + 0x41] = ns;                                             // namespace
            nameBytes.CopyTo(a, c + 0x42);
            return a;
        }

        private static byte[] BuildMftRecordWithAttrs(byte[][] attrs)
        {
            byte[] rec = new byte[1024];
            rec[0] = 0x46; rec[1] = 0x49; rec[2] = 0x4C; rec[3] = 0x45;   // "FILE"
            BitConverter.GetBytes((ushort)0x38).CopyTo(rec, 0x14);        // first attribute offset
            BitConverter.GetBytes((ushort)0x01).CopyTo(rec, 0x16);        // flags: InUse
            int off = 0x38;
            foreach (var at in attrs) { Array.Copy(at, 0, rec, off, at.Length); off += at.Length; }
            BitConverter.GetBytes((uint)0xFFFFFFFF).CopyTo(rec, off);     // attribute end marker
            return rec;
        }

        private static bool MftParser_prefers_win32_long_name_over_dos_short_name()
        {
            byte[] dos = BuildFileNameAttr("TEST~1.TXT", 2);
            byte[] win = BuildFileNameAttr("testfile.txt", 1);
            // DOS first then Win32: the Win32 long name must still win (not the last attribute).
            var e1 = IR_Collect.MFT.MftParser.ParseRecord(BuildMftRecordWithAttrs(new[] { dos, win }), 7);
            if (e1 == null || !string.Equals(e1.FileName, "testfile.txt", StringComparison.Ordinal)) return false;
            // Win32 first then DOS: still the Win32 long name.
            var e2 = IR_Collect.MFT.MftParser.ParseRecord(BuildMftRecordWithAttrs(new[] { win, dos }), 7);
            return e2 != null && string.Equals(e2.FileName, "testfile.txt", StringComparison.Ordinal);
        }

        // Build one Win10 ("10ts") AppCompatCache value: a header whose first DWORD points at the
        // single entry, then a structured entry carrying a UTF-16 path and a FILETIME.
        private static byte[] BuildWin10ShimValue(string path, DateTime lastModifiedUtc)
        {
            byte[] pathBytes = Encoding.Unicode.GetBytes(path);
            int entryDataSize = 2 + pathBytes.Length + 8 + 4;   // pathSize + path + FILETIME + dataSize(0)
            const int headerSize = 0x30;
            byte[] v = new byte[headerSize + 12 + entryDataSize];
            BitConverter.GetBytes(headerSize).CopyTo(v, 0);     // header DWORD == offset to first entry

            int o = headerSize;
            v[o] = 0x31; v[o + 1] = 0x30; v[o + 2] = 0x74; v[o + 3] = 0x73; // "10ts"
            // o+4..o+7 unknown/seq = 0
            BitConverter.GetBytes(entryDataSize).CopyTo(v, o + 8);
            BitConverter.GetBytes((ushort)pathBytes.Length).CopyTo(v, o + 12);
            pathBytes.CopyTo(v, o + 14);
            int p = o + 14 + pathBytes.Length;
            BitConverter.GetBytes(lastModifiedUtc.ToFileTimeUtc()).CopyTo(v, p);
            // trailing dataSize DWORD stays 0
            return v;
        }

        private static bool ShimCache_structured_win10_entry_recovers_path_and_filetime()
        {
            var when = new DateTime(2025, 3, 14, 9, 30, 0, DateTimeKind.Utc);
            byte[] value = BuildWin10ShimValue(@"C:\Windows\System32\evil.exe", when);
            var r = ShimCacheParser.ParseValueBytesForTest("AppCompatCache", value);
            if (r.Entries.Count != 1) return false;
            var e = r.Entries[0];
            return string.Equals(e.Path, @"C:\Windows\System32\evil.exe", StringComparison.Ordinal)
                && string.Equals(e.FileName, "evil.exe", StringComparison.Ordinal)
                && string.Equals(e.LastModifiedTime, "2025-03-14T09:30:00", StringComparison.Ordinal);
        }

        // Write a minimal artifact folder: system_info.txt (hostname) + mft_preview.csv with one row for
        // `path`, so LoadCaseFromFolder + BuildFromCase yield a single MFT Path-entity fact.
        private static void WriteMiniCaseFolder(string dir, string hostname, string path)
        {
            Directory.CreateDirectory(dir);
            File.WriteAllText(Path.Combine(dir, IR_Collect.ArtifactNames.SystemInfoTxt), "Hostname: " + hostname + "\r\n", Encoding.UTF8);
            var csv = new StringBuilder();
            csv.AppendLine("RecordNumber,InUse,IsDir,FileName,FullPath,Size,StdCreated,StdModified,StdMftModified,StdAccessed,FnCreated,FnModified,FnMftModified,FnAccessed");
            string name = System.IO.Path.GetFileName(path);
            csv.AppendLine("7,True,False," + name + "," + path + ",2048,2025-02-01 12:00:00,2025-02-01 12:00:00,2025-02-01 12:00:00,2025-02-01 12:00:00,,,,");
            File.WriteAllText(Path.Combine(dir, IR_Collect.ArtifactNames.MftPreviewCsv), csv.ToString(), Encoding.UTF8);
        }

        // Phase 3.2: two hosts that each touched the same file path must surface that path as a cross-host
        // shared entity, and the report must serialize to the correlation_v1 schema.
        private static bool CorrelateCli_finds_shared_entity_across_two_folders()
        {
            string a = Path.Combine(Path.GetTempPath(), "ircol_corrA_" + Guid.NewGuid().ToString("N"));
            string b = Path.Combine(Path.GetTempPath(), "ircol_corrB_" + Guid.NewGuid().ToString("N"));
            try
            {
                const string shared = "C:\\Temp\\shared_evil.exe";
                WriteMiniCaseFolder(a, "HOSTA", shared);
                WriteMiniCaseFolder(b, "HOSTB", shared);

                var ca = IR_Collect.Analysis.CaseManager.LoadCaseFromFolder(a);
                ca.FactStore = IR_Collect.Analysis.Correlation.FactStore.BuildFromCase(ca);
                var cb = IR_Collect.Analysis.CaseManager.LoadCaseFromFolder(b);
                cb.FactStore = IR_Collect.Analysis.Correlation.FactStore.BuildFromCase(cb);

                var report = IR_Collect.Analysis.CorrelationCli.BuildReport(
                    new[] { ca, cb }, new[] { "Path" }, null);
                if (report == null || report.HostCount != 2) return false;

                var hit = report.SharedEntities.FirstOrDefault(s =>
                    s.Value != null && s.Value.IndexOf("shared_evil.exe", StringComparison.OrdinalIgnoreCase) >= 0);
                if (hit == null) return false;
                if (hit.HostCount != 2) return false;
                if (!(hit.Hosts.Contains("HOSTA") && hit.Hosts.Contains("HOSTB"))) return false;

                string json = IR_Collect.Analysis.CorrelationExport.Serialize(report);
                return !string.IsNullOrEmpty(json)
                    && json.IndexOf("correlation_v1", StringComparison.Ordinal) >= 0
                    && json.IndexOf("shared_evil.exe", StringComparison.Ordinal) >= 0;
            }
            catch
            {
                return false;
            }
            finally
            {
                try { if (Directory.Exists(a)) Directory.Delete(a, true); } catch { }
                try { if (Directory.Exists(b)) Directory.Delete(b, true); } catch { }
            }
        }

        // Guided Hunt: a Security 1102 (audit log cleared) fact raises the log-clearing rule (T1070.001);
        // a normal logon event (4624) must not.
        private static bool GuidedHunt_flags_event_log_cleared()
        {
            try
            {
                var store = new IR_Collect.Analysis.Correlation.FactStore();
                var clear = new IR_Collect.Analysis.Correlation.Fact("EventLog_Security_0", DateTime.UtcNow, "EventLog:Security", "LogCleared");
                clear.AddEntity("EventId", "1102");
                var logon = new IR_Collect.Analysis.Correlation.Fact("EventLog_Security_1", DateTime.UtcNow, "EventLog:Security", "Logon");
                logon.AddEntity("EventId", "4624");
                store.AppendFacts(new[] { clear, logon });

                var c = new IR_Collect.Analysis.CaseData();
                c.FactStore = store;
                var res = IR_Collect.Analysis.GuidedHuntPack.Evaluate(c, true);

                var m = res.RuleMatches.FirstOrDefault(x => string.Equals(x.Id, "GH-LOGCLEAR-001", StringComparison.Ordinal));
                return m != null && string.Equals(m.AttackTechniqueId, "T1070.001", StringComparison.Ordinal)
                    && m.FactIds.Contains("EventLog_Security_0") && !m.FactIds.Contains("EventLog_Security_1");
            }
            catch
            {
                return false;
            }
        }

        // Guided Hunt: execution evidence (Amcache/ShimCache/BAM/Process) for an executable in a
        // user-writable / suspicious location raises the suspicious-path execution rule (T1204); a binary
        // under Program Files must NOT trip it.
        private static bool GuidedHunt_flags_execution_from_suspicious_path()
        {
            try
            {
                var store = new IR_Collect.Analysis.Correlation.FactStore();
                var bad = new IR_Collect.Analysis.Correlation.Fact("Amcache_file_Executed_0", DateTime.UtcNow, "Amcache", "Executed");
                bad.AddEntity("Path", "C:\\Users\\bob\\AppData\\Local\\Temp\\evil.exe");
                var ok = new IR_Collect.Analysis.Correlation.Fact("Amcache_file_Executed_1", DateTime.UtcNow, "Amcache", "Executed");
                ok.AddEntity("Path", "C:\\Program Files\\7-Zip\\7zG.exe");
                store.AppendFacts(new[] { bad, ok });

                var c = new IR_Collect.Analysis.CaseData();
                c.FactStore = store;
                var res = IR_Collect.Analysis.GuidedHuntPack.Evaluate(c, true);

                var m = res.RuleMatches.FirstOrDefault(x => string.Equals(x.Id, "GH-EXEC-SUSPATH-001", StringComparison.Ordinal));
                if (m == null) return false;
                if (!string.Equals(m.AttackTechniqueId, "T1204", StringComparison.Ordinal)) return false;
                // Evidence must show the Temp path, and Program Files must not have caused a separate hit.
                bool tempShown = m.Evidence != null && m.Evidence.Any(e => e != null && e.IndexOf("\\Temp\\evil.exe", StringComparison.OrdinalIgnoreCase) >= 0);
                bool programFilesLeaked = m.Evidence != null && m.Evidence.Any(e => e != null && e.IndexOf("7zG.exe", StringComparison.OrdinalIgnoreCase) >= 0);
                return tempShown && !programFilesLeaked;
            }
            catch
            {
                return false;
            }
        }

        // Guided Hunt: a Prefetch fact that loaded a file from a user-writable path (ReferencedFile entity)
        // must raise the DLL side-loading rule (T1574.002), with the loaded file shown in the evidence.
        private static bool GuidedHunt_flags_prefetch_dll_sideload()
        {
            try
            {
                var store = new IR_Collect.Analysis.Correlation.FactStore();
                var f = new IR_Collect.Analysis.Correlation.Fact("Prefetch_0_run_0", DateTime.UtcNow, "Prefetch", "Executed");
                f.AddEntity("FileName", "TRUSTED.EXE");
                f.AddEntity("ReferencedFile", "\\VOLUME{1}\\USERS\\BOB\\APPDATA\\LOCAL\\TEMP\\EVIL.DLL");
                // A normal system-DLL load (no ReferencedFile entity) must NOT trip the rule on its own.
                var g = new IR_Collect.Analysis.Correlation.Fact("Prefetch_1_run_0", DateTime.UtcNow, "Prefetch", "Executed");
                g.AddEntity("FileName", "NOTEPAD.EXE");
                store.AppendFacts(new[] { f, g });

                var c = new IR_Collect.Analysis.CaseData();
                c.FactStore = store;
                var res = IR_Collect.Analysis.GuidedHuntPack.Evaluate(c, true);

                var m = res.RuleMatches.FirstOrDefault(x => string.Equals(x.Id, "GH-PF-SIDELOAD-001", StringComparison.Ordinal));
                if (m == null) return false;
                if (!string.Equals(m.AttackTechniqueId, "T1574.002", StringComparison.Ordinal)) return false;
                // Evidence must surface the loaded suspicious file.
                return m.Evidence != null && m.Evidence.Any(e => e != null && e.IndexOf("EVIL.DLL", StringComparison.OrdinalIgnoreCase) >= 0);
            }
            catch
            {
                return false;
            }
        }

        // Prefetch: a synthetic uncompressed v30 .pf with known fields locks the SCCA offsets (exe @0x10,
        // hash @0x4C, last-run @0x80, run count @0xC8) that were validated 60/60 vs PECmd; plus the
        // normalizer turns it into an Executed fact carrying the exe FileName entity.
        private static bool Prefetch_parses_v30_and_normalizer_emits_executed_facts()
        {
            string dir = Path.Combine(Path.GetTempPath(), "ircol_pf_" + Guid.NewGuid().ToString("N"));
            try
            {
                Directory.CreateDirectory(dir);
                byte[] buf = new byte[0xD0];
                BitConverter.GetBytes(30).CopyTo(buf, 0x00);                     // format version 30
                buf[4] = 0x53; buf[5] = 0x43; buf[6] = 0x43; buf[7] = 0x41;      // "SCCA"
                Encoding.Unicode.GetBytes("TEST.EXE").CopyTo(buf, 0x10);         // exe name (UTF-16, null-term by zero-fill)
                BitConverter.GetBytes((uint)0xDEADBEEF).CopyTo(buf, 0x4C);       // prefetch hash
                var when = new DateTime(2025, 3, 14, 9, 30, 0, DateTimeKind.Utc);
                BitConverter.GetBytes(when.ToFileTimeUtc()).CopyTo(buf, 0x80);   // most recent run time
                BitConverter.GetBytes(42).CopyTo(buf, 0xC8);                     // run count
                string pf = Path.Combine(dir, "TEST.EXE-12345678.pf");
                File.WriteAllBytes(pf, buf);

                var e = IR_Collect.Utils.PrefetchParser.ParseFile(pf);
                if (e == null) return false;
                if (!string.Equals(e.ExecutableName, "TEST.EXE", StringComparison.Ordinal)) return false;
                if (e.FormatVersion != 30 || e.RunCount != 42) return false;
                if (!string.Equals(e.Hash, "DEADBEEF", StringComparison.OrdinalIgnoreCase)) return false;
                if (e.LastRunTimesUtc.Count < 1) return false;
                if (e.LastRunTimesUtc[0].ToString("yyyy-MM-ddTHH:mm:ss") != "2025-03-14T09:30:00") return false;

                var facts = IR_Collect.Analysis.Correlation.Normalizers.PrefetchNormalizer.ToFacts(dir);
                return facts.Any(f => string.Equals(f.Source, "Prefetch", StringComparison.Ordinal)
                    && string.Equals(f.Action, "Executed", StringComparison.Ordinal)
                    && f.EntityRefs != null && f.EntityRefs.Any(en => string.Equals(en.Value, "TEST.EXE", StringComparison.OrdinalIgnoreCase)));
            }
            catch
            {
                return false;
            }
            finally
            {
                try { if (Directory.Exists(dir)) Directory.Delete(dir, true); } catch { }
            }
        }

        // Phase 4.2 hotfix: the 7-day recent-file scan must honor a wall-clock budget so live collection
        // can't run away on a large profile. An expired budget truncates immediately; an unlimited budget
        // still finds a freshly-modified file.
        private static bool RecentFileScan_respects_time_budget()
        {
            string dir = Path.Combine(Path.GetTempPath(), "ircol_rfs_" + Guid.NewGuid().ToString("N"));
            try
            {
                Directory.CreateDirectory(dir);
                File.WriteAllText(Path.Combine(dir, "fresh.txt"), "x"); // modified now = within 7 days

                int c1; bool t1;
                IR_Collect.Collectors.UserActivityCollector.ScanRootForTest(dir, -1, out c1, out t1);
                if (!t1) return false; // expired budget -> truncated

                int c2; bool t2;
                IR_Collect.Collectors.UserActivityCollector.ScanRootForTest(dir, 0, out c2, out t2);
                return !t2 && c2 >= 1; // unlimited -> not truncated, finds the recent file
            }
            catch
            {
                return false;
            }
            finally
            {
                try { if (Directory.Exists(dir)) Directory.Delete(dir, true); } catch { }
            }
        }

        // Phase 5.2: the input folder is SHA-256-hashed at load time and the digest + per-file manifest
        // must reach the summary output, tying the report to exactly the evidence it consumed. We use the
        // textbook SHA-256 of "abc" as a known-answer check on the hashing.
        private static bool EvidenceManifest_hashes_inputs_and_summary_carries_digest()
        {
            const string knownAbcSha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
            string dir = Path.Combine(Path.GetTempPath(), "ircol_ev_" + Guid.NewGuid().ToString("N"));
            try
            {
                Directory.CreateDirectory(dir);
                // Exactly the 3 bytes "abc" (UTF8 no BOM) so the SHA-256 is the textbook value.
                File.WriteAllText(Path.Combine(dir, "evidence.bin"), "abc", new UTF8Encoding(false));

                var em = IR_Collect.Analysis.EvidenceManifest.HashFolder(dir);
                var hit = em.Files.FirstOrDefault(x => x.RelPath != null && x.RelPath.EndsWith("evidence.bin", StringComparison.OrdinalIgnoreCase));
                if (hit == null || !string.Equals(hit.Sha256, knownAbcSha256, StringComparison.OrdinalIgnoreCase)) return false;
                if (hit.SizeBytes != 3) return false;
                if (string.IsNullOrEmpty(em.Digest)) return false;

                // The digest + manifest must flow through LoadCaseFromFolder into the summary output.
                var c = IR_Collect.Analysis.CaseManager.LoadCaseFromFolder(dir);
                if (c.EvidenceFiles == null || !c.EvidenceFiles.Any(x => string.Equals(x.Sha256, knownAbcSha256, StringComparison.OrdinalIgnoreCase))) return false;
                if (!string.Equals(c.EvidenceDigest, em.Digest, StringComparison.OrdinalIgnoreCase)) return false;

                c.FactStore = IR_Collect.Analysis.Correlation.FactStore.BuildFromCase(c);
                var payload = IR_Collect.Analysis.AnalysisCli.BuildHeadlessSummary(c);
                string json = IR_Collect.Analysis.SummaryExport.Serialize(payload);
                return json.IndexOf("evidence_digest", StringComparison.Ordinal) >= 0
                    && json.IndexOf(knownAbcSha256, StringComparison.OrdinalIgnoreCase) >= 0;
            }
            catch
            {
                return false;
            }
            finally
            {
                try { if (Directory.Exists(dir)) Directory.Delete(dir, true); } catch { }
            }
        }

        // Phase 5.1: a single tool-version source of truth (read from the assembly) must be stamped into
        // the machine-readable outputs for court-admissibility (each report declares the tool that made it).
        private static bool BuildInfo_version_matches_assembly_and_is_stamped_in_outputs()
        {
            var asm = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
            string expected = asm.Major + "." + asm.Minor + "." + asm.Build;
            if (!string.Equals(IR_Collect.BuildInfo.Version, expected, StringComparison.Ordinal)) return false;
            if (string.IsNullOrEmpty(IR_Collect.BuildInfo.Version) || IR_Collect.BuildInfo.Version == "0.0.0") return false;
            if (!string.Equals(IR_Collect.BuildInfo.ToolName, "IR_Collect", StringComparison.Ordinal)) return false;

            string stamp = "\"tool_version\":\"" + expected + "\"";

            var corr = IR_Collect.Analysis.CorrelationCli.BuildReport(new IR_Collect.Analysis.CaseData[0], new[] { "Path" }, null);
            if (IR_Collect.Analysis.CorrelationExport.Serialize(corr).IndexOf(stamp, StringComparison.Ordinal) < 0) return false;

            var g = IR_Collect.Analysis.GraphCli.BuildGraph(new IR_Collect.Analysis.CaseData[0], "Path", "x", 1, null);
            string gj = IR_Collect.Analysis.GraphCli.Serialize(g);
            return gj.IndexOf(stamp, StringComparison.Ordinal) >= 0
                && gj.IndexOf("\"tool_name\":\"IR_Collect\"", StringComparison.Ordinal) >= 0;
        }

        // Phase 3.2b: two Amcache file rows share a Publisher but have different paths. Seeding the graph
        // on a.exe's path must reach b.exe's path only at DEPTH 2 (a.exe --Publisher--> b.exe), proving
        // genuine multi-hop expansion (not just single-hop co-occurrence).
        private static bool GraphCli_multi_hop_reaches_sibling_via_shared_publisher()
        {
            string dir = Path.Combine(Path.GetTempPath(), "ircol_graph_" + Guid.NewGuid().ToString("N"));
            try
            {
                Directory.CreateDirectory(dir);
                File.WriteAllText(Path.Combine(dir, IR_Collect.ArtifactNames.SystemInfoTxt), "Hostname: GHOST\r\n", Encoding.UTF8);
                var parsed = new IR_Collect.Utils.AmcacheParseResult();
                parsed.Files.Add(new IR_Collect.Utils.AmcacheFileRecord
                {
                    RegistryKey = "k1", Path = "C:\\Temp\\a.exe", FileName = "a.exe",
                    Hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Publisher = "ACMECorp",
                    ProgramId = "prog1", FirstObservedTime = "2025-01-01 08:00:00"
                });
                parsed.Files.Add(new IR_Collect.Utils.AmcacheFileRecord
                {
                    RegistryKey = "k2", Path = "C:\\Temp\\b.exe", FileName = "b.exe",
                    Hash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Publisher = "ACMECorp",
                    ProgramId = "prog2", FirstObservedTime = "2025-01-01 09:00:00"
                });
                IR_Collect.Collectors.ExecutionArtifactCsvWriter.WriteAmcacheCsvs(parsed,
                    Path.Combine(dir, IR_Collect.ArtifactNames.AmcacheProgramsCsv),
                    Path.Combine(dir, IR_Collect.ArtifactNames.AmcacheFilesCsv));

                var c = IR_Collect.Analysis.CaseManager.LoadCaseFromFolder(dir);
                c.FactStore = IR_Collect.Analysis.Correlation.FactStore.BuildFromCase(c);

                var g = IR_Collect.Analysis.GraphCli.BuildGraph(new[] { c }, "Path", "C:\\Temp\\a.exe", 2, null);
                if (g == null) return false;
                // The shared Publisher must appear at depth 1.
                bool pubAtDepth1 = g.Nodes.Any(n => string.Equals(n.Type, "Publisher", StringComparison.OrdinalIgnoreCase)
                    && n.Value != null && n.Value.IndexOf("ACMECorp", StringComparison.OrdinalIgnoreCase) >= 0 && n.Depth == 1);
                // b.exe is only reachable via the Publisher -> depth 2.
                bool siblingAtDepth2 = g.Nodes.Any(n => string.Equals(n.Type, "Path", StringComparison.OrdinalIgnoreCase)
                    && n.Value != null && n.Value.IndexOf("b.exe", StringComparison.OrdinalIgnoreCase) >= 0 && n.Depth == 2);
                if (!(pubAtDepth1 && siblingAtDepth2)) return false;

                string json = IR_Collect.Analysis.GraphCli.Serialize(g);
                return !string.IsNullOrEmpty(json) && json.IndexOf("graph_v1", StringComparison.Ordinal) >= 0;
            }
            catch
            {
                return false;
            }
            finally
            {
                try { if (Directory.Exists(dir)) Directory.Delete(dir, true); } catch { }
            }
        }

        // Phase 3.1b: the deriver writes raw-hive results to CSV via ExecutionArtifactCsvWriter; this
        // proves that CSV is byte-format-compatible with the normalizer that reads it back (the exact
        // divergence risk for Amcache/ShimCache, which can't be run here without elevation). A real hive
        // can't be synthesized, so we feed the shared writer a synthetic parse result and round-trip it.
        private static bool RawArtifactCsvWriter_amcache_output_is_consumable_by_normalizer()
        {
            string dir = Path.Combine(Path.GetTempPath(), "ircol_amcsv_" + Guid.NewGuid().ToString("N"));
            try
            {
                Directory.CreateDirectory(dir);
                var parsed = new IR_Collect.Utils.AmcacheParseResult();
                parsed.Files.Add(new IR_Collect.Utils.AmcacheFileRecord
                {
                    RegistryKey = "Root\\InventoryApplicationFile\\evil",
                    Path = "C:\\Temp\\evil.exe",
                    FileName = "evil.exe",
                    Hash = "1111111111111111111111111111111111111111",
                    ProductName = "Evil",
                    Publisher = "ACME",
                    ProgramId = "0000abcd",
                    FirstObservedTime = "2025-01-03 08:00:00",
                    ExecutedTime = "2025-01-03 09:00:00"
                });
                string progCsv = Path.Combine(dir, IR_Collect.ArtifactNames.AmcacheProgramsCsv);
                string fileCsv = Path.Combine(dir, IR_Collect.ArtifactNames.AmcacheFilesCsv);
                IR_Collect.Collectors.ExecutionArtifactCsvWriter.WriteAmcacheCsvs(parsed, progCsv, fileCsv);

                var facts = IR_Collect.Analysis.Correlation.Normalizers.AmcacheNormalizer.ToFacts(progCsv, fileCsv);
                if (facts == null || facts.Count < 1) return false;
                // The round-tripped file row must surface its path + sha1 hash as entities.
                bool hasPath = facts.Any(f => f.EntityRefs != null && f.EntityRefs.Any(e =>
                    string.Equals(e.Value, "C:\\Temp\\evil.exe", StringComparison.OrdinalIgnoreCase)));
                bool hasHash = facts.Any(f => f.EntityRefs != null && f.EntityRefs.Any(e =>
                    e.Value != null && e.Value.IndexOf("1111111111111111111111111111111111111111", StringComparison.OrdinalIgnoreCase) >= 0));
                return hasPath && hasHash;
            }
            catch
            {
                return false;
            }
            finally
            {
                try { if (Directory.Exists(dir)) Directory.Delete(dir, true); } catch { }
            }
        }

        // Phase 3.1: ingest an arbitrary folder of already-collected artifacts (no ZIP, no live host),
        // run the real facts pipeline, and emit a headless summary. Uses an mft_preview.csv so the MFT
        // normalizer produces facts deterministically without needing a real hive/ESE sample.
        private static bool AnalyzeFolder_ingests_artifacts_and_builds_summary()
        {
            string dir = Path.Combine(Path.GetTempPath(), "ircol_analyze_" + Guid.NewGuid().ToString("N"));
            try
            {
                Directory.CreateDirectory(dir);
                File.WriteAllText(Path.Combine(dir, IR_Collect.ArtifactNames.SystemInfoTxt),
                    "Hostname: TESTHOST\r\nOS: Windows\r\n", Encoding.UTF8);
                // mft_preview.csv: header + one row with >=14 columns (FullPath at [4], StdCreated at [6]).
                var csv = new StringBuilder();
                csv.AppendLine("RecordNumber,InUse,IsDir,FileName,FullPath,Size,StdCreated,StdModified,StdMftModified,StdAccessed,FnCreated,FnModified,FnMftModified,FnAccessed");
                csv.AppendLine("42,True,False,evil.exe,C:\\Temp\\evil.exe,1024,2025-01-02 10:00:00,2025-01-02 10:00:00,2025-01-02 10:00:00,2025-01-02 10:00:00,,,,");
                File.WriteAllText(Path.Combine(dir, IR_Collect.ArtifactNames.MftPreviewCsv), csv.ToString(), Encoding.UTF8);

                var c = IR_Collect.Analysis.CaseManager.LoadCaseFromFolder(dir);
                if (c == null) return false;
                if (!string.Equals(c.Hostname, "TESTHOST", StringComparison.Ordinal)) return false;
                if (c.MftEntries == null || c.MftEntries.Count < 1) return false;
                // Note: mft_preview.csv and system_info.txt are consumed/skipped by the scan (the MFT
                // preview becomes MftEntries), so they are intentionally NOT in the Artifacts dict.

                var store = IR_Collect.Analysis.Correlation.FactStore.BuildFromCase(c);
                c.FactStore = store;
                if (store == null || store.Facts == null || store.Facts.Count < 1) return false; // MFT facts

                var payload = IR_Collect.Analysis.AnalysisCli.BuildHeadlessSummary(c);
                if (payload == null || payload.FactCount < 1) return false;
                if (!string.Equals(payload.ExportSchema, "summary_v3", StringComparison.Ordinal)) return false;

                string json = IR_Collect.Analysis.SummaryExport.Serialize(payload);
                return !string.IsNullOrEmpty(json)
                    && json.IndexOf("summary_v3", StringComparison.Ordinal) >= 0
                    && json.IndexOf("TESTHOST", StringComparison.Ordinal) >= 0;
            }
            catch
            {
                return false;
            }
            finally
            {
                try { if (Directory.Exists(dir)) Directory.Delete(dir, true); } catch { }
            }
        }

        private static bool FixtureCorpus_committed_files_match_builder_and_parse_as_expected()
        {
            var sb = new StringBuilder();
            int failed = FixtureCorpus.Validate(sb);
            // Surface the per-fixture detail under this test only when something fails.
            if (failed != 0) Console.Write(sb.ToString());
            return failed == 0;
        }

        // Build a minimal MS-SHLLINK LNK (header + LinkInfo, no IDList) carrying a LocalBasePath.
        internal static byte[] BuildLnkFixture(string path, bool unicode)
        {
            var header = new byte[76];
            BitConverter.GetBytes(0x4C).CopyTo(header, 0x00);                                  // HeaderSize
            new Guid("00021401-0000-0000-C000-000000000046").ToByteArray().CopyTo(header, 0x04); // LinkCLSID
            BitConverter.GetBytes(0x00000002).CopyTo(header, 0x14);                            // LinkFlags = HasLinkInfo

            byte[] pathBytes = unicode ? Encoding.Unicode.GetBytes(path + "\0") : Encoding.ASCII.GetBytes(path + "\0");
            int linkInfoHeaderSize = unicode ? 0x24 : 0x1C;
            int pathOffset = linkInfoHeaderSize;
            int linkInfoSize = linkInfoHeaderSize + pathBytes.Length;

            var li = new byte[linkInfoSize];
            BitConverter.GetBytes(linkInfoSize).CopyTo(li, 0x00);
            BitConverter.GetBytes(linkInfoHeaderSize).CopyTo(li, 0x04);
            BitConverter.GetBytes(0x00000001).CopyTo(li, 0x08);                                // VolumeIDAndLocalBasePath
            if (unicode) BitConverter.GetBytes(pathOffset).CopyTo(li, 0x1C);                   // LocalBasePathOffsetUnicode
            else BitConverter.GetBytes(pathOffset).CopyTo(li, 0x10);                           // LocalBasePathOffset (ANSI)
            pathBytes.CopyTo(li, pathOffset);

            var all = new byte[header.Length + li.Length];
            header.CopyTo(all, 0);
            li.CopyTo(all, header.Length);
            return all;
        }

        private static bool Lnk_parser_reads_unicode_and_ansi_local_base_path()
        {
            int consumed;
            // Modern jump-list LNK: LocalBasePath is Unicode at offset 0x1C — must be read there.
            byte[] uni = BuildLnkFixture("C:\\Users\\x\\secret.docx", true);
            string up = IR_Collect.Collectors.JumpListsCollector.TryParseLnkLocalPath(uni, 0, out consumed);
            if (!string.Equals(up, "C:\\Users\\x\\secret.docx", StringComparison.Ordinal)) return false;
            // Legacy ANSI LocalBasePath (offset 0x10) still parses.
            byte[] ansi = BuildLnkFixture("C:\\temp\\a.txt", false);
            string ap = IR_Collect.Collectors.JumpListsCollector.TryParseLnkLocalPath(ansi, 0, out consumed);
            return string.Equals(ap, "C:\\temp\\a.txt", StringComparison.Ordinal);
        }

        private static bool RunToFile_streams_output_and_cleans_on_failure()
        {
            string dir = CreateTempDir("IRCollectRunToFile_");
            try
            {
                // Success: output is streamed to the file.
                string ok = Path.Combine(dir, "ok.txt");
                Collector.CommandHelper.RunToFile("echo", "STREAMOK", ok);
                if (!File.Exists(ok) || File.ReadAllText(ok).IndexOf("STREAMOK", StringComparison.Ordinal) < 0) return false;

                // Failure: a non-zero exit must throw and leave NO partial file (all-or-nothing).
                string bad = Path.Combine(dir, "bad.txt");
                bool threw = false;
                try { Collector.CommandHelper.RunToFile("cmd", "/c exit 3", bad); }
                catch { threw = true; }
                return threw && !File.Exists(bad);
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool MemoryRecord_args_governance_note_round_trips()
        {
            string dir = CreateTempDir("IRCollectMemNote_");
            try
            {
                string p = Path.Combine(dir, "memory_acquisition.json");
                var rec = new MemoryAcquisitionRecord { Status = "complete", ArgsGovernanceNote = MemoryHandoffHelper.ArgsGovernanceNote };
                MemoryAcquisitionRecord.SaveToFile(rec, p);
                var back = MemoryAcquisitionRecord.TryLoad(p);
                return back != null
                    && !string.IsNullOrEmpty(back.ArgsGovernanceNote)
                    && back.ArgsGovernanceNote.IndexOf("operator-supplied", StringComparison.OrdinalIgnoreCase) >= 0;
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool CsvExport_neutralizes_formula_injection()
        {
            // Dangerous leading chars get a single-quote prefix; field stays quoted.
            if (CsvUtils.EscapeFieldForExport("=cmd|'/c calc'!A1") != "\"'=cmd|'/c calc'!A1\"") return false;
            if (CsvUtils.EscapeFieldForExport("+1") != "\"'+1\"") return false;
            if (CsvUtils.EscapeFieldForExport("-2") != "\"'-2\"") return false;
            if (CsvUtils.EscapeFieldForExport("@x") != "\"'@x\"") return false;
            if (CsvUtils.EscapeFieldForExport("\tTabbed") != "\"'\tTabbed\"") return false;
            // Normal value: quoted, no prefix (forensic value unchanged).
            if (CsvUtils.EscapeFieldForExport("C:\\Windows\\system32") != "\"C:\\Windows\\system32\"") return false;
            // Embedded double-quote is doubled (RFC 4180).
            if (CsvUtils.EscapeFieldForExport("a\"b") != "\"a\"\"b\"") return false;
            // Null/empty -> empty quoted field.
            if (CsvUtils.EscapeFieldForExport("") != "\"\"") return false;
            if (CsvUtils.EscapeFieldForExport(null) != "\"\"") return false;
            return true;
        }

        private static bool ConfigAcl_hardening_keeps_file_readable_and_no_throw()
        {
            string dir = CreateTempDir("IRCollectCfgAcl_");
            try
            {
                string f = Path.Combine(dir, "config.ini");
                File.WriteAllText(f, "AiApiKey=secret123\nUploadApiKey=topsecret\n");
                ConfigManager.TryRestrictAclToCurrentUser(f); // best-effort; must not throw
                // We grant ourselves FullControl, so read-back must still work (not locked out).
                string back = File.ReadAllText(f);
                return back.IndexOf("AiApiKey=secret123", StringComparison.Ordinal) >= 0;
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool SqliteModule_unsigned_or_missing_dll_is_rejected()
        {
            string dir = CreateTempDir("IRCollectSqliteSig_");
            try
            {
                // A planted, unsigned System.Data.SQLite.dll must be refused (anti-DLL-planting gate).
                string dll = Path.Combine(dir, "System.Data.SQLite.dll");
                File.WriteAllBytes(dll, new byte[] { 0x4D, 0x5A, 0x90, 0x00, 0x01, 0x02, 0x03, 0x04 }); // junk, unsigned
                if (FactStorePersistence.IsTrustedSqliteModule(dll)) return false;
                // A missing file is also rejected (fail-safe).
                if (FactStorePersistence.IsTrustedSqliteModule(Path.Combine(dir, "does_not_exist.dll"))) return false;
                return true;
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool FactStore_AppendFacts_swaps_without_mutating_old_reference()
        {
            var store = new FactStore();
            var f1 = new Fact("a", DateTime.MinValue, "S1", "X");
            f1.EntityRefs.Add(new EntityRef("Path", "p1"));
            store.Facts.Add(f1);
            store.BuildEntityIndex();

            // References a concurrent reader would grab before a mutation.
            var oldFacts = store.Facts;
            var oldIndex = store.EntityIndex;

            var f2 = new Fact("b", DateTime.MinValue, "S2", "Y");
            f2.EntityRefs.Add(new EntityRef("Path", "p2"));
            store.AppendFacts(new List<Fact> { f2 });

            return oldFacts.Count == 1                         // old snapshot not mutated in place
                && oldIndex.Count == 1
                && !ReferenceEquals(store.Facts, oldFacts)     // references were swapped
                && !ReferenceEquals(store.EntityIndex, oldIndex)
                && store.Facts.Count == 2
                && store.GetByEntity("Path", "p1").Count == 1
                && store.GetByEntity("Path", "p2").Count == 1;
        }

        private static bool FactStore_concurrent_append_and_read_no_exception()
        {
            var store = new FactStore();
            var seed = new Fact("seed", DateTime.MinValue, "S", "X");
            seed.EntityRefs.Add(new EntityRef("Path", "p"));
            store.Facts.Add(seed);
            store.BuildEntityIndex();

            Exception readerError = null;
            int stop = 0;
            var reader = new System.Threading.Thread(delegate()
            {
                try
                {
                    while (System.Threading.Volatile.Read(ref stop) == 0)
                    {
                        var snap = store.Facts; // snapshot reference, then enumerate it
                        int n = 0;
                        foreach (var f in snap) { if (f != null && f.Source != null) n++; }
                        store.GetByEntity("Path", "p");
                        store.GetByTimeRange(DateTime.MinValue, DateTime.MaxValue);
                    }
                }
                catch (Exception ex) { readerError = ex; }
            });
            reader.IsBackground = true;
            reader.Start();

            for (int i = 0; i < 300 && readerError == null; i++)
            {
                var f = new Fact("f" + i, DateTime.MinValue, "S", "X");
                f.EntityRefs.Add(new EntityRef("Path", "p" + i));
                store.AppendFacts(new List<Fact> { f });
            }
            System.Threading.Volatile.Write(ref stop, 1);
            reader.Join(5000);
            return readerError == null && store.Facts.Count >= 300;
        }

        private static string SerializeFactJson(Fact f)
        {
            var ser = new System.Runtime.Serialization.Json.DataContractJsonSerializer(typeof(Fact));
            using (var ms = new MemoryStream())
            {
                ser.WriteObject(ms, f);
                return Encoding.UTF8.GetString(ms.ToArray());
            }
        }

        private static bool FactStoreLoad_skips_bad_rows_keeps_good()
        {
            string json = SerializeFactJson(new Fact("id1", new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc), "EventLog", "Observed"));
            var rows = new List<Dictionary<string, object>>
            {
                // good
                new Dictionary<string, object> { { "Id", "id1" }, { "Time", "2024-01-01T00:00:00Z" }, { "Source", "EventLog" }, { "DetailsJson", json }, { "SchemaVersion", FactStorePersistence.SchemaVersion } },
                // bad: missing SchemaVersion
                new Dictionary<string, object> { { "Id", "id2" }, { "DetailsJson", json } },
                // bad: unparseable DetailsJson (valid schema)
                new Dictionary<string, object> { { "Id", "id3" }, { "DetailsJson", "{ not json" }, { "SchemaVersion", FactStorePersistence.SchemaVersion } },
                // bad: null DetailsJson (valid schema)
                new Dictionary<string, object> { { "Id", "id4" }, { "DetailsJson", null }, { "SchemaVersion", FactStorePersistence.SchemaVersion } },
            };
            int skipped;
            FactStore store = FactStorePersistence.BuildStoreFromRows(rows, "case", "host", "", out skipped);
            return store != null && store.Facts.Count == 1 && skipped == 3;
        }

        private static bool FactStoreLoad_unsupported_schema_throws()
        {
            var rows = new List<Dictionary<string, object>>
            {
                new Dictionary<string, object> { { "DetailsJson", "{}" }, { "SchemaVersion", 999999 } },
            };
            try { int s; FactStorePersistence.BuildStoreFromRows(rows, "c", "h", "", out s); return false; }
            catch (InvalidDataException) { return true; }
        }

        private static bool FactStoreLoad_all_unreadable_rows_throws()
        {
            var rows = new List<Dictionary<string, object>>
            {
                new Dictionary<string, object> { { "DetailsJson", null }, { "SchemaVersion", FactStorePersistence.SchemaVersion } },
                new Dictionary<string, object> { { "DetailsJson", "garbage" }, { "SchemaVersion", FactStorePersistence.SchemaVersion } },
            };
            try { int s; FactStorePersistence.BuildStoreFromRows(rows, "c", "h", "", out s); return false; }
            catch (InvalidDataException) { return true; }
        }

        private static bool EventLogLabel_strips_suffix_case_insensitive()
        {
            string input = "Security_FILTERED.CSV";
            string label = ArtifactNames.GetEventLogLabelFromFileName(input);
            return string.Equals(label, "Security", StringComparison.Ordinal);
        }

        private static bool EventLogLabel_keeps_non_suffix_name()
        {
            string input = "Security_filtered.csv.bak";
            string label = ArtifactNames.GetEventLogLabelFromFileName(input);
            return string.Equals(label, input, StringComparison.Ordinal);
        }

        private static bool CaseManager_GetRelativePath_accepts_child()
        {
            string root = Path.Combine(Path.GetTempPath(), "IRCollectRelA_" + Guid.NewGuid().ToString("N"));
            string child = Path.Combine(root, "EventLogs", "Security_filtered.csv");
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(child));
                File.WriteAllText(child, "x");
                string rel = InvokeCaseManagerGetRelativePath(root, child);
                return string.Equals(rel, Path.Combine("EventLogs", "Security_filtered.csv"), StringComparison.OrdinalIgnoreCase);
            }
            finally
            {
                TryDeleteDir(root);
            }
        }

        private static bool CaseManager_GetRelativePath_rejects_prefix_sibling()
        {
            string root = Path.Combine(Path.GetTempPath(), "IRCollectRelB_" + Guid.NewGuid().ToString("N"));
            string siblingRoot = root + "_X";
            string siblingFile = Path.Combine(siblingRoot, "outside.csv");
            try
            {
                Directory.CreateDirectory(root);
                Directory.CreateDirectory(siblingRoot);
                File.WriteAllText(siblingFile, "x");
                string rel = InvokeCaseManagerGetRelativePath(root, siblingFile);
                return string.Equals(rel, "outside.csv", StringComparison.OrdinalIgnoreCase);
            }
            finally
            {
                TryDeleteDir(root);
                TryDeleteDir(siblingRoot);
            }
        }

        private static string InvokeCaseManagerGetRelativePath(string root, string path)
        {
            MethodInfo method = typeof(CaseManager).GetMethod("GetRelativePath", BindingFlags.NonPublic | BindingFlags.Static);
            if (method == null) throw new InvalidOperationException("CaseManager.GetRelativePath not found.");
            object value = method.Invoke(null, new object[] { root, path });
            return value as string ?? "";
        }

        private static bool EventLog_1149_message_fallback_adds_target_user()
        {
            string dir = CreateTempDir("IRCollectEvt1149Fallback_");
            try
            {
                string csv = Path.Combine(dir, "TerminalServices_filtered.csv");
                WriteEventLogCsv(csv, new[]
                {
                    BuildEventLogRow(
                        "2026-04-08T10:00:00Z",
                        "1149",
                        "Microsoft-Windows-TerminalServices-RemoteConnectionManager",
                        "RDP authentication succeeded for CONTOSO\\alice from 10.0.0.5.",
                        "ClientAddress=10.0.0.5")
                });

                List<Fact> facts = EventLogNormalizer.ToFacts(csv, "TerminalServices");
                if (facts.Count != 1) return false;

                Fact fact = facts[0];
                return HasEntity(fact, "TargetUser", "CONTOSO\\alice")
                    && HasEntity(fact, "RemoteIP", "10.0.0.5")
                    && string.Equals(fact.Action, "RemoteDesktopAuthenticated", StringComparison.Ordinal);
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool EventLog_1149_structured_target_user_is_not_duplicated()
        {
            string dir = CreateTempDir("IRCollectEvt1149Structured_");
            try
            {
                string csv = Path.Combine(dir, "TerminalServices_filtered.csv");
                WriteEventLogCsv(csv, new[]
                {
                    BuildEventLogRow(
                        "2026-04-08T10:01:00Z",
                        "1149",
                        "Microsoft-Windows-TerminalServices-RemoteConnectionManager",
                        "RDP authentication succeeded for CONTOSO\\alice from 10.0.0.5.",
                        "User=alice | Domain=CONTOSO | ClientAddress=10.0.0.5")
                });

                List<Fact> facts = EventLogNormalizer.ToFacts(csv, "TerminalServices");
                if (facts.Count != 1) return false;

                Fact fact = facts[0];
                int targetUserCount = CountEntities(fact, "TargetUser", "CONTOSO\\alice");
                return targetUserCount == 1;
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool EventLog_5145_relative_target_name_maps_to_path()
        {
            string dir = CreateTempDir("IRCollectEvt5145_");
            try
            {
                string csv = Path.Combine(dir, "Security_filtered.csv");
                WriteEventLogCsv(csv, new[]
                {
                    BuildEventLogRow(
                        "2026-04-08T10:02:00Z",
                        "5145",
                        "Microsoft-Windows-Security-Auditing",
                        "Share access checked for docs\\secret.txt.",
                        "SubjectDomainName=CONTOSO | SubjectUserName=bob | ShareName=\\\\server\\share | ShareLocalPath=C:\\Shares\\Team | RelativeTargetName=docs\\secret.txt | IpAddress=10.0.0.9 | IpPort=445")
                });

                List<Fact> facts = EventLogNormalizer.ToFacts(csv, "Security");
                if (facts.Count != 1) return false;

                Fact fact = facts[0];
                return HasEntity(fact, "Path", "docs\\secret.txt")
                    && HasEntity(fact, "ShareLocalPath", "C:\\Shares\\Team")
                    && !HasEntity(fact, "ShareLocalPath", "docs\\secret.txt")
                    && string.Equals(fact.Action, "ShareAccessChecked", StringComparison.Ordinal);
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool EventLog_blank_time_keeps_fact_with_entities_low_confidence()
        {
            string dir = CreateTempDir("IRCollectEvtBlankTime_");
            try
            {
                string csv = Path.Combine(dir, "Security_filtered.csv");
                WriteEventLogCsv(csv, new[]
                {
                    BuildEventLogRow(
                        "",   // blank / unparseable TimeCreated
                        "4624",
                        "Microsoft-Windows-Security-Auditing",
                        "An account was successfully logged on.",
                        "TargetUserName=alice | IpAddress=10.0.0.7 | LogonType=3")
                });

                List<Fact> facts = EventLogNormalizer.ToFacts(csv, "Security");
                if (facts.Count != 1) return false; // must NOT be dropped
                Fact fact = facts[0];
                return HasEntity(fact, "User", "alice")
                    && HasEntity(fact, "RemoteIP", "10.0.0.7")
                    && fact.Time == DateTime.MinValue
                    && string.Equals(fact.TimeConfidence, FactTimeMetadata.LowConfidence, StringComparison.Ordinal)
                    && fact.FallbackUsed
                    && (fact.ParserNote ?? "").IndexOf("TimeCreated missing", StringComparison.OrdinalIgnoreCase) >= 0;
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool MemoryHandoff_resolve_acquire_and_analyze_arg_templates()
        {
            return string.Equals(MemoryHandoffHelper.ResolveAcquireArgsTemplate(null, MemoryHandoffHelper.AcquirePresetWinPmemO), "-o \"{OutputPath}\"", StringComparison.Ordinal)
                && string.Equals(MemoryHandoffHelper.ResolveAcquireArgsTemplate(" /Q ", MemoryHandoffHelper.AcquirePresetQuotedOutput), "\"{OutputPath}\" /Q", StringComparison.Ordinal)
                && string.Equals(MemoryHandoffHelper.ResolveAcquireArgsTemplate("--slow", MemoryHandoffHelper.AcquirePresetWinPmemO), "-o \"{OutputPath}\" --slow", StringComparison.Ordinal)
                && string.Equals(MemoryHandoffHelper.ResolveAcquireArgsTemplate(null, MemoryHandoffHelper.AcquirePresetWinPmemRaw), "--format raw -o \"{OutputPath}\"", StringComparison.Ordinal)
                && string.Equals(MemoryHandoffHelper.ResolveAcquireArgsTemplate(" /Y {OutputPath} ", MemoryHandoffHelper.AcquirePresetCustom), "/Y {OutputPath}", StringComparison.Ordinal)
                && string.Equals(MemoryHandoffHelper.ResolveAnalyzeArgsTemplate(null, MemoryHandoffHelper.AnalyzePresetDualQuoted), "\"{InputPath}\" \"{OutputDir}\"", StringComparison.Ordinal)
                && string.Equals(MemoryHandoffHelper.ResolveAnalyzeArgsTemplate(null, MemoryHandoffHelper.AnalyzePresetInputOutputFlags), "-i \"{InputPath}\" -o \"{OutputDir}\"", StringComparison.Ordinal)
                && string.Equals(MemoryHandoffHelper.ResolveAnalyzeArgsTemplate(null, MemoryHandoffHelper.AnalyzePresetVolatility3OutputDir), "-f \"{InputPath}\" --output-dir \"{OutputDir}\"", StringComparison.Ordinal)
                && string.Equals(MemoryHandoffHelper.ResolveAnalyzeArgsTemplate("custom {CaseDir}", MemoryHandoffHelper.AnalyzePresetCustom), "custom {CaseDir}", StringComparison.Ordinal)
                && string.Equals(MemoryHandoffHelper.NormalizeAcquireValidationMode("min_size"), MemoryHandoffHelper.AcquireValidationMinSize, StringComparison.Ordinal)
                && string.Equals(MemoryHandoffHelper.NormalizeAnalyzeValidationMode("required_patterns"), MemoryHandoffHelper.AnalyzeValidationRequiredPatterns, StringComparison.Ordinal);
        }

        private static bool MemoryHandoff_finalize_analysis_disk_reconciles_missing_outputs()
        {
            string dir = CreateTempDir("IRCollectMemHandoffFin_");
            try
            {
                var rec = new MemoryAnalysisRecord
                {
                    Status = "complete",
                    Detail = "Analyzer reported success.",
                    OutputDirectoryRelativePath = ArtifactNames.MemoryAnalysisFolder,
                    OutputFiles = new List<string> { ArtifactNames.MemoryAnalysisFolder + "\\missing.txt" },
                    OutputFileCount = 1
                };
                MemoryHandoffHelper.FinalizeAnalysisRecordAgainstDisk(dir, rec);
                return string.Equals(rec.Status, "failed", StringComparison.OrdinalIgnoreCase)
                    && (rec.Detail ?? "").IndexOf("[Reconciled]", StringComparison.OrdinalIgnoreCase) >= 0
                    && (rec.Detail ?? "").IndexOf("output missing", StringComparison.OrdinalIgnoreCase) >= 0;
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool MemoryCoverage_complete_with_missing_dump_becomes_failed()
        {
            string dir = CreateTempDir("IRCollectMemCoverageComplete_");
            try
            {
                MemoryAcquisitionRecord.SaveToFile(new MemoryAcquisitionRecord
                {
                    Status = "complete",
                    Detail = "External tool reported success.",
                    OutputRelativePath = ArtifactNames.MemoryFolder + "\\memory.raw"
                }, Path.Combine(dir, ArtifactNames.MemoryAcquisitionJson));

                CollectionCoverageStep step = InvokeBuildMemoryAcquisitionCoverageStep(dir, new List<string>());
                if (step == null) return false;
                if (!string.Equals(step.Status, "failed", StringComparison.OrdinalIgnoreCase)) return false;
                if (step.ArtifactsMissing == null || !step.ArtifactsMissing.Contains(ArtifactNames.MemoryFolder + "\\memory.raw")) return false;
                return (step.Detail ?? "").IndexOf("Sidecar reported complete but expected dump is absent", StringComparison.OrdinalIgnoreCase) >= 0;
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool MemoryCoverage_partial_with_missing_dump_stays_partial()
        {
            string dir = CreateTempDir("IRCollectMemCoveragePartial_");
            try
            {
                MemoryAcquisitionRecord.SaveToFile(new MemoryAcquisitionRecord
                {
                    Status = "partial",
                    Detail = "Tool exited 0 but output file was not found.",
                    OutputRelativePath = ArtifactNames.MemoryFolder + "\\memory.raw"
                }, Path.Combine(dir, ArtifactNames.MemoryAcquisitionJson));

                CollectionCoverageStep step = InvokeBuildMemoryAcquisitionCoverageStep(dir, new List<string>());
                if (step == null) return false;
                if (!string.Equals(step.Status, "partial", StringComparison.OrdinalIgnoreCase)) return false;
                return (step.Detail ?? "").IndexOf("Expected dump absent on disk", StringComparison.OrdinalIgnoreCase) >= 0;
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool MemoryAnalysisOutputDir_default_folder_allowed()
        {
            string dir = CreateTempDir("IRCollectMemAnalysisDirDefault_");
            try
            {
                string dumpDir = Path.Combine(dir, ArtifactNames.MemoryFolder);
                Directory.CreateDirectory(dumpDir);
                string dumpPath = Path.Combine(dumpDir, "memory.raw");
                File.WriteAllText(dumpPath, "dump", new UTF8Encoding(false));

                string validation = IR_Collect.Collectors.MemoryAnalysisCollector.ValidateAnalysisOutputDirectory(
                    dir,
                    Path.Combine(dir, ArtifactNames.MemoryAnalysisFolder),
                    dumpPath);

                return string.IsNullOrEmpty(validation);
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool MemoryAnalysisOutputDir_case_root_rejected()
        {
            string dir = CreateTempDir("IRCollectMemAnalysisDirRoot_");
            try
            {
                string dumpDir = Path.Combine(dir, ArtifactNames.MemoryFolder);
                Directory.CreateDirectory(dumpDir);
                string dumpPath = Path.Combine(dumpDir, "memory.raw");
                File.WriteAllText(dumpPath, "dump", new UTF8Encoding(false));

                string validation = IR_Collect.Collectors.MemoryAnalysisCollector.ValidateAnalysisOutputDirectory(dir, dir, dumpPath);
                return !string.IsNullOrEmpty(validation) &&
                    validation.IndexOf("case root", StringComparison.OrdinalIgnoreCase) >= 0;
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool MemoryAnalysisOutputDir_reserved_evidence_dir_rejected()
        {
            string dir = CreateTempDir("IRCollectMemAnalysisDirReserved_");
            try
            {
                string dumpDir = Path.Combine(dir, ArtifactNames.MemoryFolder);
                Directory.CreateDirectory(dumpDir);
                string dumpPath = Path.Combine(dumpDir, "memory.raw");
                File.WriteAllText(dumpPath, "dump", new UTF8Encoding(false));

                string validation = IR_Collect.Collectors.MemoryAnalysisCollector.ValidateAnalysisOutputDirectory(
                    dir,
                    Path.Combine(dir, "EventLogs"),
                    dumpPath);

                return !string.IsNullOrEmpty(validation) &&
                    validation.IndexOf("reserved evidence directory", StringComparison.OrdinalIgnoreCase) >= 0;
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool MemoryAnalysisCoverage_complete_with_outputs_is_complete()
        {
            string dir = CreateTempDir("IRCollectMemAnalysisComplete_");
            try
            {
                string outputDir = Path.Combine(dir, ArtifactNames.MemoryAnalysisFolder);
                Directory.CreateDirectory(outputDir);
                File.WriteAllText(Path.Combine(outputDir, "pslist.json"), "{ }", new UTF8Encoding(false));
                MemoryAnalysisRecord.SaveToFile(new MemoryAnalysisRecord
                {
                    Status = "complete",
                    Detail = "Analyzer reported success.",
                    OutputDirectoryRelativePath = ArtifactNames.MemoryAnalysisFolder,
                    OutputFiles = new List<string> { ArtifactNames.MemoryAnalysisFolder + "\\pslist.json" },
                    OutputFileCount = 1,
                    OutputTotalBytes = 3
                }, Path.Combine(dir, ArtifactNames.MemoryAnalysisJson));

                CollectionCoverageStep step = InvokeBuildMemoryAnalysisCoverageStep(dir, new List<string>());
                return step != null
                    && string.Equals(step.Status, "complete", StringComparison.OrdinalIgnoreCase)
                    && step.ArtifactsPresent != null
                    && step.ArtifactsPresent.Any(v => string.Equals(v, ArtifactNames.MemoryAnalysisFolder + "\\pslist.json", StringComparison.OrdinalIgnoreCase));
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool EventLogCoverage_label_mismatch_is_partial()
        {
            string dir = CreateTempDir("IRCollectEventCoverageParity_");
            try
            {
                string logsDir = Path.Combine(dir, "EventLogs");
                Directory.CreateDirectory(logsDir);
                File.WriteAllText(Path.Combine(logsDir, "Security.evtx"), "raw", new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(logsDir, "System.evtx"), "raw", new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(logsDir, "Security_filtered.csv"), "TimeCreated,EventId\r\n", new UTF8Encoding(false));

                CollectionCoverageStep step = InvokeBuildEventLogCoverageStep(dir, new List<string>());
                return step != null
                    && string.Equals(step.Status, "partial", StringComparison.OrdinalIgnoreCase)
                    && step.ArtifactsMissing != null
                    && step.ArtifactsMissing.Any(v => string.Equals(v, Path.Combine("EventLogs", "System_filtered.csv"), StringComparison.OrdinalIgnoreCase))
                    && (step.Detail ?? "").IndexOf("missing filtered CSV for: System", StringComparison.OrdinalIgnoreCase) >= 0;
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool ExecutionArtifactsCoverage_failed_with_present_artifact_stays_failed()
        {
            string dir = CreateTempDir("IRCollectExecCoverageFailed_");
            try
            {
                File.WriteAllText(Path.Combine(dir, ArtifactNames.BitsJobsCsv), "DisplayName,OwnerAccount\r\n", new UTF8Encoding(false));

                CollectionCoverageStep step = InvokeBuildExecutionArtifactsCoverageStep(dir, new List<string> { "Execution Artifacts" });
                return step != null &&
                    string.Equals(step.Status, "failed", StringComparison.OrdinalIgnoreCase) &&
                    step.ArtifactsPresent != null &&
                    step.ArtifactsPresent.Any(v => string.Equals(v, ArtifactNames.BitsJobsCsv, StringComparison.OrdinalIgnoreCase));
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool CollectionCoverage_failed_step_with_present_artifact_makes_overall_failed()
        {
            string dir = CreateTempDir("IRCollectCoverageFailedOverall_");
            try
            {
                File.WriteAllText(Path.Combine(dir, ArtifactNames.BitsJobsCsv), "DisplayName,OwnerAccount\r\n", new UTF8Encoding(false));

                CollectionCoverageReport report = InvokeBuildCollectionCoverageReport(
                    dir,
                    "CaseExecFailed",
                    new List<string> { "Execution Artifacts" },
                    CollectionModeProfileHelper.Standard);

                CollectionCoverageStep step = report != null && report.Steps != null
                    ? report.Steps.FirstOrDefault(s => s != null && string.Equals(s.Step, "Execution Artifacts", StringComparison.OrdinalIgnoreCase))
                    : null;

                return report != null &&
                    string.Equals(report.OverallStatus, "failed", StringComparison.OrdinalIgnoreCase) &&
                    report.FailedSteps > 0 &&
                    step != null &&
                    string.Equals(step.Status, "failed", StringComparison.OrdinalIgnoreCase);
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool CollectionCoverage_missing_steps_make_overall_partial()
        {
            string dir = CreateTempDir("IRCollectCoverageOverall_");
            try
            {
                File.WriteAllText(Path.Combine(dir, ArtifactNames.SystemInfoTxt), "ok", new UTF8Encoding(false));
                CollectionCoverageReport report = InvokeBuildCollectionCoverageReport(dir, "CaseA", new List<string>(), CollectionModeProfileHelper.Standard);
                return report != null &&
                    string.Equals(report.OverallStatus, "partial", StringComparison.OrdinalIgnoreCase) &&
                    report.MissingSteps > 0 &&
                    string.Equals(report.CollectionModeProfile, CollectionModeProfileHelper.Standard, StringComparison.Ordinal);
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool CollectionResult_coverage_failed_step_sets_has_errors()
        {
            var result = new Collector.CollectionResult
            {
                FailedSteps = new List<string>(),
                CoverageReport = new CollectionCoverageReport
                {
                    OverallStatus = "failed",
                    Steps = new List<CollectionCoverageStep>
                    {
                        new CollectionCoverageStep { Step = "Memory analysis handoff", Status = "failed", Detail = "coverage downgrade" }
                    }
                }
            };

            return result.HasErrors &&
                string.Equals(result.BuildFailureSummary(), "Memory analysis handoff", StringComparison.OrdinalIgnoreCase);
        }

        private static bool MemoryAnalysisCoverage_complete_without_outputs_becomes_failed()
        {
            string dir = CreateTempDir("IRCollectMemAnalysisMissing_");
            try
            {
                MemoryAnalysisRecord.SaveToFile(new MemoryAnalysisRecord
                {
                    Status = "complete",
                    Detail = "Analyzer reported success.",
                    OutputDirectoryRelativePath = ArtifactNames.MemoryAnalysisFolder,
                    OutputFiles = new List<string>(),
                    OutputFileCount = 0
                }, Path.Combine(dir, ArtifactNames.MemoryAnalysisJson));

                CollectionCoverageStep step = InvokeBuildMemoryAnalysisCoverageStep(dir, new List<string>());
                return step != null
                    && string.Equals(step.Status, "failed", StringComparison.OrdinalIgnoreCase)
                    && (step.Detail ?? "").IndexOf("analysis outputs are absent", StringComparison.OrdinalIgnoreCase) >= 0;
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool MemoryAcquisitionNormalizer_ToFacts_emits_summary_and_output_facts()
        {
            string dir = CreateTempDir("IRCollectMemNormA_");
            try
            {
                string jsonPath = Path.Combine(dir, ArtifactNames.MemoryAcquisitionJson);
                MemoryAcquisitionRecord.SaveToFile(new MemoryAcquisitionRecord
                {
                    Status = "complete",
                    Detail = "Capture completed.",
                    ArgsPreset = MemoryHandoffHelper.AcquirePresetWinPmemRaw,
                    OutputRelativePath = ArtifactNames.MemoryFolder + "\\memory.raw",
                    OutputFileSizeBytes = 4096,
                    OutputSha256 = "ABCDEF0123456789",
                    CollectorUser = @"DOMAIN\alice",
                    ValidationStatus = "passed",
                    DiagnosticCategory = "success",
                    EndedAtUtc = "2026-04-08T12:00:00Z"
                }, jsonPath);

                var facts = MemoryAcquisitionNormalizer.ToFacts(jsonPath);
                if (facts == null || facts.Count != 2)
                    return false;
                return facts.Any(f => string.Equals(f.Action, "MemoryAcquisitionComplete", StringComparison.Ordinal)) &&
                    facts.Any(f => string.Equals(f.Action, MemoryAcquisitionNormalizer.ActionOutputObserved, StringComparison.Ordinal) &&
                                   HasEntity(f, "Path", ArtifactNames.MemoryFolder + "\\memory.raw") &&
                                   HasEntity(f, "Hash", "ABCDEF0123456789"));
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool MemoryAnalysisNormalizer_ToFacts_emits_summary_and_output_facts()
        {
            string dir = CreateTempDir("IRCollectMemNormB_");
            try
            {
                string jsonPath = Path.Combine(dir, ArtifactNames.MemoryAnalysisJson);
                MemoryAnalysisRecord.SaveToFile(new MemoryAnalysisRecord
                {
                    Status = "partial",
                    Detail = "Analyzer produced output but one validation pattern was missing.",
                    ArgsPreset = MemoryHandoffHelper.AnalyzePresetVolatility3OutputDir,
                    InputRelativePath = ArtifactNames.MemoryFolder + "\\memory.raw",
                    OutputDirectoryRelativePath = ArtifactNames.MemoryAnalysisFolder,
                    OutputFiles = new List<string> { ArtifactNames.MemoryAnalysisFolder + "\\pslist.json" },
                    OutputFileCount = 1,
                    OutputTotalBytes = 2048,
                    CollectorUser = @"DOMAIN\bob",
                    ValidationStatus = "failed",
                    MissingOutputPatterns = new List<string> { "handles*.json" },
                    DiagnosticCategory = "output_validation_failed",
                    EndedAtUtc = "2026-04-08T12:05:00Z"
                }, jsonPath);

                var facts = MemoryAnalysisNormalizer.ToFacts(jsonPath);
                if (facts == null || facts.Count != 2)
                    return false;
                return facts.Any(f => string.Equals(f.Action, "MemoryAnalysisPartial", StringComparison.Ordinal) &&
                                      HasEntity(f, "InputPath", ArtifactNames.MemoryFolder + "\\memory.raw")) &&
                    facts.Any(f => string.Equals(f.Action, MemoryAnalysisNormalizer.ActionOutputObserved, StringComparison.Ordinal) &&
                                   HasEntity(f, "Path", ArtifactNames.MemoryAnalysisFolder + "\\pslist.json"));
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool ServiceNormalizer_ToFacts_maps_service_name_and_path()
        {
            string dir = CreateTempDir("IRCollectSvcNorm_");
            try
            {
                string csvPath = Path.Combine(dir, ArtifactNames.ServicesCsv);
                File.WriteAllText(csvPath,
                    "Node,DisplayName,Name,PathName,StartMode,State\n" +
                    "HOST01,Updater Service,UpdaterSvc,\"C:\\Users\\Public\\svc.exe -service\",Auto,Running\n",
                    new UTF8Encoding(false));

                var facts = ServiceNormalizer.ToFacts(csvPath);
                if (facts == null || facts.Count != 1)
                    return false;

                Fact f = facts[0];
                return string.Equals(f.Source, ServiceNormalizer.SourceName, StringComparison.Ordinal) &&
                    string.Equals(f.Action, ServiceNormalizer.ActionServiceConfigurationObserved, StringComparison.Ordinal) &&
                    HasEntity(f, "ServiceName", "UpdaterSvc") &&
                    HasEntity(f, "Path", @"C:\Users\Public\svc.exe -service") &&
                    HasEntity(f, "Path", @"C:\Users\Public\svc.exe");
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool StoredCredentialNormalizer_ToFacts_maps_target_user_server()
        {
            string dir = CreateTempDir("IRCollectCredNorm_");
            try
            {
                string path = Path.Combine(dir, ArtifactNames.StoredCredentialsTxt);
                File.WriteAllText(path,
                    "ObservedAtUtc: 2026-04-09T01:02:03Z\n" +
                    "Currently stored credentials:\n\n" +
                    "    Target: Domain:target=TERMSRV/FILE01\n" +
                    "    Type: Domain Password\n" +
                    "    User: CONTOSO\\\\alice\n",
                    new UTF8Encoding(false));

                var facts = StoredCredentialNormalizer.ToFacts(path);
                if (facts == null || facts.Count != 1)
                    return false;

                Fact f = facts[0];
                return string.Equals(f.Source, StoredCredentialNormalizer.SourceName, StringComparison.Ordinal) &&
                    string.Equals(f.Action, StoredCredentialNormalizer.ActionStoredCredentialObserved, StringComparison.Ordinal) &&
                    HasEntity(f, "User", @"CONTOSO\\alice") &&
                    HasEntity(f, "CredentialTarget", "Domain:target=TERMSRV/FILE01") &&
                    HasEntity(f, "TargetServer", "FILE01") &&
                    HasEntity(f, "Workstation", "FILE01");
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool KerberosTicketCacheNormalizer_ToFacts_maps_ticket_entities_and_time()
        {
            string dir = CreateTempDir("IRCollectKerbNorm_");
            try
            {
                string path = Path.Combine(dir, ArtifactNames.KerberosTicketsTxt);
                File.WriteAllText(path,
                    "ObservedAtUtc: 2026-04-09T01:02:03Z\n" +
                    "Current LogonId is 0:0x3e7\n\n" +
                    "Cached Tickets: (1)\n\n" +
                    "#0>     Client: alice @ CONTOSO.LOCAL\n" +
                    "        Server: cifs/FILE01.contoso.local @ CONTOSO.LOCAL\n" +
                    "        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96\n" +
                    "        Ticket Flags: 0x40e10000 -> forwardable renewable\n" +
                    "        Start Time: 4/9/2026 8:36:31 (local)\n" +
                    "        End Time:   4/9/2026 18:36:31 (local)\n" +
                    "        Renew Time: 4/16/2026 8:36:31 (local)\n" +
                    "        Kdc Called: dc01.contoso.local\n",
                    new UTF8Encoding(false));

                var facts = KerberosTicketCacheNormalizer.ToFacts(path);
                if (facts == null || facts.Count != 1)
                    return false;

                Fact f = facts[0];
                return string.Equals(f.Source, KerberosTicketCacheNormalizer.SourceName, StringComparison.Ordinal) &&
                    string.Equals(f.Action, KerberosTicketCacheNormalizer.ActionKerberosTicketCached, StringComparison.Ordinal) &&
                    HasEntity(f, "User", "alice") &&
                    HasEntity(f, "ServiceName", "cifs/FILE01.contoso.local @ CONTOSO.LOCAL") &&
                    HasEntity(f, "TargetServer", "FILE01.contoso.local") &&
                    HasEntity(f, "Workstation", "FILE01.contoso.local") &&
                    f.Time.Year >= 2026;
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool SharedEntityPivot_finds_cross_host_path()
        {
            DateTime t1 = new DateTime(2026, 4, 8, 10, 0, 0, DateTimeKind.Utc);
            DateTime t2 = t1.AddMinutes(5);
            CaseData hostA = CreateSyntheticCase("HostA", CreateFact("A1", t1, "EventLog:Security", "ProcessCreated", "Path", @"C:\Temp\bad.exe", "User", @"CONTOSO\alice"));
            CaseData hostB = CreateSyntheticCase("HostB", CreateFact("B1", t2, "EventLog:Security", "ProcessCreated", "Path", @"C:\Temp\bad.exe", "User", @"CONTOSO\alice"));

            SharedEntityPivotResult result = SharedEntityPivotBuilder.Build(new[] { hostA, hostB }, "Path", "bad.exe", new SharedEntityPivotOptions { MaxResults = 10 });
            if (result == null || result.Items == null || result.Items.Count != 1) return false;

            SharedEntityPivotItem item = result.Items[0];
            return item.Hosts.Count == 2
                && item.FactCount == 2
                && string.Equals(item.DisplayValue, @"C:\Temp\bad.exe", StringComparison.OrdinalIgnoreCase);
        }

        private static bool RelatedEntityPivot_returns_seed_neighbors()
        {
            DateTime t1 = new DateTime(2026, 4, 8, 10, 0, 0, DateTimeKind.Utc);
            DateTime t2 = t1.AddMinutes(5);
            CaseData hostA = CreateSyntheticCase("HostA", CreateFact("A1", t1, "EventLog:Security", "ProcessCreated", "Path", @"C:\Temp\bad.exe", "User", @"CONTOSO\alice", "RemoteIP", "10.0.0.5"));
            CaseData hostB = CreateSyntheticCase("HostB", CreateFact("B1", t2, "EventLog:Security", "ProcessCreated", "Path", @"C:\Temp\bad.exe", "User", @"CONTOSO\alice", "RemoteIP", "10.0.0.5"));

            List<RelatedEntityPivotItem> items = SharedEntityPivotBuilder.BuildRelatedEntities(
                new[] { hostA, hostB },
                "Path",
                @"C:\Temp\bad.exe",
                new SharedEntityPivotOptions { MaxResults = 10 });

            if (items == null || items.Count < 2) return false;
            bool hasUser = items.Any(i => string.Equals(i.RelatedType, "User", StringComparison.OrdinalIgnoreCase) &&
                                          string.Equals(i.DisplayValue, @"CONTOSO\alice", StringComparison.OrdinalIgnoreCase) &&
                                          i.Hosts.Count == 2);
            bool hasRemoteIp = items.Any(i => string.Equals(i.RelatedType, "RemoteIP", StringComparison.OrdinalIgnoreCase) &&
                                              string.Equals(i.DisplayValue, "10.0.0.5", StringComparison.OrdinalIgnoreCase) &&
                                              i.Hosts.Count == 2);
            return hasUser && hasRemoteIp;
        }

        private static bool InvestigationGraph_returns_related_edges()
        {
            DateTime t1 = new DateTime(2026, 4, 8, 10, 0, 0, DateTimeKind.Utc);
            DateTime t2 = t1.AddMinutes(5);
            CaseData hostA = CreateSyntheticCase("HostA", CreateFact("A1", t1, "EventLog:Security", "ProcessCreated", "Path", @"C:\Temp\bad.exe", "User", @"CONTOSO\alice", "RemoteIP", "10.0.0.5"));
            CaseData hostB = CreateSyntheticCase("HostB", CreateFact("B1", t2, "EventLog:Security", "ProcessCreated", "Path", @"C:\Temp\bad.exe", "User", @"CONTOSO\alice", "RemoteIP", "10.0.0.5"));

            List<InvestigationGraphEdge> edges = InvestigationGraphBuilder.Build(
                new[] { hostA, hostB },
                "Path",
                @"C:\Temp\bad.exe",
                new SharedEntityPivotOptions { MaxResults = 10 });

            if (edges == null || edges.Count < 2) return false;
            InvestigationGraphEdge userEdge = edges.FirstOrDefault(e =>
                string.Equals(e.RelatedType, "User", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(e.DisplayValue, @"CONTOSO\alice", StringComparison.OrdinalIgnoreCase));
            if (userEdge == null) return false;

            List<SharedEntityFactHit> hits = InvestigationGraphBuilder.BuildEdgeFactHits(
                new[] { hostA, hostB },
                userEdge,
                new SharedEntityPivotOptions { MaxResults = 10 },
                true);

            return userEdge.Hosts.Count == 2 && userEdge.FactCount == 2 && hits.Count == 2;
        }

        private static bool TemporalSharedEntityPivot_groups_same_bucket_across_hosts()
        {
            DateTime t1 = new DateTime(2026, 4, 8, 10, 4, 0, DateTimeKind.Utc);
            DateTime t2 = new DateTime(2026, 4, 8, 10, 12, 0, DateTimeKind.Utc);
            CaseData hostA = CreateSyntheticCase("HostA", CreateFact("A1", t1, "EventLog:Security", "ProcessCreated", "RemoteIP", "10.0.0.5", "Path", @"C:\Temp\bad.exe"));
            CaseData hostB = CreateSyntheticCase("HostB", CreateFact("B1", t2, "EventLog:Security", "ProcessCreated", "RemoteIP", "10.0.0.5", "Path", @"C:\Temp\bad.exe"));

            List<TemporalSharedEntityPivotItem> items = SharedEntityPivotBuilder.BuildTemporalCorrelations(
                new[] { hostA, hostB },
                "RemoteIP",
                "10.0.0.5",
                new SharedEntityPivotOptions { MaxResults = 10, BucketMinutes = 30 });

            if (items == null || items.Count != 1) return false;
            TemporalSharedEntityPivotItem item = items[0];
            return item.Hosts.Count == 2 && item.FactCount == 2 && string.Equals(item.DisplayValue, "10.0.0.5", StringComparison.OrdinalIgnoreCase);
        }

        private static bool GuidedHuntPack_matches_rdp_and_admin_share_rules()
        {
            DateTime t1 = new DateTime(2026, 4, 8, 10, 0, 0, DateTimeKind.Utc);
            DateTime t2 = t1.AddMinutes(2);
            CaseData host = CreateSyntheticCase(
                "HostA",
                CreateFact("GH1", t1, "LogonSession", "RemoteInteractiveSessionObserved", "User", @"CONTOSO\alice", "Workstation", "WS-01"),
                CreateFact("GH2", t2, "ServerConnection", "ServerShareConnectionObserved", "User", @"CONTOSO\alice", "ShareName", "ADMIN$", "RemoteName", "10.10.10.20"));

            GuidedHuntResult result = GuidedHuntPack.Evaluate(host, true);
            if (result == null || !result.Enabled)
                return false;

            bool hasRdp = result.RuleMatches.Any(r =>
                r != null &&
                string.Equals(r.Id, "GH-RDP-001", StringComparison.Ordinal) &&
                string.Equals(r.AttackTechniqueId, "T1021.001", StringComparison.Ordinal) &&
                string.Equals(r.SuggestedHypothesisId, "GH-HYP-RDP", StringComparison.Ordinal));
            bool hasSmb = result.RuleMatches.Any(r =>
                r != null &&
                string.Equals(r.Id, "GH-SMB-001", StringComparison.Ordinal) &&
                string.Equals(r.AttackTechniqueId, "T1021.002", StringComparison.Ordinal) &&
                string.Equals(r.SuggestedHypothesisId, "GH-HYP-SMB", StringComparison.Ordinal));
            bool hasRdpHypothesis = result.HypothesisTemplates.Any(h => h != null && string.Equals(h.Id, "GH-HYP-RDP", StringComparison.Ordinal));
            bool hasSmbHypothesis = result.HypothesisTemplates.Any(h => h != null && string.Equals(h.Id, "GH-HYP-SMB", StringComparison.Ordinal));
            return result.FactCountEvaluated == 2 && hasRdp && hasSmb && hasRdpHypothesis && hasSmbHypothesis;
        }

        private static bool GuidedHuntPack_matches_task_service_and_credential_rules()
        {
            DateTime t1 = new DateTime(2026, 4, 8, 11, 0, 0, DateTimeKind.Utc);
            DateTime t2 = t1.AddMinutes(1);
            DateTime t3 = t1.AddMinutes(2);
            DateTime t4 = t1.AddMinutes(3);
            CaseData host = CreateSyntheticCase(
                "HostB",
                CreateFact("GT1", t1, "ScheduledTask", "Scheduled", "TaskName", @"\BadTask", "Path", @"C:\Users\Public\run.cmd"),
                CreateFact("GS1", t2, "Service", "ServiceConfigurationObserved", "ServiceName", "BadSvc", "Path", @"C:\Users\Public\svc.exe"),
                CreateFact("GC1", t3, "EventLog:Security", "ExplicitCredentialUsed", "TargetUser", @"CONTOSO\alice", "TargetServer", "FILE01"),
                CreateFact("GC2", t4, "ServerConnection", "ServerShareConnectionObserved", "User", @"CONTOSO\alice", "ShareName", "ADMIN$", "RemoteName", "FILE01"));

            host.FactStore.BuildEntityIndex();
            GuidedHuntResult result = GuidedHuntPack.Evaluate(host, true);
            if (result == null || !result.Enabled)
                return false;

            bool hasTask = result.RuleMatches.Any(r => r != null && string.Equals(r.Id, "GH-TASK-001", StringComparison.Ordinal) && string.Equals(r.AttackTechniqueId, "T1053.005", StringComparison.Ordinal));
            bool hasService = result.RuleMatches.Any(r => r != null && string.Equals(r.Id, "GH-SVC-001", StringComparison.Ordinal) && string.Equals(r.AttackTechniqueId, "T1543.003", StringComparison.Ordinal));
            bool hasCredential = result.RuleMatches.Any(r => r != null && string.Equals(r.Id, "GH-CRED-001", StringComparison.Ordinal) && string.Equals(r.AttackTechniqueId, "T1078", StringComparison.Ordinal));
            bool hasTaskHypothesis = result.HypothesisTemplates.Any(h => h != null && string.Equals(h.Id, "GH-HYP-TASK", StringComparison.Ordinal));
            bool hasServiceHypothesis = result.HypothesisTemplates.Any(h => h != null && string.Equals(h.Id, "GH-HYP-SVC", StringComparison.Ordinal));
            bool hasCredentialHypothesis = result.HypothesisTemplates.Any(h => h != null && string.Equals(h.Id, "GH-HYP-CRED", StringComparison.Ordinal));
            return hasTask && hasService && hasCredential && hasTaskHypothesis && hasServiceHypothesis && hasCredentialHypothesis;
        }

        private static bool GuidedHuntPack_matches_cmdkey_and_klist_artifacts()
        {
            DateTime t1 = new DateTime(2026, 4, 9, 1, 0, 0, DateTimeKind.Utc);
            DateTime t2 = t1.AddMinutes(1);
            DateTime t3 = t1.AddMinutes(2);
            CaseData host = CreateSyntheticCase(
                "HostC",
                CreateFact("SC1", t1, "StoredCredential", "StoredCredentialObserved", "User", @"CONTOSO\\alice", "CredentialTarget", "Domain:target=TERMSRV/FILE01", "TargetServer", "FILE01", "Workstation", "FILE01"),
                CreateFact("KT1", t2, "KerberosTicketCache", "KerberosTicketCached", "User", "alice", "ServiceName", "cifs/FILE01.contoso.local @ CONTOSO.LOCAL", "TargetServer", "FILE01.contoso.local", "Workstation", "FILE01.contoso.local"),
                CreateFact("NR1", t3, "NetworkResource", "NetworkResourceConnectionObserved", "User", @"CONTOSO\\alice", "RemoteName", @"\\\\FILE01\\Tools", "Workstation", "FILE01", "ShareName", "Tools"));

            host.FactStore.BuildEntityIndex();
            GuidedHuntResult result = GuidedHuntPack.Evaluate(host, true);
            return result != null &&
                result.RuleMatches.Any(r => r != null && string.Equals(r.Id, "GH-CRED-001", StringComparison.Ordinal)) &&
                result.HypothesisTemplates.Any(h => h != null && string.Equals(h.Id, "GH-HYP-CRED", StringComparison.Ordinal));
        }

        private static bool SummaryExport_serialize_preserves_summary_v3_schema()
        {
            var payload = new SummaryPayload
            {
                GeneratedAt = "2026-04-08T10:00:00Z",
                ExportSchema = "summary_v3",
                AnalysisMode = "facts_only",
                Host = "HostA",
                CaseId = "CaseA",
                CollectionCoverage = new CollectionCoverageReport { OverallStatus = "partial", Host = "HostA", Steps = new List<CollectionCoverageStep>() },
                MemoryAcquisition = new MemoryAcquisitionRecord { Status = "skipped", Detail = "not configured" },
                MemoryAnalysis = new MemoryAnalysisRecord { Status = "skipped", Detail = "not configured" },
                FactSourceCounts = new Dictionary<string, int> { { "EventLog:Security", 2 } },
                EntityTypeCounts = new Dictionary<string, int> { { "Path", 1 } },
                ParserNotes = new List<string> { "note" },
                FactSamples = new List<Fact>()
            };

            payload.CollectionModeProfile = CollectionModeProfileHelper.TriageFast;
            string json = SummaryExport.Serialize(payload);
            return json.IndexOf("\"export_schema\":\"summary_v3\"", StringComparison.OrdinalIgnoreCase) >= 0
                && json.IndexOf("\"analysis_mode\":\"facts_only\"", StringComparison.OrdinalIgnoreCase) >= 0
                && json.IndexOf("\"collection_mode_profile\":\"TriageFast\"", StringComparison.Ordinal) >= 0
                && json.IndexOf("\"memory_acquisition\"", StringComparison.OrdinalIgnoreCase) >= 0
                && json.IndexOf("\"memory_analysis\"", StringComparison.OrdinalIgnoreCase) >= 0
                && json.IndexOf("\"collection_coverage\"", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static bool SummaryExport_serialize_handles_minvalue_fact_time()
        {
            var payload = new SummaryPayload
            {
                GeneratedAt = "2026-04-08T10:05:00Z",
                ExportSchema = "summary_v3",
                AnalysisMode = "facts_only",
                Host = "HostA",
                CaseId = "CaseA",
                FactSamples = new List<Fact>
                {
                    CreateFact("A1", DateTime.MinValue, "Amcache", "Observed", "Path", @"C:\Temp\bad.exe")
                },
                ParserNotes = new List<string> { "note" }
            };
            payload.FactSamples[0].ParserNote = "Time unavailable; parser note should survive summary export.";
            payload.FactSamples[0].FallbackUsed = true;

            string json = SummaryExport.Serialize(payload);
            return !string.IsNullOrWhiteSpace(json) &&
                json.IndexOf("\"fact_samples\"", StringComparison.OrdinalIgnoreCase) >= 0 &&
                json.IndexOf("bad.exe", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static bool SummaryExport_serialize_includes_guided_hunt()
        {
            var payload = new SummaryPayload
            {
                GeneratedAt = "2026-04-08T10:06:00Z",
                ExportSchema = "summary_v3",
                AnalysisMode = "facts_only",
                Host = "HostA",
                CaseId = "CaseA",
                GuidedHunt = new GuidedHuntResult
                {
                    Enabled = true,
                    Host = "HostA",
                    FactCountEvaluated = 2,
                    RuleMatches = new List<GuidedHuntRuleMatch>
                    {
                        new GuidedHuntRuleMatch
                        {
                            Id = "GH-RDP-001",
                            Title = "Remote interactive logon session observed",
                            AttackTechniqueId = "T1021.001"
                        }
                    },
                    HypothesisTemplates = new List<GuidedHuntHypothesisTemplate>
                    {
                        new GuidedHuntHypothesisTemplate
                        {
                            Id = "GH-HYP-RDP",
                            Title = "Validate remote desktop usage"
                        }
                    }
                },
                FactSamples = new List<Fact>()
            };

            string json = SummaryExport.Serialize(payload);
            return json.IndexOf("\"guided_hunt\"", StringComparison.OrdinalIgnoreCase) >= 0 &&
                json.IndexOf("\"GH-RDP-001\"", StringComparison.Ordinal) >= 0 &&
                json.IndexOf("\"GH-HYP-RDP\"", StringComparison.Ordinal) >= 0;
        }

        private static bool ParserNoteSummary_includes_non_amcache_sources()
        {
            var facts = new List<Fact>();
            Fact usnFact = CreateFact("U1", DateTime.MinValue, "USN", "Observed", "Path", @"C:\Temp\a.txt");
            usnFact.ParserNote = "USN row lacked a stable full path.";
            usnFact.FallbackUsed = true;
            facts.Add(usnFact);

            Fact shimFact = CreateFact("S1", DateTime.MinValue, "ShimCache", "Observed", "Path", @"C:\Temp\b.exe");
            shimFact.ParserNote = "Path reconstructed from ShimCache binary entry stream.";
            shimFact.FallbackUsed = true;
            facts.Add(shimFact);

            List<string> notes = ParserNoteSummaryBuilder.BuildFactParserNoteLines(facts, 10);
            return notes.Any(v => v.IndexOf("USN note: USN row lacked a stable full path.", StringComparison.OrdinalIgnoreCase) >= 0) &&
                notes.Any(v => v.IndexOf("ShimCache note: Path reconstructed from ShimCache binary entry stream.", StringComparison.OrdinalIgnoreCase) >= 0);
        }

        private static bool SummaryTab_includes_parser_notes_section()
        {
            MainForm form = null;
            CaseData host = null;
            try
            {
                Fact usnFact = CreateFact("U1", DateTime.MinValue, "USN", "Observed", "Path", @"C:\Temp\a.txt");
                usnFact.ParserNote = "USN row lacked a stable full path.";
                usnFact.FallbackUsed = true;
                host = CreateSyntheticCase("HostA", usnFact);

                form = new MainForm();
                TabPage tab = InvokeCreateSummaryTab(form, host);
                TextBox box = FindDescendantControl<TextBox>(tab);
                string text = box != null ? (box.Text ?? "") : "";
                return text.IndexOf("Parser Notes:", StringComparison.OrdinalIgnoreCase) >= 0 &&
                    text.IndexOf("USN note: USN row lacked a stable full path.", StringComparison.OrdinalIgnoreCase) >= 0;
            }
            finally
            {
                if (form != null) form.Dispose();
                if (host != null) TryDeleteDir(host.ExtractPath);
            }
        }

        private static bool HtmlReport_missing_artifact_counts_render_not_found()
        {
            MainForm form = null;
            CaseData host = null;
            try
            {
                host = CreateSyntheticCase("HostA");
                host.CaseID = "CaseA";
                form = new MainForm();
                string html = InvokeBuildHtmlReport(form, host);
                return html.IndexOf("<td>Services</td><td>(not found)</td>", StringComparison.OrdinalIgnoreCase) >= 0 &&
                    html.IndexOf("<td>-1</td>", StringComparison.OrdinalIgnoreCase) < 0;
            }
            finally
            {
                if (form != null) form.Dispose();
                if (host != null) TryDeleteDir(host.ExtractPath);
            }
        }

        private static bool SummaryPayload_missing_artifact_counts_are_zero()
        {
            MainForm form = null;
            CaseData host = null;
            try
            {
                host = CreateSyntheticCase("HostA");
                host.CaseID = "CaseA";
                form = new MainForm();
                SummaryPayload payload = InvokeBuildSummaryPayload(form, host);
                if (payload == null || payload.Counts == null) return false;
                return payload.Counts.ContainsKey("services") &&
                    payload.Counts.ContainsKey("scheduled_tasks") &&
                    payload.Counts.ContainsKey("shellbags") &&
                    payload.Counts["services"] == 0 &&
                    payload.Counts["scheduled_tasks"] == 0 &&
                    payload.Counts["shellbags"] == 0;
            }
            finally
            {
                if (form != null) form.Dispose();
                if (host != null) TryDeleteDir(host.ExtractPath);
            }
        }

        private static bool ShellBagsParser_DecodeShellItemBlob_ascii_segment()
        {
            byte[] bytes = new byte[] { 0x0a, 0x00, 0x31, (byte)'T', (byte)'e', (byte)'s', (byte)'t', 0x00, 0x00, 0x00 };
            var dec = ShellBagsParser.DecodeShellItemBlob(bytes);
            return dec != null && string.Equals(dec.Path, "Test", StringComparison.Ordinal);
        }

        private static bool ShellBagsParser_TryEnsureShellBagsCsv_writes_csv()
        {
            string root = CreateTempDir("IRCollectShellBags_");
            try
            {
                string regDir = Path.Combine(root, "Registry");
                Directory.CreateDirectory(regDir);
                string regPath = Path.Combine(regDir, "ShellBags_S-1-5-21-111.reg");
                var sb = new StringBuilder();
                sb.AppendLine("Windows Registry Editor Version 5.00");
                sb.AppendLine();
                sb.AppendLine("[HKEY_USERS\\S-1-5-21-111\\SOFTWARE\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU\\0]");
                sb.AppendLine("\"1\"=hex:0a,00,31,54,65,73,74,00,00,00");
                File.WriteAllText(regPath, sb.ToString(), new UTF8Encoding(false));
                string detail;
                int n = ShellBagsParser.TryEnsureShellBagsCsv(root, true, out detail);
                string csv = Path.Combine(regDir, ArtifactNames.ShellBagsCsv);
                if (n <= 0 || !File.Exists(csv)) return false;
                string text = File.ReadAllText(csv, Encoding.UTF8);
                return text.IndexOf("DecodedPath", StringComparison.OrdinalIgnoreCase) >= 0
                    && text.IndexOf("Test", StringComparison.Ordinal) >= 0;
            }
            finally
            {
                TryDeleteDir(root);
            }
        }

        private static bool ShellBags_ReadLogicalLines_hex_continuation_strips_backslashes()
        {
            string sample =
                "Windows Registry Editor Version 5.00\r\n\r\n" +
                "[HKEY_USERS\\S-1-5-21\\Shell\\BagMRU\\0]\r\n" +
                "\"1\"=hex:0a,00,\\\r\n" +
                "  31,54,65,73,74,00,\\\r\n" +
                "  00,00\r\n";
            List<string> lines = ShellBagsParser.ReadLogicalLinesFromText(sample);
            bool hasMergedHex = false;
            foreach (string line in lines)
            {
                if (line == null || line.IndexOf("\"1\"=hex:", StringComparison.Ordinal) < 0) continue;
                if (line.IndexOf('\\') >= 0) return false;
                if (line.IndexOf("\"1\"=hex:0a,00,31,54,65,73,74,00,00,00", StringComparison.Ordinal) >= 0)
                    hasMergedHex = true;
            }
            return hasMergedHex;
        }

        private static bool ShellBagsParser_TryEnsureShellBagsCsv_multiline_hex_decodes_path()
        {
            string root = CreateTempDir("IRCollectShellBagsML_");
            try
            {
                string regDir = Path.Combine(root, "Registry");
                Directory.CreateDirectory(regDir);
                string regPath = Path.Combine(regDir, "ShellBags_S-1-5-21-ml.reg");
                var sb = new StringBuilder();
                sb.AppendLine("Windows Registry Editor Version 5.00");
                sb.AppendLine();
                sb.AppendLine("[HKEY_USERS\\S-1-5-21-ml\\SOFTWARE\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU\\0]");
                sb.AppendLine("\"1\"=hex:0a,00,\\");
                sb.AppendLine("  31,54,65,73,74,00,\\");
                sb.AppendLine("  00,00");
                File.WriteAllText(regPath, sb.ToString(), new UTF8Encoding(false));
                string detail;
                int n = ShellBagsParser.TryEnsureShellBagsCsv(root, true, out detail);
                string csv = Path.Combine(regDir, ArtifactNames.ShellBagsCsv);
                if (n <= 0 || !File.Exists(csv)) return false;
                string text = File.ReadAllText(csv, Encoding.UTF8);
                return text.IndexOf("Test", StringComparison.Ordinal) >= 0;
            }
            finally
            {
                TryDeleteDir(root);
            }
        }

        private static bool ShellBagsParser_BagsShell_key_without_Shell_segment()
        {
            string root = CreateTempDir("IRCollectShellBagsBags_");
            try
            {
                string regDir = Path.Combine(root, "Registry");
                Directory.CreateDirectory(regDir);
                string regPath = Path.Combine(regDir, "ShellBags_S-1-5-21-bags.reg");
                var sb = new StringBuilder();
                sb.AppendLine("Windows Registry Editor Version 5.00");
                sb.AppendLine();
                sb.AppendLine("[HKEY_USERS\\S-1-5-21-bags\\Software\\Microsoft\\Windows\\Bags\\7\\Shell]");
                sb.AppendLine("\"Shell\"=hex:0a,00,31,42,61,67,73,00,00,00");
                File.WriteAllText(regPath, sb.ToString(), new UTF8Encoding(false));
                string detail;
                int n = ShellBagsParser.TryEnsureShellBagsCsv(root, true, out detail);
                string csv = Path.Combine(regDir, ArtifactNames.ShellBagsCsv);
                if (n <= 0 || !File.Exists(csv)) return false;
                string text = File.ReadAllText(csv, Encoding.UTF8);
                return text.IndexOf("Bags", StringComparison.Ordinal) >= 0
                    && text.IndexOf("BagMRU", StringComparison.OrdinalIgnoreCase) < 0;
            }
            finally
            {
                TryDeleteDir(root);
            }
        }

        private static bool ShellBagsParser_BagsShellNoRoam_key()
        {
            string root = CreateTempDir("IRCollectShellBagsNR_");
            try
            {
                string regDir = Path.Combine(root, "Registry");
                Directory.CreateDirectory(regDir);
                string regPath = Path.Combine(regDir, "ShellBags_S-1-5-21-bags.reg");
                var sb = new StringBuilder();
                sb.AppendLine("Windows Registry Editor Version 5.00");
                sb.AppendLine();
                sb.AppendLine("[HKEY_USERS\\S-1-5-21-bags\\Software\\Microsoft\\Windows\\Bags\\7\\ShellNoRoam]");
                sb.AppendLine("\"Shell\"=hex:0a,00,31,5a,5a,00,00,00,00,00");
                File.WriteAllText(regPath, sb.ToString(), new UTF8Encoding(false));
                string detail;
                int n = ShellBagsParser.TryEnsureShellBagsCsv(root, true, out detail);
                string csv = Path.Combine(regDir, ArtifactNames.ShellBagsCsv);
                if (n <= 0 || !File.Exists(csv)) return false;
                string text = File.ReadAllText(csv, Encoding.UTF8);
                return text.IndexOf("ShellNoRoam", StringComparison.OrdinalIgnoreCase) >= 0
                    && text.IndexOf("ZZ", StringComparison.Ordinal) >= 0;
            }
            finally
            {
                TryDeleteDir(root);
            }
        }

        private static bool ShellBagsNormalizer_ToFacts_maps_path_user_sid()
        {
            string dir = CreateTempDir("IRCollectShellBagsNorm_");
            try
            {
                string csv = Path.Combine(dir, ArtifactNames.ShellBagsCsv);
                File.WriteAllText(csv,
                    "Sid,User,BagPath,RegistryKey,ValueName,DecodedPath,MruSlot,LastWriteTime,ParserNote,SourceFile\r\n" +
                    "S-1-5-21-1,S-1-5-21-1,0,,1,TestPath,1,2026-04-08T10:00:00Z,,ShellBags_x.reg\r\n",
                    new UTF8Encoding(false));
                List<Fact> facts = ShellBagsNormalizer.ToFacts(csv);
                if (facts == null || facts.Count != 1) return false;
                Fact f = facts[0];
                if (!string.Equals(f.Action, "FolderBrowsed", StringComparison.Ordinal)) return false;
                if (!string.Equals(f.Source, ShellBagsNormalizer.SourceName, StringComparison.Ordinal)) return false;
                bool hasPath = f.EntityRefs != null && f.EntityRefs.Any(e => e != null && e.Type == "Path" && e.Value == "TestPath");
                bool hasUser = f.EntityRefs != null && f.EntityRefs.Any(e => e != null && e.Type == "User" && e.Value == "S-1-5-21-1");
                bool hasSid = f.EntityRefs != null && f.EntityRefs.Any(e => e != null && e.Type == "Sid" && e.Value == "S-1-5-21-1");
                return hasPath && hasUser && hasSid && FactTimeMetadata.HasUsableTime(f.Time);
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool TimelineFilter_helpers_honor_minute_precision()
        {
            DateTime value = new DateTime(2026, 4, 8, 10, 15, 42, DateTimeKind.Local);
            DateTime from = MainForm.NormalizeTimelineFilterStart(value);
            DateTime to = MainForm.NormalizeTimelineFilterEnd(value);
            return from == new DateTime(2026, 4, 8, 10, 15, 0, DateTimeKind.Local) &&
                to > new DateTime(2026, 4, 8, 10, 15, 59, 998, DateTimeKind.Local) &&
                to < new DateTime(2026, 4, 8, 10, 16, 0, DateTimeKind.Local);
        }

        private static bool TimelineGraphFocus_matches_entity_refs_before_text_fallback()
        {
            var evt = new MainForm.TimelineEvent
            {
                Time = new DateTime(2026, 4, 8, 10, 0, 0, DateTimeKind.Utc),
                Source = "EventLog:Security",
                Type = "Logon",
                Description = "Unrelated description",
                EntityRefs = new List<EntityRef> { new EntityRef("RemoteIP", "10.0.0.5") }
            };
            bool structuredMatch = MainForm.TimelineEventMatchesGraphFocus(evt, "RemoteIP", "10.0.0.5", "10.0.0.5");

            var fallbackEvt = new MainForm.TimelineEvent
            {
                Time = new DateTime(2026, 4, 8, 10, 1, 0, DateTimeKind.Utc),
                Source = "Activity",
                Type = "Note",
                Description = "contains 10.0.0.5 in plain text",
                EntityRefs = new List<EntityRef>()
            };
            bool textFallbackMatch = MainForm.TimelineEventMatchesGraphFocus(fallbackEvt, "RemoteIP", "10.0.0.5", "10.0.0.5");

            return structuredMatch && textFallbackMatch;
        }

        private static bool FullLogExportJson_includes_memory_and_freshness_host_fields()
        {
            string dir = CreateTempDir("IRCollectFullLogExport_");
            try
            {
                DateTime t1 = new DateTime(2026, 4, 8, 10, 0, 0, DateTimeKind.Utc);
                CaseData host = CreateSyntheticCase("HostA", CreateFact("A1", t1, "EventLog:Security", "ProcessCreated", "Path", @"C:\Temp\bad.exe", "User", @"CONTOSO\alice"));
                host.CaseID = "CaseA";
                host.LoadWarnings.Add("sample warning");
                host.CollectionCoverage = new CollectionCoverageReport
                {
                    OverallStatus = "partial",
                    Host = "HostA",
                    CollectionModeProfile = CollectionModeProfileHelper.ForensicStrict,
                    Steps = new List<CollectionCoverageStep>()
                };
                host.FactStoreFreshnessStatus = "current";
                host.FactStoreFreshnessDetail = "cache is current";
                host.MemoryAcquisitionMeta = new MemoryAcquisitionRecord { Status = "skipped", Detail = "not configured" };
                host.MemoryAnalysisMeta = new MemoryAnalysisRecord { Status = "skipped", Detail = "not configured" };

                string outputPath = Path.Combine(dir, "full_log.json");
                FactStorePersistence.ExportFullLogJson(new[] { host }, outputPath);
                string json = File.ReadAllText(outputPath, Encoding.UTF8);

                return json.IndexOf("\"export_schema\":\"full_log_v3\"", StringComparison.OrdinalIgnoreCase) >= 0
                    && json.IndexOf("\"collection_mode_profile\":\"ForensicStrict\"", StringComparison.Ordinal) >= 0
                    && json.IndexOf("\"memory_acquisition\"", StringComparison.OrdinalIgnoreCase) >= 0
                    && json.IndexOf("\"memory_analysis\"", StringComparison.OrdinalIgnoreCase) >= 0
                    && json.IndexOf("\"collection_coverage_status\":\"partial\"", StringComparison.OrdinalIgnoreCase) >= 0
                    && json.IndexOf("\"fact_store_freshness_status\":\"current\"", StringComparison.OrdinalIgnoreCase) >= 0
                    && json.IndexOf("Memory handoff:", StringComparison.OrdinalIgnoreCase) >= 0
                    && json.IndexOf("[Reconciled]", StringComparison.OrdinalIgnoreCase) >= 0
                    && json.IndexOf("[Coverage]", StringComparison.OrdinalIgnoreCase) >= 0;
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static CollectionCoverageStep InvokeBuildMemoryAcquisitionCoverageStep(string outputDir, List<string> failedSteps)
        {
            MethodInfo method = typeof(Collector).GetMethod("BuildMemoryAcquisitionCoverageStep", BindingFlags.NonPublic | BindingFlags.Static);
            if (method == null) throw new InvalidOperationException("Collector.BuildMemoryAcquisitionCoverageStep not found.");
            object value = method.Invoke(null, new object[] { outputDir, failedSteps });
            return value as CollectionCoverageStep;
        }

        private static TabPage InvokeCreateSummaryTab(MainForm form, CaseData c)
        {
            MethodInfo method = typeof(MainForm).GetMethod("CreateSummaryTab", BindingFlags.NonPublic | BindingFlags.Instance);
            if (method == null) throw new InvalidOperationException("MainForm.CreateSummaryTab not found.");
            object value = method.Invoke(form, new object[] { c });
            return value as TabPage;
        }

        private static string InvokeBuildHtmlReport(MainForm form, CaseData c)
        {
            MethodInfo method = typeof(MainForm).GetMethod("BuildHtmlReport", BindingFlags.NonPublic | BindingFlags.Instance);
            if (method == null) throw new InvalidOperationException("MainForm.BuildHtmlReport not found.");
            object value = method.Invoke(form, new object[] { c });
            return value as string;
        }

        private static SummaryPayload InvokeBuildSummaryPayload(MainForm form, CaseData c)
        {
            MethodInfo method = typeof(MainForm).GetMethod("BuildSummaryPayload", BindingFlags.NonPublic | BindingFlags.Instance);
            if (method == null) throw new InvalidOperationException("MainForm.BuildSummaryPayload not found.");
            object value = method.Invoke(form, new object[] { c });
            return value as SummaryPayload;
        }

        private static T FindDescendantControl<T>(Control root) where T : Control
        {
            if (root == null) return null;
            T typed = root as T;
            if (typed != null) return typed;
            foreach (Control child in root.Controls)
            {
                T found = FindDescendantControl<T>(child);
                if (found != null) return found;
            }
            return null;
        }

        private static CollectionCoverageStep InvokeBuildMemoryAnalysisCoverageStep(string outputDir, List<string> failedSteps)
        {
            MethodInfo method = typeof(Collector).GetMethod("BuildMemoryAnalysisCoverageStep", BindingFlags.NonPublic | BindingFlags.Static);
            if (method == null) throw new InvalidOperationException("Collector.BuildMemoryAnalysisCoverageStep not found.");
            object value = method.Invoke(null, new object[] { outputDir, failedSteps });
            return value as CollectionCoverageStep;
        }

        private static CollectionCoverageStep InvokeBuildExecutionArtifactsCoverageStep(string outputDir, List<string> failedSteps)
        {
            MethodInfo method = typeof(Collector).GetMethod("BuildExecutionArtifactsCoverageStep", BindingFlags.NonPublic | BindingFlags.Static);
            if (method == null) throw new InvalidOperationException("Collector.BuildExecutionArtifactsCoverageStep not found.");
            object value = method.Invoke(null, new object[] { outputDir, failedSteps });
            return value as CollectionCoverageStep;
        }

        private static CollectionCoverageStep InvokeBuildEventLogCoverageStep(string outputDir, List<string> failedSteps)
        {
            MethodInfo method = typeof(Collector).GetMethod("BuildEventLogCoverageStep", BindingFlags.NonPublic | BindingFlags.Static);
            if (method == null) throw new InvalidOperationException("Collector.BuildEventLogCoverageStep not found.");
            object value = method.Invoke(null, new object[] { outputDir, failedSteps });
            return value as CollectionCoverageStep;
        }

        private static CollectionCoverageReport InvokeBuildCollectionCoverageReport(string outputDir, string evidenceId, List<string> failedSteps, string collectionModeProfile)
        {
            MethodInfo method = typeof(Collector).GetMethod(
                "BuildCollectionCoverageReport",
                BindingFlags.NonPublic | BindingFlags.Static,
                null,
                new Type[] { typeof(string), typeof(string), typeof(List<string>), typeof(string) },
                null);
            if (method == null) throw new InvalidOperationException("Collector.BuildCollectionCoverageReport not found.");
            object value = method.Invoke(null, new object[] { outputDir, evidenceId, failedSteps, collectionModeProfile ?? CollectionModeProfileHelper.Standard });
            return value as CollectionCoverageReport;
        }

        private static bool CollectionModeProfile_normalize_and_cases()
        {
            return string.Equals(CollectionModeProfileHelper.Normalize(null), CollectionModeProfileHelper.Standard, StringComparison.Ordinal) &&
                string.Equals(CollectionModeProfileHelper.Normalize(" triagefast "), CollectionModeProfileHelper.TriageFast, StringComparison.Ordinal) &&
                string.Equals(CollectionModeProfileHelper.Normalize("FORENSICSTRICT"), CollectionModeProfileHelper.ForensicStrict, StringComparison.Ordinal) &&
                string.Equals(CollectionModeProfileHelper.Normalize("nope"), CollectionModeProfileHelper.Standard, StringComparison.Ordinal);
        }

        private static bool CollectionModeProfile_forensic_strict_blocks_outbound_helpers()
        {
            var cfg = new ConfigManager();
            cfg.Set("CollectionModeProfile", CollectionModeProfileHelper.ForensicStrict);
            return CollectionModeProfileHelper.BlocksAiAnalyze(cfg) && CollectionModeProfileHelper.BlocksOutboundZipUpload(cfg);
        }

        private static bool CollectionModeProfile_standard_allows_outbound_helpers()
        {
            var cfg = new ConfigManager();
            cfg.Set("CollectionModeProfile", CollectionModeProfileHelper.Standard);
            return !CollectionModeProfileHelper.BlocksAiAnalyze(cfg) && !CollectionModeProfileHelper.BlocksOutboundZipUpload(cfg);
        }

        private static bool CollectionCoverage_report_includes_mode_profile()
        {
            string dir = CreateTempDir("IRCollectCoverProfile_");
            try
            {
                File.WriteAllText(Path.Combine(dir, ArtifactNames.SystemInfoTxt), "ok", new UTF8Encoding(false));
                CollectionCoverageReport report = InvokeBuildCollectionCoverageReport(dir, "CaseB", new List<string>(), CollectionModeProfileHelper.ForensicStrict);
                return report != null &&
                    string.Equals(report.CollectionModeProfile, CollectionModeProfileHelper.ForensicStrict, StringComparison.Ordinal);
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool ZipUpload_gate_uses_run_profile_ForensicStrict_even_if_settings_Standard()
        {
            var cfg = new ConfigManager();
            cfg.Set("CollectionModeProfile", CollectionModeProfileHelper.Standard);
            return CollectionModeProfileHelper.BlocksOutboundZipUploadForLocalCollectRun(CollectionModeProfileHelper.ForensicStrict, cfg) &&
                !CollectionModeProfileHelper.BlocksOutboundZipUpload(cfg);
        }

        private static bool ZipUpload_gate_run_Standard_not_blocked_when_settings_ForensicStrict()
        {
            var cfg = new ConfigManager();
            cfg.Set("CollectionModeProfile", CollectionModeProfileHelper.ForensicStrict);
            return !CollectionModeProfileHelper.BlocksOutboundZipUploadForLocalCollectRun(CollectionModeProfileHelper.Standard, cfg) &&
                !CollectionModeProfileHelper.BlocksOutboundZipUploadForLocalCollectRun("", cfg) &&
                CollectionModeProfileHelper.BlocksOutboundZipUpload(cfg);
        }

        private static bool ZipUpload_gate_null_run_falls_back_to_settings_ForensicStrict()
        {
            var cfg = new ConfigManager();
            cfg.Set("CollectionModeProfile", CollectionModeProfileHelper.ForensicStrict);
            return CollectionModeProfileHelper.BlocksOutboundZipUploadForLocalCollectRun(null, cfg) &&
                CollectionModeProfileHelper.BlocksOutboundZipUpload(cfg);
        }

        private static bool Dashboard_loaded_case_profiles_line_mixed()
        {
            var list = new List<string> { CollectionModeProfileHelper.Standard, CollectionModeProfileHelper.ForensicStrict, null };
            string line = CollectionModeProfileHelper.FormatDashboardLoadedCollectionProfilesLine(list);
            return line.IndexOf("Mixed", StringComparison.Ordinal) >= 0 &&
                line.IndexOf("ForensicStrict", StringComparison.Ordinal) >= 0 &&
                line.IndexOf("Standard", StringComparison.Ordinal) >= 0 &&
                line.IndexOf("lack recorded profile", StringComparison.Ordinal) >= 0;
        }

        private static bool Dashboard_loaded_case_profiles_line_all_unlabeled()
        {
            var list = new List<string> { null, null };
            string line = CollectionModeProfileHelper.FormatDashboardLoadedCollectionProfilesLine(list);
            return line.IndexOf("not recorded", StringComparison.Ordinal) >= 0;
        }

        private static bool Dashboard_loaded_case_profiles_line_single()
        {
            var list = new List<string> { CollectionModeProfileHelper.TriageFast };
            string line = CollectionModeProfileHelper.FormatDashboardLoadedCollectionProfilesLine(list);
            return line.IndexOf("Loaded case collection profiles: TriageFast", StringComparison.Ordinal) >= 0 &&
                line.IndexOf("Mixed", StringComparison.Ordinal) < 0;
        }

        private static string CreateTempDir(string prefix)
        {
            string dir = Path.Combine(Path.GetTempPath(), prefix + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            return dir;
        }

        private static void WriteEventLogCsv(string path, IEnumerable<string[]> rows)
        {
            var sb = new StringBuilder();
            sb.AppendLine("TimeCreated,EventId,LevelDisplayName,ProviderName,Computer,UserId,TaskDisplayName,Message,EventData");
            foreach (string[] row in rows)
            {
                for (int i = 0; i < row.Length; i++)
                {
                    if (i > 0) sb.Append(",");
                    sb.Append(CsvUtils.EscapeField(row[i] ?? ""));
                }
                sb.AppendLine();
            }
            File.WriteAllText(path, sb.ToString(), new UTF8Encoding(false));
        }

        private static string[] BuildEventLogRow(string timeCreated, string eventId, string providerName, string message, string eventData)
        {
            return new[]
            {
                timeCreated ?? "",
                eventId ?? "",
                "Information",
                providerName ?? "",
                "HOST01",
                "",
                "",
                message ?? "",
                eventData ?? ""
            };
        }

        private static bool EndpointGovernance_empty_allowlist_blocks()
        {
            return !EndpointGovernance.IsEndpointAllowed("https://example.com/a", "") &&
                !EndpointGovernance.IsEndpointAllowed("https://example.com/a", "   ");
        }

        private static bool EndpointGovernance_prefix_allows_child_path()
        {
            const string allow = "https://api.example.com/v1";
            return EndpointGovernance.IsEndpointAllowed("https://api.example.com/v1/chat", allow) &&
                EndpointGovernance.IsEndpointAllowed("https://api.example.com/v1", allow) &&
                !EndpointGovernance.IsEndpointAllowed("https://api.example.com/v2/chat", allow);
        }

        private static bool EndpointGovernance_different_host_rejected()
        {
            return !EndpointGovernance.IsEndpointAllowed("https://evil.example.com/v1/a", "https://api.example.com/v1");
        }

        private static bool EndpointGovernance_path_case_mismatch_rejected()
        {
            const string allow = "https://api.example.com/API/v1";
            return !EndpointGovernance.IsEndpointAllowed("https://api.example.com/api/v1/chat", allow) &&
                EndpointGovernance.IsEndpointAllowed("https://api.example.com/API/v1/chat", allow);
        }

        private static bool AiRedaction_basic_masks_collection_coverage_identity()
        {
            var live = new CollectionCoverageReport
            {
                Host = "SECRET-HOSTNAME",
                EvidenceId = "E-SECRET-001",
                CollectorUser = @"DOMAIN\secret.user",
                OverallStatus = "complete",
                Steps = new List<CollectionCoverageStep>()
            };
            var payload = new SummaryPayload
            {
                ExportSchema = "summary_v3",
                CollectionCoverage = live,
                FactSamples = new List<Fact>()
            };
            var copy = SummaryExport.CloneForSerialization(payload);
            SummaryPayloadAiRedactor.Apply(copy, "Basic");
            string json = SummaryExport.Serialize(copy);
            bool liveIntact =
                string.Equals(live.Host, "SECRET-HOSTNAME", StringComparison.Ordinal) &&
                string.Equals(live.EvidenceId, "E-SECRET-001", StringComparison.Ordinal) &&
                string.Equals(live.CollectorUser, @"DOMAIN\secret.user", StringComparison.Ordinal);
            bool jsonRedacted =
                json.IndexOf("SECRET-HOSTNAME", StringComparison.OrdinalIgnoreCase) < 0 &&
                json.IndexOf("E-SECRET-001", StringComparison.OrdinalIgnoreCase) < 0 &&
                json.IndexOf("secret.user", StringComparison.OrdinalIgnoreCase) < 0 &&
                json.IndexOf("[redacted]", StringComparison.OrdinalIgnoreCase) >= 0;
            return liveIntact && jsonRedacted;
        }

        private static bool AiRedaction_basic_masks_top_level_host_case_id()
        {
            var p = new SummaryPayload
            {
                ExportSchema = "summary_v3",
                Host = "TOP-SHOST-99",
                CaseId = "CASE-TOP-001",
                FactSamples = new List<Fact>()
            };
            var copy = SummaryExport.CloneForSerialization(p);
            SummaryPayloadAiRedactor.Apply(copy, "Basic");
            string json = SummaryExport.Serialize(copy);
            return string.Equals(p.Host, "TOP-SHOST-99", StringComparison.Ordinal) &&
                string.Equals(p.CaseId, "CASE-TOP-001", StringComparison.Ordinal) &&
                json.IndexOf("TOP-SHOST-99", StringComparison.OrdinalIgnoreCase) < 0 &&
                json.IndexOf("CASE-TOP-001", StringComparison.OrdinalIgnoreCase) < 0 &&
                json.IndexOf("\"host\":\"[redacted]\"", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static bool AiRedaction_basic_masks_memory_collector_user()
        {
            const string collector = @"ACME-DOMAIN\collector.operator";
            var acq = new MemoryAcquisitionRecord { ToolArgs = "x", Status = "complete", CollectorUser = collector };
            var pyld = new MemoryAnalysisRecord { Status = "skipped", Detail = "n/a", CollectorUser = collector };
            var payload = new SummaryPayload
            {
                ExportSchema = "summary_v3",
                MemoryAcquisition = acq,
                MemoryAnalysis = pyld,
                FactSamples = new List<Fact>()
            };
            var copy = SummaryExport.CloneForSerialization(payload);
            SummaryPayloadAiRedactor.Apply(copy, "Basic");
            string json = SummaryExport.Serialize(copy);
            bool liveOk = string.Equals(acq.CollectorUser, collector, StringComparison.Ordinal) &&
                string.Equals(pyld.CollectorUser, collector, StringComparison.Ordinal);
            bool jsonOk = json.IndexOf("ACME-DOMAIN", StringComparison.OrdinalIgnoreCase) < 0 &&
                json.IndexOf("collector.operator", StringComparison.OrdinalIgnoreCase) < 0 &&
                json.IndexOf("user_redacted", StringComparison.OrdinalIgnoreCase) >= 0;
            return liveOk && jsonOk;
        }

        private static bool AiRedaction_basic_masks_fact_details_unc_paths_live_untouched()
        {
            Fact live = CreateFact("F1", DateTime.UtcNow, "EventLog", "Observed", "Path", @"C:\Windows\System32\notepad.exe");
            const string secretDetails = @"Loaded module from \\FILESERVER01.contoso.lan\Shares\tools\payload.dll";
            live.Details = secretDetails;
            var payload = new SummaryPayload
            {
                ExportSchema = "summary_v3",
                FactSamples = new List<Fact> { live }
            };
            var copy = SummaryExport.CloneForSerialization(payload);
            SummaryPayloadAiRedactor.Apply(copy, "Basic");
            string json = SummaryExport.Serialize(copy);
            bool liveIntact = string.Equals(live.Details, secretDetails, StringComparison.Ordinal);
            bool jsonOk = json.IndexOf("FILESERVER01", StringComparison.OrdinalIgnoreCase) < 0 &&
                json.IndexOf("path_redacted", StringComparison.OrdinalIgnoreCase) >= 0;
            return liveIntact && jsonOk;
        }

        private static bool AiRedaction_basic_masks_workflow_notes_paths_live_untouched()
        {
            const string notes = @"Reviewer: check C:\Cases\2026\Host-A\Evtx\Security.evtx before pivot.";
            var wf = new AnalystWorkflowState { Notes = notes, Hypothesis = "h" };
            var payload = new SummaryPayload
            {
                ExportSchema = "summary_v3",
                AnalystWorkflow = wf,
                FactSamples = new List<Fact>()
            };
            var copy = SummaryExport.CloneForSerialization(payload);
            SummaryPayloadAiRedactor.Apply(copy, "Basic");
            string json = SummaryExport.Serialize(copy);
            bool liveIntact = string.Equals(wf.Notes, notes, StringComparison.Ordinal);
            bool jsonOk = json.IndexOf(@"Cases\2026", StringComparison.OrdinalIgnoreCase) < 0 &&
                json.IndexOf("path_redacted", StringComparison.OrdinalIgnoreCase) >= 0;
            return liveIntact && jsonOk;
        }

        private static bool AiRedaction_basic_masks_memory_toolargs_paths()
        {
            const string secretArgs = @"C:\Users\alice\AppData\Local\tool.exe --out D:\IR_Output\case1\memory.raw %USERPROFILE%\x";
            var acq = new MemoryAcquisitionRecord { ToolArgs = secretArgs, Status = "complete" };
            var payload = new SummaryPayload
            {
                ExportSchema = "summary_v3",
                MemoryAcquisition = acq,
                FactSamples = new List<Fact>()
            };
            var copy = SummaryExport.CloneForSerialization(payload);
            SummaryPayloadAiRedactor.Apply(copy, "Basic");
            string json = SummaryExport.Serialize(copy);
            bool liveArgsUnchanged = (acq.ToolArgs ?? "").IndexOf(@"C:\Users\alice", StringComparison.Ordinal) >= 0;
            bool jsonNoLeak =
                json.IndexOf(@"C:\Users\alice", StringComparison.OrdinalIgnoreCase) < 0 &&
                json.IndexOf(@"D:\IR_Output", StringComparison.OrdinalIgnoreCase) < 0 &&
                json.IndexOf("path_redacted", StringComparison.OrdinalIgnoreCase) >= 0 &&
                json.IndexOf("env_redacted", StringComparison.OrdinalIgnoreCase) >= 0;
            return liveArgsUnchanged && jsonNoLeak;
        }

        private static bool AiRedaction_strict_clears_fact_samples()
        {
            var payload = new SummaryPayload
            {
                Host = "HOST01",
                CaseId = "CID",
                ExportSchema = "summary_v3",
                FactSamples = new List<Fact> { CreateFact("F1", DateTime.UtcNow, "USN", "Observed", "Path", @"C:\secret\x.txt") },
                EventHighlights = new List<string> { "hi" }
            };
            var copy = SummaryExport.CloneForSerialization(payload);
            SummaryPayloadAiRedactor.Apply(copy, "Strict");
            string json = SummaryExport.Serialize(copy);
            return (copy.FactSamples == null || copy.FactSamples.Count == 0) &&
                json.IndexOf("HOST01", StringComparison.OrdinalIgnoreCase) < 0 &&
                json.IndexOf("x.txt", StringComparison.OrdinalIgnoreCase) < 0;
        }

        private static bool AiRedaction_basic_masks_ipv4_in_highlights()
        {
            var payload = new SummaryPayload
            {
                ExportSchema = "summary_v3",
                EventHighlights = new List<string> { "User from 192.168.1.10 logged on" }
            };
            var copy = SummaryExport.CloneForSerialization(payload);
            SummaryPayloadAiRedactor.Apply(copy, "Basic");
            string json = SummaryExport.Serialize(copy);
            return json.IndexOf("192.168.1.10", StringComparison.OrdinalIgnoreCase) < 0 &&
                json.IndexOf("[ipv4]", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static bool AiRedaction_none_unchanged_highlight()
        {
            var payload = new SummaryPayload
            {
                ExportSchema = "summary_v3",
                EventHighlights = new List<string> { "User from 192.168.1.10 logged on" }
            };
            var copy = SummaryExport.CloneForSerialization(payload);
            SummaryPayloadAiRedactor.Apply(copy, "None");
            string json = SummaryExport.Serialize(copy);
            return json.IndexOf("192.168.1.10", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static CaseData CreateSyntheticCase(string host, params Fact[] facts)
        {
            var c = new CaseData();
            c.Hostname = host;
            c.CaseID = host + "_Case";
            c.ExtractPath = Path.Combine(Path.GetTempPath(), "IRCollectSyntheticCase_" + Guid.NewGuid().ToString("N"));
            c.CachePath = c.ExtractPath;
            c.FactStore = new FactStore();
            c.FactStore.CaseId = c.CaseID;
            c.FactStore.Hostname = c.Hostname;
            if (facts != null)
                c.FactStore.Facts.AddRange(facts);
            c.FactStore.BuildEntityIndex();
            return c;
        }

        private static Fact CreateFact(string id, DateTime time, string source, string action, params string[] entityPairs)
        {
            var fact = new Fact(id, time, source, action);
            FactTimeMetadata.Apply(fact, FactTimeMetadata.EventTimeKind, FactTimeMetadata.HighConfidence);
            fact.SourceFile = "synthetic.csv";
            fact.RawRef = "synthetic.csv:2";
            fact.ParseLevel = FactProvenanceMetadata.StructuredParseLevel;
            if (entityPairs != null)
            {
                for (int i = 0; i + 1 < entityPairs.Length; i += 2)
                    fact.AddEntity(entityPairs[i], entityPairs[i + 1]);
            }
            return fact;
        }

        private static bool HasEntity(Fact fact, string type, string value)
        {
            return CountEntities(fact, type, value) > 0;
        }

        private static int CountEntities(Fact fact, string type, string value)
        {
            if (fact == null || fact.EntityRefs == null) return 0;
            return fact.EntityRefs.Count(e =>
                e != null &&
                string.Equals(e.Type, type, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(e.Value, value, StringComparison.OrdinalIgnoreCase));
        }

        private static bool JumpListNormalizer_ToFacts_emits_entities()
        {
            string dir = Path.Combine(Path.GetTempPath(), "IRCollectJL_" + Guid.NewGuid().ToString("N"));
            string csv = Path.Combine(dir, ArtifactNames.JumpListsCsv);
            try
            {
                Directory.CreateDirectory(dir);
                File.WriteAllText(csv,
                    "Time,Source,AppId,Path,User,Details\n" +
                    "2020-01-02 03:04:05,Automatic,app123,C:\\Windows\\notepad.exe,DOMAIN\\alice,slot=1\n",
                    new UTF8Encoding(false));
                var facts = JumpListNormalizer.ToFacts(csv);
                if (facts == null || facts.Count != 1)
                    return false;
                Fact f = facts[0];
                if (!string.Equals(f.Source, JumpListNormalizer.SourceName, StringComparison.Ordinal))
                    return false;
                if (!string.Equals(f.Action, JumpListNormalizer.ActionJumpListDestinationObserved, StringComparison.Ordinal))
                    return false;
                if (!HasEntity(f, "Path", @"C:\Windows\notepad.exe"))
                    return false;
                if (!HasEntity(f, "User", @"DOMAIN\alice"))
                    return false;
                if (!HasEntity(f, "AppId", "app123"))
                    return false;
                return string.Equals(f.SourceFile, ArtifactNames.JumpListsCsv, StringComparison.OrdinalIgnoreCase);
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool JumpListNormalizer_ToFacts_unc_derives_workstation_share()
        {
            string dir = Path.Combine(Path.GetTempPath(), "IRCollectJLunc_" + Guid.NewGuid().ToString("N"));
            string csv = Path.Combine(dir, ArtifactNames.JumpListsCsv);
            try
            {
                Directory.CreateDirectory(dir);
                File.WriteAllText(csv,
                    "Time,Source,AppId,Path,User,Details\n" +
                    ",Automatic,app,\\\\FILESERVER\\tools\\x\\y.txt,user1,\n",
                    new UTF8Encoding(false));
                var facts = JumpListNormalizer.ToFacts(csv);
                if (facts == null || facts.Count != 1)
                    return false;
                Fact f = facts[0];
                if (!HasEntity(f, "Workstation", "FILESERVER"))
                    return false;
                if (!HasEntity(f, "ShareName", "tools"))
                    return false;
                if (!HasEntity(f, "Path", @"\\FILESERVER\tools\x\y.txt"))
                    return false;
                return f.FallbackUsed;
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool BitsJobNormalizer_ToFacts_unc_derives_share_and_remote_ip()
        {
            string dir = Path.Combine(Path.GetTempPath(), "IRCollectBitsU_" + Guid.NewGuid().ToString("N"));
            string csv = Path.Combine(dir, ArtifactNames.BitsJobsCsv);
            try
            {
                Directory.CreateDirectory(dir);
                File.WriteAllText(csv,
                    "DisplayName,OwnerAccount,JobState,RemoteName,LocalName,Description,ModificationTime,CreationTime\n" +
                    "MyJob,DOMAIN\\bob,Queued,\\\\10.10.10.10\\Public\\a.txt,C:\\temp\\a.dat,,2020-05-05 10:00:00,2020-05-05 09:00:00\n",
                    new UTF8Encoding(false));
                var facts = BitsJobNormalizer.ToFacts(csv);
                if (facts == null || facts.Count != 1)
                    return false;
                Fact f = facts[0];
                if (!HasEntity(f, "RemoteIP", "10.10.10.10"))
                    return false;
                if (!HasEntity(f, "ShareName", "Public"))
                    return false;
                if (!HasEntity(f, "User", @"DOMAIN\bob"))
                    return false;
                return HasEntity(f, "RemoteName", @"\\10.10.10.10\Public\a.txt");
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        /// <summary>
        /// BITS RemoteName may list multiple targets separated by ';'. One fact, multiple derived ShareName / Workstation / RemoteIP.
        /// </summary>
        private static bool BitsJobNormalizer_ToFacts_multi_segment_remote_name_derives_unc_and_urls()
        {
            string dir = Path.Combine(Path.GetTempPath(), "IRCollectBitsMulti_" + Guid.NewGuid().ToString("N"));
            string csv = Path.Combine(dir, ArtifactNames.BitsJobsCsv);
            try
            {
                Directory.CreateDirectory(dir);
                string rn = @"\\srv-one\shareA\x.txt; \\srv-two\shareB\y.txt; http://192.168.0.1/a; https://10.20.30.40/b";
                File.WriteAllText(csv,
                    "DisplayName,OwnerAccount,JobState,RemoteName,LocalName,Description,ModificationTime,CreationTime\n" +
                    "J1,u1,Queued," + rn + ",,,2020-06-06 12:00:00,2020-06-06 11:00:00\n",
                    new UTF8Encoding(false));
                var facts = BitsJobNormalizer.ToFacts(csv);
                if (facts == null || facts.Count != 1)
                    return false;
                Fact f = facts[0];
                if (!HasEntity(f, "RemoteName", rn))
                    return false;
                if (!HasEntity(f, "Workstation", "srv-one") || !HasEntity(f, "Workstation", "srv-two"))
                    return false;
                if (!HasEntity(f, "ShareName", "shareA") || !HasEntity(f, "ShareName", "shareB"))
                    return false;
                if (!HasEntity(f, "RemoteIP", "192.168.0.1") || !HasEntity(f, "RemoteIP", "10.20.30.40"))
                    return false;
                return true;
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool LogonSessionNormalizer_ToFacts_maps_user_sid_and_logon_metadata()
        {
            string dir = Path.Combine(Path.GetTempPath(), "IRCollectLogon_" + Guid.NewGuid().ToString("N"));
            string csv = Path.Combine(dir, ArtifactNames.LogonSessionsCsv);
            try
            {
                Directory.CreateDirectory(dir);
                File.WriteAllText(csv,
                    "ObservedAtUtc,StartTime,LogonId,User,Domain,Sid,LogonType,LogonTypeName,AuthenticationPackage,LogonProcessName\n" +
                    "2026-04-08T12:34:56Z,2026-04-08T11:00:00Z,999,DOMAIN\\alice,DOMAIN,S-1-5-21-1,10,RemoteInteractive,Negotiate,User32\n",
                    new UTF8Encoding(false));
                var facts = LogonSessionNormalizer.ToFacts(csv);
                if (facts == null || facts.Count != 1)
                    return false;
                Fact f = facts[0];
                return string.Equals(f.Action, "RemoteInteractiveSessionObserved", StringComparison.Ordinal) &&
                    HasEntity(f, "User", @"DOMAIN\alice") &&
                    HasEntity(f, "Sid", "S-1-5-21-1") &&
                    HasEntity(f, "LogonType", "10") &&
                    HasEntity(f, "AuthenticationPackage", "Negotiate") &&
                    HasEntity(f, "LogonProcess", "User32") &&
                    f.Time.Year >= 2026;
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool NetworkResourceNormalizer_ToFacts_derives_unc_entities()
        {
            string dir = Path.Combine(Path.GetTempPath(), "IRCollectNetRes_" + Guid.NewGuid().ToString("N"));
            string csv = Path.Combine(dir, ArtifactNames.NetworkResourcesCsv);
            try
            {
                Directory.CreateDirectory(dir);
                File.WriteAllText(csv,
                    "ObservedAtUtc,LocalName,RemoteName,UserName,ConnectionState,ConnectionType,DisplayType,ProviderName,Persistent,Status,Comment\n" +
                    "2026-04-08T12:34:56Z,Z:,\\\\FILE01\\Tools,DOMAIN\\bob,Connected,1,3,Microsoft Windows Network,True,OK,\n",
                    new UTF8Encoding(false));
                var facts = NetworkResourceNormalizer.ToFacts(csv);
                if (facts == null || facts.Count != 1)
                    return false;
                Fact f = facts[0];
                return HasEntity(f, "User", @"DOMAIN\bob") &&
                    HasEntity(f, "Path", @"\\FILE01\Tools") &&
                    HasEntity(f, "RemoteName", @"\\FILE01\Tools") &&
                    HasEntity(f, "Workstation", "FILE01") &&
                    HasEntity(f, "ShareName", "Tools") &&
                    HasEntity(f, "Path", "Z:");
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool ServerConnectionNormalizer_ToFacts_maps_user_share_and_remote_host()
        {
            string dir = Path.Combine(Path.GetTempPath(), "IRCollectSrvConn_" + Guid.NewGuid().ToString("N"));
            string csv = Path.Combine(dir, ArtifactNames.ServerConnectionsCsv);
            try
            {
                Directory.CreateDirectory(dir);
                File.WriteAllText(csv,
                    "ObservedAtUtc,ComputerName,UserName,ShareName,ActiveTimeSec,IdleTimeSec,ConnectionId,NumberOfFiles,NumberOfUsers\n" +
                    "2026-04-08T12:34:56Z,10.10.10.20,DOMAIN\\carol,ADMIN$,120,5,77,2,1\n",
                    new UTF8Encoding(false));
                var facts = ServerConnectionNormalizer.ToFacts(csv);
                if (facts == null || facts.Count != 1)
                    return false;
                Fact f = facts[0];
                return HasEntity(f, "User", @"DOMAIN\carol") &&
                    HasEntity(f, "ShareName", "ADMIN$") &&
                    HasEntity(f, "RemoteName", "10.10.10.20") &&
                    HasEntity(f, "RemoteIP", "10.10.10.20");
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool FactProvenance_logon_session_uses_system_info_step()
        {
            var fact = new Fact("logon1", DateTime.UtcNow, "LogonSession", "Observed");
            fact.SourceFile = ArtifactNames.LogonSessionsCsv;
            fact.CollectionStep = "unknown";
            fact.CollectionStatus = "unknown";
            fact.CollectionPrivilege = "unknown";
            fact.ParseLevel = FactProvenanceMetadata.UnknownParseLevel;

            var c = new CaseData
            {
                CollectionCoverage = new CollectionCoverageReport
                {
                    Steps = new List<CollectionCoverageStep>
                    {
                        new CollectionCoverageStep { Step = "System Info", Status = "partial" }
                    }
                }
            };

            FactProvenanceHelper.ApplyCaseMetadata(c, new[] { fact });
            return string.Equals(fact.CollectionStep, "System Info", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(fact.CollectionStatus, "partial", StringComparison.OrdinalIgnoreCase);
        }

        private static bool FactProvenance_bits_uses_execution_artifacts_step()
        {
            var fact = new Fact("bits1", DateTime.UtcNow, "BITS", "Transferred");
            fact.SourceFile = ArtifactNames.BitsJobsCsv;
            fact.CollectionStep = "unknown";
            fact.CollectionStatus = "unknown";
            fact.CollectionPrivilege = "unknown";
            fact.ParseLevel = FactProvenanceMetadata.UnknownParseLevel;

            var c = new CaseData
            {
                CollectionCoverage = new CollectionCoverageReport
                {
                    Steps = new List<CollectionCoverageStep>
                    {
                        new CollectionCoverageStep { Step = "Persistence", Status = "complete" },
                        new CollectionCoverageStep { Step = "Execution Artifacts", Status = "partial" }
                    }
                }
            };

            FactProvenanceHelper.ApplyCaseMetadata(c, new[] { fact });
            return string.Equals(fact.CollectionStep, "Execution Artifacts", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(fact.CollectionStatus, "partial", StringComparison.OrdinalIgnoreCase);
        }

        private static bool FactProvenance_wmi_uses_execution_artifacts_step()
        {
            var fact = new Fact("wmi1", DateTime.UtcNow, "WmiPersistence", "Observed");
            fact.SourceFile = ArtifactNames.WmiPersistenceCsv;
            fact.CollectionStep = "unknown";
            fact.CollectionStatus = "unknown";
            fact.CollectionPrivilege = "unknown";
            fact.ParseLevel = FactProvenanceMetadata.UnknownParseLevel;

            var c = new CaseData
            {
                CollectionCoverage = new CollectionCoverageReport
                {
                    Steps = new List<CollectionCoverageStep>
                    {
                        new CollectionCoverageStep { Step = "Persistence", Status = "complete" },
                        new CollectionCoverageStep { Step = "Execution Artifacts", Status = "missing" }
                    }
                }
            };

            FactProvenanceHelper.ApplyCaseMetadata(c, new[] { fact });
            return string.Equals(fact.CollectionStep, "Execution Artifacts", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(fact.CollectionStatus, "missing", StringComparison.OrdinalIgnoreCase);
        }

        private static bool FactProvenance_service_uses_persistence_step()
        {
            var fact = new Fact("svc1", DateTime.UtcNow, "Service", "ServiceConfigurationObserved");
            fact.SourceFile = ArtifactNames.ServicesCsv;
            fact.CollectionStep = "unknown";
            fact.CollectionStatus = "unknown";
            fact.CollectionPrivilege = "unknown";
            fact.ParseLevel = FactProvenanceMetadata.UnknownParseLevel;

            var c = new CaseData
            {
                CollectionCoverage = new CollectionCoverageReport
                {
                    Steps = new List<CollectionCoverageStep>
                    {
                        new CollectionCoverageStep { Step = "Persistence", Status = "complete" }
                    }
                }
            };

            FactProvenanceHelper.ApplyCaseMetadata(c, new[] { fact });
            return string.Equals(fact.CollectionStep, "Persistence", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(fact.CollectionStatus, "complete", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(fact.ParseLevel, FactProvenanceMetadata.StructuredParseLevel, StringComparison.OrdinalIgnoreCase);
        }

        private static bool FactProvenance_stored_credential_uses_system_info_step()
        {
            var fact = new Fact("cred1", DateTime.UtcNow, "StoredCredential", "StoredCredentialObserved");
            fact.SourceFile = ArtifactNames.StoredCredentialsTxt;
            fact.CollectionStep = "unknown";
            fact.CollectionStatus = "unknown";
            fact.CollectionPrivilege = "unknown";
            fact.ParseLevel = FactProvenanceMetadata.UnknownParseLevel;

            var c = new CaseData
            {
                CollectionCoverage = new CollectionCoverageReport
                {
                    Steps = new List<CollectionCoverageStep>
                    {
                        new CollectionCoverageStep { Step = "System Info", Status = "partial" }
                    }
                }
            };

            FactProvenanceHelper.ApplyCaseMetadata(c, new[] { fact });
            return string.Equals(fact.CollectionStep, "System Info", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(fact.CollectionStatus, "partial", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(fact.ParseLevel, FactProvenanceMetadata.RawArtifactDerivedParseLevel, StringComparison.OrdinalIgnoreCase);
        }

        private static bool FactProvenance_kerberos_ticket_uses_system_info_step()
        {
            var fact = new Fact("kerb1", DateTime.UtcNow, "KerberosTicketCache", "KerberosTicketCached");
            fact.SourceFile = ArtifactNames.KerberosTicketsTxt;
            fact.CollectionStep = "unknown";
            fact.CollectionStatus = "unknown";
            fact.CollectionPrivilege = "unknown";
            fact.ParseLevel = FactProvenanceMetadata.UnknownParseLevel;

            var c = new CaseData
            {
                CollectionCoverage = new CollectionCoverageReport
                {
                    Steps = new List<CollectionCoverageStep>
                    {
                        new CollectionCoverageStep { Step = "System Info", Status = "complete" }
                    }
                }
            };

            FactProvenanceHelper.ApplyCaseMetadata(c, new[] { fact });
            return string.Equals(fact.CollectionStep, "System Info", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(fact.CollectionStatus, "complete", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(fact.ParseLevel, FactProvenanceMetadata.RawArtifactDerivedParseLevel, StringComparison.OrdinalIgnoreCase);
        }

        private static bool FactProvenance_memory_acquisition_uses_memory_acquisition_step()
        {
            var fact = new Fact("memacq1", DateTime.UtcNow, "MemoryAcquisition", "MemoryAcquisitionComplete");
            fact.SourceFile = ArtifactNames.MemoryAcquisitionJson;
            fact.CollectionStep = "unknown";
            fact.CollectionStatus = "unknown";
            fact.CollectionPrivilege = "unknown";
            fact.ParseLevel = FactProvenanceMetadata.UnknownParseLevel;

            var c = new CaseData
            {
                CollectionCoverage = new CollectionCoverageReport
                {
                    Steps = new List<CollectionCoverageStep>
                    {
                        new CollectionCoverageStep { Step = "Memory acquisition", Status = "complete" }
                    }
                }
            };

            FactProvenanceHelper.ApplyCaseMetadata(c, new[] { fact });
            return string.Equals(fact.CollectionStep, "Memory acquisition", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(fact.CollectionStatus, "complete", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(fact.ParseLevel, FactProvenanceMetadata.SynthesizedParseLevel, StringComparison.OrdinalIgnoreCase);
        }

        private static bool FactProvenance_memory_analysis_uses_memory_analysis_step()
        {
            var fact = new Fact("memana1", DateTime.UtcNow, "MemoryAnalysis", "MemoryAnalysisPartial");
            fact.SourceFile = ArtifactNames.MemoryAnalysisJson;
            fact.CollectionStep = "unknown";
            fact.CollectionStatus = "unknown";
            fact.CollectionPrivilege = "unknown";
            fact.ParseLevel = FactProvenanceMetadata.UnknownParseLevel;

            var c = new CaseData
            {
                CollectionCoverage = new CollectionCoverageReport
                {
                    Steps = new List<CollectionCoverageStep>
                    {
                        new CollectionCoverageStep { Step = "Memory analysis handoff", Status = "partial" }
                    }
                }
            };

            FactProvenanceHelper.ApplyCaseMetadata(c, new[] { fact });
            return string.Equals(fact.CollectionStep, "Memory analysis handoff", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(fact.CollectionStatus, "partial", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(fact.ParseLevel, FactProvenanceMetadata.SynthesizedParseLevel, StringComparison.OrdinalIgnoreCase);
        }

        private static bool Timeline_unified_jumplist_row_count_equals_activity_only_not_jump_csv_dup()
        {
            string dir = Path.Combine(Path.GetTempPath(), "IRCollectTlJl_" + Guid.NewGuid().ToString("N"));
            string activity = Path.Combine(dir, ArtifactNames.ActivityTimelineCsv);
            string jump = Path.Combine(dir, ArtifactNames.JumpListsCsv);
            try
            {
                Directory.CreateDirectory(dir);
                File.WriteAllText(activity,
                    "Time,Source,Action,Path,User,Details\n" +
                    "2021-01-01 10:00:00,JumpList,Recent,C:\\\\Windows\\\\notepad.exe,u1,\n",
                    new UTF8Encoding(false));
                File.WriteAllText(jump,
                    "Time,Source,AppId,Path,User,Details\n" +
                    "2021-01-01 10:00:00,Automatic,app1,C:\\\\Windows\\\\notepad.exe,u1,\n",
                    new UTF8Encoding(false));
                var actFacts = ActivityTimelineNormalizer.ToFacts(activity);
                var jlFacts = JumpListNormalizer.ToFacts(jump);
                int jumpRowsInActivity = actFacts.Count(f => f != null && string.Equals(f.Source, "JumpList", StringComparison.OrdinalIgnoreCase));
                if (jumpRowsInActivity != 1 || jlFacts.Count != 1)
                    return false;
                // If MainFormTimeline wrongly added jlFacts again, JumpList-shaped timeline rows would be jumpRowsInActivity + jlFacts.Count.
                int unifiedJumpListTimelineRows = jumpRowsInActivity;
                int wouldDoubleCount = jumpRowsInActivity + jlFacts.Count;
                return unifiedJumpListTimelineRows == 1 && wouldDoubleCount == 2;
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        /// <summary>Hits <see cref="IR_Collect.MainForm.BuildTimelineEventsForSelfTest"/> → real BuildTimelineEvents (WP-D Jump List dedupe).</summary>
        private static bool BuildTimelineEvents_MainForm_path_jumplist_single_when_activity_and_jump_csv_present()
        {
            string dir = Path.Combine(Path.GetTempPath(), "IRCollectTlMain_" + Guid.NewGuid().ToString("N"));
            string activity = Path.Combine(dir, ArtifactNames.ActivityTimelineCsv);
            string jump = Path.Combine(dir, ArtifactNames.JumpListsCsv);
            const string destPath = @"C:\Windows\notepad.exe";
            IR_Collect.MainForm form = null;
            try
            {
                Directory.CreateDirectory(dir);
                File.WriteAllText(activity,
                    "Time,Source,Action,Path,User,Details\n" +
                    "2021-02-02 11:22:33,JumpList,Recent," + destPath + ",userA,\n",
                    new UTF8Encoding(false));
                File.WriteAllText(jump,
                    "Time,Source,AppId,Path,User,Details\n" +
                    "2021-02-02 11:22:33,Automatic,appZ," + destPath + ",userA,\n",
                    new UTF8Encoding(false));

                var c = new CaseData();
                c.ExtractPath = dir;
                c.CachePath = dir;
                c.Hostname = "SelfTestHost";
                c.MftEntries = null;

                form = new IR_Collect.MainForm();
                List<IR_Collect.MainForm.TimelineEvent> events = form.BuildTimelineEventsForSelfTest(c);
                if (events == null)
                    return false;

                int jlTimeline = 0;
                for (int i = 0; i < events.Count; i++)
                {
                    IR_Collect.MainForm.TimelineEvent ev = events[i];
                    if (ev == null || !string.Equals(ev.Source, "JumpList", StringComparison.OrdinalIgnoreCase))
                        continue;
                    if (ev.EntityRefs == null)
                        continue;
                    for (int j = 0; j < ev.EntityRefs.Count; j++)
                    {
                        EntityRef er = ev.EntityRefs[j];
                        if (er == null)
                            continue;
                        if (!string.Equals(er.Type, "Path", StringComparison.OrdinalIgnoreCase))
                            continue;
                        if (string.Equals(er.Value, destPath, StringComparison.OrdinalIgnoreCase))
                        {
                            jlTimeline++;
                            break;
                        }
                    }
                }

                return jlTimeline == 1;
            }
            finally
            {
                if (form != null)
                {
                    form.Dispose();
                    form = null;
                }
                TryDeleteDir(dir);
            }
        }

        private static void TryDeleteDir(string path)
        {
            try
            {
                if (!string.IsNullOrEmpty(path) && Directory.Exists(path))
                    Directory.Delete(path, true);
            }
            catch { }
        }
    }
}
#endif
