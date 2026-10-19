#pragma once

#include "ph_graph.h"

void ph_collect_core(PH_GRAPH *graph);
void ph_collect_token_privileges(PH_GRAPH *graph);
void ph_collect_services(PH_GRAPH *graph);
void ph_collect_unquoted_service_paths(PH_GRAPH *graph);
void ph_collect_writable_path(PH_GRAPH *graph);
void ph_collect_always_install_elevated(PH_GRAPH *graph);
void ph_collect_uac(PH_GRAPH *graph);
void ph_collect_scheduled_tasks(PH_GRAPH *graph);
void ph_collect_autoruns(PH_GRAPH *graph);
void ph_collect_service_registry_keys(PH_GRAPH *graph);
void ph_collect_writable_program_dirs(PH_GRAPH *graph);
void ph_collect_service_recovery(PH_GRAPH *graph);
void ph_collect_stored_credentials(PH_GRAPH *graph);
void ph_collect_gpp_passwords(PH_GRAPH *graph);
void ph_collect_unattend_files(PH_GRAPH *graph);
void ph_collect_ps_history(PH_GRAPH *graph);
void ph_collect_sensitive_files(PH_GRAPH *graph);
void ph_collect_cross_user_profiles(PH_GRAPH *graph);
void ph_collect_jit_admin_tools(PH_GRAPH *graph);
void ph_collect_print_spooler(PH_GRAPH *graph);
void ph_collect_wsus_config(PH_GRAPH *graph);
void ph_collect_com_hijacking(PH_GRAPH *graph);
void ph_collect_named_pipe_permissions(PH_GRAPH *graph);
void ph_collect_cached_credentials(PH_GRAPH *graph);
void ph_collect_webclient_relay(PH_GRAPH *graph);
void ph_collect_sccm_credentials(PH_GRAPH *graph);
void ph_collect_wmi_subscriptions(PH_GRAPH *graph);
void ph_collect_shadow_copy_files(PH_GRAPH *graph);
void ph_collect_credential_login_paths(PH_GRAPH *graph);

