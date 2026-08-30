# kotlin-tor ↔ C Tor parity TODO (generated backlog)

_Generated 2026-08-30 from `docs/generated/ctor_master_inventory.csv`._

**Not a claim of completeness.** Elevate D2→D3 one grade at a time per `docs/PARITY_PROCESS.md`.
Source queue: [`CTOR_MISSING_INVENTORY.md`](CTOR_MISSING_INVENTORY.md). Re-run:

```bash
export CTOR_SRC=/path/to/tor
python3 scripts/ctor_inventory_scan.py
python3 scripts/gen_parity_todo.py
```

## Snapshot

| Depth | Count |
|-------|------:|
| D3 | 1683 |
| **D2 (open elevate)** | **450** |
| N/A (platform/stub/OOS) | 203 |

D2 breakdown: **241 L3 ops** + **209 L4 options**. L1 modules and L2 product types are already ≥D3 (or N/A).

## How to use this TODO

1. Work **priority modules** in order: `feature/control` → `feature/nodelist` → `feature/hs` → `feature/relay` → `feature/dirauth` → `app/config` (L4).
2. Each batch ≤25 ops: camelCase aliases + `OP_SEED_DEPTH` + elevation test + rescan.
3. Do **not** mark PARITY_GAPS ✅ until linked inventory rows are D3.

## A. L3 operations still D2 (241)

### `feature/nodelist` — 96 ops

| Family / batch | Count | Example units | Kotlin primary |
|----------------|------:|---------------|----------------|
| `router_*` | 36 | `router_describe`, `router_get_verbose_nickname`, `router_addr_is_trusted_dir_type`, `router_digest_is_fallback_dir`, … (+32) | `dir/Describe.kt` |
| `routerset_*` | 21 | `routerset_add_unknown_ccs`, `routerset_contains`, `routerset_contains_bridge`, `routerset_contains_extendinfo`, … (+17) | `dir/RouterSet.kt` |
| `tor_cert_*` | 10 | `tor_cert_checksig`, `tor_cert_create_ed25519`, `tor_cert_create_raw`, `tor_cert_describe_signature_status`, … (+6) | `dir/TorCert.kt` |
| `or_handshake_*` | 5 | `or_handshake_certs_check_both`, `or_handshake_certs_ed25519_ok`, `or_handshake_certs_free_`, `or_handshake_certs_new`, … (+1) | `dir/TorCert.kt` |
| `trusted_dirs_*` | 4 | `trusted_dirs_flush_certs_to_disk`, `trusted_dirs_load_certs_from_string`, `trusted_dirs_reload_certs`, `trusted_dirs_remove_old_certs` | `dir/AuthCert.kt` |
| `trusted_dir_*` | 4 | `trusted_dir_server_add_dirport`, `trusted_dir_server_get_dirport`, `trusted_dir_server_get_dirport_exact`, `trusted_dir_server_new` | `dir/DirList.kt` |
| `we_fetch_*` | 2 | `we_fetch_microdescriptors`, `we_fetch_router_descriptors` | `dir/Microdesc.kt` |
| `nodefamily_free_*` | 2 | `nodefamily_free_`, `nodefamily_free_all` | `dir/NodeFamily.kt` |
| `routerstatus_describe_*` | 1 | `routerstatus_describe` | `dir/Describe.kt` |
| `routerstatus_format_*` | 1 | `routerstatus_format_entry` | `dir/FmtRouterStatus.kt` |
| `update_microdesc_*` | 1 | `update_microdesc_downloads` | `dir/Microdesc.kt` |
| `update_microdescs_*` | 1 | `update_microdescs_from_networkstatus` | `dir/Microdesc.kt` |
| `we_use_*` | 1 | `we_use_microdescriptors_for_circuits` | `dir/Microdesc.kt` |
| `scale_array_*` | 1 | `scale_array_elements_to_u64` | `dir/NodeSelect.kt` |
| `nodefamily_format_*` | 1 | `nodefamily_format` | `dir/NodeFamily.kt` |
| `nodefamily_from_*` | 1 | `nodefamily_from_members` | `dir/NodeFamily.kt` |
| `nodefamily_parse_*` | 1 | `nodefamily_parse` | `dir/NodeFamily.kt` |
| `routerinfo_get_*` | 1 | `routerinfo_get_ed25519_id` | `dir/RouterInfo.kt` |
| `refresh_all_*` | 1 | `refresh_all_country_info` | `dir/RouterList.kt` |
| `tor_make_*` | 1 | `tor_make_rsa_ed25519_crosscert` | `dir/TorCert.kt` |

### `feature/relay` — 145 ops

| Family / batch | Count | Example units | Kotlin primary |
|----------------|------:|---------------|----------------|
| `dns_*` | 14 | `dns_cache_handle_oom`, `dns_cache_total_allocation`, `dns_free_all`, `dns_get_cache_entry`, … (+10) | `net/Dns.kt` |
| `relay_*` | 12 | `relay_config_free_all`, `relay_get_effective_bwburst`, `relay_addr_learn_from_dirauth`, `relay_address_new_suggestion`, … (+8) | `relay/RelayConfig.kt` |
| `options_act_*` | 10 | `options_act_bridge_stats`, `options_act_relay`, `options_act_relay_accounting`, `options_act_relay_bandwidth`, … (+6) | `relay/RelayConfig.kt` |
| `options_validate_*` | 9 | `options_validate_publish_server`, `options_validate_relay_accounting`, `options_validate_relay_bandwidth`, `options_validate_relay_info`, … (+5) | `relay/RelayConfig.kt` |
| `circuit_*` | 8 | `circuit_choose_ip_ap_for_extend`, `circuit_extend`, `circuit_extend_add_ed25519_helper`, `circuit_extend_add_ipv4_helper`, … (+4) | `circuit/CircuitBuildRelay.kt` |
| `connection_*` | 8 | `connection_dns_remove`, `connection_ext_or_finished_flushing`, `connection_ext_or_process_inbuf`, `connection_ext_or_start_auth`, … (+4) | `net/Dns.kt` |
| `router_*` | 6 | `router_ed25519_id_is_me`, `router_do_reachability_checks`, `router_orport_found_reachable`, `router_orport_seems_reachable`, … (+2) | `relay/RouterKeys.kt` |
| `get_my_*` | 4 | `get_my_declared_family`, `get_my_v3_authority_signing_key`, `get_my_v3_legacy_cert`, `get_my_v3_legacy_signing_key` | `relay/Router.kt` |
| `get_current_*` | 4 | `get_current_auth_key_cert`, `get_current_auth_keypair`, `get_current_family_id_keys`, `get_current_link_cert_cert` | `relay/RouterKeys.kt` |
| `get_onion_*` | 3 | `get_onion_key_grace_period`, `get_onion_key_lifetime`, `get_onion_key_set_at` | `relay/Router.kt` |
| `mark_my_*` | 3 | `mark_my_descriptor_dirty`, `mark_my_descriptor_dirty_if_too_old`, `mark_my_descriptor_if_omit_ipv6_changes` | `relay/Router.kt` |
| `get_master_*` | 3 | `get_master_identity_key`, `get_master_identity_keypair`, `get_master_rsa_crosscert` | `relay/RouterKeys.kt` |
| `onion_pending_*` | 2 | `onion_pending_add`, `onion_pending_remove` | `relay/OnionQueue.kt` |
| `authchallenge_type_*` | 2 | `authchallenge_type_is_better`, `authchallenge_type_is_supported` | `relay/RelayHandshake.kt` |
| `check_descriptor_*` | 2 | `check_descriptor_bandwidth_changed`, `check_descriptor_ipaddress_changed` | `relay/Router.kt` |
| `init_keys_*` | 2 | `init_keys`, `init_keys_client` | `relay/Router.kt` |
| `load_family_*` | 2 | `load_family_id_keys`, `load_family_id_keys_impl` | `relay/RouterKeys.kt` |
| `pt_get_*` | 2 | `pt_get_bindaddr_from_config`, `pt_get_options_for_server_transport` | `relay/TransportConfig.kt` |
| `circuitbuild_warn_*` | 1 | `circuitbuild_warn_client_extend` | `circuit/CircuitBuildRelay.kt` |
| `onionskin_answer_*` | 1 | `onionskin_answer` | `circuit/CircuitBuildRelay.kt` |
| `assert_connection_*` | 1 | `assert_connection_edge_not_dns_pending` | `net/Dns.kt` |
| `configured_nameserver_*` | 1 | `configured_nameserver_address` | `net/Dns.kt` |
| `dump_dns_*` | 1 | `dump_dns_mem_usage` | `net/Dns.kt` |
| `has_dns_*` | 1 | `has_dns_init_failed` | `net/Dns.kt` |
| `number_of_*` | 1 | `number_of_configured_nameservers` | `net/Dns.kt` |
| `ext_orport_*` | 1 | `ext_orport_free_all` | `pt/ExtOrPort.kt` |
| `get_ext_*` | 1 | `get_ext_or_auth_cookie_file_name` | `pt/ExtOrPort.kt` |
| `handle_client_*` | 1 | `handle_client_auth_nonce` | `pt/ExtOrPort.kt` |
| `init_ext_*` | 1 | `init_ext_or_cookie_authentication` | `pt/ExtOrPort.kt` |
| `clear_pending_*` | 1 | `clear_pending_onions` | `relay/OnionQueue.kt` |
| `onion_consensus_*` | 1 | `onion_consensus_has_changed` | `relay/OnionQueue.kt` |
| `onion_next_*` | 1 | `onion_next_task` | `relay/OnionQueue.kt` |
| `onion_num_*` | 1 | `onion_num_pending` | `relay/OnionQueue.kt` |
| `check_bridge_*` | 1 | `check_bridge_distribution_setting` | `relay/RelayConfig.kt` |
| `describe_relay_*` | 1 | `describe_relay_port` | `relay/RelayConfig.kt` |
| `have_enough_*` | 1 | `have_enough_mem_for_dircache` | `relay/RelayConfig.kt` |
| `port_parse_*` | 1 | `port_parse_ports_relay` | `relay/RelayConfig.kt` |
| `port_update_*` | 1 | `port_update_port_set_relay` | `relay/RelayConfig.kt` |
| `port_warn_*` | 1 | `port_warn_nonlocal_ext_orports` | `relay/RelayConfig.kt` |
| `reschedule_descriptor_*` | 1 | `reschedule_descriptor_update_check` | `relay/RelayPeriodic.kt` |
| `client_identity_*` | 1 | `client_identity_key_is_set` | `relay/Router.kt` |
| `consider_publishable_*` | 1 | `consider_publishable_server` | `relay/Router.kt` |
| `construct_ntor_*` | 1 | `construct_ntor_key_map` | `relay/Router.kt` |
| `dup_onion_*` | 1 | `dup_onion_keys` | `relay/Router.kt` |
| `expire_old_*` | 1 | `expire_old_onion_keys` | `relay/Router.kt` |
| `extrainfo_dump_*` | 1 | `extrainfo_dump_to_string` | `relay/Router.kt` |
| `get_platform_*` | 1 | `get_platform_str` | `relay/Router.kt` |
| `get_tlsclient_*` | 1 | `get_tlsclient_identity_key` | `relay/Router.kt` |
| `init_curve25519_*` | 1 | `init_curve25519_keypair_from_file` | `relay/Router.kt` |
| `load_stats_*` | 1 | `load_stats_file` | `relay/Router.kt` |
| `log_addr_*` | 1 | `log_addr_has_changed` | `relay/Router.kt` |
| `create_family_*` | 1 | `create_family_id_key` | `relay/RouterKeys.kt` |
| `generate_ed_*` | 1 | `generate_ed_link_cert` | `relay/RouterKeys.kt` |
| `init_mock_*` | 1 | `init_mock_ed_keys` | `relay/RouterKeys.kt` |
| `is_family_*` | 1 | `is_family_key_fname` | `relay/RouterKeys.kt` |
| `list_family_*` | 1 | `list_family_key_files` | `relay/RouterKeys.kt` |
| `load_ed_*` | 1 | `load_ed_keys` | `relay/RouterKeys.kt` |
| `log_cert_*` | 1 | `log_cert_expiration` | `relay/RouterKeys.kt` |
| `make_ntor_*` | 1 | `make_ntor_onion_key_crosscert` | `relay/RouterKeys.kt` |
| `make_tap_*` | 1 | `make_tap_onion_key_crosscert` | `relay/RouterKeys.kt` |
| `routerkeys_free_*` | 1 | `routerkeys_free_all` | `relay/RouterKeys.kt` |
| `set_family_*` | 1 | `set_family_id_keys` | `relay/RouterKeys.kt` |
| `should_make_*` | 1 | `should_make_new_ed_keys` | `relay/RouterKeys.kt` |
| `warn_about_*` | 1 | `warn_about_family_id_config` | `relay/RouterKeys.kt` |
| `dir_server_*` | 1 | `dir_server_mode` | `relay/RouterMode.kt` |
| `set_server_*` | 1 | `set_server_advertised` | `relay/RouterMode.kt` |
| `get_options_*` | 1 | `get_options_from_transport_options_line` | `relay/TransportConfig.kt` |

#### Nodelist op checklist (all 96)

<details><summary><code>router_*</code> (36)</summary>

- [ ] `L3:feature/nodelist/router_add_extrainfo_to_routerlist`
- [ ] `L3:feature/nodelist/router_add_running_nodes_to_smartlist`
- [ ] `L3:feature/nodelist/router_add_to_routerlist`
- [ ] `L3:feature/nodelist/router_addr_is_trusted_dir_type`
- [ ] `L3:feature/nodelist/router_can_choose_node`
- [ ] `L3:feature/nodelist/router_choose_random_node`
- [ ] `L3:feature/nodelist/router_describe`
- [ ] `L3:feature/nodelist/router_differences_are_cosmetic`
- [ ] `L3:feature/nodelist/router_digest_is_fallback_dir`
- [ ] `L3:feature/nodelist/router_dir_conn_should_skip_reachable_address_check`
- [ ] `L3:feature/nodelist/router_get_advertised_bandwidth`
- [ ] `L3:feature/nodelist/router_get_advertised_bandwidth_capped`
- [ ] `L3:feature/nodelist/router_get_all_orports`
- [ ] `L3:feature/nodelist/router_get_by_descriptor_digest`
- [ ] `L3:feature/nodelist/router_get_by_id_digest`
- [ ] `L3:feature/nodelist/router_get_fallback_dir_servers`
- [ ] `L3:feature/nodelist/router_get_fallback_dir_servers_mutable`
- [ ] `L3:feature/nodelist/router_get_fallback_dirserver_by_digest`
- [ ] `L3:feature/nodelist/router_get_mutable_by_digest`
- [ ] `L3:feature/nodelist/router_get_my_share_of_directory_requests`
- [ ] `L3:feature/nodelist/router_get_orport`
- [ ] `L3:feature/nodelist/router_get_routerlist`
- [ ] `L3:feature/nodelist/router_get_trusted_dir_servers`
- [ ] `L3:feature/nodelist/router_get_trusted_dir_servers_mutable`
- [ ] `L3:feature/nodelist/router_get_trusteddirserver_by_digest`
- [ ] `L3:feature/nodelist/router_get_verbose_nickname`
- [ ] `L3:feature/nodelist/router_has_orport`
- [ ] `L3:feature/nodelist/router_is_already_dir_fetching`
- [ ] `L3:feature/nodelist/router_load_extrainfo_from_string`
- [ ] `L3:feature/nodelist/router_load_routers_from_string`
- [ ] `L3:feature/nodelist/router_pick_directory_server`
- [ ] `L3:feature/nodelist/router_pick_directory_server_impl`
- [ ] `L3:feature/nodelist/router_pick_fallback_dirserver`
- [ ] `L3:feature/nodelist/router_pick_trusteddirserver`
- [ ] `L3:feature/nodelist/router_purpose_from_string`
- [ ] `L3:feature/nodelist/router_purpose_to_string`

</details>

<details><summary><code>routerset_*</code> (21)</summary>

- [ ] `L3:feature/nodelist/routerset_add_unknown_ccs`
- [ ] `L3:feature/nodelist/routerset_contains`
- [ ] `L3:feature/nodelist/routerset_contains_bridge`
- [ ] `L3:feature/nodelist/routerset_contains_extendinfo`
- [ ] `L3:feature/nodelist/routerset_contains_node`
- [ ] `L3:feature/nodelist/routerset_contains_router`
- [ ] `L3:feature/nodelist/routerset_contains_routerstatus`
- [ ] `L3:feature/nodelist/routerset_equal`
- [ ] `L3:feature/nodelist/routerset_free_`
- [ ] `L3:feature/nodelist/routerset_get_all_nodes`
- [ ] `L3:feature/nodelist/routerset_get_countryname`
- [ ] `L3:feature/nodelist/routerset_is_empty`
- [ ] `L3:feature/nodelist/routerset_is_list`
- [ ] `L3:feature/nodelist/routerset_len`
- [ ] `L3:feature/nodelist/routerset_needs_geoip`
- [ ] `L3:feature/nodelist/routerset_new`
- [ ] `L3:feature/nodelist/routerset_parse`
- [ ] `L3:feature/nodelist/routerset_refresh_countries`
- [ ] `L3:feature/nodelist/routerset_subtract_nodes`
- [ ] `L3:feature/nodelist/routerset_to_string`
- [ ] `L3:feature/nodelist/routerset_union`

</details>

<details><summary><code>tor_cert_*</code> (10)</summary>

- [ ] `L3:feature/nodelist/tor_cert_checksig`
- [ ] `L3:feature/nodelist/tor_cert_create_ed25519`
- [ ] `L3:feature/nodelist/tor_cert_create_raw`
- [ ] `L3:feature/nodelist/tor_cert_describe_signature_status`
- [ ] `L3:feature/nodelist/tor_cert_encode_ed22519`
- [ ] `L3:feature/nodelist/tor_cert_eq`
- [ ] `L3:feature/nodelist/tor_cert_free_`
- [ ] `L3:feature/nodelist/tor_cert_get_checkable_sig`
- [ ] `L3:feature/nodelist/tor_cert_opt_eq`
- [ ] `L3:feature/nodelist/tor_cert_parse`

</details>

<details><summary><code>or_handshake_*</code> (5)</summary>

- [ ] `L3:feature/nodelist/or_handshake_certs_check_both`
- [ ] `L3:feature/nodelist/or_handshake_certs_ed25519_ok`
- [ ] `L3:feature/nodelist/or_handshake_certs_free_`
- [ ] `L3:feature/nodelist/or_handshake_certs_new`
- [ ] `L3:feature/nodelist/or_handshake_certs_rsa_ok`

</details>

<details><summary><code>trusted_dirs_*</code> (4)</summary>

- [ ] `L3:feature/nodelist/trusted_dirs_flush_certs_to_disk`
- [ ] `L3:feature/nodelist/trusted_dirs_load_certs_from_string`
- [ ] `L3:feature/nodelist/trusted_dirs_reload_certs`
- [ ] `L3:feature/nodelist/trusted_dirs_remove_old_certs`

</details>

<details><summary><code>trusted_dir_*</code> (4)</summary>

- [ ] `L3:feature/nodelist/trusted_dir_server_add_dirport`
- [ ] `L3:feature/nodelist/trusted_dir_server_get_dirport`
- [ ] `L3:feature/nodelist/trusted_dir_server_get_dirport_exact`
- [ ] `L3:feature/nodelist/trusted_dir_server_new`

</details>

<details><summary><code>we_fetch_*</code> (2)</summary>

- [ ] `L3:feature/nodelist/we_fetch_microdescriptors`
- [ ] `L3:feature/nodelist/we_fetch_router_descriptors`

</details>

<details><summary><code>nodefamily_free_*</code> (2)</summary>

- [ ] `L3:feature/nodelist/nodefamily_free_`
- [ ] `L3:feature/nodelist/nodefamily_free_all`

</details>

<details><summary><code>routerstatus_describe_*</code> (1)</summary>

- [ ] `L3:feature/nodelist/routerstatus_describe`

</details>

<details><summary><code>routerstatus_format_*</code> (1)</summary>

- [ ] `L3:feature/nodelist/routerstatus_format_entry`

</details>

<details><summary><code>update_microdesc_*</code> (1)</summary>

- [ ] `L3:feature/nodelist/update_microdesc_downloads`

</details>

<details><summary><code>update_microdescs_*</code> (1)</summary>

- [ ] `L3:feature/nodelist/update_microdescs_from_networkstatus`

</details>

<details><summary><code>we_use_*</code> (1)</summary>

- [ ] `L3:feature/nodelist/we_use_microdescriptors_for_circuits`

</details>

<details><summary><code>scale_array_*</code> (1)</summary>

- [ ] `L3:feature/nodelist/scale_array_elements_to_u64`

</details>

<details><summary><code>nodefamily_format_*</code> (1)</summary>

- [ ] `L3:feature/nodelist/nodefamily_format`

</details>

<details><summary><code>nodefamily_from_*</code> (1)</summary>

- [ ] `L3:feature/nodelist/nodefamily_from_members`

</details>

<details><summary><code>nodefamily_parse_*</code> (1)</summary>

- [ ] `L3:feature/nodelist/nodefamily_parse`

</details>

<details><summary><code>routerinfo_get_*</code> (1)</summary>

- [ ] `L3:feature/nodelist/routerinfo_get_ed25519_id`

</details>

<details><summary><code>refresh_all_*</code> (1)</summary>

- [ ] `L3:feature/nodelist/refresh_all_country_info`

</details>

<details><summary><code>tor_make_*</code> (1)</summary>

- [ ] `L3:feature/nodelist/tor_make_rsa_ed25519_crosscert`

</details>

#### Relay op checklist (all 145)

<details><summary><code>dns_*</code> (14)</summary>

- [ ] `L3:feature/relay/dns_cache_handle_oom`
- [ ] `L3:feature/relay/dns_cache_total_allocation`
- [ ] `L3:feature/relay/dns_free_all`
- [ ] `L3:feature/relay/dns_get_cache_entry`
- [ ] `L3:feature/relay/dns_init`
- [ ] `L3:feature/relay/dns_insert_cache_entry`
- [ ] `L3:feature/relay/dns_launch_correctness_checks`
- [ ] `L3:feature/relay/dns_new_consensus_params`
- [ ] `L3:feature/relay/dns_reset`
- [ ] `L3:feature/relay/dns_reset_correctness_checks`
- [ ] `L3:feature/relay/dns_resolve`
- [ ] `L3:feature/relay/dns_seems_to_be_broken`
- [ ] `L3:feature/relay/dns_seems_to_be_broken_for_ipv6`
- [ ] `L3:feature/relay/dns_send_resolved_error_cell`

</details>

<details><summary><code>relay_*</code> (12)</summary>

- [ ] `L3:feature/relay/relay_addr_learn_from_dirauth`
- [ ] `L3:feature/relay/relay_address_new_suggestion`
- [ ] `L3:feature/relay/relay_config_free_all`
- [ ] `L3:feature/relay/relay_get_effective_bwburst`
- [ ] `L3:feature/relay/relay_increment_est_intro_action`
- [ ] `L3:feature/relay/relay_increment_est_rend_action`
- [ ] `L3:feature/relay/relay_increment_intro1_action`
- [ ] `L3:feature/relay/relay_increment_rend1_action`
- [ ] `L3:feature/relay/relay_metrics_free`
- [ ] `L3:feature/relay/relay_metrics_get_stores`
- [ ] `L3:feature/relay/relay_metrics_init`
- [ ] `L3:feature/relay/relay_register_periodic_events`

</details>

<details><summary><code>options_act_*</code> (10)</summary>

- [ ] `L3:feature/relay/options_act_bridge_stats`
- [ ] `L3:feature/relay/options_act_relay`
- [ ] `L3:feature/relay/options_act_relay_accounting`
- [ ] `L3:feature/relay/options_act_relay_bandwidth`
- [ ] `L3:feature/relay/options_act_relay_desc`
- [ ] `L3:feature/relay/options_act_relay_dir`
- [ ] `L3:feature/relay/options_act_relay_dos`
- [ ] `L3:feature/relay/options_act_relay_stats`
- [ ] `L3:feature/relay/options_act_relay_stats_msg`
- [ ] `L3:feature/relay/options_act_server_transport`

</details>

<details><summary><code>options_validate_*</code> (9)</summary>

- [ ] `L3:feature/relay/options_validate_publish_server`
- [ ] `L3:feature/relay/options_validate_relay_accounting`
- [ ] `L3:feature/relay/options_validate_relay_bandwidth`
- [ ] `L3:feature/relay/options_validate_relay_info`
- [ ] `L3:feature/relay/options_validate_relay_mode`
- [ ] `L3:feature/relay/options_validate_relay_os`
- [ ] `L3:feature/relay/options_validate_relay_padding`
- [ ] `L3:feature/relay/options_validate_relay_testing`
- [ ] `L3:feature/relay/options_validate_server_transport`

</details>

<details><summary><code>circuit_*</code> (8)</summary>

- [ ] `L3:feature/relay/circuit_choose_ip_ap_for_extend`
- [ ] `L3:feature/relay/circuit_extend`
- [ ] `L3:feature/relay/circuit_extend_add_ed25519_helper`
- [ ] `L3:feature/relay/circuit_extend_add_ipv4_helper`
- [ ] `L3:feature/relay/circuit_extend_add_ipv6_helper`
- [ ] `L3:feature/relay/circuit_extend_lspec_valid_helper`
- [ ] `L3:feature/relay/circuit_extend_state_valid_helper`
- [ ] `L3:feature/relay/circuit_open_connection_for_extend`

</details>

<details><summary><code>connection_*</code> (8)</summary>

- [ ] `L3:feature/relay/connection_dns_remove`
- [ ] `L3:feature/relay/connection_ext_or_finished_flushing`
- [ ] `L3:feature/relay/connection_ext_or_process_inbuf`
- [ ] `L3:feature/relay/connection_ext_or_start_auth`
- [ ] `L3:feature/relay/connection_or_compute_authenticate_cell_body`
- [ ] `L3:feature/relay/connection_or_send_auth_challenge_cell`
- [ ] `L3:feature/relay/connection_or_send_certs_cell`
- [ ] `L3:feature/relay/connection_write_ext_or_command`

</details>

<details><summary><code>router_*</code> (6)</summary>

- [ ] `L3:feature/relay/router_do_reachability_checks`
- [ ] `L3:feature/relay/router_ed25519_id_is_me`
- [ ] `L3:feature/relay/router_orport_found_reachable`
- [ ] `L3:feature/relay/router_orport_seems_reachable`
- [ ] `L3:feature/relay/router_perform_bandwidth_test`
- [ ] `L3:feature/relay/router_reset_reachability`

</details>

<details><summary><code>get_my_*</code> (4)</summary>

- [ ] `L3:feature/relay/get_my_declared_family`
- [ ] `L3:feature/relay/get_my_v3_authority_signing_key`
- [ ] `L3:feature/relay/get_my_v3_legacy_cert`
- [ ] `L3:feature/relay/get_my_v3_legacy_signing_key`

</details>

<details><summary><code>get_current_*</code> (4)</summary>

- [ ] `L3:feature/relay/get_current_auth_key_cert`
- [ ] `L3:feature/relay/get_current_auth_keypair`
- [ ] `L3:feature/relay/get_current_family_id_keys`
- [ ] `L3:feature/relay/get_current_link_cert_cert`

</details>

<details><summary><code>get_onion_*</code> (3)</summary>

- [ ] `L3:feature/relay/get_onion_key_grace_period`
- [ ] `L3:feature/relay/get_onion_key_lifetime`
- [ ] `L3:feature/relay/get_onion_key_set_at`

</details>

<details><summary><code>mark_my_*</code> (3)</summary>

- [ ] `L3:feature/relay/mark_my_descriptor_dirty`
- [ ] `L3:feature/relay/mark_my_descriptor_dirty_if_too_old`
- [ ] `L3:feature/relay/mark_my_descriptor_if_omit_ipv6_changes`

</details>

<details><summary><code>get_master_*</code> (3)</summary>

- [ ] `L3:feature/relay/get_master_identity_key`
- [ ] `L3:feature/relay/get_master_identity_keypair`
- [ ] `L3:feature/relay/get_master_rsa_crosscert`

</details>

<details><summary><code>onion_pending_*</code> (2)</summary>

- [ ] `L3:feature/relay/onion_pending_add`
- [ ] `L3:feature/relay/onion_pending_remove`

</details>

<details><summary><code>authchallenge_type_*</code> (2)</summary>

- [ ] `L3:feature/relay/authchallenge_type_is_better`
- [ ] `L3:feature/relay/authchallenge_type_is_supported`

</details>

<details><summary><code>check_descriptor_*</code> (2)</summary>

- [ ] `L3:feature/relay/check_descriptor_bandwidth_changed`
- [ ] `L3:feature/relay/check_descriptor_ipaddress_changed`

</details>

<details><summary><code>init_keys_*</code> (2)</summary>

- [ ] `L3:feature/relay/init_keys`
- [ ] `L3:feature/relay/init_keys_client`

</details>

<details><summary><code>load_family_*</code> (2)</summary>

- [ ] `L3:feature/relay/load_family_id_keys`
- [ ] `L3:feature/relay/load_family_id_keys_impl`

</details>

<details><summary><code>pt_get_*</code> (2)</summary>

- [ ] `L3:feature/relay/pt_get_bindaddr_from_config`
- [ ] `L3:feature/relay/pt_get_options_for_server_transport`

</details>

<details><summary><code>circuitbuild_warn_*</code> (1)</summary>

- [ ] `L3:feature/relay/circuitbuild_warn_client_extend`

</details>

<details><summary><code>onionskin_answer_*</code> (1)</summary>

- [ ] `L3:feature/relay/onionskin_answer`

</details>

<details><summary><code>assert_connection_*</code> (1)</summary>

- [ ] `L3:feature/relay/assert_connection_edge_not_dns_pending`

</details>

<details><summary><code>configured_nameserver_*</code> (1)</summary>

- [ ] `L3:feature/relay/configured_nameserver_address`

</details>

<details><summary><code>dump_dns_*</code> (1)</summary>

- [ ] `L3:feature/relay/dump_dns_mem_usage`

</details>

<details><summary><code>has_dns_*</code> (1)</summary>

- [ ] `L3:feature/relay/has_dns_init_failed`

</details>

<details><summary><code>number_of_*</code> (1)</summary>

- [ ] `L3:feature/relay/number_of_configured_nameservers`

</details>

<details><summary><code>ext_orport_*</code> (1)</summary>

- [ ] `L3:feature/relay/ext_orport_free_all`

</details>

<details><summary><code>get_ext_*</code> (1)</summary>

- [ ] `L3:feature/relay/get_ext_or_auth_cookie_file_name`

</details>

<details><summary><code>handle_client_*</code> (1)</summary>

- [ ] `L3:feature/relay/handle_client_auth_nonce`

</details>

<details><summary><code>init_ext_*</code> (1)</summary>

- [ ] `L3:feature/relay/init_ext_or_cookie_authentication`

</details>

<details><summary><code>clear_pending_*</code> (1)</summary>

- [ ] `L3:feature/relay/clear_pending_onions`

</details>

<details><summary><code>onion_consensus_*</code> (1)</summary>

- [ ] `L3:feature/relay/onion_consensus_has_changed`

</details>

<details><summary><code>onion_next_*</code> (1)</summary>

- [ ] `L3:feature/relay/onion_next_task`

</details>

<details><summary><code>onion_num_*</code> (1)</summary>

- [ ] `L3:feature/relay/onion_num_pending`

</details>

<details><summary><code>check_bridge_*</code> (1)</summary>

- [ ] `L3:feature/relay/check_bridge_distribution_setting`

</details>

<details><summary><code>describe_relay_*</code> (1)</summary>

- [ ] `L3:feature/relay/describe_relay_port`

</details>

<details><summary><code>have_enough_*</code> (1)</summary>

- [ ] `L3:feature/relay/have_enough_mem_for_dircache`

</details>

<details><summary><code>port_parse_*</code> (1)</summary>

- [ ] `L3:feature/relay/port_parse_ports_relay`

</details>

<details><summary><code>port_update_*</code> (1)</summary>

- [ ] `L3:feature/relay/port_update_port_set_relay`

</details>

<details><summary><code>port_warn_*</code> (1)</summary>

- [ ] `L3:feature/relay/port_warn_nonlocal_ext_orports`

</details>

<details><summary><code>reschedule_descriptor_*</code> (1)</summary>

- [ ] `L3:feature/relay/reschedule_descriptor_update_check`

</details>

<details><summary><code>client_identity_*</code> (1)</summary>

- [ ] `L3:feature/relay/client_identity_key_is_set`

</details>

<details><summary><code>consider_publishable_*</code> (1)</summary>

- [ ] `L3:feature/relay/consider_publishable_server`

</details>

<details><summary><code>construct_ntor_*</code> (1)</summary>

- [ ] `L3:feature/relay/construct_ntor_key_map`

</details>

<details><summary><code>dup_onion_*</code> (1)</summary>

- [ ] `L3:feature/relay/dup_onion_keys`

</details>

<details><summary><code>expire_old_*</code> (1)</summary>

- [ ] `L3:feature/relay/expire_old_onion_keys`

</details>

<details><summary><code>extrainfo_dump_*</code> (1)</summary>

- [ ] `L3:feature/relay/extrainfo_dump_to_string`

</details>

<details><summary><code>get_platform_*</code> (1)</summary>

- [ ] `L3:feature/relay/get_platform_str`

</details>

<details><summary><code>get_tlsclient_*</code> (1)</summary>

- [ ] `L3:feature/relay/get_tlsclient_identity_key`

</details>

<details><summary><code>init_curve25519_*</code> (1)</summary>

- [ ] `L3:feature/relay/init_curve25519_keypair_from_file`

</details>

<details><summary><code>load_stats_*</code> (1)</summary>

- [ ] `L3:feature/relay/load_stats_file`

</details>

<details><summary><code>log_addr_*</code> (1)</summary>

- [ ] `L3:feature/relay/log_addr_has_changed`

</details>

<details><summary><code>create_family_*</code> (1)</summary>

- [ ] `L3:feature/relay/create_family_id_key`

</details>

<details><summary><code>generate_ed_*</code> (1)</summary>

- [ ] `L3:feature/relay/generate_ed_link_cert`

</details>

<details><summary><code>init_mock_*</code> (1)</summary>

- [ ] `L3:feature/relay/init_mock_ed_keys`

</details>

<details><summary><code>is_family_*</code> (1)</summary>

- [ ] `L3:feature/relay/is_family_key_fname`

</details>

<details><summary><code>list_family_*</code> (1)</summary>

- [ ] `L3:feature/relay/list_family_key_files`

</details>

<details><summary><code>load_ed_*</code> (1)</summary>

- [ ] `L3:feature/relay/load_ed_keys`

</details>

<details><summary><code>log_cert_*</code> (1)</summary>

- [ ] `L3:feature/relay/log_cert_expiration`

</details>

<details><summary><code>make_ntor_*</code> (1)</summary>

- [ ] `L3:feature/relay/make_ntor_onion_key_crosscert`

</details>

<details><summary><code>make_tap_*</code> (1)</summary>

- [ ] `L3:feature/relay/make_tap_onion_key_crosscert`

</details>

<details><summary><code>routerkeys_free_*</code> (1)</summary>

- [ ] `L3:feature/relay/routerkeys_free_all`

</details>

<details><summary><code>set_family_*</code> (1)</summary>

- [ ] `L3:feature/relay/set_family_id_keys`

</details>

<details><summary><code>should_make_*</code> (1)</summary>

- [ ] `L3:feature/relay/should_make_new_ed_keys`

</details>

<details><summary><code>warn_about_*</code> (1)</summary>

- [ ] `L3:feature/relay/warn_about_family_id_config`

</details>

<details><summary><code>dir_server_*</code> (1)</summary>

- [ ] `L3:feature/relay/dir_server_mode`

</details>

<details><summary><code>set_server_*</code> (1)</summary>

- [ ] `L3:feature/relay/set_server_advertised`

</details>

<details><summary><code>get_options_*</code> (1)</summary>

- [ ] `L3:feature/relay/get_options_from_transport_options_line`

</details>

## B. L4 `or_options` fields still D2 (209)

Typed parse/wiring incomplete vs C Tor `or_options_t`. Module: `app/config`.

<details><summary>All 209 option names</summary>

- [ ] `L4:or_options/AccountingMax` — `AccountingMax`
- [ ] `L4:or_options/AddressDisableIPv6` — `AddressDisableIPv6`
- [ ] `L4:or_options/AllDirActionsPrivate` — `AllDirActionsPrivate`
- [ ] `L4:or_options/AllFamilyIdsExpected` — `AllFamilyIdsExpected`
- [ ] `L4:or_options/AllowNonRFC953Hostnames` — `AllowNonRFC953Hostnames`
- [ ] `L4:or_options/AlwaysCongestionControl` — `AlwaysCongestionControl`
- [ ] `L4:or_options/AssumeReachable` — `AssumeReachable`
- [ ] `L4:or_options/AssumeReachableIPv6` — `AssumeReachableIPv6`
- [ ] `L4:or_options/AuthoritativeDir` — `AuthoritativeDir`
- [ ] `L4:or_options/AutomapHostsOnResolve` — `AutomapHostsOnResolve`
- [ ] `L4:or_options/AvoidDiskWrites` — `AvoidDiskWrites`
- [ ] `L4:or_options/BandwidthBurst` — `BandwidthBurst`
- [ ] `L4:or_options/BandwidthRate` — `BandwidthRate`
- [ ] `L4:or_options/BridgeAuthoritativeDir` — `BridgeAuthoritativeDir`
- [ ] `L4:or_options/BridgeRecordUsageByCountry` — `BridgeRecordUsageByCountry`
- [ ] `L4:or_options/BridgeRelay` — `BridgeRelay`
- [ ] `L4:or_options/CacheDirectoryGroupReadable` — `CacheDirectoryGroupReadable`
- [ ] `L4:or_options/CellStatistics` — `CellStatistics`
- [ ] `L4:or_options/CircuitBuildTimeout` — `CircuitBuildTimeout`
- [ ] `L4:or_options/CircuitPadding` — `CircuitPadding`
- [ ] `L4:or_options/CircuitPriorityHalflife` — `CircuitPriorityHalflife`
- [ ] `L4:or_options/CircuitStreamTimeout` — `CircuitStreamTimeout`
- [ ] `L4:or_options/CircuitsAvailableTimeout` — `CircuitsAvailableTimeout`
- [ ] `L4:or_options/ClientBootstrapConsensusAuthorityDownloadInitialDelay` — `ClientBootstrapConsensusAuthorityDownloadInitialDelay`
- [ ] `L4:or_options/ClientBootstrapConsensusAuthorityOnlyDownloadInitialDelay` — `ClientBootstrapConsensusAuthorityOnlyDownloadInitialDelay`
- [ ] `L4:or_options/ClientBootstrapConsensusFallbackDownloadInitialDelay` — `ClientBootstrapConsensusFallbackDownloadInitialDelay`
- [ ] `L4:or_options/ClientBootstrapConsensusMaxInProgressTries` — `ClientBootstrapConsensusMaxInProgressTries`
- [ ] `L4:or_options/ClientDNSRejectInternalAddresses` — `ClientDNSRejectInternalAddresses`
- [ ] `L4:or_options/ClientOnly` — `ClientOnly`
- [ ] `L4:or_options/ClientPreferIPv6DirPort` — `ClientPreferIPv6DirPort`
- [ ] `L4:or_options/ClientPreferIPv6ORPort` — `ClientPreferIPv6ORPort`
- [ ] `L4:or_options/ClientRejectInternalAddresses` — `ClientRejectInternalAddresses`
- [ ] `L4:or_options/ClientUseIPv4` — `ClientUseIPv4`
- [ ] `L4:or_options/ClientUseIPv6` — `ClientUseIPv6`
- [ ] `L4:or_options/CompiledProofOfWorkHash` — `CompiledProofOfWorkHash`
- [ ] `L4:or_options/ConfluxClientUX` — `ConfluxClientUX`
- [ ] `L4:or_options/ConfluxEnabled` — `ConfluxEnabled`
- [ ] `L4:or_options/ConnDirectionStatistics` — `ConnDirectionStatistics`
- [ ] `L4:or_options/ConnLimit` — `ConnLimit`
- [ ] `L4:or_options/ConnLimit_high_thresh` — `ConnLimit_high_thresh`
- [ ] `L4:or_options/ConnLimit_low_thresh` — `ConnLimit_low_thresh`
- [ ] `L4:or_options/ConnectionPadding` — `ConnectionPadding`
- [ ] `L4:or_options/ConstrainedSockSize` — `ConstrainedSockSize`
- [ ] `L4:or_options/ConstrainedSockets` — `ConstrainedSockets`
- [ ] `L4:or_options/ControlPortFileGroupReadable` — `ControlPortFileGroupReadable`
- [ ] `L4:or_options/ControlSocketsGroupWritable` — `ControlSocketsGroupWritable`
- [ ] `L4:or_options/CookieAuthFileGroupReadable` — `CookieAuthFileGroupReadable`
- [ ] `L4:or_options/CountPrivateBandwidth` — `CountPrivateBandwidth`
- [ ] `L4:or_options/DataDirectoryGroupReadable` — `DataDirectoryGroupReadable`
- [ ] `L4:or_options/DirAllowPrivateAddresses` — `DirAllowPrivateAddresses`
- [ ] `L4:or_options/DirAuthorityFallbackRate` — `DirAuthorityFallbackRate`
- [ ] `L4:or_options/DirCache` — `DirCache`
- [ ] `L4:or_options/DirReqStatistics` — `DirReqStatistics`
- [ ] `L4:or_options/DirReqStatistics_option` — `DirReqStatistics_option`
- [ ] `L4:or_options/DisableAllSwap` — `DisableAllSwap`
- [ ] `L4:or_options/DisableDebuggerAttachment` — `DisableDebuggerAttachment`
- [ ] `L4:or_options/DisableNetwork` — `DisableNetwork`
- [ ] `L4:or_options/DisableOOSCheck` — `DisableOOSCheck`
- [ ] `L4:or_options/DisablePredictedCircuits` — `DisablePredictedCircuits`
- [ ] `L4:or_options/DisableSignalHandlers` — `DisableSignalHandlers`
- [ ] `L4:or_options/DormantCanceledByStartup` — `DormantCanceledByStartup`
- [ ] `L4:or_options/DormantClientTimeout` — `DormantClientTimeout`
- [ ] `L4:or_options/DormantOnFirstStartup` — `DormantOnFirstStartup`
- [ ] `L4:or_options/DormantTimeoutDisabledByIdleStreams` — `DormantTimeoutDisabledByIdleStreams`
- [ ] `L4:or_options/DormantTimeoutEnabled` — `DormantTimeoutEnabled`
- [ ] `L4:or_options/DownloadExtraInfo` — `DownloadExtraInfo`
- [ ] `L4:or_options/EnforceDistinctSubnets` — `EnforceDistinctSubnets`
- [ ] `L4:or_options/EntryStatistics` — `EntryStatistics`
- [ ] `L4:or_options/ExitPolicyRejectLocalInterfaces` — `ExitPolicyRejectLocalInterfaces`
- [ ] `L4:or_options/ExitPolicyRejectPrivate` — `ExitPolicyRejectPrivate`
- [ ] `L4:or_options/ExitPortStatistics` — `ExitPortStatistics`
- [ ] `L4:or_options/ExtORPortCookieAuthFileGroupReadable` — `ExtORPortCookieAuthFileGroupReadable`
- [ ] `L4:or_options/ExtendAllowPrivateAddresses` — `ExtendAllowPrivateAddresses`
- [ ] `L4:or_options/ExtendByEd25519ID` — `ExtendByEd25519ID`
- [ ] `L4:or_options/ExtraInfoStatistics` — `ExtraInfoStatistics`
- [ ] `L4:or_options/FascistFirewall` — `FascistFirewall`
- [ ] `L4:or_options/FetchDirInfoEarly` — `FetchDirInfoEarly`
- [ ] `L4:or_options/FetchDirInfoExtraEarly` — `FetchDirInfoExtraEarly`
- [ ] `L4:or_options/FetchHidServDescriptors` — `FetchHidServDescriptors`
- [ ] `L4:or_options/FetchServerDescriptors` — `FetchServerDescriptors`
- [ ] `L4:or_options/FetchUselessDescriptors` — `FetchUselessDescriptors`
- [ ] `L4:or_options/GeoIPExcludeUnknown` — `GeoIPExcludeUnknown`
- [ ] `L4:or_options/GuardLifetime` — `GuardLifetime`
- [ ] `L4:or_options/HTTPProxyAddr` — `HTTPProxyAddr`
- [ ] `L4:or_options/HTTPProxyPort` — `HTTPProxyPort`
- [ ] `L4:or_options/HTTPSProxyAddr` — `HTTPSProxyAddr`
- [ ] `L4:or_options/HTTPSProxyPort` — `HTTPSProxyPort`
- [ ] `L4:or_options/HeartbeatPeriod` — `HeartbeatPeriod`
- [ ] `L4:or_options/HiddenServiceNonAnonymousMode` — `HiddenServiceNonAnonymousMode`
- [ ] `L4:or_options/HiddenServiceSingleHopMode` — `HiddenServiceSingleHopMode`
- [ ] `L4:or_options/HiddenServiceStatistics` — `HiddenServiceStatistics`
- [ ] `L4:or_options/HiddenServiceStatistics_option` — `HiddenServiceStatistics_option`
- [ ] `L4:or_options/IPv6Exit` — `IPv6Exit`
- [ ] `L4:or_options/KISTSchedRunInterval` — `KISTSchedRunInterval`
- [ ] `L4:or_options/KISTSockBufSizeFactor` — `KISTSockBufSizeFactor`
- [ ] `L4:or_options/KeepBindCapabilities` — `KeepBindCapabilities`
- [ ] `L4:or_options/KeepalivePeriod` — `KeepalivePeriod`
- [ ] `L4:or_options/KeyDirectoryGroupReadable` — `KeyDirectoryGroupReadable`
- [ ] `L4:or_options/LearnCircuitBuildTimeout` — `LearnCircuitBuildTimeout`
- [ ] `L4:or_options/LeaveStreamsUnattached` — `LeaveStreamsUnattached`
- [ ] `L4:or_options/LogMessageDomains` — `LogMessageDomains`
- [ ] `L4:or_options/LogTimeGranularity` — `LogTimeGranularity`
- [ ] `L4:or_options/MainloopStats` — `MainloopStats`
- [ ] `L4:or_options/ManualOnionKeyRotation` — `ManualOnionKeyRotation`
- [ ] `L4:or_options/MaxAdvertisedBandwidth` — `MaxAdvertisedBandwidth`
- [ ] `L4:or_options/MaxCircuitDirtiness` — `MaxCircuitDirtiness`
- [ ] `L4:or_options/MaxClientCircuitsPending` — `MaxClientCircuitsPending`
- [ ] `L4:or_options/MaxConsensusAgeForDiffs` — `MaxConsensusAgeForDiffs`
- [ ] `L4:or_options/MaxHSDirCacheBytes` — `MaxHSDirCacheBytes`
- [ ] `L4:or_options/MaxMemInQueues` — `MaxMemInQueues`
- [ ] `L4:or_options/MaxMemInQueues_low_threshold` — `MaxMemInQueues_low_threshold`
- [ ] `L4:or_options/MaxMemInQueues_raw` — `MaxMemInQueues_raw`
- [ ] `L4:or_options/MaxOnionQueueDelay` — `MaxOnionQueueDelay`
- [ ] `L4:or_options/MaxUnparseableDescSizeToLog` — `MaxUnparseableDescSizeToLog`
- [ ] `L4:or_options/NewCircuitPeriod` — `NewCircuitPeriod`
- [ ] `L4:or_options/NoExec` — `NoExec`
- [ ] `L4:or_options/NumCPUs` — `NumCPUs`
- [ ] `L4:or_options/NumDirectoryGuards` — `NumDirectoryGuards`
- [ ] `L4:or_options/NumEntryGuards` — `NumEntryGuards`
- [ ] `L4:or_options/NumPrimaryGuards` — `NumPrimaryGuards`
- [ ] `L4:or_options/OfflineMasterKey` — `OfflineMasterKey`
- [ ] `L4:or_options/OverloadStatistics` — `OverloadStatistics`
- [ ] `L4:or_options/OwningControllerFD` — `OwningControllerFD`
- [ ] `L4:or_options/PaddingStatistics` — `PaddingStatistics`
- [ ] `L4:or_options/PathBiasCircThreshold` — `PathBiasCircThreshold`
- [ ] `L4:or_options/PathBiasDropGuards` — `PathBiasDropGuards`
- [ ] `L4:or_options/PathBiasExtremeRate` — `PathBiasExtremeRate`
- [ ] `L4:or_options/PathBiasExtremeUseRate` — `PathBiasExtremeUseRate`
- [ ] `L4:or_options/PathBiasNoticeRate` — `PathBiasNoticeRate`
- [ ] `L4:or_options/PathBiasNoticeUseRate` — `PathBiasNoticeUseRate`
- [ ] `L4:or_options/PathBiasScaleThreshold` — `PathBiasScaleThreshold`
- [ ] `L4:or_options/PathBiasScaleUseThreshold` — `PathBiasScaleUseThreshold`
- [ ] `L4:or_options/PathBiasUseThreshold` — `PathBiasUseThreshold`
- [ ] `L4:or_options/PathBiasWarnRate` — `PathBiasWarnRate`
- [ ] `L4:or_options/PathsNeededToBuildCircuits` — `PathsNeededToBuildCircuits`
- [ ] `L4:or_options/PerConnBWBurst` — `PerConnBWBurst`
- [ ] `L4:or_options/PerConnBWRate` — `PerConnBWRate`
- [ ] `L4:or_options/ProtocolWarnings` — `ProtocolWarnings`
- [ ] `L4:or_options/PublishHidServDescriptors` — `PublishHidServDescriptors`
- [ ] `L4:or_options/ReconfigDropsBridgeDescs` — `ReconfigDropsBridgeDescs`
- [ ] `L4:or_options/ReducedCircuitPadding` — `ReducedCircuitPadding`
- [ ] `L4:or_options/ReducedConnectionPadding` — `ReducedConnectionPadding`
- [ ] `L4:or_options/ReducedExitPolicy` — `ReducedExitPolicy`
- [ ] `L4:or_options/ReevaluateExitPolicy` — `ReevaluateExitPolicy`
- [ ] `L4:or_options/RefuseUnknownExits` — `RefuseUnknownExits`
- [ ] `L4:or_options/RelayBandwidthBurst` — `RelayBandwidthBurst`
- [ ] `L4:or_options/RelayBandwidthRate` — `RelayBandwidthRate`
- [ ] `L4:or_options/ReloadTorrcOnSIGHUP` — `ReloadTorrcOnSIGHUP`
- [ ] `L4:or_options/RephistTrackTime` — `RephistTrackTime`
- [ ] `L4:or_options/RunAsDaemon` — `RunAsDaemon`
- [ ] `L4:or_options/SSLKeyLifetime` — `SSLKeyLifetime`
- [ ] `L4:or_options/SafeSocks` — `SafeSocks`
- [ ] `L4:or_options/Sandbox` — `Sandbox`
- [ ] `L4:or_options/SbwsExit` — `SbwsExit`
- [ ] `L4:or_options/ServerDNSAllowBrokenConfig` — `ServerDNSAllowBrokenConfig`
- [ ] `L4:or_options/ServerDNSAllowNonRFC953Hostnames` — `ServerDNSAllowNonRFC953Hostnames`
- [ ] `L4:or_options/ServerDNSDetectHijacking` — `ServerDNSDetectHijacking`
- [ ] `L4:or_options/ServerDNSRandomizeCase` — `ServerDNSRandomizeCase`
- [ ] `L4:or_options/ServerDNSSearchDomains` — `ServerDNSSearchDomains`
- [ ] `L4:or_options/ShutdownWaitLength` — `ShutdownWaitLength`
- [ ] `L4:or_options/SigningKeyLifetime` — `SigningKeyLifetime`
- [ ] `L4:or_options/Socks4ProxyAddr` — `Socks4ProxyAddr`
- [ ] `L4:or_options/Socks4ProxyPort` — `Socks4ProxyPort`
- [ ] `L4:or_options/Socks5ProxyAddr` — `Socks5ProxyAddr`
- [ ] `L4:or_options/Socks5ProxyPort` — `Socks5ProxyPort`
- [ ] `L4:or_options/SocksTimeout` — `SocksTimeout`
- [ ] `L4:or_options/StrictNodes` — `StrictNodes`
- [ ] `L4:or_options/TCPProxyAddr` — `TCPProxyAddr`
- [ ] `L4:or_options/TCPProxyPort` — `TCPProxyPort`
- [ ] `L4:or_options/TCPProxyProtocol` — `TCPProxyProtocol`
- [ ] `L4:or_options/TestSocks` — `TestSocks`
- [ ] `L4:or_options/TestingAuthKeyLifetime` — `TestingAuthKeyLifetime`
- [ ] `L4:or_options/TestingAuthKeySlop` — `TestingAuthKeySlop`
- [ ] `L4:or_options/TestingBridgeBootstrapDownloadInitialDelay` — `TestingBridgeBootstrapDownloadInitialDelay`
- [ ] `L4:or_options/TestingBridgeDownloadInitialDelay` — `TestingBridgeDownloadInitialDelay`
- [ ] `L4:or_options/TestingClientConsensusDownloadInitialDelay` — `TestingClientConsensusDownloadInitialDelay`
- [ ] `L4:or_options/TestingClientDownloadInitialDelay` — `TestingClientDownloadInitialDelay`
- [ ] `L4:or_options/TestingClientMaxIntervalWithoutRequest` — `TestingClientMaxIntervalWithoutRequest`
- [ ] `L4:or_options/TestingDirConnectionMaxStall` — `TestingDirConnectionMaxStall`
- [ ] `L4:or_options/TestingEnableCellStatsEvent` — `TestingEnableCellStatsEvent`
- [ ] `L4:or_options/TestingEnableConnBwEvent` — `TestingEnableConnBwEvent`
- [ ] `L4:or_options/TestingLinkCertLifetime` — `TestingLinkCertLifetime`
- [ ] `L4:or_options/TestingLinkKeySlop` — `TestingLinkKeySlop`
- [ ] `L4:or_options/TestingMinTimeToReportBandwidth` — `TestingMinTimeToReportBandwidth`
- [ ] `L4:or_options/TestingServerConsensusDownloadInitialDelay` — `TestingServerConsensusDownloadInitialDelay`
- [ ] `L4:or_options/TestingServerDownloadInitialDelay` — `TestingServerDownloadInitialDelay`
- [ ] `L4:or_options/TestingSigningKeySlop` — `TestingSigningKeySlop`
- [ ] `L4:or_options/TestingTorNetwork` — `TestingTorNetwork`
- [ ] `L4:or_options/TestingV3AuthInitialDistDelay` — `TestingV3AuthInitialDistDelay`
- [ ] `L4:or_options/TestingV3AuthInitialVoteDelay` — `TestingV3AuthInitialVoteDelay`
- [ ] `L4:or_options/TestingV3AuthInitialVotingInterval` — `TestingV3AuthInitialVotingInterval`
- [ ] `L4:or_options/TestingV3AuthVotingStartOffset` — `TestingV3AuthVotingStartOffset`
- [ ] `L4:or_options/TokenBucketRefillInterval` — `TokenBucketRefillInterval`
- [ ] `L4:or_options/TrackHostExitsExpire` — `TrackHostExitsExpire`
- [ ] `L4:or_options/TruncateLogFile` — `TruncateLogFile`
- [ ] `L4:or_options/UnixSocksGroupWritable` — `UnixSocksGroupWritable`
- [ ] `L4:or_options/UpdateBridgesFromAuthority` — `UpdateBridgesFromAuthority`
- [ ] `L4:or_options/UseDefaultFallbackDirs` — `UseDefaultFallbackDirs`
- [ ] `L4:or_options/UseEntryGuards` — `UseEntryGuards`
- [ ] `L4:or_options/UseEntryGuards_option` — `UseEntryGuards_option`
- [ ] `L4:or_options/UseGuardFraction` — `UseGuardFraction`
- [ ] `L4:or_options/UseMicrodescriptors` — `UseMicrodescriptors`
- [ ] `L4:or_options/V3AuthDistDelay` — `V3AuthDistDelay`
- [ ] `L4:or_options/V3AuthNIntervalsValid` — `V3AuthNIntervalsValid`
- [ ] `L4:or_options/V3AuthUseLegacyKey` — `V3AuthUseLegacyKey`
- [ ] `L4:or_options/V3AuthVoteDelay` — `V3AuthVoteDelay`
- [ ] `L4:or_options/V3AuthVotingInterval` — `V3AuthVotingInterval`
- [ ] `L4:or_options/V3AuthoritativeDir` — `V3AuthoritativeDir`
- [ ] `L4:or_options/VanguardsLiteEnabled` — `VanguardsLiteEnabled`

</details>

## C. N/A surface (203) — map, stub, or out-of-scope

Not “missing product features” by default: C platform libs, stubs, deprecated rend.

### C.1 N/A modules (L1) — 166

| Module | Count | Notes |
|--------|------:|-------|
| `lib/crypt_ops` | 27 | JVM/BC crypto — keep N/A unless API shim needed |
| `lib/fs` | 10 | platform / decide |
| `lib/process` | 10 | platform / decide |
| `lib/net` | 9 | platform / decide |
| `lib/encoding` | 8 | platform / decide |
| `lib/tls` | 8 | JDK TLS / Conscrypt — keep N/A |
| `lib/compress` | 6 | JDK zip / optional codecs |
| `lib/evloop` | 6 | Kotlin coroutines / NIO |
| `lib/log` | 6 | platform / decide |
| `lib/string` | 6 | platform / decide |
| `lib/confmgt` | 5 | platform / decide |
| `lib/container` | 5 | platform / decide |
| `lib/dispatch` | 4 | Optional — decide |
| `lib/intmath` | 4 | platform / decide |
| `lib/metrics` | 4 | platform / decide |
| `lib/thread` | 4 | platform / decide |
| `lib/err` | 3 | platform / decide |
| `lib/lock` | 3 | platform / decide |
| `lib/math` | 3 | platform / decide |
| `lib/pubsub` | 3 | Optional event bus — decide |
| `lib/time` | 3 | platform / decide |
| `lib/trace` | 3 | platform / decide |
| `lib/wallclock` | 3 | platform / decide |
| `feature/rend` | 2 | Deprecated v2 onion — OOS |
| `lib/malloc` | 2 | platform / decide |
| `lib/osinfo` | 2 | platform / decide |
| `lib/smartlist_core` | 2 | platform / decide |
| `lib/version` | 2 | platform / decide |
| `core/or` | 1 | trace probes — OOS |
| `feature/dirauth` | 1 | platform / decide |
| `feature/dircache` | 1 | platform / decide |
| `feature/relay` | 1 | platform / decide |
| `lib/buf` | 1 | platform / decide |
| `lib/ctime` | 1 | platform / decide |
| `lib/fdio` | 1 | platform / decide |
| `lib/geoip` | 1 | platform / decide |
| `lib/llharden` | 1 | platform / decide |
| `lib/memarea` | 1 | platform / decide |
| `lib/meminfo` | 1 | platform / decide |
| `lib/sandbox` | 1 | platform / decide |
| `lib/term` | 1 | platform / decide |

<details><summary>Full L1 N/A unit list</summary>

- [ ] `L1:core/or/trace_probes_cc.c` — `core/or/trace_probes_cc.c`
- [ ] `L1:feature/dirauth/dirauth_stub.c` — `feature/dirauth/dirauth_stub.c`
- [ ] `L1:feature/dircache/dircache_stub.c` — `feature/dircache/dircache_stub.c`
- [ ] `L1:feature/relay/relay_stub.c` — `feature/relay/relay_stub.c`
- [ ] `L1:feature/rend/rendcommon.c` — `feature/rend/rendcommon.c`
- [ ] `L1:feature/rend/rendmid.c` — `feature/rend/rendmid.c`
- [ ] `L1:lib/buf/buffers.c` — `lib/buf/buffers.c`
- [ ] `L1:lib/compress/compress.c` — `lib/compress/compress.c`
- [ ] `L1:lib/compress/compress_buf.c` — `lib/compress/compress_buf.c`
- [ ] `L1:lib/compress/compress_lzma.c` — `lib/compress/compress_lzma.c`
- [ ] `L1:lib/compress/compress_none.c` — `lib/compress/compress_none.c`
- [ ] `L1:lib/compress/compress_zlib.c` — `lib/compress/compress_zlib.c`
- [ ] `L1:lib/compress/compress_zstd.c` — `lib/compress/compress_zstd.c`
- [ ] `L1:lib/confmgt/confmgt.c` — `lib/confmgt/confmgt.c`
- [ ] `L1:lib/confmgt/structvar.c` — `lib/confmgt/structvar.c`
- [ ] `L1:lib/confmgt/type_defs.c` — `lib/confmgt/type_defs.c`
- [ ] `L1:lib/confmgt/typedvar.c` — `lib/confmgt/typedvar.c`
- [ ] `L1:lib/confmgt/unitparse.c` — `lib/confmgt/unitparse.c`
- [ ] `L1:lib/container/bloomfilt.c` — `lib/container/bloomfilt.c`
- [ ] `L1:lib/container/map.c` — `lib/container/map.c`
- [ ] `L1:lib/container/namemap.c` — `lib/container/namemap.c`
- [ ] `L1:lib/container/order.c` — `lib/container/order.c`
- [ ] `L1:lib/container/smartlist.c` — `lib/container/smartlist.c`
- [ ] `L1:lib/crypt_ops/aes_nss.c` — `lib/crypt_ops/aes_nss.c`
- [ ] `L1:lib/crypt_ops/aes_openssl.c` — `lib/crypt_ops/aes_openssl.c`
- [ ] `L1:lib/crypt_ops/crypto_cipher.c` — `lib/crypt_ops/crypto_cipher.c`
- [ ] `L1:lib/crypt_ops/crypto_curve25519.c` — `lib/crypt_ops/crypto_curve25519.c`
- [ ] `L1:lib/crypt_ops/crypto_dh.c` — `lib/crypt_ops/crypto_dh.c`
- [ ] `L1:lib/crypt_ops/crypto_dh_nss.c` — `lib/crypt_ops/crypto_dh_nss.c`
- [ ] `L1:lib/crypt_ops/crypto_dh_openssl.c` — `lib/crypt_ops/crypto_dh_openssl.c`
- [ ] `L1:lib/crypt_ops/crypto_digest.c` — `lib/crypt_ops/crypto_digest.c`
- [ ] `L1:lib/crypt_ops/crypto_digest_nss.c` — `lib/crypt_ops/crypto_digest_nss.c`
- [ ] `L1:lib/crypt_ops/crypto_digest_openssl.c` — `lib/crypt_ops/crypto_digest_openssl.c`
- [ ] `L1:lib/crypt_ops/crypto_ed25519.c` — `lib/crypt_ops/crypto_ed25519.c`
- [ ] `L1:lib/crypt_ops/crypto_format.c` — `lib/crypt_ops/crypto_format.c`
- [ ] `L1:lib/crypt_ops/crypto_hkdf.c` — `lib/crypt_ops/crypto_hkdf.c`
- [ ] `L1:lib/crypt_ops/crypto_init.c` — `lib/crypt_ops/crypto_init.c`
- [ ] `L1:lib/crypt_ops/crypto_nss_mgt.c` — `lib/crypt_ops/crypto_nss_mgt.c`
- [ ] `L1:lib/crypt_ops/crypto_ope.c` — `lib/crypt_ops/crypto_ope.c`
- [ ] `L1:lib/crypt_ops/crypto_openssl_mgt.c` — `lib/crypt_ops/crypto_openssl_mgt.c`
- [ ] `L1:lib/crypt_ops/crypto_pwbox.c` — `lib/crypt_ops/crypto_pwbox.c`
- [ ] `L1:lib/crypt_ops/crypto_rand.c` — `lib/crypt_ops/crypto_rand.c`
- [ ] `L1:lib/crypt_ops/crypto_rand_fast.c` — `lib/crypt_ops/crypto_rand_fast.c`
- [ ] `L1:lib/crypt_ops/crypto_rand_numeric.c` — `lib/crypt_ops/crypto_rand_numeric.c`
- [ ] `L1:lib/crypt_ops/crypto_rsa.c` — `lib/crypt_ops/crypto_rsa.c`
- [ ] `L1:lib/crypt_ops/crypto_rsa_nss.c` — `lib/crypt_ops/crypto_rsa_nss.c`
- [ ] `L1:lib/crypt_ops/crypto_rsa_openssl.c` — `lib/crypt_ops/crypto_rsa_openssl.c`
- [ ] `L1:lib/crypt_ops/crypto_s2k.c` — `lib/crypt_ops/crypto_s2k.c`
- [ ] `L1:lib/crypt_ops/crypto_util.c` — `lib/crypt_ops/crypto_util.c`
- [ ] `L1:lib/crypt_ops/digestset.c` — `lib/crypt_ops/digestset.c`
- [ ] `L1:lib/ctime/di_ops.c` — `lib/ctime/di_ops.c`
- [ ] `L1:lib/dispatch/dispatch_cfg.c` — `lib/dispatch/dispatch_cfg.c`
- [ ] `L1:lib/dispatch/dispatch_core.c` — `lib/dispatch/dispatch_core.c`
- [ ] `L1:lib/dispatch/dispatch_naming.c` — `lib/dispatch/dispatch_naming.c`
- [ ] `L1:lib/dispatch/dispatch_new.c` — `lib/dispatch/dispatch_new.c`
- [ ] `L1:lib/encoding/binascii.c` — `lib/encoding/binascii.c`
- [ ] `L1:lib/encoding/confline.c` — `lib/encoding/confline.c`
- [ ] `L1:lib/encoding/cstring.c` — `lib/encoding/cstring.c`
- [ ] `L1:lib/encoding/keyval.c` — `lib/encoding/keyval.c`
- [ ] `L1:lib/encoding/kvline.c` — `lib/encoding/kvline.c`
- [ ] `L1:lib/encoding/pem.c` — `lib/encoding/pem.c`
- [ ] `L1:lib/encoding/qstring.c` — `lib/encoding/qstring.c`
- [ ] `L1:lib/encoding/time_fmt.c` — `lib/encoding/time_fmt.c`
- [ ] `L1:lib/err/backtrace.c` — `lib/err/backtrace.c`
- [ ] `L1:lib/err/torerr.c` — `lib/err/torerr.c`
- [ ] `L1:lib/err/torerr_sys.c` — `lib/err/torerr_sys.c`
- [ ] `L1:lib/evloop/compat_libevent.c` — `lib/evloop/compat_libevent.c`
- [ ] `L1:lib/evloop/evloop_sys.c` — `lib/evloop/evloop_sys.c`
- [ ] `L1:lib/evloop/procmon.c` — `lib/evloop/procmon.c`
- [ ] `L1:lib/evloop/timers.c` — `lib/evloop/timers.c`
- [ ] `L1:lib/evloop/token_bucket.c` — `lib/evloop/token_bucket.c`
- [ ] `L1:lib/evloop/workqueue.c` — `lib/evloop/workqueue.c`
- [ ] `L1:lib/fdio/fdio.c` — `lib/fdio/fdio.c`
- [ ] `L1:lib/fs/conffile.c` — `lib/fs/conffile.c`
- [ ] `L1:lib/fs/dir.c` — `lib/fs/dir.c`
- [ ] `L1:lib/fs/files.c` — `lib/fs/files.c`
- [ ] `L1:lib/fs/freespace.c` — `lib/fs/freespace.c`
- [ ] `L1:lib/fs/lockfile.c` — `lib/fs/lockfile.c`
- [ ] `L1:lib/fs/mmap.c` — `lib/fs/mmap.c`
- [ ] `L1:lib/fs/path.c` — `lib/fs/path.c`
- [ ] `L1:lib/fs/storagedir.c` — `lib/fs/storagedir.c`
- [ ] `L1:lib/fs/userdb.c` — `lib/fs/userdb.c`
- [ ] `L1:lib/fs/winlib.c` — `lib/fs/winlib.c`
- [ ] `L1:lib/geoip/geoip.c` — `lib/geoip/geoip.c`
- [ ] `L1:lib/intmath/addsub.c` — `lib/intmath/addsub.c`
- [ ] `L1:lib/intmath/bits.c` — `lib/intmath/bits.c`
- [ ] `L1:lib/intmath/muldiv.c` — `lib/intmath/muldiv.c`
- [ ] `L1:lib/intmath/weakrng.c` — `lib/intmath/weakrng.c`
- [ ] `L1:lib/llharden/winprocess_sys.c` — `lib/llharden/winprocess_sys.c`
- [ ] `L1:lib/lock/compat_mutex.c` — `lib/lock/compat_mutex.c`
- [ ] `L1:lib/lock/compat_mutex_pthreads.c` — `lib/lock/compat_mutex_pthreads.c`
- [ ] `L1:lib/lock/compat_mutex_winthreads.c` — `lib/lock/compat_mutex_winthreads.c`
- [ ] `L1:lib/log/escape.c` — `lib/log/escape.c`
- [ ] `L1:lib/log/log.c` — `lib/log/log.c`
- [ ] `L1:lib/log/log_sys.c` — `lib/log/log_sys.c`
- [ ] `L1:lib/log/ratelim.c` — `lib/log/ratelim.c`
- [ ] `L1:lib/log/util_bug.c` — `lib/log/util_bug.c`
- [ ] `L1:lib/log/win32err.c` — `lib/log/win32err.c`
- [ ] `L1:lib/malloc/malloc.c` — `lib/malloc/malloc.c`
- [ ] `L1:lib/malloc/map_anon.c` — `lib/malloc/map_anon.c`
- [ ] `L1:lib/math/fp.c` — `lib/math/fp.c`
- [ ] `L1:lib/math/laplace.c` — `lib/math/laplace.c`
- [ ] `L1:lib/math/prob_distr.c` — `lib/math/prob_distr.c`
- [ ] `L1:lib/memarea/memarea.c` — `lib/memarea/memarea.c`
- [ ] `L1:lib/meminfo/meminfo.c` — `lib/meminfo/meminfo.c`
- [ ] `L1:lib/metrics/metrics_common.c` — `lib/metrics/metrics_common.c`
- [ ] `L1:lib/metrics/metrics_store.c` — `lib/metrics/metrics_store.c`
- [ ] `L1:lib/metrics/metrics_store_entry.c` — `lib/metrics/metrics_store_entry.c`
- [ ] `L1:lib/metrics/prometheus.c` — `lib/metrics/prometheus.c`
- [ ] `L1:lib/net/address.c` — `lib/net/address.c`
- [ ] `L1:lib/net/alertsock.c` — `lib/net/alertsock.c`
- [ ] `L1:lib/net/buffers_net.c` — `lib/net/buffers_net.c`
- [ ] `L1:lib/net/gethostname.c` — `lib/net/gethostname.c`
- [ ] `L1:lib/net/inaddr.c` — `lib/net/inaddr.c`
- [ ] `L1:lib/net/network_sys.c` — `lib/net/network_sys.c`
- [ ] `L1:lib/net/resolve.c` — `lib/net/resolve.c`
- [ ] `L1:lib/net/socket.c` — `lib/net/socket.c`
- [ ] `L1:lib/net/socketpair.c` — `lib/net/socketpair.c`
- [ ] `L1:lib/osinfo/libc.c` — `lib/osinfo/libc.c`
- [ ] `L1:lib/osinfo/uname.c` — `lib/osinfo/uname.c`
- [ ] `L1:lib/process/daemon.c` — `lib/process/daemon.c`
- [ ] `L1:lib/process/env.c` — `lib/process/env.c`
- [ ] `L1:lib/process/pidfile.c` — `lib/process/pidfile.c`
- [ ] `L1:lib/process/process.c` — `lib/process/process.c`
- [ ] `L1:lib/process/process_sys.c` — `lib/process/process_sys.c`
- [ ] `L1:lib/process/process_unix.c` — `lib/process/process_unix.c`
- [ ] `L1:lib/process/process_win32.c` — `lib/process/process_win32.c`
- [ ] `L1:lib/process/restrict.c` — `lib/process/restrict.c`
- [ ] `L1:lib/process/setuid.c` — `lib/process/setuid.c`
- [ ] `L1:lib/process/waitpid.c` — `lib/process/waitpid.c`
- [ ] `L1:lib/pubsub/pubsub_build.c` — `lib/pubsub/pubsub_build.c`
- [ ] `L1:lib/pubsub/pubsub_check.c` — `lib/pubsub/pubsub_check.c`
- [ ] `L1:lib/pubsub/pubsub_publish.c` — `lib/pubsub/pubsub_publish.c`
- [ ] `L1:lib/sandbox/sandbox.c` — `lib/sandbox/sandbox.c`
- [ ] `L1:lib/smartlist_core/smartlist_core.c` — `lib/smartlist_core/smartlist_core.c`
- [ ] `L1:lib/smartlist_core/smartlist_split.c` — `lib/smartlist_core/smartlist_split.c`
- [ ] `L1:lib/string/compat_ctype.c` — `lib/string/compat_ctype.c`
- [ ] `L1:lib/string/compat_string.c` — `lib/string/compat_string.c`
- [ ] `L1:lib/string/parse_int.c` — `lib/string/parse_int.c`
- [ ] `L1:lib/string/printf.c` — `lib/string/printf.c`
- [ ] `L1:lib/string/scanf.c` — `lib/string/scanf.c`
- [ ] `L1:lib/string/util_string.c` — `lib/string/util_string.c`
- [ ] `L1:lib/term/getpass.c` — `lib/term/getpass.c`
- [ ] `L1:lib/thread/compat_pthreads.c` — `lib/thread/compat_pthreads.c`
- [ ] `L1:lib/thread/compat_threads.c` — `lib/thread/compat_threads.c`
- [ ] `L1:lib/thread/compat_winthreads.c` — `lib/thread/compat_winthreads.c`
- [ ] `L1:lib/thread/numcpus.c` — `lib/thread/numcpus.c`
- [ ] `L1:lib/time/compat_time.c` — `lib/time/compat_time.c`
- [ ] `L1:lib/time/time_sys.c` — `lib/time/time_sys.c`
- [ ] `L1:lib/time/tvdiff.c` — `lib/time/tvdiff.c`
- [ ] `L1:lib/tls/buffers_tls.c` — `lib/tls/buffers_tls.c`
- [ ] `L1:lib/tls/nss_countbytes.c` — `lib/tls/nss_countbytes.c`
- [ ] `L1:lib/tls/tortls.c` — `lib/tls/tortls.c`
- [ ] `L1:lib/tls/tortls_nss.c` — `lib/tls/tortls_nss.c`
- [ ] `L1:lib/tls/tortls_openssl.c` — `lib/tls/tortls_openssl.c`
- [ ] `L1:lib/tls/x509.c` — `lib/tls/x509.c`
- [ ] `L1:lib/tls/x509_nss.c` — `lib/tls/x509_nss.c`
- [ ] `L1:lib/tls/x509_openssl.c` — `lib/tls/x509_openssl.c`
- [ ] `L1:lib/trace/trace.c` — `lib/trace/trace.c`
- [ ] `L1:lib/trace/trace_stub.c` — `lib/trace/trace_stub.c`
- [ ] `L1:lib/trace/trace_sys.c` — `lib/trace/trace_sys.c`
- [ ] `L1:lib/version/git_revision.c` — `lib/version/git_revision.c`
- [ ] `L1:lib/version/version.c` — `lib/version/version.c`
- [ ] `L1:lib/wallclock/approx_time.c` — `lib/wallclock/approx_time.c`
- [ ] `L1:lib/wallclock/time_to_tm.c` — `lib/wallclock/time_to_tm.c`
- [ ] `L1:lib/wallclock/tor_gettimeofday.c` — `lib/wallclock/tor_gettimeofday.c`

</details>

### C.2 N/A data types (L2) — 23

- [ ] `L2:lib/crypt_ops/crypto_options_t` — `crypto_options_t` (lib/crypt_ops)
- [ ] `L2:lib/dispatch/dispatch_cfg_t` — `dispatch_cfg_t` (lib/dispatch)
- [ ] `L2:lib/dispatch/dispatch_rcv_t` — `dispatch_rcv_t` (lib/dispatch)
- [ ] `L2:lib/dispatch/dispatch_t` — `dispatch_t` (lib/dispatch)
- [ ] `L2:lib/dispatch/dqueue_t` — `dqueue_t` (lib/dispatch)
- [ ] `L2:lib/dispatch/dtbl_entry_t` — `dtbl_entry_t` (lib/dispatch)
- [ ] `L2:lib/net/in6_addr` — `in6_addr` (lib/net)
- [ ] `L2:lib/net/inaddr_t` — `inaddr_t` (lib/net)
- [ ] `L2:lib/container/mapped_name_t` — `mapped_name_t` (lib/container)
- [ ] `L2:lib/container/namemap_t` — `namemap_t` (lib/container)
- [ ] `L2:lib/pubsub/pub_binding_t` — `pub_binding_t` (lib/pubsub)
- [ ] `L2:lib/pubsub/pubsub_adjmap_t` — `pubsub_adjmap_t` (lib/pubsub)
- [ ] `L2:lib/pubsub/pubsub_builder_t` — `pubsub_builder_t` (lib/pubsub)
- [ ] `L2:lib/pubsub/pubsub_cfg_t` — `pubsub_cfg_t` (lib/pubsub)
- [ ] `L2:lib/pubsub/pubsub_connector_t` — `pubsub_connector_t` (lib/pubsub)
- [ ] `L2:lib/pubsub/pubsub_items_t` — `pubsub_items_t` (lib/pubsub)
- [ ] `L2:lib/pubsub/pubsub_type_cfg_t` — `pubsub_type_cfg_t` (lib/pubsub)
- [ ] `L2:lib/net/sockaddr_in6` — `sockaddr_in6` (lib/net)
- [ ] `L2:lib/tls/tor_tls_context_t` — `tor_tls_context_t` (lib/tls)
- [ ] `L2:lib/tls/tor_tls_t` — `tor_tls_t` (lib/tls)
- [ ] `L2:lib/tls/tortls_t` — `tortls_t` (lib/tls)
- [ ] `L2:lib/confmgt/var_type_def_t` — `var_type_def_t` (lib/confmgt)
- [ ] `L2:lib/confmgt/var_type_fns_t` — `var_type_fns_t` (lib/confmgt)

### C.3 N/A options (L4) — 14

- [ ] `L4:or_options/ConnLimit_` — `ConnLimit_`
- [ ] `L4:or_options/IncludeUsed` — `IncludeUsed`
- [ ] `L4:or_options/PublishServerDescriptor_` — `PublishServerDescriptor_`
- [ ] `L4:or_options/UsingTestNetworkDefaults_` — `UsingTestNetworkDefaults_`
- [ ] `L4:or_options/autobool` — `autobool`
- [ ] `L4:or_options/change_key_passphrase` — `change_key_passphrase`
- [ ] `L4:or_options/command` — `command`
- [ ] `L4:or_options/key_expiration_format` — `key_expiration_format`
- [ ] `L4:or_options/keygen_passphrase_fd` — `keygen_passphrase_fd`
- [ ] `L4:or_options/magic_` — `magic_`
- [ ] `L4:or_options/ptrace` — `ptrace`
- [ ] `L4:or_options/smartlist_t` — `smartlist_t`
- [ ] `L4:or_options/unauthenticated` — `unauthenticated`
- [ ] `L4:or_options/use_keygen_passphrase_fd` — `use_keygen_passphrase_fd`

## D. Feature-board gaps (product semantics — still 🟡)

From [`PARITY_GAPS.md`](../PARITY_GAPS.md) — not inventory-complete until linked rows ≥D3:

- [ ] TLS OR / CERTS / AUTHENTICATE full channel state machine
- [ ] Channel padding + circuit padding (WTF-PAD) full machines
- [ ] tor1 relay crypto audit depth; SENDME v1 + Prop324 CC wiring
- [ ] Conflux full scheduler vs lite
- [ ] Dir cache / DirPort / bwauth / dirvote production depth
- [ ] Guards FSM / vanguards / pathbias DropGuards live path
- [ ] HS client+service full descriptor/intro/rendezvous
- [ ] Control protocol events + bootstrap tracking (btrack)
- [ ] PT managed-proxy lifecycle beyond aliases
- [ ] Relay DNS / keys / descriptor publish

## E. Suggested elevate order (next batches)

| # | Batch | Module | ~ops |
|---|-------|--------|-----:|
| 1 | btrack_* / bto_* | `feature/control` | 13 |
| 2 | control_event_* | `feature/control` | 21 |
| 3 | control_reply_* + control_cmd_* | `feature/control` | 25 |
| 4 | getinfo_helper_* + handle_control_* | `feature/control` | 18 |
| 5 | remaining control_* | `feature/control` | ~32 |
| 6 | node_get_* / router_* | `feature/nodelist` | 25 |
| 7 | networkstatus_* / microdesc_* | `feature/nodelist` | 25 |
| 8 | hs_* client/service/descriptor | `feature/hs` | 25 |
| 9 | relay dns_* / options / keys | `feature/relay` | 25 |
| 10 | dirvote_* / sr_state_* / keypin_* | `feature/dirauth` | 25 |

Then remaining families + L4 option wiring.

