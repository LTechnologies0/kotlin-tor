# C Tor missing / partial inventory (generated)

**Source of truth:** [`CTOR_MASTER_INVENTORY.md`](CTOR_MASTER_INVENTORY.md) + [`generated/ctor_master_inventory.csv`](generated/ctor_master_inventory.csv)

Do **not** treat feature-board ✅ in PARITY_GAPS as completeness. Elevate only by citing `row_id` below; raise at most one depth grade per change.

Global depth counts: D2=450, D3=1683, N/A=203

## Lowest-depth queue (priority modules, top 80)

| row_id | depth | unit | ktor_path | gaps |
|--------|-------|------|-----------|------|
| `L3:feature/nodelist/nodefamily_format` | D2 | `nodefamily_format` | `core/src/main/kotlin/org/kotlintor/dir/NodeFamily.kt;core/sr` | op-level mapping unaudited for nodefamily_format |
| `L3:feature/nodelist/nodefamily_free_` | D2 | `nodefamily_free_` | `core/src/main/kotlin/org/kotlintor/dir/NodeFamily.kt;core/sr` | op-level mapping unaudited for nodefamily_free_ |
| `L3:feature/nodelist/nodefamily_free_all` | D2 | `nodefamily_free_all` | `core/src/main/kotlin/org/kotlintor/dir/NodeFamily.kt;core/sr` | op-level mapping unaudited for nodefamily_free_all |
| `L3:feature/nodelist/nodefamily_from_members` | D2 | `nodefamily_from_members` | `core/src/main/kotlin/org/kotlintor/dir/NodeFamily.kt;core/sr` | op-level mapping unaudited for nodefamily_from_members |
| `L3:feature/nodelist/nodefamily_parse` | D2 | `nodefamily_parse` | `core/src/main/kotlin/org/kotlintor/dir/NodeFamily.kt;core/sr` | op-level mapping unaudited for nodefamily_parse |
| `L3:feature/nodelist/or_handshake_certs_check_both` | D2 | `or_handshake_certs_check_both` | `core/src/main/kotlin/org/kotlintor/dir/TorCert.kt;core/src/m` | op-level mapping unaudited for or_handshake_certs_check_both |
| `L3:feature/nodelist/or_handshake_certs_ed25519_ok` | D2 | `or_handshake_certs_ed25519_ok` | `core/src/main/kotlin/org/kotlintor/dir/TorCert.kt;core/src/m` | op-level mapping unaudited for or_handshake_certs_ed25519_ok |
| `L3:feature/nodelist/or_handshake_certs_free_` | D2 | `or_handshake_certs_free_` | `core/src/main/kotlin/org/kotlintor/dir/TorCert.kt;core/src/m` | op-level mapping unaudited for or_handshake_certs_free_ |
| `L3:feature/nodelist/or_handshake_certs_new` | D2 | `or_handshake_certs_new` | `core/src/main/kotlin/org/kotlintor/dir/TorCert.kt;core/src/m` | op-level mapping unaudited for or_handshake_certs_new |
| `L3:feature/nodelist/or_handshake_certs_rsa_ok` | D2 | `or_handshake_certs_rsa_ok` | `core/src/main/kotlin/org/kotlintor/dir/TorCert.kt;core/src/m` | op-level mapping unaudited for or_handshake_certs_rsa_ok |
| `L3:feature/nodelist/refresh_all_country_info` | D2 | `refresh_all_country_info` | `core/src/main/kotlin/org/kotlintor/dir/RouterList.kt;core/sr` | op-level mapping unaudited for refresh_all_country_info |
| `L3:feature/nodelist/router_add_extrainfo_to_routerlist` | D2 | `router_add_extrainfo_to_routerlist` | `core/src/main/kotlin/org/kotlintor/dir/RouterList.kt;core/sr` | op-level mapping unaudited for router_add_extrainfo_to_routerlist |
| `L3:feature/nodelist/router_add_running_nodes_to_smartlist` | D2 | `router_add_running_nodes_to_smartlist` | `core/src/main/kotlin/org/kotlintor/dir/RouterList.kt;core/sr` | op-level mapping unaudited for router_add_running_nodes_to_smartlist |
| `L3:feature/nodelist/router_add_to_routerlist` | D2 | `router_add_to_routerlist` | `core/src/main/kotlin/org/kotlintor/dir/RouterList.kt;core/sr` | op-level mapping unaudited for router_add_to_routerlist |
| `L3:feature/nodelist/router_addr_is_trusted_dir_type` | D2 | `router_addr_is_trusted_dir_type` | `core/src/main/kotlin/org/kotlintor/dir/DirList.kt` | op-level mapping unaudited for router_addr_is_trusted_dir_type |
| `L3:feature/nodelist/router_can_choose_node` | D2 | `router_can_choose_node` | `core/src/main/kotlin/org/kotlintor/dir/RouterList.kt;core/sr` | op-level mapping unaudited for router_can_choose_node |
| `L3:feature/nodelist/router_choose_random_node` | D2 | `router_choose_random_node` | `core/src/main/kotlin/org/kotlintor/dir/NodeSelect.kt;core/sr` | op-level mapping unaudited for router_choose_random_node |
| `L3:feature/nodelist/router_describe` | D2 | `router_describe` | `core/src/main/kotlin/org/kotlintor/dir/Describe.kt;core/src/` | op-level mapping unaudited for router_describe |
| `L3:feature/nodelist/router_differences_are_cosmetic` | D2 | `router_differences_are_cosmetic` | `core/src/main/kotlin/org/kotlintor/dir/RouterList.kt;core/sr` | op-level mapping unaudited for router_differences_are_cosmetic |
| `L3:feature/nodelist/router_digest_is_fallback_dir` | D2 | `router_digest_is_fallback_dir` | `core/src/main/kotlin/org/kotlintor/dir/DirList.kt` | op-level mapping unaudited for router_digest_is_fallback_dir |
| `L3:feature/nodelist/router_dir_conn_should_skip_reachable_address_check` | D2 | `router_dir_conn_should_skip_reachable_address_check` | `core/src/main/kotlin/org/kotlintor/dir/RouterList.kt;core/sr` | op-level mapping unaudited for router_dir_conn_should_skip_reachable_address_che |
| `L3:feature/nodelist/router_get_advertised_bandwidth` | D2 | `router_get_advertised_bandwidth` | `core/src/main/kotlin/org/kotlintor/dir/RouterList.kt;core/sr` | op-level mapping unaudited for router_get_advertised_bandwidth |
| `L3:feature/nodelist/router_get_advertised_bandwidth_capped` | D2 | `router_get_advertised_bandwidth_capped` | `core/src/main/kotlin/org/kotlintor/dir/RouterList.kt;core/sr` | op-level mapping unaudited for router_get_advertised_bandwidth_capped |
| `L3:feature/nodelist/router_get_all_orports` | D2 | `router_get_all_orports` | `core/src/main/kotlin/org/kotlintor/dir/RouterInfo.kt;core/sr` | op-level mapping unaudited for router_get_all_orports |
| `L3:feature/nodelist/router_get_by_descriptor_digest` | D2 | `router_get_by_descriptor_digest` | `core/src/main/kotlin/org/kotlintor/dir/RouterList.kt;core/sr` | op-level mapping unaudited for router_get_by_descriptor_digest |
| `L3:feature/nodelist/router_get_by_id_digest` | D2 | `router_get_by_id_digest` | `core/src/main/kotlin/org/kotlintor/dir/RouterList.kt;core/sr` | op-level mapping unaudited for router_get_by_id_digest |
| `L3:feature/nodelist/router_get_fallback_dir_servers` | D2 | `router_get_fallback_dir_servers` | `core/src/main/kotlin/org/kotlintor/dir/DirList.kt` | op-level mapping unaudited for router_get_fallback_dir_servers |
| `L3:feature/nodelist/router_get_fallback_dir_servers_mutable` | D2 | `router_get_fallback_dir_servers_mutable` | `core/src/main/kotlin/org/kotlintor/dir/DirList.kt` | op-level mapping unaudited for router_get_fallback_dir_servers_mutable |
| `L3:feature/nodelist/router_get_fallback_dirserver_by_digest` | D2 | `router_get_fallback_dirserver_by_digest` | `core/src/main/kotlin/org/kotlintor/dir/DirList.kt` | op-level mapping unaudited for router_get_fallback_dirserver_by_digest |
| `L3:feature/nodelist/router_get_mutable_by_digest` | D2 | `router_get_mutable_by_digest` | `core/src/main/kotlin/org/kotlintor/dir/RouterList.kt;core/sr` | op-level mapping unaudited for router_get_mutable_by_digest |
| `L3:feature/nodelist/router_get_my_share_of_directory_requests` | D2 | `router_get_my_share_of_directory_requests` | `core/src/main/kotlin/org/kotlintor/dir/NodeSelect.kt;core/sr` | op-level mapping unaudited for router_get_my_share_of_directory_requests |
| `L3:feature/nodelist/router_get_orport` | D2 | `router_get_orport` | `core/src/main/kotlin/org/kotlintor/dir/RouterInfo.kt;core/sr` | op-level mapping unaudited for router_get_orport |
| `L3:feature/nodelist/router_get_routerlist` | D2 | `router_get_routerlist` | `core/src/main/kotlin/org/kotlintor/dir/RouterList.kt;core/sr` | op-level mapping unaudited for router_get_routerlist |
| `L3:feature/nodelist/router_get_trusted_dir_servers` | D2 | `router_get_trusted_dir_servers` | `core/src/main/kotlin/org/kotlintor/dir/DirList.kt` | op-level mapping unaudited for router_get_trusted_dir_servers |
| `L3:feature/nodelist/router_get_trusted_dir_servers_mutable` | D2 | `router_get_trusted_dir_servers_mutable` | `core/src/main/kotlin/org/kotlintor/dir/DirList.kt` | op-level mapping unaudited for router_get_trusted_dir_servers_mutable |
| `L3:feature/nodelist/router_get_trusteddirserver_by_digest` | D2 | `router_get_trusteddirserver_by_digest` | `core/src/main/kotlin/org/kotlintor/dir/DirList.kt` | op-level mapping unaudited for router_get_trusteddirserver_by_digest |
| `L3:feature/nodelist/router_get_verbose_nickname` | D2 | `router_get_verbose_nickname` | `core/src/main/kotlin/org/kotlintor/dir/Describe.kt;core/src/` | op-level mapping unaudited for router_get_verbose_nickname |
| `L3:feature/nodelist/router_has_orport` | D2 | `router_has_orport` | `core/src/main/kotlin/org/kotlintor/dir/RouterInfo.kt;core/sr` | op-level mapping unaudited for router_has_orport |
| `L3:feature/nodelist/router_is_already_dir_fetching` | D2 | `router_is_already_dir_fetching` | `core/src/main/kotlin/org/kotlintor/dir/NodeSelect.kt;core/sr` | op-level mapping unaudited for router_is_already_dir_fetching |
| `L3:feature/nodelist/router_load_extrainfo_from_string` | D2 | `router_load_extrainfo_from_string` | `core/src/main/kotlin/org/kotlintor/dir/RouterList.kt;core/sr` | op-level mapping unaudited for router_load_extrainfo_from_string |
| `L3:feature/nodelist/router_load_routers_from_string` | D2 | `router_load_routers_from_string` | `core/src/main/kotlin/org/kotlintor/dir/RouterList.kt;core/sr` | op-level mapping unaudited for router_load_routers_from_string |
| `L3:feature/nodelist/router_pick_directory_server` | D2 | `router_pick_directory_server` | `core/src/main/kotlin/org/kotlintor/dir/NodeSelect.kt;core/sr` | op-level mapping unaudited for router_pick_directory_server |
| `L3:feature/nodelist/router_pick_directory_server_impl` | D2 | `router_pick_directory_server_impl` | `core/src/main/kotlin/org/kotlintor/dir/NodeSelect.kt;core/sr` | op-level mapping unaudited for router_pick_directory_server_impl |
| `L3:feature/nodelist/router_pick_fallback_dirserver` | D2 | `router_pick_fallback_dirserver` | `core/src/main/kotlin/org/kotlintor/dir/NodeSelect.kt;core/sr` | op-level mapping unaudited for router_pick_fallback_dirserver |
| `L3:feature/nodelist/router_pick_trusteddirserver` | D2 | `router_pick_trusteddirserver` | `core/src/main/kotlin/org/kotlintor/dir/NodeSelect.kt;core/sr` | op-level mapping unaudited for router_pick_trusteddirserver |
| `L3:feature/nodelist/router_purpose_from_string` | D2 | `router_purpose_from_string` | `core/src/main/kotlin/org/kotlintor/dir/RouterInfo.kt;core/sr` | op-level mapping unaudited for router_purpose_from_string |
| `L3:feature/nodelist/router_purpose_to_string` | D2 | `router_purpose_to_string` | `core/src/main/kotlin/org/kotlintor/dir/RouterInfo.kt;core/sr` | op-level mapping unaudited for router_purpose_to_string |
| `L3:feature/nodelist/routerinfo_get_ed25519_id` | D2 | `routerinfo_get_ed25519_id` | `core/src/main/kotlin/org/kotlintor/dir/RouterInfo.kt;core/sr` | op-level mapping unaudited for routerinfo_get_ed25519_id |
| `L3:feature/nodelist/routerset_add_unknown_ccs` | D2 | `routerset_add_unknown_ccs` | `core/src/main/kotlin/org/kotlintor/dir/RouterSet.kt;core/src` | op-level mapping unaudited for routerset_add_unknown_ccs |
| `L3:feature/nodelist/routerset_contains` | D2 | `routerset_contains` | `core/src/main/kotlin/org/kotlintor/dir/RouterSet.kt;core/src` | op-level mapping unaudited for routerset_contains |
| `L3:feature/nodelist/routerset_contains_bridge` | D2 | `routerset_contains_bridge` | `core/src/main/kotlin/org/kotlintor/dir/RouterSet.kt;core/src` | op-level mapping unaudited for routerset_contains_bridge |
| `L3:feature/nodelist/routerset_contains_extendinfo` | D2 | `routerset_contains_extendinfo` | `core/src/main/kotlin/org/kotlintor/dir/RouterSet.kt;core/src` | op-level mapping unaudited for routerset_contains_extendinfo |
| `L3:feature/nodelist/routerset_contains_node` | D2 | `routerset_contains_node` | `core/src/main/kotlin/org/kotlintor/dir/RouterSet.kt;core/src` | op-level mapping unaudited for routerset_contains_node |
| `L3:feature/nodelist/routerset_contains_router` | D2 | `routerset_contains_router` | `core/src/main/kotlin/org/kotlintor/dir/RouterSet.kt;core/src` | op-level mapping unaudited for routerset_contains_router |
| `L3:feature/nodelist/routerset_contains_routerstatus` | D2 | `routerset_contains_routerstatus` | `core/src/main/kotlin/org/kotlintor/dir/RouterSet.kt;core/src` | op-level mapping unaudited for routerset_contains_routerstatus |
| `L3:feature/nodelist/routerset_equal` | D2 | `routerset_equal` | `core/src/main/kotlin/org/kotlintor/dir/RouterSet.kt;core/src` | op-level mapping unaudited for routerset_equal |
| `L3:feature/nodelist/routerset_free_` | D2 | `routerset_free_` | `core/src/main/kotlin/org/kotlintor/dir/RouterSet.kt;core/src` | op-level mapping unaudited for routerset_free_ |
| `L3:feature/nodelist/routerset_get_all_nodes` | D2 | `routerset_get_all_nodes` | `core/src/main/kotlin/org/kotlintor/dir/RouterSet.kt;core/src` | op-level mapping unaudited for routerset_get_all_nodes |
| `L3:feature/nodelist/routerset_get_countryname` | D2 | `routerset_get_countryname` | `core/src/main/kotlin/org/kotlintor/dir/RouterSet.kt;core/src` | op-level mapping unaudited for routerset_get_countryname |
| `L3:feature/nodelist/routerset_is_empty` | D2 | `routerset_is_empty` | `core/src/main/kotlin/org/kotlintor/dir/RouterSet.kt;core/src` | op-level mapping unaudited for routerset_is_empty |
| `L3:feature/nodelist/routerset_is_list` | D2 | `routerset_is_list` | `core/src/main/kotlin/org/kotlintor/dir/RouterSet.kt;core/src` | op-level mapping unaudited for routerset_is_list |
| `L3:feature/nodelist/routerset_len` | D2 | `routerset_len` | `core/src/main/kotlin/org/kotlintor/dir/RouterSet.kt;core/src` | op-level mapping unaudited for routerset_len |
| `L3:feature/nodelist/routerset_needs_geoip` | D2 | `routerset_needs_geoip` | `core/src/main/kotlin/org/kotlintor/dir/RouterSet.kt;core/src` | op-level mapping unaudited for routerset_needs_geoip |
| `L3:feature/nodelist/routerset_new` | D2 | `routerset_new` | `core/src/main/kotlin/org/kotlintor/dir/RouterSet.kt;core/src` | op-level mapping unaudited for routerset_new |
| `L3:feature/nodelist/routerset_parse` | D2 | `routerset_parse` | `core/src/main/kotlin/org/kotlintor/dir/RouterSet.kt;core/src` | op-level mapping unaudited for routerset_parse |
| `L3:feature/nodelist/routerset_refresh_countries` | D2 | `routerset_refresh_countries` | `core/src/main/kotlin/org/kotlintor/dir/RouterSet.kt;core/src` | op-level mapping unaudited for routerset_refresh_countries |
| `L3:feature/nodelist/routerset_subtract_nodes` | D2 | `routerset_subtract_nodes` | `core/src/main/kotlin/org/kotlintor/dir/RouterSet.kt;core/src` | op-level mapping unaudited for routerset_subtract_nodes |
| `L3:feature/nodelist/routerset_to_string` | D2 | `routerset_to_string` | `core/src/main/kotlin/org/kotlintor/dir/RouterSet.kt;core/src` | op-level mapping unaudited for routerset_to_string |
| `L3:feature/nodelist/routerset_union` | D2 | `routerset_union` | `core/src/main/kotlin/org/kotlintor/dir/RouterSet.kt;core/src` | op-level mapping unaudited for routerset_union |
| `L3:feature/nodelist/routerstatus_describe` | D2 | `routerstatus_describe` | `core/src/main/kotlin/org/kotlintor/dir/Describe.kt;core/src/` | op-level mapping unaudited for routerstatus_describe |
| `L3:feature/nodelist/routerstatus_format_entry` | D2 | `routerstatus_format_entry` | `core/src/main/kotlin/org/kotlintor/dir/FmtRouterStatus.kt;co` | op-level mapping unaudited for routerstatus_format_entry |
| `L3:feature/nodelist/scale_array_elements_to_u64` | D2 | `scale_array_elements_to_u64` | `core/src/main/kotlin/org/kotlintor/dir/NodeSelect.kt;core/sr` | op-level mapping unaudited for scale_array_elements_to_u64 |
| `L3:feature/nodelist/tor_cert_checksig` | D2 | `tor_cert_checksig` | `core/src/main/kotlin/org/kotlintor/dir/TorCert.kt;core/src/m` | op-level mapping unaudited for tor_cert_checksig |
| `L3:feature/nodelist/tor_cert_create_ed25519` | D2 | `tor_cert_create_ed25519` | `core/src/main/kotlin/org/kotlintor/dir/TorCert.kt;core/src/m` | op-level mapping unaudited for tor_cert_create_ed25519 |
| `L3:feature/nodelist/tor_cert_create_raw` | D2 | `tor_cert_create_raw` | `core/src/main/kotlin/org/kotlintor/dir/TorCert.kt;core/src/m` | op-level mapping unaudited for tor_cert_create_raw |
| `L3:feature/nodelist/tor_cert_describe_signature_status` | D2 | `tor_cert_describe_signature_status` | `core/src/main/kotlin/org/kotlintor/dir/TorCert.kt;core/src/m` | op-level mapping unaudited for tor_cert_describe_signature_status |
| `L3:feature/nodelist/tor_cert_encode_ed22519` | D2 | `tor_cert_encode_ed22519` | `core/src/main/kotlin/org/kotlintor/dir/TorCert.kt;core/src/m` | op-level mapping unaudited for tor_cert_encode_ed22519 |
| `L3:feature/nodelist/tor_cert_eq` | D2 | `tor_cert_eq` | `core/src/main/kotlin/org/kotlintor/dir/TorCert.kt;core/src/m` | op-level mapping unaudited for tor_cert_eq |
| `L3:feature/nodelist/tor_cert_free_` | D2 | `tor_cert_free_` | `core/src/main/kotlin/org/kotlintor/dir/TorCert.kt;core/src/m` | op-level mapping unaudited for tor_cert_free_ |
| `L3:feature/nodelist/tor_cert_get_checkable_sig` | D2 | `tor_cert_get_checkable_sig` | `core/src/main/kotlin/org/kotlintor/dir/TorCert.kt;core/src/m` | op-level mapping unaudited for tor_cert_get_checkable_sig |

## Process

1. Pick the first `D0`/`D1` row in a priority module.
2. Implement against C Tor source; add/adjust tests.
3. Re-run `python3 scripts/ctor_inventory_scan.py` and update depth only with evidence.
4. Status remains **0.1.0-SNAPSHOT** until release criteria say otherwise.

```bash
python3 scripts/ctor_inventory_scan.py
./gradlew :core:test --tests 'org.kotlintor.elevate.*'
```
