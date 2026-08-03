# C Tor missing / partial inventory (generated)

**Source of truth:** [`CTOR_MASTER_INVENTORY.md`](CTOR_MASTER_INVENTORY.md) + [`generated/ctor_master_inventory.csv`](generated/ctor_master_inventory.csv)

Do **not** treat feature-board ✅ in PARITY_GAPS as completeness. Elevate only by citing `row_id` below; raise at most one depth grade per change.

Global depth counts: D2=2122, D3=11, N/A=203

## Lowest-depth queue (priority modules, top 80)

| row_id | depth | unit | ktor_path | gaps |
|--------|-------|------|-----------|------|
| `L1:app/config/config.c` | D2 | `config.c` | `core/src/main/kotlin/org/kotlintor/config/TorConfig.kt;core/` | field-by-field semantic wiring |
| `L1:app/config/quiet_level.c` | D2 | `quiet_level.c` | `core/src/main/kotlin/org/kotlintor/config/TorConfig.kt` | deepen toward C Tor control-flow |
| `L1:app/config/resolve_addr.c` | D2 | `resolve_addr.c` | `core/src/main/kotlin/org/kotlintor/net/NetworkPolicy.kt;core` | deepen toward C Tor control-flow |
| `L1:app/config/statefile.c` | D2 | `statefile.c` | `core/src/main/kotlin/org/kotlintor/config/*` | full subsystem_list parity |
| `L1:core/crypto/hs_ntor.c` | D2 | `hs_ntor.c` | `core/src/main/kotlin/org/kotlintor/crypto/*;core/src/main/ko` | audit hot-path + tests before D3 |
| `L1:core/crypto/onion_crypto.c` | D2 | `onion_crypto.c` | `core/src/main/kotlin/org/kotlintor/crypto/*` | audit hot-path + tests before D3 |
| `L1:core/crypto/onion_fast.c` | D2 | `onion_fast.c` | `core/src/main/kotlin/org/kotlintor/crypto/*` | audit hot-path + tests before D3 |
| `L1:core/crypto/relay_crypto.c` | D2 | `relay_crypto.c` | `core/src/main/kotlin/org/kotlintor/circuit/CircuitCrypto.kt` | audit hot-path + tests before D3 |
| `L1:core/crypto/relay_crypto_tor1.c` | D2 | `relay_crypto_tor1.c` | `core/src/main/kotlin/org/kotlintor/circuit/CircuitCrypto.kt` | audit hot-path + tests before D3 |
| `L1:core/mainloop/connection.c` | D2 | `connection.c` | `core/src/main/kotlin/org/kotlintor/link/ConnectionSt.kt;core` | full connection_t mainloop |
| `L1:core/mainloop/cpuworker.c` | D2 | `cpuworker.c` | `core/src/main/kotlin/org/kotlintor/os/*` | audit hot-path + tests before D3 |
| `L1:core/mainloop/mainloop.c` | D2 | `mainloop.c` | `core/src/main/kotlin/org/kotlintor/TorDaemon.kt;cli/src/main` | audit hot-path + tests before D3 |
| `L1:core/mainloop/mainloop_pubsub.c` | D2 | `mainloop_pubsub.c` | `cli/src/main/kotlin/org/kotlintor/cli/Main.kt` | audit hot-path + tests before D3 |
| `L1:core/mainloop/mainloop_sys.c` | D2 | `mainloop_sys.c` | `cli/src/main/kotlin/org/kotlintor/cli/Main.kt` | audit hot-path + tests before D3 |
| `L1:core/mainloop/netstatus.c` | D2 | `netstatus.c` | `core/src/main/kotlin/org/kotlintor/status/HeartbeatStatus.kt` | deepen toward C Tor control-flow |
| `L1:core/mainloop/periodic.c` | D2 | `periodic.c` | `core/src/main/kotlin/org/kotlintor/TorDaemon.kt` | audit hot-path + tests before D3 |
| `L1:core/or/address_set.c` | D2 | `address_set.c` | `core/src/main/kotlin/org/kotlintor/net/AddressSet.kt` | audit hot-path + tests before D3 |
| `L1:core/or/channel.c` | D2 | `channel.c` | `core/src/main/kotlin/org/kotlintor/link/OrChannel.kt;core/sr` | deepen toward C Tor control-flow |
| `L1:core/or/channelpadding.c` | D2 | `channelpadding.c` | `core/src/main/kotlin/org/kotlintor/link/ChannelPadding.kt;co` | audit hot-path + tests before D3 |
| `L1:core/or/channeltls.c` | D2 | `channeltls.c` | `core/src/main/kotlin/org/kotlintor/link/OrConnection.kt;core` | capped by lite/not-ported |
| `L1:core/or/circuitbuild.c` | D2 | `circuitbuild.c` | `core/src/main/kotlin/org/kotlintor/circuit/Circuit.kt;core/s` | deepen toward C Tor control-flow |
| `L1:core/or/circuitlist.c` | D2 | `circuitlist.c` | `core/src/main/kotlin/org/kotlintor/circuit/CircuitList.kt;co` | full purpose matrix / global lists |
| `L1:core/or/circuitmux.c` | D2 | `circuitmux.c` | `core/src/main/kotlin/org/kotlintor/circuit/CircuitMux.kt;cor` | full cmux queues / policies |
| `L1:core/or/circuitmux_ewma.c` | D2 | `circuitmux_ewma.c` | `core/src/main/kotlin/org/kotlintor/circuit/CircuitMux.kt;cor` | consensus-tuned EWMA edge cases |
| `L1:core/or/circuitpadding.c` | D2 | `circuitpadding.c` | `core/src/main/kotlin/org/kotlintor/circuit/CircpadFsm.kt;cor` | live middle ACK / full machines |
| `L1:core/or/circuitpadding_machines.c` | D2 | `circuitpadding_machines.c` | `core/src/main/kotlin/org/kotlintor/circuit/CircuitPaddingMac` | full WTF-PAD machine tables from C |
| `L1:core/or/circuitstats.c` | D2 | `circuitstats.c` | `core/src/main/kotlin/org/kotlintor/path/PathBias.kt;core/src` | deepen toward C Tor control-flow |
| `L1:core/or/circuituse.c` | D2 | `circuituse.c` | `core/src/main/kotlin/org/kotlintor/circuit/Circuit.kt` | deepen toward C Tor control-flow |
| `L1:core/or/command.c` | D2 | `command.c` | `core/src/main/kotlin/org/kotlintor/circuit/Circuit.kt;core/s` | deepen toward C Tor control-flow |
| `L1:core/or/conflux.c` | D2 | `conflux.c` | `core/src/main/kotlin/org/kotlintor/circuit/Conflux.kt;core/s` | deepen toward C Tor control-flow |
| `L1:core/or/conflux_cell.c` | D2 | `conflux_cell.c` | `core/src/main/kotlin/org/kotlintor/circuit/Conflux.kt;core/s` | audit hot-path + tests before D3 |
| `L1:core/or/conflux_params.c` | D2 | `conflux_params.c` | `core/src/main/kotlin/org/kotlintor/circuit/Conflux.kt` | audit hot-path + tests before D3 |
| `L1:core/or/conflux_pool.c` | D2 | `conflux_pool.c` | `core/src/main/kotlin/org/kotlintor/circuit/Conflux.kt` | audit hot-path + tests before D3 |
| `L1:core/or/conflux_sys.c` | D2 | `conflux_sys.c` | `core/src/main/kotlin/org/kotlintor/circuit/ConfluxScheduler.` | deepen toward C Tor control-flow |
| `L1:core/or/conflux_util.c` | D2 | `conflux_util.c` | `core/src/main/kotlin/org/kotlintor/circuit/Conflux.kt` | audit hot-path + tests before D3 |
| `L1:core/or/congestion_control_common.c` | D2 | `congestion_control_common.c` | `core/src/main/kotlin/org/kotlintor/circuit/CongestionControl` | audit hot-path + tests before D3 |
| `L1:core/or/congestion_control_flow.c` | D2 | `congestion_control_flow.c` | `core/src/main/kotlin/org/kotlintor/circuit/CircuitFlowContro` | audit hot-path + tests before D3 |
| `L1:core/or/congestion_control_vegas.c` | D2 | `congestion_control_vegas.c` | `core/src/main/kotlin/org/kotlintor/circuit/CongestionControl` | audit hot-path + tests before D3 |
| `L1:core/or/connection_edge.c` | D2 | `connection_edge.c` | `core/src/main/kotlin/org/kotlintor/circuit/ConnectionEdge.kt` | deepen toward C Tor control-flow |
| `L1:core/or/connection_or.c` | D2 | `connection_or.c` | `core/src/main/kotlin/org/kotlintor/link/OrConnection.kt;core` | remaining edge cases vs connection_or.c; capped by lite/not-ported |
| `L1:core/or/crypt_path.c` | D2 | `crypt_path.c` | `core/src/main/kotlin/org/kotlintor/circuit/CircuitCrypto.kt;` | audit hot-path + tests before D3 |
| `L1:core/or/dos.c` | D2 | `dos.c` | `core/src/main/kotlin/org/kotlintor/relay/*;core/src/main/kot` | deepen toward C Tor control-flow |
| `L1:core/or/dos_config.c` | D2 | `dos_config.c` | `core/src/main/kotlin/org/kotlintor/config/TorConfig.kt;core/` | deepen toward C Tor control-flow |
| `L1:core/or/dos_sys.c` | D2 | `dos_sys.c` | `core/src/main/kotlin/org/kotlintor/relay/*` | audit hot-path + tests before D3 |
| `L1:core/or/extendinfo.c` | D2 | `extendinfo.c` | `core/src/main/kotlin/org/kotlintor/circuit/ExtendInfo.kt` | full extendinfo.c helpers |
| `L1:core/or/ocirc_event.c` | D2 | `ocirc_event.c` | `control/src/main/kotlin/org/kotlintor/control/ControlServer.` | audit hot-path + tests before D3 |
| `L1:core/or/onion.c` | D2 | `onion.c` | `core/src/main/kotlin/org/kotlintor/circuit/Circuit.kt;core/s` | deepen toward C Tor control-flow |
| `L1:core/or/or_periodic.c` | D2 | `or_periodic.c` | `core/src/main/kotlin/org/kotlintor/relay/RelayService.kt;cor` | audit hot-path + tests before D3 |
| `L1:core/or/or_sys.c` | D2 | `or_sys.c` | `core/src/main/kotlin/org/kotlintor/relay/RelayService.kt;cor` | audit hot-path + tests before D3 |
| `L1:core/or/orconn_event.c` | D2 | `orconn_event.c` | `control/src/main/kotlin/org/kotlintor/control/ControlServer.` | audit hot-path + tests before D3 |
| `L1:core/or/policies.c` | D2 | `policies.c` | `core/src/main/kotlin/org/kotlintor/net/NetworkPolicy.kt;core` | deepen toward C Tor control-flow |
| `L1:core/or/protover.c` | D2 | `protover.c` | `core/src/main/kotlin/org/kotlintor/dir/*` | audit hot-path + tests before D3 |
| `L1:core/or/reasons.c` | D2 | `reasons.c` | `core/src/main/kotlin/org/kotlintor/cell/Reasons.kt` | audit hot-path + tests before D3 |
| `L1:core/or/relay.c` | D2 | `relay.c` | `core/src/main/kotlin/org/kotlintor/circuit/Circuit.kt;core/s` | deepen toward C Tor control-flow |
| `L1:core/or/relay_msg.c` | D2 | `relay_msg.c` | `core/src/main/kotlin/org/kotlintor/cell/*;core/src/main/kotl` | deepen toward C Tor control-flow |
| `L1:core/or/scheduler.c` | D2 | `scheduler.c` | `core/src/main/kotlin/org/kotlintor/link/ChannelScheduler.kt;` | full scheduler policies |
| `L1:core/or/scheduler_kist.c` | D2 | `scheduler_kist.c` | `core/src/main/kotlin/org/kotlintor/link/ChannelScheduler.kt;` | kernel KIST scheduler_channel full path |
| `L1:core/or/scheduler_vanilla.c` | D2 | `scheduler_vanilla.c` | `core/src/main/kotlin/org/kotlintor/link/ChannelScheduler.kt` | deepen toward C Tor control-flow |
| `L1:core/or/sendme.c` | D2 | `sendme.c` | `core/src/main/kotlin/org/kotlintor/circuit/CircuitFlowContro` | audit hot-path + tests before D3 |
| `L1:core/or/status.c` | D2 | `status.c` | `core/src/main/kotlin/org/kotlintor/status/HeartbeatStatus.kt` | full status.c heartbeat counters |
| `L1:core/or/trace_probes_circuit.c` | D2 | `trace_probes_circuit.c` | `core/src/main/kotlin/org/kotlintor/circuit/Circuit.kt` | deepen toward C Tor control-flow |
| `L1:core/or/versions.c` | D2 | `versions.c` | `core/src/main/kotlin/org/kotlintor/link/OrConnection.kt;core` | deepen toward C Tor control-flow |
| `L1:core/proto/proto_cell.c` | D2 | `proto_cell.c` | `core/src/main/kotlin/org/kotlintor/cell/*;core/src/main/kotl` | audit hot-path + tests before D3 |
| `L1:core/proto/proto_control0.c` | D2 | `proto_control0.c` | `core/src/main/kotlin/org/kotlintor/link/Control0Peek.kt` | full control0 reject on live control port |
| `L1:core/proto/proto_ext_or.c` | D2 | `proto_ext_or.c` | `core/src/main/kotlin/org/kotlintor/pt/ExtOrPort.kt` | audit hot-path + tests before D3 |
| `L1:core/proto/proto_haproxy.c` | D2 | `proto_haproxy.c` | `core/src/main/kotlin/org/kotlintor/net/HaproxyProxyHeader.kt` | PROXY v2 / listener inject path |
| `L1:core/proto/proto_http.c` | D2 | `proto_http.c` | `core/src/main/kotlin/org/kotlintor/net/*` | audit hot-path + tests before D3 |
| `L1:core/proto/proto_socks.c` | D2 | `proto_socks.c` | `core/src/main/kotlin/org/kotlintor/net/*;proxy/src/main/kotl` | audit hot-path + tests before D3 |
| `L1:feature/client/addressmap.c` | D2 | `addressmap.c` | `core/src/main/kotlin/org/kotlintor/net/AutomapAndDnsCache.kt` | deepen toward C Tor control-flow |
| `L1:feature/client/bridges.c` | D2 | `bridges.c` | `core/src/main/kotlin/org/kotlintor/pt/*;core/src/main/kotlin` | deepen toward C Tor control-flow |
| `L1:feature/client/circpathbias.c` | D2 | `circpathbias.c` | `core/src/main/kotlin/org/kotlintor/path/PathBias.kt;core/src` | full pathbias use/build FSM |
| `L1:feature/client/dnsserv.c` | D2 | `dnsserv.c` | `proxy/src/main/kotlin/org/kotlintor/proxy/*;core/src/main/ko` | audit hot-path + tests before D3 |
| `L1:feature/client/entrynodes.c` | D2 | `entrynodes.c` | `core/src/main/kotlin/org/kotlintor/path/EntryGuardFsm.kt;cor` | deepen toward C Tor control-flow |
| `L1:feature/client/proxymode.c` | D2 | `proxymode.c` | `proxy/src/main/kotlin/org/kotlintor/proxy/*` | audit hot-path + tests before D3 |
| `L1:feature/client/transports.c` | D2 | `transports.c` | `core/src/main/kotlin/org/kotlintor/pt/*` | audit hot-path + tests before D3 |
| `L1:feature/control/btrack.c` | D2 | `btrack.c` | `control/src/main/kotlin/org/kotlintor/control/ControlServer.` | audit hot-path + tests before D3 |
| `L1:feature/control/btrack_circuit.c` | D2 | `btrack_circuit.c` | `core/src/main/kotlin/org/kotlintor/circuit/Circuit.kt` | deepen toward C Tor control-flow |
| `L1:feature/control/btrack_orconn.c` | D2 | `btrack_orconn.c` | `control/src/main/kotlin/org/kotlintor/control/ControlServer.` | audit hot-path + tests before D3 |
| `L1:feature/control/btrack_orconn_cevent.c` | D2 | `btrack_orconn_cevent.c` | `control/src/main/kotlin/org/kotlintor/control/ControlServer.` | audit hot-path + tests before D3 |
| `L1:feature/control/btrack_orconn_maps.c` | D2 | `btrack_orconn_maps.c` | `control/src/main/kotlin/org/kotlintor/control/ControlServer.` | audit hot-path + tests before D3 |

## Process

1. Pick the first `D0`/`D1` row in a priority module.
2. Implement against C Tor source; add/adjust tests.
3. Re-run `python3 scripts/ctor_inventory_scan.py` and update depth only with evidence.
4. Status remains **0.1.0-SNAPSHOT** until release criteria say otherwise.

```bash
python3 scripts/ctor_inventory_scan.py
./gradlew :core:test --tests 'org.kotlintor.elevate.*'
```
