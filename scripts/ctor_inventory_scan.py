#!/usr/bin/env python3
"""Enumerate C Tor product surface vs kotlin-tor and emit master inventory CSV.

Layers:
  1 — product .c modules
  2 — *_st.h / or.h typedefs
  3 — exported ops from priority headers
  4 — or_options_st.h fields vs TorConfig / TorrcManpageKeys

Also regenerates docs/CTOR_MISSING_INVENTORY.md lowest-depth queue and
injects a summary into docs/CTOR_MASTER_INVENTORY.md.

Usage:
  python3 scripts/ctor_inventory_scan.py
  python3 scripts/ctor_inventory_scan.py --check-lite
  python3 scripts/ctor_inventory_scan.py --check-naming
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

CTOR_DEFAULT = Path("/home/user/repos/tor")
KTOR_DEFAULT = Path("/home/user/repos/kotlin-tor")

SKIP_TOP = {"test", "ext", "tools", "config"}  # config/ is geoip data only
PRODUCT_TOP = {"app", "core", "feature", "lib", "trunnel"}

# Heuristic basename → kotlin relative path hints (under org/kotlintor)
BASENAME_HINTS: dict[str, list[str]] = {
    "socks5": ["trunnel/Socks5.kt"],
    "sendme_cell": ["trunnel/SendmeCell.kt"],
    "cell_rendezvous": ["trunnel/CellRendezvous.kt"],
    "cell_introduce1": ["trunnel/CellIntroduce1.kt"],
    "cell_establish_intro": ["trunnel/CellEstablishIntro.kt"],
    "flow_control_cells": ["trunnel/FlowControlCells.kt"],
    "extension": ["trunnel/Extension.kt"],
    "ed25519_cert": ["hs/Ed25519Cert.kt"],
    "congestion_control": ["trunnel/CongestionControl.kt"],
    "circpad_negotiation": ["trunnel/CircpadNegotiation.kt"],
    "channelpadding_negotiation": ["trunnel/ChannelpaddingNegotiation.kt"],
    "trace_probes_circuit": ["circuit/TraceProbesCircuit.kt"],
    "metrics": ["metrics/Metrics.kt"],
    "tor_main": ["app/TorMain.kt"],
    "ntmain": ["app/NtMain.kt"],
    "main": ["app/Main.kt"],
    "circuitbuild_relay": ["circuit/CircuitBuildRelay.kt"],
    "channel": ["link/Channel.kt"],
    "channeltls": ["link/ChannelTls.kt", "link/OrConnection.kt"],
    "channelpadding": ["link/ChannelPadding.kt", "link/PaddingNegotiate.kt"],
    "circuitbuild": ["circuit/CircuitBuild.kt"],
    "circuitlist": ["circuit/CircuitList.kt"],
    "circuituse": ["circuit/CircuitUse.kt"],
    "circuitmux": ["circuit/CircuitMux.kt"],
    "circuitmux_ewma": ["circuit/CircuitMuxEwma.kt"],
    "circuitpadding": ["circuit/CircuitPadding.kt"],
    "circuitpadding_machines": ["circuit/CircuitPaddingMachines.kt"],
    "circuitstats": ["circuit/CircuitStats.kt"],
    "command": ["circuit/Command.kt"],
    "or": ["cell/Cell.kt"],
    "connection_edge": ["circuit/ConnectionEdge.kt"],
    "connection_or": ["link/ConnectionOr.kt", "link/OrConnection.kt"],
    "crypt_path": ["circuit/CryptPath.kt", "circuit/CircuitCrypto.kt", "circuit/RelayCryptoCgo.kt"],
    "onion": ["circuit/Onion.kt"],
    "relay": ["circuit/Relay.kt"],
    "relay_msg": ["cell/RelayMsg.kt"],
    "sendme": ["circuit/Sendme.kt", "circuit/CircuitFlowControl.kt", "circuit/CongestionControl.kt"],
    "policies": ["net/Policies.kt"],
    "protover": ["dir/Protover.kt"],
    "scheduler": ["link/Scheduler.kt"],
    "scheduler_kist": ["link/SchedulerKist.kt"],
    "scheduler_vanilla": ["link/SchedulerVanilla.kt"],
    "dos": ["relay/Dos.kt", "relay/DosGuard.kt"],
    "conflux": ["circuit/Conflux.kt"],
    "conflux_pool": ["circuit/ConfluxPool.kt", "circuit/Conflux.kt"],
    "conflux_cell": ["circuit/ConfluxCell.kt", "circuit/Conflux.kt"],
    "conflux_util": ["circuit/ConfluxUtil.kt", "circuit/Conflux.kt"],
    "conflux_params": ["circuit/ConfluxParams.kt", "circuit/Conflux.kt"],
    "conflux_sys": ["circuit/ConfluxSys.kt"],
    "congestion_control_common": ["circuit/CongestionControlCommon.kt", "circuit/CongestionControl.kt"],
    "congestion_control_vegas": ["circuit/CongestionControlVegas.kt", "circuit/CongestionControl.kt"],
    "congestion_control_flow": ["circuit/CongestionControlFlow.kt"],
    "status": ["status/Status.kt", "status/HeartbeatStatus.kt"],
    "address_set": ["net/AddressSet.kt"],
    "onion_ntor": ["crypto/OnionNtor.kt", "crypto/Ntor.kt"],
    "onion_ntor_v3": ["crypto/OnionNtorV3.kt", "crypto/NtorV3.kt"],
    "onion_fast": ["crypto/OnionFast.kt", "crypto/CreateFast.kt"],
    "hs_ntor": ["hs/HsNtor.kt"],
    "relay_crypto": ["circuit/RelayCrypto.kt", "circuit/CircuitCrypto.kt", "circuit/RelayCryptoTor1.kt"],
    "relay_crypto_tor1": ["circuit/RelayCryptoTor1.kt", "circuit/CircuitCrypto.kt"],
    "relay_crypto_cgo": ["circuit/RelayCryptoCgo.kt", "crypto/"],
    "onion_crypto": ["crypto/OnionCrypto.kt", "crypto/OnionFast.kt"],
    "proto_socks": ["net/ProtoSocks.kt", "net/SocksCodec.kt"],
    "proto_http": ["net/ProtoHttp.kt", "net/HttpConnectCodec.kt"],
    "proto_cell": ["cell/ProtoCell.kt", "cell/Cell.kt"],
    "proto_ext_or": ["pt/ProtoExtOr.kt"],
    "entrynodes": ["path/EntryNodes.kt", "path/EntryGuardFsm.kt"],
    "bridges": ["pt/Bridges.kt"],
    "transports": ["pt/Transports.kt"],
    "addressmap": ["net/AddressMap.kt"],
    "dnsserv": ["proxy/DnsServ.kt"],
    "circpathbias": ["path/CircPathBias.kt", "path/PathBias.kt"],
    "control": ["control/Control.kt"],
    "control_cmd": ["control/ControlCmd.kt"],
    "control_events": ["control/ControlEvents.kt"],
    "control_getinfo": ["control/ControlGetinfo.kt"],
    "control_auth": ["control/ControlAuth.kt"],
    "control_bootstrap": ["control/ControlBootstrap.kt"],
    "control_hs": ["control/ControlHs.kt"],
    "control_proto": ["control/ControlProto.kt"],
    "control_fmt": ["control/ControlFmt.kt"],
    "btrack": ["control/Btrack.kt"],
    "btrack_orconn": ["control/BtrackOrconn.kt"],
    "btrack_orconn_cevent": ["control/BtrackOrconnCevent.kt"],
    "btrack_orconn_maps": ["control/BtrackOrconnMaps.kt"],
    "btrack_circuit": ["control/BtrackCircuit.kt"],
    "getinfo_geoip": ["control/GetinfoGeoip.kt"],
    "dos_config": ["relay/DosConfig.kt", "relay/DosOptions.kt"],
    "dos_sys": ["relay/DosSys.kt", "relay/DosGuard.kt"],
    "extendinfo": ["circuit/ExtendInfo.kt"],
    "hs_cache": ["hs/HsCache.kt"],
    "dirlist": ["dir/DirList.kt"],
    "routermode": ["relay/RouterMode.kt"],
    "proto_haproxy": ["net/ProtoHaproxy.kt"],
    "proto_control0": ["link/ProtoControl0.kt"],
    "dirauth_config": ["dir/DirAuthConfig.kt"],
    "dirauth_sys": ["dir/DirAuthSys.kt"],
    "dirauth_periodic": ["dir/DirAuthPeriodic.kt"],
    "dirclient_modes": ["dir/DirClientModes.kt"],
    "parsecommon": ["dir/ParseCommon.kt"],
    "policy_parse": ["dir/PolicyParse.kt"],
    "unparseable": ["dir/Unparseable.kt"],
    "sigcommon": ["dir/SigCommon.kt", "dir/DirParseHelpers.kt"],
    "signing": ["dir/Signing.kt"],
    "authcert_parse": ["dir/AuthCertParse.kt"],
    "hs_common": ["hs/HsCommon.kt", "hs/HsCommonConfigDos.kt"],
    "hs_stats": ["stats/HsStats.kt"],
    "hs_circuitmap": ["hs/HsCircuitmap.kt"],
    "hs_config": ["hs/HsConfig.kt"],
    "hs_control": ["hs/HsControl.kt"],
    "hs_dos": ["hs/HsDos.kt"],
    "hs_ident": ["hs/HsIdent.kt"],
    "hs_intropoint": ["hs/HsIntropoint.kt"],
    "hs_metrics": ["hs/HsMetrics.kt"],
    "hs_metrics_entry": ["hs/HsMetricsEntry.kt"],
    "hs_sys": ["hs/HsSys.kt"],
    "torcert": ["dir/TorCert.kt", "hs/Ed25519Cert.kt"],
    "relay_config": ["relay/RelayConfig.kt"],
    "relay_find_addr": ["relay/RelayFindAddr.kt"],
    "relay_sys": ["relay/RelaySys.kt"],
    "relay_periodic": ["relay/RelayPeriodic.kt"],
    "relay_metrics": ["relay/RelayMetrics.kt"],
    "relay_handshake": ["relay/RelayHandshake.kt"],
    "transport_config": ["relay/TransportConfig.kt"],
    "tor_api": ["api/TorApi.kt"],
    "loadkey": ["keymgt/LoadKey.kt"],
    "metrics_sys": ["metrics/MetricsSys.kt", "relay/MetricsPort.kt"],
    "link_handshake": ["trunnel/LinkHandshake.kt"],
    "netinfo": ["trunnel/Netinfo.kt"],
    "subproto_request": ["trunnel/SubprotoRequest.kt"],
    "pwbox": ["trunnel/Pwbox.kt"],
    "dsigs_parse": ["dir/DsigsParse.kt"],
    "versions": ["dir/Versions.kt"],
    "ocirc_event": ["control/OcircEvent.kt"],
    "orconn_event": ["control/OrconnEvent.kt"],
    "or_periodic": ["relay/OrPeriodic.kt", "relay/RelayService.kt"],
    "or_sys": ["relay/OrSys.kt", "relay/RelayService.kt", "TorDaemon.kt"],
    "periodic": ["mainloop/Periodic.kt"],
    "netstatus": ["status/NetStatus.kt", "status/HeartbeatStatus.kt", "TorDaemon.kt"],
    "quiet_level": ["config/QuietLevel.kt"],
    "resolve_addr": ["net/ResolveAddr.kt"],
    "shutdown": ["app/Shutdown.kt"],
    "subsysmgr": ["app/SubsysMgr.kt"],
    "subsystem_list": ["app/SubsystemList.kt"],
    "risky_options": ["config/RiskyOptions.kt"],
    "proxymode": ["proxy/ProxyMode.kt"],
    "hs_service": ["hs/HsService.kt", "hs/OnionService.kt"],
    "hs_client": ["hs/HsClient.kt", "hs/OnionClient.kt"],
    "hs_circuit": ["hs/HsCircuit.kt"],
    "hs_descriptor": ["hs/HsDescriptor.kt"],
    "hs_cell": ["hs/HsCell.kt"],
    "hs_pow": ["hs/HsPow.kt"],
    "hs_ob": ["hs/HsOb.kt"],
    "replaycache": ["hs/ReplayCache.kt"],
    "shared_random_client": ["dir/SharedRandomClient.kt"],
    "shared_random": ["dir/SharedRandom.kt"],
    "shared_random_state": ["dir/SharedRandomState.kt"],
    "nodelist": ["dir/NodeList.kt"],
    "node_select": ["dir/NodeSelect.kt"],
    "networkstatus": ["dir/NetworkStatus.kt"],
    "microdesc": ["dir/Microdesc.kt"],
    "routerlist": ["dir/RouterList.kt"],
    "routerinfo": ["dir/RouterInfo.kt"],
    "authcert": ["dir/AuthCert.kt"],
    "routerset": ["dir/RouterSet.kt"],
    "nodefamily": ["dir/NodeFamily.kt"],
    "nickname": ["dir/Nickname.kt"],
    "describe": ["dir/Describe.kt"],
    "fmt_routerstatus": ["dir/FmtRouterStatus.kt"],
    "dirvote": ["dir/DirVote.kt"],
    "process_descs": ["dir/ProcessDescs.kt"],
    "bwauth": ["dir/BwAuth.kt"],
    "authmode": ["dir/AuthMode.kt"],
    "fp_pair": ["dir/FpPair.kt"],
    "recommend_pkg": ["dir/RecommendPkg.kt"],
    "bridgeauth": ["dir/BridgeAuth.kt"],
    "dircollate": ["dir/DirCollate.kt"],
    "voteflags": ["dir/VoteFlags.kt"],
    "voting_schedule": ["dir/VotingSchedule.kt"],
    "reachability": ["dir/Reachability.kt"],
    "keypin": ["dir/Keypin.kt", "dir/KeypinAndConsDiff.kt"],
    "guardfraction": ["dir/GuardFraction.kt"],
    "dircache": ["dir/DirCache.kt"],
    "dirserv": ["dir/DirServ.kt"],
    "conscache": ["dir/ConsCache.kt"],
    "consdiffmgr": ["dir/ConsDiffMgr.kt"],
    "dirclient": ["dir/DirClient.kt"],
    "dlstatus": ["dir/DlStatus.kt"],
    "directory": ["dir/Directory.kt"],
    "consdiff": ["dir/ConsDiff.kt"],
    "routerparse": ["dir/RouterParse.kt"],
    "ns_parse": ["dir/NsParse.kt"],
    "microdesc_parse": ["dir/MicrodescParse.kt"],
    "router": ["relay/Router.kt"],
    "routerkeys": ["relay/RouterKeys.kt"],
    "dns": ["net/Dns.kt"],
    "onion_queue": ["relay/OnionQueue.kt"],
    "ext_orport": ["pt/ExtOrPort.kt"],
    "selftest": ["relay/Selftest.kt"],
    "hibernate": ["relay/Hibernate.kt"],
    "rephist": ["relay/RepHist.kt"],
    "bwhist": ["relay/BwHist.kt"],
    "geoip_stats": ["stats/GeoipStats.kt"],
    "connstats": ["stats/ConnStats.kt"],
    "predict_ports": ["dir/PredictPorts.kt"],
    "geoip": ["dir/", "stats/"],
    "config": ["config/Config.kt"],
    "statefile": ["config/Statefile.kt"],
    "connection": ["link/Connection.kt"],
    "mainloop": ["mainloop/Mainloop.kt"],
    "mainloop_sys": ["mainloop/MainloopSys.kt"],
    "mainloop_pubsub": ["mainloop/MainloopPubsub.kt"],
    "cpuworker": ["os/CpuWorker.kt"],
    "tortls": ["link/TorSsl.kt"],
    "compress": ["compress/"],
    "compress_lzma": ["compress/"],
    "compress_zstd": ["compress/"],
    "compress_zlib": ["compress/"],
    "buffers": ["net/BytePipe.kt", "link/OrChannel.kt"],
    "address": ["net/"],
    "sandbox": ["os/LinuxSandbox.kt", "os/SeccompBpf.kt"],
}

LIB_NA_REASON = "Kotlin/JDK collections+stdlib+BC/Conscrypt stand in for C Tor lib/*"
REND_NA_REASON = "Legacy onion service v2; out of kotlin-tor v3 scope"

PRIORITY_OP_MODULES = {
    "core/or",
    "core/crypto",
    "core/proto",
    "core/mainloop",
    "feature/dirauth",
    "feature/hs",
    "feature/relay",
    "feature/client",
    "feature/control",
    "feature/nodelist",
}

SEED_DEPTH: dict[str, tuple[str, str, str]] = {
    "hs_config": (
        "D3",
        "HsRelayNodelistElevationTest + HsConfig/HsOpts vs hs_config.c",
        "full hs_opts_t field matrix thinner",
    ),
    "hs_dos": (
        "D3",
        "HsRelayNodelistElevationTest + HsDos/HsDosDefense vs hs_dos.c",
        "token-bucket exact C parity thinner",
    ),
    "hs_ident": (
        "D3",
        "HsRelayNodelistElevationTest + HsIdent tags vs hs_ident.c",
        "full circuit attach matrix thinner",
    ),
    "hs_intropoint": (
        "D3",
        "HsRelayNodelistElevationTest + HsIntropoint table vs hs_intropoint.c",
        "full intro rotate / failure FSM thinner",
    ),
    "hs_metrics": (
        "D3",
        "HsRelayNodelistElevationTest + HsMetrics vs hs_metrics.c",
        "full prometheus entry table thinner",
    ),
    "hs_metrics_entry": (
        "D3",
        "HsRelayNodelistElevationTest + HsMetricsEntry keys vs hs_metrics_entry.c",
        "full entry table thinner",
    ),
    "hs_sys": (
        "D3",
        "HsRelayNodelistElevationTest + HsSys lifecycle vs hs_sys.c",
        "subsystem event loop thinner",
    ),
    "hs_cell": (
        "D3",
        "HsRelayNodelistElevationTest + HsCell commands vs hs_cell.c",
        "full cell codec thinner",
    ),
    "hs_circuit": (
        "D3",
        "HsRelayNodelistElevationTest + HsCircuit purposes vs hs_circuit.c",
        "full HS circuit launch thinner",
    ),
    "hs_circuitmap": (
        "D3",
        "HsRelayNodelistElevationTest + HsCircuitmap vs hs_circuitmap.c",
        "full token map edge cases thinner",
    ),
    "hs_descriptor": (
        "D3",
        "HsRelayNodelistElevationTest + HsDescriptor vs hs_descriptor.c",
        "full encrypted desc layer thinner",
    ),
    "hs_pow": (
        "D3",
        "HsRelayNodelistElevationTest + HsPow effort vs hs_pow.c",
        "Equi-X solver thinner",
    ),
    "hs_ob": (
        "D3",
        "HsRelayNodelistElevationTest + HsOb/OnionBalanceFrontend vs hs_ob.c",
        "full OB backend sync thinner",
    ),
    "hs_stats": (
        "D3",
        "HsRelayNodelistElevationTest + HsStats vs hs_stats.c",
        "full HS stats export thinner",
    ),
    "relay_config": (
        "D3",
        "HsRelayNodelistElevationTest + RelayConfig/View vs relay_config.c",
        "full relay_config validation matrix thinner",
    ),
    "relay_find_addr": (
        "D3",
        "HsRelayNodelistElevationTest + RelayFindAddr vs relay_find_addr.c",
        "full address suggestion / IPv6 ORPort thinner",
    ),
    "relay_handshake": (
        "D3",
        "HsRelayNodelistElevationTest + RelayHandshake vs relay_handshake.c",
        "full OR handshake state machine thinner",
    ),
    "relay_metrics": (
        "D3",
        "HsRelayNodelistElevationTest + RelayMetrics vs relay_metrics.c",
        "full relay metrics catalog thinner",
    ),
    "relay_periodic": (
        "D3",
        "HsRelayNodelistElevationTest + RelayPeriodic vs relay_periodic.c",
        "full relay periodic events thinner",
    ),
    "relay_sys": (
        "D3",
        "HsRelayNodelistElevationTest + RelaySys vs relay_sys.c",
        "subsystem lifecycle thinner",
    ),
    "transport_config": (
        "D3",
        "HsRelayNodelistElevationTest + TransportConfig vs transport_config.c",
        "full PT listen option matrix thinner",
    ),
    "onion_queue": (
        "D3",
        "HsRelayNodelistElevationTest + OnionQueue vs onion_queue.c",
        "priority CREATE queue parity thinner",
    ),
    "routerlist": (
        "D3",
        "HsRelayNodelistElevationTest + RouterList vs routerlist.c",
        "full routerlist download / store thinner",
    ),
    "routerset": (
        "D3",
        "HsRelayNodelistElevationTest + RouterSet vs routerset.c",
        "full routerset policy matching thinner",
    ),
    "routerinfo": (
        "D3",
        "HsRelayNodelistElevationTest + RouterInfo vs routerinfo.c",
        "full routerinfo parse/store thinner",
    ),
    "router": (
        "D3",
        "HsRelayNodelistElevationTest + Router/RouterMode vs router.c",
        "full router identity / descriptor publish thinner",
    ),
    "dns": (
        "D3",
        "HsRelayNodelistElevationTest + Dns helpers vs dns.c",
        "full exit DNS cache / launch thinner",
    ),
    "circuitbuild_relay": (
        "D3",
        "HsRelayNodelistElevationTest + CircuitBuildRelay vs circuitbuild_relay.c",
        "full relay CREATE/EXTEND handling thinner",
    ),
    "address_set": (
        "D3",
        "AddressSet elevation vs address_set.c",
        "",
    ),
    "authmode": (
        "D3",
        "ConfigControlMuxPaddingElevationTest + AuthMode vs authmode.c",
        "dirauth live vote path thinner",
    ),
    "parsecommon": (
        "D3",
        "DirParseNodelistElevationTest + parsecommon naming primary",
        "full C Tor edge cases thinner",
    ),
    "policy_parse": (
        "D3",
        "DirParseNodelistElevationTest + policy_parse naming primary",
        "full C Tor edge cases thinner",
    ),
    "unparseable": (
        "D3",
        "DirParseNodelistElevationTest + unparseable naming primary",
        "full C Tor edge cases thinner",
    ),
    "signing": (
        "D3",
        "DirParseNodelistElevationTest + signing naming primary",
        "full C Tor edge cases thinner",
    ),
    "authcert_parse": (
        "D3",
        "DirParseNodelistElevationTest + authcert_parse naming primary",
        "full C Tor edge cases thinner",
    ),
    "nickname": (
        "D3",
        "DirParseNodelistElevationTest + nickname naming primary",
        "full C Tor edge cases thinner",
    ),
    "describe": (
        "D3",
        "DirParseNodelistElevationTest + describe naming primary",
        "full C Tor edge cases thinner",
    ),
    "node_select": (
        "D3",
        "DirParseNodelistElevationTest + node_select naming primary",
        "full C Tor edge cases thinner",
    ),
    "nodefamily": (
        "D3",
        "DirParseNodelistElevationTest + nodefamily naming primary",
        "full C Tor edge cases thinner",
    ),
    "nodelist": (
        "D3",
        "DirParseNodelistElevationTest + nodelist naming primary",
        "full C Tor edge cases thinner",
    ),
    "voting_schedule": (
        "D3",
        "DirParseNodelistElevationTest + voting_schedule naming primary",
        "full C Tor edge cases thinner",
    ),
    "dlstatus": (
        "D3",
        "DirParseNodelistElevationTest + dlstatus naming primary",
        "full C Tor edge cases thinner",
    ),
    "dirserv": (
        "D3",
        "DirParseNodelistElevationTest + dirserv naming primary",
        "full C Tor edge cases thinner",
    ),
    "microdesc_parse": (
        "D3",
        "DirParseNodelistElevationTest + microdesc_parse naming primary",
        "full C Tor edge cases thinner",
    ),
    "ns_parse": (
        "D3",
        "DirParseNodelistElevationTest + ns_parse naming primary",
        "full C Tor edge cases thinner",
    ),
    "routerparse": (
        "D3",
        "DirParseNodelistElevationTest + routerparse naming primary",
        "full C Tor edge cases thinner",
    ),
    "microdesc": (
        "D3",
        "DirParseNodelistElevationTest + microdesc naming primary",
        "full C Tor edge cases thinner",
    ),
    "authcert": (
        "D3",
        "DirParseNodelistElevationTest + authcert naming primary",
        "full C Tor edge cases thinner",
    ),
    "networkstatus": (
        "D3",
        "DirParseNodelistElevationTest + networkstatus naming primary",
        "full C Tor edge cases thinner",
    ),
    "bridgeauth": (
        "D3",
        "DirAuthElevationTest + BridgeAuth vs bridgeauth.c",
        "full bridge authority publish loop thinner",
    ),
    "bwauth": (
        "D3",
        "DirAuthElevationTest + BwAuth/BwAuthFile vs bwauth.c",
        "full measured bw vote headers thinner",
    ),
    "conscache": (
        "D3",
        "DirAuthElevationTest + ConsCache vs conscache.c",
        "full mmap / diff compression thinner",
    ),
    "consdiff": (
        "D3",
        "DirAuthElevationTest + ConsDiff vs consdiff.c",
        "full ed-script apply edge cases thinner",
    ),
    "consdiffmgr": (
        "D3",
        "DirAuthElevationTest + ConsDiffMgr vs consdiffmgr.c",
        "full background diff generation thinner",
    ),
    "dirauth_config": (
        "D3",
        "DirAuthElevationTest + DirAuthConfig vs dirauth_config.c",
        "full dirauth_options_t field matrix thinner",
    ),
    "dirauth_periodic": (
        "D3",
        "DirAuthElevationTest + DirAuthPeriodic vs dirauth_periodic.c",
        "full dirauth periodic events thinner",
    ),
    "dirauth_sys": (
        "D3",
        "DirAuthElevationTest + DirAuthSys vs dirauth_sys.c",
        "subsystem event loop thinner",
    ),
    "dircache": (
        "D3",
        "DirAuthElevationTest + DirCache vs dircache.c",
        "full HTTP dirport handler matrix thinner",
    ),
    "dircollate": (
        "D3",
        "DirAuthElevationTest + DirCollate vs dircollate.c",
        "production consensus compute thinner",
    ),
    "dirclient": (
        "D3",
        "DirAuthElevationTest + DirClient vs dirclient.c",
        "full directory_request_t state machine thinner",
    ),
    "dirclient_modes": (
        "D3",
        "DirAuthElevationTest + DirClientModes vs dirclient_modes.c",
        "all dirclient_modes predicates thinner",
    ),
    "directory": (
        "D3",
        "DirAuthElevationTest + Directory vs directory.c",
        "full directory connection purpose matrix thinner",
    ),
    "dirvote": (
        "D3",
        "DirAuthElevationTest + DirVote vs dirvote.c",
        "RSA vote signing depth thinner",
    ),
    "dsigs_parse": (
        "D3",
        "DirAuthElevationTest + DsigsParse vs dsigs_parse.c",
        "full dsigs_parse edge cases thinner",
    ),
    "fp_pair": (
        "D3",
        "DirAuthElevationTest + FpPair vs fp_pair.c",
        "",
    ),
    "guardfraction": (
        "D3",
        "DirAuthElevationTest + GuardFraction vs guardfraction.c",
        "full guardfraction weighting thinner",
    ),
    "process_descs": (
        "D3",
        "DirAuthElevationTest + ProcessDescs vs process_descs.c",
        "full authdir reject list matrix thinner",
    ),
    "reachability": (
        "D3",
        "DirAuthElevationTest + Reachability vs reachability.c",
        "dirauth OR reach testing loop thinner",
    ),
    "recommend_pkg": (
        "D3",
        "DirAuthElevationTest + RecommendPkg vs recommend_pkg.c",
        "",
    ),
    "shared_random": (
        "D3",
        "DirAuthElevationTest + SharedRandom vs shared_random.c",
        "full SRV commit/reveal phases thinner",
    ),
    "shared_random_state": (
        "D3",
        "DirAuthElevationTest + SharedRandomState vs shared_random_state.c",
        "full sr_state disk format thinner",
    ),
    "voteflags": (
        "D3",
        "DirAuthElevationTest + VoteFlags vs voteflags.c",
        "full flag threshold consensus params thinner",
    ),
    "btrack": (
        "D3",
        "ConfigControlMuxPaddingElevationTest + Btrack/BootstrapTracker vs btrack.c",
        "full controller STATUS fan-out thinner",
    ),
    "btrack_circuit": (
        "D3",
        "ConfigControlMuxPaddingElevationTest + BtrackCircuit/OcircEvent vs btrack_circuit.c",
        "full CIRC event attribute matrix thinner",
    ),
    "btrack_orconn": (
        "D3",
        "ConfigControlMuxPaddingElevationTest + BtrackOrconn vs btrack_orconn.c",
        "full ORCONN bootstrap coupling thinner",
    ),
    "btrack_orconn_cevent": (
        "D3",
        "ConfigControlMuxPaddingElevationTest + BtrackOrconnCevent vs btrack_orconn_cevent.c",
        "full ORCONN event attribute matrix thinner",
    ),
    "btrack_orconn_maps": (
        "D3",
        "ConfigControlMuxPaddingElevationTest + BtrackOrconnMaps vs btrack_orconn_maps.c",
        "full id map GC thinner",
    ),
    "control": (
        "D3",
        "ConfigControlMuxPaddingElevationTest + Control/ControlServer vs control.c",
        "full control connection lifecycle thinner",
    ),
    "control_auth": (
        "D3",
        "ConfigControlMuxPaddingElevationTest + ControlAuth/SAFECOOKIE vs control_auth.c",
        "hashed-password edge cases thinner",
    ),
    "control_bootstrap": (
        "D3",
        "ConfigControlMuxPaddingElevationTest + ControlBootstrap vs control_bootstrap.c",
        "full STATUS_CLIENT fan-out thinner",
    ),
    "control_cmd": (
        "D3",
        "ConfigControlMuxPaddingElevationTest + ControlCmd table vs control_cmd.c",
        "full command handler matrix thinner",
    ),
    "control_events": (
        "D3",
        "ConfigControlMuxPaddingElevationTest + ControlEvents vs control_events.c",
        "full event mask / rate limits thinner",
    ),
    "control_fmt": (
        "D3",
        "ConfigControlMuxPaddingElevationTest + ControlFmt vs control_fmt.c",
        "full event line attribute formatting thinner",
    ),
    "control_getinfo": (
        "D3",
        "ConfigControlMuxPaddingElevationTest + ControlGetinfo keys vs control_getinfo.c",
        "full GETINFO key table thinner",
    ),
    "control_hs": (
        "D3",
        "ConfigControlMuxPaddingElevationTest + ControlHs vs control_hs.c",
        "full ADD_ONION keyblob / client-auth thinner",
    ),
    "control_proto": (
        "D3",
        "ConfigControlMuxPaddingElevationTest + ControlProto vs control_proto.c",
        "full multiline / ISO control framing thinner",
    ),
    "getinfo_geoip": (
        "D3",
        "ConfigControlMuxPaddingElevationTest + GetinfoGeoip vs getinfo_geoip.c",
        "full ip-to-country GETINFO wiring thinner",
    ),
    "addressmap": (
        "D3",
        "MainloopChannelCircuitClientElevationTest + AddressMap vs addressmap.c",
        "full virtualaddr / TrackHostExits thinner",
    ),
    "bridges": (
        "D3",
        "MainloopChannelCircuitClientElevationTest + Bridges parse vs bridges.c",
        "full bridge transport download thinner",
    ),
    "channeltls": (
        "D3",
        "OrConnection TLS",
        "",
    ),
    "channel": (
        "D3",
        "MainloopChannelCircuitClientElevationTest + Channel/OrChannel vs channel.c",
        "full channel_t flush / destroy queue thinner",
    ),
    "circpathbias": (
        "D3",
        "OnionFastRelayDosHsElevationTest + CircPathBias/PathBiasTracker vs circpathbias.c",
        "extreme DropGuards + scale thresholds thinner",
    ),
    "circuitlist": (
        "D3",
        "CircuitListElevationTest + purpose/state/mark-close/global lists vs circuitlist.c",
        "chan-indexed circ maps / package window consensus param",
    ),
    "circuitbuild": (
        "D3",
        "MainloopChannelCircuitClientElevationTest + CircuitBuild plans vs circuitbuild.c",
        "full onion_extend / pathbias launch thinner",
    ),
    "circuitmux": (
        "D3",
        "ConfigControlMuxPaddingElevationTest + CircuitMux flushFair vs circuitmux.c",
        "full cmux channel destroy / EWMA live flush thinner",
    ),
    "circuitmux_ewma": (
        "D3",
        "ProtoverConfluxHsElevationTest + CircuitMuxEwma vs circuitmux_ewma.c",
        "live cmux channel flush thinner",
    ),
    "circuitstats": (
        "D3",
        "OnionCryptoCpuWorkerVersionsElevationTest + CircuitStats CBT quantile vs circuitstats.c",
        "full Xm/alpha timeout close consensus params thinner",
    ),
    "circuituse": (
        "D3",
        "OnionCryptoCpuWorkerVersionsElevationTest + CircuitUse purpose/dirty vs circuituse.c",
        "full launch_prediction / cannibalize / isolate streams thinner",
    ),
    "command": (
        "D3",
        "OnionCryptoCpuWorkerVersionsElevationTest + Command classify vs command.c",
        "full create/relay process_cell handlers thinner",
    ),
    "connection_edge": (
        "D3",
        "OnionDosPoliciesEventsElevationTest + ConnectionEdge stream table vs connection_edge.c",
        "full exit DNS / linked conn / half-stream thinner",
    ),
    "conflux": (
        "D3",
        "MainloopChannelCircuitClientElevationTest + Conflux set/cells vs conflux.c",
        "full multipath DATA reordering / leg failure thinner",
    ),
    "conflux_sys": (
        "D3",
        "OnionDosPoliciesEventsElevationTest + ConfluxSys init vs conflux_sys.c",
        "full pubsub / pool lifecycle thinner",
    ),
    "circuitpadding": (
        "D3",
        "ConfigControlMuxPaddingElevationTest + CircuitPadding vs circuitpadding.c",
        "live middle ACK / full machines thinner",
    ),
    "circuitpadding_machines": (
        "D3",
        "ConfigControlMuxPaddingElevationTest + CircuitPaddingMachines vs circuitpadding_machines.c",
        "full WTF-PAD machine tables thinner",
    ),
    "crypt_path": (
        "D3",
        "MetricsTorCertCryptPathElevationTest + CryptPath circular list/nextNonOpen vs crypt_path.c",
        "relay crypto attach / SENDME tag live path thinner",
    ),
    "cpuworker": (
        "D3",
        "OnionCryptoCpuWorkerVersionsElevationTest + CpuWorker queue vs cpuworker.c",
        "full onionskin reply path / workqueue priorities thinner",
    ),
    "config": (
        "D3",
        "ConfigControlMuxPaddingElevationTest + Config/TorConfig parse vs config.c",
        "field-by-field semantic wiring thinner",
    ),
    "congestion_control_common": (
        "D3",
        "ChannelPaddingCcCommonElevationTest + CongestionControlCommon enabled/params vs congestion_control_common.c",
        "full cwnd init path / AlwaysCongestionControl / trunnel CC ext thinner",
    ),
    "congestion_control_flow": (
        "D3",
        "CongestionControlFlowElevationTest + CongestionControlFlow XON/XOFF vs congestion_control_flow.c",
        "dropmark rate-limit scaling / control STREAM_EVENT wiring",
    ),
    "congestion_control_vegas": (
        "D3",
        "ConfluxParamsCellVegasElevationTest + CongestionControlVegas params/update vs congestion_control_vegas.c",
        "full cwnd_full / gamma path / consensus param wiring thinner",
    ),
    "channelpadding": (
        "D3",
        "ChannelPaddingCcCommonElevationTest + ChannelPaddingController decide vs channelpadding.c",
        "live channel timer / netflow reduced SOS edge thinner",
    ),
    "conflux_cell": (
        "D3",
        "ConfluxParamsCellVegasElevationTest + ConfluxCell LINK/SWITCH vs conflux_cell.c",
        "live relay_send_command_from_edge path thinner",
    ),
    "conflux_params": (
        "D3",
        "ConfluxParamsCellVegasElevationTest + ConfluxParams consensus/torrc vs conflux_params.c",
        "ConfluxEnabled=-1 auto ternary / server ratelim warn thinner",
    ),
    "conflux_pool": (
        "D3",
        "ProtoverConfluxHsElevationTest + ConfluxPool init/link/alg vs conflux_pool.c",
        "live launch_leg / predict_new / get_circ_for_conn thinner",
    ),
    "conflux_util": (
        "D3",
        "ProtoverConfluxHsElevationTest + ConfluxUtil can_send/validate vs conflux_util.c",
        "stream list sync / half-stream attach thinner",
    ),
    "connection": (
        "D3",
        "MainloopChannelCircuitClientElevationTest + ConnectionModule/Table vs connection.c",
        "full connection_t mainloop / linked flush thinner",
    ),
    "connection_or": (
        "D3",
        "OrConnection live TLS OR",
        "remaining edge cases vs connection_or.c",
    ),
    "dirauth_stub": (
        "N/A",
        "C Tor build stub when dirauth disabled",
        "kotlin-tor always has dirauth lite",
    ),
    "dos_sys": (
        "D3",
        "OnionFastRelayDosHsElevationTest + DosSys init/shutdown vs dos_sys.c",
        "full DoS consensus param reload / circuit flood thinner",
    ),
    "dos": (
        "D3",
        "OnionDosPoliciesEventsElevationTest + Dos/DosGuard vs dos.c",
        "full CC DoS / intro point defenses thinner",
    ),
    "dos_config": (
        "D3",
        "OnionDosPoliciesEventsElevationTest + DosConfig/DosOptions vs dos_config.c",
        "full dos_options.inc consensus update thinner",
    ),
    "dnsserv": (
        "D3",
        "DnsServProxyModeElevationTest + DnsServ vs dnsserv.c",
        "full DNSPort UDP/TCP answer path thinner",
    ),
    "dircache_stub": (
        "N/A",
        "C Tor build stub",
        "",
    ),
    "dirlist": (
        "D3",
        "DirListElevationTest + DirList digest/dirport helpers vs dirlist.c",
        "auth_dirport_usage enum matrix thinner",
    ),
    "ext_orport": (
        "D3",
        "ExtOrPortServer",
        "",
    ),
    "extendinfo": (
        "D3",
        "ExtendInfo.describe + fromRouterStatus elevation",
        "full extendinfo.c helpers thinner",
    ),
    "entrynodes": (
        "D3",
        "MainloopChannelCircuitClientElevationTest + EntryNodes/Fsm vs entrynodes.c",
        "full sampled/confirmed/primary set thinner",
    ),
    "fmt_routerstatus": (
        "D3",
        "FmtRouterStatusElevationTest + vote Measured/GuardFraction/id vs fmt_routerstatus.c",
        "descriptor digest assert path for non-control formats",
    ),
    "hibernate": (
        "D3",
        "RelayStatsElevationTest + Hibernate/HibernateAccounting vs hibernate.c",
        "full accounting hibernate FSM thinner",
    ),
    "hs_ntor": (
        "D3",
        "ProtoverConfluxHsElevationTest + HsNtorTest vectors vs hs_ntor.c",
        "service-side INTRODUCE decrypt path thinner",
    ),
    "hs_cache": (
        "D3",
        "OnionFastRelayDosHsElevationTest + HsCache dir/client/intro/oom vs hs_cache.c",
        "full OOM policy / dirconn fetch race thinner",
    ),
    "hs_client": (
        "D3",
        "hs client INTRODUCE/REND",
        "",
    ),
    "hs_common": (
        "D3",
        "OnionFastRelayDosHsElevationTest + HsCommon period/index vs hs_common.c",
        "full hsdir index math / consensus SRV thinner",
    ),
    "hs_control": (
        "D3",
        "HsControlElevationTest + HS_DESC_CONTENT body / auth / fail reasons vs hs_control.c",
        "full hsdir_index fetch/store wiring into events",
    ),
    "hs_service": (
        "D3",
        "OnionService host path",
        "full hs_service.c edge cases",
    ),
    "keypin": (
        "D3",
        "KeypinElevationTest + Keypin FOUND/ADDED/MISMATCH/NOT_FOUND vs keypin.c",
        "O_SYNC journal fd edge cases",
    ),
    "link_handshake": (
        "D3",
        "TrunnelElevationTest + LinkHandshake vs link_handshake.c",
        "full CERTS/AUTHENTICATE trunnel thinner",
    ),
    "loadkey": (
        "D3",
        "LoadKeyElevationTest + ed_key_init_from_file flags vs loadkey.c",
        "encrypted secret / NEEDCERT / OfflineMasterKey path",
    ),
    "metrics_sys": (
        "D3",
        "MetricsTorCertCryptPathElevationTest + MetricsSys init/shutdown vs metrics_sys.c",
        "full prometheus scrape HTTP + label matrix",
    ),
    "mainloop": (
        "D3",
        "MainloopChannelCircuitClientElevationTest + Mainloop tick vs mainloop.c",
        "full libevent / socket callbacks thinner",
    ),
    "mainloop_sys": (
        "D3",
        "MainloopChannelCircuitClientElevationTest + MainloopSys vs mainloop_sys.c",
        "full subsystem list wiring thinner",
    ),
    "mainloop_pubsub": (
        "D3",
        "MainloopChannelCircuitClientElevationTest + MainloopPubsub vs mainloop_pubsub.c",
        "full msg delivery / cross-subsys thinner",
    ),
    "netinfo": (
        "D3",
        "TrunnelElevationTest + Netinfo vs netinfo.c",
        "full netinfo address lists thinner",
    ),
    "netstatus": (
        "D3",
        "NetStatusElevationTest + NetStatus.kt vs netstatus.c",
        "mainloop periodic reschedule on wake thinner",
    ),
    "onion_crypto": (
        "D3",
        "OnionCryptoCpuWorkerVersionsElevationTest + OnionCrypto dispatch vs onion_crypto.c",
        "ntor/ntor-v3 onion_skin_* server path thinner",
    ),
    "onion": (
        "D3",
        "OnionDosPoliciesEventsElevationTest + Onion CREATE2 helpers vs onion.c",
        "full create_cell queue / TAP reject / handshake length table thinner",
    ),
    "onion_fast": (
        "D3",
        "OnionFastRelayDosHsElevationTest + OnionFast/CreateFast vs onion_fast.c",
        "CREATE_FAST obsolete KDF-TOR path only; CreateOnehop later",
    ),
    "or_sys": (
        "D3",
        "OnionFastRelayDosHsElevationTest + OrSys/RelaySys vs or_sys.c",
        "full OR subsystem list / periodic hook matrix thinner",
    ),
    "or_periodic": (
        "D3",
        "OnionCryptoCpuWorkerVersionsElevationTest + OrPeriodic vs or_periodic.c",
        "full descriptor/reachability event table thinner",
    ),
    "ocirc_event": (
        "D3",
        "OnionDosPoliciesEventsElevationTest + OcircEvent CIRC vs ocirc_event.c",
        "full pubsub / control mask thinner",
    ),
    "orconn_event": (
        "D3",
        "OnionDosPoliciesEventsElevationTest + OrconnEvent ORCONN vs orconn_event.c",
        "full pubsub / control mask thinner",
    ),
    "onion_ntor": (
        "D3",
        "crypto ntor",
        "",
    ),
    "onion_ntor_v3": (
        "D3",
        "crypto ntor-v3",
        "",
    ),
    "periodic": (
        "D3",
        "OnionCryptoCpuWorkerVersionsElevationTest + Periodic roles/flags vs periodic.c",
        "mainloop_event_t enable/disable / net-disabled thinner",
    ),
    "policies": (
        "D3",
        "OnionDosPoliciesEventsElevationTest + Policies/AddrPolicy vs policies.c",
        "full exit policy / IPv6 / rejectstar thinner",
    ),
    "proto_control0": (
        "D3",
        "ProtoControl0ElevationTest + ProtoControl0 peek vs proto_control0.c",
        "full control0 reject on live control port",
    ),
    "proto_cell": (
        "D3",
        "OnionCryptoCpuWorkerVersionsElevationTest + ProtoCell/CellCodec vs proto_cell.c",
        "var_cell / packed_cell queue thinner",
    ),
    "proto_ext_or": (
        "D3",
        "OnionCryptoCpuWorkerVersionsElevationTest + ProtoExtOr framing vs proto_ext_or.c",
        "ExtORPort text handshake + buf_t integration thinner",
    ),
    "proto_http": (
        "D3",
        "MainloopChannelCircuitClientElevationTest + ProtoHttp vs proto_http.c",
        "full fetch_from_buf_http / chunked thinner",
    ),
    "proto_socks": (
        "D3",
        "MainloopChannelCircuitClientElevationTest + ProtoSocks vs proto_socks.c",
        "full socks negotiation state machine thinner",
    ),
    "proto_haproxy": (
        "D3",
        "ProtoHaproxyElevationTest + ProtoHaproxy format/parse vs proto_haproxy.c",
        "PROXY v2 / listener inject path",
    ),
    "proxymode": (
        "D3",
        "DnsServProxyModeElevationTest + ProxyMode vs proxymode.c",
        "full proxy listener bind matrix thinner",
    ),
    "protover": (
        "D3",
        "ProtoverConfluxHsElevationTest + Protover supported/parse vs protover.c",
        "voting recommended/required lists thinner",
    ),
    "pwbox": (
        "D3",
        "TrunnelElevationTest + Pwbox vs pwbox.c",
        "password-box unused on JVM thinner",
    ),
    "quiet_level": (
        "D3",
        "QuietLevelElevationTest vs quiet_level.c",
        "",
    ),
    "reasons": (
        "D3",
        "ReasonsElevationTest vs reasons.c",
        "",
    ),
    "relay": (
        "D3",
        "MainloopChannelCircuitClientElevationTest + Relay helpers vs relay.c",
        "full relay_send_command_from_edge / deliver thinner",
    ),
    "resolve_addr": (
        "D3",
        "MainloopChannelCircuitClientElevationTest + ResolveAddr vs resolve_addr.c",
        "full AddressDisableIPv6 / authority resolve thinner",
    ),
    "relay_crypto": (
        "D3",
        "OnionFastRelayDosHsElevationTest + RelayCrypto dispatch vs relay_crypto.c",
        "full relay_crypto_t cell encrypt/decrypt hot path thinner",
    ),
    "relay_crypto_cgo": (
        "D3",
        "RelayCryptoCgo + live EXTEND V1",
        "",
    ),
    "relay_crypto_tor1": (
        "D3",
        "ProtoverConfluxHsElevationTest + RelayCryptoTor1 vs relay_crypto_tor1.c",
        "full cake encrypt/peel integration thinner",
    ),
    "relay_msg": (
        "D3",
        "OnionCryptoCpuWorkerVersionsElevationTest + RelayMsg vs relay_msg.c",
        "V1 encode/decode / tag area thinner",
    ),
    "relay_stub": (
        "N/A",
        "C Tor build stub when relay disabled",
        "kotlin-tor RelayService covers relay path",
    ),
    "rephist": (
        "D3",
        "RelayStatsElevationTest + RepHist vs rephist.c",
        "full reputation histograms thinner",
    ),
    "replaycache": (
        "D3",
        "ReplayCache INTRODUCE2",
        "",
    ),
    "routermode": (
        "D3",
        "RouterModeElevationTest + set_server_advertised/dir_server_mode vs routermode.c",
        "router_has_bandwidth_to_be_dirserver full accounting",
    ),
    "scheduler": (
        "D3",
        "ConfigControlMuxPaddingElevationTest + Scheduler select vs scheduler.c",
        "full scheduler policies / pending drain thinner",
    ),
    "scheduler_vanilla": (
        "D3",
        "OnionDosPoliciesEventsElevationTest + SchedulerVanilla vs scheduler_vanilla.c",
        "full mainloop wait / cmux flush integration thinner",
    ),
    "scheduler_kist": (
        "D3",
        "ConfigControlMuxPaddingElevationTest + SchedulerKist/KistMath vs scheduler_kist.c",
        "kernel TCP_INFO KIST scheduler_channel full path thinner",
    ),
    "sendme": (
        "D3",
        "SendmeElevationTest + Sendme v1/validate/windows vs sendme.c",
        "per-layer digest queues / edge package_window package_window edge cases",
    ),
    "sigcommon": (
        "D3",
        "SigCommonElevationTest + SigCommon hash/checksig vs sigcommon.c",
        "CST flags beyond NO_CHECK_OBJTYPE",
    ),
    "status": (
        "D3",
        "HeartbeatStatusElevationTest + secs_to_uptime/bytes_to_usage/note_connection vs status.c",
        "accounting/TLS overhead ratio lines thinner",
    ),
    "statefile": (
        "D3",
        "MainloopChannelCircuitClientElevationTest + Statefile load/save vs statefile.c",
        "full or_state_t field matrix / ExtrInfo thinner",
    ),
    "subproto_request": (
        "D3",
        "TrunnelElevationTest + subproto_request naming primary vs subproto_request.c",
        "full trunnel generated 1:1 thinner",
    ),
    "tor_api": (
        "D3",
        "TorApiElevationTest + set_command_line/setup_control_socket/run_main ownership vs tor_api.c",
        "blocking full daemon mainloop parity",
    ),
    "transports": (
        "D3",
        "MainloopChannelCircuitClientElevationTest + Transports registry vs transports.c",
        "full PT managed proxy launch thinner",
    ),
    "torcert": (
        "D3",
        "MetricsTorCertCryptPathElevationTest + TorCert parse/checksig/eq vs torcert.c",
        "RSA crosscert / X509 SHA256 cert-key types thinner",
    ),
    "trace_probes_cc": (
        "N/A",
        "LTTng/trace probes not used on JVM",
        "",
    ),
    "versions": (
        "D3",
        "OnionCryptoCpuWorkerVersionsElevationTest + Versions parse/obsolete vs versions.c",
        "protover_summary_flags / platform parse thinner",
    ),
    "selftest": (
        "D3",
        "RelayStatsElevationTest + Selftest/RelaySelfTest vs selftest.c",
        "full ORPort IPv6 reachability thinner",
    ),
    "bwhist": (
        "D3",
        "RelayStatsElevationTest + BwHist vs bwhist.c",
        "full bw_array history export thinner",
    ),
    "geoip_stats": (
        "D3",
        "RelayStatsElevationTest + GeoipStats/GeoIpStats vs geoip_stats.c",
        "full geoip request history thinner",
    ),
    "connstats": (
        "D3",
        "RelayStatsElevationTest + ConnStats vs connstats.c",
        "full conn-bi-direct export thinner",
    ),
    "routerkeys": (
        "D3",
        "RelayStatsElevationTest + RouterKeys/OnionKeyRotator vs routerkeys.c",
        "full master key offline path thinner",
    ),
    "predict_ports": (
        "D3",
        "RelayStatsElevationTest + PredictPorts vs predict_ports.c",
        "full port prediction window thinner",
    ),
    "main": (
        "D3",
        "AppMainElevationTest + Main/SubsystemList vs main.c",
        "full libevent mainloop wiring thinner",
    ),
    "ntmain": (
        "D3",
        "AppMainElevationTest + NtMain vs ntmain.c",
        "Windows service host thinner",
    ),
    "tor_main": (
        "D3",
        "AppMainElevationTest + TorMain/TorDaemon vs tor_main.c",
        "full argv/option act thinner",
    ),
    "shutdown": (
        "D3",
        "AppMainElevationTest + Shutdown/TorDaemon.stop vs shutdown.c",
        "full ordered subsystem teardown thinner",
    ),
    "subsysmgr": (
        "D3",
        "AppMainElevationTest + SubsysMgr vs subsysmgr.c",
        "full subsystem level order thinner",
    ),
    "subsystem_list": (
        "D3",
        "AppMainElevationTest + SubsystemList vs subsystem_list.c",
        "full C subsystem_t table thinner",
    ),
    "risky_options": (
        "D3",
        "AppMainElevationTest + RiskyOptions vs risky_options.c",
        "full risky option gate matrix thinner",
    ),
    "shared_random_client": (
        "D3",
        "AppMainElevationTest + SharedRandomClient vs shared_random_client.c",
        "full SRV fetch/store thinner",
    ),
    "metrics": (
        "D3",
        "AppMainElevationTest + Metrics/MetricsSys vs metrics.c",
        "full metrics store registry thinner",
    ),
    "trace_probes_circuit": (
        "D3",
        "AppMainElevationTest + TraceProbesCircuit vs trace_probes_circuit.c",
        "full LTTng/USDT probe thinner",
    ),
    "channelpadding_negotiation": (
        "D3",
        "TrunnelElevationTest + channelpadding_negotiation naming primary vs channelpadding_negotiation.c",
        "full trunnel generated 1:1 thinner",
    ),
    "circpad_negotiation": (
        "D3",
        "TrunnelElevationTest + circpad_negotiation naming primary vs circpad_negotiation.c",
        "full trunnel generated 1:1 thinner",
    ),
    "congestion_control": (
        "D3",
        "TrunnelElevationTest + congestion_control naming primary vs congestion_control.c",
        "full trunnel generated 1:1 thinner",
    ),
    "ed25519_cert": (
        "D3",
        "TrunnelElevationTest + Ed25519Cert vs ed25519_cert.c",
        "full prop220 extension matrix thinner",
    ),
    "extension": (
        "D3",
        "TrunnelElevationTest + extension naming primary vs extension.c",
        "full trunnel generated 1:1 thinner",
    ),
    "flow_control_cells": (
        "D3",
        "TrunnelElevationTest + flow_control_cells naming primary vs flow_control_cells.c",
        "full trunnel generated 1:1 thinner",
    ),
    "cell_establish_intro": (
        "D3",
        "TrunnelElevationTest + cell_establish_intro naming primary vs cell_establish_intro.c",
        "full trunnel generated 1:1 thinner",
    ),
    "cell_introduce1": (
        "D3",
        "TrunnelElevationTest + cell_introduce1 naming primary vs cell_introduce1.c",
        "full trunnel generated 1:1 thinner",
    ),
    "cell_rendezvous": (
        "D3",
        "TrunnelElevationTest + cell_rendezvous naming primary vs cell_rendezvous.c",
        "full trunnel generated 1:1 thinner",
    ),
    "sendme_cell": (
        "D3",
        "TrunnelElevationTest + sendme_cell naming primary vs sendme_cell.c",
        "full trunnel generated 1:1 thinner",
    ),
    "socks5": (
        "D3",
        "TrunnelElevationTest + Socks5 vs socks5.c",
        "full socks5 trunnel 1:1 thinner",
    ),
}


@dataclass
class Row:
    row_id: str
    layer: str
    ctor_module: str
    ctor_unit: str
    ctor_symbols: str
    ktor_path: str
    depth: str
    evidence: str
    gaps: str
    parity_board_id: str = ""

    def as_dict(self) -> dict[str, str]:
        return {
            "row_id": self.row_id,
            "layer": self.layer,
            "ctor_module": self.ctor_module,
            "ctor_unit": self.ctor_unit,
            "ctor_symbols": self.ctor_symbols,
            "ktor_path": self.ktor_path,
            "depth": self.depth,
            "evidence": self.evidence,
            "gaps": self.gaps,
            "parity_board_id": self.parity_board_id,
        }


@dataclass
class ScanState:
    ktor: Path
    ctor: Path
    lite_files: set[str] = field(default_factory=set)
    not_ported_files: set[str] = field(default_factory=set)
    kt_index: dict[str, list[str]] = field(default_factory=dict)  # stem -> paths
    ctor_refs: dict[str, list[str]] = field(default_factory=dict)  # c basename -> kt files
    manpage_keys: set[str] = field(default_factory=set)
    torconfig_fields: set[str] = field(default_factory=set)
    torconfig_text: str = ""


def module_of(rel: Path) -> str:
    parts = rel.parts
    if len(parts) >= 2 and parts[0] in PRODUCT_TOP:
        if parts[0] == "trunnel":
            return "trunnel"
        return f"{parts[0]}/{parts[1]}"
    return parts[0] if parts else ""


def collect_kotlin_signals(state: ScanState) -> None:
    roots = [
        state.ktor / "core/src/main/kotlin",
        state.ktor / "proxy/src/main/kotlin",
        state.ktor / "control/src/main/kotlin",
        state.ktor / "cli/src/main/kotlin",
        state.ktor / "android/src/main/kotlin",
    ]
    ctor_ref_re = re.compile(r"C Tor [`']([^`']+)[`']")
    for root in roots:
        if not root.is_dir():
            continue
        for p in root.rglob("*.kt"):
            rel = str(p.relative_to(state.ktor))
            text = p.read_text(encoding="utf-8", errors="replace")
            if re.search(r"lite\)", text) or re.search(r"\blite\b.*C Tor|C Tor.*\blite\b", text):
                state.lite_files.add(rel)
            if "not ported" in text.lower():
                state.not_ported_files.add(rel)
            stem = p.stem.lower()
            state.kt_index.setdefault(stem, []).append(rel)
            for m in ctor_ref_re.finditer(text):
                ref = m.group(1)
                base = Path(ref).stem.lower().replace(".c", "")
                if base.endswith(".h"):
                    base = base[:-2]
                base = re.sub(r"[^a-z0-9_]", "", base.split()[0])
                if base:
                    state.ctor_refs.setdefault(base, []).append(rel)

    # TorrcManpageKeys
    manpage = state.ktor / "core/src/main/kotlin/org/kotlintor/config/TorrcManpageKeys.kt"
    if manpage.is_file():
        t = manpage.read_text(encoding="utf-8", errors="replace")
        state.manpage_keys = set(re.findall(r'"([A-Za-z][A-Za-z0-9*]+)"', t))

    tc = state.ktor / "core/src/main/kotlin/org/kotlintor/config/TorConfig.kt"
    if tc.is_file():
        state.torconfig_text = tc.read_text(encoding="utf-8", errors="replace")
        # data class property names
        state.torconfig_fields = set(
            re.findall(r"^\s+(?:val|var)\s+([A-Za-z][A-Za-z0-9_]*)\s*:", state.torconfig_text, re.M)
        )
    cfg_dir = state.ktor / "core/src/main/kotlin/org/kotlintor/config"
    if cfg_dir.is_dir():
        for p in cfg_dir.glob("*.kt"):
            t = p.read_text(encoding="utf-8", errors="replace")
            state.torconfig_fields.update(
                re.findall(r"^\s+(?:val|var)\s+([A-Za-z][A-Za-z0-9_]*)\s*:", t, re.M)
            )
            state.torconfig_text += "\n" + t


def resolve_ktor(state: ScanState, basename: str) -> tuple[str, str]:
    """Return (ktor_path, evidence_extra)."""
    paths: list[str] = []
    pkg_roots = [
        state.ktor / "core/src/main/kotlin/org/kotlintor",
        state.ktor / "proxy/src/main/kotlin/org/kotlintor",
        state.ktor / "control/src/main/kotlin/org/kotlintor",
        state.ktor / "cli/src/main/kotlin/org/kotlintor",
        state.ktor / "android/src/main/kotlin/org/kotlintor",
    ]
    exclusive = basename in {"or"}  # too ambiguous for fuzzy stem match
    if basename in BASENAME_HINTS:
        for hint in BASENAME_HINTS[basename]:
            if hint.endswith("/"):
                for root in pkg_roots:
                    d = root / hint
                    if d.is_dir():
                        paths.append(str(d.relative_to(state.ktor)) + "/*")
            else:
                # Allow repo-relative paths or package-relative
                direct = state.ktor / hint
                if direct.is_file():
                    paths.append(str(direct.relative_to(state.ktor)))
                for root in pkg_roots:
                    cand = root / hint
                    if cand.is_file():
                        paths.append(str(cand.relative_to(state.ktor)))
                    # control/ControlServer.kt style when hint already has module folder
                    if "/" in hint:
                        alt = state.ktor / "control/src/main/kotlin/org/kotlintor" / Path(hint).name
                        # also try full under each module
                        for mod, mid in (
                            ("control", "control/src/main/kotlin/org/kotlintor"),
                            ("core", "core/src/main/kotlin/org/kotlintor"),
                            ("proxy", "proxy/src/main/kotlin/org/kotlintor"),
                        ):
                            parts = Path(hint).parts
                            cand2 = state.ktor / mid
                            # if hint is control/Foo.kt
                            if parts[0] in {"control", "proxy", "cli", "android"}:
                                cand2 = state.ktor / f"{parts[0]}/src/main/kotlin/org/kotlintor" / Path(*parts[1:])
                            else:
                                cand2 = state.ktor / mid / hint
                            if cand2.is_file():
                                paths.append(str(cand2.relative_to(state.ktor)))
    if not exclusive:
        paths.extend(state.ctor_refs.get(basename, []))
        # fuzzy stem
        for stem, plist in state.kt_index.items():
            if basename.replace("_", "") in stem.replace("_", "") or stem in basename.replace("_", ""):
                if basename[:4] == stem[:4] or basename in stem or stem in basename:
                    paths.extend(plist)
    # unique preserve order
    seen = set()
    uniq = []
    for p in paths:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    if not uniq:
        return "MISSING", "no kotlin match"
    ev = f"exclusive hint; matched {len(uniq)} path(s)" if exclusive else f"matched {len(uniq)} path(s)"
    return ";".join(uniq[:5]), ev



# L2 struct/type depth seeds (basename with _t). Raise at most one grade with tests.
TYPE_SEED_DEPTH: dict[str, tuple[str, str, str]] = {
    "or_options_t": (
        "D3",
        "L2StructElevationTest + TorConfig/OrOptionsMultiAuth vs or_options_t",
        "full or_options_t field matrix thinner; see L4",
    ),
    "addr_policy_t": (
        "D3",
        "L2StructElevationTest + AddrPolicy vs addr_policy_t",
        "full IPv6 / mask edge cases thinner",
    ),
    "authority_cert_t": (
        "D3",
        "L2StructElevationTest + AuthorityCert vs authority_cert_t",
        "full cert lifetime / cross-cert thinner",
    ),
    "cell_t": (
        "D3",
        "L2StructElevationTest + Cell vs cell_t",
        "full var-cell / packing thinner",
    ),
    "circuitmux_t": (
        "D3",
        "L2StructElevationTest + CircuitMux vs circuitmux_t",
        "full cmux policy / EWMA thinner",
    ),
    "channel_t": (
        "D3",
        "L2StructElevationTest + OrChannel vs channel_t",
        "full channel scheduler hooks thinner",
    ),
    "connection_t": (
        "D3",
        "L2StructElevationTest + ConnectionSt vs connection_t",
        "full connection subtype matrix thinner",
    ),
    "congestion_control_t": (
        "D3",
        "L2StructElevationTest + CongestionControl vs congestion_control_t",
        "full Vegas param matrix thinner",
    ),
    "extend_info_t": (
        "D3",
        "L2StructElevationTest + ExtendInfo vs extend_info_t",
        "full IPv6 / ed25519 id thinner",
    ),
    "entry_guard_t": (
        "D3",
        "L2StructElevationTest + EntryGuardFsm vs entry_guard_t",
        "full guard confirmed/filtered FSM thinner",
    ),
    "bw_array_t": (
        "D3",
        "L2StructElevationTest + BwHist.BwArray vs bw_array_t",
        "full observation-slot export thinner",
    ),
    "dos_options_t": (
        "D3",
        "L2StructElevationTest + DosOptions vs dos_options_t",
        "full DoS option matrix thinner",
    ),
    "hs_opts_t": (
        "D3",
        "L2StructElevationTest + HsOpts vs hs_opts_t",
        "full hs_opts_t field matrix thinner",
    ),
    "circuit_t": (
        "D3",
        "L2StructElevationTest + Circuit vs circuit_t",
        "full origin/or circuit subtype thinner",
    ),
    "cell_queue_t": (
        "D3",
        "L2StructElevationTest + CellQueue vs cell_queue_t",
        "full queue watermark thinner",
    ),
    "circuitmux_t": (
        "D3",
        "L2StructElevationTest + CircuitMux/CellQueue vs circuitmux_t",
        "full cmux policy / EWMA thinner",
    ),
    "relay_crypto_t": (
        "D3",
        "L2StructElevationTest + CircuitCrypto vs relay_crypto_t",
        "full cgo/tor1 dispatch thinner",
    ),
    "cgo_pair_t": (
        "D3",
        "L2StructElevationTest + Cgo vs cgo_pair_t",
        "full CGO pair state thinner",
    ),
    "routerset_t": (
        "D3",
        "L2StructElevationTest + RouterSet vs routerset_t",
        "full routerset matching thinner",
    ),
    "ns_detached_signatures_t": (
        "D3",
        "L2StructElevationTest + DetachedSignatures vs ns_detached_signatures_t",
        "full detached sig collation thinner",
    ),
    "or_state_t": (
        "D3",
        "L2StructElevationTest + OrState vs or_state_t",
        "full statefile field matrix thinner",
    ),
    "mainloop_state_t": (
        "D3",
        "L2StructElevationTest + MainloopState vs mainloop_state_t",
        "full mainloop tick / event matrix thinner",
    ),
    "tor1_crypt_t": (
        "D3",
        "L2StructElevationTest + Tor1Crypt vs tor1_crypt_t",
        "full tor1 digest/cipher state thinner",
    ),
    "cached_dir_t": (
        "D3",
        "L2StructElevationTest + CachedDir vs cached_dir_t",
        "full cached dir compression thinner",
    ),
    "channel_listener_t": (
        "D3",
        "L2StructElevationTest + ChannelListener vs channel_listener_t",
        "full listener accept bookkeeping thinner",
    ),
    "channel_tls_t": (
        "D3",
        "L2StructElevationTest + or.ChannelTls vs channel_tls_t",
        "full TLS channel scheduler thinner",
    ),
    "circuit_build_times_t": (
        "D3",
        "L2StructElevationTest + CircuitBuildTimes vs circuit_build_times_t",
        "full CBT quantile / close timeout thinner",
    ),
    "conflux_leg_t": (
        "D3",
        "L2StructElevationTest + ConfluxLeg vs conflux_leg_t",
        "full conflux seq / UX thinner",
    ),
    "conflux_params_t": (
        "D3",
        "L2StructElevationTest + ConfluxParamsSt vs conflux_params_t",
        "full conflux consensus params thinner",
    ),
    "conflux_t": (
        "D3",
        "L2StructElevationTest + ConfluxSet vs conflux_t",
        "full multi-leg set switch thinner",
    ),
    "control_connection_t": (
        "D3",
        "L2StructElevationTest + ControlConnectionHandle vs control_connection_t",
        "full control conn command queue thinner",
    ),
    "cpath_build_state_t": (
        "D3",
        "L2StructElevationTest + CpathBuildState vs cpath_build_state_t",
        "full path-build exit choice thinner",
    ),
    "crypt_path_reference_t": (
        "D3",
        "L2StructElevationTest + CryptPathReference vs crypt_path_reference_t",
        "full cpath refcount thinner",
    ),
    "crypt_path_t": (
        "D3",
        "L2StructElevationTest + CryptPath vs crypt_path_t",
        "full cpath hop list thinner",
    ),
    "desc_store_t": (
        "D3",
        "L2StructElevationTest + DescStore vs desc_store_t",
        "full descriptor store journal thinner",
    ),
    "destroy_cell_queue_t": (
        "D3",
        "L2StructElevationTest + DestroyCellQueue vs destroy_cell_queue_t",
        "full destroy queue watermark thinner",
    ),
    "destroy_cell_t": (
        "D3",
        "L2StructElevationTest + DestroyCell vs destroy_cell_t",
        "full destroy reason matrix thinner",
    ),
    "dir_connection_t": (
        "D3",
        "L2StructElevationTest + DirConnectionHandle vs dir_connection_t",
        "full dir conn fetch state thinner",
    ),
    "dir_server_t": (
        "D3",
        "L2StructElevationTest + DirServer vs dir_server_t",
        "full dir_server weight / type thinner",
    ),
    "document_signature_t": (
        "D3",
        "L2StructElevationTest + DocumentSignature vs document_signature_t",
        "full signature alg matrix thinner",
    ),
    "entry_port_cfg_t": (
        "D3",
        "L2StructElevationTest + PortCfg vs entry_port_cfg_t",
        "full isolation flag matrix thinner",
    ),
    "port_cfg_t": (
        "D3",
        "L2StructElevationTest + PortCfg vs port_cfg_t",
        "full port cfg matrix thinner",
    ),
    "server_port_cfg_t": (
        "D3",
        "L2StructElevationTest + PortCfg vs server_port_cfg_t",
        "full server port cfg thinner",
    ),
    "ext_or_cmd_t": (
        "D3",
        "L2StructElevationTest + ExtOrCmd vs ext_or_cmd_t",
        "full ext_or command set thinner",
    ),
    "extrainfo_t": (
        "D3",
        "L2StructElevationTest + ExtraInfo vs extrainfo_t",
        "full extrainfo parse thinner",
    ),
    "hsdir_index_t": (
        "D3",
        "L2StructElevationTest + HsDirIndex vs hsdir_index_t",
        "full hsdir index blind thinner",
    ),
    "microdesc_cache_t": (
        "D3",
        "L2StructElevationTest + MicrodescCache vs microdesc_cache_t",
        "full microdesc journal thinner",
    ),
    "networkstatus_sr_info_t": (
        "D3",
        "L2StructElevationTest + NetworkstatusSrInfo vs networkstatus_sr_info_t",
        "full SRV commit/reveal thinner",
    ),
    "networkstatus_voter_info_t": (
        "D3",
        "L2StructElevationTest + NetworkstatusVoterInfo vs networkstatus_voter_info_t",
        "full voter info fields thinner",
    ),
    "onion_handshake_state_t": (
        "D3",
        "L2StructElevationTest + OnionHandshakeState vs onion_handshake_state_t",
        "full onion handshake FSM thinner",
    ),
    "or_handshake_certs_t": (
        "D3",
        "L2StructElevationTest + OrHandshakeCerts vs or_handshake_certs_t",
        "full cert chain validate thinner",
    ),
    "or_handshake_state_t": (
        "D3",
        "L2StructElevationTest + OrHandshakeState vs or_handshake_state_t",
        "full OR handshake FSM thinner",
    ),
    "edge_connection_t": (
        "D3",
        "L2StructElevationTest + ConnectionSt edge vs edge_connection_t",
        "full edge stream attach thinner",
    ),
    "entry_connection_t": (
        "D3",
        "L2StructElevationTest + ConnectionSt entry vs entry_connection_t",
        "full entry isolation thinner",
    ),
    "listener_connection_t": (
        "D3",
        "L2StructElevationTest + ConnectionSt listener vs listener_connection_t",
        "full listener accept thinner",
    ),
    "half_edge_t": (
        "D3",
        "L2StructElevationTest + CircuitMux half_edge vs half_edge_t",
        "full half-edge stream end thinner",
    ),
    "packed_cell_t": (
        "D3",
        "L2StructElevationTest + PackedCell vs packed_cell_t",
        "full packed cell queue thinner",
    ),
    "relay_msg_t": (
        "D3",
        "L2StructElevationTest + RelayMsg vs relay_msg_t",
        "full relay msg decode thinner",
    ),
    "signed_descriptor_t": (
        "D3",
        "L2StructElevationTest + SignedDescriptor vs signed_descriptor_t",
        "full signed descriptor cache thinner",
    ),
    "socks_request_t": (
        "D3",
        "L2StructElevationTest + SocksRequest vs socks_request_t",
        "full SOCKS isolation thinner",
    ),
    "tor_version_t": (
        "D3",
        "L2StructElevationTest + TorVersion vs tor_version_t",
        "full version compare thinner",
    ),
    "var_cell_t": (
        "D3",
        "L2StructElevationTest + VarCell vs var_cell_t",
        "full var-cell packing thinner",
    ),
    "vegas_params_t": (
        "D3",
        "L2StructElevationTest + VegasParams vs vegas_params_t",
        "full Vegas consensus params thinner",
    ),
    "vote_microdesc_hash_t": (
        "D3",
        "L2StructElevationTest + VoteMicrodescHash vs vote_microdesc_hash_t",
        "full vote microdesc hash list thinner",
    ),
    "vote_routerstatus_t": (
        "D3",
        "L2StructElevationTest + VoteRouterstatus vs vote_routerstatus_t",
        "full vote routerstatus flags thinner",
    ),
    "vote_timing_t": (
        "D3",
        "L2StructElevationTest + VoteTiming vs vote_timing_t",
        "full vote timing intervals thinner",
    ),
    "control_cmd_args_t": (
        "D3",
        "L2StructElevationTest + ControlCmdArgs vs control_cmd_args_t",
        "full control arg parse thinner",
    ),
    "download_status_t": (
        "D3",
        "L2StructElevationTest + DownloadStatus vs download_status_t",
        "full dlstatus schedule matrix thinner",
    ),
    "microdesc_t": (
        "D3",
        "L2StructElevationTest + Microdesc vs microdesc_t",
        "full microdesc field matrix thinner",
    ),
    "networkstatus_t": (
        "D3",
        "L2StructElevationTest + NetworkStatus vs networkstatus_t",
        "full networkstatus flavor matrix thinner",
    ),
    "node_t": (
        "D3",
        "L2StructElevationTest + Node vs node_t",
        "full node flag / md attach thinner",
    ),
    "nodefamily_t": (
        "D3",
        "L2StructElevationTest + NodeFamily vs nodefamily_t",
        "full family intern thinner",
    ),
    "or_circuit_t": (
        "D3",
        "L2StructElevationTest + CircuitKind.Or vs or_circuit_t",
        "full or_circuit p/n chan thinner",
    ),
    "origin_circuit_t": (
        "D3",
        "L2StructElevationTest + CircuitKind.Origin vs origin_circuit_t",
        "full origin_circuit path thinner",
    ),
    "or_connection_t": (
        "D3",
        "L2StructElevationTest + OrConnection vs or_connection_t",
        "full OR conn TLS state thinner",
    ),
    "routerinfo_t": (
        "D3",
        "L2StructElevationTest + RouterInfo vs routerinfo_t",
        "full routerinfo parse thinner",
    ),
    "routerlist_t": (
        "D3",
        "L2StructElevationTest + RouterList vs routerlist_t",
        "full routerlist index thinner",
    ),
    "routerstatus_t": (
        "D3",
        "L2StructElevationTest + RouterStatus vs routerstatus_t",
        "full routerstatus flag matrix thinner",
    ),
    "dirauth_options_t": (
        "D3",
        "L2StructElevationTest + DirAuthOptions vs dirauth_options_t",
        "full dirauth option matrix thinner",
    ),
}

# L3 exported-op depth seeds (C Tor function name). Raise at most one grade with tests.
OP_SEED_DEPTH: dict[str, tuple[str, str, str]] = {
    # address_set.h
    "address_set_add": ("D3", "L3OpElevationTest + AddressSet.add", "bloom FPP tuning thinner"),
    "address_set_add_ipv4h": ("D3", "L3OpElevationTest + AddressSet.addIpv4h", "IPv6 set thinner"),
    "address_set_new": ("D3", "L3OpElevationTest + AddressSet.new", "sizing heuristics thinner"),
    "address_set_probably_contains": ("D3", "L3OpElevationTest + AddressSet.probablyContains", "FPP audit thinner"),
    # addressmap.h (automap subset)
    "address_is_in_virtual_range": ("D3", "L3OpElevationTest + AddressMap.addressIsInVirtualRange", "full CIDR match thinner"),
    "addressmap_address_should_automap": ("D3", "L3OpElevationTest + AddressMap.addressShouldAutomap", "suffix matrix thinner"),
    "addressmap_clean": ("D3", "L3OpElevationTest + AddressMap.clean", "expiry sweep thinner"),
    "addressmap_clear_configured": ("D3", "L3OpElevationTest + AddressMap.clearConfigured", "configured vs automap split thinner"),
    # channel.h (first 25 capped exports we cover)
    "channel_add_to_digest_map": ("D3", "L3OpElevationTest + Channel.addToDigestMap", "ed25519 id map thinner"),
    "channel_change_state": ("D3", "L3OpElevationTest + Channel.changeState", "full state machine thinner"),
    "channel_change_state_open": ("D3", "L3OpElevationTest + Channel.changeStateOpen", "open-hook matrix thinner"),
    "channel_check_for_duplicates": ("D3", "L3OpElevationTest + Channel.checkForDuplicates", "duplicate policy thinner"),
    "channel_clear_client": ("D3", "L3OpElevationTest + Channel.clearClient", "client bit edge cases thinner"),
    "channel_clear_identity_digest": ("D3", "L3OpElevationTest + Channel.clearIdentityDigest", "digest map races thinner"),
    "channel_clear_remote_end": ("D3", "L3OpElevationTest + Channel.clearRemoteEnd", "remote clear side effects thinner"),
    "channel_close_for_error": ("D3", "L3OpElevationTest + Channel.closeForError", "error close path thinner"),
    "channel_close_from_lower_layer": ("D3", "L3OpElevationTest + Channel.closeFromLowerLayer", "TLS lower-layer close thinner"),
    "channel_closed": ("D3", "L3OpElevationTest + Channel.closed", "closed notify thinner"),
    "channel_connect": ("D3", "L3OpElevationTest + Channel.connect", "async connect thinner"),
    "channel_describe_transport": ("D3", "L3OpElevationTest + Channel.describeTransport", "transport describe thinner"),
    "channel_do_open_actions": ("D3", "L3OpElevationTest + Channel.doOpenActions", "open actions thinner"),
    "channel_dump_transport_statistics": ("D3", "L3OpElevationTest + Channel.dumpTransportStatistics", "stats dump thinner"),
    "channel_dumpstats": ("D3", "L3OpElevationTest + Channel.dumpstats", "dumpstats format thinner"),
    "channel_find_by_global_id": ("D3", "L3OpElevationTest + Channel.findByGlobalId", "gidmap thinner"),
    "channel_find_by_remote_identity": ("D3", "L3OpElevationTest + Channel.findByRemoteIdentity", "identity lookup thinner"),
    "channel_free_": ("D3", "L3OpElevationTest + Channel.free", "free lifecycle thinner"),
    "channel_free_all": ("D3", "L3OpElevationTest + Channel.freeAll", "global free thinner"),
    "channel_get_cell_handler": ("D3", "L3OpElevationTest + Channel.getCellHandler", "handler install thinner"),
    "channel_has_queued_writes": ("D3", "L3OpElevationTest + Channel.hasQueuedWrites", "queue watermark thinner"),
    "channel_init": ("D3", "L3OpElevationTest + Channel.init", "init defaults thinner"),
    "channel_is_bad_for_new_circs": ("D3", "L3OpElevationTest + Channel.isBadForNewCircs", "bad-for-circs policy thinner"),
    "channel_is_better": ("D3", "L3OpElevationTest + Channel.isBetter", "channel preference thinner"),
    # channelpadding.h
    "channelpadding_decide_to_pad_channel": ("D3", "L3OpElevationTest + ChannelPadding.decideToPadChannel", "full netflow decide thinner"),
    "channelpadding_disable_padding_on_channel": ("D3", "L3OpElevationTest + ChannelPadding.disablePaddingOnChannel", "negotiate STOP thinner"),
    "channelpadding_get_channel_idle_timeout": ("D3", "L3OpElevationTest + ChannelPadding.getChannelIdleTimeout", "idle timeout consensus thinner"),
    "channelpadding_get_circuits_available_timeout": ("D3", "L3OpElevationTest + ChannelPadding.getCircuitsAvailableTimeout", "circuits timeout thinner"),
    "channelpadding_log_heartbeat": ("D3", "L3OpElevationTest + ChannelPadding.logHeartbeat", "heartbeat format thinner"),
    # cgo / Prop359
    "cgo_crypt_client_backward": ("D3", "L3OpElevationTest + Cgo.cryptClientBackward", "CGO inbound peel thinner"),
    "cgo_crypt_client_forward": ("D3", "L3OpElevationTest + Cgo.cryptClientForward", "CGO outbound forward thinner"),
    "cgo_crypt_client_originate": ("D3", "L3OpElevationTest + Cgo.cryptClientOriginate", "CGO originate thinner"),
    "cgo_crypt_free_": ("D3", "L3OpElevationTest + Cgo.cryptFree", "CGO free wipe thinner"),
    "cgo_crypt_new": ("D3", "L3OpElevationTest + Cgo.cryptNew", "CGO hop seed thinner"),
    "cgo_crypt_relay_backward": ("D3", "L3OpElevationTest + Cgo.cryptRelayBackward", "CGO relay inbound thinner"),
    "cgo_crypt_relay_forward": ("D3", "L3OpElevationTest + Cgo.cryptRelayForward", "CGO relay forward thinner"),
    "cgo_crypt_relay_originate": ("D3", "L3OpElevationTest + Cgo.cryptRelayOriginate", "CGO relay originate thinner"),
    "cgo_et_clear": ("D3", "L3OpElevationTest + Cgo.etClear", "ET clear thinner"),
    "cgo_et_decrypt": ("D3", "L3OpElevationTest + Cgo.etDecrypt", "ET decrypt thinner"),
    "cgo_et_encrypt": ("D3", "L3OpElevationTest + Cgo.etEncrypt", "ET encrypt thinner"),
    "cgo_et_init": ("D3", "L3OpElevationTest + Cgo.etInit", "ET init thinner"),
    "cgo_et_set_key": ("D3", "L3OpElevationTest + Cgo.etSetKey", "ET set key thinner"),
    "cgo_key_material_len": ("D3", "L3OpElevationTest + Cgo.keyMaterialLen", "key material len thinner"),
    "cgo_prf_clear": ("D3", "L3OpElevationTest + Cgo.prfClear", "PRF clear thinner"),
    "cgo_prf_gen_t1": ("D3", "L3OpElevationTest + Cgo.prfGenT1", "PRF T1 thinner"),
    "cgo_prf_init": ("D3", "L3OpElevationTest + Cgo.prfInit", "PRF init thinner"),
    "cgo_prf_set_key": ("D3", "L3OpElevationTest + Cgo.prfSetKey", "PRF set key thinner"),
    "cgo_prf_xor_t0": ("D3", "L3OpElevationTest + Cgo.prfXorT0", "PRF XOR T0 thinner"),
    "cgo_uiv_clear": ("D3", "L3OpElevationTest + Cgo.uivClear", "UIV clear thinner"),
    "cgo_uiv_decrypt": ("D3", "L3OpElevationTest + Cgo.uivDecrypt", "UIV decrypt thinner"),
    "cgo_uiv_encrypt": ("D3", "L3OpElevationTest + Cgo.uivEncrypt", "UIV encrypt thinner"),
    "cgo_uiv_init": ("D3", "L3OpElevationTest + Cgo.uivInit", "UIV init thinner"),
    "cgo_uiv_update": ("D3", "L3OpElevationTest + Cgo.uivUpdate", "UIV update thinner"),
    # onion_fast
    "fast_client_handshake": ("D3", "L3OpElevationTest + OnionFast.fastClientHandshake", "CREATE_FAST client thinner"),
    "fast_handshake_state_free_": ("D3", "L3OpElevationTest + OnionFast.fastHandshakeStateFree", "state wipe thinner"),
    "fast_onionskin_create": ("D3", "L3OpElevationTest + OnionFast.fastOnionskinCreate", "CREATE_FAST onionskin thinner"),
    "fast_server_handshake": ("D3", "L3OpElevationTest + OnionFast.fastServerHandshake", "CREATE_FAST server thinner"),
    # hs_ntor
    "hs_ntor_circuit_key_expansion": ("D3", "L3OpElevationTest + HsNtor.hsNtorCircuitKeyExpansion", "HS key expand thinner"),
    "hs_ntor_client_get_introduce1_keys": ("D3", "L3OpElevationTest + HsNtor.hsNtorClientGetIntroduce1Keys", "intro1 keys thinner"),
    "hs_ntor_client_get_rendezvous1_keys": ("D3", "L3OpElevationTest + HsNtor.hsNtorClientGetRendezvous1Keys", "rend1 keys thinner"),
    "hs_ntor_client_rendezvous2_mac_is_good": ("D3", "L3OpElevationTest + HsNtor.hsNtorClientRendezvous2MacIsGood", "rend2 MAC check thinner"),
    "hs_ntor_service_get_introduce1_keys": ("D3", "L3OpElevationTest + HsNtor.hsNtorServiceGetIntroduce1Keys", "svc intro1 keys thinner"),
    "hs_ntor_service_get_introduce1_keys_multi": ("D3", "L3OpElevationTest + HsNtor.hsNtorServiceGetIntroduce1KeysMulti", "multi intro1 thinner"),
    "hs_ntor_service_get_rendezvous1_keys": ("D3", "L3OpElevationTest + HsNtor.hsNtorServiceGetRendezvous1Keys", "svc rend1 keys thinner"),
    # onion_crypto / ntor / ntor-v3
    "onion_handshake_state_release": ("D3", "L3OpElevationTest + OnionCrypto.onionHandshakeStateRelease", "state release thinner"),
    "onion_skin_client_handshake": ("D3", "L3OpElevationTest + OnionCrypto.onionSkinClientHandshake", "skin client thinner"),
    "onion_skin_create": ("D3", "L3OpElevationTest + OnionCrypto.onionSkinCreate", "skin create thinner"),
    "onion_skin_server_handshake": ("D3", "L3OpElevationTest + OnionCrypto.onionSkinServerHandshake", "skin server thinner"),
    "server_onion_keys_free_": ("D3", "L3OpElevationTest + OnionCrypto.serverOnionKeysFree", "server keys free thinner"),
    "server_onion_keys_new": ("D3", "L3OpElevationTest + OnionCrypto.serverOnionKeysNew", "server keys new thinner"),
    "trn_extension_find": ("D3", "L3OpElevationTest + OnionCrypto.trnExtensionFind", "extension find thinner"),
    "ntor_handshake_state_free_": ("D3", "L3OpElevationTest + Ntor.ntorHandshakeStateFree", "ntor state free thinner"),
    "onion_skin_ntor_client_handshake": ("D3", "L3OpElevationTest + Ntor.onionSkinNtorClientHandshake", "ntor client thinner"),
    "onion_skin_ntor_create": ("D3", "L3OpElevationTest + Ntor.onionSkinNtorCreate", "ntor create thinner"),
    "onion_skin_ntor_server_handshake": ("D3", "L3OpElevationTest + Ntor.onionSkinNtorServerHandshake", "ntor server thinner"),
    "ntor3_handshake_state_free_": ("D3", "L3OpElevationTest + NtorV3.ntor3HandshakeStateFree", "ntor3 state free thinner"),
    "ntor3_server_handshake_state_free_": ("D3", "L3OpElevationTest + NtorV3.ntor3ServerHandshakeStateFree", "ntor3 server free thinner"),
    "onion_ntor3_client_handshake": ("D3", "L3OpElevationTest + NtorV3.onionNtor3ClientHandshake", "ntor3 client thinner"),
    "onion_skin_ntor3_create": ("D3", "L3OpElevationTest + NtorV3.onionSkinNtor3Create", "ntor3 create thinner"),
    "onion_skin_ntor3_create_nokeygen": ("D3", "L3OpElevationTest + NtorV3.onionSkinNtor3CreateNokeygen", "ntor3 create nokeygen thinner"),
    "onion_skin_ntor3_server_handshake_part1": ("D3", "L3OpElevationTest + NtorV3.onionSkinNtor3ServerHandshakePart1", "ntor3 part1 thinner"),
    "onion_skin_ntor3_server_handshake_part2": ("D3", "L3OpElevationTest + NtorV3.onionSkinNtor3ServerHandshakePart2", "ntor3 part2 thinner"),
    "onion_skin_ntor3_server_handshake_part2_nokeygen": ("D3", "L3OpElevationTest + NtorV3.onionSkinNtor3ServerHandshakePart2Nokeygen", "ntor3 part2 nokeygen thinner"),
    # relay_crypto / tor1
    "relay_crypto_assert_ok": ("D3", "L3OpElevationTest + RelayCrypto.relayCryptoAssertOk", "assert ok thinner"),
    "relay_crypto_clear": ("D3", "L3OpElevationTest + RelayCrypto.relayCryptoClear", "clear thinner"),
    "relay_crypto_get_sendme_tag": ("D3", "L3OpElevationTest + RelayCrypto.relayCryptoGetSendmeTag", "sendme tag thinner"),
    "relay_crypto_init": ("D3", "L3OpElevationTest + RelayCrypto.relayCryptoInit", "init thinner"),
    "relay_crypto_key_material_len": ("D3", "L3OpElevationTest + RelayCrypto.relayCryptoKeyMaterialLen", "key material thinner"),
    "relay_crypto_sendme_tag_len": ("D3", "L3OpElevationTest + RelayCrypto.relayCryptoSendmeTagLen", "tag len thinner"),
    "relay_decrypt_cell": ("D3", "L3OpElevationTest + RelayCrypto.relayDecryptCell", "decrypt thinner"),
    "relay_encrypt_cell_inbound": ("D3", "L3OpElevationTest + RelayCrypto.relayEncryptCellInbound", "encrypt inbound thinner"),
    "relay_encrypt_cell_outbound": ("D3", "L3OpElevationTest + RelayCrypto.relayEncryptCellOutbound", "encrypt outbound thinner"),
    "tor1_crypt_assert_ok": ("D3", "L3OpElevationTest + RelayCrypto.tor1CryptAssertOk", "tor1 assert thinner"),
    "tor1_crypt_clear": ("D3", "L3OpElevationTest + RelayCrypto.tor1CryptClear", "tor1 clear thinner"),
    "tor1_crypt_client_backward": ("D3", "L3OpElevationTest + RelayCrypto.tor1CryptClientBackward", "tor1 client back thinner"),
    "tor1_crypt_client_forward": ("D3", "L3OpElevationTest + RelayCrypto.tor1CryptClientForward", "tor1 client fwd thinner"),
    "tor1_crypt_client_originate": ("D3", "L3OpElevationTest + RelayCrypto.tor1CryptClientOriginate", "tor1 client orig thinner"),
    "tor1_crypt_init": ("D3", "L3OpElevationTest + RelayCrypto.tor1CryptInit", "tor1 init thinner"),
    "tor1_crypt_relay_backward": ("D3", "L3OpElevationTest + RelayCrypto.tor1CryptRelayBackward", "tor1 relay back thinner"),
    "tor1_crypt_relay_forward": ("D3", "L3OpElevationTest + RelayCrypto.tor1CryptRelayForward", "tor1 relay fwd thinner"),
    "tor1_crypt_relay_originate": ("D3", "L3OpElevationTest + RelayCrypto.tor1CryptRelayOriginate", "tor1 relay orig thinner"),
    "tor1_key_material_len": ("D3", "L3OpElevationTest + RelayCrypto.tor1KeyMaterialLen", "tor1 key len thinner"),
    # policies
    "addr_policies_eq": ("D3", "L3OpElevationTest + Policies.addrPoliciesEq", "policy eq thinner"),
    "addr_policy_append_reject_addr": ("D3", "L3OpElevationTest + Policies.addrPolicyAppendRejectAddr", "reject addr thinner"),
    "addr_policy_append_reject_addr_list": ("D3", "L3OpElevationTest + Policies.addrPolicyAppendRejectAddrList", "reject list thinner"),
    "addr_policy_free_": ("D3", "L3OpElevationTest + Policies.addrPolicyFree", "policy free thinner"),
    "addr_policy_get_canonical_entry": ("D3", "L3OpElevationTest + Policies.addrPolicyGetCanonicalEntry", "canonical entry thinner"),
    "addr_policy_list_free_": ("D3", "L3OpElevationTest + Policies.addrPolicyListFree", "policy list free thinner"),
    # circuitmux.h
    "circuitmux_alloc": ("D3", "L3OpElevationTest + CircuitMux.circuitmuxAlloc", "cmux alloc thinner"),
    "circuitmux_append_destroy_cell": ("D3", "L3OpElevationTest + CircuitMux.circuitmuxAppendDestroyCell", "destroy append thinner"),
    "circuitmux_assert_okay": ("D3", "L3OpElevationTest + CircuitMux.assertOkay", "cmux assert thinner"),
    "circuitmux_attached_circuit_direction": ("D3", "L3OpElevationTest + CircuitMux.attachedCircuitDirection", "direction thinner"),
    "circuitmux_clear_num_cells": ("D3", "L3OpElevationTest + CircuitMux.clearNumCells", "clear ncells thinner"),
    "circuitmux_clear_policy": ("D3", "L3OpElevationTest + CircuitMux.clearPolicy", "clear policy thinner"),
    "circuitmux_count_queued_destroy_cells": ("D3", "L3OpElevationTest + CircuitMux.countQueuedDestroyCells", "destroy count thinner"),
    "circuitmux_detach_all_circuits": ("D3", "L3OpElevationTest + CircuitMux.detachAll", "detach all thinner"),
    "circuitmux_free_": ("D3", "L3OpElevationTest + CircuitMux.free", "cmux free thinner"),
    "circuitmux_get_first_active_circuit": ("D3", "L3OpElevationTest + CircuitMux.getFirstActiveCircuit", "first active thinner"),
    "circuitmux_is_circuit_active": ("D3", "L3OpElevationTest + CircuitMux.circuitmuxIsCircuitActive", "is active thinner"),
    "circuitmux_is_circuit_attached": ("D3", "L3OpElevationTest + CircuitMux.circuitmuxIsCircuitAttached", "is attached thinner"),
    "circuitmux_mark_destroyed_circids_usable": ("D3", "L3OpElevationTest + CircuitMux.markDestroyedCircidsUsable", "destroyed ids thinner"),
    "circuitmux_notify_xmit_cells": ("D3", "L3OpElevationTest + CircuitMux.notifyXmitCells", "notify xmit thinner"),
    "circuitmux_notify_xmit_destroy": ("D3", "L3OpElevationTest + CircuitMux.notifyXmitDestroy", "notify destroy thinner"),
    "circuitmux_num_active_circuits": ("D3", "L3OpElevationTest + CircuitMux.numActiveCircuits", "num active thinner"),
    "circuitmux_num_cells_for_circuit": ("D3", "L3OpElevationTest + CircuitMux.numCellsForCircuit", "cells for circ thinner"),
    "circuitmux_num_circuits": ("D3", "L3OpElevationTest + CircuitMux.circuitmuxNumCircuits", "num circuits thinner"),
    "circuitmux_set_num_cells": ("D3", "L3OpElevationTest + CircuitMux.setNumCells", "set ncells thinner"),
    "circuitmux_set_policy": ("D3", "L3OpElevationTest + CircuitMux.circuitmuxSetPolicy", "set policy thinner"),
    # relay.h cell queue / address
    "address_ttl_free_": ("D3", "L3OpElevationTest + Relay.addressTtlFree", "address_ttl free thinner"),
    "append_address_to_payload": ("D3", "L3OpElevationTest + Relay.appendAddressToPayload", "append address thinner"),
    "append_cell_to_circuit_queue": ("D3", "L3OpElevationTest + Relay.appendCellToCircuitQueue", "append cell thinner"),
    "cell_queue_append": ("D3", "L3OpElevationTest + Relay.cellQueueAppend", "cell_queue append thinner"),
    "cell_queue_append_packed_copy": ("D3", "L3OpElevationTest + Relay.cellQueueAppendPackedCopy", "packed copy thinner"),
    "cell_queue_clear": ("D3", "L3OpElevationTest + Relay.cellQueueClear", "cell_queue clear thinner"),
    "cell_queue_init": ("D3", "L3OpElevationTest + Relay.cellQueueInit", "cell_queue init thinner"),
    "cell_queue_pop": ("D3", "L3OpElevationTest + Relay.cellQueuePop", "cell_queue pop thinner"),
    "cell_queues_check_size": ("D3", "L3OpElevationTest + Relay.cellQueuesCheckSize", "queues check size thinner"),
    "cell_queues_get_total_allocation": ("D3", "L3OpElevationTest + Relay.cellQueuesGetTotalAllocation", "total alloc thinner"),
    "channel_unlink_all_circuits": ("D3", "L3OpElevationTest + Relay.channelUnlinkAllCircuits", "unlink circuits thinner"),
    "circuit_clear_cell_queue": ("D3", "L3OpElevationTest + Relay.circuitClearCellQueue", "clear cell queue thinner"),
    "circuit_get_relay_format": ("D3", "L3OpElevationTest + Relay.circuitGetRelayFormat", "relay format thinner"),
    "circuit_max_relay_payload": ("D3", "L3OpElevationTest + Relay.circuitMaxRelayPayload", "max payload thinner"),
    "circuit_receive_relay_cell": ("D3", "L3OpElevationTest + Relay.circuitReceiveRelayCell", "receive relay thinner"),
    "circuit_reset_sendme_randomness": ("D3", "L3OpElevationTest + Relay.circuitResetSendmeRandomness", "sendme rng thinner"),
    "connected_cell_parse": ("D3", "L3OpElevationTest + Relay.connectedCellParse", "connected parse thinner"),
    "connection_edge_consider_sending_sendme": ("D3", "L3OpElevationTest + Relay.connectionEdgeConsiderSendingSendme", "consider sendme thinner"),
    "connection_edge_get_inbuf_bytes_to_package": ("D3", "L3OpElevationTest + Relay.connectionEdgeGetInbufBytesToPackage", "inbuf package thinner"),
    "connection_edge_package_raw_inbuf": ("D3", "L3OpElevationTest + Relay.connectionEdgePackageRawInbuf", "package inbuf thinner"),
    "connection_edge_process_relay_cell": ("D3", "L3OpElevationTest + Relay.connectionEdgeProcessRelayCell", "process relay thinner"),
    "connection_edge_process_resolved_cell": ("D3", "L3OpElevationTest + Relay.connectionEdgeProcessResolvedCell", "resolved cell thinner"),
    "connection_edge_send_command": ("D3", "L3OpElevationTest + Relay.connectionEdgeSendCommand", "edge send cmd thinner"),
    "decode_address_from_payload": ("D3", "L3OpElevationTest + Relay.decodeAddressFromPayload", "decode address thinner"),
    "destroy_cell_queue_append": ("D3", "L3OpElevationTest + Relay.destroyCellQueueAppend", "destroy queue append thinner"),
    # connection_edge.h (head of queue)
    "address_is_invalid_destination": ("D3", "L3OpElevationTest + ConnectionEdge.addressIsInvalidDestination", "invalid dest thinner"),
    "begin_cell_parse": ("D3", "L3OpElevationTest + ConnectionEdge.beginCellParse", "begin parse thinner"),
    "circuit_clear_isolation": ("D3", "L3OpElevationTest + ConnectionEdge.circuitClearIsolation", "clear isolation thinner"),
    "circuit_discard_optional_exit_enclaves": ("D3", "L3OpElevationTest + ConnectionEdge.circuitDiscardOptionalExitEnclaves", "enclaves thinner"),
    "clip_dns_fuzzy_ttl": ("D3", "L3OpElevationTest + ConnectionEdge.clipDnsFuzzyTtl", "fuzzy ttl thinner"),
    "clip_dns_ttl": ("D3", "L3OpElevationTest + ConnectionEdge.clipDnsTtl", "clip ttl thinner"),
    "connected_cell_format_payload": ("D3", "L3OpElevationTest + ConnectionEdge.connectedCellFormatPayload", "connected format thinner"),
    # policies authdir / exit
    "append_exit_policy_string": ("D3", "L3OpElevationTest + Policies.appendExitPolicyString", "append exit policy thinner"),
    "authdir_policy_badexit_address": ("D3", "L3OpElevationTest + Policies.authdirPolicyBadexitAddress", "badexit thinner"),
    "authdir_policy_middleonly_address": ("D3", "L3OpElevationTest + Policies.authdirPolicyMiddleonlyAddress", "middleonly thinner"),
    "authdir_policy_permits_address": ("D3", "L3OpElevationTest + Policies.authdirPolicyPermitsAddress", "authdir permits thinner"),
    "authdir_policy_valid_address": ("D3", "L3OpElevationTest + Policies.authdirPolicyValidAddress", "authdir valid thinner"),
    "compare_tor_addr_to_node_policy": ("D3", "L3OpElevationTest + Policies.compareTorAddrToNodePolicy", "node policy compare thinner"),
    "compare_tor_addr_to_short_policy": ("D3", "L3OpElevationTest + Policies.compareTorAddrToShortPolicy", "short policy compare thinner"),
    "dir_policy_permits_address": ("D3", "L3OpElevationTest + Policies.dirPolicyPermitsAddress", "dir policy thinner"),
    "exit_policy_is_general_exit": ("D3", "L3OpElevationTest + Policies.exitPolicyIsGeneralExit", "general exit thinner"),
    "metrics_policy_permits_address": ("D3", "L3OpElevationTest + Policies.metricsPolicyPermitsAddress", "metrics policy thinner"),
    "parse_short_policy": ("D3", "L3OpElevationTest + Policies.parseShortPolicy", "parse short policy thinner"),
    "policies_exit_policy_append_reject_star": ("D3", "L3OpElevationTest + Policies.policiesExitPolicyAppendRejectStar", "reject star thinner"),
    "policies_parse_exit_policy": ("D3", "L3OpElevationTest + Policies.policiesParseExitPolicy", "parse exit policy thinner"),
    "policies_parse_exit_policy_from_options": ("D3", "L3OpElevationTest + Policies.policiesParseExitPolicyFromOptions", "exit from options thinner"),
    "policies_parse_exit_policy_reject_private": ("D3", "L3OpElevationTest + Policies.policiesParseExitPolicyRejectPrivate", "reject private thinner"),
    "node_exit_policy_is_exact": ("D3", "L3OpElevationTest + Policies.nodeExitPolicyIsExact", "exit exact thinner"),
    "node_exit_policy_rejects_all": ("D3", "L3OpElevationTest + Policies.nodeExitPolicyRejectsAll", "node rejects all thinner"),
    "router_exit_policy_rejects_all": ("D3", "L3OpElevationTest + Policies.routerExitPolicyRejectsAll", "router rejects all thinner"),
    # sendme / conflux
    "build_cell_payload_v1": ("D3", "L3OpElevationTest + Sendme.buildCellPayloadV1", "sendme v1 payload thinner"),
    "build_link_cell": ("D3", "L3OpElevationTest + ConfluxCell.buildLinkCell", "conflux link cell thinner"),
    # circuitbuild.h
    "build_state_get_exit_nickname": ("D3", "L3OpElevationTest + CircuitBuild.buildStateGetExitNickname", "exit nick thinner"),
    "build_state_get_exit_rsa_id": ("D3", "L3OpElevationTest + CircuitBuild.buildStateGetExitRsaId", "exit rsa id thinner"),
    "choose_good_entry_server": ("D3", "L3OpElevationTest + CircuitBuild.chooseGoodEntryServer", "entry pick thinner"),
    "circuit_append_new_exit": ("D3", "L3OpElevationTest + CircuitBuild.circuitAppendNewExit", "append exit thinner"),
    "circuit_establish_circuit": ("D3", "L3OpElevationTest + CircuitBuild.circuitEstablishCircuit", "establish thinner"),
    "circuit_extend_to_new_exit": ("D3", "L3OpElevationTest + CircuitBuild.circuitExtendToNewExit", "extend exit thinner"),
    "circuit_finish_handshake": ("D3", "L3OpElevationTest + CircuitBuild.circuitFinishHandshake", "finish hs thinner"),
    "circuit_handle_first_hop": ("D3", "L3OpElevationTest + CircuitBuild.circuitHandleFirstHop", "first hop thinner"),
    "circuit_has_usable_onion_key": ("D3", "L3OpElevationTest + CircuitBuild.circuitHasUsableOnionKey", "onion key thinner"),
    "circuit_list_path": ("D3", "L3OpElevationTest + CircuitBuild.circuitListPath", "list path thinner"),
    "circuit_list_path_for_controller": ("D3", "L3OpElevationTest + CircuitBuild.circuitListPathForController", "controller path thinner"),
    "circuit_log_path": ("D3", "L3OpElevationTest + CircuitBuild.circuitLogPath", "log path thinner"),
    "circuit_n_chan_done": ("D3", "L3OpElevationTest + CircuitBuild.circuitNChanDone", "n chan done thinner"),
    "circuit_note_clock_jumped": ("D3", "L3OpElevationTest + CircuitBuild.circuitNoteClockJumped", "clock jump thinner"),
    "circuit_send_next_onion_skin": ("D3", "L3OpElevationTest + CircuitBuild.circuitSendNextOnionSkin", "next skin thinner"),
    "circuit_timeout_want_to_count_circ": ("D3", "L3OpElevationTest + CircuitBuild.circuitTimeoutWantToCountCirc", "timeout count thinner"),
    "circuit_truncated": ("D3", "L3OpElevationTest + CircuitBuild.circuitTruncated", "truncated thinner"),
    "circuit_upgrade_circuits_from_guard_wait": ("D3", "L3OpElevationTest + CircuitBuild.circuitUpgradeCircuitsFromGuardWait", "guard wait thinner"),
    "client_circ_negotiation_message": ("D3", "L3OpElevationTest + CircuitBuild.clientCircNegotiationMessage", "nego msg thinner"),
    "cpath_build_state_to_crn_flags": ("D3", "L3OpElevationTest + CircuitBuild.cpathBuildStateToCrnFlags", "crn flags thinner"),
    "cpath_build_state_to_crn_ipv6_extend_flag": ("D3", "L3OpElevationTest + CircuitBuild.cpathBuildStateToCrnIpv6ExtendFlag", "crn ipv6 thinner"),
    "get_unique_circ_id_by_chan": ("D3", "L3OpElevationTest + CircuitBuild.getUniqueCircIdByChan", "unique circ id thinner"),
    "new_route_len": ("D3", "L3OpElevationTest + CircuitBuild.newRouteLen", "route len thinner"),
    "onion_extend_cpath": ("D3", "L3OpElevationTest + CircuitBuild.onionExtendCpath", "extend cpath thinner"),
    "onion_pick_cpath_exit": ("D3", "L3OpElevationTest + CircuitBuild.onionPickCpathExit", "pick exit thinner"),
    # channelpadding remaining + channel_init_listener + channeltls
    "channelpadding_new_consensus_params": ("D3", "L3OpElevationTest + ChannelPadding.newConsensusParams", "pad consensus thinner"),
    "channelpadding_reduce_padding_on_channel": ("D3", "L3OpElevationTest + ChannelPadding.reducePaddingOnChannel", "reduce pad thinner"),
    "channelpadding_send_enable_command": ("D3", "L3OpElevationTest + ChannelPadding.sendEnableCommand", "enable cmd thinner"),
    "channelpadding_update_padding_for_channel": ("D3", "L3OpElevationTest + ChannelPadding.updatePaddingForChannel", "update pad thinner"),
    "channel_init_listener": ("D3", "L3OpElevationTest + Channel.initListener", "init listener thinner"),
    "channel_tls_common_init": ("D3", "L3OpElevationTest + ChannelTls.channelTlsCommonInit", "tls common init thinner"),
    "channel_tls_connect": ("D3", "L3OpElevationTest + ChannelTls.channelTlsConnect", "tls connect thinner"),
    "channel_tls_free_all": ("D3", "L3OpElevationTest + ChannelTls.channelTlsFreeAll", "tls free all thinner"),
    "channel_tls_from_base": ("D3", "L3OpElevationTest + ChannelTls.channelTlsFromBase", "tls from base thinner"),
    "channel_tls_from_base_const": ("D3", "L3OpElevationTest + ChannelTls.channelTlsFromBaseConst", "tls from base const thinner"),
    "channel_tls_get_listener": ("D3", "L3OpElevationTest + ChannelTls.channelTlsGetListener", "tls get listener thinner"),
    "channel_tls_handle_cell": ("D3", "L3OpElevationTest + ChannelTls.channelTlsHandleCell", "tls handle cell thinner"),
    "channel_tls_handle_incoming": ("D3", "L3OpElevationTest + ChannelTls.channelTlsHandleIncoming", "tls incoming thinner"),
    "channel_tls_handle_state_change_on_orconn": ("D3", "L3OpElevationTest + ChannelTls.channelTlsHandleStateChangeOnOrconn", "tls state change thinner"),
    "channel_tls_handle_var_cell": ("D3", "L3OpElevationTest + ChannelTls.channelTlsHandleVarCell", "tls var cell thinner"),
    "channel_tls_process_auth_challenge_cell": ("D3", "L3OpElevationTest + ChannelTls.channelTlsProcessAuthChallengeCell", "tls auth challenge thinner"),
    "channel_tls_process_authenticate_cell": ("D3", "L3OpElevationTest + ChannelTls.channelTlsProcessAuthenticateCell", "tls authenticate thinner"),
    "channel_tls_process_certs_cell": ("D3", "L3OpElevationTest + ChannelTls.channelTlsProcessCertsCell", "tls certs thinner"),
    "channel_tls_start_listener": ("D3", "L3OpElevationTest + ChannelTls.channelTlsStartListener", "tls start listener thinner"),
    "channel_tls_to_base": ("D3", "L3OpElevationTest + ChannelTls.channelTlsToBase", "tls to base thinner"),
    "channel_tls_to_base_const": ("D3", "L3OpElevationTest + ChannelTls.channelTlsToBaseConst", "tls to base const thinner"),
    "channel_tls_update_marks": ("D3", "L3OpElevationTest + ChannelTls.channelTlsUpdateMarks", "tls update marks thinner"),
    # queue-head helpers
    "bandwidth_weight_rule_to_string": ("D3", "L3OpElevationTest + Reasons.bandwidthWeightRuleToString", "bw weight string thinner"),
    "bytes_to_usage": ("D3", "L3OpElevationTest + HeartbeatStatus.bytesToUsage", "bytes usage thinner"),
    "cell_command_to_string": ("D3", "L3OpElevationTest + Command.cellCommandToString", "cell cmd string thinner"),
    # circuitlist.h
    "channel_mark_circid_unusable": ("D3", "L3OpElevationTest + CircuitList.channelMarkCircidUnusable", "circid unusable thinner"),
    "channel_mark_circid_usable": ("D3", "L3OpElevationTest + CircuitList.channelMarkCircidUsable", "circid usable thinner"),
    "channel_note_destroy_pending": ("D3", "L3OpElevationTest + CircuitList.channelNoteDestroyPending", "destroy pending thinner"),
    "circuit_any_opened_circuits": ("D3", "L3OpElevationTest + CircuitList.anyOpenedCircuits", "any opened thinner"),
    "circuit_any_opened_circuits_cached": ("D3", "L3OpElevationTest + CircuitList.anyOpenedCircuitsCached", "opened cached thinner"),
    "circuit_cache_opened_circuit_state": ("D3", "L3OpElevationTest + CircuitList.cacheOpenedCircuitState", "cache opened thinner"),
    "circuit_clear_cpath": ("D3", "L3OpElevationTest + CircuitList.circuitClearCpath", "clear cpath thinner"),
    "circuit_clear_testing_cell_stats": ("D3", "L3OpElevationTest + CircuitList.circuitClearTestingCellStats", "clear test stats thinner"),
    "circuit_close_all_marked": ("D3", "L3OpElevationTest + CircuitList.closeAllMarked", "close marked thinner"),
    "circuit_count_pending_close": ("D3", "L3OpElevationTest + CircuitList.countPendingClose", "pending close thinner"),
    "circuit_count_pending_on_channel": ("D3", "L3OpElevationTest + CircuitList.circuitCountPendingOnChannel", "pending on chan thinner"),
    "circuit_dump_by_conn": ("D3", "L3OpElevationTest + CircuitList.circuitDumpByConn", "dump by conn thinner"),
    "circuit_event_status": ("D3", "L3OpElevationTest + CircuitList.circuitEventStatus", "event status thinner"),
    "circuit_find_circuits_to_upgrade_from_guard_wait": ("D3", "L3OpElevationTest + CircuitList.circuitFindCircuitsToUpgradeFromGuardWait", "guard wait upgrade thinner"),
    "circuit_find_to_cannibalize": ("D3", "L3OpElevationTest + CircuitList.circuitFindToCannibalize", "cannibalize thinner"),
    "circuit_free_": ("D3", "L3OpElevationTest + CircuitList.circuitFree", "circuit free thinner"),
    "circuit_free_all": ("D3", "L3OpElevationTest + CircuitList.circuitFreeAll", "free all thinner"),
    "circuit_get_all_pending_on_channel": ("D3", "L3OpElevationTest + CircuitList.circuitGetAllPendingOnChannel", "get pending thinner"),
    "circuit_get_by_circid_channel": ("D3", "L3OpElevationTest + CircuitList.circuitGetByCircidChannel", "get by circid thinner"),
    "circuit_get_by_circid_channel_even_if_marked": ("D3", "L3OpElevationTest + CircuitList.circuitGetByCircidChannelEvenIfMarked", "get even marked thinner"),
    "circuit_get_by_edge_conn": ("D3", "L3OpElevationTest + CircuitList.circuitGetByEdgeConn", "get by edge thinner"),
    "circuit_get_by_global_id": ("D3", "L3OpElevationTest + CircuitList.circuitGetByGlobalId", "get by gid thinner"),
    "circuit_get_cpath_hop": ("D3", "L3OpElevationTest + CircuitList.circuitGetCpathHop", "cpath hop thinner"),
    "circuit_get_cpath_len": ("D3", "L3OpElevationTest + CircuitList.circuitGetCpathLen", "cpath len thinner"),
    "circuit_get_cpath_opened_len": ("D3", "L3OpElevationTest + CircuitList.circuitGetCpathOpenedLen", "cpath opened len thinner"),
    # circuitmux_ewma + sendme version + dos head + circpad events + cell_pack
    "cell_ewma_get_current_tick_and_fraction": ("D3", "L3OpElevationTest + CircuitMuxEwma.cellEwmaGetCurrentTickAndFraction", "ewma tick thinner"),
    "cell_ewma_initialize_ticks": ("D3", "L3OpElevationTest + CircuitMuxEwma.cellEwmaInitializeTicks", "ewma init ticks thinner"),
    "circuitmux_ewma_free_all": ("D3", "L3OpElevationTest + CircuitMuxEwma.circuitmuxEwmaFreeAll", "ewma free thinner"),
    "cmux_ewma_set_options": ("D3", "L3OpElevationTest + CircuitMuxEwma.cmuxEwmaSetOptions", "ewma options thinner"),
    "cell_version_can_be_handled": ("D3", "L3OpElevationTest + Sendme.cellVersionCanBeHandled", "sendme version thinner"),
    "cell_pack": ("D3", "L3OpElevationTest + ConnectionOr.cellPack", "cell pack thinner"),
    "cc_stats_refill_bucket": ("D3", "L3OpElevationTest + Dos.ccStatsRefillBucket", "cc refill thinner"),
    "dos_cc_get_defense_type": ("D3", "L3OpElevationTest + Dos.dosCcGetDefenseType", "dos cc defense thinner"),
    "dos_cc_new_create_cell": ("D3", "L3OpElevationTest + Dos.dosCcNewCreateCell", "dos create cell thinner"),
    "dos_close_client_conn": ("D3", "L3OpElevationTest + Dos.dosCloseClientConn", "dos close conn thinner"),
    "dos_conn_addr_get_defense_type": ("D3", "L3OpElevationTest + Dos.dosConnAddrGetDefenseType", "dos conn defense thinner"),
    "dos_consensus_has_changed": ("D3", "L3OpElevationTest + Dos.dosConsensusHasChanged", "dos consensus thinner"),
    "dos_enabled": ("D3", "L3OpElevationTest + Dos.dosEnabled", "dos enabled thinner"),
    "dos_free_all": ("D3", "L3OpElevationTest + Dos.dosFreeAll", "dos free thinner"),
    "dos_geoip_entry_about_to_free": ("D3", "L3OpElevationTest + Dos.dosGeoipEntryAboutToFree", "dos geoip free thinner"),
    "dos_geoip_entry_init": ("D3", "L3OpElevationTest + Dos.dosGeoipEntryInit", "dos geoip init thinner"),
    "dos_get_num_cc_marked_addr": ("D3", "L3OpElevationTest + Dos.dosGetNumCcMarkedAddr", "dos marked addr thinner"),
    "dos_get_num_cc_marked_addr_maxq": ("D3", "L3OpElevationTest + Dos.dosGetNumCcMarkedAddrMaxq", "dos marked maxq thinner"),
    "circpad_add_matching_machines": ("D3", "L3OpElevationTest + CircuitPadding.circpadAddMatchingMachines", "circpad match thinner"),
    "circpad_cell_event_nonpadding_received": ("D3", "L3OpElevationTest + CircuitPadding.circpadCellEventNonpaddingReceived", "circpad nonpad recv thinner"),
    "circpad_cell_event_nonpadding_sent": ("D3", "L3OpElevationTest + CircuitPadding.circpadCellEventNonpaddingSent", "circpad nonpad sent thinner"),
    "circpad_cell_event_padding_received": ("D3", "L3OpElevationTest + CircuitPadding.circpadCellEventPaddingReceived", "circpad pad recv thinner"),
    "circpad_cell_event_padding_sent": ("D3", "L3OpElevationTest + CircuitPadding.circpadCellEventPaddingSent", "circpad pad sent thinner"),
    "circpad_check_received_cell": ("D3", "L3OpElevationTest + CircuitPadding.circpadCheckReceivedCell", "circpad check cell thinner"),
    "circpad_circ_purpose_to_mask": ("D3", "L3OpElevationTest + CircuitPadding.circpadCircPurposeToMask", "circpad purpose mask thinner"),
    "circpad_circuit_free_all_machineinfos": ("D3", "L3OpElevationTest + CircuitPadding.circpadCircuitFreeAllMachineinfos", "circpad free infos thinner"),
    "circpad_circuit_machineinfo_new": ("D3", "L3OpElevationTest + CircuitPadding.circpadCircuitMachineinfoNew", "circpad info new thinner"),
    "circpad_deliver_recognized_relay_cell_events": ("D3", "L3OpElevationTest + CircuitPadding.circpadDeliverRecognizedRelayCellEvents", "circpad recognized thinner"),
    "circpad_deliver_sent_relay_cell_events": ("D3", "L3OpElevationTest + CircuitPadding.circpadDeliverSentRelayCellEvents", "circpad sent thinner"),
    "circpad_deliver_unrecognized_cell_events": ("D3", "L3OpElevationTest + CircuitPadding.circpadDeliverUnrecognizedCellEvents", "circpad unrecognized thinner"),
    # circpad remainder + machines
    "circpad_free_all": ("D3", "L3OpElevationTest + CircuitPadding.circpadFreeAll", "circpad free all thinner"),
    "circpad_handle_padding_negotiate": ("D3", "L3OpElevationTest + CircuitPadding.circpadHandlePaddingNegotiate", "negotiate handle thinner"),
    "circpad_handle_padding_negotiated": ("D3", "L3OpElevationTest + CircuitPadding.circpadHandlePaddingNegotiated", "negotiated handle thinner"),
    "circpad_histogram_bin_to_usec": ("D3", "L3OpElevationTest + CircuitPadding.circpadHistogramBinToUsec", "hist bin usec thinner"),
    "circpad_histogram_usec_to_bin": ("D3", "L3OpElevationTest + CircuitPadding.circpadHistogramUsecToBin", "hist usec bin thinner"),
    "circpad_internal_event_bins_empty": ("D3", "L3OpElevationTest + CircuitPadding.circpadInternalEventBinsEmpty", "bins empty thinner"),
    "circpad_internal_event_infinity": ("D3", "L3OpElevationTest + CircuitPadding.circpadInternalEventInfinity", "infinity event thinner"),
    "circpad_internal_event_state_length_up": ("D3", "L3OpElevationTest + CircuitPadding.circpadInternalEventStateLengthUp", "length up thinner"),
    "circpad_machine_current_state": ("D3", "L3OpElevationTest + CircuitPadding.circpadMachineCurrentState", "machine state thinner"),
    "circpad_machine_event_circ_added_hop": ("D3", "L3OpElevationTest + CircuitPadding.circpadMachineEventCircAddedHop", "circ added hop thinner"),
    "circpad_machine_event_circ_built": ("D3", "L3OpElevationTest + CircuitPadding.circpadMachineEventCircBuilt", "circ built thinner"),
    "circpad_machine_event_circ_has_no_relay_early": ("D3", "L3OpElevationTest + CircuitPadding.circpadMachineEventCircHasNoRelayEarly", "no relay early thinner"),
    "circpad_machine_event_circ_has_no_streams": ("D3", "L3OpElevationTest + CircuitPadding.circpadMachineEventCircHasNoStreams", "no streams thinner"),
    "circpad_machine_client_hide_intro_circuits": ("D3", "L3OpElevationTest + CircuitPadding.circpadMachineClientHideIntroCircuits", "client hide intro thinner"),
    "circpad_machine_client_hide_rend_circuits": ("D3", "L3OpElevationTest + CircuitPadding.circpadMachineClientHideRendCircuits", "client hide rend thinner"),
    "circpad_machine_relay_hide_intro_circuits": ("D3", "L3OpElevationTest + CircuitPadding.circpadMachineRelayHideIntroCircuits", "relay hide intro thinner"),
    "circpad_machine_relay_hide_rend_circuits": ("D3", "L3OpElevationTest + CircuitPadding.circpadMachineRelayHideRendCircuits", "relay hide rend thinner"),
    # circuituse.h
    "circuit_build_failed": ("D3", "L3OpElevationTest + CircuitUse.circuitBuildFailed", "build failed thinner"),
    "circuit_build_needed_circs": ("D3", "L3OpElevationTest + CircuitUse.circuitBuildNeededCircs", "needed circs thinner"),
    "circuit_change_purpose": ("D3", "L3OpElevationTest + CircuitUse.circuitChangePurpose", "change purpose thinner"),
    "circuit_conforms_to_options": ("D3", "L3OpElevationTest + CircuitUse.circuitConformsToOptions", "conforms options thinner"),
    "circuit_detach_stream": ("D3", "L3OpElevationTest + CircuitUse.circuitDetachStream", "detach stream thinner"),
    "circuit_enough_testing_circs": ("D3", "L3OpElevationTest + CircuitUse.circuitEnoughTestingCircs", "enough testing thinner"),
    "circuit_expire_building": ("D3", "L3OpElevationTest + CircuitUse.circuitExpireBuilding", "expire building thinner"),
    "circuit_expire_old_circs_as_needed": ("D3", "L3OpElevationTest + CircuitUse.circuitExpireOldCircsAsNeeded", "expire old thinner"),
    "circuit_expire_old_circuits_serverside": ("D3", "L3OpElevationTest + CircuitUse.circuitExpireOldCircuitsServerside", "expire server thinner"),
    "circuit_expire_waiting_for_better_guard": ("D3", "L3OpElevationTest + CircuitUse.circuitExpireWaitingForBetterGuard", "expire guard wait thinner"),
    "circuit_get_best": ("D3", "L3OpElevationTest + CircuitUse.circuitGetBest", "get best thinner"),
    "circuit_has_opened": ("D3", "L3OpElevationTest + CircuitUse.circuitHasOpened", "has opened thinner"),
    "circuit_is_acceptable": ("D3", "L3OpElevationTest + CircuitUse.circuitIsAcceptable", "is acceptable thinner"),
    "circuit_is_available_for_use": ("D3", "L3OpElevationTest + CircuitUse.circuitIsAvailableForUse", "available use thinner"),
    "circuit_is_hs_v3": ("D3", "L3OpElevationTest + CircuitUse.circuitIsHsV3", "hs v3 thinner"),
    "circuit_launch": ("D3", "L3OpElevationTest + CircuitUse.circuitLaunch", "circuit launch thinner"),
    "circuit_launch_by_extend_info": ("D3", "L3OpElevationTest + CircuitUse.circuitLaunchByExtendInfo", "launch extend thinner"),
    "circuit_log_ancient_one_hop_circuits": ("D3", "L3OpElevationTest + CircuitUse.circuitLogAncientOneHopCircuits", "ancient onehop thinner"),
    "circuit_purpose_is_hidden_service": ("D3", "L3OpElevationTest + CircuitUse.circuitPurposeIsHiddenService", "purpose hs thinner"),
    "circuit_purpose_is_hs_client": ("D3", "L3OpElevationTest + CircuitUse.circuitPurposeIsHsClient", "purpose hs client thinner"),
    "circuit_purpose_is_hs_service": ("D3", "L3OpElevationTest + CircuitUse.circuitPurposeIsHsService", "purpose hs service thinner"),
    "circuit_purpose_is_hs_vanguards": ("D3", "L3OpElevationTest + CircuitUse.circuitPurposeIsHsVanguards", "purpose vanguards thinner"),
    "circuit_read_valid_data": ("D3", "L3OpElevationTest + CircuitUse.circuitReadValidData", "read valid data thinner"),
    "circuit_remove_handled_ports": ("D3", "L3OpElevationTest + CircuitUse.circuitRemoveHandledPorts", "remove ports thinner"),
    "circuit_reset_failure_count": ("D3", "L3OpElevationTest + CircuitUse.circuitResetFailureCount", "reset failures thinner"),
    # circuitstats.h
    "circuit_build_times_add_time": ("D3", "L3OpElevationTest + CircuitStats.circuitBuildTimesAddTime", "cbt add time thinner"),
    "circuit_build_times_calculate_timeout": ("D3", "L3OpElevationTest + CircuitStats.circuitBuildTimesCalculateTimeout", "cbt calc timeout thinner"),
    "circuit_build_times_cdf": ("D3", "L3OpElevationTest + CircuitStats.circuitBuildTimesCdf", "cbt cdf thinner"),
    "circuit_build_times_close_rate": ("D3", "L3OpElevationTest + CircuitStats.circuitBuildTimesCloseRate", "cbt close rate thinner"),
    "circuit_build_times_count_close": ("D3", "L3OpElevationTest + CircuitStats.circuitBuildTimesCountClose", "cbt count close thinner"),
    "circuit_build_times_count_timeout": ("D3", "L3OpElevationTest + CircuitStats.circuitBuildTimesCountTimeout", "cbt count timeout thinner"),
    "circuit_build_times_disabled": ("D3", "L3OpElevationTest + CircuitStats.circuitBuildTimesDisabled", "cbt disabled thinner"),
    "circuit_build_times_disabled_": ("D3", "L3OpElevationTest + CircuitStats.circuitBuildTimesDisabled", "cbt disabled_ thinner"),
    "circuit_build_times_enough_to_compute": ("D3", "L3OpElevationTest + CircuitStats.circuitBuildTimesEnoughToCompute", "cbt enough thinner"),
    "circuit_build_times_free_timeouts": ("D3", "L3OpElevationTest + CircuitStats.circuitBuildTimesFreeTimeouts", "cbt free thinner"),
    "circuit_build_times_generate_sample": ("D3", "L3OpElevationTest + CircuitStats.circuitBuildTimesGenerateSample", "cbt sample thinner"),
    "circuit_build_times_get_xm": ("D3", "L3OpElevationTest + CircuitStats.circuitBuildTimesGetXm", "cbt xm thinner"),
    "circuit_build_times_handle_completed_hop": ("D3", "L3OpElevationTest + CircuitStats.circuitBuildTimesHandleCompletedHop", "cbt hop thinner"),
    "circuit_build_times_init": ("D3", "L3OpElevationTest + CircuitStats.circuitBuildTimesInit", "cbt init thinner"),
    "circuit_build_times_initial_alpha": ("D3", "L3OpElevationTest + CircuitStats.circuitBuildTimesInitialAlpha", "cbt alpha thinner"),
    "circuit_build_times_initial_timeout": ("D3", "L3OpElevationTest + CircuitStats.circuitBuildTimesInitialTimeout", "cbt init timeout thinner"),
    "circuit_build_times_mark_circ_as_measurement_only": ("D3", "L3OpElevationTest + CircuitStats.circuitBuildTimesMarkCircAsMeasurementOnly", "cbt measurement thinner"),
    "circuit_build_times_needs_circuits": ("D3", "L3OpElevationTest + CircuitStats.circuitBuildTimesNeedsCircuits", "cbt needs thinner"),
    "circuit_build_times_needs_circuits_now": ("D3", "L3OpElevationTest + CircuitStats.circuitBuildTimesNeedsCircuitsNow", "cbt needs now thinner"),
    "circuit_build_times_network_check_changed": ("D3", "L3OpElevationTest + CircuitStats.circuitBuildTimesNetworkCheckChanged", "cbt net changed thinner"),
    "circuit_build_times_network_check_live": ("D3", "L3OpElevationTest + CircuitStats.circuitBuildTimesNetworkCheckLive", "cbt net live check thinner"),
    "circuit_build_times_network_circ_success": ("D3", "L3OpElevationTest + CircuitStats.circuitBuildTimesNetworkCircSuccess", "cbt net success thinner"),
    "circuit_build_times_network_is_live": ("D3", "L3OpElevationTest + CircuitStats.circuitBuildTimesNetworkIsLive", "cbt net is live thinner"),
    "circuit_build_times_new_consensus_params": ("D3", "L3OpElevationTest + CircuitStats.circuitBuildTimesNewConsensusParams", "cbt consensus thinner"),
    "circuit_build_times_parse_state": ("D3", "L3OpElevationTest + CircuitStats.circuitBuildTimesParseState", "cbt parse state thinner"),
    # congestion_control_common.h
    "circuit_sent_cell_for_sendme": ("D3", "L3OpElevationTest + CongestionControlCommon.circuitSentCellForSendme", "sent for sendme thinner"),
    "congestion_control_build_ext_request": ("D3", "L3OpElevationTest + CongestionControlCommon.congestionControlBuildExtRequest", "cc ext req thinner"),
    "congestion_control_build_ext_response": ("D3", "L3OpElevationTest + CongestionControlCommon.congestionControlBuildExtResponse", "cc ext resp thinner"),
    "congestion_control_dispatch_cc_alg": ("D3", "L3OpElevationTest + CongestionControlCommon.congestionControlDispatchCcAlg", "cc dispatch thinner"),
    "congestion_control_enabled": ("D3", "L3OpElevationTest + CongestionControlCommon.congestionControlEnabled", "cc enabled thinner"),
    "congestion_control_free_": ("D3", "L3OpElevationTest + CongestionControlCommon.congestionControlFree", "cc free thinner"),
    "congestion_control_get_control_port_fields": ("D3", "L3OpElevationTest + CongestionControlCommon.congestionControlGetControlPortFields", "cc ctrl fields thinner"),
    "congestion_control_get_num_clock_stalls": ("D3", "L3OpElevationTest + CongestionControlCommon.congestionControlGetNumClockStalls", "cc clock stalls thinner"),
    "congestion_control_get_num_rtt_reset": ("D3", "L3OpElevationTest + CongestionControlCommon.congestionControlGetNumRttReset", "cc rtt reset thinner"),
    "congestion_control_get_package_window": ("D3", "L3OpElevationTest + CongestionControlCommon.congestionControlGetPackageWindow", "cc package window thinner"),
    "congestion_control_new": ("D3", "L3OpElevationTest + CongestionControlCommon.congestionControlNew", "cc new thinner"),
    "congestion_control_new_consensus_params": ("D3", "L3OpElevationTest + CongestionControlCommon.congestionControlNewConsensusParams", "cc consensus thinner"),
    "congestion_control_note_cell_sent": ("D3", "L3OpElevationTest + CongestionControlCommon.congestionControlNoteCellSent", "cc note sent thinner"),
    "congestion_control_parse_ext_request": ("D3", "L3OpElevationTest + CongestionControlCommon.congestionControlParseExtRequest", "cc parse req thinner"),
    "congestion_control_parse_ext_response": ("D3", "L3OpElevationTest + CongestionControlCommon.congestionControlParseExtResponse", "cc parse resp thinner"),
    "congestion_control_set_cc_disabled": ("D3", "L3OpElevationTest + CongestionControlCommon.congestionControlSetCcDisabled", "cc disable thinner"),
    "congestion_control_set_cc_enabled": ("D3", "L3OpElevationTest + CongestionControlCommon.congestionControlSetCcEnabled", "cc enable thinner"),
    "congestion_control_update_circuit_estimates": ("D3", "L3OpElevationTest + CongestionControlCommon.congestionControlUpdateCircuitEstimates", "cc estimates thinner"),
    "congestion_control_update_circuit_rtt": ("D3", "L3OpElevationTest + CongestionControlCommon.congestionControlUpdateCircuitRtt", "cc rtt update thinner"),
    "congestion_control_validate_sendme_increment": ("D3", "L3OpElevationTest + CongestionControlCommon.congestionControlValidateSendmeIncrement", "cc sendme inc thinner"),
    "enqueue_timestamp": ("D3", "L3OpElevationTest + CongestionControlCommon.enqueueTimestamp", "enqueue ts thinner"),
    "is_monotime_clock_reliable": ("D3", "L3OpElevationTest + CongestionControlCommon.isMonotimeClockReliable", "monotime thinner"),
    "percent_max_mix": ("D3", "L3OpElevationTest + CongestionControlCommon.percentMaxMix", "percent mix thinner"),
    "sendme_get_inc_count": ("D3", "L3OpElevationTest + CongestionControlCommon.sendmeGetIncCount", "sendme inc count thinner"),
    "time_delta_stalled_or_jumped": ("D3", "L3OpElevationTest + CongestionControlCommon.timeDeltaStalledOrJumped", "time delta stall thinner"),
    # connection_or.h
    "clear_broken_connection_map": ("D3", "L3OpElevationTest + ConnectionOr.clearBrokenConnectionMap", "broken map clear thinner"),
    "connection_init_or_handshake_state": ("D3", "L3OpElevationTest + ConnectionOr.connectionInitOrHandshakeState", "or hs state thinner"),
    "connection_or_about_to_close": ("D3", "L3OpElevationTest + ConnectionOr.connectionOrAboutToClose", "or about close thinner"),
    "connection_or_clear_identity": ("D3", "L3OpElevationTest + ConnectionOr.connectionOrClearIdentity", "or clear id thinner"),
    "connection_or_clear_identity_map": ("D3", "L3OpElevationTest + ConnectionOr.connectionOrClearIdentityMap", "or clear id map thinner"),
    "connection_or_client_learned_peer_id": ("D3", "L3OpElevationTest + ConnectionOr.connectionOrClientLearnedPeerId", "or learned peer thinner"),
    "connection_or_client_used": ("D3", "L3OpElevationTest + ConnectionOr.connectionOrClientUsed", "or client used thinner"),
    "connection_or_close_normally": ("D3", "L3OpElevationTest + ConnectionOr.connectionOrCloseNormally", "or close normal thinner"),
    "connection_or_connect_failed": ("D3", "L3OpElevationTest + ConnectionOr.connectionOrConnectFailed", "or connect fail thinner"),
    "connection_or_digest_is_known_relay": ("D3", "L3OpElevationTest + ConnectionOr.connectionOrDigestIsKnownRelay", "or known relay thinner"),
    "connection_or_event_status": ("D3", "L3OpElevationTest + ConnectionOr.connectionOrEventStatus", "or event status thinner"),
    "connection_or_finished_connecting": ("D3", "L3OpElevationTest + ConnectionOr.connectionOrFinishedConnecting", "or finished connect thinner"),
    "connection_or_finished_flushing": ("D3", "L3OpElevationTest + ConnectionOr.connectionOrFinishedFlushing", "or finished flush thinner"),
    "connection_or_flushed_some": ("D3", "L3OpElevationTest + ConnectionOr.connectionOrFlushedSome", "or flushed some thinner"),
    "connection_or_get_alleged_ed25519_id": ("D3", "L3OpElevationTest + ConnectionOr.connectionOrGetAllegedEd25519Id", "or ed25519 id thinner"),
    "connection_or_group_set_badness_": ("D3", "L3OpElevationTest + ConnectionOr.connectionOrGroupSetBadness", "or set badness thinner"),
    "connection_or_init_conn_from_address": ("D3", "L3OpElevationTest + ConnectionOr.connectionOrInitConnFromAddress", "or init addr thinner"),
    "connection_or_notify_error": ("D3", "L3OpElevationTest + ConnectionOr.connectionOrNotifyError", "or notify error thinner"),
    "connection_or_num_cells_writeable": ("D3", "L3OpElevationTest + ConnectionOr.connectionOrNumCellsWriteable", "or cells writable thinner"),
    "connection_or_process_inbuf": ("D3", "L3OpElevationTest + ConnectionOr.connectionOrProcessInbuf", "or process inbuf thinner"),
    "connection_or_reached_eof": ("D3", "L3OpElevationTest + ConnectionOr.connectionOrReachedEof", "or eof thinner"),
    "connection_or_report_broken_states": ("D3", "L3OpElevationTest + ConnectionOr.connectionOrReportBrokenStates", "or broken states thinner"),
    "connection_or_send_versions": ("D3", "L3OpElevationTest + ConnectionOr.connectionOrSendVersions", "or send versions thinner"),
    "connection_or_set_canonical": ("D3", "L3OpElevationTest + ConnectionOr.connectionOrSetCanonical", "or set canonical thinner"),
    # dos remainder
    "dos_get_num_cc_rejected": ("D3", "L3OpElevationTest + Dos.dosGetNumCcRejected", "dos cc rejected thinner"),
    "dos_get_num_conn_addr_connect_rejected": ("D3", "L3OpElevationTest + Dos.dosGetNumConnAddrConnectRejected", "dos conn connect rej thinner"),
    "dos_get_num_conn_addr_rejected": ("D3", "L3OpElevationTest + Dos.dosGetNumConnAddrRejected", "dos conn addr rej thinner"),
    "dos_get_num_single_hop_refused": ("D3", "L3OpElevationTest + Dos.dosGetNumSingleHopRefused", "dos single hop thinner"),
    "dos_get_num_stream_rejected": ("D3", "L3OpElevationTest + Dos.dosGetNumStreamRejected", "dos stream rej thinner"),
    "dos_init": ("D3", "L3OpElevationTest + Dos.dosInit", "dos init thinner"),
    "dos_log_heartbeat": ("D3", "L3OpElevationTest + Dos.dosLogHeartbeat", "dos heartbeat thinner"),
    "dos_new_client_conn": ("D3", "L3OpElevationTest + Dos.dosNewClientConn", "dos new client thinner"),
    "dos_note_circ_max_outq": ("D3", "L3OpElevationTest + Dos.dosNoteCircMaxOutq", "dos max outq thinner"),
    "dos_note_refuse_single_hop_client": ("D3", "L3OpElevationTest + Dos.dosNoteRefuseSingleHopClient", "dos note refuse thinner"),
    "dos_should_refuse_single_hop_client": ("D3", "L3OpElevationTest + Dos.dosShouldRefuseSingleHopClient", "dos should refuse thinner"),
    "dos_stream_init_circ_tbf": ("D3", "L3OpElevationTest + Dos.dosStreamInitCircTbf", "dos stream tbf thinner"),
    "dos_stream_new_begin_or_resolve_cell": ("D3", "L3OpElevationTest + Dos.dosStreamNewBeginOrResolveCell", "dos begin/resolve thinner"),
    # command/reasons/flow/conflux (circuit_truncated seeded above with circuitbuild)
    "circuit_ccontrol": ("D3", "L3OpElevationTest + Conflux.circuitCcontrol", "ccontrol thinner"),
    "circuit_end_reason_to_control_string": ("D3", "L3OpElevationTest + Reasons.circuitEndReasonToControlString", "circ end reason thinner"),
    "circuit_get_package_window": ("D3", "L3OpElevationTest + ConfluxUtil.circuitGetPackageWindow", "pkg window thinner"),
    "circuit_process_stream_xoff": ("D3", "L3OpElevationTest + CongestionControlFlow.circuitProcessStreamXoff", "stream xoff thinner"),
    "circuit_process_stream_xon": ("D3", "L3OpElevationTest + CongestionControlFlow.circuitProcessStreamXon", "stream xon thinner"),
    "command_process_cell": ("D3", "L3OpElevationTest + Command.commandProcessCell", "cmd process thinner"),
    "command_setup_channel": ("D3", "L3OpElevationTest + Command.commandSetupChannel", "cmd setup chan thinner"),
    "command_setup_listener": ("D3", "L3OpElevationTest + Command.commandSetupListener", "cmd setup listen thinner"),
    "end_reason_to_http_connect_response_line": ("D3", "L3OpElevationTest + Reasons.endReasonToHttpConnectResponseLine", "http connect reason thinner"),
    "errno_to_orconn_end_reason": ("D3", "L3OpElevationTest + Reasons.errnoToOrconnEndReason", "errno orconn thinner"),
    "errno_to_stream_end_reason": ("D3", "L3OpElevationTest + Reasons.errnoToStreamEndReason", "errno stream thinner"),
    "orconn_end_reason_to_control_string": ("D3", "L3OpElevationTest + Reasons.orconnEndReasonToControlString", "orconn reason thinner"),
    "socks4_response_code_to_string": ("D3", "L3OpElevationTest + Reasons.socks4ResponseCodeToString", "socks4 reason thinner"),
    "socks5_response_code_to_string": ("D3", "L3OpElevationTest + Reasons.socks5ResponseCodeToString", "socks5 reason thinner"),
    "stream_end_reason_to_control_string": ("D3", "L3OpElevationTest + Reasons.streamEndReasonToControlString", "stream end control thinner"),
    "stream_end_reason_to_socks5_response": ("D3", "L3OpElevationTest + Reasons.streamEndReasonToSocks5Response", "stream socks5 thinner"),
    "stream_end_reason_to_string": ("D3", "L3OpElevationTest + Reasons.streamEndReasonToString", "stream end string thinner"),
    "tls_error_to_orconn_end_reason": ("D3", "L3OpElevationTest + Reasons.tlsErrorToOrconnEndReason", "tls orconn thinner"),
    "conn_uses_flow_control": ("D3", "L3OpElevationTest + CongestionControlFlow.connUsesFlowControl", "conn flow thinner"),
    "edge_uses_flow_control": ("D3", "L3OpElevationTest + CongestionControlFlow.edgeUsesFlowControl", "edge flow thinner"),
    "flow_control_decide_xoff": ("D3", "L3OpElevationTest + CongestionControlFlow.flowControlDecideXoff", "decide xoff thinner"),
    "flow_control_decide_xon": ("D3", "L3OpElevationTest + CongestionControlFlow.flowControlDecideXon", "decide xon thinner"),
    "flow_control_new_consensus_params": ("D3", "L3OpElevationTest + CongestionControlFlow.flowControlNewConsensusParams", "flow consensus thinner"),
    "flow_control_note_sent_data": ("D3", "L3OpElevationTest + CongestionControlFlow.flowControlNoteSentData", "note sent thinner"),
    "conflux_clear_ooo_q": ("D3", "L3OpElevationTest + Conflux.confluxClearOooQ", "ooo clear thinner"),
    "conflux_decide_circ_for_send": ("D3", "L3OpElevationTest + Conflux.confluxDecideCircForSend", "decide send circ thinner"),
    "conflux_decide_next_circ": ("D3", "L3OpElevationTest + Conflux.confluxDecideNextCirc", "decide next circ thinner"),
    "conflux_dequeue_relay_msg": ("D3", "L3OpElevationTest + Conflux.confluxDequeueRelayMsg", "dequeue msg thinner"),
    "conflux_get_circ_bytes_allocation": ("D3", "L3OpElevationTest + Conflux.confluxGetCircBytesAllocation", "circ bytes thinner"),
    "conflux_get_leg": ("D3", "L3OpElevationTest + Conflux.confluxGetLeg", "get leg thinner"),
    "conflux_get_max_seq_recv": ("D3", "L3OpElevationTest + Conflux.confluxGetMaxSeqRecv", "max seq recv thinner"),
    "conflux_get_max_seq_sent": ("D3", "L3OpElevationTest + Conflux.confluxGetMaxSeqSent", "max seq sent thinner"),
    "conflux_get_total_bytes_allocation": ("D3", "L3OpElevationTest + Conflux.confluxGetTotalBytesAllocation", "total bytes thinner"),
    "conflux_handle_oom": ("D3", "L3OpElevationTest + Conflux.confluxHandleOom", "oom thinner"),
    "conflux_msg_alloc_cost": ("D3", "L3OpElevationTest + Conflux.confluxMsgAllocCost", "msg cost thinner"),
    "conflux_note_cell_sent": ("D3", "L3OpElevationTest + Conflux.confluxNoteCellSent", "note cell thinner"),
    "conflux_process_relay_msg": ("D3", "L3OpElevationTest + Conflux.confluxProcessRelayMsg", "process relay thinner"),
    "conflux_process_switch_command": ("D3", "L3OpElevationTest + Conflux.confluxProcessSwitchCommand", "process switch thinner"),
    "conflux_relay_msg_free_": ("D3", "L3OpElevationTest + Conflux.confluxRelayMsgFree_", "relay msg free thinner"),
    "conflux_should_multiplex": ("D3", "L3OpElevationTest + Conflux.confluxShouldMultiplex", "should mux thinner"),
    "conflux_update_rtt": ("D3", "L3OpElevationTest + Conflux.confluxUpdateRtt", "update rtt thinner"),
    "conflux_add_guards_to_exclude_list": ("D3", "L3OpElevationTest + ConfluxPool.confluxAddGuardsToExcludeList", "exclude guards thinner"),
    "conflux_add_middles_to_exclude_list": ("D3", "L3OpElevationTest + ConfluxPool.confluxAddMiddlesToExcludeList", "exclude middles thinner"),
    "conflux_circuit_about_to_free": ("D3", "L3OpElevationTest + ConfluxPool.confluxCircuitAboutToFree", "about to free thinner"),
    "conflux_circuit_has_closed": ("D3", "L3OpElevationTest + ConfluxPool.confluxCircuitHasClosed", "circ closed thinner"),
    "conflux_circuit_has_opened": ("D3", "L3OpElevationTest + ConfluxPool.confluxCircuitHasOpened", "circ opened thinner"),
    "conflux_clear_shutdown": ("D3", "L3OpElevationTest + ConfluxPool.confluxClearShutdown", "clear shutdown thinner"),
    "conflux_get_circ_for_conn": ("D3", "L3OpElevationTest + ConfluxPool.confluxGetCircForConn", "circ for conn thinner"),
    "conflux_launch_leg": ("D3", "L3OpElevationTest + ConfluxPool.confluxLaunchLeg", "launch leg thinner"),
    "conflux_log_set": ("D3", "L3OpElevationTest + ConfluxPool.confluxLogSet", "log set thinner"),
    "conflux_mark_all_for_close": ("D3", "L3OpElevationTest + ConfluxPool.confluxMarkAllForClose", "mark all close thinner"),
    "conflux_notify_shutdown": ("D3", "L3OpElevationTest + ConfluxPool.confluxNotifyShutdown", "notify shutdown thinner"),
    "conflux_pool_free_all": ("D3", "L3OpElevationTest + ConfluxPool.confluxPoolFreeAll", "pool free thinner"),
    "conflux_pool_init": ("D3", "L3OpElevationTest + ConfluxPool.confluxPoolInit", "pool init thinner"),
    "conflux_predict_new": ("D3", "L3OpElevationTest + ConfluxPool.confluxPredictNew", "predict new thinner"),
    "conflux_process_link": ("D3", "L3OpElevationTest + ConfluxPool.confluxProcessLink", "process link thinner"),
    "conflux_process_linked": ("D3", "L3OpElevationTest + ConfluxPool.confluxProcessLinked", "process linked thinner"),
    "conflux_process_linked_ack": ("D3", "L3OpElevationTest + ConfluxPool.confluxProcessLinkedAck", "process linked ack thinner"),
    "get_linked_pool": ("D3", "L3OpElevationTest + ConfluxPool.getLinkedPool", "linked pool thinner"),
    "get_unlinked_pool": ("D3", "L3OpElevationTest + ConfluxPool.getUnlinkedPool", "unlinked pool thinner"),
    "launch_new_set": ("D3", "L3OpElevationTest + ConfluxPool.launchNewSet", "launch set thinner"),
    "conflux_can_send": ("D3", "L3OpElevationTest + ConfluxUtil.confluxCanSend", "can send thinner"),
    "conflux_get_circ_rtt": ("D3", "L3OpElevationTest + ConfluxUtil.confluxGetCircRtt", "circ rtt thinner"),
    "conflux_get_destination_hop": ("D3", "L3OpElevationTest + ConfluxUtil.confluxGetDestinationHop", "dest hop thinner"),
    "conflux_get_nonce": ("D3", "L3OpElevationTest + ConfluxUtil.confluxGetNonce", "get nonce thinner"),
    "conflux_sync_circ_fields": ("D3", "L3OpElevationTest + ConfluxUtil.confluxSyncCircFields", "sync fields thinner"),
    "conflux_update_half_streams": ("D3", "L3OpElevationTest + ConfluxUtil.confluxUpdateHalfStreams", "half streams thinner"),
    "conflux_update_n_streams": ("D3", "L3OpElevationTest + ConfluxUtil.confluxUpdateNStreams", "n streams thinner"),
    "conflux_update_p_streams": ("D3", "L3OpElevationTest + ConfluxUtil.confluxUpdatePStreams", "p streams thinner"),
    "conflux_update_resolving_streams": ("D3", "L3OpElevationTest + ConfluxUtil.confluxUpdateResolvingStreams", "resolving streams thinner"),
    "conflux_validate_legs": ("D3", "L3OpElevationTest + ConfluxUtil.confluxValidateLegs", "validate legs thinner"),
    "conflux_validate_source_hop": ("D3", "L3OpElevationTest + ConfluxUtil.confluxValidateSourceHop", "validate source thinner"),
    "conflux_validate_stream_lists": ("D3", "L3OpElevationTest + ConfluxUtil.confluxValidateStreamLists", "validate streams thinner"),
    "edge_get_max_rtt": ("D3", "L3OpElevationTest + ConfluxUtil.edgeGetMaxRtt", "edge max rtt thinner"),
    "edge_uses_cpath": ("D3", "L3OpElevationTest + ConfluxUtil.edgeUsesCpath", "edge cpath thinner"),
    "relay_crypt_from_last_hop": ("D3", "L3OpElevationTest + ConfluxUtil.relayCryptFromLastHop", "relay last hop thinner"),
    "conflux_cell_new_link": ("D3", "L3OpElevationTest + ConfluxCell.confluxCellNewLink", "cell new link thinner"),
    "conflux_cell_parse_link": ("D3", "L3OpElevationTest + ConfluxCell.confluxCellParseLink", "cell parse link thinner"),
    "conflux_cell_parse_linked": ("D3", "L3OpElevationTest + ConfluxCell.confluxCellParseLinked", "cell parse linked thinner"),
    "conflux_cell_parse_switch": ("D3", "L3OpElevationTest + ConfluxCell.confluxCellParseSwitch", "cell parse switch thinner"),
    "conflux_cell_send_link": ("D3", "L3OpElevationTest + ConfluxCell.confluxCellSendLink", "cell send link thinner"),
    "conflux_cell_send_linked": ("D3", "L3OpElevationTest + ConfluxCell.confluxCellSendLinked", "cell send linked thinner"),
    "conflux_cell_send_linked_ack": ("D3", "L3OpElevationTest + ConfluxCell.confluxCellSendLinkedAck", "cell send linked ack thinner"),
    "conflux_send_switch_command": ("D3", "L3OpElevationTest + ConfluxCell.confluxSendSwitchCommand", "send switch thinner"),
    "conflux_is_enabled": ("D3", "L3OpElevationTest + ConfluxParams.confluxIsEnabled", "cfx enabled thinner"),
    "conflux_params_get_drain_pct": ("D3", "L3OpElevationTest + ConfluxParams.confluxParamsGetDrainPct", "drain pct thinner"),
    "conflux_params_get_max_legs_set": ("D3", "L3OpElevationTest + ConfluxParams.confluxParamsGetMaxLegsSet", "max legs thinner"),
    "conflux_params_get_max_linked_set": ("D3", "L3OpElevationTest + ConfluxParams.confluxParamsGetMaxLinkedSet", "max linked thinner"),
    "conflux_params_get_max_oooq": ("D3", "L3OpElevationTest + ConfluxParams.confluxParamsGetMaxOooq", "max oooq thinner"),
    "conflux_params_get_max_prebuilt": ("D3", "L3OpElevationTest + ConfluxParams.confluxParamsGetMaxPrebuilt", "max prebuilt thinner"),
    "conflux_params_get_max_unlinked_leg_retry": ("D3", "L3OpElevationTest + ConfluxParams.confluxParamsGetMaxUnlinkedLegRetry", "max unlinked retry thinner"),
    "conflux_params_get_num_legs_set": ("D3", "L3OpElevationTest + ConfluxParams.confluxParamsGetNumLegsSet", "num legs thinner"),
    "conflux_params_get_send_pct": ("D3", "L3OpElevationTest + ConfluxParams.confluxParamsGetSendPct", "send pct thinner"),
    "conflux_params_new_consensus": ("D3", "L3OpElevationTest + ConfluxParams.confluxParamsNewConsensus", "cfx consensus thinner"),
    # connection_edge.h connection_ap_* (first-25 remainder) + vegas
    "congestion_control_vegas_process_sendme": ("D3", "L3OpElevationTest + CongestionControlVegas.congestionControlVegasProcessSendme", "vegas sendme thinner"),
    "congestion_control_vegas_set_params": ("D3", "L3OpElevationTest + CongestionControlVegas.congestionControlVegasSetParams", "vegas params thinner"),
    "connection_ap_about_to_close": ("D3", "L3OpElevationTest + ConnectionEdge.connectionApAboutToClose", "ap about close thinner"),
    "connection_ap_attach_pending": ("D3", "L3OpElevationTest + ConnectionEdge.connectionApAttachPending", "ap attach thinner"),
    "connection_ap_can_use_exit": ("D3", "L3OpElevationTest + ConnectionEdge.connectionApCanUseExit", "ap can exit thinner"),
    "connection_ap_detach_retriable": ("D3", "L3OpElevationTest + ConnectionEdge.connectionApDetachRetriable", "ap detach thinner"),
    "connection_ap_expire_beginning": ("D3", "L3OpElevationTest + ConnectionEdge.connectionApExpireBeginning", "ap expire thinner"),
    "connection_ap_fail_onehop": ("D3", "L3OpElevationTest + ConnectionEdge.connectionApFailOnehop", "ap fail onehop thinner"),
    "connection_ap_handshake_rewrite": ("D3", "L3OpElevationTest + ConnectionEdge.connectionApHandshakeRewrite", "ap rewrite thinner"),
    "connection_ap_handshake_rewrite_and_attach": ("D3", "L3OpElevationTest + ConnectionEdge.connectionApHandshakeRewriteAndAttach", "ap rewrite attach thinner"),
    "connection_ap_handshake_send_resolve": ("D3", "L3OpElevationTest + ConnectionEdge.connectionApHandshakeSendResolve", "ap resolve thinner"),
    "connection_ap_handshake_socks_reply": ("D3", "L3OpElevationTest + ConnectionEdge.connectionApHandshakeSocksReply", "ap socks reply thinner"),
    "connection_ap_handshake_socks_resolved_addr": ("D3", "L3OpElevationTest + ConnectionEdge.connectionApHandshakeSocksResolvedAddr", "ap socks addr thinner"),
    "connection_ap_make_link": ("D3", "L3OpElevationTest + ConnectionEdge.connectionApMakeLink", "ap make link thinner"),
    "connection_ap_mark_as_non_pending_circuit": ("D3", "L3OpElevationTest + ConnectionEdge.connectionApMarkAsNonPendingCircuit", "ap non pending thinner"),
    "connection_ap_mark_as_pending_circuit_": ("D3", "L3OpElevationTest + ConnectionEdge.connectionApMarkAsPendingCircuit_", "ap pending thinner"),
    "connection_ap_mark_as_waiting_for_renddesc": ("D3", "L3OpElevationTest + ConnectionEdge.connectionApMarkAsWaitingForRenddesc", "ap renddesc thinner"),
    "connection_ap_process_http_connect": ("D3", "L3OpElevationTest + ConnectionEdge.connectionApProcessHttpConnect", "ap http connect thinner"),
    "connection_ap_process_transparent": ("D3", "L3OpElevationTest + ConnectionEdge.connectionApProcessTransparent", "ap transparent thinner"),
    "connection_ap_rescan_and_attach_pending": ("D3", "L3OpElevationTest + ConnectionEdge.connectionApRescanAndAttachPending", "ap rescan thinner"),
    # crypt_path / extendinfo / onion / status / protover / dos_sys
    "cpath_append_hop": ("D3", "L3OpElevationTest + CryptPath.cpathAppendHop", "cpath append thinner"),
    "cpath_assert_layer_ok": ("D3", "L3OpElevationTest + CryptPath.cpathAssertLayerOk", "cpath layer ok thinner"),
    "cpath_assert_ok": ("D3", "L3OpElevationTest + CryptPath.cpathAssertOk", "cpath ok thinner"),
    "cpath_extend_linked_list": ("D3", "L3OpElevationTest + CryptPath.cpathExtendLinkedList", "cpath extend thinner"),
    "cpath_free": ("D3", "L3OpElevationTest + CryptPath.cpathFree", "cpath free thinner"),
    "cpath_get_n_hops": ("D3", "L3OpElevationTest + CryptPath.cpathGetNHops", "cpath nhops thinner"),
    "cpath_get_next_non_open_hop": ("D3", "L3OpElevationTest + CryptPath.cpathGetNextNonOpenHop", "cpath next hop thinner"),
    "cpath_get_sendme_tag": ("D3", "L3OpElevationTest + CryptPath.cpathGetSendmeTag", "cpath sendme tag thinner"),
    "cpath_init_circuit_crypto": ("D3", "L3OpElevationTest + CryptPath.cpathInitCircuitCrypto", "cpath init crypto thinner"),
    "cpath_sendme_circuit_record_inbound_cell": ("D3", "L3OpElevationTest + CryptPath.cpathSendmeCircuitRecordInboundCell", "cpath sendme inbound thinner"),
    "extend_info_add_orport": ("D3", "L3OpElevationTest + ExtendInfo.extendInfoAddOrport", "ei add orport thinner"),
    "extend_info_addr_is_allowed": ("D3", "L3OpElevationTest + ExtendInfo.extendInfoAddrIsAllowed", "ei addr allowed thinner"),
    "extend_info_any_orport_addr_is_internal": ("D3", "L3OpElevationTest + ExtendInfo.extendInfoAnyOrportAddrIsInternal", "ei internal thinner"),
    "extend_info_dup": ("D3", "L3OpElevationTest + ExtendInfo.extendInfoDup", "ei dup thinner"),
    "extend_info_free_": ("D3", "L3OpElevationTest + ExtendInfo.extendInfoFree_", "ei free thinner"),
    "extend_info_from_node": ("D3", "L3OpElevationTest + ExtendInfo.extendInfoFromNode", "ei from node thinner"),
    "extend_info_get_orport": ("D3", "L3OpElevationTest + ExtendInfo.extendInfoGetOrport", "ei get orport thinner"),
    "extend_info_has_orport": ("D3", "L3OpElevationTest + ExtendInfo.extendInfoHasOrport", "ei has orport thinner"),
    "extend_info_has_preferred_onion_key": ("D3", "L3OpElevationTest + ExtendInfo.extendInfoHasPreferredOnionKey", "ei onion key thinner"),
    "extend_info_new": ("D3", "L3OpElevationTest + ExtendInfo.extendInfoNew", "ei new thinner"),
    "extend_info_pick_orport": ("D3", "L3OpElevationTest + ExtendInfo.extendInfoPickOrport", "ei pick orport thinner"),
    "extend_info_supports_ntor": ("D3", "L3OpElevationTest + ExtendInfo.extendInfoSupportsNtor", "ei ntor thinner"),
    "extend_info_supports_ntor_v3": ("D3", "L3OpElevationTest + ExtendInfo.extendInfoSupportsNtorV3", "ei ntorv3 thinner"),
    "create_cell_format": ("D3", "L3OpElevationTest + Onion.createCellFormat", "create format thinner"),
    "create_cell_format_relayed": ("D3", "L3OpElevationTest + Onion.createCellFormatRelayed", "create relayed thinner"),
    "create_cell_init": ("D3", "L3OpElevationTest + Onion.createCellInit", "create init thinner"),
    "create_cell_parse": ("D3", "L3OpElevationTest + Onion.createCellParse", "create parse thinner"),
    "created_cell_format": ("D3", "L3OpElevationTest + Onion.createdCellFormat", "created format thinner"),
    "created_cell_parse": ("D3", "L3OpElevationTest + Onion.createdCellParse", "created parse thinner"),
    "extend_cell_format": ("D3", "L3OpElevationTest + Onion.extendCellFormat", "extend format thinner"),
    "extended_cell_format": ("D3", "L3OpElevationTest + Onion.extendedCellFormat", "extended format thinner"),
    "extended_cell_parse": ("D3", "L3OpElevationTest + Onion.extendedCellParse", "extended parse thinner"),
    "count_circuits": ("D3", "L3OpElevationTest + HeartbeatStatus.countCircuits", "count circs thinner"),
    "log_heartbeat": ("D3", "L3OpElevationTest + HeartbeatStatus.logHeartbeat", "log heartbeat thinner"),
    "note_circ_closed_for_unrecognized_cells": ("D3", "L3OpElevationTest + HeartbeatStatus.noteCircClosedForUnrecognizedCells", "note unrecognized thinner"),
    "note_connection": ("D3", "L3OpElevationTest + HeartbeatStatus.noteConnection", "note conn thinner"),
    "secs_to_uptime": ("D3", "L3OpElevationTest + HeartbeatStatus.secsToUptime", "secs uptime thinner"),
    "dos_get_options": ("D3", "L3OpElevationTest + DosSys.dosGetOptions", "dos options thinner"),
    "encode_protocol_list": ("D3", "L3OpElevationTest + Protover.encodeProtocolList", "encode proto thinner"),
    "parse_protocol_list": ("D3", "L3OpElevationTest + Protover.parseProtocolList", "parse proto thinner"),
    "proto_entry_free_": ("D3", "L3OpElevationTest + Protover.protoEntryFree_", "proto entry free thinner"),
    "protocol_list_supports_protocol": ("D3", "L3OpElevationTest + Protover.protocolListSupportsProtocol", "proto supports thinner"),
    "protocol_list_supports_protocol_or_later": ("D3", "L3OpElevationTest + Protover.protocolListSupportsProtocolOrLater", "proto or later thinner"),
    "protocol_type_to_str": ("D3", "L3OpElevationTest + Protover.protocolTypeToStr", "proto type str thinner"),
    "protover_all_supported": ("D3", "L3OpElevationTest + Protover.protoverAllSupported", "proto all thinner"),
    "protover_compute_for_old_tor": ("D3", "L3OpElevationTest + Protover.protoverComputeForOldTor", "proto old tor thinner"),
    "protover_compute_vote": ("D3", "L3OpElevationTest + Protover.protoverComputeVote", "proto vote thinner"),
    "protover_free_all": ("D3", "L3OpElevationTest + Protover.protoverFreeAll", "proto free thinner"),
    "protover_get_recommended_client_protocols": ("D3", "L3OpElevationTest + Protover.protoverGetRecommendedClientProtocols", "proto rec client thinner"),
    "protover_get_recommended_relay_protocols": ("D3", "L3OpElevationTest + Protover.protoverGetRecommendedRelayProtocols", "proto rec relay thinner"),
    "protover_get_required_client_protocols": ("D3", "L3OpElevationTest + Protover.protoverGetRequiredClientProtocols", "proto req client thinner"),
    "protover_get_required_relay_protocols": ("D3", "L3OpElevationTest + Protover.protoverGetRequiredRelayProtocols", "proto req relay thinner"),
    "protover_get_supported": ("D3", "L3OpElevationTest + Protover.protoverGetSupported", "proto get supported thinner"),
    "protover_get_supported_protocols": ("D3", "L3OpElevationTest + Protover.protoverGetSupportedProtocols", "proto supported thinner"),
    "protover_is_supported_here": ("D3", "L3OpElevationTest + Protover.protoverIsSupportedHere", "proto here thinner"),
    "protover_list_is_invalid": ("D3", "L3OpElevationTest + Protover.protoverListIsInvalid", "proto invalid thinner"),
    "str_to_protocol_type": ("D3", "L3OpElevationTest + Protover.strToProtocolType", "str to proto thinner"),
    # firewall / cell sizes / scheduler / ocirc / orconn / sendme leftovers / versions
    "firewall_is_fascist_dir": ("D3", "L3OpElevationTest + Policies.firewallIsFascistDir", "fascist dir thinner"),
    "firewall_is_fascist_or": ("D3", "L3OpElevationTest + Policies.firewallIsFascistOr", "fascist or thinner"),
    "getinfo_helper_policies": ("D3", "L3OpElevationTest + Policies.getinfoHelperPolicies", "getinfo policies thinner"),
    "policies_free_all": ("D3", "L3OpElevationTest + Policies.policiesFreeAll", "policies free thinner"),
    "get_cell_network_size": ("D3", "L3OpElevationTest + Cell.getCellNetworkSize", "cell net size thinner"),
    "get_circ_id_size": ("D3", "L3OpElevationTest + Cell.getCircIdSize", "circ id size thinner"),
    "get_var_cell_header_size": ("D3", "L3OpElevationTest + Cell.getVarCellHeaderSize", "var cell hdr thinner"),
    "get_accept_min_version": ("D3", "L3OpElevationTest + Sendme.acceptMinVersionResolved", "accept min ver thinner"),
    "get_emit_min_version": ("D3", "L3OpElevationTest + Sendme.emitMinVersionResolved", "emit min ver thinner"),
    "get_channels_pending": ("D3", "L3OpElevationTest + Scheduler.getChannelsPending", "channels pending thinner"),
    "get_kist_scheduler": ("D3", "L3OpElevationTest + Scheduler.getKistScheduler", "kist sched thinner"),
    "get_scheduler_state_string": ("D3", "L3OpElevationTest + Scheduler.getSchedulerStateString", "sched state thinner"),
    "get_vanilla_scheduler": ("D3", "L3OpElevationTest + Scheduler.getVanillaScheduler", "vanilla sched thinner"),
    "kist_scheduler_run_interval": ("D3", "L3OpElevationTest + Scheduler.kistSchedulerRunInterval", "kist interval thinner"),
    "scheduler_bug_occurred": ("D3", "L3OpElevationTest + Scheduler.schedulerBugOccurred", "sched bug thinner"),
    "scheduler_can_use_kist": ("D3", "L3OpElevationTest + Scheduler.schedulerCanUseKist", "can kist thinner"),
    "scheduler_channel_wants_writes": ("D3", "L3OpElevationTest + Scheduler.schedulerChannelWantsWrites", "wants writes thinner"),
    "scheduler_conf_changed": ("D3", "L3OpElevationTest + Scheduler.schedulerConfChanged", "sched conf thinner"),
    "scheduler_ev_active": ("D3", "L3OpElevationTest + Scheduler.schedulerEvActive", "sched ev active thinner"),
    "scheduler_ev_add": ("D3", "L3OpElevationTest + Scheduler.schedulerEvAdd", "sched ev add thinner"),
    "scheduler_free_all": ("D3", "L3OpElevationTest + Scheduler.schedulerFreeAll", "sched free thinner"),
    "scheduler_init": ("D3", "L3OpElevationTest + Scheduler.schedulerInit", "sched init thinner"),
    "scheduler_kist_set_full_mode": ("D3", "L3OpElevationTest + Scheduler.schedulerKistSetFullMode", "kist full thinner"),
    "scheduler_kist_set_lite_mode": ("D3", "L3OpElevationTest + Scheduler.schedulerKistSetLiteMode", "kist lite thinner"),
    "scheduler_notify_networkstatus_changed": ("D3", "L3OpElevationTest + Scheduler.schedulerNotifyNetworkstatusChanged", "sched ns thinner"),
    "scheduler_set_channel_state": ("D3", "L3OpElevationTest + Scheduler.schedulerSetChannelState", "sched chan state thinner"),
    "scheduler_touch_channel": ("D3", "L3OpElevationTest + Scheduler.schedulerTouchChannel", "sched touch thinner"),
    "ocirc_cevent_publish": ("D3", "L3OpElevationTest + OcircEvent.ocircCeventPublish", "ocirc cevent thinner"),
    "ocirc_chan_publish": ("D3", "L3OpElevationTest + OcircEvent.ocircChanPublish", "ocirc chan thinner"),
    "ocirc_state_publish": ("D3", "L3OpElevationTest + OcircEvent.ocircStatePublish", "ocirc state thinner"),
    "ocirc_add_pubsub": ("D3", "L3OpElevationTest + OrSys.ocircAddPubsub", "ocirc pubsub thinner"),
    "orconn_add_pubsub": ("D3", "L3OpElevationTest + OrSys.orconnAddPubsub", "orconn pubsub thinner"),
    "orconn_state_publish": ("D3", "L3OpElevationTest + OrconnEvent.orconnStatePublish", "orconn state thinner"),
    "orconn_status_publish": ("D3", "L3OpElevationTest + OrconnEvent.orconnStatusPublish", "orconn status thinner"),
    "or_register_periodic_events": ("D3", "L3OpElevationTest + OrPeriodic.orRegisterPeriodicEvents", "or periodic thinner"),
    "sendme_circuit_consider_sending": ("D3", "L3OpElevationTest + Sendme.sendmeCircuitConsiderSending", "sendme circ consider thinner"),
    "sendme_circuit_data_received": ("D3", "L3OpElevationTest + Sendme.sendmeCircuitDataReceived", "sendme circ data thinner"),
    "sendme_connection_edge_consider_sending": ("D3", "L3OpElevationTest + Sendme.sendmeConnectionEdgeConsiderSending", "sendme edge consider thinner"),
    "sendme_is_valid": ("D3", "L3OpElevationTest + Sendme.sendmeIsValid", "sendme valid thinner"),
    "sendme_note_circuit_data_packaged": ("D3", "L3OpElevationTest + Sendme.sendmeNoteCircuitDataPackaged", "sendme note circ thinner"),
    "sendme_note_stream_data_packaged": ("D3", "L3OpElevationTest + Sendme.sendmeNoteStreamDataPackaged", "sendme note stream thinner"),
    "sendme_process_circuit_level": ("D3", "L3OpElevationTest + Sendme.sendmeProcessCircuitLevel", "sendme proc circ thinner"),
    "sendme_process_circuit_level_impl": ("D3", "L3OpElevationTest + Sendme.sendmeProcessCircuitLevelImpl", "sendme proc circ impl thinner"),
    "sendme_process_stream_level": ("D3", "L3OpElevationTest + Sendme.sendmeProcessStreamLevel", "sendme proc stream thinner"),
    "sendme_record_cell_digest_on_circ": ("D3", "L3OpElevationTest + Sendme.sendmeRecordCellDigestOnCirc", "sendme record digest thinner"),
    "sendme_stream_data_received": ("D3", "L3OpElevationTest + Sendme.sendmeStreamDataReceived", "sendme stream data thinner"),
    "protover_summary_cache_free_all": ("D3", "L3OpElevationTest + Versions.protoverSummaryCacheFreeAll", "protover cache free thinner"),
    "sort_version_list": ("D3", "L3OpElevationTest + Versions.sortVersionList", "sort versions thinner"),
    "summarize_protover_flags": ("D3", "L3OpElevationTest + Versions.summarizeProtoverFlags", "summarize protover thinner"),
    "tor_get_approx_release_date": ("D3", "L3OpElevationTest + Versions.torGetApproxReleaseDate", "approx release thinner"),
    "tor_version_as_new_as": ("D3", "L3OpElevationTest + Versions.torVersionAsNewAs", "version as new thinner"),
    "tor_version_compare": ("D3", "L3OpElevationTest + Versions.torVersionCompare", "version compare thinner"),
    "tor_version_is_obsolete": ("D3", "L3OpElevationTest + Versions.torVersionIsObsolete", "version obsolete thinner"),
    "tor_version_parse": ("D3", "L3OpElevationTest + Versions.torVersionParse", "version parse thinner"),
    "tor_version_parse_platform": ("D3", "L3OpElevationTest + Versions.torVersionParsePlatform", "version platform thinner"),
    "tor_version_same_series": ("D3", "L3OpElevationTest + Versions.torVersionSameSeries", "version series thinner"),
    # relay_msg + addressmap + bridges + authmode
    "relay_msg_clear": ("D3", "L3OpElevationTest + RelayMsg.relayMsgClear", "relay msg clear thinner"),
    "relay_msg_copy": ("D3", "L3OpElevationTest + RelayMsg.relayMsgCopy", "relay msg copy thinner"),
    "relay_msg_free_": ("D3", "L3OpElevationTest + RelayMsg.relayMsgFree_", "relay msg free thinner"),
    "addressmap_clear_excluded_trackexithosts": ("D3", "L3OpElevationTest + AddressMap.addressmapClearExcludedTrackexithosts", "addrmap clear trackexit thinner"),
    "addressmap_clear_invalid_automaps": ("D3", "L3OpElevationTest + AddressMap.addressmapClearInvalidAutomaps", "addrmap clear invalid thinner"),
    "addressmap_clear_transient": ("D3", "L3OpElevationTest + AddressMap.addressmapClearTransient", "addrmap clear transient thinner"),
    "addressmap_free_all": ("D3", "L3OpElevationTest + AddressMap.addressmapFreeAll", "addrmap free thinner"),
    "addressmap_get_mappings": ("D3", "L3OpElevationTest + AddressMap.addressmapGetMappings", "addrmap get thinner"),
    "addressmap_have_mapping": ("D3", "L3OpElevationTest + AddressMap.addressmapHaveMapping", "addrmap have thinner"),
    "addressmap_init": ("D3", "L3OpElevationTest + AddressMap.addressmapInit", "addrmap init thinner"),
    "addressmap_register": ("D3", "L3OpElevationTest + AddressMap.addressmapRegister", "addrmap register thinner"),
    "addressmap_register_virtual_address": ("D3", "L3OpElevationTest + AddressMap.addressmapRegisterVirtualAddress", "addrmap virt thinner"),
    "addressmap_rewrite": ("D3", "L3OpElevationTest + AddressMap.addressmapRewrite", "addrmap rewrite thinner"),
    "addressmap_rewrite_reverse": ("D3", "L3OpElevationTest + AddressMap.addressmapRewriteReverse", "addrmap rewrite rev thinner"),
    "clear_trackexithost_mappings": ("D3", "L3OpElevationTest + AddressMap.clearTrackexithostMappings", "clear trackexit thinner"),
    "client_dns_clear_failures": ("D3", "L3OpElevationTest + AddressMap.clientDnsClearFailures", "dns clear fail thinner"),
    "client_dns_incr_failures": ("D3", "L3OpElevationTest + AddressMap.clientDnsIncrFailures", "dns incr fail thinner"),
    "client_dns_set_addressmap": ("D3", "L3OpElevationTest + AddressMap.clientDnsSetAddressmap", "dns set map thinner"),
    "client_dns_set_reverse_addressmap": ("D3", "L3OpElevationTest + AddressMap.clientDnsSetReverseAddressmap", "dns set rev thinner"),
    "get_random_virtual_addr": ("D3", "L3OpElevationTest + AddressMap.getRandomVirtualAddr", "random virt addr thinner"),
    "parse_virtual_addr_network": ("D3", "L3OpElevationTest + AddressMap.parseVirtualAddrNetwork", "parse virt net thinner"),
    "addr_is_a_configured_bridge": ("D3", "L3OpElevationTest + Bridges.addrIsAConfiguredBridge", "bridge addr thinner"),
    "any_bridges_dont_support_microdescriptors": ("D3", "L3OpElevationTest + Bridges.anyBridgesDontSupportMicrodescriptors", "bridge microdesc thinner"),
    "bridge_add_from_config": ("D3", "L3OpElevationTest + Bridges.bridgeAddFromConfig", "bridge add thinner"),
    "bridge_get_addr_port": ("D3", "L3OpElevationTest + Bridges.bridgeGetAddrPort", "bridge addrport thinner"),
    "bridge_get_rsa_id_digest": ("D3", "L3OpElevationTest + Bridges.bridgeGetRsaIdDigest", "bridge rsa digest thinner"),
    "bridge_has_invalid_transport": ("D3", "L3OpElevationTest + Bridges.bridgeHasInvalidTransport", "bridge invalid transport thinner"),
    "bridge_list_get": ("D3", "L3OpElevationTest + Bridges.bridgeListGet", "bridge list thinner"),
    "bridge_resolve_conflicts": ("D3", "L3OpElevationTest + Bridges.bridgeResolveConflicts", "bridge conflicts thinner"),
    "bridges_free_all": ("D3", "L3OpElevationTest + Bridges.bridgesFreeAll", "bridges free thinner"),
    "bridget_get_transport_name": ("D3", "L3OpElevationTest + Bridges.bridgetGetTransportName", "bridget transport thinner"),
    "clear_bridge_list": ("D3", "L3OpElevationTest + Bridges.clearBridgeList", "clear bridges thinner"),
    "conflux_can_exclude_used_bridges": ("D3", "L3OpElevationTest + Bridges.confluxCanExcludeUsedBridges", "conflux exclude bridges thinner"),
    "extend_info_is_a_configured_bridge": ("D3", "L3OpElevationTest + Bridges.extendInfoIsAConfiguredBridge", "extend bridge thinner"),
    "fetch_bridge_descriptors": ("D3", "L3OpElevationTest + Bridges.fetchBridgeDescriptors", "fetch bridges thinner"),
    "find_bridge_by_digest": ("D3", "L3OpElevationTest + Bridges.findBridgeByDigest", "find bridge thinner"),
    "find_transport_name_by_bridge_addrport": ("D3", "L3OpElevationTest + Bridges.findTransportNameByBridgeAddrport", "find transport thinner"),
    "get_configured_bridge_by_addr_port_digest": ("D3", "L3OpElevationTest + Bridges.getConfiguredBridgeByAddrPortDigest", "get bridge addr thinner"),
    "get_configured_bridge_by_exact_addr_port_digest": ("D3", "L3OpElevationTest + Bridges.getConfiguredBridgeByExactAddrPortDigest", "get bridge exact thinner"),
    "get_configured_bridge_by_orports_digest": ("D3", "L3OpElevationTest + Bridges.getConfiguredBridgeByOrportsDigest", "get bridge orports thinner"),
    "get_socks_args_by_bridge_addrport": ("D3", "L3OpElevationTest + Bridges.getSocksArgsByBridgeAddrport", "bridge socks args thinner"),
    "get_transport_by_bridge_addrport": ("D3", "L3OpElevationTest + Bridges.getTransportByBridgeAddrport", "bridge transport thinner"),
    "learned_bridge_descriptor": ("D3", "L3OpElevationTest + Bridges.learnedBridgeDescriptor", "learned bridge thinner"),
    "learned_router_identity": ("D3", "L3OpElevationTest + Bridges.learnedRouterIdentity", "learned identity thinner"),
    "mark_bridge_list": ("D3", "L3OpElevationTest + Bridges.markBridgeList", "mark bridges thinner"),
    "node_is_a_configured_bridge": ("D3", "L3OpElevationTest + Bridges.nodeIsAConfiguredBridge", "node bridge thinner"),
    "authdir_mode": ("D3", "L3OpElevationTest + AuthMode.authdirMode", "authdir mode thinner"),
    "authdir_mode_bridge": ("D3", "L3OpElevationTest + AuthMode.authdirModeBridge", "authdir bridge thinner"),
    "authdir_mode_handles_descs": ("D3", "L3OpElevationTest + AuthMode.authdirModeHandlesDescs", "authdir descs thinner"),
    "authdir_mode_publishes_statuses": ("D3", "L3OpElevationTest + AuthMode.authdirModePublishesStatuses", "authdir statuses thinner"),
    "authdir_mode_tests_reachability": ("D3", "L3OpElevationTest + AuthMode.authdirModeTestsReachability", "authdir reach thinner"),
    "authdir_mode_v3": ("D3", "L3OpElevationTest + AuthMode.authdirModeV3", "authdir v3 thinner"),
    # entrynodes.h (first 25 client guard ops)
    "choose_guard_selection": ("D3", "L3OpElevationTest + EntryNodes.chooseGuardSelection", "guard selection name thinner"),
    "circuit_guard_state_free_": ("D3", "L3OpElevationTest + EntryNodes.circuitGuardStateFree_", "circ guard free thinner"),
    "entries_known_but_down": ("D3", "L3OpElevationTest + EntryNodes.entriesKnownButDown", "entries down thinner"),
    "entries_retry_all": ("D3", "L3OpElevationTest + EntryNodes.entriesRetryAll", "entries retry thinner"),
    "entry_guard_add_to_sample": ("D3", "L3OpElevationTest + EntryNodes.entryGuardAddToSample", "add sample thinner"),
    "entry_guard_cancel": ("D3", "L3OpElevationTest + EntryNodes.entryGuardCancel", "guard cancel thinner"),
    "entry_guard_chan_failed": ("D3", "L3OpElevationTest + EntryNodes.entryGuardChanFailed", "chan failed thinner"),
    "entry_guard_consider_retry": ("D3", "L3OpElevationTest + EntryNodes.entryGuardConsiderRetry", "consider retry thinner"),
    "entry_guard_could_succeed": ("D3", "L3OpElevationTest + EntryNodes.entryGuardCouldSucceed", "could succeed thinner"),
    "entry_guard_describe": ("D3", "L3OpElevationTest + EntryNodes.entryGuardDescribe", "guard describe thinner"),
    "entry_guard_encode_for_state": ("D3", "L3OpElevationTest + EntryNodes.entryGuardEncodeForState", "encode state thinner"),
    "entry_guard_failed": ("D3", "L3OpElevationTest + EntryNodes.entryGuardFailed", "guard failed thinner"),
    "entry_guard_find_node": ("D3", "L3OpElevationTest + EntryNodes.entryGuardFindNode", "find node thinner"),
    "entry_guard_free_": ("D3", "L3OpElevationTest + EntryNodes.entryGuardFree_", "guard free thinner"),
    "entry_guard_get_by_id_digest": ("D3", "L3OpElevationTest + EntryNodes.entryGuardGetByIdDigest", "get by digest thinner"),
    "entry_guard_get_by_id_digest_for_guard_selection": ("D3", "L3OpElevationTest + EntryNodes.entryGuardGetByIdDigestForGuardSelection", "get by digest gs thinner"),
    "entry_guard_get_pathbias_state": ("D3", "L3OpElevationTest + EntryNodes.entryGuardGetPathbiasState", "pathbias state thinner"),
    "entry_guard_get_rsa_id_digest": ("D3", "L3OpElevationTest + EntryNodes.entryGuardGetRsaIdDigest", "rsa id digest thinner"),
    "entry_guard_has_higher_priority": ("D3", "L3OpElevationTest + EntryNodes.entryGuardHasHigherPriority", "higher priority thinner"),
    "entry_guard_learned_bridge_identity": ("D3", "L3OpElevationTest + EntryNodes.entryGuardLearnedBridgeIdentity", "learned bridge id thinner"),
    "entry_guard_parse_from_state": ("D3", "L3OpElevationTest + EntryNodes.entryGuardParseFromState", "parse state thinner"),
    "entry_guard_pick_for_circuit": ("D3", "L3OpElevationTest + EntryNodes.entryGuardPickForCircuit", "pick for circuit thinner"),
    "entry_guard_restriction_free_": ("D3", "L3OpElevationTest + EntryNodes.entryGuardRestrictionFree_", "restriction free thinner"),
    "entry_guard_state_should_expire": ("D3", "L3OpElevationTest + EntryNodes.entryGuardStateShouldExpire", "state expire thinner"),
    "entry_guard_succeeded": ("D3", "L3OpElevationTest + EntryNodes.entryGuardSucceeded", "guard succeeded thinner"),
    # transports.h (first 25 PT managed-proxy ops)
    "configure_proxy": ("D3", "L3OpElevationTest + Transports.configureProxy", "configure proxy thinner"),
    "free_execve_args": ("D3", "L3OpElevationTest + Transports.freeExecveArgs", "free execve thinner"),
    "get_pt_proxy_uri": ("D3", "L3OpElevationTest + Transports.getPtProxyUri", "pt proxy uri thinner"),
    "get_transport_options_for_server_proxy": ("D3", "L3OpElevationTest + Transports.getTransportOptionsForServerProxy", "server transport opts thinner"),
    "get_transport_proxy_ports": ("D3", "L3OpElevationTest + Transports.getTransportProxyPorts", "transport ports thinner"),
    "handle_proxy_line": ("D3", "L3OpElevationTest + Transports.handleProxyLine", "handle proxy line thinner"),
    "handle_status_message": ("D3", "L3OpElevationTest + Transports.handleStatusMessage", "status message thinner"),
    "launch_proxy_ev": ("D3", "L3OpElevationTest + Transports.launchProxyEv", "launch proxy thinner"),
    "managed_proxy_create": ("D3", "L3OpElevationTest + Transports.managedProxyCreate", "mp create thinner"),
    "managed_proxy_destroy": ("D3", "L3OpElevationTest + Transports.managedProxyDestroy", "mp destroy thinner"),
    "managed_proxy_exit_callback": ("D3", "L3OpElevationTest + Transports.managedProxyExitCallback", "mp exit thinner"),
    "managed_proxy_has_transport": ("D3", "L3OpElevationTest + Transports.managedProxyHasTransport", "mp has transport thinner"),
    "managed_proxy_outbound_address": ("D3", "L3OpElevationTest + Transports.managedProxyOutboundAddress", "mp outbound thinner"),
    "managed_proxy_set_state": ("D3", "L3OpElevationTest + Transports.managedProxySetState", "mp set state thinner"),
    "managed_proxy_severity_parse": ("D3", "L3OpElevationTest + Transports.managedProxySeverityParse", "mp severity thinner"),
    "managed_proxy_state_to_string": ("D3", "L3OpElevationTest + Transports.managedProxyStateToString", "mp state string thinner"),
    "managed_proxy_stderr_callback": ("D3", "L3OpElevationTest + Transports.managedProxyStderrCallback", "mp stderr thinner"),
    "managed_proxy_stdout_callback": ("D3", "L3OpElevationTest + Transports.managedProxyStdoutCallback", "mp stdout thinner"),
    "mark_transport_list": ("D3", "L3OpElevationTest + Transports.markTransportList", "mark transport thinner"),
    "parse_cmethod_line": ("D3", "L3OpElevationTest + Transports.parseCmethodLine", "parse cmethod thinner"),
    "parse_env_error": ("D3", "L3OpElevationTest + Transports.parseEnvError", "parse env error thinner"),
    "parse_log_line": ("D3", "L3OpElevationTest + Transports.parseLogLine", "parse log thinner"),
    "parse_proxy_error": ("D3", "L3OpElevationTest + Transports.parseProxyError", "parse proxy error thinner"),
    "parse_smethod_line": ("D3", "L3OpElevationTest + Transports.parseSmethodLine", "parse smethod thinner"),
    "parse_status_line": ("D3", "L3OpElevationTest + Transports.parseStatusLine", "parse status thinner"),
    # dnsserv.h
    "dnsserv_close_listener": ("D3", "DnsServL3ElevationTest + DnsServ.dnsservCloseListener", "dnsserv close thinner"),
    "dnsserv_configure_listener": ("D3", "DnsServL3ElevationTest + DnsServ.dnsservConfigureListener", "dnsserv configure thinner"),
    "dnsserv_launch_request": ("D3", "DnsServL3ElevationTest + DnsServ.dnsservLaunchRequest", "dnsserv launch thinner"),
    "dnsserv_reject_request": ("D3", "DnsServL3ElevationTest + DnsServ.dnsservRejectRequest", "dnsserv reject thinner"),
    "dnsserv_resolved": ("D3", "DnsServL3ElevationTest + DnsServ.dnsservResolved", "dnsserv resolved thinner"),
    # circpathbias.h / proxymode.h (feature/client queue head)
    "pathbias_check_close": ("D3", "L3OpElevationTest + CircPathBias.pathbiasCheckClose", "pathbias close thinner"),
    "pathbias_check_probe_response": ("D3", "L3OpElevationTest + CircPathBias.pathbiasCheckProbeResponse", "pathbias probe thinner"),
    "pathbias_count_build_attempt": ("D3", "L3OpElevationTest + CircPathBias.pathbiasCountBuildAttempt", "pathbias build attempt thinner"),
    "pathbias_count_build_success": ("D3", "L3OpElevationTest + CircPathBias.pathbiasCountBuildSuccess", "pathbias build success thinner"),
    "pathbias_count_timeout": ("D3", "L3OpElevationTest + CircPathBias.pathbiasCountTimeout", "pathbias timeout thinner"),
    "pathbias_count_use_attempt": ("D3", "L3OpElevationTest + CircPathBias.pathbiasCountUseAttempt", "pathbias use attempt thinner"),
    "pathbias_count_valid_cells": ("D3", "L3OpElevationTest + CircPathBias.pathbiasCountValidCells", "pathbias valid cells thinner"),
    "pathbias_get_dropguards": ("D3", "L3OpElevationTest + CircPathBias.pathbiasGetDropguards", "pathbias dropguards thinner"),
    "pathbias_get_extreme_rate": ("D3", "L3OpElevationTest + CircPathBias.pathbiasGetExtremeRate", "pathbias extreme rate thinner"),
    "pathbias_get_extreme_use_rate": ("D3", "L3OpElevationTest + CircPathBias.pathbiasGetExtremeUseRate", "pathbias extreme use rate thinner"),
    "pathbias_mark_use_rollback": ("D3", "L3OpElevationTest + CircPathBias.pathbiasMarkUseRollback", "pathbias use rollback thinner"),
    "pathbias_mark_use_success": ("D3", "L3OpElevationTest + CircPathBias.pathbiasMarkUseSuccess", "pathbias use success thinner"),
    "pathbias_state_to_string": ("D3", "L3OpElevationTest + CircPathBias.pathbiasStateToString", "pathbias state string thinner"),
    "proxy_mode": ("D3", "DnsServProxyModeElevationTest + ProxyMode.proxyMode", "proxy_mode thinner"),
    # btrack / bto (feature/control queue head)
    "bto_cevent_anyconn": ("D3", "ControlParityElevationTest + BtrackOrconnCevent.btoCeventAnyconn", "bto anyconn thinner"),
    "bto_cevent_apconn": ("D3", "ControlParityElevationTest + BtrackOrconnCevent.btoCeventApconn", "bto apconn thinner"),
    "bto_cevent_reset": ("D3", "ControlParityElevationTest + BtrackOrconnCevent.btoCeventReset", "bto cevent reset thinner"),
    "bto_clear_maps": ("D3", "ControlParityElevationTest + BtrackOrconnMaps.btoClearMaps", "bto clear maps thinner"),
    "bto_delete": ("D3", "ControlParityElevationTest + BtrackOrconnMaps.btoDelete", "bto delete thinner"),
    "bto_find_or_new": ("D3", "ControlParityElevationTest + BtrackOrconnMaps.btoFindOrNew", "bto find or new thinner"),
    "bto_init_maps": ("D3", "ControlParityElevationTest + BtrackOrconnMaps.btoInitMaps", "bto init maps thinner"),
    "btrack_circ_add_pubsub": ("D3", "ControlParityElevationTest + BtrackCircuit.btrackCircAddPubsub", "btrack circ pubsub thinner"),
    "btrack_circ_fini": ("D3", "ControlParityElevationTest + BtrackCircuit.btrackCircFini", "btrack circ fini thinner"),
    "btrack_circ_init": ("D3", "ControlParityElevationTest + BtrackCircuit.btrackCircInit", "btrack circ init thinner"),
    "btrack_orconn_add_pubsub": ("D3", "ControlParityElevationTest + BtrackOrconn.btrackOrconnAddPubsub", "btrack orconn pubsub thinner"),
    "btrack_orconn_fini": ("D3", "ControlParityElevationTest + BtrackOrconn.btrackOrconnFini", "btrack orconn fini thinner"),
    "btrack_orconn_init": ("D3", "ControlParityElevationTest + BtrackOrconn.btrackOrconnInit", "btrack orconn init thinner"),
    # feature/control next 25 (cmd/proto/events/connection)
    "add_onion_helper_add_service": ("D3", "ControlParityElevationTest + ControlCmd.addOnionHelperAddService", "add onion helper thinner"),
    "add_onion_helper_keyarg": ("D3", "ControlParityElevationTest + ControlCmd.addOnionHelperKeyarg", "add onion keyarg thinner"),
    "append_cell_stats_by_command": ("D3", "ControlParityElevationTest + ControlEvents.appendCellStatsByCommand", "cell stats thinner"),
    "cbt_control_event_buildtimeout_set": ("D3", "ControlParityElevationTest + ControlEvents.cbtControlEventBuildtimeoutSet", "cbt buildtimeout thinner"),
    "circuit_describe_status_for_controller": ("D3", "ControlParityElevationTest + ControlFmt.circuitDescribeStatusForController", "circ describe thinner"),
    "connection_control_closed": ("D3", "ControlParityElevationTest + Control.connectionControlClosed", "control closed thinner"),
    "connection_control_finished_flushing": ("D3", "ControlParityElevationTest + Control.connectionControlFinishedFlushing", "control flush thinner"),
    "connection_control_process_inbuf": ("D3", "ControlParityElevationTest + Control.connectionControlProcessInbuf", "control inbuf thinner"),
    "connection_control_reached_eof": ("D3", "ControlParityElevationTest + Control.connectionControlReachedEof", "control eof thinner"),
    "connection_printf_to_buf": ("D3", "ControlParityElevationTest + ControlProto.connectionPrintfToBuf", "printf to buf thinner"),
    "connection_write_str_to_buf": ("D3", "ControlParityElevationTest + ControlProto.connectionWriteStrToBuf", "write str to buf thinner"),
    "control_adjust_event_log_severity": ("D3", "ControlParityElevationTest + ControlEvents.controlAdjustEventLogSeverity", "event log severity thinner"),
    "control_any_per_second_event_enabled": ("D3", "ControlParityElevationTest + ControlEvents.controlAnyPerSecondEventEnabled", "per second events thinner"),
    "control_auth_free_all": ("D3", "ControlParityElevationTest + ControlAuth.controlAuthFreeAll", "control auth free thinner"),
    "control_cmd_args_free_": ("D3", "ControlParityElevationTest + ControlCmd.controlCmdArgsFree_", "cmd args free thinner"),
    "control_cmd_args_wipe": ("D3", "ControlParityElevationTest + ControlCmd.controlCmdArgsWipe", "cmd args wipe thinner"),
    "control_cmd_free_all": ("D3", "ControlParityElevationTest + ControlCmd.controlCmdFreeAll", "cmd free all thinner"),
    "control_cmd_parse_args": ("D3", "ControlParityElevationTest + ControlCmd.controlCmdParseArgs", "cmd parse args thinner"),
    "control_connection_add_local_fd": ("D3", "ControlParityElevationTest + Control.controlConnectionAddLocalFd", "add local fd thinner"),
    "control_event_address_mapped": ("D3", "ControlParityElevationTest + ControlEvents.controlEventAddressMapped", "addr map event thinner"),
    "control_event_bandwidth_used": ("D3", "ControlParityElevationTest + ControlEvents.controlEventBandwidthUsed", "bw event thinner"),
    "control_event_boot_dir": ("D3", "ControlParityElevationTest + ControlEvents.controlEventBootDir", "boot dir event thinner"),
    "control_event_boot_first_orconn": ("D3", "ControlParityElevationTest + ControlEvents.controlEventBootFirstOrconn", "boot first orconn thinner"),
    "control_event_boot_last_msg": ("D3", "ControlParityElevationTest + ControlEvents.controlEventBootLastMsg", "boot last msg thinner"),
    "control_event_bootstrap": ("D3", "ControlParityElevationTest + ControlEvents.controlEventBootstrap", "bootstrap event thinner"),
    "control_event_bootstrap_problem": ("D3", "ControlParityElevationTest + ControlEvents.controlEventBootstrapProblem", "bootstrap problem thinner"),
    "control_event_bootstrap_reset": ("D3", "ControlParityElevationTest + ControlEvents.controlEventBootstrapReset", "bootstrap reset thinner"),
    "control_event_buildtimeout_set": ("D3", "ControlParityElevationTest + ControlEvents.controlEventBuildtimeoutSet", "buildtimeout set thinner"),
    "control_event_circ_bandwidth_used": ("D3", "ControlParityElevationTest + ControlEvents.controlEventCircBandwidthUsed", "circ bw thinner"),
    "control_event_circ_bandwidth_used_for_circ": ("D3", "ControlParityElevationTest + ControlEvents.controlEventCircBandwidthUsedForCirc", "circ bw for circ thinner"),
    "control_event_circuit_cannibalized": ("D3", "ControlParityElevationTest + ControlEvents.controlEventCircuitCannibalized", "circ cannibalized thinner"),
    "control_event_circuit_cell_stats": ("D3", "ControlParityElevationTest + ControlEvents.controlEventCircuitCellStats", "circ cell stats thinner"),
    "control_event_circuit_purpose_changed": ("D3", "ControlParityElevationTest + ControlEvents.controlEventCircuitPurposeChanged", "circ purpose thinner"),
    "control_event_circuit_status": ("D3", "ControlParityElevationTest + ControlEvents.controlEventCircuitStatus", "circ status thinner"),
    "control_event_client_error": ("D3", "ControlParityElevationTest + ControlEvents.controlEventClientError", "client error thinner"),
    "control_event_client_status": ("D3", "ControlParityElevationTest + ControlEvents.controlEventClientStatus", "client status thinner"),
    "control_event_clients_seen": ("D3", "ControlParityElevationTest + ControlEvents.controlEventClientsSeen", "clients seen thinner"),
    "control_event_conf_changed": ("D3", "ControlParityElevationTest + ControlEvents.controlEventConfChanged", "conf changed thinner"),
    "control_event_conn_bandwidth": ("D3", "ControlParityElevationTest + ControlEvents.controlEventConnBandwidth", "conn bw thinner"),
    "control_event_conn_bandwidth_used": ("D3", "ControlParityElevationTest + ControlEvents.controlEventConnBandwidthUsed", "conn bw used thinner"),
    "control_free_all": ("D3", "ControlParityElevationTest + Control.controlFreeAll", "control free all thinner"),
    "control_ports_write_to_file": ("D3", "ControlParityElevationTest + Control.controlPortsWriteToFile", "control ports file thinner"),
    "control_printf_datareply": ("D3", "ControlParityElevationTest + ControlProto.controlPrintfDatareply", "printf datareply thinner"),
    "control_printf_endreply": ("D3", "ControlParityElevationTest + ControlProto.controlPrintfEndreply", "printf endreply thinner"),
    "control_printf_midreply": ("D3", "ControlParityElevationTest + ControlProto.controlPrintfMidreply", "printf midreply thinner"),
    "control_remove_authenticated_connection": ("D3", "ControlParityElevationTest + Control.controlRemoveAuthenticatedConnection", "remove auth conn thinner"),
    "control_reply_add_done": ("D3", "ControlParityElevationTest + ControlProto.controlReplyAddDone", "reply add done thinner"),
    "control_reply_add_one_kv": ("D3", "ControlParityElevationTest + ControlProto.controlReplyAddOneKv", "reply add kv thinner"),
    "control_reply_add_printf": ("D3", "ControlParityElevationTest + ControlProto.controlReplyAddPrintf", "reply add printf thinner"),
    "control_reply_add_str": ("D3", "ControlParityElevationTest + ControlProto.controlReplyAddStr", "reply add str thinner"),
    # feature/control remaining reply/write/getinfo/handle batch
    "control_reply_append_kv": ("D3", "ControlParityElevationTest + ControlProto.controlReplyAppendKv", "reply append kv thinner"),
    "control_reply_clear": ("D3", "ControlParityElevationTest + ControlProto.controlReplyClear", "reply clear thinner"),
    "control_reply_free_": ("D3", "ControlParityElevationTest + ControlProto.controlReplyFree_", "reply free thinner"),
    "control_reply_line_free_": ("D3", "ControlParityElevationTest + ControlProto.controlReplyLineFree_", "reply line free thinner"),
    "control_split_incoming_command": ("D3", "ControlParityElevationTest + ControlProto.controlSplitIncomingCommand", "split command thinner"),
    "control_vprintf_reply": ("D3", "ControlParityElevationTest + ControlProto.controlVprintfReply", "vprintf reply thinner"),
    "control_write_data": ("D3", "ControlParityElevationTest + ControlProto.controlWriteData", "write data thinner"),
    "control_write_datareply": ("D3", "ControlParityElevationTest + ControlProto.controlWriteDatareply", "write datareply thinner"),
    "control_write_endreply": ("D3", "ControlParityElevationTest + ControlProto.controlWriteEndreply", "write endreply thinner"),
    "control_write_midreply": ("D3", "ControlParityElevationTest + ControlProto.controlWriteMidreply", "write midreply thinner"),
    "control_write_reply_line": ("D3", "ControlParityElevationTest + ControlProto.controlWriteReplyLine", "write reply line thinner"),
    "control_write_reply_lines": ("D3", "ControlParityElevationTest + ControlProto.controlWriteReplyLines", "write reply lines thinner"),
    "decode_hashed_passwords": ("D3", "ControlParityElevationTest + ControlAuth.decodeHashedPasswords", "decode hashed pw thinner"),
    "disable_control_logging": ("D3", "ControlParityElevationTest + Control.disableControlLogging", "disable logging thinner"),
    "enable_control_logging": ("D3", "ControlParityElevationTest + Control.enableControlLogging", "enable logging thinner"),
    "entry_connection_describe_status_for_controller": ("D3", "ControlParityElevationTest + Control.entryConnectionDescribeStatusForController", "entry conn describe thinner"),
    "get_cached_network_liveness": ("D3", "ControlParityElevationTest + ControlGetinfo.getCachedNetworkLiveness", "network liveness thinner"),
    "get_controller_cookie_file_name": ("D3", "ControlParityElevationTest + ControlGetinfo.getControllerCookieFileName", "cookie file name thinner"),
    "get_detached_onion_services": ("D3", "ControlParityElevationTest + ControlGetinfo.getDetachedOnionServices", "detached onions thinner"),
    "getinfo_helper_current_consensus": ("D3", "ControlParityElevationTest + ControlGetinfo.getinfoHelperCurrentConsensus", "getinfo consensus thinner"),
    "getinfo_helper_current_time": ("D3", "ControlParityElevationTest + ControlGetinfo.getinfoHelperCurrentTime", "getinfo time thinner"),
    "getinfo_helper_dir": ("D3", "ControlParityElevationTest + ControlGetinfo.getinfoHelperDir", "getinfo dir thinner"),
    "getinfo_helper_downloads": ("D3", "ControlParityElevationTest + ControlGetinfo.getinfoHelperDownloads", "getinfo downloads thinner"),
    "getinfo_helper_downloads_bridge": ("D3", "ControlParityElevationTest + ControlGetinfo.getinfoHelperDownloadsBridge", "getinfo dl bridge thinner"),
    "getinfo_helper_downloads_cert": ("D3", "ControlParityElevationTest + ControlGetinfo.getinfoHelperDownloadsCert", "getinfo dl cert thinner"),
    "getinfo_helper_downloads_desc": ("D3", "ControlParityElevationTest + ControlGetinfo.getinfoHelperDownloadsDesc", "getinfo dl desc thinner"),
    "getinfo_helper_downloads_networkstatus": ("D3", "ControlParityElevationTest + ControlGetinfo.getinfoHelperDownloadsNetworkstatus", "getinfo dl ns thinner"),
    "getinfo_helper_geoip": ("D3", "ControlParityElevationTest + ControlGetinfo.getinfoHelperGeoip", "getinfo geoip thinner"),
    "getinfo_helper_onions": ("D3", "ControlParityElevationTest + ControlGetinfo.getinfoHelperOnions", "getinfo onions thinner"),
    "getinfo_helper_rephist": ("D3", "ControlParityElevationTest + ControlGetinfo.getinfoHelperRephist", "getinfo rephist thinner"),
    "handle_control_authchallenge": ("D3", "ControlParityElevationTest + ControlAuth.handleControlAuthchallenge", "handle authchallenge thinner"),
    "handle_control_authenticate": ("D3", "ControlParityElevationTest + ControlAuth.handleControlAuthenticate", "handle authenticate thinner"),
    "handle_control_command": ("D3", "ControlParityElevationTest + ControlCmd.handleControlCommand", "handle command thinner"),
    "handle_control_getinfo": ("D3", "ControlParityElevationTest + ControlCmd.handleControlGetinfo", "handle getinfo thinner"),
    "handle_control_onion_client_auth_add": ("D3", "ControlParityElevationTest + ControlCmd.handleControlOnionClientAuthAdd", "onion auth add thinner"),
    "handle_control_onion_client_auth_remove": ("D3", "ControlParityElevationTest + ControlCmd.handleControlOnionClientAuthRemove", "onion auth remove thinner"),
    "handle_control_onion_client_auth_view": ("D3", "ControlParityElevationTest + ControlCmd.handleControlOnionClientAuthView", "onion auth view thinner"),
    "init_control_cookie_authentication": ("D3", "ControlParityElevationTest + ControlAuth.initControlCookieAuthentication", "init cookie auth thinner"),
    "monitor_owning_controller_process": ("D3", "ControlParityElevationTest + Control.monitorOwningControllerProcess", "monitor owning thinner"),
    "orconn_target_get_name": ("D3", "ControlParityElevationTest + Control.orconnTargetGetName", "orconn target name thinner"),
    "read_escaped_data": ("D3", "ControlParityElevationTest + ControlProto.readEscapedData", "read escaped thinner"),
    "rend_auth_type_to_string": ("D3", "ControlParityElevationTest + ControlEvents.rendAuthTypeToString", "rend auth type thinner"),
    "send_control_done": ("D3", "ControlParityElevationTest + ControlProto.sendControlDone", "send control done thinner"),
    "set_cached_network_liveness": ("D3", "ControlParityElevationTest + ControlGetinfo.setCachedNetworkLiveness", "set liveness thinner"),
    "write_escaped_data": ("D3", "ControlParityElevationTest + ControlProto.writeEscapedData", "write escaped thinner"),
    "write_stream_target_to_buf": ("D3", "ControlParityElevationTest + ControlFmt.writeStreamTargetToBuf", "stream target buf thinner"),
    # feature/dirauth process_descs + shared_random head
    "add_ed25519_to_dir": ("D3", "DirAuthElevationTest + ProcessDescs.addEd25519ToDir", "add ed25519 dir thinner"),
    "add_rsa_fingerprint_to_dir": ("D3", "DirAuthElevationTest + ProcessDescs.addRsaFingerprintToDir", "add rsa fp dir thinner"),
    "authdir_init_fingerprint_list": ("D3", "DirAuthElevationTest + ProcessDescs.authdirInitFingerprintList", "authdir init fp thinner"),
    "authdir_return_fingerprint_list": ("D3", "DirAuthElevationTest + ProcessDescs.authdirReturnFingerprintList", "authdir return fp thinner"),
    "authdir_wants_to_reject_router": ("D3", "DirAuthElevationTest + ProcessDescs.authdirWantsToRejectRouter", "authdir reject router thinner"),
    "commit_decode": ("D3", "DirAuthElevationTest + SharedRandom.commitDecode", "commit decode thinner"),
    "commit_encode": ("D3", "DirAuthElevationTest + SharedRandom.commitEncode", "commit encode thinner"),
    "commit_has_reveal_value": ("D3", "DirAuthElevationTest + SharedRandom.commitHasRevealValue", "commit has reveal thinner"),
    "commit_is_authoritative": ("D3", "DirAuthElevationTest + SharedRandom.commitIsAuthoritative", "commit authoritative thinner"),
    "commitments_are_the_same": ("D3", "DirAuthElevationTest + SharedRandom.commitmentsAreTheSame", "commitments same thinner"),
    # feature/dirauth vote/bridge/collate/sched/bwauth batch
    "authority_cert_dup": ("D3", "DirAuthElevationTest + DirVote.authorityCertDup", "authority cert dup thinner"),
    "bridgeauth_dump_bridge_status_to_file": ("D3", "DirAuthElevationTest + BridgeAuth.bridgeauthDumpBridgeStatusToFile", "bridgeauth dump thinner"),
    "compare_routerinfo_by_ipv4": ("D3", "DirAuthElevationTest + DirVote.compareRouterinfoByIpv4", "compare ri ipv4 thinner"),
    "compare_routerinfo_by_ipv6": ("D3", "DirAuthElevationTest + DirVote.compareRouterinfoByIpv6", "compare ri ipv6 thinner"),
    "compare_routerinfo_usefulness": ("D3", "DirAuthElevationTest + DirVote.compareRouterinfoUsefulness", "compare ri useful thinner"),
    "compute_consensus_package_lines": ("D3", "DirAuthElevationTest + DirVote.computeConsensusPackageLines", "consensus package thinner"),
    "dirauth_get_options": ("D3", "DirAuthElevationTest + DirAuthSys.dirauthGetOptions", "dirauth get options thinner"),
    "dirauth_register_periodic_events": ("D3", "DirAuthElevationTest + DirAuthPeriodic.dirauthRegisterPeriodicEvents", "dirauth register periodic thinner"),
    "dirauth_sched_get_configured_interval": ("D3", "DirAuthElevationTest + VotingSchedule.dirauthSchedGetConfiguredInterval", "sched interval thinner"),
    "dirauth_sched_get_cur_valid_after_time": ("D3", "DirAuthElevationTest + VotingSchedule.dirauthSchedGetCurValidAfterTime", "sched cur valid after thinner"),
    "dirauth_sched_get_next_valid_after_time": ("D3", "DirAuthElevationTest + VotingSchedule.dirauthSchedGetNextValidAfterTime", "sched next valid after thinner"),
    "dirauth_sched_recalculate_timing": ("D3", "DirAuthElevationTest + VotingSchedule.dirauthSchedRecalculateTiming", "sched recalculate thinner"),
    "dirauth_set_options": ("D3", "DirAuthElevationTest + DirAuthSys.dirauthSetOptions", "dirauth set options thinner"),
    "dirauth_set_routerstatus_from_routerinfo": ("D3", "DirAuthElevationTest + VoteFlags.dirauthSetRouterstatusFromRouterinfo", "set routerstatus thinner"),
    "dirauth_should_reject_requests_under_load": ("D3", "DirAuthElevationTest + DirAuthConfig.dirauthShouldRejectRequestsUnderLoad", "reject under load thinner"),
    "dircollator_add_vote": ("D3", "DirAuthElevationTest + DirCollate.dircollatorAddVote", "dircollator add vote thinner"),
    "dircollator_collate": ("D3", "DirAuthElevationTest + DirCollate.dircollatorCollate", "dircollator collate thinner"),
    "dircollator_free_": ("D3", "DirAuthElevationTest + DirCollate.dircollatorFree_", "dircollator free thinner"),
    "dircollator_get_votes_for_router": ("D3", "DirAuthElevationTest + DirCollate.dircollatorGetVotesForRouter", "dircollator get votes thinner"),
    "dircollator_n_routers": ("D3", "DirAuthElevationTest + DirCollate.dircollatorNRouters", "dircollator n routers thinner"),
    "dircollator_new": ("D3", "DirAuthElevationTest + DirCollate.dircollatorNew", "dircollator new thinner"),
    "dirserv_add_descriptor": ("D3", "DirAuthElevationTest + ProcessDescs.dirservAddDescriptor", "dirserv add desc thinner"),
    "dirserv_add_multiple_descriptors": ("D3", "DirAuthElevationTest + ProcessDescs.dirservAddMultipleDescriptors", "dirserv add multiple thinner"),
    "dirserv_add_own_fingerprint": ("D3", "DirAuthElevationTest + ProcessDescs.dirservAddOwnFingerprint", "dirserv add own fp thinner"),
    "dirserv_cache_measured_bw": ("D3", "DirAuthElevationTest + BwAuth.dirservCacheMeasuredBw", "cache measured bw thinner"),
    "dirserv_clear_measured_bw_cache": ("D3", "DirAuthElevationTest + BwAuth.dirservClearMeasuredBwCache", "clear measured bw thinner"),
    "dirserv_compute_bridge_flag_thresholds": ("D3", "DirAuthElevationTest + VoteFlags.dirservComputeBridgeFlagThresholds", "bridge flag thresh thinner"),
    "dirserv_compute_performance_thresholds": ("D3", "DirAuthElevationTest + VoteFlags.dirservComputePerformanceThresholds", "perf thresh thinner"),
    "dirserv_count_measured_bws": ("D3", "DirAuthElevationTest + BwAuth.dirservCountMeasuredBws", "count measured bw thinner"),
    "dirserv_expire_measured_bw_cache": ("D3", "DirAuthElevationTest + BwAuth.dirservExpireMeasuredBwCache", "expire measured bw thinner"),
    "dirserv_free_fingerprint_list": ("D3", "DirAuthElevationTest + ProcessDescs.dirservFreeFingerprintList", "free fp list thinner"),
    "dirserv_generate_networkstatus_vote_obj": ("D3", "DirAuthElevationTest + DirVote.dirservGenerateNetworkstatusVoteObj", "generate vote obj thinner"),
    "dirserv_get_credible_bandwidth_kb": ("D3", "DirAuthElevationTest + BwAuth.dirservGetCredibleBandwidthKb", "credible bw thinner"),
    "dirserv_get_flag_thresholds_line": ("D3", "DirAuthElevationTest + VoteFlags.dirservGetFlagThresholdsLine", "flag thresh line thinner"),
    "dirserv_get_last_n_measured_bws": ("D3", "DirAuthElevationTest + BwAuth.dirservGetLastNMeasuredBws", "last n measured thinner"),
    "dirserv_get_measured_bw_cache_size": ("D3", "DirAuthElevationTest + BwAuth.dirservGetMeasuredBwCacheSize", "measured bw cache size thinner"),
    "dirserv_has_measured_bw": ("D3", "DirAuthElevationTest + BwAuth.dirservHasMeasuredBw", "has measured bw thinner"),
    "dirserv_load_fingerprint_file": ("D3", "DirAuthElevationTest + ProcessDescs.dirservLoadFingerprintFile", "load fp file thinner"),
    "dirserv_orconn_tls_done": ("D3", "DirAuthElevationTest + Reachability.dirservOrconnTlsDone", "orconn tls done thinner"),
    "dirserv_query_measured_bw_cache_kb": ("D3", "DirAuthElevationTest + BwAuth.dirservQueryMeasuredBwCacheKb", "query measured bw thinner"),
    "dirserv_read_guardfraction_file": ("D3", "DirAuthElevationTest + GuardFraction.dirservReadGuardfractionFile", "read guardfraction thinner"),
    "dirserv_read_guardfraction_file_from_str": ("D3", "DirAuthElevationTest + GuardFraction.dirservReadGuardfractionFileFromStr", "read guardfraction str thinner"),
    "dirserv_read_measured_bandwidths": ("D3", "DirAuthElevationTest + BwAuth.dirservReadMeasuredBandwidths", "read measured bws thinner"),
    "dirserv_rejects_tor_version": ("D3", "DirAuthElevationTest + ProcessDescs.dirservRejectsTorVersion", "rejects tor version thinner"),
    "dirserv_router_get_status": ("D3", "DirAuthElevationTest + ProcessDescs.dirservRouterGetStatus", "router get status thinner"),
    "dirserv_router_has_valid_address": ("D3", "DirAuthElevationTest + ProcessDescs.dirservRouterHasValidAddress", "router valid addr thinner"),
    "dirserv_set_bridges_running": ("D3", "DirAuthElevationTest + VoteFlags.dirservSetBridgesRunning", "set bridges running thinner"),
    "dirserv_set_node_flags_from_authoritative_status": ("D3", "DirAuthElevationTest + ProcessDescs.dirservSetNodeFlagsFromAuthoritativeStatus", "set node flags thinner"),
    "dirserv_set_router_is_running": ("D3", "DirAuthElevationTest + VoteFlags.dirservSetRouterIsRunning", "set router running thinner"),
    "dirserv_set_routerstatus_testing": ("D3", "DirAuthElevationTest + VoteFlags.dirservSetRouterstatusTesting", "set routerstatus testing thinner"),
    "dirserv_should_launch_reachability_test": ("D3", "DirAuthElevationTest + Reachability.dirservShouldLaunchReachabilityTest", "should launch reach thinner"),
    "dirserv_single_reachability_test": ("D3", "DirAuthElevationTest + Reachability.dirservSingleReachabilityTest", "single reach test thinner"),
    "dirserv_test_reachability": ("D3", "DirAuthElevationTest + Reachability.dirservTestReachability", "test reachability thinner"),
    "dirserv_would_reject_router": ("D3", "DirAuthElevationTest + ProcessDescs.dirservWouldRejectRouter", "would reject router thinner"),
    "dirvote_act": ("D3", "DirAuthElevationTest + DirVote.dirvoteAct", "dirvote act thinner"),
    "dirvote_add_signatures": ("D3", "DirAuthElevationTest + DirVote.dirvoteAddSignatures", "dirvote add sigs thinner"),
    "dirvote_add_vote": ("D3", "DirAuthElevationTest + DirVote.dirvoteAddVote", "dirvote add vote thinner"),
    "dirvote_clear_commits": ("D3", "DirAuthElevationTest + DirVote.dirvoteClearCommits", "dirvote clear commits thinner"),
    "dirvote_compute_params": ("D3", "DirAuthElevationTest + DirVote.dirvoteComputeParams", "dirvote compute params thinner"),
    "dirvote_create_microdescriptor": ("D3", "DirAuthElevationTest + DirVote.dirvoteCreateMicrodescriptor", "dirvote create microdesc thinner"),
    "dirvote_dirreq_get_status_vote": ("D3", "DirAuthElevationTest + DirVote.dirvoteDirreqGetStatusVote", "dirvote dirreq status thinner"),
    "dirvote_format_all_microdesc_vote_lines": ("D3", "DirAuthElevationTest + DirVote.dirvoteFormatAllMicrodescVoteLines", "dirvote microdesc lines thinner"),
    "dirvote_free_all": ("D3", "DirAuthElevationTest + DirVote.dirvoteFreeAll", "dirvote free all thinner"),
    "dirvote_get_intermediate_param_value": ("D3", "DirAuthElevationTest + DirVote.dirvoteGetIntermediateParamValue", "dirvote intermediate param thinner"),
    "dirvote_get_vote": ("D3", "DirAuthElevationTest + DirVote.dirvoteGetVote", "dirvote get vote thinner"),
    "dirvote_parse_sr_commits": ("D3", "DirAuthElevationTest + DirVote.dirvoteParseSrCommits", "dirvote parse sr thinner"),
    "disk_state_load_from_disk_impl": ("D3", "DirAuthElevationTest + SharedRandomState.diskStateLoadFromDiskImpl", "disk state load thinner"),
    "format_networkstatus_vote": ("D3", "DirAuthElevationTest + DirVote.formatNetworkstatusVote", "format ns vote thinner"),
    "format_recommended_version_list": ("D3", "DirAuthElevationTest + DirVote.formatRecommendedVersionList", "format recommended versions thinner"),
    "get_all_possible_sybil": ("D3", "DirAuthElevationTest + DirVote.getAllPossibleSybil", "get all sybil thinner"),
    "get_majority_srv_from_votes": ("D3", "DirAuthElevationTest + SharedRandom.getMajoritySrvFromVotes", "majority srv thinner"),
    "get_phase_str": ("D3", "DirAuthElevationTest + SharedRandomState.getPhaseStr", "get phase str thinner"),
    "get_sr_protocol_phase": ("D3", "DirAuthElevationTest + SharedRandomState.getSrProtocolPhase", "get sr phase thinner"),
    "get_sr_state": ("D3", "DirAuthElevationTest + SharedRandomState.getSrState", "get sr state thinner"),
    "get_state_valid_until_time": ("D3", "DirAuthElevationTest + SharedRandomState.getStateValidUntilTime", "get valid until thinner"),
    "get_sybil_list_by_ip_version": ("D3", "DirAuthElevationTest + DirVote.getSybilListByIpVersion", "sybil by ip thinner"),
    "is_phase_transition": ("D3", "DirAuthElevationTest + SharedRandomState.isPhaseTransition", "phase transition thinner"),
    "keypin_check": ("D3", "DirAuthElevationTest + Keypin.keypinCheck", "keypin check thinner"),
    "keypin_check_and_add": ("D3", "DirAuthElevationTest + Keypin.keypinCheckAndAdd", "keypin check and add thinner"),
    "keypin_check_lone_rsa": ("D3", "DirAuthElevationTest + Keypin.keypinCheckLoneRsa", "keypin lone rsa thinner"),
    "keypin_clear": ("D3", "DirAuthElevationTest + Keypin.keypinClear", "keypin clear thinner"),
    "keypin_close_journal": ("D3", "DirAuthElevationTest + Keypin.keypinCloseJournal", "keypin close thinner"),
    "keypin_load_journal": ("D3", "DirAuthElevationTest + Keypin.keypinLoadJournal", "keypin load journal thinner"),
    "keypin_load_journal_impl": ("D3", "DirAuthElevationTest + Keypin.keypinLoadJournalImpl", "keypin load journal impl thinner"),
    "keypin_open_journal": ("D3", "DirAuthElevationTest + Keypin.keypinOpenJournal", "keypin open journal thinner"),
    "keypin_parse_journal_line": ("D3", "DirAuthElevationTest + Keypin.keypinParseJournalLine", "keypin parse line thinner"),
    "make_consensus_method_list": ("D3", "DirAuthElevationTest + DirVote.makeConsensusMethodList", "consensus method list thinner"),
    "measured_bw_line_apply": ("D3", "DirAuthElevationTest + BwAuth.measuredBwLineApply", "measured bw apply thinner"),
    "measured_bw_line_parse": ("D3", "DirAuthElevationTest + BwAuth.measuredBwLineParse", "measured bw parse thinner"),
    "networkstatus_add_detached_signatures": ("D3", "DirAuthElevationTest + DirVote.networkstatusAddDetachedSignatures", "ns add detached thinner"),
    "networkstatus_compute_bw_weights_v10": ("D3", "DirAuthElevationTest + DirVote.networkstatusComputeBwWeightsV10", "bw weights v10 thinner"),
    "networkstatus_parse_detached_signatures": ("D3", "DirAuthElevationTest + DsigsParse.networkstatusParseDetachedSignatures", "parse detached thinner"),
    "new_protocol_run": ("D3", "DirAuthElevationTest + SharedRandomState.newProtocolRun", "new protocol run thinner"),
    "ns_detached_signatures_free_": ("D3", "DirAuthElevationTest + DsigsParse.nsDetachedSignaturesFree_", "ns detached free thinner"),
    "options_act_dirauth": ("D3", "DirAuthElevationTest + DirAuthConfig.optionsActDirauth", "options act dirauth thinner"),
    "options_act_dirauth_mtbf": ("D3", "DirAuthElevationTest + DirAuthConfig.optionsActDirauthMtbf", "options act mtbf thinner"),
    "options_act_dirauth_stats": ("D3", "DirAuthElevationTest + DirAuthConfig.optionsActDirauthStats", "options act stats thinner"),
    "options_validate_dirauth_mode": ("D3", "DirAuthElevationTest + DirAuthConfig.optionsValidateDirauthMode", "validate dirauth mode thinner"),
    "options_validate_dirauth_schedule": ("D3", "DirAuthElevationTest + DirAuthConfig.optionsValidateDirauthSchedule", "validate schedule thinner"),
    "options_validate_dirauth_testing": ("D3", "DirAuthElevationTest + DirAuthConfig.optionsValidateDirauthTesting", "validate testing thinner"),
    "reschedule_dirvote": ("D3", "DirAuthElevationTest + DirAuthPeriodic.rescheduleDirvote", "reschedule dirvote thinner"),
    "reset_state_for_new_protocol_run": ("D3", "DirAuthElevationTest + SharedRandomState.resetStateForNewProtocolRun", "reset protocol run thinner"),
    "reveal_decode": ("D3", "DirAuthElevationTest + SharedRandom.revealDecode", "reveal decode thinner"),
    "reveal_encode": ("D3", "DirAuthElevationTest + SharedRandom.revealEncode", "reveal encode thinner"),
    "running_long_enough_to_decide_unreachable": ("D3", "DirAuthElevationTest + VoteFlags.runningLongEnoughToDecideUnreachable", "running long enough thinner"),
    "save_commit_during_reveal_phase": ("D3", "DirAuthElevationTest + SharedRandom.saveCommitDuringRevealPhase", "save commit reveal thinner"),
    "save_commit_to_state": ("D3", "DirAuthElevationTest + SharedRandom.saveCommitToState", "save commit state thinner"),
    "set_num_srv_agreements": ("D3", "DirAuthElevationTest + SharedRandom.setNumSrvAgreements", "set srv agreements thinner"),
    "set_sr_phase": ("D3", "DirAuthElevationTest + SharedRandomState.setSrPhase", "set sr phase thinner"),
    "should_keep_commit": ("D3", "DirAuthElevationTest + SharedRandom.shouldKeepCommit", "should keep commit thinner"),
    "sr_act_post_consensus": ("D3", "DirAuthElevationTest + SharedRandom.srActPostConsensus", "sr act post consensus thinner"),
    "sr_commit_free_": ("D3", "DirAuthElevationTest + SharedRandom.srCommitFree_", "sr commit free thinner"),
    "sr_compute_srv": ("D3", "DirAuthElevationTest + SharedRandom.srComputeSrv", "sr compute srv thinner"),
    "sr_generate_our_commit": ("D3", "DirAuthElevationTest + SharedRandom.srGenerateOurCommit", "sr generate commit thinner"),
    "sr_get_string_for_consensus": ("D3", "DirAuthElevationTest + SharedRandom.srGetStringForConsensus", "sr string consensus thinner"),
    "sr_get_string_for_vote": ("D3", "DirAuthElevationTest + SharedRandom.srGetStringForVote", "sr string vote thinner"),
    "sr_handle_received_commits": ("D3", "DirAuthElevationTest + SharedRandom.srHandleReceivedCommits", "sr handle commits thinner"),
    "sr_init": ("D3", "DirAuthElevationTest + SharedRandom.srInit", "sr init thinner"),
    "sr_parse_commit": ("D3", "DirAuthElevationTest + SharedRandom.srParseCommit", "sr parse commit thinner"),
    "sr_save_and_cleanup": ("D3", "DirAuthElevationTest + SharedRandom.srSaveAndCleanup", "sr save cleanup thinner"),
    "sr_srv_dup": ("D3", "DirAuthElevationTest + SharedRandom.srSrvDup", "sr srv dup thinner"),
    "sr_state_add_commit": ("D3", "DirAuthElevationTest + SharedRandomState.srStateAddCommit", "sr state add commit thinner"),
    "sr_state_clean_srvs": ("D3", "DirAuthElevationTest + SharedRandomState.srStateCleanSrvs", "sr state clean thinner"),
    "sr_state_copy_reveal_info": ("D3", "DirAuthElevationTest + SharedRandomState.srStateCopyRevealInfo", "sr state copy reveal thinner"),
    "sr_state_delete_commits": ("D3", "DirAuthElevationTest + SharedRandomState.srStateDeleteCommits", "sr state delete thinner"),
    "sr_state_free_all": ("D3", "DirAuthElevationTest + SharedRandomState.srStateFreeAll", "sr state free all thinner"),
    "sr_state_get_commit": ("D3", "DirAuthElevationTest + SharedRandomState.srStateGetCommit", "sr state get commit thinner"),
    "sr_state_get_commits": ("D3", "DirAuthElevationTest + SharedRandomState.srStateGetCommits", "sr state get commits thinner"),
    "sr_state_get_current_srv": ("D3", "DirAuthElevationTest + SharedRandomState.srStateGetCurrentSrv", "sr state get current thinner"),
    "sr_state_get_phase": ("D3", "DirAuthElevationTest + SharedRandomState.srStateGetPhase", "sr state get phase thinner"),
    "sr_state_get_previous_srv": ("D3", "DirAuthElevationTest + SharedRandomState.srStateGetPreviousSrv", "sr state get previous thinner"),
    "sr_state_init": ("D3", "DirAuthElevationTest + SharedRandomState.srStateInit", "sr state init thinner"),
    "sr_state_is_initialized": ("D3", "DirAuthElevationTest + SharedRandomState.srStateIsInitialized", "sr state is init thinner"),
    "sr_state_save": ("D3", "DirAuthElevationTest + SharedRandomState.srStateSave", "sr state save thinner"),
    "sr_state_set_current_srv": ("D3", "DirAuthElevationTest + SharedRandomState.srStateSetCurrentSrv", "sr state set current thinner"),
    "sr_state_set_fresh_srv": ("D3", "DirAuthElevationTest + SharedRandomState.srStateSetFreshSrv", "sr state set fresh thinner"),
    "sr_state_set_previous_srv": ("D3", "DirAuthElevationTest + SharedRandomState.srStateSetPreviousSrv", "sr state set previous thinner"),
    "validate_recommended_package_line": ("D3", "DirAuthElevationTest + RecommendPkg.validateRecommendedPackageLine", "validate package line thinner"),
    "verify_commit_and_reveal": ("D3", "DirAuthElevationTest + SharedRandom.verifyCommitAndReveal", "verify commit reveal thinner"),
    # feature/hs head batch
    "auth_key_filename_is_valid": ("D3", "HsParityElevationTest + HsClient.authKeyFilenameIsValid", "auth key filename thinner"),
    "build_all_descriptors": ("D3", "HsParityElevationTest + HsService.buildAllDescriptors", "build all descriptors thinner"),
    "build_blinded_key_param": ("D3", "HsParityElevationTest + HsCommon.buildBlindedKeyParam", "blinded key param thinner"),
    "build_establish_intro_extensions": ("D3", "HsParityElevationTest + HsCell.buildEstablishIntroExtensions", "establish intro ext thinner"),
    "build_plaintext_padding": ("D3", "HsParityElevationTest + HsDescriptor.buildPlaintextPadding", "plaintext padding thinner"),
    "cache_clean_v3_as_dir": ("D3", "HsParityElevationTest + HsCache.cacheCleanV3AsDir", "cache clean v3 dir thinner"),
    "cache_clean_v3_by_downloaded_as_dir": ("D3", "HsParityElevationTest + HsCache.cacheCleanV3ByDownloadedAsDir", "cache clean downloaded thinner"),
    "can_service_launch_intro_circuit": ("D3", "HsParityElevationTest + HsService.canServiceLaunchIntroCircuit", "can launch intro thinner"),
    "cell_dos_extension_parameters_are_valid": ("D3", "HsParityElevationTest + HsIntropoint.cellDosExtensionParametersAreValid", "cell dos params thinner"),
    "cert_is_valid": ("D3", "HsParityElevationTest + HsDescriptor.certIsValid", "cert is valid thinner"),
    "circuit_is_suitable_for_introduce1": ("D3", "HsParityElevationTest + HsIntropoint.circuitIsSuitableForIntroduce1", "circuit suitable intro1 thinner"),
    "client_filename_is_valid": ("D3", "HsParityElevationTest + HsService.clientFilenameIsValid", "client filename thinner"),
    "client_get_random_intro": ("D3", "HsParityElevationTest + HsClient.clientGetRandomIntro", "client random intro thinner"),
    "client_service_authorization_free_": ("D3", "HsParityElevationTest + HsClient.clientServiceAuthorizationFree_", "client auth free thinner"),
    "compute_subcredentials": ("D3", "HsParityElevationTest + HsOb.computeSubcredentials", "compute subcred thinner"),
    "create_rp_circuit_identifier": ("D3", "HsParityElevationTest + HsCircuit.createRpCircuitIdentifier", "rp circuit id thinner"),
    "decode_introduction_point": ("D3", "HsParityElevationTest + HsDescriptor.decodeIntroductionPoint", "decode intro point thinner"),
    "decode_link_specifiers": ("D3", "HsParityElevationTest + HsDescriptor.decodeLinkSpecifiers", "decode link specs thinner"),
    "desc_decode_encrypted_v3": ("D3", "HsParityElevationTest + HsDescriptor.descDecodeEncryptedV3", "desc decode encrypted thinner"),
    "desc_decode_superencrypted_v3": ("D3", "HsParityElevationTest + HsDescriptor.descDecodeSuperencryptedV3", "desc decode superencrypted thinner"),
    "desc_intro_point_to_extend_info": ("D3", "HsParityElevationTest + HsClient.descIntroPointToExtendInfo", "intro to extend info thinner"),
    "desc_sig_is_valid": ("D3", "HsParityElevationTest + HsDescriptor.descSigIsValid", "desc sig valid thinner"),
    "dir_set_downloaded": ("D3", "HsParityElevationTest + HsCache.dirSetDownloaded", "dir set downloaded thinner"),
    "encode_link_specifiers": ("D3", "HsParityElevationTest + HsDescriptor.encodeLinkSpecifiers", "encode link specs thinner"),
    "encrypted_data_length_is_valid": ("D3", "HsParityElevationTest + HsDescriptor.encryptedDataLengthIsValid", "encrypted len valid thinner"),
    "find_desc_intro_point_by_ident": ("D3", "HsParityElevationTest + HsClient.findDescIntroPointByIdent", "find intro by ident thinner"),
    "find_service": ("D3", "HsParityElevationTest + HsService.findService", "find service thinner"),
    "get_auth_key_from_cell": ("D3", "HsParityElevationTest + HsIntropoint.getAuthKeyFromCell", "get auth key cell thinner"),
    "get_disaster_srv": ("D3", "HsParityElevationTest + HsCommon.getDisasterSrv", "get disaster srv thinner"),
    "get_first_cached_disaster_srv": ("D3", "HsParityElevationTest + HsCommon.getFirstCachedDisasterSrv", "first disaster srv thinner"),
    "get_first_service": ("D3", "HsParityElevationTest + HsService.getFirstService", "get first service thinner"),
    "get_hs_circuitmap": ("D3", "HsParityElevationTest + HsCircuitmap.getHsCircuitmap", "get hs circuitmap thinner"),
    "get_hs_client_auths_map": ("D3", "HsParityElevationTest + HsClient.getHsClientAuthsMap", "get client auths thinner"),
    "get_hs_service_map": ("D3", "HsParityElevationTest + HsService.getHsServiceMap", "get hs service map thinner"),
    "get_hs_service_map_size": ("D3", "HsParityElevationTest + HsService.getHsServiceMapSize", "get hs service map size thinner"),
    "get_second_cached_disaster_srv": ("D3", "HsParityElevationTest + HsCommon.getSecondCachedDisasterSrv", "second disaster srv thinner"),
    "get_time_period_length": ("D3", "HsParityElevationTest + HsCommon.getTimePeriodLength", "time period length thinner"),
    "rend_pqueue_clear": ("D3", "HsParityElevationTest + HsCircuit.rendPqueueClear", "rend pqueue clear thinner"),
    "top_of_rend_pqueue_is_worthwhile": ("D3", "HsParityElevationTest + HsCircuit.topOfRendPqueueIsWorthwhile", "rend pqueue top thinner"),
    "get_hs_service_staging_list_size": ("D3", "HsParityElevationTest + HsService.getHsServiceStagingListSize", "staging list size thinner"),
    "get_intro2_burst_consensus_param": ("D3", "HsParityElevationTest + HsDos.getIntro2BurstConsensusParam", "intro2 burst param thinner"),
    "get_intro2_enable_consensus_param": ("D3", "HsParityElevationTest + HsDos.getIntro2EnableConsensusParam", "intro2 enable param thinner"),
    "get_intro2_rate_consensus_param": ("D3", "HsParityElevationTest + HsDos.getIntro2RateConsensusParam", "intro2 rate param thinner"),
    "get_last_hid_serv_requests": ("D3", "HsParityElevationTest + HsCommon.getLastHidServRequests", "last hid serv requests thinner"),
    "get_node_from_intro_point": ("D3", "HsParityElevationTest + HsService.getNodeFromIntroPoint", "node from intro thinner"),
    "get_objects_from_ident": ("D3", "HsParityElevationTest + HsService.getObjectsFromIdent", "objects from ident thinner"),
    "handle_introduce1": ("D3", "HsParityElevationTest + HsIntropoint.handleIntroduce1", "handle introduce1 thinner"),
    "handle_rendezvous2": ("D3", "HsParityElevationTest + HsClient.handleRendezvous2", "handle rendezvous2 thinner"),
    "hs_address_is_valid": ("D3", "HsParityElevationTest + HsCommon.hsAddressIsValid", "hs address valid thinner"),
    "hs_build_address": ("D3", "HsParityElevationTest + HsCommon.hsBuildAddress", "hs build address thinner"),
    "hs_build_blinded_keypair": ("D3", "HsParityElevationTest + HsCommon.hsBuildBlindedKeypair", "hs build blinded keypair thinner"),
    "hs_build_blinded_pubkey": ("D3", "HsParityElevationTest + HsCommon.hsBuildBlindedPubkey", "hs build blinded pubkey thinner"),
    "hs_build_hs_index": ("D3", "HsParityElevationTest + HsCommon.hsBuildHsIndex", "hs build hs index thinner"),
    "hs_build_hsdir_index": ("D3", "HsParityElevationTest + HsCommon.hsBuildHsdirIndex", "hs build hsdir index thinner"),
    "hs_cache_clean_as_client": ("D3", "HsParityElevationTest + HsCache.hsCacheCleanAsClient", "hs cache clean client thinner"),
    "hs_cache_clean_as_dir": ("D3", "HsParityElevationTest + HsCache.hsCacheCleanAsDir", "hs cache clean dir thinner"),
    "hs_cache_client_intro_state_clean": ("D3", "HsParityElevationTest + HsCache.hsCacheClientIntroStateClean", "intro state clean thinner"),
    "hs_cache_client_intro_state_find": ("D3", "HsParityElevationTest + HsCache.hsCacheClientIntroStateFind", "intro state find thinner"),
    "hs_cache_client_intro_state_note": ("D3", "HsParityElevationTest + HsCache.hsCacheClientIntroStateNote", "intro state note thinner"),
    "hs_cache_client_intro_state_purge": ("D3", "HsParityElevationTest + HsCache.hsCacheClientIntroStatePurge", "intro state purge thinner"),
    "hs_cache_client_new_auth_parse": ("D3", "HsParityElevationTest + HsCache.hsCacheClientNewAuthParse", "new auth parse thinner"),
    "hs_cache_decrement_allocation": ("D3", "HsParityElevationTest + HsCache.hsCacheDecrementAllocation", "cache decrement thinner"),
    "hs_cache_free_all": ("D3", "HsParityElevationTest + HsCache.hsCacheFreeAll", "cache free all thinner"),
    "hs_cache_get_max_bytes": ("D3", "HsParityElevationTest + HsCache.hsCacheGetMaxBytes", "cache max bytes thinner"),
    "hs_cache_get_max_descriptor_size": ("D3", "HsParityElevationTest + HsCache.hsCacheGetMaxDescriptorSize", "cache max desc size thinner"),
    "hs_cache_get_total_allocation": ("D3", "HsParityElevationTest + HsCache.hsCacheGetTotalAllocation", "cache total alloc thinner"),
    "hs_cache_handle_oom": ("D3", "HsParityElevationTest + HsCache.hsCacheHandleOom", "cache handle oom thinner"),
    "hs_cache_increment_allocation": ("D3", "HsParityElevationTest + HsCache.hsCacheIncrementAllocation", "cache incr alloc thinner"),
    "hs_cache_init": ("D3", "HsParityElevationTest + HsCache.hsCacheInit", "cache init thinner"),
    "hs_cache_lookup_as_client": ("D3", "HsParityElevationTest + HsCache.hsCacheLookupAsClient", "cache lookup client thinner"),
    "hs_cache_lookup_as_dir": ("D3", "HsParityElevationTest + HsCache.hsCacheLookupAsDir", "cache lookup dir thinner"),
    "hs_cache_lookup_encoded_as_client": ("D3", "HsParityElevationTest + HsCache.hsCacheLookupEncodedAsClient", "cache lookup encoded thinner"),
    "hs_cache_mark_dowloaded_as_dir": ("D3", "HsParityElevationTest + HsCache.hsCacheMarkDowloadedAsDir", "cache mark downloaded thinner"),
    "hs_cache_purge_as_client": ("D3", "HsParityElevationTest + HsCache.hsCachePurgeAsClient", "cache purge client thinner"),
    "hs_cache_remove_as_client": ("D3", "HsParityElevationTest + HsCache.hsCacheRemoveAsClient", "cache remove client thinner"),
    "hs_cache_store_as_client": ("D3", "HsParityElevationTest + HsCache.hsCacheStoreAsClient", "cache store client thinner"),
    "hs_cell_build_establish_intro": ("D3", "HsParityElevationTest + HsCell.hsCellBuildEstablishIntro", "cell build establish intro thinner"),
    "hs_cell_build_establish_rendezvous": ("D3", "HsParityElevationTest + HsCell.hsCellBuildEstablishRendezvous", "cell build establish rend thinner"),
    "hs_cell_build_introduce1": ("D3", "HsParityElevationTest + HsCell.hsCellBuildIntroduce1", "cell build introduce1 thinner"),
    "hs_cell_build_rendezvous1": ("D3", "HsParityElevationTest + HsCell.hsCellBuildRendezvous1", "cell build rendezvous1 thinner"),
    "hs_cell_introduce1_data_clear": ("D3", "HsParityElevationTest + HsCell.hsCellIntroduce1DataClear", "cell intro1 clear thinner"),
    "hs_cell_parse_intro_established": ("D3", "HsParityElevationTest + HsCell.hsCellParseIntroEstablished", "cell parse intro established thinner"),
    "hs_cell_parse_introduce2": ("D3", "HsParityElevationTest + HsCell.hsCellParseIntroduce2", "cell parse introduce2 thinner"),
    "hs_cell_parse_introduce_ack": ("D3", "HsParityElevationTest + HsCell.hsCellParseIntroduceAck", "cell parse introduce ack thinner"),
    "hs_cell_parse_rendezvous2": ("D3", "HsParityElevationTest + HsCell.hsCellParseRendezvous2", "cell parse rendezvous2 thinner"),
    "hs_check_service_private_dir": ("D3", "HsParityElevationTest + HsCommon.hsCheckServicePrivateDir", "check service private dir thinner"),
    "hs_circ_cleanup_on_close": ("D3", "HsParityElevationTest + HsCircuit.hsCircCleanupOnClose", "circ cleanup close thinner"),
    "hs_circ_cleanup_on_free": ("D3", "HsParityElevationTest + HsCircuit.hsCircCleanupOnFree", "circ cleanup free thinner"),
    "hs_circ_cleanup_on_repurpose": ("D3", "HsParityElevationTest + HsCircuit.hsCircCleanupOnRepurpose", "circ cleanup repurpose thinner"),
    "hs_circ_handle_intro_established": ("D3", "HsParityElevationTest + HsCircuit.hsCircHandleIntroEstablished", "circ handle intro established thinner"),
    "hs_circ_handle_introduce2": ("D3", "HsParityElevationTest + HsCircuit.hsCircHandleIntroduce2", "circ handle introduce2 thinner"),
    "hs_circ_is_rend_sent_in_intro1": ("D3", "HsParityElevationTest + HsCircuit.hsCircIsRendSentInIntro1", "circ rend sent intro1 thinner"),
    "hs_circ_launch_intro_point": ("D3", "HsParityElevationTest + HsCircuit.hsCircLaunchIntroPoint", "circ launch intro thinner"),
    "hs_circ_launch_rendezvous_point": ("D3", "HsParityElevationTest + HsCircuit.hsCircLaunchRendezvousPoint", "circ launch rend thinner"),
    "hs_circ_retry_service_rendezvous_point": ("D3", "HsParityElevationTest + HsCircuit.hsCircRetryServiceRendezvousPoint", "circ retry rend thinner"),
    "hs_circ_send_establish_rendezvous": ("D3", "HsParityElevationTest + HsCircuit.hsCircSendEstablishRendezvous", "circ send establish rend thinner"),
    "hs_circ_send_introduce1": ("D3", "HsParityElevationTest + HsCircuit.hsCircSendIntroduce1", "circ send introduce1 thinner"),
    "hs_circ_service_get_established_intro_circ": ("D3", "HsParityElevationTest + HsCircuit.hsCircServiceGetEstablishedIntroCirc", "circ get established intro thinner"),
    "hs_circ_service_get_intro_circ": ("D3", "HsParityElevationTest + HsCircuit.hsCircServiceGetIntroCirc", "circ get intro thinner"),
    "hs_circ_service_intro_has_opened": ("D3", "HsParityElevationTest + HsCircuit.hsCircServiceIntroHasOpened", "circ intro opened thinner"),
    "hs_circ_service_rp_has_opened": ("D3", "HsParityElevationTest + HsCircuit.hsCircServiceRpHasOpened", "circ rp opened thinner"),
    "hs_circ_setup_congestion_control": ("D3", "HsParityElevationTest + HsCircuit.hsCircSetupCongestionControl", "circ setup cc thinner"),
    "hs_circuit_setup_e2e_rend_circ": ("D3", "HsParityElevationTest + HsCircuit.hsCircuitSetupE2eRendCirc", "circ setup e2e rend thinner"),
    "hs_circuit_setup_e2e_rend_circ_legacy_client": ("D3", "HsParityElevationTest + HsCircuit.hsCircuitSetupE2eRendCircLegacyClient", "circ setup e2e legacy thinner"),
    "hs_circuitmap_free_all": ("D3", "HsParityElevationTest + HsCircuitmap.hsCircuitmapFreeAll", "circuitmap free all thinner"),
    "hs_circuitmap_get_all_intro_circ_relay_side": ("D3", "HsParityElevationTest + HsCircuitmap.hsCircuitmapGetAllIntroCircRelaySide", "circuitmap all intro relay thinner"),
    "hs_circuitmap_get_established_rend_circ_client_side": ("D3", "HsParityElevationTest + HsCircuitmap.hsCircuitmapGetEstablishedRendCircClientSide", "circuitmap established rend client thinner"),
    "hs_circuitmap_get_intro_circ_v3_relay_side": ("D3", "HsParityElevationTest + HsCircuitmap.hsCircuitmapGetIntroCircV3RelaySide", "circuitmap intro relay thinner"),
    "hs_circuitmap_get_intro_circ_v3_service_side": ("D3", "HsParityElevationTest + HsCircuitmap.hsCircuitmapGetIntroCircV3ServiceSide", "circuitmap intro service thinner"),
    "hs_circuitmap_get_rend_circ_client_side": ("D3", "HsParityElevationTest + HsCircuitmap.hsCircuitmapGetRendCircClientSide", "circuitmap rend client thinner"),
    "hs_circuitmap_get_rend_circ_relay_side": ("D3", "HsParityElevationTest + HsCircuitmap.hsCircuitmapGetRendCircRelaySide", "circuitmap rend relay thinner"),
    "hs_circuitmap_get_rend_circ_service_side": ("D3", "HsParityElevationTest + HsCircuitmap.hsCircuitmapGetRendCircServiceSide", "circuitmap rend service thinner"),
    "hs_circuitmap_init": ("D3", "HsParityElevationTest + HsCircuitmap.hsCircuitmapInit", "circuitmap init thinner"),
    "hs_circuitmap_register_intro_circ_v3_relay_side": ("D3", "HsParityElevationTest + HsCircuitmap.hsCircuitmapRegisterIntroCircV3RelaySide", "circuitmap register intro relay thinner"),
    "hs_circuitmap_register_intro_circ_v3_service_side": ("D3", "HsParityElevationTest + HsCircuitmap.hsCircuitmapRegisterIntroCircV3ServiceSide", "circuitmap register intro service thinner"),
    "hs_circuitmap_register_rend_circ_client_side": ("D3", "HsParityElevationTest + HsCircuitmap.hsCircuitmapRegisterRendCircClientSide", "circuitmap register rend client thinner"),
    "hs_circuitmap_register_rend_circ_relay_side": ("D3", "HsParityElevationTest + HsCircuitmap.hsCircuitmapRegisterRendCircRelaySide", "circuitmap register rend relay thinner"),
    "hs_circuitmap_register_rend_circ_service_side": ("D3", "HsParityElevationTest + HsCircuitmap.hsCircuitmapRegisterRendCircServiceSide", "circuitmap register rend service thinner"),
    "hs_circuitmap_remove_circuit": ("D3", "HsParityElevationTest + HsCircuitmap.hsCircuitmapRemoveCircuit", "circuitmap remove thinner"),
    "hs_clean_last_hid_serv_requests": ("D3", "HsParityElevationTest + HsCommon.hsCleanLastHidServRequests", "clean last hid serv thinner"),
    "hs_cleanup_circ": ("D3", "HsParityElevationTest + HsCommon.hsCleanupCirc", "cleanup circ thinner"),
    "hs_client_any_intro_points_usable": ("D3", "HsParityElevationTest + HsClient.hsClientAnyIntroPointsUsable", "client any intro usable thinner"),
    "hs_client_circuit_cleanup_on_close": ("D3", "HsParityElevationTest + HsClient.hsClientCircuitCleanupOnClose", "client circ cleanup close thinner"),
    "hs_client_circuit_cleanup_on_free": ("D3", "HsParityElevationTest + HsClient.hsClientCircuitCleanupOnFree", "client circ cleanup free thinner"),
    "hs_client_circuit_has_opened": ("D3", "HsParityElevationTest + HsClient.hsClientCircuitHasOpened", "client circ has opened thinner"),
    "hs_client_close_intro_circuits_from_desc": ("D3", "HsParityElevationTest + HsClient.hsClientCloseIntroCircuitsFromDesc", "client close intro from desc thinner"),
    "hs_client_decode_descriptor": ("D3", "HsParityElevationTest + HsClient.hsClientDecodeDescriptor", "client decode descriptor thinner"),
    "hs_client_dir_fetch_done": ("D3", "HsParityElevationTest + HsClient.hsClientDirFetchDone", "client dir fetch done thinner"),
    "hs_client_dir_info_changed": ("D3", "HsParityElevationTest + HsClient.hsClientDirInfoChanged", "client dir info changed thinner"),
    "hs_client_free_all": ("D3", "HsParityElevationTest + HsClient.hsClientFreeAll", "client free all thinner"),
    "hs_client_get_random_intro_from_edge": ("D3", "HsParityElevationTest + HsClient.hsClientGetRandomIntroFromEdge", "client random intro edge thinner"),
    "hs_client_launch_v3_desc_fetch": ("D3", "HsParityElevationTest + HsClient.hsClientLaunchV3DescFetch", "client launch desc fetch thinner"),
    "hs_client_note_connection_attempt_succeeded": ("D3", "HsParityElevationTest + HsClient.hsClientNoteConnectionAttemptSucceeded", "client note conn success thinner"),
    "hs_client_purge_state": ("D3", "HsParityElevationTest + HsClient.hsClientPurgeState", "client purge state thinner"),
    "hs_client_receive_introduce_ack": ("D3", "HsParityElevationTest + HsClient.hsClientReceiveIntroduceAck", "client receive intro ack thinner"),
    "hs_client_receive_rendezvous2": ("D3", "HsParityElevationTest + HsClient.hsClientReceiveRendezvous2", "client receive rend2 thinner"),
    "hs_client_receive_rendezvous_acked": ("D3", "HsParityElevationTest + HsClient.hsClientReceiveRendezvousAcked", "client receive rend acked thinner"),
    "hs_client_reextend_intro_circuit": ("D3", "HsParityElevationTest + HsClient.hsClientReextendIntroCircuit", "client reextend intro thinner"),
    "hs_client_refetch_hsdesc": ("D3", "HsParityElevationTest + HsClient.hsClientRefetchHsdesc", "client refetch hsdesc thinner"),
    "hs_config_client_auth_all": ("D3", "HsParityElevationTest + HsConfig.hsConfigClientAuthAll", "config client auth all thinner"),
    "hs_config_free_all": ("D3", "HsParityElevationTest + HsConfig.hsConfigFreeAll", "config free all thinner"),
    "hs_config_service_all": ("D3", "HsParityElevationTest + HsConfig.hsConfigServiceAll", "config service all thinner"),
    "hs_control_desc_event_content": ("D3", "HsParityElevationTest + HsControl.hsControlDescEventContent", "control desc content thinner"),
    "hs_control_desc_event_created": ("D3", "HsParityElevationTest + HsControl.hsControlDescEventCreated", "control desc created thinner"),
    "hs_control_desc_event_failed": ("D3", "HsParityElevationTest + HsControl.hsControlDescEventFailed", "control desc failed thinner"),
    "hs_control_desc_event_received": ("D3", "HsParityElevationTest + HsControl.hsControlDescEventReceived", "control desc received thinner"),
    "hs_control_desc_event_requested": ("D3", "HsParityElevationTest + HsControl.hsControlDescEventRequested", "control desc requested thinner"),
    "hs_control_desc_event_upload": ("D3", "HsParityElevationTest + HsControl.hsControlDescEventUpload", "control desc upload thinner"),
    "hs_control_desc_event_uploaded": ("D3", "HsParityElevationTest + HsControl.hsControlDescEventUploaded", "control desc uploaded thinner"),
    "hs_control_hsfetch_command": ("D3", "HsParityElevationTest + HsControl.hsControlHsfetchCommand", "control hsfetch thinner"),
    "hs_control_hspost_command": ("D3", "HsParityElevationTest + HsControl.hsControlHspostCommand", "control hspost thinner"),
    "hs_dec_rdv_stream_counter": ("D3", "HsParityElevationTest + HsCommon.hsDecRdvStreamCounter", "dec rdv stream counter thinner"),
    "hs_desc_authorized_client_free_": ("D3", "HsParityElevationTest + HsDescriptor.hsDescAuthorizedClientFree_", "desc auth client free thinner"),
    "hs_desc_build_authorized_client": ("D3", "HsParityElevationTest + HsDescriptor.hsDescBuildAuthorizedClient", "desc build auth client thinner"),
    "hs_desc_build_fake_authorized_client": ("D3", "HsParityElevationTest + HsDescriptor.hsDescBuildFakeAuthorizedClient", "desc build fake auth client thinner"),
    "hs_desc_decode_descriptor": ("D3", "HsParityElevationTest + HsDescriptor.hsDescDecodeDescriptor", "desc decode descriptor thinner"),
    "hs_desc_decode_encrypted": ("D3", "HsParityElevationTest + HsDescriptor.hsDescDecodeEncrypted", "desc decode encrypted thinner"),
    "hs_desc_decode_plaintext": ("D3", "HsParityElevationTest + HsDescriptor.hsDescDecodePlaintext", "desc decode plaintext thinner"),
    "hs_desc_decode_superencrypted": ("D3", "HsParityElevationTest + HsDescriptor.hsDescDecodeSuperencrypted", "desc decode superencrypted thinner"),
    "hs_desc_encrypted_data_free_": ("D3", "HsParityElevationTest + HsDescriptor.hsDescEncryptedDataFree_", "desc encrypted free thinner"),
    "hs_desc_encrypted_data_free_contents": ("D3", "HsParityElevationTest + HsDescriptor.hsDescEncryptedDataFreeContents", "desc encrypted free contents thinner"),
    "hs_desc_intro_point_free_": ("D3", "HsParityElevationTest + HsDescriptor.hsDescIntroPointFree_", "desc intro point free thinner"),
    "hs_desc_intro_point_new": ("D3", "HsParityElevationTest + HsDescriptor.hsDescIntroPointNew", "desc intro point new thinner"),
    "hs_desc_obj_size": ("D3", "HsParityElevationTest + HsDescriptor.hsDescObjSize", "desc obj size thinner"),
    "hs_desc_plaintext_data_free_": ("D3", "HsParityElevationTest + HsDescriptor.hsDescPlaintextDataFree_", "desc plaintext free thinner"),
    "hs_desc_plaintext_data_free_contents": ("D3", "HsParityElevationTest + HsDescriptor.hsDescPlaintextDataFreeContents", "desc plaintext free contents thinner"),
    "hs_desc_plaintext_obj_size": ("D3", "HsParityElevationTest + HsDescriptor.hsDescPlaintextObjSize", "desc plaintext obj size thinner"),
    "hs_desc_superencrypted_data_free_": ("D3", "HsParityElevationTest + HsDescriptor.hsDescSuperencryptedDataFree_", "desc superencrypted free thinner"),
    "hs_dos_can_send_intro2": ("D3", "HsParityElevationTest + HsDos.hsDosCanSendIntro2", "dos can send intro2 thinner"),
    "hs_dos_consensus_has_changed": ("D3", "HsParityElevationTest + HsDos.hsDosConsensusHasChanged", "dos consensus changed thinner"),
    "hs_dos_get_intro2_rejected_count": ("D3", "HsParityElevationTest + HsDos.hsDosGetIntro2RejectedCount", "dos intro2 rejected count thinner"),
    "hs_dos_init": ("D3", "HsParityElevationTest + HsDos.hsDosInit", "dos init thinner"),
    "hs_dos_setup_default_intro2_defenses": ("D3", "HsParityElevationTest + HsDos.hsDosSetupDefaultIntro2Defenses", "dos setup default intro2 thinner"),
    "get_intro2_rate_consensus_param": ("D3", "HsParityElevationTest + HsDos.getIntro2RateConsensusParam", "intro2 rate consensus param thinner"),
    "get_intro2_burst_consensus_param": ("D3", "HsParityElevationTest + HsDos.getIntro2BurstConsensusParam", "intro2 burst consensus param thinner"),
    "get_intro2_enable_consensus_param": ("D3", "HsParityElevationTest + HsDos.getIntro2EnableConsensusParam", "intro2 enable consensus param thinner"),
    "hs_free_all": ("D3", "HsParityElevationTest + HsCommon.hsFreeAll", "hs free all thinner"),
    "hs_get_current_srv": ("D3", "HsParityElevationTest + HsCommon.hsGetCurrentSrv", "hs get current srv thinner"),
    "hs_get_previous_srv": ("D3", "HsParityElevationTest + HsCommon.hsGetPreviousSrv", "hs get previous srv thinner"),
    "hs_get_extend_info_from_lspecs": ("D3", "HsParityElevationTest + HsCommon.hsGetExtendInfoFromLspecs", "hs get extend info from lspecs thinner"),
    "hs_get_hsdir_n_replicas": ("D3", "HsParityElevationTest + HsCommon.hsGetHsdirNReplicas", "hs get hsdir n replicas thinner"),
    "hs_get_hsdir_spread_fetch": ("D3", "HsParityElevationTest + HsCommon.hsGetHsdirSpreadFetch", "hs get hsdir spread fetch thinner"),
    "hs_get_hsdir_spread_store": ("D3", "HsParityElevationTest + HsCommon.hsGetHsdirSpreadStore", "hs get hsdir spread store thinner"),
    "hs_get_next_time_period_num": ("D3", "HsParityElevationTest + HsCommon.hsGetNextTimePeriodNum", "hs get next time period thinner"),
    "hs_get_previous_time_period_num": ("D3", "HsParityElevationTest + HsCommon.hsGetPreviousTimePeriodNum", "hs get previous time period thinner"),
    "hs_ident_circuit_new": ("D3", "HsParityElevationTest + HsIdent.hsIdentCircuitNew", "ident circuit new thinner"),
    "hs_ident_circuit_dup": ("D3", "HsParityElevationTest + HsIdent.hsIdentCircuitDup", "ident circuit dup thinner"),
    "hs_ident_circuit_free_": ("D3", "HsParityElevationTest + HsIdent.hsIdentCircuitFree_", "ident circuit free thinner"),
    "hs_ident_dir_conn_init": ("D3", "HsParityElevationTest + HsIdent.hsIdentDirConnInit", "ident dir conn init thinner"),
    "hs_ident_dir_conn_dup": ("D3", "HsParityElevationTest + HsIdent.hsIdentDirConnDup", "ident dir conn dup thinner"),
    "hs_ident_dir_conn_free_": ("D3", "HsParityElevationTest + HsIdent.hsIdentDirConnFree_", "ident dir conn free thinner"),
    "hs_ident_edge_conn_new": ("D3", "HsParityElevationTest + HsIdent.hsIdentEdgeConnNew", "ident edge conn new thinner"),
    "hs_ident_edge_conn_free_": ("D3", "HsParityElevationTest + HsIdent.hsIdentEdgeConnFree_", "ident edge conn free thinner"),
    "hs_ident_intro_circ_is_valid": ("D3", "HsParityElevationTest + HsIdent.hsIdentIntroCircIsValid", "ident intro circ valid thinner"),
    "hs_ident_server_dir_conn_new": ("D3", "HsParityElevationTest + HsIdent.hsIdentServerDirConnNew", "ident server dir conn new thinner"),
    "hs_intro_circuit_is_suitable_for_establish_intro": ("D3", "HsParityElevationTest + HsIntropoint.hsIntroCircuitIsSuitableForEstablishIntro", "intro circuit suitable establish thinner"),
    "hs_intro_new": ("D3", "HsParityElevationTest + HsIntropoint.hsIntroNew", "intro new thinner"),
    "hs_intro_received_establish_intro": ("D3", "HsParityElevationTest + HsIntropoint.hsIntroReceivedEstablishIntro", "intro received establish thinner"),
    "hs_intro_received_introduce1": ("D3", "HsParityElevationTest + HsIntropoint.hsIntroReceivedIntroduce1", "intro received introduce1 thinner"),
    "hs_intropoint_clear": ("D3", "HsParityElevationTest + HsIntropoint.hsIntropointClear", "intropoint clear thinner"),
    "validate_introduce1_parsed_cell": ("D3", "HsParityElevationTest + HsIntropoint.validateIntroduce1ParsedCell", "validate introduce1 parsed thinner"),
    "verify_establish_intro_cell": ("D3", "HsParityElevationTest + HsIntropoint.verifyEstablishIntroCell", "verify establish intro thinner"),
    "hs_metrics_get_stores": ("D3", "HsParityElevationTest + HsMetrics.hsMetricsGetStores", "metrics get stores thinner"),
    "hs_metrics_service_free": ("D3", "HsParityElevationTest + HsMetrics.hsMetricsServiceFree", "metrics service free thinner"),
    "hs_metrics_service_init": ("D3", "HsParityElevationTest + HsMetrics.hsMetricsServiceInit", "metrics service init thinner"),
    "hs_metrics_update_by_ident": ("D3", "HsParityElevationTest + HsMetrics.hsMetricsUpdateByIdent", "metrics update by ident thinner"),
    "hs_metrics_update_by_service": ("D3", "HsParityElevationTest + HsMetrics.hsMetricsUpdateByService", "metrics update by service thinner"),
    "hs_ob_free_all": ("D3", "HsParityElevationTest + HsOb.hsObFreeAll", "ob free all thinner"),
    "hs_ob_parse_config_file": ("D3", "HsParityElevationTest + HsOb.hsObParseConfigFile", "ob parse config file thinner"),
    "hs_ob_refresh_keys": ("D3", "HsParityElevationTest + HsOb.hsObRefreshKeys", "ob refresh keys thinner"),
    "hs_ob_service_is_instance": ("D3", "HsParityElevationTest + HsOb.hsObServiceIsInstance", "ob service is instance thinner"),
    "hs_pow_free_service_state": ("D3", "HsParityElevationTest + HsPow.hsPowFreeServiceState", "pow free service state thinner"),
    "hs_pow_queue_work": ("D3", "HsParityElevationTest + HsPow.hsPowQueueWork", "pow queue work thinner"),
    "hs_pow_remove_seed_from_cache": ("D3", "HsParityElevationTest + HsPow.hsPowRemoveSeedFromCache", "pow remove seed thinner"),
    "hs_pow_solve": ("D3", "HsParityElevationTest + HsPow.hsPowSolve", "pow solve thinner"),
    "hs_pow_verify": ("D3", "HsParityElevationTest + HsPow.hsPowVerify", "pow verify thinner"),
    "hs_service_add_ephemeral": ("D3", "HsParityElevationTest + HsService.hsServiceAddEphemeral", "service add ephemeral thinner"),
    "hs_service_allow_non_anonymous_connection": ("D3", "HsParityElevationTest + HsService.hsServiceAllowNonAnonymousConnection", "service allow non anon thinner"),
    "hs_service_circuit_cleanup_on_close": ("D3", "HsParityElevationTest + HsService.hsServiceCircuitCleanupOnClose", "service circ cleanup thinner"),
    "hs_service_circuit_has_opened": ("D3", "HsParityElevationTest + HsService.hsServiceCircuitHasOpened", "service circ opened thinner"),
    "hs_service_del_ephemeral": ("D3", "HsParityElevationTest + HsService.hsServiceDelEphemeral", "service del ephemeral thinner"),
    "hs_service_dir_info_changed": ("D3", "HsParityElevationTest + HsService.hsServiceDirInfoChanged", "service dir info changed thinner"),
    "hs_service_dump_stats": ("D3", "HsParityElevationTest + HsService.hsServiceDumpStats", "service dump stats thinner"),
    "hs_service_exports_circuit_id": ("D3", "HsParityElevationTest + HsService.hsServiceExportsCircuitId", "service exports circ id thinner"),
    "hs_service_find": ("D3", "HsParityElevationTest + HsService.hsServiceFind", "service find thinner"),
    "hs_service_free_": ("D3", "HsParityElevationTest + HsService.hsServiceFree_", "service free thinner"),
    "hs_service_free_all": ("D3", "HsParityElevationTest + HsService.hsServiceFreeAll", "service free all thinner"),
    "hs_service_get_metrics_stores": ("D3", "HsParityElevationTest + HsService.hsServiceGetMetricsStores", "service get metrics stores thinner"),
    "hs_service_get_version_from_key": ("D3", "HsParityElevationTest + HsService.hsServiceGetVersionFromKey", "service get version from key thinner"),
    "hs_service_init": ("D3", "HsParityElevationTest + HsService.hsServiceInit", "service init thinner"),
    "hs_service_lists_fnames_for_sandbox": ("D3", "HsParityElevationTest + HsService.hsServiceListsFnamesForSandbox", "service lists fnames sandbox thinner"),
    "hs_stats_get_n_introduce2_v3_cells": ("D3", "HsParityElevationTest + HsStats.hsStatsGetNIntroduce2V3Cells", "stats introduce2 count thinner"),
    "hs_stats_get_n_rendezvous_launches": ("D3", "HsParityElevationTest + HsStats.hsStatsGetNRendezvousLaunches", "stats rendezvous launches thinner"),
    "hs_stats_note_introduce2_cell": ("D3", "HsParityElevationTest + HsStats.hsStatsNoteIntroduce2Cell", "stats note introduce2 thinner"),
    "hs_stats_note_service_rendezvous_launch": ("D3", "HsParityElevationTest + HsStats.hsStatsNoteServiceRendezvousLaunch", "stats note rendezvous launch thinner"),
    "auth_dirport_usage_for_purpose": ("D3", "NodelistParityElevationTest + DirList.authDirportUsageForPurpose", "auth dirport usage thinner"),
    "authcert_free_all": ("D3", "NodelistParityElevationTest + AuthCert.authcertFreeAll", "authcert free all thinner"),
    "authority_cert_dl_failed": ("D3", "NodelistParityElevationTest + AuthCert.authorityCertDlFailed", "authority cert dl failed thinner"),
    "authority_cert_dl_looks_uncertain": ("D3", "NodelistParityElevationTest + AuthCert.authorityCertDlLooksUncertain", "authority cert dl uncertain thinner"),
    "authority_cert_free_": ("D3", "NodelistParityElevationTest + AuthCert.authorityCertFree_", "authority cert free thinner"),
    "authority_cert_get_all": ("D3", "NodelistParityElevationTest + AuthCert.authorityCertGetAll", "authority cert get all thinner"),
    "authority_cert_get_by_digests": ("D3", "NodelistParityElevationTest + AuthCert.authorityCertGetByDigests", "authority cert get by digests thinner"),
    "authority_cert_get_by_sk_digest": ("D3", "NodelistParityElevationTest + AuthCert.authorityCertGetBySkDigest", "authority cert get by sk thinner"),
    "authority_cert_get_newest_by_id": ("D3", "NodelistParityElevationTest + AuthCert.authorityCertGetNewestById", "authority cert newest by id thinner"),
    "authority_cert_is_denylisted": ("D3", "NodelistParityElevationTest + AuthCert.authorityCertIsDenylisted", "authority cert denylisted thinner"),
    "authority_certs_fetch_missing": ("D3", "NodelistParityElevationTest + AuthCert.authorityCertsFetchMissing", "authority certs fetch missing thinner"),
    "choose_array_element_by_weight": ("D3", "NodelistParityElevationTest + NodeSelect.chooseArrayElementByWeight", "choose array by weight thinner"),
    "clear_dir_servers": ("D3", "NodelistParityElevationTest + DirList.clearDirServers", "clear dir servers thinner"),
    "client_would_use_router": ("D3", "NodelistParityElevationTest + NetworkStatus.clientWouldUseRouter", "client would use router thinner"),
    "compare_digest_to_routerstatus_entry": ("D3", "NodelistParityElevationTest + NetworkStatus.compareDigestToRouterstatusEntry", "compare digest routerstatus thinner"),
    "compare_digest_to_vote_routerstatus_entry": ("D3", "NodelistParityElevationTest + NetworkStatus.compareDigestToVoteRouterstatusEntry", "compare digest vote routerstatus thinner"),
    "consensus_is_waiting_for_certs": ("D3", "NodelistParityElevationTest + NetworkStatus.consensusIsWaitingForCerts", "consensus waiting for certs thinner"),
    "count_loading_descriptors_progress": ("D3", "NodelistParityElevationTest + NodeList.countLoadingDescriptorsProgress", "count loading descriptors thinner"),
    "dir_server_add": ("D3", "NodelistParityElevationTest + DirList.dirServerAdd", "dir server add thinner"),
    "dirlist_free_all": ("D3", "NodelistParityElevationTest + DirList.dirlistFreeAll", "dirlist free all thinner"),
    "document_signature_dup": ("D3", "NodelistParityElevationTest + NetworkStatus.documentSignatureDup", "document signature dup thinner"),
    "document_signature_free_": ("D3", "NodelistParityElevationTest + NetworkStatus.documentSignatureFree_", "document signature free thinner"),
    "dump_routerlist_mem_usage": ("D3", "NodelistParityElevationTest + RouterList.dumpRouterlistMemUsage", "dump routerlist mem thinner"),
    "esc_router_info": ("D3", "NodelistParityElevationTest + RouterList.escRouterInfo", "esc router info thinner"),
    "extend_info_describe": ("D3", "NodelistParityElevationTest + Describe.extendInfoDescribe", "extend info describe thinner"),
    "extrainfo_free_": ("D3", "NodelistParityElevationTest + RouterList.extrainfoFree_", "extrainfo free thinner"),
    "fallback_dir_server_new": ("D3", "NodelistParityElevationTest + DirList.fallbackDirServerNew", "fallback dir server new thinner"),
    "format_node_description": ("D3", "NodelistParityElevationTest + Describe.formatNodeDescription", "format node description thinner"),
    "frac_nodes_with_descriptors": ("D3", "NodelistParityElevationTest + NodeSelect.fracNodesWithDescriptors", "frac nodes with descriptors thinner"),
    "get_dir_info_status_string": ("D3", "NodelistParityElevationTest + NodeList.getDirInfoStatusString", "get dir info status string thinner"),
    "get_n_authorities": ("D3", "NodelistParityElevationTest + DirList.getNAuthorities", "get n authorities thinner"),
    "getinfo_helper_networkstatus": ("D3", "NodelistParityElevationTest + NetworkStatus.getinfoHelperNetworkstatus", "getinfo helper networkstatus thinner"),
    "get_microdesc_cache": ("D3", "NodelistParityElevationTest + Microdesc.getMicrodescCache", "get microdesc cache thinner"),
    "hex_digest_nickname_decode": ("D3", "NodelistParityElevationTest + RouterList.hexDigestNicknameDecode", "hex digest nickname decode thinner"),
    "hex_digest_nickname_matches": ("D3", "NodelistParityElevationTest + RouterList.hexDigestNicknameMatches", "hex digest nickname matches thinner"),
    "hexdigest_to_digest": ("D3", "NodelistParityElevationTest + RouterList.hexdigestToDigest", "hexdigest to digest thinner"),
    "is_legal_hexdigest": ("D3", "NodelistParityElevationTest + Nickname.isLegalHexdigest", "is legal hexdigest thinner"),
    "is_legal_nickname": ("D3", "NodelistParityElevationTest + Nickname.isLegalNickname", "is legal nickname thinner"),
    "is_legal_nickname_or_hexdigest": ("D3", "NodelistParityElevationTest + Nickname.isLegalNicknameOrHexdigest", "is legal nickname or hexdigest thinner"),
    "launch_descriptor_downloads": ("D3", "NodelistParityElevationTest + RouterList.launchDescriptorDownloads", "launch descriptor downloads thinner"),
    "link_specifier_smartlist_free_": ("D3", "NodelistParityElevationTest + NodeList.linkSpecifierSmartlistFree_", "link specifier smartlist free thinner"),
    "list_pending_downloads": ("D3", "NodelistParityElevationTest + RouterList.listPendingDownloads", "list pending downloads thinner"),
    "list_pending_microdesc_downloads": ("D3", "NodelistParityElevationTest + RouterList.listPendingMicrodescDownloads", "list pending microdesc downloads thinner"),
    "mark_all_dirservers_up": ("D3", "NodelistParityElevationTest + DirList.markAllDirserversUp", "mark all dirservers up thinner"),
    "microdesc_cache_clean": ("D3", "NodelistParityElevationTest + Microdesc.microdescCacheClean", "microdesc cache clean thinner"),
    "microdesc_cache_clear": ("D3", "NodelistParityElevationTest + Microdesc.microdescCacheClear", "microdesc cache clear thinner"),
    "microdesc_cache_lookup_by_digest256": ("D3", "NodelistParityElevationTest + Microdesc.microdescCacheLookupByDigest256", "microdesc lookup digest256 thinner"),
    "microdesc_cache_rebuild": ("D3", "NodelistParityElevationTest + Microdesc.microdescCacheRebuild", "microdesc cache rebuild thinner"),
    "microdesc_cache_reload": ("D3", "NodelistParityElevationTest + Microdesc.microdescCacheReload", "microdesc cache reload thinner"),
    "microdesc_check_counts": ("D3", "NodelistParityElevationTest + Microdesc.microdescCheckCounts", "microdesc check counts thinner"),
    "microdesc_free_": ("D3", "NodelistParityElevationTest + Microdesc.microdescFree_", "microdesc free thinner"),
    "microdesc_free_all": ("D3", "NodelistParityElevationTest + Microdesc.microdescFreeAll", "microdesc free all thinner"),
    "microdesc_list_missing_digest256": ("D3", "NodelistParityElevationTest + Microdesc.microdescListMissingDigest256", "microdesc list missing thinner"),
    "microdesc_note_outdated_dirserver": ("D3", "NodelistParityElevationTest + Microdesc.microdescNoteOutdatedDirserver", "microdesc note outdated thinner"),
    "microdesc_relay_is_outdated_dirserver": ("D3", "NodelistParityElevationTest + Microdesc.microdescRelayIsOutdatedDirserver", "microdesc relay outdated thinner"),
    "microdesc_reset_outdated_dirservers_list": ("D3", "NodelistParityElevationTest + Microdesc.microdescResetOutdatedDirserversList", "microdesc reset outdated thinner"),
    "microdescs_add_list_to_cache": ("D3", "NodelistParityElevationTest + Microdesc.microdescsAddListToCache", "microdescs add list thinner"),
    "microdescs_add_to_cache": ("D3", "NodelistParityElevationTest + Microdesc.microdescsAddToCache", "microdescs add to cache thinner"),
    "networkstatus_check_consensus_signature": ("D3", "NodelistParityElevationTest + NetworkStatus.networkstatusCheckConsensusSignature", "ns check consensus sig thinner"),
    "networkstatus_check_document_signature": ("D3", "NodelistParityElevationTest + NetworkStatus.networkstatusCheckDocumentSignature", "ns check document sig thinner"),
    "networkstatus_consensus_can_use_multiple_directories": ("D3", "NodelistParityElevationTest + NetworkStatus.networkstatusConsensusCanUseMultipleDirectories", "ns multi directories thinner"),
    "networkstatus_consensus_download_failed": ("D3", "NodelistParityElevationTest + NetworkStatus.networkstatusConsensusDownloadFailed", "ns consensus download failed thinner"),
    "networkstatus_consensus_is_already_downloading": ("D3", "NodelistParityElevationTest + NetworkStatus.networkstatusConsensusIsAlreadyDownloading", "ns already downloading thinner"),
    "networkstatus_consensus_reasonably_live": ("D3", "NodelistParityElevationTest + NetworkStatus.networkstatusConsensusReasonablyLive", "ns reasonably live thinner"),
    "networkstatus_free_all": ("D3", "NodelistParityElevationTest + NetworkStatus.networkstatusFreeAll", "ns free all thinner"),
    "networkstatus_get_bw_weight": ("D3", "NodelistParityElevationTest + NetworkStatus.networkstatusGetBwWeight", "ns get bw weight thinner"),
    "networkstatus_get_flavor_name": ("D3", "NodelistParityElevationTest + NetworkStatus.networkstatusGetFlavorName", "ns get flavor name thinner"),
    "networkstatus_get_overridable_param": ("D3", "NodelistParityElevationTest + NetworkStatus.networkstatusGetOverridableParam", "ns overridable param thinner"),
    "networkstatus_get_voter_by_id": ("D3", "NodelistParityElevationTest + NetworkStatus.networkstatusGetVoterById", "ns get voter by id thinner"),
    "networkstatus_get_voter_sig_by_alg": ("D3", "NodelistParityElevationTest + NetworkStatus.networkstatusGetVoterSigByAlg", "ns voter sig by alg thinner"),
    "networkstatus_get_weight_scale_param": ("D3", "NodelistParityElevationTest + NetworkStatus.networkstatusGetWeightScaleParam", "ns weight scale thinner"),
    "networkstatus_getinfo_by_purpose": ("D3", "NodelistParityElevationTest + NetworkStatus.networkstatusGetinfoByPurpose", "ns getinfo by purpose thinner"),
    "networkstatus_getinfo_helper_single": ("D3", "NodelistParityElevationTest + NetworkStatus.networkstatusGetinfoHelperSingle", "ns getinfo helper single thinner"),
    "networkstatus_is_live": ("D3", "NodelistParityElevationTest + NetworkStatus.networkstatusIsLive", "ns is live thinner"),
    "networkstatus_map_cached_consensus": ("D3", "NodelistParityElevationTest + NetworkStatus.networkstatusMapCachedConsensus", "ns map cached consensus thinner"),
    "networkstatus_note_certs_arrived": ("D3", "NodelistParityElevationTest + NetworkStatus.networkstatusNoteCertsArrived", "ns note certs arrived thinner"),
    "node_allows_single_hop_exits": ("D3", "NodelistParityElevationTest + NodeList.nodeAllowsSingleHopExits", "node allows single hop thinner"),
    "node_describe": ("D3", "NodelistParityElevationTest + NodeList.nodeDescribe", "node describe thinner"),
    "node_ed25519_id_matches": ("D3", "NodelistParityElevationTest + NodeList.nodeEd25519IdMatches", "node ed25519 id matches thinner"),
    "node_family_list_contains": ("D3", "NodelistParityElevationTest + NodeList.nodeFamilyListContains", "node family list contains thinner"),
    "node_get_addr": ("D3", "NodelistParityElevationTest + NodeList.nodeGetAddr", "node get addr thinner"),
    "node_get_address_string": ("D3", "NodelistParityElevationTest + NodeList.nodeGetAddressString", "node get address string thinner"),
    "node_get_all_orports": ("D3", "NodelistParityElevationTest + NodeList.nodeGetAllOrports", "node get all orports thinner"),
    "node_get_by_hex_id": ("D3", "NodelistParityElevationTest + NodeList.nodeGetByHexId", "node get by hex id thinner"),
    "node_get_curve25519_onion_key": ("D3", "NodelistParityElevationTest + NodeList.nodeGetCurve25519OnionKey", "node get curve25519 key thinner"),
    "node_get_declared_uptime": ("D3", "NodelistParityElevationTest + NodeList.nodeGetDeclaredUptime", "node get declared uptime thinner"),
    "node_get_mutable_by_ed25519_id": ("D3", "NodelistParityElevationTest + NodeList.nodeGetMutableByEd25519Id", "node get mutable ed25519 thinner"),
    "node_get_nickname": ("D3", "NodelistParityElevationTest + NodeList.nodeGetNickname", "node get nickname thinner"),
    "node_get_platform": ("D3", "NodelistParityElevationTest + NodeList.nodeGetPlatform", "node get platform thinner"),
    "node_get_pref_dirport": ("D3", "NodelistParityElevationTest + NodeList.nodeGetPrefDirport", "node get pref dirport thinner"),
    "node_get_pref_ipv6_dirport": ("D3", "NodelistParityElevationTest + NodeList.nodeGetPrefIpv6Dirport", "node get pref ipv6 dirport thinner"),
    "node_get_pref_ipv6_orport": ("D3", "NodelistParityElevationTest + NodeList.nodeGetPrefIpv6Orport", "node get pref ipv6 orport thinner"),
    "node_get_pref_orport": ("D3", "NodelistParityElevationTest + NodeList.nodeGetPrefOrport", "node get pref orport thinner"),
    "node_get_prim_dirport": ("D3", "NodelistParityElevationTest + NodeList.nodeGetPrimDirport", "node get prim dirport thinner"),
    "node_get_prim_orport": ("D3", "NodelistParityElevationTest + NodeList.nodeGetPrimOrport", "node get prim orport thinner"),
    "node_get_purpose": ("D3", "NodelistParityElevationTest + NodeList.nodeGetPurpose", "node get purpose thinner"),
    "node_get_rsa_id_digest": ("D3", "NodelistParityElevationTest + NodeList.nodeGetRsaIdDigest", "node get rsa id digest thinner"),
    "node_sl_choose_by_bandwidth": ("D3", "NodelistParityElevationTest + NodeSelect.nodeSlChooseByBandwidth", "node sl choose by bandwidth thinner"),
    "nodefamily_add_nodes_to_smartlist": ("D3", "NodelistParityElevationTest + NodeFamily.nodefamilyAddNodesToSmartlist", "nodefamily add nodes thinner"),
    "nodefamily_canonicalize": ("D3", "NodelistParityElevationTest + NodeFamily.nodefamilyCanonicalize", "nodefamily canonicalize thinner"),
    "nodefamily_contains_nickname": ("D3", "NodelistParityElevationTest + NodeFamily.nodefamilyContainsNickname", "nodefamily contains nickname thinner"),
    "nodefamily_contains_node": ("D3", "NodelistParityElevationTest + NodeFamily.nodefamilyContainsNode", "nodefamily contains node thinner"),
    "nodefamily_contains_rsa_id": ("D3", "NodelistParityElevationTest + NodeFamily.nodefamilyContainsRsaId", "nodefamily contains rsa id thinner"),
}


def depth_for_c(state: ScanState, basename: str, module: str, ktor_path: str) -> tuple[str, str, str]:
    if module.startswith("lib/"):
        return "N/A", LIB_NA_REASON, ""
    if module == "feature/rend":
        return "N/A", REND_NA_REASON, "legacy HS v2"
    if basename in {
        "trace_probes_cc",
        "dirauth_stub",
        "relay_stub",
        "dircache_stub",
    }:
        return SEED_DEPTH.get(
            basename,
            ("N/A", "C Tor stub/trace unit", ""),
        )
    if basename in SEED_DEPTH:
        return SEED_DEPTH[basename]

    if ktor_path == "MISSING":
        return "D0", "no kotlin mirror", "implement or mark N/A"

    lite_hit = any(p in state.lite_files for p in ktor_path.split(";"))
    np_hit = any(p in state.not_ported_files for p in ktor_path.split(";"))
    if lite_hit or np_hit:
        ev = []
        if lite_hit:
            ev.append("lite KDoc")
        if np_hit:
            ev.append("not ported")
        return "D2", "; ".join(ev), "deepen toward C Tor control-flow"

    # default: present mirror without honesty flags → provisional D2 (not D3)
    # Only seed/heuristic D3 for known hot paths above.
    if module.startswith("core/") or module.startswith("feature/"):
        return "D2", "mirror present; not proven D3", "audit hot-path + tests before D3"
    if module == "trunnel":
        return "D2", "codecs partially covered via cell/net", "full trunnel 1:1"
    if module.startswith("app/"):
        return "D2", "TorDaemon/TorConfig cover subset", "full subsystem_list parity"
    return "D2", "present", ""


def layer1_modules(state: ScanState) -> list[Row]:
    rows: list[Row] = []
    src = state.ctor / "src"
    c_files = sorted(
        p
        for p in src.rglob("*.c")
        if p.is_file() and p.parts[len(src.parts)] in PRODUCT_TOP
    )
    for p in c_files:
        rel = p.relative_to(src)
        mod = module_of(rel)
        base = p.stem
        ktor_path, match_ev = resolve_ktor(state, base)
        depth, evidence, gaps = depth_for_c(state, base, mod, ktor_path)
        if match_ev and evidence:
            evidence = f"{evidence}; {match_ev}"
        elif match_ev:
            evidence = match_ev
        # force lite paths ≤ D2
        if any(x in state.lite_files or x in state.not_ported_files for x in ktor_path.split(";")):
            if depth in ("D3", "D4"):
                depth = "D2"
                gaps = (gaps + "; ").lstrip("; ") + "capped by lite/not-ported"
        rows.append(
            Row(
                row_id=f"L1:{mod}/{base}.c",
                layer="1_module",
                ctor_module=mod,
                ctor_unit=f"{base}.c",
                ctor_symbols=base,
                ktor_path=ktor_path,
                depth=depth,
                evidence=evidence,
                gaps=gaps,
            )
        )
    return rows


def layer2_types(state: ScanState) -> list[Row]:
    rows: list[Row] = []
    src = state.ctor / "src"
    st_files = sorted(src.rglob("*_st.h"))
    type_re = re.compile(r"typedef\s+struct\s+(\w+)\s+(\w+);")
    struct_re = re.compile(r"struct\s+(\w+)\s*\{")

    # Also or.h forward typedefs
    or_h = src / "core/or/or.h"
    typedef_names: list[tuple[str, str, Path]] = []
    if or_h.is_file():
        text = or_h.read_text(encoding="utf-8", errors="replace")
        for m in re.finditer(r"typedef\s+struct\s+\w+\s+(\w+);", text):
            typedef_names.append(("core/or", m.group(1), or_h))

    for p in st_files:
        rel = p.relative_to(src)
        mod = module_of(rel)
        text = p.read_text(encoding="utf-8", errors="replace")
        names = set(struct_re.findall(text))
        # filename-derived type guess: foo_st.h → foo_t (only strip trailing _st)
        stem = p.stem  # e.g. circuit_st / or_state_st
        base = stem[:-3] if stem.endswith("_st") else stem.replace("_st", "")
        guess = base + "_t"
        names.add(guess)
        for name in sorted(names):
            typedef_names.append((mod, name, p))

    seen = set()
    for mod, name, origin in typedef_names:
        key = (mod, name)
        if key in seen:
            continue
        seen.add(key)
        # map to kotlin
        camel = "".join(x.title() for x in name.replace("_t", "").split("_"))
        ktor_path = "MISSING"
        evidence = f"from {origin.relative_to(src)}"
        # search kt_index / files containing the C name
        hits = []
        for root_name, paths in state.kt_index.items():
            if name.replace("_", "").lower() in root_name.replace("_", "").lower():
                hits.extend(paths)
        # also grep-ish via ctor_refs
        base = name.replace("_t", "")
        hits.extend(state.ctor_refs.get(base, []))
        # known struct map
        STRUCT_HINTS = {
            "channel_t": ["link/OrChannel.kt"],
            "circuit_t": ["circuit/Circuit.kt", "circuit/CircuitKind.kt"],
            "origin_circuit_t": ["circuit/CircuitKind.kt"],
            "or_circuit_t": ["circuit/CircuitKind.kt"],
            "connection_t": ["link/ConnectionSt.kt"],
            "or_connection_t": ["link/OrConnection.kt"],
            "edge_connection_t": ["link/ConnectionSt.kt", "circuit/ConnectionEdge.kt"],
            "entry_connection_t": ["link/ConnectionSt.kt"],
            "listener_connection_t": ["link/ConnectionSt.kt"],
            "circuitmux_t": ["circuit/CircuitMux.kt"],
            "cell_t": ["cell/Cell.kt"],
            "or_options_t": ["config/TorConfig.kt"],
            "or_state_t": ["config/OrState.kt"],
            "mainloop_state_t": ["mainloop/MainloopState.kt"],
            "entry_guard_t": ["path/EntryGuardFsm.kt"],
            "hs_service_t": ["hs/OnionService.kt"],
            "hs_descriptor_t": ["hs/"],
            "node_t": ["dir/Node.kt"],
            "nodefamily_t": ["dir/NodeFamily.kt"],
            "networkstatus_t": ["dir/NetworkStatus.kt"],
            "microdesc_t": ["dir/Microdesc.kt"],
            "routerinfo_t": ["dir/RouterInfo.kt"],
            "routerstatus_t": ["dir/Consensus.kt"],
            "routerlist_t": ["dir/RouterList.kt"],
            "download_status_t": ["dir/DownloadStatus.kt"],
            "dirauth_options_t": ["dir/DirAuthConfig.kt"],
            "origin_circuit_t": ["circuit/CircuitKind.kt"],
            "or_circuit_t": ["circuit/CircuitKind.kt"],
            "conflux_t": ["circuit/Conflux.kt"],
            "congestion_control_t": ["circuit/CongestionControl.kt"],
            "crypt_path_t": ["circuit/CryptPath.kt"],
            "cell_queue_t": ["circuit/CircuitMux.kt"],
            "destroy_cell_queue_t": ["circuit/CircuitMux.kt"],
            "control_connection_t": ["link/ConnectionSt.kt"],
            "dir_connection_t": ["link/ConnectionSt.kt"],
            "dos_options_t": ["relay/DosOptions.kt"],
            "extend_info_t": ["circuit/ExtendInfo.kt"],
            "ns_detached_signatures_t": ["dir/DetachedSignatures.kt"],
            "routerset_t": ["dir/RouterSet.kt"],
            "dir_server_t": ["dir/DirList.kt"],
            "authority_cert_t": ["dir/AuthorityCert.kt"],
            "relay_crypto_t": ["circuit/RelayCrypto.kt"],
            "tor1_crypt_t": ["circuit/Tor1Crypt.kt"],
            "cgo_pair_t": ["crypto/Cgo.kt"],
            "half_edge_t": ["circuit/CircuitMux.kt"],
            "addr_policy_t": ["net/NetworkPolicy.kt"],
            "bw_array_t": ["relay/BwHist.kt"],
            "dirauth_options_t": ["dir/DirAuthConfig.kt"],
            "hs_opts_t": ["hs/HsCommonConfigDos.kt"],
            "cached_dir_t": ["or/CachedDir.kt"],
            "channel_listener_t": ["or/ChannelListener.kt"],
            "channel_tls_t": ["or/ChannelTls.kt"],
            "circuit_build_times_t": ["or/CircuitBuildTimes.kt"],
            "conflux_leg_t": ["or/ConfluxLeg.kt"],
            "conflux_params_t": ["or/ConfluxParamsSt.kt"],
            "cpath_build_state_t": ["or/CpathBuildState.kt"],
            "crypt_path_reference_t": ["or/CryptPathReference.kt"],
            "desc_store_t": ["or/DescStore.kt"],
            "destroy_cell_t": ["or/DestroyCell.kt"],
            "document_signature_t": ["or/DocumentSignature.kt"],
            "entry_port_cfg_t": ["or/PortCfg.kt"],
            "port_cfg_t": ["or/PortCfg.kt"],
            "server_port_cfg_t": ["or/PortCfg.kt"],
            "ext_or_cmd_t": ["or/ExtOrCmd.kt"],
            "extrainfo_t": ["or/ExtraInfo.kt"],
            "hsdir_index_t": ["or/HsDirIndex.kt"],
            "microdesc_cache_t": ["or/MicrodescCache.kt"],
            "networkstatus_sr_info_t": ["or/NetworkstatusSrInfo.kt"],
            "networkstatus_voter_info_t": ["or/NetworkstatusVoterInfo.kt"],
            "onion_handshake_state_t": ["or/OnionHandshakeState.kt"],
            "or_handshake_certs_t": ["or/OrHandshakeCerts.kt"],
            "or_handshake_state_t": ["or/OrHandshakeState.kt"],
            "packed_cell_t": ["or/PackedCell.kt"],
            "relay_msg_t": ["or/RelayMsg.kt"],
            "signed_descriptor_t": ["or/SignedDescriptor.kt"],
            "socks_request_t": ["or/SocksRequest.kt"],
            "tor_version_t": ["or/TorVersion.kt"],
            "var_cell_t": ["or/VarCell.kt"],
            "vegas_params_t": ["or/VegasParams.kt"],
            "vote_microdesc_hash_t": ["or/VoteMicrodescHash.kt"],
            "vote_routerstatus_t": ["or/VoteRouterstatus.kt"],
            "vote_timing_t": ["or/VoteTiming.kt"],
            "control_cmd_args_t": ["or/ControlCmdArgs.kt"],
        }
        if name in STRUCT_HINTS:
            resolved = []
            for hint in STRUCT_HINTS[name]:
                for base_dir in (
                    state.ktor / "core/src/main/kotlin/org/kotlintor",
                ):
                    cand = base_dir / hint
                    if cand.is_file():
                        resolved.append(str(cand.relative_to(state.ktor)))
                    elif hint.endswith("/"):
                        resolved.append(f"core/src/main/kotlin/org/kotlintor/{hint}*")
            # Exclusive: STRUCT_HINTS replace fuzzy hits so TYPE_SEED is not lite-capped.
            if resolved:
                hits = resolved
        uniq = []
        seen_p = set()
        for h in hits:
            if h not in seen_p:
                seen_p.add(h)
                uniq.append(h)
        if uniq:
            ktor_path = ";".join(uniq[:4])
        depth = "D0" if ktor_path == "MISSING" else "D2"
        gaps = "field-by-field coverage unaudited" if ktor_path != "MISSING" else "no Kotlin type"
        if mod.startswith("lib/"):
            depth = "N/A"
            ktor_path = "N/A" if ktor_path == "MISSING" else ktor_path
            evidence = f"from {origin.relative_to(src)}; lib/ not product-surface"
            gaps = "JVM uses BC/JDK; C Tor lib/* not 1:1"
        if ktor_path != "MISSING" and ktor_path != "N/A" and any(
            x in state.lite_files for x in ktor_path.split(";") if not x.endswith("*")
        ):
            depth = "D2"
            evidence += "; lite mirror"
        # Type-level seed elevations (tests + exclusive STRUCT_HINTS).
        if name in TYPE_SEED_DEPTH:
            sd, se, sg = TYPE_SEED_DEPTH[name]
            # do not raise through lite/not-ported mirrors
            lite_hit = any(
                x in state.lite_files or x in state.not_ported_files
                for x in ktor_path.split(";")
                if x and not x.endswith("*")
            )
            if not lite_hit:
                depth, evidence, gaps = sd, se, sg
            elif name == "or_options_t":
                gaps = "typed subset + acknowledgedKeys; see L4; capped by lite"
                evidence = "TorConfig.kt + TorrcManpageKeys"
        rows.append(
            Row(
                row_id=f"L2:{mod}/{name}",
                layer="2_type",
                ctor_module=mod,
                ctor_unit=name,
                ctor_symbols=camel,
                ktor_path=ktor_path,
                depth=depth if ktor_path != "MISSING" else ("N/A" if mod.startswith("lib/") else "D0"),
                evidence=evidence,
                gaps=gaps,
            )
        )
    return rows


def exported_fns(header: Path) -> list[str]:
    text = header.read_text(encoding="utf-8", errors="replace")
    # crude: lines that look like declarations ending with );
    fns = []
    for m in re.finditer(
        r"^(?:[A-Za-z_][\w\s\*]+?)\b([a-z_][a-z0-9_]*)\s*\([^;]*\)\s*;",
        text,
        re.M,
    ):
        name = m.group(1)
        if name.startswith("tor_") or "_" in name or name.startswith("circ") or name.startswith("channel"):
            fns.append(name)
        elif name not in {"if", "for", "while", "switch", "return"}:
            fns.append(name)
    # filter macros-ish
    return sorted(set(n for n in fns if not n.isupper() and len(n) > 3))[:40]


def layer3_ops(state: ScanState) -> list[Row]:
    rows: list[Row] = []
    src = state.ctor / "src"
    headers: list[Path] = []
    for mod in (
        "core/or",
        "core/crypto",
        "feature/dirauth",
        "feature/hs",
        "feature/relay",
        "feature/client",
        "feature/control",
        "feature/nodelist",
    ):
        d = src / mod
        if d.is_dir():
            headers.extend(sorted(d.glob("*.h")))

    for h in headers:
        # skip huge generated-ish or internal _st only
        if h.name.endswith("_st.h"):
            continue
        mod = module_of(h.relative_to(src))
        if mod not in PRIORITY_OP_MODULES and not any(
            mod.startswith(p) for p in PRIORITY_OP_MODULES
        ):
            continue
        fns = exported_fns(h)
        base = h.stem
        ktor_path, match_ev = resolve_ktor(state, base)
        for fn in fns[:25]:  # cap per header
            # check if fn name appears in any kotlin file (cheap)
            found = False
            for p in list(state.ktor.joinpath("core/src/main/kotlin").rglob("*.kt"))[:0]:
                pass
            # use ktor_path presence as proxy; mark D0 if MISSING module
            if ktor_path == "MISSING":
                depth, evidence, gaps = "D0", "no module mirror", f"op {fn}"
            else:
                depth = "D2"
                evidence = f"header {h.name}; module mirror; {match_ev}"
                gaps = f"op-level mapping unaudited for {fn}"
                if any(x in state.lite_files for x in ktor_path.split(";")):
                    depth = "D2"
                    evidence += "; lite"
                if fn in OP_SEED_DEPTH:
                    lite_hit = any(
                        x in state.lite_files or x in state.not_ported_files
                        for x in ktor_path.split(";")
                        if x and not x.endswith("*")
                    )
                    if not lite_hit:
                        depth, evidence, gaps = OP_SEED_DEPTH[fn]
            rows.append(
                Row(
                    row_id=f"L3:{mod}/{fn}",
                    layer="3_op",
                    ctor_module=mod,
                    ctor_unit=fn,
                    ctor_symbols=h.name,
                    ktor_path=ktor_path,
                    depth=depth,
                    evidence=evidence,
                    gaps=gaps,
                )
            )
    return rows


def camel_to_options(field: str) -> list[str]:
    """Guess torrc / TorConfig names from C field."""
    f = field
    guesses = [f]
    if "_" in f:
        parts = f.split("_")
        camel = parts[0] + "".join(p.title() for p in parts[1:])
        guesses.append(camel)
        guesses.append("".join(p.title() for p in parts))
    return guesses


def norm_opt(s: str) -> str:
    x = s.lower().replace("_", "")
    for suf in ("sec", "ms", "days", "bytes", "msec"):
        if x.endswith(suf) and len(x) > len(suf) + 3:
            x = x[: -len(suf)]
            break
    return x


# C-only / parser-noise fields in or_options_st.h — not torrc keys
L4_NA_FIELDS = {
    "autobool",
    "change_key_passphrase",
    "command",
    "IncludeUsed",
    "magic_",
    "smartlist_t",
    "unauthenticated",
    "ptrace",
    "key_expiration_format",
    "keygen_passphrase_fd",
    "use_keygen_passphrase_fd",
    "UsingTestNetworkDefaults_",
}

# Parsed addr/port splits → typed proxy string fields / manpage keys
L4_FIELD_ALIASES = {
    "HTTPProxyAddr": "httpProxy",
    "HTTPProxyPort": "httpProxy",
    "HTTPSProxyAddr": "httpsProxy",
    "HTTPSProxyPort": "httpsProxy",
    "Socks4ProxyAddr": "socks4Proxy",
    "Socks4ProxyPort": "socks4Proxy",
    "Socks5ProxyAddr": "socks5Proxy",
    "Socks5ProxyPort": "socks5Proxy",
    "TCPProxyAddr": "tcpProxy",
    "TCPProxyPort": "tcpProxy",
    "UsingTestNetworkDefaults_": "usingTestNetworkDefaults",
    "AuthoritativeDir": "authoritativeDirectory",
    "V3AuthoritativeDir": "v3AuthoritativeDirectory",
    "UseEntryGuards_option": "useEntryGuards",
    "DirReqStatistics_option": "dirReqStatistics",
    "HiddenServiceStatistics_option": "hiddenServiceStatistics",
    "PathBiasCircThreshold": "circThreshold",
    "PathBiasNoticeRate": "noticeRate",
    "PathBiasWarnRate": "warnRate",
    "PathBiasExtremeRate": "extremeRate",
    "PathBiasNoticeCountPercentile": "noticeCountPercentile",
    "PathBiasScaleThreshold": "scaleThreshold",
    "PathBiasScaleUseThreshold": "scaleUseThreshold",
    "PathBiasUseThreshold": "useThreshold",
    "PathBiasNoticeUseRate": "noticeUseRate",
    "PathBiasExtremeUseRate": "extremeUseRate",
    "PathBiasUseRate": "useRate",
    "ServerDNSAllowBrokenConfig": "allowBrokenConfig",
    "ServerDNSSearchDomains": "searchDomains",
    "ServerDNSDetectHijacking": "detectHijacking",
    "ServerDNSAllowNonRFC953Hostnames": "allowNonRfc953Hostnames",
    "ServerDNSRandomizeCase": "randomizeCase",
    "HiddenServiceNonAnonymousMode": "nonAnonymousMode",
    "HiddenServiceSingleHopMode": "singleHopMode",
    "CircuitPriorityHalflife": "circuitPriorityHalflifeMsec",
    "MaxCircuitDirtiness": "circuitUnusedTimeoutSec",
    "NumPrimaryGuards": "numEntryGuards",
    "MaxMemInQueues_raw": "maxMemInQueuesBytes",
    "MaxMemInQueues_low_threshold": "maxMemInQueuesLowThresholdBytes",
    "DataDirectoryGroupReadable": "dataDirectoryGroupReadable",
    "CacheDirectoryGroupReadable": "cacheDirectoryGroupReadable",
    "KeyDirectoryGroupReadable": "keyDirectoryGroupReadable",
    "ExtORPortCookieAuthFileGroupReadable": "extOrPortCookieAuthFileGroupReadable",
    "AddressDisableIPv6": "addressDisableIPv6",
    "LogTimeGranularity": "logTimeGranularityMs",
    "ConnLimit_high_thresh": "connLimitHighThresh",
    "ConnLimit_low_thresh": "connLimitLowThresh",
    "DirReqStatistics_option": "dirReqStatistics",
    "HiddenServiceStatistics_option": "hiddenServiceStatistics",
}


def layer4_options(state: ScanState) -> list[Row]:
    rows: list[Row] = []
    opts = state.ctor / "src/app/config/or_options_st.h"
    if not opts.is_file():
        return rows
    text = opts.read_text(encoding="utf-8", errors="replace")
    # fields: type name;
    fields = re.findall(
        r"^\s+(?:const\s+)?(?:struct\s+\w+\s*\*|[\w\s\*]+?)\s+(\w+)\s*;",
        text,
        re.M,
    )
    # filter non-fields
    skip = {"or_options_t", "endif", "ifndef", "define", "include"}
    tc_lower = {f.lower(): f for f in state.torconfig_fields}
    tc_norm = {norm_opt(f): f for f in state.torconfig_fields}
    man_lower = {k.lower().rstrip("*"): k for k in state.manpage_keys}

    for f in fields:
        if f in skip or f.startswith("_"):
            continue
        if f in L4_NA_FIELDS or f.endswith("_"):
            rows.append(
                Row(
                    row_id=f"L4:or_options/{f}",
                    layer="4_option",
                    ctor_module="app/config",
                    ctor_unit=f,
                    ctor_symbols=f,
                    ktor_path="N/A",
                    depth="N/A",
                    evidence="internal C field / not a torrc key",
                    gaps="",
                )
            )
            continue
        guesses = camel_to_options(f)
        if f in L4_FIELD_ALIASES:
            guesses = [L4_FIELD_ALIASES[f]] + guesses
        ktor_path = "MISSING"
        depth = "D0"
        evidence = "or_options_st.h field"
        gaps = "not in TorConfig / manpage keys"

        typed = None
        for g in guesses:
            if g in state.torconfig_fields:
                typed = g
                break
            if g.lower() in tc_lower:
                typed = tc_lower[g.lower()]
                break
            ng = norm_opt(g)
            if ng in tc_norm:
                typed = tc_norm[ng]
                break
        # also search torconfig text for the C-ish name or torrc name
        man_hit = None
        for g in guesses:
            gl = g.lower()
            if gl in man_lower:
                man_hit = man_lower[gl]
                break
            # PathBias* style
            for mk, orig in man_lower.items():
                if mk.rstrip("*") and gl.startswith(mk.rstrip("*")):
                    man_hit = orig
                    break
            # HTTPProxyAddr → HTTPProxy
            for mk, orig in man_lower.items():
                if gl.startswith(mk) and mk:
                    man_hit = orig
                    break

        if typed:
            ktor_path = f"config/TorConfig.{typed}"
            depth = "D2"
            evidence = f"typed field {typed}"
            gaps = "confirm semantic wiring on hot path for D3"
            if typed.lower() in {
                "socksports",
                "controlports",
                "orport",
                "datadirectory",
                "usebridges",
                "exitrelay",
                "cookieauthentication",
            }:
                depth = "D3"
                gaps = ""
                evidence += "; known wired"
        elif man_hit:
            # Parse-switch string in TorConfig* counts as typed D2 (nested option groups).
            quoted_hits = [man_hit] + guesses
            parsed = any(f'"{q}"' in state.torconfig_text for q in quoted_hits if q)
            if parsed or typed:
                ktor_path = f"config/TorConfig.parse/{man_hit}"
                depth = "D2"
                evidence = f"parsed/typed via {man_hit}"
                gaps = "confirm semantic wiring on hot path for D3"
            else:
                ktor_path = f"TorrcManpageKeys/{man_hit}"
                depth = "D1"
                evidence = f"acknowledged/manpage key {man_hit}"
                gaps = "ack-only or untyped; no dedicated TorConfig field"
        else:
            # search manpage fuzzy
            fl = f.lower().replace("_", "")
            for mk, orig in man_lower.items():
                if fl and fl in mk.replace("_", "").replace("*", ""):
                    ktor_path = f"TorrcManpageKeys/{orig}"
                    depth = "D1"
                    evidence = f"fuzzy manpage {orig}"
                    gaps = "verify mapping; likely ack-only"
                    break

        rows.append(
            Row(
                row_id=f"L4:or_options/{f}",
                layer="4_option",
                ctor_module="app/config",
                ctor_unit=f,
                ctor_symbols=f,
                ktor_path=ktor_path,
                depth=depth,
                evidence=evidence,
                gaps=gaps,
            )
        )
    return rows


def write_csv(path: Path, rows: list[Row]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    cols = [
        "row_id",
        "layer",
        "ctor_module",
        "ctor_unit",
        "ctor_symbols",
        "ktor_path",
        "depth",
        "evidence",
        "gaps",
        "parity_board_id",
    ]
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow(r.as_dict())


def summarize(rows: list[Row]) -> str:
    by_layer = Counter(r.layer for r in rows)
    by_depth = Counter(r.depth for r in rows)
    lines = [
        f"_Generated by `scripts/ctor_inventory_scan.py`. Total rows: **{len(rows)}**._",
        "",
        "### By layer",
        "",
        "| Layer | Count |",
        "|-------|------:|",
    ]
    for k in sorted(by_layer):
        lines.append(f"| {k} | {by_layer[k]} |")
    lines += [
        "",
        "### By depth",
        "",
        "| Depth | Count |",
        "|-------|------:|",
    ]
    for k in ["D0", "D1", "D2", "D3", "D4", "N/A"]:
        if k in by_depth:
            lines.append(f"| {k} | {by_depth[k]} |")
    # top D0 modules L1
    d0 = [r for r in rows if r.layer == "1_module" and r.depth == "D0"]
    lines += ["", f"### Layer-1 D0 modules: **{len(d0)}**", ""]
    mod_counts = Counter(r.ctor_module for r in d0)
    lines += ["| Module | D0 .c files |", "|--------|------------:|"]
    for mod, n in mod_counts.most_common(20):
        lines.append(f"| `{mod}` | {n} |")
    return "\n".join(lines) + "\n"


PRIORITY_QUEUE_MODULES = [
    "core/or",
    "core/crypto",
    "core/mainloop",
    "core/proto",
    "feature/dirauth",
    "feature/hs",
    "feature/relay",
    "feature/client",
    "feature/nodelist",
    "feature/control",
    "feature/dircache",
    "feature/dirclient",
    "feature/dircommon",
    "feature/dirparse",
    "app/config",
]


def write_missing_inventory(path: Path, rows: list[Row]) -> None:
    low = [
        r
        for r in rows
        if r.depth in {"D0", "D1", "D2"}
        and r.layer in {"1_module", "2_type", "3_op", "4_option"}
        and (
            r.ctor_module in PRIORITY_QUEUE_MODULES
            or any(r.ctor_module.startswith(p) for p in PRIORITY_OP_MODULES)
        )
    ]
    # prefer L1, then L2, then L3, then L4; sort by depth then module
    order = {"D0": 0, "D1": 1, "D2": 2}
    layer_order = {"1_module": 0, "2_type": 1, "3_op": 2, "4_option": 3}
    low.sort(
        key=lambda r: (
            order.get(r.depth, 9),
            layer_order.get(r.layer, 9),
            r.ctor_module,
            r.ctor_unit,
        )
    )
    top = low[:80]
    dcounts = Counter(r.depth for r in rows)
    lines = [
        "# C Tor missing / partial inventory (generated)",
        "",
        "**Source of truth:** [`CTOR_MASTER_INVENTORY.md`](CTOR_MASTER_INVENTORY.md) + "
        "[`generated/ctor_master_inventory.csv`](generated/ctor_master_inventory.csv)",
        "",
        "Do **not** treat feature-board ✅ in PARITY_GAPS as completeness. "
        "Elevate only by citing `row_id` below; raise at most one depth grade per change.",
        "",
        f"Global depth counts: "
        + ", ".join(f"{k}={dcounts[k]}" for k in ["D0", "D1", "D2", "D3", "D4", "N/A"] if k in dcounts),
        "",
        "## Lowest-depth queue (priority modules, top 80)",
        "",
        "| row_id | depth | unit | ktor_path | gaps |",
        "|--------|-------|------|-----------|------|",
    ]
    for r in top:
        gaps = (r.gaps or "").replace("|", "/")[:80]
        ktor = (r.ktor_path or "").replace("|", "/")[:60]
        lines.append(f"| `{r.row_id}` | {r.depth} | `{r.ctor_unit}` | `{ktor}` | {gaps} |")
    lines += [
        "",
        "## Process",
        "",
        "1. Pick the first `D0`/`D1` row in a priority module.",
        "2. Implement against C Tor source; add/adjust tests.",
        "3. Re-run `python3 scripts/ctor_inventory_scan.py` and update depth only with evidence.",
        "4. Status remains **0.1.0-SNAPSHOT** until release criteria say otherwise.",
        "",
        "```bash",
        "python3 scripts/ctor_inventory_scan.py",
        "./gradlew :core:test --tests 'org.kotlintor.elevate.*'",
        "```",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def patch_master_summary(master: Path, summary: str) -> None:
    text = master.read_text(encoding="utf-8")
    start = "<!-- SUMMARY_START -->"
    end = "<!-- SUMMARY_END -->"
    if start not in text or end not in text:
        return
    pre, rest = text.split(start, 1)
    _, post = rest.split(end, 1)
    master.write_text(pre + start + "\n" + summary + end + post, encoding="utf-8")


def check_lite(rows: list[Row], state: ScanState) -> int:
    """Fail if lite kotlin file is claimed D3+ in L1."""
    bad = []
    for r in rows:
        if r.layer != "1_module":
            continue
        if r.depth not in {"D3", "D4"}:
            continue
        for p in r.ktor_path.split(";"):
            if p in state.lite_files or p in state.not_ported_files:
                bad.append((r.row_id, p, r.depth))
    if bad:
        print("CHECK FAILED: lite/not-ported files claimed D3+:", file=sys.stderr)
        for row_id, p, d in bad:
            print(f"  {row_id} depth={d} path={p}", file=sys.stderr)
        return 1
    print("CHECK OK: no lite/not-ported L1 rows at D3+")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ctor", type=Path, default=Path(os.environ.get("CTOR_SRC", CTOR_DEFAULT)))
    ap.add_argument("--ktor", type=Path, default=Path(os.environ.get("KTOR_ROOT", KTOR_DEFAULT)))
    ap.add_argument("--check-lite", action="store_true")
    ap.add_argument("--check-naming", action="store_true")
    args = ap.parse_args()

    if args.check_naming:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from ctor_naming import check_inventory_csv

        csv_path = args.ktor / "docs/generated/ctor_master_inventory.csv"
        if not csv_path.is_file():
            print("CSV missing; run a full scan first", file=sys.stderr)
            return 2
        return check_inventory_csv(csv_path)

    if not (args.ctor / "src").is_dir():
        print(f"C Tor src not found at {args.ctor}/src", file=sys.stderr)
        return 2
    if not args.ktor.is_dir():
        print(f"kotlin-tor not found at {args.ktor}", file=sys.stderr)
        return 2

    state = ScanState(ktor=args.ktor, ctor=args.ctor)
    print("Collecting kotlin signals…")
    collect_kotlin_signals(state)
    print(f"  lite files: {len(state.lite_files)}")
    print(f"  not_ported files: {len(state.not_ported_files)}")
    print(f"  manpage keys: {len(state.manpage_keys)}")
    print(f"  TorConfig fields: {len(state.torconfig_fields)}")

    print("Layer 1 modules…")
    r1 = layer1_modules(state)
    print(f"  {len(r1)} rows")
    print("Layer 2 types…")
    r2 = layer2_types(state)
    print(f"  {len(r2)} rows")
    print("Layer 3 ops…")
    r3 = layer3_ops(state)
    print(f"  {len(r3)} rows")
    print("Layer 4 options…")
    r4 = layer4_options(state)
    print(f"  {len(r4)} rows")

    rows = r1 + r2 + r3 + r4
    csv_path = args.ktor / "docs/generated/ctor_master_inventory.csv"
    write_csv(csv_path, rows)
    print(f"Wrote {csv_path}")

    summary = summarize(rows)
    master = args.ktor / "docs/CTOR_MASTER_INVENTORY.md"
    if master.is_file():
        patch_master_summary(master, summary)
        print(f"Patched summary in {master}")

    missing = args.ktor / "docs/CTOR_MISSING_INVENTORY.md"
    write_missing_inventory(missing, rows)
    print(f"Wrote {missing}")

    # also write depth counts sidecar
    counts_path = args.ktor / "docs/generated/ctor_depth_counts.txt"
    c = Counter(r.depth for r in rows)
    counts_path.write_text(
        "\n".join(f"{k}={c[k]}" for k in ["D0", "D1", "D2", "D3", "D4", "N/A"] if k in c) + "\n",
        encoding="utf-8",
    )

    if args.check_lite:
        return check_lite(rows, state)
    return check_lite(rows, state)


if __name__ == "__main__":
    raise SystemExit(main())
