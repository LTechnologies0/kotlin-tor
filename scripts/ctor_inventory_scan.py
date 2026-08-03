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
    "channel": ["link/OrChannel.kt", "link/ChannelScheduler.kt"],
    "channeltls": ["link/OrConnection.kt", "link/TorSsl.kt"],
    "channelpadding": ["link/ChannelPadding.kt", "link/PaddingNegotiate.kt"],
    "circuitbuild": ["circuit/Circuit.kt", "path/PathSelector.kt"],
    "circuitlist": ["circuit/CircuitList.kt"],
    "circuituse": ["circuit/Circuit.kt"],
    "circuitmux": ["circuit/CircuitMux.kt"],
    "circuitmux_ewma": ["circuit/CircuitMux.kt"],
    "circuitpadding": [
        "circuit/CircpadFsm.kt",
        "circuit/CircpadHistogram.kt",
        "circuit/CircpadStateMachine.kt",
        "circuit/CircpadNegotiate.kt",
        "circuit/CircpadMachineConditions.kt",
    ],
    "circuitpadding_machines": ["circuit/CircuitPaddingMachines.kt"],
    "circuitstats": ["path/PathBias.kt"],
    "command": ["circuit/Circuit.kt", "relay/RelayService.kt"],
    "connection_edge": ["circuit/ConnectionEdge.kt", "link/ConnectionSt.kt"],
    "connection_or": ["link/OrConnection.kt", "link/ConnectionSt.kt"],
    "crypt_path": ["circuit/CircuitCrypto.kt", "circuit/CgoLayers.kt"],
    "onion": ["circuit/Circuit.kt", "crypto/"],
    "relay": ["circuit/Circuit.kt", "relay/RelayService.kt"],
    "relay_msg": ["cell/", "circuit/Circuit.kt"],
    "sendme": ["circuit/CircuitFlowControl.kt", "circuit/CongestionControl.kt"],
    "policies": ["net/NetworkPolicy.kt", "relay/"],
    "protover": ["dir/"],
    "scheduler": ["link/ChannelScheduler.kt", "link/KistMath.kt"],
    "scheduler_kist": ["link/ChannelScheduler.kt", "link/KistMath.kt", "link/KistCmuxLoad.kt"],
    "scheduler_vanilla": ["link/ChannelScheduler.kt"],
    "dos": ["relay/", "config/TorConfig.kt"],
    "conflux": ["circuit/Conflux.kt"],
    "conflux_pool": ["circuit/Conflux.kt"],
    "conflux_cell": ["circuit/Conflux.kt"],
    "conflux_util": ["circuit/Conflux.kt"],
    "conflux_params": ["circuit/Conflux.kt"],
    "conflux_sys": ["circuit/ConfluxScheduler.kt"],
    "congestion_control_common": ["circuit/CongestionControl.kt"],
    "congestion_control_vegas": ["circuit/CongestionControl.kt"],
    "congestion_control_flow": ["circuit/CircuitFlowControl.kt"],
    "status": ["status/HeartbeatStatus.kt"],
    "address_set": ["net/AddressSet.kt"],
    "onion_ntor": ["crypto/"],
    "onion_ntor_v3": ["crypto/"],
    "onion_fast": ["crypto/"],
    "hs_ntor": ["crypto/", "hs/"],
    "relay_crypto": ["circuit/CircuitCrypto.kt"],
    "relay_crypto_tor1": ["circuit/CircuitCrypto.kt"],
    "relay_crypto_cgo": ["circuit/CgoLayers.kt", "crypto/"],
    "onion_crypto": ["crypto/"],
    "proto_socks": ["net/", "proxy/"],
    "proto_http": ["net/"],
    "proto_cell": ["cell/"],
    "proto_ext_or": ["pt/ExtOrPort.kt"],
    "entrynodes": ["path/EntryGuardFsm.kt", "path/PathSelector.kt"],
    "bridges": ["pt/", "TorClient.kt"],
    "transports": ["pt/"],
    "addressmap": ["net/AutomapAndDnsCache.kt", "TorClient.kt"],
    "dnsserv": ["proxy/", "net/"],
    "circpathbias": ["path/PathBias.kt"],
    "control": ["control/ControlServer.kt"],
    "control_cmd": ["control/ControlServer.kt"],
    "control_events": ["control/ControlServer.kt"],
    "control_getinfo": ["control/ControlServer.kt"],
    "control_auth": ["control/ControlServer.kt"],
    "control_bootstrap": ["control/ControlServer.kt"],
    "control_hs": ["control/ControlServer.kt"],
    "control_proto": ["control/ControlServer.kt"],
    "control_fmt": ["control/ControlServer.kt"],
    "btrack": ["control/ControlServer.kt", "Bootstrap.kt"],
    "btrack_orconn": ["control/ControlServer.kt"],
    "btrack_orconn_cevent": ["control/ControlServer.kt"],
    "btrack_orconn_maps": ["control/ControlServer.kt"],
    "getinfo_geoip": ["control/ControlServer.kt", "stats/ConnGeoHsStats.kt"],
    "dos_config": ["config/TorConfig.kt", "relay/"],
    "dos_sys": ["relay/"],
    "extendinfo": ["circuit/ExtendInfo.kt"],
    "hs_cache": ["hs/HsCache.kt"],
    "dirlist": ["dir/DirList.kt"],
    "routermode": ["relay/RouterMode.kt"],
    "proto_haproxy": ["net/HaproxyProxyHeader.kt"],
    "proto_control0": ["link/Control0Peek.kt"],
    "dirauth_config": ["dir/DirAuthAndClientModes.kt"],
    "dirauth_sys": ["dir/DirAuthAndClientModes.kt"],
    "dirauth_periodic": ["dir/DirAuthAndClientModes.kt", "dir/DirAuthPublishLoop.kt"],
    "dirclient_modes": ["dir/DirAuthAndClientModes.kt"],
    "parsecommon": ["dir/DirParseHelpers.kt"],
    "policy_parse": ["dir/DirParseHelpers.kt"],
    "unparseable": ["dir/DirParseHelpers.kt"],
    "sigcommon": ["dir/DirParseHelpers.kt"],
    "signing": ["dir/DirParseHelpers.kt"],
    "authcert_parse": ["dir/DirParseHelpers.kt", "dir/AuthorityCert.kt"],
    "hs_common": ["hs/HsCommonConfigDos.kt"],
    "hs_config": ["hs/HsCommonConfigDos.kt"],
    "hs_control": ["hs/HsControl.kt"],
    "hs_dos": ["hs/HsCommonConfigDos.kt"],
    "hs_ident": ["hs/HsCommonConfigDos.kt"],
    "hs_intropoint": ["hs/HsCommonConfigDos.kt"],
    "hs_metrics": ["hs/HsCommonConfigDos.kt"],
    "hs_metrics_entry": ["hs/HsCommonConfigDos.kt"],
    "hs_sys": ["hs/HsCommonConfigDos.kt"],
    "torcert": ["dir/TorCert.kt", "hs/Ed25519Cert.kt"],
    "relay_config": ["relay/RelayConfigFindAddr.kt"],
    "relay_find_addr": ["relay/RelayConfigFindAddr.kt"],
    "relay_sys": ["relay/RelayConfigFindAddr.kt"],
    "relay_periodic": ["relay/RelayConfigFindAddr.kt"],
    "relay_metrics": ["relay/RelayConfigFindAddr.kt"],
    "relay_handshake": ["relay/RelayConfigFindAddr.kt"],
    "transport_config": ["relay/RelayConfigFindAddr.kt"],
    "tor_api": ["api/TorApi.kt"],
    "loadkey": ["keymgt/LoadKey.kt"],
    "metrics_sys": ["metrics/MetricsSys.kt", "relay/MetricsPort.kt"],
    "link_handshake": ["trunnel/TrunnelLite.kt", "link/OrConnection.kt"],
    "netinfo": ["trunnel/TrunnelLite.kt", "link/OrConnection.kt"],
    "subproto_request": ["trunnel/TrunnelLite.kt"],
    "pwbox": ["trunnel/TrunnelLite.kt"],
    "dsigs_parse": ["dir/DetachedSignatures.kt"],
    "versions": ["link/OrConnection.kt", "cell/"],
    "ocirc_event": ["control/ControlServer.kt", "circuit/"],
    "orconn_event": ["control/ControlServer.kt", "link/"],
    "or_periodic": ["relay/RelayService.kt", "TorDaemon.kt"],
    "or_sys": ["relay/RelayService.kt", "TorDaemon.kt"],
    "periodic": ["TorDaemon.kt"],
    "netstatus": ["status/HeartbeatStatus.kt", "TorDaemon.kt"],
    "quiet_level": ["config/TorConfig.kt"],
    "resolve_addr": ["net/NetworkPolicy.kt", "relay/"],
    "shutdown": ["TorDaemon.kt"],
    "subsysmgr": ["TorDaemon.kt"],
    "subsystem_list": ["TorDaemon.kt"],
    "risky_options": ["config/TorConfig.kt"],
    "proxymode": ["proxy/"],
    "hs_service": ["hs/OnionService.kt"],
    "hs_client": ["hs/"],
    "hs_circuit": ["hs/"],
    "hs_descriptor": ["hs/"],
    "hs_cell": ["hs/"],
    "hs_pow": ["pow/", "hs/"],
    "hs_ob": ["hs/OnionBalanceFrontend.kt"],
    "replaycache": ["hs/ReplayCache.kt"],
    "shared_random_client": ["dir/SharedRandom.kt"],
    "shared_random": ["dir/SharedRandom.kt"],
    "shared_random_state": ["dir/SharedRandom.kt"],
    "nodelist": ["dir/NodeFamilyAndRouterList.kt"],
    "node_select": ["dir/NicknameDescribeNodeSelect.kt", "path/PathSelector.kt"],
    "networkstatus": ["dir/"],
    "microdesc": ["dir/"],
    "routerlist": ["dir/NodeFamilyAndRouterList.kt"],
    "routerinfo": ["dir/"],
    "authcert": ["dir/"],
    "routerset": ["dir/"],
    "nodefamily": ["dir/NodeFamilyAndRouterList.kt"],
    "nickname": ["dir/NicknameDescribeNodeSelect.kt"],
    "describe": ["dir/NicknameDescribeNodeSelect.kt"],
    "fmt_routerstatus": ["dir/FmtRouterStatus.kt"],
    "dirvote": ["dir/"],
    "process_descs": ["dir/ProcessDescsAndAuthMode.kt"],
    "bwauth": ["dir/"],
    "authmode": ["dir/ProcessDescsAndAuthMode.kt"],
    "bridgeauth": ["dir/BridgeAuthRecommendSrv.kt"],
    "dircollate": ["dir/"],
    "voteflags": ["dir/ConsCacheAndVoteFlags.kt"],
    "voting_schedule": ["dir/"],
    "reachability": ["dir/GuardFractionAndReachability.kt"],
    "keypin": ["dir/"],
    "guardfraction": ["dir/GuardFractionAndReachability.kt"],
    "dircache": ["dir/", "relay/"],
    "dirserv": ["relay/"],
    "conscache": ["dir/ConsCacheAndVoteFlags.kt"],
    "consdiffmgr": ["dir/BridgeAuthRecommendSrv.kt"],
    "dirclient": ["dir/", "TorClient.kt"],
    "dlstatus": ["dir/"],
    "directory": ["dir/"],
    "consdiff": ["dir/"],
    "routerparse": ["dir/"],
    "ns_parse": ["dir/"],
    "microdesc_parse": ["dir/"],
    "router": ["relay/RelayService.kt", "relay/RelayDescriptorBuilder.kt"],
    "routerkeys": ["relay/"],
    "dns": ["net/AutomapAndDnsCache.kt", "relay/"],
    "onion_queue": ["relay/OnionQueueAndHibernate.kt"],
    "ext_orport": ["pt/ExtOrPort.kt"],
    "selftest": ["relay/BwHistAndSelfTest.kt"],
    "hibernate": ["relay/OnionQueueAndHibernate.kt"],
    "rephist": ["relay/OnionQueueAndHibernate.kt"],
    "bwhist": ["relay/BwHistAndSelfTest.kt"],
    "geoip_stats": ["stats/ConnGeoHsStats.kt"],
    "connstats": ["stats/ConnGeoHsStats.kt"],
    "predict_ports": ["dir/ConsCacheAndVoteFlags.kt"],
    "geoip": ["dir/", "stats/"],
    "config": ["config/TorConfig.kt"],
    "statefile": ["config/"],
    "connection": ["link/ConnectionSt.kt"],
    "mainloop": ["TorDaemon.kt"],
    "cpuworker": ["os/"],
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
    # basename -> (depth, evidence, gaps)
    "circuitlist": ("D2", "CircuitList purpose/dirty/counts; elevation", "full purpose matrix / global lists"),
    "status": ("D2", "HeartbeatStatus counters + age; elevation", "full status.c heartbeat counters"),
    "circuitpadding_machines": (
        "D2",
        "CircuitPaddingMachines.kt; KDoc not ported / wtfPadLite",
        "full WTF-PAD machine tables from C",
    ),
    "scheduler_kist": (
        "D2",
        "ChannelScheduler.kt; Full KIST not ported",
        "kernel KIST scheduler_channel full path",
    ),
    "scheduler": ("D2", "ChannelScheduler + KistMath; lite", "full scheduler policies"),
    "dircollate": ("D2", "DirCollator Lite vote collator", "production consensus compute"),
    "dirvote": ("D2", "DirVote* present; live multi-auth thinner", "RSA vote signing depth"),
    "keypin": ("D2", "Keypin.Journal persist/verifyAll + elevation", "full keypin conflict policies"),
    "guardfraction": ("D2", "GuardFraction parse/apply + DirVote.loadGuardFractionFile", "full guardfraction weighting"),
    "reachability": ("D2", "reachability lite", "dirauth OR reach testing loop"),
    "hibernate": ("D2", "OnionQueueAndHibernate lite", "full accounting hibernate FSM"),
    "onion_queue": ("D2", "OnionQueueAndHibernate lite", "priority CREATE queue parity"),
    "rephist": ("D2", "RepHist lite", "full reputation histograms"),
    "circuitmux": ("D2", "CircuitMux.kt lite + flushFair", "full cmux queues / policies"),
    "circuitmux_ewma": ("D2", "EwmaCircuitMuxPolicy", "consensus-tuned EWMA edge cases"),
    "circuitpadding": ("D2", "Circpad* FSM+hist+conditions", "live middle ACK / full machines"),
    "circpathbias": ("D2", "PathBias.kt; DropGuards thinner", "full pathbias use/build FSM"),
    "connection": ("D2", "ConnectionSt hierarchy lite", "full connection_t mainloop"),
    "extendinfo": ("D2", "ExtendInfo.describe + fromRouterStatus elevation", "full extendinfo.c helpers"),
    "hs_cache": ("D2", "HsCache dir+client+dirconn+intro-state; OnionService publish store", "full OOM policy parity"),
    "dirlist": ("D2", "DirList mutable remove/size/all; elevation", "dirport exact match edge"),
    "proto_haproxy": ("D2", "HaproxyProxyHeader format/parse; elevation", "PROXY v2 / listener inject path"),
    "proto_control0": ("D2", "Control0Peek reject; elevation", "full control0 reject on live control port"),
    "dirauth_config": ("D2", "DirAuthOptions.validate + fromTorConfig voting delays", "full dirauth_options_t"),
    "dirauth_sys": ("D2", "DirAuthSys.init/voteAct + elevation", "subsystem lifecycle parity"),
    "dirauth_periodic": ("D2", "DirAuthPeriodic.scheduleHints", "full dirauth periodic events"),
    "dirclient_modes": ("D2", "DirClientModes V2/V3 predicates", "all dirclient_modes.c predicates"),
    "parsecommon": ("D2", "DirParseCommon keywordAll/hasKeyword", "full tokenize / object map"),
    "policy_parse": ("D2", "PolicyParse.isWellFormed edge cases", "full addr_policy parse edge cases"),
    "unparseable": ("D2", "UnparseableDump.tags", "disk dump + sandbox"),
    "sigcommon": ("D2", "DirSigning.stripSignatures", "full RSA verify helpers"),
    "signing": ("D2", "DirSigning helpers", "full dir signing pipeline"),
    "authcert_parse": ("D2", "AuthCertParse.tryParse", "full authcert_parse edge cases"),
    "hs_common": ("D2", "HsCommon period/index + validate; elevation", "full hsdir index math"),
    "hs_config": ("D2", "HsOpts validate SingleHop/NonAnon; elevation", "full hs_opts_t field matrix"),
    "hs_control": ("D2", "HsControl → ControlServer HSFETCH/HSPOST + TorEvent.HsDesc", "full SETEVENTS HS_DESC_CONTENT body"),
    "hs_dos": ("D2", "HsDosDefense consensus params + OnionService INTRODUCE2", "token-bucket exact C parity"),
    "hs_ident": ("D2", "HsIdentCircuit/DirConn + HsCache.noteDirConn", "full circuit attach matrix"),
    "hs_intropoint": ("D2", "HsIntroPointTable FSM wired in OnionService establish", "full intro rotate / failure FSM"),
    "hs_metrics": ("D2", "HsMetrics + exportPrometheus; live intro/upload notes", "full prometheus entry table"),
    "hs_metrics_entry": ("D2", "HsMetrics snapshot keys", "full entry table"),
    "hs_sys": ("D2", "HsSys.init/shutdown via OnionServiceManager", "subsystem event loop parity"),
    "torcert": ("D2", "TorCert.encode/looksValid matrix", "full torcert encode/verify matrix"),
    "relay_config": ("D2", "RelayConfigView.validate + RelayService start", "full relay_config validation matrix"),
    "relay_find_addr": ("D2", "RelayFindAddr IPv4/IPv6 suggestAddresses", "full address suggestion / IPv6 ORPort"),
    "relay_sys": ("D2", "RelaySys.init via RelayService", "subsystem lifecycle"),
    "relay_periodic": ("D2", "RelayPeriodic scheduleHints + RelayService republish loop", "full relay periodic events"),
    "relay_metrics": ("D2", "RelayMetrics catalog + exportPrometheus; descriptor note", "full relay metrics catalog"),
    "relay_handshake": ("D2", "RelayHandshakeState notes + capability flags", "full OR handshake state machine"),
    "transport_config": ("D2", "TransportConfig.parseListenLine PT addrs", "full PT listen option parse"),
    "routermode": ("D2", "RouterMode.setAdvertisedServerMode + elevation", "full advertised_server_mode global"),
    "tor_api": ("D2", "TorApiConfiguration + elevation test", "full tor_run_main ownership"),
    "loadkey": ("D2", "LoadKey ed/RSA via OrCertMaterial; elevation", "full authority key hierarchy"),
    "metrics_sys": ("D2", "MetricsSys + MetricsPortServer; elevation", "full metrics subsystem"),
    "link_handshake": ("D2", "LinkHandshakeTrunnel + OrConnection live CERTS", "full trunnel generated parity"),
    "netinfo": ("D2", "NetinfoTrunnel + OrConnection NETINFO", "full netinfo address lists"),
    "subproto_request": ("D2", "SubprotoRequestTrunnel codecs", "CREATE subproto wire path"),
    "pwbox": ("D2", "PwBoxTrunnel stub codecs", "password-box unused on JVM"),
    "dsigs_parse": ("D2", "DetachedSignatures.kt", "full dsigs_parse edge cases"),
    "trace_probes_cc": ("N/A", "LTTng/trace probes not used on JVM", ""),
    "dirauth_stub": ("N/A", "C Tor build stub when dirauth disabled", "kotlin-tor always has dirauth lite"),
    "relay_stub": ("N/A", "C Tor build stub when relay disabled", "kotlin-tor RelayService covers relay path"),
    "dircache_stub": ("N/A", "C Tor build stub", ""),
    "connection_or": ("D3", "OrConnection live TLS OR", "remaining edge cases vs connection_or.c"),
    "channeltls": ("D3", "OrConnection TLS", ""),
    "relay_crypto_cgo": ("D3", "CgoLayers + live EXTEND V1", ""),
    "onion_ntor": ("D3", "crypto ntor", ""),
    "onion_ntor_v3": ("D3", "crypto ntor-v3", ""),
    "hs_service": ("D3", "OnionService host path", "full hs_service.c edge cases"),
    "hs_client": ("D3", "hs client INTRODUCE/REND", ""),
    "replaycache": ("D3", "ReplayCache INTRODUCE2", ""),
    "ext_orport": ("D3", "ExtOrPortServer", ""),
    "config": ("D2", "TorConfig + acknowledgedKeys", "field-by-field semantic wiring"),
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
    return ";".join(uniq[:5]), f"matched {len(uniq)} path(s)"


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
            "or_connection_t": ["link/ConnectionSt.kt", "link/OrConnection.kt"],
            "edge_connection_t": ["link/ConnectionSt.kt", "circuit/ConnectionEdge.kt"],
            "entry_connection_t": ["link/ConnectionSt.kt"],
            "listener_connection_t": ["link/ConnectionSt.kt"],
            "circuitmux_t": ["circuit/CircuitMux.kt"],
            "cell_t": ["cell/"],
            "or_options_t": ["config/TorConfig.kt"],
            "or_state_t": ["config/"],
            "entry_guard_t": ["path/EntryGuardFsm.kt"],
            "hs_service_t": ["hs/OnionService.kt"],
            "hs_descriptor_t": ["hs/"],
            "node_t": ["dir/NodeFamilyAndRouterList.kt"],
            "networkstatus_t": ["dir/"],
            "microdesc_t": ["dir/"],
            "routerinfo_t": ["dir/"],
            "routerstatus_t": ["dir/"],
            "download_status_t": ["dir/"],
            "conflux_t": ["circuit/Conflux.kt"],
            "congestion_control_t": ["circuit/CongestionControl.kt"],
            "crypt_path_t": ["circuit/CircuitCrypto.kt"],
            "cell_queue_t": ["circuit/CircuitMux.kt"],
            "destroy_cell_queue_t": ["circuit/CircuitMux.kt"],
            "control_connection_t": ["link/ConnectionSt.kt"],
            "dir_connection_t": ["link/ConnectionSt.kt"],
            "dos_options_t": ["relay/DosOptions.kt"],
            "extend_info_t": ["circuit/ExtendInfo.kt"],
            "ns_detached_signatures_t": ["dir/DetachedSignatures.kt"],
            "routerset_t": ["dir/RouterSetAndDlStatus.kt"],
            "dir_server_t": ["dir/DirList.kt"],
            "authority_cert_t": ["dir/AuthorityCert.kt"],
            "relay_crypto_t": ["circuit/CircuitCrypto.kt", "circuit/CgoLayers.kt"],
            "tor1_crypt_t": ["circuit/CircuitCrypto.kt"],
            "cgo_pair_t": ["circuit/CgoLayers.kt", "crypto/"],
            "half_edge_t": ["circuit/CircuitMux.kt"],
            "addr_policy_t": ["net/NetworkPolicy.kt"],
            "bw_array_t": ["relay/BwHistAndSelfTest.kt"],
            "dirauth_options_t": ["dir/DirAuthAndClientModes.kt"],
            "hs_opts_t": ["hs/HsCommonConfigDos.kt"],
            "cached_dir_t": ["or/OrStructMirrors.kt"],
            "channel_listener_t": ["or/OrStructMirrors.kt"],
            "channel_tls_t": ["or/OrStructMirrors.kt", "link/OrConnection.kt"],
            "circuit_build_times_t": ["or/OrStructMirrors.kt"],
            "conflux_leg_t": ["or/OrStructMirrors.kt", "circuit/Conflux.kt"],
            "conflux_params_t": ["or/OrStructMirrors.kt", "circuit/Conflux.kt"],
            "cpath_build_state_t": ["or/OrStructMirrors.kt"],
            "crypt_path_reference_t": ["or/OrStructMirrors.kt"],
            "desc_store_t": ["or/OrStructMirrors.kt"],
            "destroy_cell_t": ["or/OrStructMirrors.kt", "circuit/CircuitMux.kt"],
            "document_signature_t": ["dir/DetachedSignatures.kt", "or/OrStructMirrors.kt"],
            "entry_port_cfg_t": ["or/OrStructMirrors.kt"],
            "port_cfg_t": ["or/OrStructMirrors.kt"],
            "server_port_cfg_t": ["or/OrStructMirrors.kt"],
            "ext_or_cmd_t": ["or/OrStructMirrors.kt", "pt/ExtOrPort.kt"],
            "extrainfo_t": ["or/OrStructMirrors.kt"],
            "hsdir_index_t": ["or/OrStructMirrors.kt"],
            "microdesc_cache_t": ["or/OrStructMirrors.kt"],
            "networkstatus_sr_info_t": ["or/OrStructMirrors.kt", "dir/SharedRandom.kt"],
            "networkstatus_voter_info_t": ["or/OrStructMirrors.kt"],
            "onion_handshake_state_t": ["or/OrStructMirrors.kt"],
            "or_handshake_certs_t": ["or/OrStructMirrors.kt"],
            "or_handshake_state_t": ["or/OrStructMirrors.kt"],
            "packed_cell_t": ["or/OrStructMirrors.kt", "cell/Cell.kt"],
            "relay_msg_t": ["or/OrStructMirrors.kt", "cell/Cell.kt"],
            "signed_descriptor_t": ["or/OrStructMirrors.kt"],
            "socks_request_t": ["or/OrStructMirrors.kt"],
            "tor_version_t": ["or/OrStructMirrors.kt"],
            "var_cell_t": ["or/OrStructMirrors.kt", "cell/Cell.kt"],
            "vegas_params_t": ["or/OrStructMirrors.kt", "circuit/CongestionControl.kt"],
            "vote_microdesc_hash_t": ["or/OrStructMirrors.kt"],
            "vote_routerstatus_t": ["or/OrStructMirrors.kt"],
            "vote_timing_t": ["dir/DirVote.kt", "or/OrStructMirrors.kt"],
            "control_cmd_args_t": ["or/OrStructMirrors.kt"],
            "or_state_t": ["config/TorConfig.kt"],
            "mainloop_state_t": ["TorDaemon.kt"],
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
            if resolved:
                hits = resolved + hits
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
        # or_options special
        if name == "or_options_t":
            depth = "D2"
            gaps = "typed subset + acknowledgedKeys; see L4"
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
        and r.layer in {"1_module", "2_type", "4_option"}
        and r.ctor_module in PRIORITY_QUEUE_MODULES
    ]
    # prefer L1, then L2, then L4; sort by depth then module
    order = {"D0": 0, "D1": 1, "D2": 2}
    low.sort(key=lambda r: (order.get(r.depth, 9), r.layer, r.ctor_module, r.ctor_unit))
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
    args = ap.parse_args()

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
