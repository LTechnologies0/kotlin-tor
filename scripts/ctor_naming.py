#!/usr/bin/env python3
"""C Tor → kotlin-tor codefile / API naming convention.

Rules (see docs/PARITY_PROCESS.md § Naming):
  1. Each L1 product `.c` basename maps to a primary Kotlin file
     `ExpectedPascal.kt` under `org/kotlintor/…`.
  2. Underscores split words: `congestion_control_flow` → CongestionControlFlow.
  3. Concatenated C Tor stems use STEM_PASCAL word breaks
     (`circuitlist` → CircuitList, not Circuitlist).
  4. Public APIs expose camelCase of C Tor snake_case symbols
     (`tor_run_main` → `torRunMain`), with idiomatic aliases allowed.

Usage:
  python3 scripts/ctor_naming.py --check
  python3 scripts/ctor_naming.py --expected congestion_control_flow
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

KTOR_DEFAULT = Path("/home/user/repos/kotlin-tor")

# Concatenated / irregular C Tor stems → PascalCase Kotlin codefile stem.
STEM_PASCAL: dict[str, str] = {
    "address_set": "AddressSet",
    "addressmap": "AddressMap",
    "authcert": "AuthCert",
    "authcert_parse": "AuthCertParse",
    "authmode": "AuthMode",
    "bridgeauth": "BridgeAuth",
    "bridges": "Bridges",
    "btrack": "Btrack",
    "btrack_circuit": "BtrackCircuit",
    "btrack_orconn": "BtrackOrconn",
    "btrack_orconn_cevent": "BtrackOrconnCevent",
    "btrack_orconn_maps": "BtrackOrconnMaps",
    "bwauth": "BwAuth",
    "bwhist": "BwHist",
    "cell_establish_intro": "CellEstablishIntro",
    "cell_introduce1": "CellIntroduce1",
    "cell_rendezvous": "CellRendezvous",
    "channel": "Channel",
    "channelpadding": "ChannelPadding",
    "channelpadding_negotiation": "ChannelpaddingNegotiation",
    "channeltls": "ChannelTls",
    "circpad_negotiation": "CircpadNegotiation",
    "circpathbias": "CircPathBias",
    "circuitbuild": "CircuitBuild",
    "circuitbuild_relay": "CircuitBuildRelay",
    "circuitlist": "CircuitList",
    "circuitmux": "CircuitMux",
    "circuitmux_ewma": "CircuitMuxEwma",
    "circuitpadding": "CircuitPadding",
    "circuitpadding_machines": "CircuitPaddingMachines",
    "circuitstats": "CircuitStats",
    "circuituse": "CircuitUse",
    "command": "Command",
    "config": "Config",
    "conflux": "Conflux",
    "conflux_cell": "ConfluxCell",
    "conflux_params": "ConfluxParams",
    "conflux_pool": "ConfluxPool",
    "conflux_sys": "ConfluxSys",
    "conflux_util": "ConfluxUtil",
    "congestion_control": "CongestionControl",
    "congestion_control_common": "CongestionControlCommon",
    "congestion_control_flow": "CongestionControlFlow",
    "congestion_control_vegas": "CongestionControlVegas",
    "connection": "Connection",
    "connection_edge": "ConnectionEdge",
    "connection_or": "ConnectionOr",
    "connstats": "ConnStats",
    "conscache": "ConsCache",
    "consdiff": "ConsDiff",
    "consdiffmgr": "ConsDiffMgr",
    "control": "Control",
    "control_auth": "ControlAuth",
    "control_bootstrap": "ControlBootstrap",
    "control_cmd": "ControlCmd",
    "control_events": "ControlEvents",
    "control_fmt": "ControlFmt",
    "control_getinfo": "ControlGetinfo",
    "control_hs": "ControlHs",
    "control_proto": "ControlProto",
    "cpuworker": "CpuWorker",
    "crypt_path": "CryptPath",
    "describe": "Describe",
    "dirauth_config": "DirAuthConfig",
    "dirauth_periodic": "DirAuthPeriodic",
    "dirauth_sys": "DirAuthSys",
    "dircache": "DirCache",
    "dirclient": "DirClient",
    "dirclient_modes": "DirClientModes",
    "dircollate": "DirCollate",
    "directory": "Directory",
    "dirlist": "DirList",
    "dirserv": "DirServ",
    "dirvote": "DirVote",
    "dlstatus": "DlStatus",
    "dns": "Dns",
    "dnsserv": "DnsServ",
    "dos": "Dos",
    "dos_config": "DosConfig",
    "dos_sys": "DosSys",
    "dsigs_parse": "DsigsParse",
    "ed25519_cert": "Ed25519Cert",
    "entrynodes": "EntryNodes",
    "ext_orport": "ExtOrPort",
    "extendinfo": "ExtendInfo",
    "extension": "Extension",
    "flow_control_cells": "FlowControlCells",
    "fmt_routerstatus": "FmtRouterStatus",
    "fp_pair": "FpPair",
    "geoip_stats": "GeoipStats",
    "getinfo_geoip": "GetinfoGeoip",
    "guardfraction": "GuardFraction",
    "hibernate": "Hibernate",
    "hs_cache": "HsCache",
    "hs_cell": "HsCell",
    "hs_circuit": "HsCircuit",
    "hs_circuitmap": "HsCircuitmap",
    "hs_client": "HsClient",
    "hs_common": "HsCommon",
    "hs_config": "HsConfig",
    "hs_control": "HsControl",
    "hs_descriptor": "HsDescriptor",
    "hs_dos": "HsDos",
    "hs_ident": "HsIdent",
    "hs_intropoint": "HsIntropoint",
    "hs_metrics": "HsMetrics",
    "hs_metrics_entry": "HsMetricsEntry",
    "hs_ntor": "HsNtor",
    "hs_ob": "HsOb",
    "hs_pow": "HsPow",
    "hs_service": "HsService",
    "hs_stats": "HsStats",
    "hs_sys": "HsSys",
    "keypin": "Keypin",
    "link_handshake": "LinkHandshake",
    "loadkey": "LoadKey",
    "main": "Main",
    "mainloop": "Mainloop",
    "mainloop_pubsub": "MainloopPubsub",
    "mainloop_sys": "MainloopSys",
    "metrics": "Metrics",
    "metrics_sys": "MetricsSys",
    "microdesc": "Microdesc",
    "microdesc_parse": "MicrodescParse",
    "netinfo": "Netinfo",
    "netstatus": "NetStatus",
    "networkstatus": "NetworkStatus",
    "nickname": "Nickname",
    "node_select": "NodeSelect",
    "nodefamily": "NodeFamily",
    "nodelist": "NodeList",
    "ns_parse": "NsParse",
    "ntmain": "NtMain",
    "ocirc_event": "OcircEvent",
    "onion": "Onion",
    "onion_crypto": "OnionCrypto",
    "onion_fast": "OnionFast",
    "onion_ntor": "OnionNtor",
    "onion_ntor_v3": "OnionNtorV3",
    "onion_queue": "OnionQueue",
    "or_periodic": "OrPeriodic",
    "or_sys": "OrSys",
    "orconn_event": "OrconnEvent",
    "parsecommon": "ParseCommon",
    "periodic": "Periodic",
    "policies": "Policies",
    "policy_parse": "PolicyParse",
    "predict_ports": "PredictPorts",
    "process_descs": "ProcessDescs",
    "proto_cell": "ProtoCell",
    "proto_control0": "ProtoControl0",
    "proto_ext_or": "ProtoExtOr",
    "proto_haproxy": "ProtoHaproxy",
    "proto_http": "ProtoHttp",
    "proto_socks": "ProtoSocks",
    "protover": "Protover",
    "proxymode": "ProxyMode",
    "pwbox": "Pwbox",
    "quiet_level": "QuietLevel",
    "reachability": "Reachability",
    "reasons": "Reasons",
    "recommend_pkg": "RecommendPkg",
    "relay": "Relay",
    "relay_config": "RelayConfig",
    "relay_crypto": "RelayCrypto",
    "relay_crypto_cgo": "RelayCryptoCgo",
    "relay_crypto_tor1": "RelayCryptoTor1",
    "relay_find_addr": "RelayFindAddr",
    "relay_handshake": "RelayHandshake",
    "relay_metrics": "RelayMetrics",
    "relay_msg": "RelayMsg",
    "relay_periodic": "RelayPeriodic",
    "relay_sys": "RelaySys",
    "rephist": "RepHist",
    "replaycache": "ReplayCache",
    "resolve_addr": "ResolveAddr",
    "risky_options": "RiskyOptions",
    "router": "Router",
    "routerinfo": "RouterInfo",
    "routerkeys": "RouterKeys",
    "routerlist": "RouterList",
    "routermode": "RouterMode",
    "routerparse": "RouterParse",
    "routerset": "RouterSet",
    "scheduler": "Scheduler",
    "scheduler_kist": "SchedulerKist",
    "scheduler_vanilla": "SchedulerVanilla",
    "selftest": "Selftest",
    "sendme": "Sendme",
    "sendme_cell": "SendmeCell",
    "shared_random": "SharedRandom",
    "shared_random_client": "SharedRandomClient",
    "shared_random_state": "SharedRandomState",
    "shutdown": "Shutdown",
    "sigcommon": "SigCommon",
    "signing": "Signing",
    "socks5": "Socks5",
    "statefile": "Statefile",
    "status": "Status",
    "subproto_request": "SubprotoRequest",
    "subsysmgr": "SubsysMgr",
    "subsystem_list": "SubsystemList",
    "tor_api": "TorApi",
    "tor_main": "TorMain",
    "torcert": "TorCert",
    "trace_probes_circuit": "TraceProbesCircuit",
    "transport_config": "TransportConfig",
    "transports": "Transports",
    "unparseable": "Unparseable",
    "versions": "Versions",
    "voteflags": "VoteFlags",
    "voting_schedule": "VotingSchedule",
}


def snake_to_pascal(stem: str) -> str:
    if stem in STEM_PASCAL:
        return STEM_PASCAL[stem]
    return "".join(p[:1].upper() + p[1:] for p in stem.split("_") if p)


def expected_pascal(stem: str) -> str:
    return snake_to_pascal(stem)


def check_primary_hint(
    basename: str,
    ktor_path: str,
    *,
    require_exact_file: bool = True,
) -> tuple[bool, str]:
    """Return (ok, detail). Primary path = first concrete `.kt` in ktor_path."""
    expect = expected_pascal(basename)
    if ktor_path in ("", "MISSING"):
        return False, f"no concrete primary path (want {expect}.kt)"
    first_kt = next(
        (p for p in ktor_path.split(";") if p.endswith(".kt") and "*" not in p),
        None,
    )
    if not first_kt:
        return False, f"directory-only match (want {expect}.kt)"
    stem = Path(first_kt).stem
    if stem == expect:
        return True, first_kt
    if require_exact_file:
        return False, f"primary={stem}.kt want={expect}.kt ({first_kt})"
    return False, f"primary={stem}.kt want={expect}.kt"


def check_inventory_csv(csv_path: Path, *, depth_filter: str | None = None) -> int:
    rows = list(csv.DictReader(csv_path.open()))
    fail = 0
    ok = 0
    skip = 0
    label = f"depth={depth_filter}" if depth_filter else "all depths"
    print(f"Naming check (L1 product modules, primary .kt == STEM_PASCAL, {label}):")
    for r in rows:
        if r.get("layer") != "1_module":
            continue
        if r.get("depth") == "N/A":
            skip += 1
            continue
        if depth_filter and r.get("depth") != depth_filter:
            continue
        stem = Path(r["ctor_unit"]).stem
        good, detail = check_primary_hint(stem, r["ktor_path"])
        if good:
            ok += 1
        else:
            fail += 1
            print(f"  FAIL {r['row_id']}: {detail}")
    print(f"OK={ok} FAIL={fail} N/A_skip={skip}")
    return 1 if fail else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ktor", type=Path, default=Path(__file__).resolve().parents[1])
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--check-d3", action="store_true", help="Only require naming parity for L1 D3 rows")
    ap.add_argument("--expected", type=str, help="Print expected PascalCase for a C stem")
    args = ap.parse_args()
    if args.expected:
        print(expected_pascal(args.expected))
        return 0
    if args.check or args.check_d3:
        csv_path = args.ktor / "docs/generated/ctor_master_inventory.csv"
        if not csv_path.is_file():
            print(f"missing {csv_path}; run ctor_inventory_scan.py first", file=sys.stderr)
            return 2
        return check_inventory_csv(csv_path, depth_filter="D3" if args.check_d3 else None)
    ap.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
