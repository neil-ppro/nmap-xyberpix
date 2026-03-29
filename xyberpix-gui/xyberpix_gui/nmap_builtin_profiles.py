"""Built-in Nmap checklist profiles (combo indices aligned with nmap_option_catalog.COMBO_SPECS)."""

from __future__ import annotations

from dataclasses import dataclass

from xyberpix_gui.nmap_option_catalog import COMBO_SPECS


def _combo_index_by_argv(key: str, wanted: tuple[str, ...]) -> int:
    spec = next(s for s in COMBO_SPECS if s.key == key)
    for i, (_label, argv) in enumerate(spec.choices):
        if argv == wanted:
            return i
    return 0


@dataclass(frozen=True)
class BuiltinNmapProfile:
    id: str
    title: str
    summary: str
    detail: str
    state: dict


def list_builtin_nmap_profiles() -> tuple[BuiltinNmapProfile, ...]:
    """Return built-in profiles; indices are resolved from catalog argv tuples."""
    t2 = _combo_index_by_argv("timing_template", ("-T2",))
    t3 = _combo_index_by_argv("timing_template", ("-T3",))
    sn = _combo_index_by_argv("ping_scan", ("-sn",))
    safe_on = _combo_index_by_argv("safe_profile", ("--safe-profile", "--safe-profile"))
    safe_off = _combo_index_by_argv("safe_profile", ())
    siem_syslog_off = _combo_index_by_argv("siem_syslog", ())
    reason_on = _combo_index_by_argv("port_reason", ("--reason",))
    decoy_rand_on = _combo_index_by_argv("decoy_stagger_random", ("--decoy-stagger-random",))
    n_on = _combo_index_by_argv("dns_resolution", ("-n",))
    ipv6_robust_on = _combo_index_by_argv("ipv6_robust", ("--ipv6-robust", "--ipv6-robust"))

    polite_siem = BuiltinNmapProfile(
        id="polite_siem_lab",
        title="Polite + SIEM lab",
        summary="T2, safe profile, reason; intended for logged, low-rate scans.",
        detail=(
            "Applies **-T2 (Polite)** and **--safe-profile** (caps host group, optional max rate).\n\n"
            "Wire **SIEM log path** and **--siem-tag** in the text fields before running.\n\n"
            "On the wire: slower timing templates reduce probe rates versus **-T4**/**-T5**; "
            "safe profile adds fork-specific caps documented in **nmap** help."
        ),
        state={
            "v": 2,
            "combo": {
                "timing_template": t2,
                "safe_profile": safe_on,
                "ping_scan": _combo_index_by_argv("ping_scan", ()),
                "skip_discovery": _combo_index_by_argv("skip_discovery", ()),
                "siem_syslog": siem_syslog_off,
                "port_reason": reason_on,
                "aggressive": _combo_index_by_argv("aggressive", ()),
            },
            "lines": {
                "siem_tag": "lab=polite",
            },
        },
    )

    discovery_only = BuiltinNmapProfile(
        id="discovery_only_external",
        title="Discovery-only (ping, no ports)",
        summary="-sn host discovery; pair with explicit target scope.",
        detail=(
            "Uses **-sn** so Nmap performs host discovery **without a port scan**.\n\n"
            "Use for external inventories where port probing is out of scope.\n\n"
            "On the wire: ICMP / scripted discovery traffic only (plus ARP/ND on LAN), "
            "no TCP/UDP port scan phase."
        ),
        state={
            "v": 2,
            "combo": {
                "timing_template": t3,
                "safe_profile": safe_on,
                "ping_scan": sn,
                "skip_discovery": _combo_index_by_argv("skip_discovery", ()),
                "list_scan": _combo_index_by_argv("list_scan", ()),
            },
            "lines": {},
        },
    )

    decoy_lab = BuiltinNmapProfile(
        id="decoy_stagger_lab",
        title="Decoy stagger (lab)",
        summary="Decoy + stagger + reason; requires legal decoy source permission.",
        detail=(
            "Enables **--decoy-stagger-random** for time-spread decoy sends (fork option).\n\n"
            "You must fill **Decoys (-D)** with addresses your program and jurisdiction allow.\n"
            "Spoofed or third-party decoys can be unlawful—use only in authorized labs.\n\n"
            "On the wire: extra probe packets from decoy IPs in addition to your scanner."
        ),
        state={
            "v": 2,
            "combo": {
                "timing_template": t3,
                "safe_profile": safe_on,
                "decoy_stagger_random": decoy_rand_on,
                "port_reason": reason_on,
            },
            "lines": {
                "decoy_stagger_usec": "250000",
                "decoy": "RND:5,ME",
            },
        },
    )

    ipv6_robust_audit = BuiltinNmapProfile(
        id="ipv6_robust_siem",
        title="IPv6 robust + SIEM",
        summary="-6, ipv6-robust, polite timing; for IPv6 lab audits.",
        detail=(
            "Select **IPv6 (-6)** in the catalog and uses **--ipv6-robust** for longer RTT defaults.\n\n"
            "Set **targets** to IPv6 literals or names that resolve to IPv6.\n\n"
            "On the wire: IPv6 scans with more conservative timeout behavior for lossy paths."
        ),
        state={
            "v": 2,
            "combo": {
                "timing_template": t2,
                "ipv6": _combo_index_by_argv("ipv6", ("-6",)),
                "ipv6_robust": ipv6_robust_on,
                "safe_profile": safe_off,
                "dns_resolution": n_on,
            },
            "lines": {
                "siem_tag": "lab=ipv6",
            },
        },
    )

    return (polite_siem, discovery_only, decoy_lab, ipv6_robust_audit)


def get_builtin_by_id(bid: str) -> BuiltinNmapProfile | None:
    for p in list_builtin_nmap_profiles():
        if p.id == bid:
            return p
    return None
