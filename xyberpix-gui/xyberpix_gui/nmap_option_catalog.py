"""
Nmap CLI options as combobox choices (display label -> argv tokens).

Covers categories from `nmap --help` plus nmap-xyberpix extensions (SIEM, safe-profile, etc.).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class NmapComboSpec:
    """Single dropdown: stable key, form label, choices (display, argv list)."""

    key: str
    label: str
    choices: tuple[tuple[str, tuple[str, ...]], ...]


def _c(label: str, *argv: str) -> tuple[str, tuple[str, ...]]:
    return (label, argv)


NONE = _c("— Default / off —",)


def _timing_template() -> NmapComboSpec:
    ch = [NONE]
    for i in range(6):
        ch.append(_c(f"-T{i} ({['Paranoid','Sneaky','Polite','Normal','Aggressive','Insane'][i]})", f"-T{i}"))
    return NmapComboSpec("timing_template", "Timing template (-T)", tuple(ch))


def _version_intensity() -> NmapComboSpec:
    ch = [NONE]
    for i in range(10):
        ch.append(_c(f"--version-intensity {i}", f"--version-intensity", str(i)))
    return NmapComboSpec("version_intensity", "Version intensity", tuple(ch))


def _max_retries() -> NmapComboSpec:
    ch = [NONE]
    for i in range(11):
        ch.append(_c(f"--max-retries {i}", "--max-retries", str(i)))
    return NmapComboSpec("max_retries", "Max retries", tuple(ch))


COMBO_SPECS: tuple[NmapComboSpec, ...] = (
    NmapComboSpec(
        "list_scan",
        "List scan (-sL)",
        (NONE, _c("List targets only (-sL)", "-sL")),
    ),
    NmapComboSpec(
        "ping_scan",
        "Ping scan, no ports (-sn)",
        (NONE, _c("Ping scan only (-sn)", "-sn")),
    ),
    NmapComboSpec(
        "skip_discovery",
        "Skip host discovery (-Pn)",
        (NONE, _c("Treat all hosts as up (-Pn)", "-Pn")),
    ),
    NmapComboSpec(
        "dns_resolution",
        "DNS resolution",
        (
            NONE,
            _c("Never resolve (-n)", "-n"),
            _c("Always resolve (-R)", "-R"),
        ),
    ),
    NmapComboSpec(
        "icmp_discovery",
        "ICMP discovery",
        (
            NONE,
            _c("ICMP echo (-PE)", "-PE"),
            _c("ICMP timestamp (-PP)", "-PP"),
            _c("ICMP netmask (-PM)", "-PM"),
        ),
    ),
    NmapComboSpec(
        "tcp_syn_ping",
        "TCP SYN discovery (-PS)",
        (
            NONE,
            _c("-PS (default ports)", "-PS"),
            _c("-PS22", "-PS22"),
            _c("-PS80,443", "-PS80,443"),
            _c("-PS21,22,23,25,53,80,110,111,135,139,143,443,445,993,995", "-PS21,22,23,25,53,80,110,111,135,139,143,443,445,993,995"),
        ),
    ),
    NmapComboSpec(
        "tcp_ack_ping",
        "TCP ACK discovery (-PA)",
        (NONE, _c("-PA (default ports)", "-PA"), _c("-PA80", "-PA80"), _c("-PA443", "-PA443")),
    ),
    NmapComboSpec(
        "udp_ping",
        "UDP discovery (-PU)",
        (NONE, _c("-PU40125", "-PU40125"), _c("-PU53", "-PU53"), _c("-PU161", "-PU161")),
    ),
    NmapComboSpec(
        "sctp_ping",
        "SCTP discovery (-PY)",
        (NONE, _c("-PY80", "-PY80"), _c("-PY20", "-PY20"), _c("-PY443", "-PY443")),
    ),
    NmapComboSpec(
        "ip_proto_ping",
        "IP protocol ping (-PO)",
        (NONE, _c("-PO1 (ICMP)", "-PO1"), _c("-PO6 (TCP)", "-PO6"), _c("-PO17 (UDP)", "-PO17")),
    ),
    NmapComboSpec(
        "traceroute",
        "Traceroute",
        (NONE, _c("Trace path (--traceroute)", "--traceroute")),
    ),
    NmapComboSpec(
        "system_dns",
        "Resolver",
        (NONE, _c("Use OS resolver (--system-dns)", "--system-dns")),
    ),
    NmapComboSpec(
        "scan_technique",
        "Scan technique (TCP/UDP/IP)",
        (
            NONE,
            _c("TCP SYN (-sS)", "-sS"),
            _c("TCP connect (-sT)", "-sT"),
            _c("TCP ACK (-sA)", "-sA"),
            _c("TCP Window (-sW)", "-sW"),
            _c("TCP Maimon (-sM)", "-sM"),
            _c("UDP (-sU)", "-sU"),
            _c("TCP Null (-sN)", "-sN"),
            _c("TCP FIN (-sF)", "-sF"),
            _c("TCP Xmas (-sX)", "-sX"),
            _c("SCTP INIT (-sY)", "-sY"),
            _c("SCTP COOKIE-ECHO (-sZ)", "-sZ"),
            _c("IP protocol (-sO)", "-sO"),
        ),
    ),
    NmapComboSpec(
        "port_strategy",
        "Port selection preset",
        (
            NONE,
            _c("Fast top ports (-F)", "-F"),
            _c("Sequential ports (-r)", "-r"),
            _c("Top 10 ports (--top-ports 10)", "--top-ports", "10"),
            _c("Top 100 ports (--top-ports 100)", "--top-ports", "100"),
            _c("Top 1000 ports (--top-ports 1000)", "--top-ports", "1000"),
            _c("Top 5000 ports (--top-ports 5000)", "--top-ports", "5000"),
            _c("Port ratio 1% (--port-ratio 0.01)", "--port-ratio", "0.01"),
            _c("Port ratio 10% (--port-ratio 0.1)", "--port-ratio", "0.1"),
            _c("All TCP ports (-p-)", "-p-"),
        ),
    ),
    NmapComboSpec(
        "service_version",
        "Service / version detection",
        (
            NONE,
            _c("Version scan (-sV)", "-sV"),
            _c("Version light (--version-light)", "--version-light"),
            _c("Version all (--version-all)", "--version-all"),
        ),
    ),
    _version_intensity(),
    NmapComboSpec(
        "version_trace",
        "Version trace",
        (NONE, _c("Version trace (--version-trace)", "--version-trace")),
    ),
    NmapComboSpec(
        "script_scan",
        "NSE scripts",
        (
            NONE,
            _c("Default scripts (-sC)", "-sC"),
            _c("--script=default", "--script=default"),
            _c("--script=safe", "--script=safe"),
            _c("--script=discovery", "--script=discovery"),
            _c("--script=auth", "--script=auth"),
            _c("--script=vuln", "--script=vuln"),
            _c("--script=intrusive", "--script=intrusive"),
            _c("--script=malware", "--script=malware"),
            _c("--script=broadcast", "--script=broadcast"),
            _c("--script=external", "--script=external"),
        ),
    ),
    NmapComboSpec(
        "script_trace",
        "Script trace",
        (NONE, _c("Script trace (--script-trace)", "--script-trace")),
    ),
    NmapComboSpec(
        "script_updatedb",
        "Script DB",
        (NONE, _c("Update script DB (--script-updatedb)", "--script-updatedb")),
    ),
    NmapComboSpec(
        "os_detection",
        "OS detection",
        (
            NONE,
            _c("OS detection (-O)", "-O"),
            _c("-O --osscan-limit", "-O", "--osscan-limit"),
            _c("-O --osscan-guess", "-O", "--osscan-guess"),
            _c("--osscan-limit (with -O)", "--osscan-limit"),
            _c("--osscan-guess (with -O)", "--osscan-guess"),
        ),
    ),
    _timing_template(),
    NmapComboSpec(
        "min_hostgroup",
        "Min host group",
        tuple(
            [NONE]
            + [_c(f"--min-hostgroup {n}", "--min-hostgroup", str(n)) for n in (1, 2, 4, 8, 16, 32, 64, 128, 256)]
        ),
    ),
    NmapComboSpec(
        "max_hostgroup",
        "Max host group",
        tuple(
            [NONE]
            + [_c(f"--max-hostgroup {n}", "--max-hostgroup", str(n)) for n in (1, 2, 4, 8, 16, 32, 64, 128, 256, 1024)]
        ),
    ),
    NmapComboSpec(
        "min_parallelism",
        "Min parallelism",
        tuple([NONE] + [_c(f"--min-parallelism {n}", "--min-parallelism", str(n)) for n in (1, 5, 10, 25, 50, 100)]),
    ),
    NmapComboSpec(
        "max_parallelism",
        "Max parallelism",
        tuple(
            [NONE]
            + [_c(f"--max-parallelism {n}", "--max-parallelism", str(n)) for n in (10, 25, 50, 100, 250, 500, 1000)]
        ),
    ),
    NmapComboSpec(
        "max_rtt_timeout",
        "Max RTT timeout",
        (
            NONE,
            _c("--max-rtt-timeout 100ms", "--max-rtt-timeout", "100ms"),
            _c("--max-rtt-timeout 1s", "--max-rtt-timeout", "1s"),
            _c("--max-rtt-timeout 5s", "--max-rtt-timeout", "5s"),
            _c("--max-rtt-timeout 30s", "--max-rtt-timeout", "30s"),
        ),
    ),
    NmapComboSpec(
        "host_timeout",
        "Host timeout",
        (
            NONE,
            _c("--host-timeout 5m", "--host-timeout", "5m"),
            _c("--host-timeout 15m", "--host-timeout", "15m"),
            _c("--host-timeout 30m", "--host-timeout", "30m"),
            _c("--host-timeout 1h", "--host-timeout", "1h"),
        ),
    ),
    NmapComboSpec(
        "scan_delay",
        "Scan delay",
        (
            NONE,
            _c("--scan-delay 1s", "--scan-delay", "1s"),
            _c("--scan-delay 5s", "--scan-delay", "5s"),
            _c("--max-scan-delay 10s", "--max-scan-delay", "10s"),
        ),
    ),
    NmapComboSpec(
        "min_rate",
        "Min packet rate",
        (
            NONE,
            _c("--min-rate 10", "--min-rate", "10"),
            _c("--min-rate 100", "--min-rate", "100"),
            _c("--min-rate 1000", "--min-rate", "1000"),
        ),
    ),
    NmapComboSpec(
        "max_rate",
        "Max packet rate",
        (
            NONE,
            _c("--max-rate 10", "--max-rate", "10"),
            _c("--max-rate 100", "--max-rate", "100"),
            _c("--max-rate 1000", "--max-rate", "1000"),
            _c("--max-rate 10000", "--max-rate", "10000"),
        ),
    ),
    _max_retries(),
    NmapComboSpec(
        "fragmentation",
        "Packet fragmentation",
        (
            NONE,
            _c("Fragment (-f)", "-f"),
            _c("--mtu 8", "--mtu", "8"),
            _c("--mtu 16", "--mtu", "16"),
            _c("--mtu 24", "--mtu", "24"),
            _c("--mtu 32", "--mtu", "32"),
        ),
    ),
    NmapComboSpec(
        "badsum",
        "Bad checksum",
        (NONE, _c("Bogus checksum (--badsum)", "--badsum")),
    ),
    NmapComboSpec(
        "verbosity",
        "Verbosity / debug",
        (NONE, _c("-v", "-v"), _c("-vv", "-vv"), _c("-d", "-d"), _c("-dd", "-dd"), _c("-ddd", "-ddd")),
    ),
    NmapComboSpec(
        "port_reason",
        "Port state display",
        (NONE, _c("--reason", "--reason"), _c("--open", "--open"), _c("--reason --open", "--reason", "--open")),
    ),
    NmapComboSpec(
        "packet_trace",
        "Packet trace",
        (NONE, _c("--packet-trace", "--packet-trace")),
    ),
    NmapComboSpec(
        "iflist",
        "Interface list",
        (NONE, _c("--iflist", "--iflist")),
    ),
    NmapComboSpec(
        "append_output",
        "Output files",
        (NONE, _c("--append-output", "--append-output")),
    ),
    NmapComboSpec(
        "output_format",
        "Output file format (uses path below)",
        (
            NONE,
            _c("Normal (-oN)", "oN"),
            _c("XML (-oX)", "oX"),
            _c("Grepable (-oG)", "oG"),
            _c("All (-oA)", "oA"),
        ),
    ),
    NmapComboSpec(
        "stylesheet",
        "XML stylesheet",
        (NONE, _c("--webxml", "--webxml"), _c("--no-stylesheet", "--no-stylesheet")),
    ),
    NmapComboSpec(
        "ipv6",
        "IPv6",
        (NONE, _c("IPv6 scanning (-6)", "-6")),
    ),
    NmapComboSpec(
        "aggressive",
        "Aggressive (-A)",
        (NONE, _c("Aggressive (-A)", "-A")),
    ),
    NmapComboSpec(
        "privilege",
        "Privileges",
        (NONE, _c("--privileged", "--privileged"), _c("--unprivileged", "--unprivileged")),
    ),
    NmapComboSpec(
        "send_layer",
        "Send layer",
        (NONE, _c("--send-eth", "--send-eth"), _c("--send-ip", "--send-ip")),
    ),
    NmapComboSpec(
        "noninteractive",
        "Non-interactive",
        (NONE, _c("--noninteractive", "--noninteractive")),
    ),
    NmapComboSpec(
        "siem_syslog",
        "SIEM: syslog",
        (NONE, _c("SIEM to syslog (--siem-syslog)", "--siem-syslog")),
    ),
    NmapComboSpec(
        "safe_profile",
        "Safe / polite profile",
        (NONE, _c("--safe-profile", "--safe-profile")),
    ),
    NmapComboSpec(
        "ipv6_robust",
        "IPv6 robust timing",
        (NONE, _c("--ipv6-robust", "--ipv6-robust")),
    ),
    NmapComboSpec(
        "adaptive_rate",
        "Adaptive rate",
        (NONE, _c("--adaptive-rate", "--adaptive-rate")),
    ),
    NmapComboSpec(
        "auto_hostgroup",
        "Auto host group",
        (NONE, _c("--auto-hostgroup", "--auto-hostgroup")),
    ),
    NmapComboSpec(
        "decoy_stagger_random",
        "Decoy stagger random",
        (NONE, _c("--decoy-stagger-random", "--decoy-stagger-random")),
    ),
)


# Line edits: key -> (label, flag, takes_value, placeholder).
# "extra" and "targets" use argv_utils (POSIX shlex, bounded); other keys are one argv token per field.
LINE_SPECS: tuple[tuple[str, str, str, str], ...] = (
    ("targets", "Targets (hosts / CIDR / ranges)", "", "scanme.nmap.org or 192.168.1.0/24"),
    ("ports", "Port list (-p)", "-p", "22,80,443 or 1-1024 or U:53,T:80"),
    ("exclude_ports", "Exclude ports (--exclude-ports)", "--exclude-ports", "9100-9102"),
    ("input_list", "Input list file (-iL)", "-iL", "/path/to/hosts.txt"),
    ("random_targets", "Random targets (-iR)", "-iR", "100"),
    ("exclude_hosts", "Exclude hosts (--exclude)", "--exclude", "host1,host2"),
    ("exclude_file", "Exclude file (--excludefile)", "--excludefile", "/path/to/exclude.txt"),
    ("dns_servers", "DNS servers (--dns-servers)", "--dns-servers", "8.8.8.8,1.1.1.1"),
    ("scanflags", "Custom TCP flags (--scanflags)", "--scanflags", "URGACKPSHRSTSYNFIN"),
    ("idle_zombie", "Idle scan zombie (-sI)", "-sI", "zombie.example.com:80"),
    ("ftp_bounce", "FTP bounce (-b)", "-b", "ftp.example.com"),
    ("script_custom", "Custom scripts (--script)", "--script", "http-title,vuln"),
    ("script_args", "Script arguments (--script-args)", "--script-args", "user=foo,pass=bar"),
    ("script_args_file", "Script args file (--script-args-file)", "--script-args-file", "/path/to/args.txt"),
    ("script_help", "Script help (--script-help)", "--script-help", "http-*"),
    ("decoy", "Decoys (-D)", "-D", "RND:10,ME,192.0.2.1"),
    ("spoof_ip", "Spoof source (-S)", "-S", "192.0.2.5"),
    ("iface", "Interface (-e)", "-e", "eth0"),
    ("source_port", "Source port (-g)", "-g", "53"),
    ("proxies", "Proxies (--proxies)", "--proxies", "http://127.0.0.1:8080"),
    ("ssh_bounce", "SSH bounce (--ssh-bounce)", "--ssh-bounce", "user@jump"),
    ("ssh_bounce_port", "SSH bounce port (--ssh-bounce-port)", "--ssh-bounce-port", "22"),
    ("data_hex", "Payload hex (--data)", "--data", "0xdeadbeef"),
    ("data_string", "Payload string (--data-string)", "--data-string", "USER test"),
    ("data_length", "Random data length (--data-length)", "--data-length", "25"),
    ("ip_options", "IP options (--ip-options)", "--ip-options", "R"),
    ("ttl", "TTL (--ttl)", "--ttl", "64"),
    ("spoof_mac", "Spoof MAC (--spoof-mac)", "--spoof-mac", "0"),
    ("output_path", "Output file path (with format dropdown)", "", "/tmp/scan"),
    ("stylesheet_path", "Stylesheet (--stylesheet)", "--stylesheet", "/path/style.xsl"),
    ("datadir", "Data directory (--datadir)", "--datadir", "/path/to/nmap-data"),
    ("resume", "Resume (--resume)", "--resume", "/path/to/.xml"),
    ("min_rtt_custom", "Min RTT (--min-rtt-timeout)", "--min-rtt-timeout", "100ms"),
    ("initial_rtt_custom", "Initial RTT (--initial-rtt-timeout)", "--initial-rtt-timeout", "1s"),
    ("decoy_stagger_usec", "Decoy stagger µs (--decoy-stagger)", "--decoy-stagger", "0"),
    ("siem_log", "SIEM JSON log file (--siem-log)", "--siem-log", "/tmp/scan.siem.jsonl"),
    ("siem_tag", "SIEM tag (--siem-tag)", "--siem-tag", "site=lab"),
    ("extra", "Extra arguments (appended last)", "", "-Pn --reason"),
)


def catalog_keys() -> tuple[str, ...]:
    return tuple(s.key for s in COMBO_SPECS)


def line_keys() -> tuple[str, ...]:
    return tuple(s[0] for s in LINE_SPECS)
