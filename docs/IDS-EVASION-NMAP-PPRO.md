# Firewall and IDS-oriented tuning (nmap-ppro)

This note describes **nmap-ppro** options and combinations that help operators
run scans more politely or reduce predictable packet patterns that firewalls and
IDS/IPS devices often key on. Use only on systems and networks you are authorized
to test.

## Decoy scans: spacing and correlation

Nmap’s **`-D`** (decoy) mode sends spoofed probes that appear to come from
multiple addresses. Historically, all decoy packets for one probe were sent
**back-to-back**, which can look like a single tight burst to rate- or
threshold-based rules.

**`--decoy-stagger <usec>`** (0–1,000,000 μs; 0 = off, default) waits **`usec`**
microseconds **between** successive decoy packets in each batch (not after the
last). That spreads the burst in time without changing which addresses are used.

**`--decoy-stagger-random`** randomizes each gap uniformly in **`[1, usec]`**
when **`usec` > 1** (rejection sampling over 32-bit draws, so the distribution is
not modulo-skewed). It has no effect unless **`--decoy-stagger`** is set to a
positive value; Nmap may warn if the random flag is set without a positive stagger.

For **IPv4** raw decoy probes, each decoy packet uses its **own IP ID**, so decoys
are less artificially correlated in packet headers.

Example (illustrative; adjust decoys and timing for your environment):

```text
nmap -sS -D RND:5,ME target --decoy-stagger 3000 --decoy-stagger-random
```

See also **`nmap(1)`** under *Firewall/IDS evasion and spoofing* and **`nmap
--help`**.

## Combining with other controls

These upstream and **nmap-ppro** options are often used together with decoys or
on their own to reduce load and obvious scan signatures:

| Goal | Options to consider |
|------|---------------------|
| Lower parallelism and gentler defaults | **`--safe-profile`** |
| IPv6 path quirks | **`--ipv6-robust`** |
| Back off on admin-prohibited ICMP | **`--adaptive-rate`** |
| Cap parallel hosts | **`--auto-hostgroup`**, **`--min-hostgroup`** / **`--max-hostgroup`** |
| Space probes to one host | **`--scan-delay`**, **`--max-scan-delay`** |
| Global send rate | **`--min-rate`**, **`--max-rate`** |
| Fragmentation (raw scans only) | **`-f`**, **`--mtu`** |
| SIEM / audit trail | **`--siem-log`**, **`--siem-tag`**, **`--siem-syslog`** |

Fragmentation and spoofed decoys interact with **path MTU**, **middlebox
behavior**, and **ISP filtering**; validate with a capture tool when tuning.

## References

- **`docs/nmap.1`** — full option descriptions (installed as the **nmap** man page when you `make install`).
- **`docs/refguide.xml`** — DocBook source for the reference guide (used alongside the man page in this tree).
- **Zenmap** — *SIEM & scan policy* profile tab includes **`--decoy-stagger`** and **`--decoy-stagger-random`**.
