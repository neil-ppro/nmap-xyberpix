#!/usr/bin/env python3
# Zenmap profile command diff (CLI helper; no GUI).
#
# Usage:
#   python3 maint/zenmap_profile_diff.py PROFILE_A PROFILE_B
#   python3 maint/zenmap_profile_diff.py --profile-file /path/to/scan_profiles.usp A B

from __future__ import annotations

import argparse
import difflib
import os
import sys


def _repo_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main():
    parser = argparse.ArgumentParser(
        description="Unified diff of two Zenmap profile nmap command strings.")
    parser.add_argument("profile_a", help="First profile name")
    parser.add_argument("profile_b", help="Second profile name")
    parser.add_argument(
        "--profile-file",
        metavar="PATH",
        help="scan_profiles.usp path (default: zenmap user path via zenmapCore)",
    )
    args = parser.parse_args()

    zenmap_dir = os.path.join(_repo_root(), "zenmap")
    if not os.path.isdir(zenmap_dir):
        print("zenmap/ directory not found next to maint/", file=sys.stderr)
        return 2
    sys.path.insert(0, zenmap_dir)

    from zenmapCore.UmitConf import CommandProfile  # noqa: E402
    from zenmapCore.NmapOptions import NmapOptions  # noqa: E402

    if args.profile_file:
        prof = CommandProfile(user_profile=args.profile_file)
    else:
        prof = CommandProfile()

    for name in (args.profile_a, args.profile_b):
        if name not in prof.sections():
            print("Unknown profile %r (not in profile file)." % name, file=sys.stderr)
            return 1

    def normalized(cmd):
        ops = NmapOptions()
        ops.parse_string(cmd)
        return ops.render_string()

    a = normalized(prof.get_command(args.profile_a))
    b = normalized(prof.get_command(args.profile_b))
    diff = difflib.unified_diff(
        a.splitlines(),
        b.splitlines(),
        fromfile=args.profile_a,
        tofile=args.profile_b,
        lineterm="",
    )
    for line in diff:
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
