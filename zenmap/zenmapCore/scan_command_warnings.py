#!/usr/bin/env python3

# ***********************IMPORTANT NMAP LICENSE TERMS************************
# *
# * The Nmap Security Scanner is (C) 1996-2026 Nmap Software LLC ("The Nmap
# * Project"). Nmap is also a registered trademark of the Nmap Project.
# *
# * This program is distributed under the terms of the Nmap Public Source
# * License (NPSL). The exact license text applying to a particular Nmap
# * release or source code control revision is contained in the LICENSE
# * file distributed with that version of Nmap or source code control
# * revision. More Nmap copyright/legal information is available from
# * https://nmap.org/book/man-legal.html, and further information on the
# * NPSL license itself can be found at https://nmap.org/npsl/ . This
# * header summarizes some key points from the Nmap license, but it is no
# * substitute for the actual license text.
# *
# * Nmap is generally free for end users to download and use themselves,
# * including commercial use. It is available from https://nmap.org.
# *
# * The Nmap license generally prohibits companies from using and
# * redistributing Nmap in commercial products, but we sell a special Nmap
# * OEM Edition with a more permissive license and special features for
# * this purpose. See https://nmap.org/oem/
# *
# * If you have received a written Nmap license agreement or contract
# * stating terms other than these (such as an Nmap OEM license), you may
# * choose to use and redistribute Nmap under those terms instead.
# *
# * The official Nmap Windows builds include the Npcap software
# * (https://npcap.com) for packet capture and transmission. It is under
# * separate license terms which forbid redistribution without special
# * permission. So the official Nmap Windows builds may not be redistributed
# * without special permission (such as an Nmap OEM license).
# *
# * Source is provided to this software because we believe users have a
# * right to know exactly what a program is going to do before they run it.
# * This also allows you to audit the software for security holes.
# *
# * Source code also allows you to port Nmap to new platforms, fix bugs, and
# * add new features. You are highly encouraged to submit your changes as a
# * Github PR or by email to the dev@nmap.org mailing list for possible
# * incorporation into the main distribution. Unless you specify otherwise, it
# * is understood that you are offering us very broad rights to use your
# * submissions as described in the Nmap Public Source License Contributor
# * Agreement. This is important because we fund the project by selling licenses
# * with various terms, and also because the inability to relicense code has
# * caused devastating problems for other Free Software projects (such as KDE
# * and NASM).
# *
# * The free version of Nmap is distributed in the hope that it will be
# * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Warranties,
# * indemnification and commercial support are all available through the
# * Npcap OEM program--see https://nmap.org/oem/
# *
# ***************************************************************************/

"""Heuristics for Zenmap scan confirmations (intrusive or file-reading flags)."""

import zenmapCore.I18N  # lgtm[py/unused-import]
from zenmapCore.NmapOptions import split_quoted


def intrusive_scan_warnings(command_string):
    """Return a list of user-facing warning lines, or [] if none apply.

    Parsing uses the same quoting rules as the rest of Zenmap. The first
    token may be an ``nmap`` executable path and is ignored.
    """
    text = (command_string or "").strip()
    if not text:
        return []

    try:
        tokens = split_quoted(text)
    except Exception:
        return [_("Could not parse the command line; review it before running.")]

    if not tokens:
        return []

    if tokens[0] == "nmap" or tokens[0].endswith("/nmap"):
        tokens = tokens[1:]

    warnings = []
    seen = set()
    i = 0
    n = len(tokens)

    def add(msg):
        if msg not in seen:
            seen.add(msg)
            warnings.append(msg)

    while i < n:
        t = tokens[i]
        if t == "-A":
            add(_(
                "-A enables OS detection, version detection, script scanning, "
                "and traceroute (aggressive)."))
        elif t == "-sC":
            add(_("-sC runs the default NSE script set."))
        elif t.startswith("--script"):
            add(_("This command uses the Nmap Scripting Engine (--script); "
                  "scripts may be intrusive or unexpected on the target."))
        elif t.startswith("-iL") and len(t) > 3:
            add(_("-iL reads target addresses from a file; use only trusted paths."))
        elif t in ("-iL", "--iL"):
            add(_("-iL reads target addresses from a file; use only trusted paths."))
            i += 2
            continue
        elif t == "--script-args-file":
            add(_("This command reads NSE script arguments from a file; use only "
                  "trusted paths."))
            i += 2
            continue
        i += 1

    return warnings
