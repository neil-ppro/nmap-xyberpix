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
# * header summarizes some key points from the Nmap license, but is no
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
# * (https://npcap.com) which is under separate license terms.
# *
# * Source is provided to this software because we believe users have a
# * right to know exactly what a program is going to do before they run it.
# *
# ***************************************************************************/

"""
Secure defaults for xml.sax parsers in Zenmap.

Disables external general/parameter entities (reduces XXE / unexpected network
fetches) and supplies an entity resolver that returns empty input instead of
fetching remote DTDs.
"""

from __future__ import annotations

import xml.sax
import xml.sax.xmlreader as xmlreader
from io import StringIO
from xml.sax.handler import EntityResolver


class EmptyEntityResolver(EntityResolver):
    """Return empty input for any external entity (no DTD/network fetch)."""

    empty = StringIO()

    def resolveEntity(self, publicId, systemId):
        return EmptyEntityResolver.empty


def configure_secure_sax_parser(parser) -> None:
    """
    Apply safe feature flags and entity resolver to a SAX parser.

    Ignores features the underlying expat driver does not support.
    """
    for feat, val in (
        (xmlreader.feature_external_ges, False),
        (xmlreader.feature_external_pes, False),
    ):
        try:
            parser.setFeature(feat, val)
        except (xml.sax.SAXNotRecognizedException, xml.sax.SAXNotSupportedException):
            pass
    parser.setEntityResolver(EmptyEntityResolver())
