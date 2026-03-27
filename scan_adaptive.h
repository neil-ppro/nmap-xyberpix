/***************************************************************************
 * scan_adaptive.h -- Optional adaptive timing when ICMP admin-prohibited   *
 *                    responses are observed during raw scans                *
 ***************************************************************************/

#ifndef SCAN_ADAPTIVE_H
#define SCAN_ADAPTIVE_H

class NmapOps;

void nmap_adaptive_icmp_admin_seen(void);
void nmap_adaptive_apply_pending(NmapOps *o);

#endif
