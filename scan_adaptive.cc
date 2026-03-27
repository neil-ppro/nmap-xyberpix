/***************************************************************************
 * scan_adaptive.cc -- Apply timing backoff when ICMP type 3 code 9/10/13   *
 *                    (IPv4) or ICMPv6 admin prohibitions are seen           *
 ***************************************************************************/

#include "scan_adaptive.h"
#include "NmapOps.h"

#include <atomic>
#include <algorithm>

static std::atomic<unsigned int> g_adaptive_pending{0};

void nmap_adaptive_icmp_admin_seen(void) {
  g_adaptive_pending.fetch_add(1, std::memory_order_relaxed);
}

void nmap_adaptive_apply_pending(NmapOps *o) {
  if (!o || !o->adaptive_rate)
    return;
  /* Cap pending count so 5*n cannot overflow and one flood cannot max delays in one step */
  unsigned int n = g_adaptive_pending.exchange(0, std::memory_order_relaxed);
  if (n == 0)
    return;
  if (n > 512)
    n = 512;
  unsigned int md = o->maxTCPScanDelay();
  unsigned int add = (n > 8) ? 40u : 5u * n;
  o->setMaxTCPScanDelay(std::min(md + add, 500u));
  o->setMaxUDPScanDelay(std::min(o->maxUDPScanDelay() + add, 500u));
  o->setMaxSCTPScanDelay(std::min(o->maxSCTPScanDelay() + add, 500u));
  if (o->max_packet_send_rate > 0.0f)
    o->max_packet_send_rate = std::max(o->max_packet_send_rate * 0.85f, 10.0f);
}
