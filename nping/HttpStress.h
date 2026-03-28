/***************************************************************************
 * HttpStress.h -- Authorized HTTP load / resilience testing (nmap-ppro)   *
 ***************************************************************************/

#ifndef NPING_HTTPSTRESS_H
#define NPING_HTTPSTRESS_H

#include "nping.h"
#include "nsock.h"
#include "NpingTarget.h"
#include <utility>
#include <vector>

class HttpStress {
  public:
    HttpStress();
    ~HttpStress();
    int start();

  private:
    bool more_to_send();
    void pump();
    void try_finish_work();
    void issue_connection();
    static void cb_timer_kick(nsock_pool nsp, nsock_event nse, void *userdata);
    static void cb_connect(nsock_pool nsp, nsock_event nse, void *userdata);
    static void cb_write(nsock_pool nsp, nsock_event nse, void *userdata);
    static void cb_read(nsock_pool nsp, nsock_event nse, void *userdata);

    nsock_pool nsp;
    bool nsp_active;
    std::vector<std::pair<NpingTarget *, u16> > endpoints;
    size_t ep_cursor;
    u32 inflight;
    u32 issued;
    u32 ok;
    u32 fail;
    struct timeval time_end;
    bool use_time_limit;
};

#endif /* NPING_HTTPSTRESS_H */
