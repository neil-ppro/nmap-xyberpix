/***************************************************************************
 * HttpStress.cc -- Authorized parallel HTTP/1.x requests for load testing   *
 *                  (nmap-ppro; requires --authorized-dos)                   *
 ***************************************************************************/

#include "nping.h"
#include "HttpStress.h"
#include "NpingOps.h"
#include "output.h"
#include "nsock.h"
#include "nbase.h"

#include <stdlib.h>
#include <string.h>

#if TIME_WITH_SYS_TIME
#include <sys/time.h>
#include <time.h>
#else
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#else
#include <time.h>
#endif
#endif

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

extern NpingOps o;

#define HS_READ_MAX 65536
#define HS_CONN_TIMEOUT 20000
#define HS_READ_CHUNK_TIMEOUT 60000
#define HS_WBUF_SIZE 16384

struct hs_conn {
  NpingTarget *target;
  u16 port;
  int wlen;
  int rl;
  char rb[HS_READ_MAX + 1];
  char wbuf[HS_WBUF_SIZE];
  nsock_iod nsi;
};

static HttpStress *g_hs = NULL;

/* Host header value must not contain CR/LF (injection). Mirrors NpingOps checks. */
static bool hs_host_field_safe(const char *h) {
  size_t n = 0;

  if (h == NULL)
    return false;
  for (; *h != '\0'; h++) {
    if (++n > 255u)
      return false;
    unsigned char c = (unsigned char)*h;
    if (c == '\r' || c == '\n' || c < 0x20u || c >= 0x7fu)
      return false;
  }
  return n > 0;
}

/* Find end of HTTP header block without relying on strstr across binary data. */
static bool hs_headers_complete(const char *buf, int len) {
  int i;

  for (i = 0; i + 3 < len; i++) {
    if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n')
      return true;
  }
  return false;
}

HttpStress::HttpStress() {
  this->nsp = NULL;
  this->nsp_active = false;
  this->ep_cursor = 0;
  this->inflight = 0;
  this->issued = 0;
  this->ok = 0;
  this->fail = 0;
  this->use_time_limit = false;
  memset(&this->time_end, 0, sizeof(this->time_end));
}

HttpStress::~HttpStress() {
}

static int build_http_request(hs_conn *c) {
  const char *path = o.getStressHttpPath();
  const char *meth = o.getStressHttpMethod();
  const char *host = c->target->getSuppliedHostName();
  const char *body = o.issetStressHttpBody() ? o.getStressHttpBody() : NULL;
  size_t body_len = body ? strlen(body) : 0;

  if (body_len > 8192)
    body_len = 8192;

  if (!host || !host[0])
    host = c->target->getTargetIPstr();
  if (!host || !host[0])
    return -1;
  if (!hs_host_field_safe(host))
    return -1;

  if (!path || path[0] != '/')
    return -1;

  if (body && body_len > 0) {
    char hdr[2048];
    int hn = Snprintf(hdr, sizeof(hdr),
        "%s %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Connection: close\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: %zu\r\n"
        "User-Agent: Nping-authorized-loadtest/1.0\r\n"
        "\r\n",
        meth, path, host, body_len);
    if (hn < 0 || (size_t)hn >= sizeof(hdr))
      return -1;
    if ((size_t)hn + body_len + 1 >= HS_WBUF_SIZE)
      return -1;
    memcpy(c->wbuf, hdr, (size_t)hn);
    memcpy(c->wbuf + hn, body, body_len);
    c->wbuf[hn + (int)body_len] = '\0';
    return hn + (int)body_len;
  }

  int n = Snprintf(c->wbuf, HS_WBUF_SIZE,
      "%s %s HTTP/1.1\r\n"
      "Host: %s\r\n"
      "Connection: close\r\n"
      "User-Agent: Nping-authorized-loadtest/1.0\r\n"
      "\r\n",
      meth, path, host);
  if (n < 0 || (size_t)n >= HS_WBUF_SIZE)
    return -1;
  return n;
}

void HttpStress::try_finish_work() {
  if (this->inflight != 0)
    return;
  if (this->more_to_send())
    return;
  if (this->nsp_active && this->nsp != NULL)
    nsock_loop_quit(this->nsp);
}

bool HttpStress::more_to_send() {
  struct timeval now;

  if (this->use_time_limit) {
    gettimeofday(&now, NULL);
    if (timercmp(&now, &this->time_end, >))
      return false;
  }
  u32 cap = o.getPacketCount();
  if (cap != 0xFFFFFFFFu && this->issued >= (u64)cap)
    return false;
  return true;
}

void HttpStress::pump() {
  u32 parallel = o.getStressParallel();

  while (this->inflight < parallel && this->more_to_send()) {
    this->issue_connection();
  }
  this->try_finish_work();
}

void HttpStress::issue_connection() {
  if (this->endpoints.empty())
    return;

  hs_conn *c = (hs_conn *)safe_malloc(sizeof(hs_conn));
  memset(c, 0, sizeof(*c));
  c->target = this->endpoints[this->ep_cursor % this->endpoints.size()].first;
  c->port = this->endpoints[this->ep_cursor % this->endpoints.size()].second;
  this->ep_cursor++;

  struct sockaddr_storage ss;
  size_t slen;

  if (c->target->getTargetSockAddr(&ss, &slen) != OP_SUCCESS) {
    free(c);
    this->fail++;
    return;
  }

  c->nsi = nsock_iod_new(this->nsp, NULL);
  if (c->nsi == NULL) {
    free(c);
    this->fail++;
    return;
  }

  /* Omit local bind unless a source port or source address was requested; bind
   * with sizeof(sockaddr_storage) breaks on some hosts (e.g. macOS EINVAL). */
  if (o.issetSourcePort() || o.issetIPv4SourceAddress() || o.issetIPv6SourceAddress() || o.spoofSource()) {
    struct sockaddr_storage src;
    o.getSourceSockAddr(&src);
    if (o.ipv4())
      nsock_iod_set_localaddr(c->nsi, &src, sizeof(struct sockaddr_in));
    else
      nsock_iod_set_localaddr(c->nsi, &src, sizeof(struct sockaddr_in6));
  }

  nsock_connect_tcp(this->nsp, c->nsi, HttpStress::cb_connect, HS_CONN_TIMEOUT, c,
      (struct sockaddr *)&ss, slen, c->port);

  this->inflight++;
  this->issued++;
}

void HttpStress::cb_timer_kick(nsock_pool nsp, nsock_event nse, void *userdata) {
  (void)nse;
  HttpStress *hs = (HttpStress *)userdata;

  hs->nsp = nsp;
  hs->pump();
}

void HttpStress::cb_connect(nsock_pool nsp, nsock_event nse, void *userdata) {
  hs_conn *c = (hs_conn *)userdata;
  HttpStress *hs = g_hs;
  enum nse_status status = nse_status(nse);

  if (hs == NULL) {
    if (c != NULL && c->nsi != NULL)
      nsock_iod_delete(c->nsi, NSOCK_PENDING_SILENT);
    free(c);
    return;
  }

  if (status != NSE_STATUS_SUCCESS || nse_type(nse) != NSE_TYPE_CONNECT) {
    nsock_iod_delete(c->nsi, NSOCK_PENDING_SILENT);
    free(c);
    hs->inflight--;
    hs->fail++;
    hs->pump();
    return;
  }

  c->wlen = build_http_request(c);
  if (c->wlen < 0) {
    nsock_iod_delete(c->nsi, NSOCK_PENDING_SILENT);
    free(c);
    hs->inflight--;
    hs->fail++;
    hs->pump();
    return;
  }

  nsock_write(nsp, c->nsi, HttpStress::cb_write, HS_READ_CHUNK_TIMEOUT, c, c->wbuf, c->wlen);
}

void HttpStress::cb_write(nsock_pool nsp, nsock_event nse, void *userdata) {
  hs_conn *c = (hs_conn *)userdata;
  HttpStress *hs = g_hs;
  enum nse_status status = nse_status(nse);

  if (hs == NULL) {
    if (c != NULL && c->nsi != NULL)
      nsock_iod_delete(c->nsi, NSOCK_PENDING_SILENT);
    free(c);
    return;
  }

  if (status != NSE_STATUS_SUCCESS) {
    nsock_iod_delete(c->nsi, NSOCK_PENDING_SILENT);
    free(c);
    hs->inflight--;
    hs->fail++;
    hs->pump();
    return;
  }

  if (c->wlen > 0)
    o.stats.addSentPacket((u32)c->wlen);
  c->rl = 0;
  nsock_read(nsp, c->nsi, HttpStress::cb_read, HS_READ_CHUNK_TIMEOUT, c);
}

void HttpStress::cb_read(nsock_pool nsp, nsock_event nse, void *userdata) {
  hs_conn *c = (hs_conn *)userdata;
  HttpStress *hs = g_hs;
  enum nse_status status = nse_status(nse);
  int nbytes = 0;
  char *data;

  if (hs == NULL) {
    if (c != NULL && c->nsi != NULL)
      nsock_iod_delete(c->nsi, NSOCK_PENDING_SILENT);
    free(c);
    return;
  }

  if (status != NSE_STATUS_SUCCESS) {
    nsock_iod_delete(c->nsi, NSOCK_PENDING_SILENT);
    free(c);
    hs->inflight--;
    hs->fail++;
    hs->pump();
    return;
  }

  data = nse_readbuf(nse, &nbytes);
  if (data == NULL || nbytes <= 0) {
    nsock_iod_delete(c->nsi, NSOCK_PENDING_SILENT);
    free(c);
    hs->inflight--;
    hs->fail++;
    hs->pump();
    return;
  }

  if (c->rl + nbytes > HS_READ_MAX) {
    nbytes = HS_READ_MAX - c->rl;
  }
  if (nbytes > 0) {
    memcpy(c->rb + c->rl, data, nbytes);
    c->rl += nbytes;
    c->rb[c->rl] = '\0';
  }

  if (hs_headers_complete(c->rb, c->rl) || c->rl >= HS_READ_MAX) {
    o.stats.addRecvPacket((u32)(c->rl > 0 ? c->rl : 1));
    hs->ok++;
    nsock_iod_delete(c->nsi, NSOCK_PENDING_SILENT);
    free(c);
    hs->inflight--;
    hs->pump();
    return;
  }

  nsock_read(nsp, c->nsi, HttpStress::cb_read, HS_READ_CHUNK_TIMEOUT, c);
}

int HttpStress::start() {
  int np = 0;
  u16 *ports = o.getTargetPorts(&np);
  size_t i, j;

  if (np <= 0)
    return OP_FAILURE;

  for (i = 0; i < o.targets.Targets.size(); i++) {
    NpingTarget *t = o.targets.Targets[i];
    for (j = 0; (int)j < np; j++) {
      this->endpoints.push_back(std::make_pair(t, ports[j]));
    }
  }

  if (this->endpoints.empty())
    return OP_FAILURE;

  if (o.issetStressDurationSec()) {
    struct timeval start_tv;

    this->use_time_limit = true;
    gettimeofday(&start_tv, NULL);
    this->time_end.tv_sec = start_tv.tv_sec + (time_t)o.getStressDurationSec();
    this->time_end.tv_usec = start_tv.tv_usec;
  }

  this->nsp = nsock_pool_new(NULL);
  if (this->nsp == NULL)
    nping_fatal(QT_3, "HttpStress: nsock_pool_new failed.");
  this->nsp_active = true;

  if (o.getDevice()[0] != '\0')
    nsock_pool_set_device(this->nsp, o.getDevice());

  g_hs = this;
  o.stats.startClocks();

  nsock_timer_create(this->nsp, HttpStress::cb_timer_kick, 1, this);

  enum nsock_loopstatus ls = nsock_loop(this->nsp, -1);
  (void)ls;

  o.stats.stopClocks();
  nsock_pool_delete(this->nsp);
  this->nsp = NULL;
  this->nsp_active = false;
  g_hs = NULL;

#ifdef WIN32
  nping_print(QT_1, "HTTP stress: completed=%I64u failed=%I64u (connections attempted=%I64u)",
      this->ok, this->fail, this->issued);
#else
  nping_print(QT_1, "HTTP stress: completed=%llu failed=%llu (connections attempted=%llu)",
      (unsigned long long)this->ok, (unsigned long long)this->fail, (unsigned long long)this->issued);
#endif

  return OP_SUCCESS;
}
